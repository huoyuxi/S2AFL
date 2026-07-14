"""Thread C: schedule boundary / vuln mutation tasks.

This scheduler is the runtime bridge from replay evidence to semantics-guided
mutation. It materializes SBGM tasks from boundary flips and VSAM tasks from
high-risk program points that were confirmed during replay.
"""

from __future__ import annotations

import json
import queue
import random
import threading
import time
from pathlib import Path
from typing import Any

from .config import RuntimeConfig
from .knowledge_loader import RuntimeKnowledge
from .logging_utils import RuntimeLogger
from .models import CoverageReplayResult
from .state_db import RuntimeStateDB


class MutationScheduler(threading.Thread):
    """Thread C: consume coverage results and create LLM tasks."""

    daemon = True

    def __init__(
        self,
        *,
        config: RuntimeConfig,
        state: RuntimeStateDB,
        knowledge: RuntimeKnowledge,
        coverage_queue: "queue.Queue[CoverageReplayResult]",
        logger: RuntimeLogger,
        stop_event: threading.Event,
    ):
        super().__init__(name="MutationScheduler")
        self.config = config
        self.state = state
        self.knowledge = knowledge
        self.coverage_queue = coverage_queue
        self.logger = logger
        self.stop_event = stop_event
        self._recent_results: list[CoverageReplayResult] = []
        self._last_boundary_gate_ts: dict[str, float] = {}
        self._last_boundary_candidate_stats: dict[str, Any] = {}
        self._boundary_rng = random.Random(int(getattr(self.config, "psei_seed", 1337) or 1337))

    def run(self) -> None:
        self.logger.log("C", "mutation scheduler started")
        while not self.stop_event.is_set():
            self._consume_coverage_results()
            self._maybe_schedule_boundary_task()
            self.stop_event.wait(1.0)

    def _consume_coverage_results(self) -> None:
        while True:
            try:
                result = self.coverage_queue.get_nowait()
            except queue.Empty:
                break
            self._recent_results.append(result)
            self._recent_results = self._recent_results[-64:]
            if result.flipped_boundary_target_ids:
                for target_id in result.flipped_boundary_target_ids:
                    self.state.set_target_analysis_result(target_id, f"branch-flipped:{result.seed_id}")
                self.state.update_metric("last_boundary_flip_at", time.time())
                self.logger.log(
                    "C",
                    "boundary target confirmed flipped",
                    seed_id=result.seed_id,
                    target_ids=",".join(result.flipped_boundary_target_ids),
                )
            self._backfeed_generated_handoff_vuln_targets(result)
            if (
                result.measurement_lane == "generated-handoff"
                and result.replay_accepted
                and not result.accepted
                and not self._replay_feedback_degraded()
                and self.config.enable_vuln_tasks
                and result.hit_vuln_target_ids
            ):
                self._schedule_vuln_tasks(result)
            if not result.accepted:
                self.logger.log("C", "coverage result ignored", seed_id=result.seed_id, reason=result.reason, measurement_lane=result.measurement_lane)
                self.coverage_queue.task_done()
                continue
            if self._replay_feedback_degraded():
                self.logger.log("C", "coverage result ignored", seed_id=result.seed_id, reason="replay-health-degraded", measurement_lane=result.measurement_lane)
                self.coverage_queue.task_done()
                continue
            if self.config.enable_vuln_tasks:
                self._schedule_vuln_tasks(result)
            self.coverage_queue.task_done()

    def _schedule_vuln_tasks(self, result: CoverageReplayResult) -> None:
        max_vuln_tasks = max(1, int(getattr(self.config, "max_vuln_tasks", 1) or 1))
        for delta in result.message_deltas:
            for target_id in delta.hit_vuln_target_ids:
                target_row = self._ensure_materialized_target(target_id)
                if not target_row:
                    self._record_vuln_gate(result, target_id, delta, reason="missing-target")
                    continue
                task_count = self.state.count_tasks_for_target(target_id, kind="vuln-generate")
                limit_override = self._vuln_limit_override(result=result, target_id=target_id, task_count=task_count, max_vuln_tasks=max_vuln_tasks)
                if task_count >= max_vuln_tasks and not limit_override.get("allowed"):
                    override_details = {
                        ("override_reason" if k == "reason" else k): v
                        for k, v in limit_override.items()
                        if k != "allowed"
                    }
                    self._record_vuln_gate(
                        result,
                        target_id,
                        delta,
                        reason="target-task-limit",
                        task_count=task_count,
                        max_vuln_tasks=max_vuln_tasks,
                        **override_details,
                    )
                    if not int(target_row.get("analyzed") or 0):
                        self.state.mark_target_analyzed(target_id, result=f"vuln-task-limit:{max_vuln_tasks}")
                    continue
                if self.state.has_task_for_target_seed(target_id, result.seed_id, kind="vuln-generate"):
                    self._record_vuln_gate(result, target_id, delta, reason="duplicate-target-seed", task_count=task_count)
                    continue
                if self.state.has_active_task_for_target(target_id, kind="vuln-generate"):
                    self._record_vuln_gate(result, target_id, delta, reason="active-task-exists", task_count=task_count)
                    continue
                payload = {
                    "reason": "covered-vulnerability-line",
                    "step_index": delta.step_index,
                    "message_preview": delta.message_preview,
                    "target_id": target_id,
                    "evidence_score": int(target_row.get("evidence_score") or 0),
                    "vuln_task_count_before": task_count,
                    "max_vuln_tasks": max_vuln_tasks,
                    "vuln_limit_override": limit_override,
                }
                self._create_one_shot_task(
                    kind="vuln-generate",
                    target_row=target_row,
                    seed_id=result.seed_id,
                    payload=payload,
                )

    def _backfeed_generated_handoff_vuln_targets(self, result: CoverageReplayResult) -> None:
        if result.measurement_lane != "generated-handoff":
            return
        target_ids = self._collect_vuln_target_ids(result)
        if not target_ids:
            return
        materialized: list[str] = []
        missing: list[str] = []
        for target_id in target_ids:
            target_row = self._ensure_materialized_target(target_id)
            if target_row:
                materialized.append(target_id)
            else:
                missing.append(target_id)
        if not materialized and not missing:
            return
        self.state.record_event(
            kind="generated_handoff_vuln_backfeed",
            subject=self.config.subject,
            protocol=self.config.protocol,
            seed_id=result.seed_id,
            payload={
                "measurement_lane": result.measurement_lane,
                "accepted": result.accepted,
                "replay_accepted": result.replay_accepted,
                "scheduler_accepted": result.scheduler_accepted,
                "reason": result.reason,
                "materialized_target_ids": materialized,
                "missing_target_ids": missing,
            },
        )
        self.logger.log(
            "C",
            "generated-handoff vuln targets backfed",
            seed_id=result.seed_id,
            materialized=len(materialized),
            missing=len(missing),
            accepted=result.accepted,
            replay_accepted=result.replay_accepted,
        )

    @staticmethod
    def _collect_vuln_target_ids(result: CoverageReplayResult) -> list[str]:
        seen: set[str] = set()
        ordered: list[str] = []
        for target_id in result.hit_vuln_target_ids:
            if target_id and target_id not in seen:
                seen.add(target_id)
                ordered.append(target_id)
        for delta in result.message_deltas:
            for target_id in delta.hit_vuln_target_ids:
                if target_id and target_id not in seen:
                    seen.add(target_id)
                    ordered.append(target_id)
        return ordered

    def _replay_feedback_degraded(self) -> bool:
        if not bool(getattr(self.config, "scheduler_pause_on_replay_degraded", True)):
            return False
        health = self.state.get_metric("replay_health", {}) or {}
        return bool(health.get("degraded"))

    def _ensure_materialized_target(self, target_id: str) -> dict[str, Any] | None:
        target_row = self.state.get_target_row(target_id)
        if target_row:
            return target_row
        records = self.knowledge.materialize_targets_by_id([target_id])
        if not records:
            return None
        self.state.upsert_targets(records)
        self._update_target_count_metric(materialized_delta=len(records))
        return self.state.get_target_row(target_id)

    def _materialize_boundary_frontier_targets(self) -> int:
        records = self.knowledge.materialize_boundary_targets_for_coverage(
            covered_lines=self.state.covered_line_keys(),
            covered_branches=self.state.covered_branch_keys(),
            radius=self.config.boundary_frontier_radius,
        )
        if not records:
            return 0
        self.state.upsert_targets(records)
        self._update_target_count_metric(materialized_delta=len(records))
        self.logger.log(
            "C",
            "boundary frontier targets materialized",
            count=len(records),
            target_catalog_size=self.knowledge.target_catalog_size(),
        )
        return len(records)

    def _update_target_count_metric(self, *, materialized_delta: int = 0) -> None:
        current = self.state.get_metric("target_count", {}) or {}
        count = int(current.get("count", 0) or 0)
        catalog_count = int(current.get("catalog_count", 0) or 0) or self.knowledge.target_catalog_size()
        self.state.update_metric(
            "target_count",
            {
                "count": count + materialized_delta,
                "catalog_count": catalog_count,
                "materialization": "lazy",
            },
        )

    def _seed_module(self, seed_id: str) -> str:
        row = self.state.get_seed_row(seed_id)
        if not row:
            return ""
        raw = row.get("metadata_json") or "{}"
        try:
            meta = json.loads(raw) if isinstance(raw, str) else dict(raw)
        except Exception:
            meta = {}
        return str(meta.get("task_kind") or meta.get("source") or "")

    def _vuln_limit_override(self, *, result: CoverageReplayResult, target_id: str, task_count: int, max_vuln_tasks: int) -> dict[str, Any]:
        if task_count < max_vuln_tasks:
            return {"allowed": True, "reason": "under-limit"}
        extra_budget = max(0, int(getattr(self.config, "max_vuln_generated_extra_tasks_per_target", 0) or 0))
        if extra_budget <= 0:
            return {"allowed": False, "reason": "no-extra-budget"}
        if result.measurement_lane != "generated-handoff":
            return {"allowed": False, "reason": "not-generated-handoff"}
        if result.global_new_lines <= 0 and result.global_new_branches <= 0 and not result.flipped_boundary_target_ids:
            return {"allowed": False, "reason": "no-generated-new-coverage"}
        module = self._seed_module(result.seed_id)
        if module not in {"boundary-generate", "vuln-generate"}:
            return {"allowed": False, "reason": "not-generated-module", "module": module}
        module_count = self.state.count_tasks_for_target_module(target_id, kind="vuln-generate", module=module)
        extra_used = max(0, task_count - max_vuln_tasks)
        allowed = module_count <= 0 and extra_used < extra_budget
        return {
            "allowed": allowed,
            "reason": "generated-extra-budget" if allowed else "generated-extra-budget-exhausted",
            "module": module,
            "module_task_count": module_count,
            "extra_budget": extra_budget,
            "extra_used": extra_used,
        }

    def _record_vuln_gate(
        self,
        result: CoverageReplayResult,
        target_id: str,
        delta: Any,
        *,
        reason: str,
        **extra: Any,
    ) -> None:
        self.state.record_event(
            kind="vuln_scheduler_gate",
            subject=self.config.subject,
            protocol=self.config.protocol,
            seed_id=result.seed_id,
            payload={
                "target_id": target_id,
                "reason": reason,
                "measurement_lane": result.measurement_lane,
                "accepted": result.accepted,
                "step_index": getattr(delta, "step_index", 0),
                "message_preview": getattr(delta, "message_preview", ""),
                **extra,
            },
        )

    def _maybe_schedule_boundary_task(self) -> None:
        if self._replay_feedback_degraded():
            self._record_boundary_gate("replay-health-degraded")
            return
        if not self.config.enable_boundary_tasks:
            self._record_boundary_gate("disabled")
            return
        now = time.time()
        batch_state = self._refresh_boundary_batch_state(now)
        if batch_state.get("active"):
            self._record_boundary_gate(
                "batch-in-flight",
                now=now,
                batch_id=batch_state.get("batch_id", ""),
                status_counts=batch_state.get("status_counts", {}),
            )
            return
        progress = self.state.get_metric("initial_replay_progress", {}) or {}
        initial_replay_completed_at = float(progress.get("completed_at") or 0.0)
        if initial_replay_completed_at <= 0.0:
            started_at = float(progress.get("started_at") or 0.0)
            timeout_sec = max(0.0, float(getattr(self.config, "initial_replay_timeout_sec", 1800) or 0.0))
            expected_count = int(progress.get("expected_count") or 0)
            completed_seed_names = list(progress.get("completed_seed_names") or [])
            completed_count = len(completed_seed_names)
            timeout_open = (
                started_at > 0.0
                and timeout_sec > 0.0
                and now - started_at >= timeout_sec
                and completed_count > 0
            )
            if not timeout_open:
                self._record_boundary_gate(
                    "waiting-initial-replay",
                    now=now,
                    started_at=started_at,
                    timeout_sec=timeout_sec,
                    expected_count=expected_count,
                    completed_count=completed_count,
                )
                return
            initial_replay_completed_at = now
            self.state.update_metric(
                "initial_replay_progress",
                {
                    "expected_count": expected_count,
                    "seed_names": list(progress.get("seed_names") or []),
                    "completed_seed_names": completed_seed_names,
                    "completed": True,
                    "started_at": started_at,
                    "completed_at": initial_replay_completed_at,
                    "timeout_open": True,
                },
            )
            self.logger.log(
                "C",
                "initial replay timeout opened boundary scheduling",
                completed_seed_count=completed_count,
                expected_count=expected_count,
                timeout_sec=timeout_sec,
            )
        last_new_coverage_at = float(self.state.get_metric("last_new_coverage_at", 0.0) or 0.0)
        stagnation_anchor = self._boundary_progress_anchor(initial_replay_completed_at, last_new_coverage_at)
        if now - stagnation_anchor < self.config.stagnation_window_sec:
            self._record_boundary_gate(
                "waiting-stagnation",
                now=now,
                remaining_sec=max(0.0, float(self.config.stagnation_window_sec) - (now - stagnation_anchor)),
                stagnation_anchor=stagnation_anchor,
                initial_replay_completed_at=initial_replay_completed_at,
                last_new_coverage_at=last_new_coverage_at,
                last_boundary_batch_completed_at=float(self.state.get_metric("last_boundary_batch_completed_at", 0.0) or 0.0),
            )
            return

        candidates = self._collect_boundary_candidates(now)
        if not candidates:
            self._record_boundary_gate(
                "no-boundary-candidates",
                now=now,
                candidate_stats=self._last_boundary_candidate_stats,
                initial_replay_completed_at=initial_replay_completed_at,
                last_new_coverage_at=last_new_coverage_at,
            )
            return

        selected, selection_meta = self._select_boundary_batch(candidates)
        if not selected:
            self._record_boundary_gate(
                "no-eligible-boundary-candidates",
                now=now,
                candidate_stats=self._last_boundary_candidate_stats,
                selection_meta=selection_meta,
            )
            return

        batch_id = f"bnd-{int(now * 1000)}-{len(selected)}"
        batch_size = self._boundary_batch_size()
        queued = 0
        rank_counts: dict[int, int] = {}
        context_counts: dict[str, int] = {}
        lane_counts: dict[str, int] = {}
        queued_target_ids: list[str] = []
        for item in selected:
            target_row = item["target_row"]
            branch_state = item["branch_state"]
            payload = {
                "reason": "uncovered-branch-side" if branch_state else "stagnation-boundary-target",
                "step_index": item["step_index"],
                "message_preview": item["preview"],
                "condition_expr": self._condition_expr_for_target(target_row),
                "frontier_score": item["frontier_score"],
                "evidence_score": item["evidence_score"],
                "boundary_signal_at": now,
                "context_kind": item["context_kind"],
                "boundary_lane": item["boundary_lane"],
                "batch_id": batch_id,
                "batch_pool": selection_meta.get("pool_name", ""),
                "batch_size": batch_size,
                "attempt_count_before": item["attempt_count"],
                "attempt_limit": self._boundary_attempt_limit(),
                "touched_boundary": bool(item["touched"]),
            }
            if branch_state:
                payload.update(
                    {
                        "covered_branch_side": branch_state["covered_side"],
                        "missing_branch_side": branch_state["missing_side"],
                        "covered_branch_key": branch_state["covered_branch_key"],
                        "missing_branch_key": branch_state["missing_branch_key"],
                    }
                )
            created = self._create_one_shot_task(
                kind="boundary-generate",
                target_row=target_row,
                seed_id=item["seed_id"],
                payload=payload,
            )
            if not created:
                continue
            queued += 1
            queued_target_ids.append(target_row["target_id"])
            rank_counts[int(item["info_rank"])] = rank_counts.get(int(item["info_rank"]), 0) + 1
            context_counts[item["context_kind"]] = context_counts.get(item["context_kind"], 0) + 1
            lane_counts[item["boundary_lane"]] = lane_counts.get(item["boundary_lane"], 0) + 1

        if queued <= 0:
            self._record_boundary_gate(
                "boundary-batch-empty-after-filter",
                now=now,
                candidate_stats=self._last_boundary_candidate_stats,
                selection_meta=selection_meta,
            )
            return

        self.state.update_metric(
            "active_boundary_batch",
            {
                "active": True,
                "batch_id": batch_id,
                "queued_at": now,
                "task_count": queued,
                "target_ids": queued_target_ids,
                "pool_name": selection_meta.get("pool_name", ""),
                "batch_size": batch_size,
            },
        )
        self.logger.log(
            "C",
            "boundary batch queued",
            queued=queued,
            total_candidates=len(candidates),
            batch_id=batch_id,
            batch_size=batch_size,
            pool_name=selection_meta.get("pool_name", ""),
            rank_counts=json.dumps(rank_counts, ensure_ascii=False, sort_keys=True),
            context_counts=json.dumps(context_counts, ensure_ascii=False, sort_keys=True),
            lane_counts=json.dumps(lane_counts, ensure_ascii=False, sort_keys=True),
        )

    def _boundary_progress_anchor(self, initial_replay_completed_at: float, last_new_coverage_at: float) -> float:
        last_batch_completed_at = float(self.state.get_metric("last_boundary_batch_completed_at", 0.0) or 0.0)
        return max(initial_replay_completed_at, last_new_coverage_at, last_batch_completed_at)

    def _boundary_batch_size(self) -> int:
        return max(1, int(getattr(self.config, "max_guess_boundary_tasks", 5) or 5))

    def _boundary_attempt_limit(self) -> int:
        return max(1, int(getattr(self.config, "max_boundary_attempts_per_target", 3) or 3))

    def _refresh_boundary_batch_state(self, now: float) -> dict[str, Any]:
        batch_state = self.state.get_metric("active_boundary_batch", {}) or {}
        if not isinstance(batch_state, dict):
            return {}
        if not batch_state.get("active") or not batch_state.get("batch_id"):
            return batch_state
        batch_id = str(batch_state.get("batch_id") or "")
        counts = self.state.task_batch_status_counts(batch_id, kind="boundary-generate")
        batch_state["status_counts"] = counts
        pending = int(counts.get("pending", 0)) + int(counts.get("leased", 0))
        if counts.get("total", 0) <= 0 or pending > 0:
            return batch_state
        batch_state["active"] = False
        batch_state["completed_at"] = now
        self.state.update_metric("active_boundary_batch", batch_state)
        self.state.update_metric("last_boundary_batch_completed_at", now)
        self.state.record_event(
            kind="boundary_batch_completed",
            subject=self.config.subject,
            protocol=self.config.protocol,
            payload={
                "batch_id": batch_id,
                "completed_at": now,
                "status_counts": counts,
                "target_ids": batch_state.get("target_ids", []),
            },
        )
        self.logger.log(
            "C",
            "boundary batch completed",
            batch_id=batch_id,
            status_counts=json.dumps(counts, ensure_ascii=False, sort_keys=True),
        )
        return batch_state

    def _is_confirmed_flip_target(self, target_row: dict[str, Any]) -> bool:
        return str(target_row.get("analysis_result") or "").startswith("branch-flipped:")

    def _candidate_sort_key(self, item: dict[str, Any]) -> tuple[Any, ...]:
        return (
            int(item["touched_rank"]),
            int(item["info_rank"]),
            self._context_rank(item["context_kind"]),
            -float(item["evidence_score"]),
            -float(item["frontier_score"]),
            float(item["activation_ts"]),
            str(item["target_row"]["target_id"]),
        )

    def _sample_guess_candidates(self, pool: list[dict[str, Any]], count: int) -> list[dict[str, Any]]:
        if count <= 0 or not pool:
            return []
        if len(pool) <= count:
            return sorted(pool, key=self._candidate_sort_key)
        sampled = self._boundary_rng.sample(pool, count)
        sampled.sort(key=self._candidate_sort_key)
        return sampled

    def _select_boundary_candidates_from_pool(self, pool: list[dict[str, Any]], batch_size: int) -> list[dict[str, Any]]:
        selected: list[dict[str, Any]] = []
        touched_strict = sorted(
            [item for item in pool if item["touched"] and item["boundary_lane"] == "strict"],
            key=self._candidate_sort_key,
        )
        touched_guess = [item for item in pool if item["touched"] and item["boundary_lane"] == "guess"]
        untouched_strict = sorted(
            [item for item in pool if (not item["touched"]) and item["boundary_lane"] == "strict"],
            key=self._candidate_sort_key,
        )
        untouched_guess = [item for item in pool if (not item["touched"]) and item["boundary_lane"] == "guess"]

        ranked_buckets: list[tuple[str, list[dict[str, Any]]]] = [
            ("ordered", touched_strict),
            ("sampled", touched_guess),
            ("ordered", untouched_strict),
            ("sampled", untouched_guess),
        ]
        for mode, bucket in ranked_buckets:
            if len(selected) >= batch_size:
                break
            remaining = [item for item in bucket if item not in selected]
            need = batch_size - len(selected)
            if mode == "sampled":
                selected.extend(self._sample_guess_candidates(remaining, need))
            else:
                selected.extend(remaining[:need])

        if len(selected) < batch_size and len(selected) < len(pool):
            remaining = [item for item in pool if item not in selected]
            selected.extend(sorted(remaining, key=self._candidate_sort_key)[: batch_size - len(selected)])
        return selected

    def _select_boundary_batch(self, candidates: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        batch_size = self._boundary_batch_size()
        untried = [item for item in candidates if not item["tried"]]
        retryable = [item for item in candidates if item["tried"]]
        if untried:
            return self._select_boundary_candidates_from_pool(untried, batch_size), {
                "pool_name": "untried",
                "pool_size": len(untried),
                "retryable_size": len(retryable),
            }
        return self._select_boundary_candidates_from_pool(retryable, batch_size), {
            "pool_name": "retryable",
            "pool_size": len(retryable),
            "retryable_size": len(retryable),
        }

    def _record_boundary_gate(self, reason: str, *, now: float | None = None, throttle_sec: float = 60.0, **payload: Any) -> None:
        ts = time.time() if now is None else now
        last = float(self._last_boundary_gate_ts.get(reason) or 0.0)
        if ts - last < throttle_sec:
            return
        self._last_boundary_gate_ts[reason] = ts
        event_payload = {"reason": reason, **payload}
        self.state.record_event(
            kind="boundary_scheduler_gate",
            subject=self.config.subject,
            protocol=self.config.protocol,
            payload=event_payload,
        )
        self.logger.log("C", "boundary scheduler gated", payload=json.dumps(event_payload, ensure_ascii=False, sort_keys=True))

    def _collect_boundary_candidates(self, now: float) -> list[dict[str, Any]]:
        materialized = self._materialize_boundary_frontier_targets()
        covered_branches = self.state.covered_branch_keys()
        covered_lines = self.state.covered_line_keys()
        candidates: list[dict[str, Any]] = []
        min_frontier = float(getattr(self.config, "boundary_min_frontier_score", 0.0) or 0.0)
        attempt_limit = self._boundary_attempt_limit()
        stats: dict[str, Any] = {
            "targets_seen": 0,
            "no_seed_context": 0,
            "frontier_below_threshold": 0,
            "branch_state": 0,
            "strict_candidates": 0,
            "guess_candidates": 0,
            "untried_candidates": 0,
            "retryable_candidates": 0,
            "attempt_budget_exhausted": 0,
            "context_counts": {},
            "boundary_lane_counts": {},
            "min_frontier_score": min_frontier,
        }
        for target_row in self.state.list_candidate_targets("boundary"):
            stats["targets_seen"] += 1
            boundary_lane = self._boundary_lane_for_target(target_row)
            confirmed_flip = self._is_confirmed_flip_target(target_row)
            attempt_count = self.state.count_tasks_for_target(target_row["target_id"], kind="boundary-generate")
            if attempt_count >= attempt_limit and not confirmed_flip:
                stats["attempt_budget_exhausted"] += 1
                continue
            branch_state = self.knowledge.boundary_branch_state(target_row, covered_branches)
            if branch_state:
                stats["branch_state"] += 1
            frontier_score = self.knowledge.frontier_score(
                target_row,
                covered_lines,
                radius=self.config.boundary_frontier_radius,
            )
            seed_id, step_index, preview, context_kind = self._find_seed_context_for_boundary(
                target_row,
                branch_state["covered_branch_key"] if branch_state else None,
            )
            if not seed_id:
                stats["no_seed_context"] += 1
                continue
            if not branch_state and context_kind == "recent-fallback" and frontier_score < min_frontier:
                stats["frontier_below_threshold"] += 1
                boundary_lane = "guess"
            touched = bool(branch_state) or context_kind in {"branch-exact", "line-hit", "branch-prefix"}
            stats["context_counts"][context_kind] = int(stats["context_counts"].get(context_kind, 0)) + 1
            stats["boundary_lane_counts"][boundary_lane] = int(stats["boundary_lane_counts"].get(boundary_lane, 0)) + 1
            if boundary_lane == "guess":
                stats["guess_candidates"] += 1
            else:
                stats["strict_candidates"] += 1
            if attempt_count > 0:
                stats["retryable_candidates"] += 1
            else:
                stats["untried_candidates"] += 1
            candidates.append(
                {
                    "info_rank": int(target_row["info_rank"]),
                    "activation_ts": float(target_row.get("first_activation_ts") or now),
                    "target_row": target_row,
                    "seed_id": seed_id,
                    "step_index": step_index,
                    "preview": preview,
                    "branch_state": branch_state,
                    "context_kind": context_kind,
                    "boundary_lane": boundary_lane,
                    "frontier_score": float(frontier_score),
                    "evidence_score": int(target_row.get("evidence_score") or 0),
                    "attempt_count": attempt_count,
                    "tried": attempt_count > 0,
                    "touched": touched,
                    "touched_rank": 0 if touched else 1,
                    "confirmed_flip": confirmed_flip,
                }
            )
        stats["candidate_count"] = len(candidates)
        stats["materialized_now"] = materialized
        self._last_boundary_candidate_stats = stats
        return candidates

    @staticmethod
    def _boundary_lane_for_target(target_row: dict[str, Any]) -> str:
        payload = target_row.get("source_payload")
        if isinstance(payload, str):
            try:
                payload = json.loads(payload)
            except Exception:
                payload = {}
        if not isinstance(payload, dict):
            raw = target_row.get("source_payload_json")
            if isinstance(raw, str):
                try:
                    payload = json.loads(raw)
                except Exception:
                    payload = {}
            else:
                payload = {}
        lane = str(payload.get("boundary_lane") or "").strip().lower()
        return lane if lane in {"strict", "guess"} else "strict"

    def _find_seed_context_for_boundary(
        self,
        target_row: dict[str, Any],
        covered_branch_key: str | None,
    ) -> tuple[str | None, int, str, str]:
        target_file = target_row["relative_path"]
        target_line = int(target_row["line"])
        target_id = target_row["target_id"]
        prefixes = [f"{target_file}:{target_line}:", f"{Path(target_file).name}:{target_line}:"]
        if prefixes[0] == prefixes[1]:
            prefixes.pop()
        line_keys = [f"{target_file}:{target_line}", f"{Path(target_file).name}:{target_line}"]
        if line_keys[0] == line_keys[1]:
            line_keys.pop()

        branch_prefix_fallback: tuple[str | None, int, str, str] = (None, 0, "", "branch-prefix")
        line_hit_fallback: tuple[str | None, int, str, str] = (None, 0, "", "line-hit")
        recent_fallback: tuple[str | None, int, str, str] = (None, 0, "", "recent-fallback")

        for result in reversed(self._recent_results):
            for delta in reversed(result.message_deltas):
                recent_fallback = (result.seed_id, delta.step_index, delta.message_preview, "recent-fallback")
                if covered_branch_key and covered_branch_key in delta.cumulative_branches:
                    return result.seed_id, delta.step_index, delta.message_preview, "branch-exact"
                if target_id in delta.hit_boundary_target_ids or any(line_key in delta.cumulative_lines for line_key in line_keys):
                    return result.seed_id, delta.step_index, delta.message_preview, "line-hit"
                if covered_branch_key and not branch_prefix_fallback[0] and any(
                    branch.startswith(p) for p in prefixes for branch in delta.cumulative_branches
                ):
                    branch_prefix_fallback = (result.seed_id, delta.step_index, delta.message_preview, "branch-prefix")
                if not line_hit_fallback[0] and any(line_key in delta.cumulative_lines for line_key in line_keys):
                    line_hit_fallback = (result.seed_id, delta.step_index, delta.message_preview, "line-hit")

        if branch_prefix_fallback[0]:
            return branch_prefix_fallback
        if line_hit_fallback[0]:
            return line_hit_fallback
        return recent_fallback

    @staticmethod
    def _context_rank(context_kind: str) -> int:
        order = {
            "branch-exact": 0,
            "line-hit": 1,
            "branch-prefix": 2,
            "recent-fallback": 3,
        }
        return order.get(context_kind, 9)

    @staticmethod
    def _condition_expr_for_target(target_row: dict[str, Any]) -> str:
        payload = target_row.get("source_payload")
        if isinstance(payload, str):
            try:
                payload = json.loads(payload)
            except Exception:
                payload = {}
        if not isinstance(payload, dict):
            raw = target_row.get("source_payload_json")
            if isinstance(raw, str):
                try:
                    payload = json.loads(raw)
                except Exception:
                    payload = {}
            else:
                payload = {}
        program_point = payload.get("program_point") or {}
        return str(program_point.get("condition_expr") or program_point.get("condition") or target_row.get("code") or "")

    def _create_one_shot_task(
        self,
        *,
        kind: str,
        target_row: dict[str, Any],
        seed_id: str,
        payload: dict[str, Any],
    ) -> bool:
        target_id = target_row["target_id"]
        if kind != "vuln-generate" and int(target_row.get("analyzed") or 0):
            return False
        if kind != "vuln-generate" and self.state.has_active_task_for_target(target_id, kind=kind):
            return False
        if kind == "boundary-generate":
            attempt_limit = self._boundary_attempt_limit()
            attempt_count = self.state.count_tasks_for_target(target_id, kind=kind)
            if attempt_count >= attempt_limit and not self._is_confirmed_flip_target(target_row):
                self.logger.log(
                    "C",
                    "boundary target attempt budget exhausted",
                    target_id=target_id,
                    attempts=attempt_count,
                    limit=attempt_limit,
                )
                return False
        now = time.time()
        self.state.activate_target(target_id, activated_at=now)
        priority = self._priority_value(int(target_row["info_rank"]), float(target_row.get("first_activation_ts") or now), payload)
        self.state.create_task(
            kind=kind,
            protocol=self.config.protocol,
            subject=self.config.subject,
            seed_id=seed_id,
            target_id=target_id,
            priority=priority,
            payload=payload,
        )
        one_shot = bool(getattr(self.config, "one_shot_per_target", True)) and kind not in {"boundary-generate", "vuln-generate"}
        if one_shot:
            self.state.mark_target_analyzed(target_id, result="queued")
        self.state.record_event(
            kind="scheduler_decision",
            subject=self.config.subject,
            protocol=self.config.protocol,
            seed_id=seed_id,
            payload={
                "task_kind": kind,
                "target_id": target_id,
                "priority": priority,
                "payload": payload,
            },
        )
        self.logger.log(
            "C",
            "task queued",
            task_kind=kind,
            target_id=target_id,
            seed_id=seed_id,
            payload=json.dumps(payload, ensure_ascii=False),
        )
        return True

    @staticmethod
    def _priority_value(info_rank: int, activation_ts: float, payload: dict[str, Any]) -> float:
        """Priority order: evidence mode first, then evidence strength, then frontier score."""
        frontier_bonus = float(payload.get("frontier_score", 0.0))
        evidence_bonus = min(float(payload.get("evidence_score", 0.0)), 100.0) / 1000.0
        return (info_rank * 10_000_000_000.0) + activation_ts - frontier_bonus - evidence_bonus
