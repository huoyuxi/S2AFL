"""Thread B: replay queue seeds and collect coverage diffs."""

from __future__ import annotations

import json
import queue
import re
import threading
import time
from pathlib import Path

from .aflnet import AFLNetRuntime
from .command_utils import CommandResult, run_command, try_load_json
from .config import RuntimeConfig
from .knowledge_loader import RuntimeKnowledge
from .logging_utils import RuntimeLogger
from .models import CoverageReplayResult, CoverageSnapshot, MessageDelta, SeedRecord
from .seed_utils import body_sha1, load_seed_file, message_method, message_preview, prefix_messages, split_seed_messages
from .state_db import RuntimeStateDB

_STATUS_CODE_RE = re.compile(r"\b([1-5]\d{2})\b")


def _normalize_snapshot(payload: dict) -> CoverageSnapshot:
    """Normalize a coverage JSON payload into line/branch sets."""
    lines = set()
    for entry in payload.get("lines", []):
        if isinstance(entry, str):
            lines.add(entry)
        elif isinstance(entry, dict):
            rel = entry.get("relative_path") or entry.get("file")
            line = entry.get("line")
            if rel and line is not None:
                lines.add(f"{rel}:{int(line)}")
    branches = set()
    for entry in payload.get("branches", []):
        if isinstance(entry, str):
            branches.add(entry)
        elif isinstance(entry, dict):
            rel = entry.get("relative_path") or entry.get("file")
            line = entry.get("line")
            ident = entry.get("branch") or entry.get("id") or entry.get("taken")
            if rel and line is not None:
                branches.add(f"{rel}:{int(line)}:{ident}")
    return CoverageSnapshot(lines=lines, branches=branches, raw=payload)


def _result_reason(prefix: str, *, step_index: int, detail: str = "") -> str:
    reason = f"{prefix}@step{step_index}"
    if detail:
        reason = f"{reason}:{detail}"
    return reason


def _serialize_message_deltas(deltas: list[MessageDelta]) -> list[dict]:
    return [
        {
            "step_index": delta.step_index,
            "method": delta.method,
            "message_preview": delta.message_preview,
            "delta_lines": delta.delta_lines,
            "delta_line_count": len(delta.delta_lines),
            "cumulative_lines": delta.cumulative_lines,
            "cumulative_line_count": len(delta.cumulative_lines),
            "delta_branches": delta.delta_branches,
            "delta_branch_count": len(delta.delta_branches),
            "cumulative_branches": delta.cumulative_branches,
            "cumulative_branch_count": len(delta.cumulative_branches),
            "hit_boundary_target_ids": delta.hit_boundary_target_ids,
            "hit_vuln_target_ids": delta.hit_vuln_target_ids,
        }
        for delta in deltas
    ]


def _response_status_code(response_preview_text: str) -> int | None:
    match = _STATUS_CODE_RE.search(str(response_preview_text or ""))
    if not match:
        return None
    try:
        code = int(match.group(1))
    except ValueError:
        return None
    return code if 100 <= code <= 599 else None


def _extract_success_prefix_witness(trace_payload: dict[str, object], messages: list[str]) -> dict[str, object]:
    steps = list(trace_payload.get("steps") or [])
    replay_prefix_messages = 0
    success_prefix_messages = 0
    first_failure_status_step: int | None = None
    prefix_methods: list[str] = []
    prefix_status_codes: list[int] = []
    prefix_response_previews: list[str] = []
    for default_idx, step in enumerate(steps):
        if not isinstance(step, dict):
            break
        step_index = int(step.get("step_index") or default_idx)
        if step_index != replay_prefix_messages or step_index >= len(messages):
            break
        send_error = str(step.get("send_error") or step.get("response_error") or "").strip()
        if send_error:
            break
        capture_payload = step.get("capture_payload") if isinstance(step.get("capture_payload"), dict) else {}
        capture_rc = int(step.get("capture_returncode") or 0)
        if capture_rc != 0 or capture_payload.get("error"):
            break
        response_preview_text = str(step.get("response_preview") or "").strip()
        if not response_preview_text:
            break
        status_code = _response_status_code(response_preview_text)
        prefix_methods.append(str(step.get("method") or message_method(messages[step_index]) or ""))
        if status_code is not None:
            prefix_status_codes.append(status_code)
        prefix_response_previews.append(message_preview(response_preview_text))
        replay_prefix_messages += 1
        if status_code is not None and status_code >= 400:
            first_failure_status_step = step_index
            break
        success_prefix_messages = replay_prefix_messages
    return {
        "replay_prefix_messages": replay_prefix_messages,
        "success_prefix_messages": success_prefix_messages,
        "replay_first_failure_status_step": first_failure_status_step,
        "replay_prefix_methods": prefix_methods,
        "replay_prefix_status_codes": prefix_status_codes,
        "replay_prefix_response_previews": prefix_response_previews,
    }


class CoverageReplayWorker(threading.Thread):
    """Thread B: consume new seeds, run prefix replay, and compute coverage deltas."""

    daemon = True

    def __init__(
        self,
        *,
        worker_id: int,
        config: RuntimeConfig,
        state: RuntimeStateDB,
        runtime: AFLNetRuntime,
        knowledge: RuntimeKnowledge,
        replay_queue: "queue.Queue[SeedRecord]",
        result_queue: "queue.Queue[CoverageReplayResult]",
        logger: RuntimeLogger,
        stop_event: threading.Event,
        publish_results: bool = True,
    ):
        super().__init__(name=f"CoverageReplayWorker-{worker_id}")
        self.worker_id = worker_id
        self.config = config
        self.state = state
        self.runtime = runtime
        self.knowledge = knowledge
        self.replay_queue = replay_queue
        self.result_queue = result_queue
        self.logger = logger
        self.stop_event = stop_event
        self.publish_results = publish_results

    def run(self) -> None:
        self.logger.log("B", "coverage replay worker started", worker=self.worker_id)
        if not self._wait_for_afl_ready():
            return
        while not self.stop_event.is_set():
            try:
                seed = self.replay_queue.get(timeout=self.config.replay_poll_interval_sec)
            except queue.Empty:
                continue
            try:
                result = self._replay_seed(seed)
                lane = str(result.measurement_lane or seed.metadata.get("measurement_lane") or "coverage")
                if self.publish_results and lane in {"coverage", "generated-handoff"}:
                    self.result_queue.put(result)
            finally:
                self.replay_queue.task_done()

    def _wait_for_afl_ready(self) -> bool:
        wait_logged = False
        while not self.stop_event.is_set():
            if self.runtime.fuzzer_started() and self.runtime.fuzzer_alive() and self.runtime.fuzzer_ready():
                if self.worker_id == 0:
                    self.logger.log("B", "afl-fuzz ready; replay enabled", worker=self.worker_id)
                return True
            if self.runtime.fuzzer_started() and not self.runtime.fuzzer_alive():
                return False
            if self.worker_id == 0 and not wait_logged:
                self.logger.log(
                    "B",
                    "waiting for afl-fuzz ready state before replay",
                    worker=self.worker_id,
                )
                wait_logged = True
            self.stop_event.wait(self.config.replay_poll_interval_sec)
        return False

    def _replay_seed(self, seed: SeedRecord) -> CoverageReplayResult:
        mode = str(getattr(self.config, "replay_prefix_mode", "stream") or "stream").strip().lower()
        if mode == "stream":
            return self._replay_seed_stream(seed)
        return self._replay_seed_legacy(seed)

    def _replay_seed_legacy(self, seed: SeedRecord) -> CoverageReplayResult:
        raw = load_seed_file(seed.queue_path)
        replay_started_at = time.time()
        replay_enqueued_at = float(seed.metadata.get("replay_enqueued_at") or 0.0)
        queue_wait_ms = max(0.0, (replay_started_at - replay_enqueued_at) * 1000.0) if replay_enqueued_at > 0 else 0.0
        actual_sha1 = body_sha1(raw)
        expected_sha1 = str(seed.metadata.get("expected_sha1") or seed.body_sha1 or "").strip()
        if expected_sha1 and actual_sha1 != expected_sha1:
            return self._build_failure_result(
                seed=seed,
                deltas=[],
                last_snapshot=CoverageSnapshot(),
                step_index=0,
                reason=_result_reason("seed-hash-mismatch", step_index=0, detail=f"expected={expected_sha1},actual={actual_sha1}"),
                replay_started_at=replay_started_at,
                queue_wait_ms=queue_wait_ms,
                failure_payload={
                    "phase": "seed_hash",
                    "expected_sha1": expected_sha1,
                    "actual_sha1": actual_sha1,
                    "queue_path": seed.queue_path,
                },
            )
        messages = split_seed_messages(self.config.protocol, raw)
        prev_snapshot = CoverageSnapshot()
        deltas: list[MessageDelta] = []

        mode = str(getattr(self.config, "replay_prefix_mode", "prefix") or "prefix").strip().lower()
        if mode == "whole-seed":
            replay_units = [(len(messages) - 1 if messages else 0, raw, message_method(messages[0]) if messages else "", message_preview(raw))]
            replay_label = "seed replayed"
        else:
            replay_units = [
                (idx, prefix_messages(messages, idx), message_method(messages[idx]), message_preview(messages[idx]))
                for idx in range(len(messages))
            ]
            replay_label = "seed prefix replayed"

        for idx, replay_raw, method_name, preview_text in replay_units:
            prefix_path = self.config.resolved_temp_dir / f"{seed.seed_id}-{idx:03d}.raw"
            prefix_path.write_bytes(replay_raw.encode("latin-1", errors="replace"))

            if self.config.replay_prepare_cmd:
                prepare_res = run_command(self.config.render_command(self.config.replay_prepare_cmd, seed_path=str(prefix_path)), timeout=self.config.replay_prepare_timeout_sec or self.config.command_timeout_sec)
                if prepare_res.returncode != 0:
                    return self._build_failure_result(
                        seed=seed,
                        deltas=deltas,
                        last_snapshot=prev_snapshot,
                        step_index=idx,
                        reason=_result_reason("replay-prepare-failed", step_index=idx, detail=f"rc={prepare_res.returncode}"),
                        replay_started_at=replay_started_at,
                        queue_wait_ms=queue_wait_ms,
                        failure_payload={
                            "phase": "replay_prepare",
                            "step_index": idx,
                            "message_preview": preview_text,
                            "command": self._command_payload(prepare_res),
                        },
                    )

            if self.config.coverage_reset_cmd and (self.config.per_message_reset or idx == replay_units[0][0]):
                reset_res = run_command(self.config.render_command(self.config.coverage_reset_cmd, seed_path=str(prefix_path)), timeout=self.config.coverage_reset_timeout_sec or self.config.command_timeout_sec)
                if reset_res.returncode != 0:
                    return self._build_failure_result(
                        seed=seed,
                        deltas=deltas,
                        last_snapshot=prev_snapshot,
                        step_index=idx,
                        reason=_result_reason("coverage-reset-failed", step_index=idx, detail=f"rc={reset_res.returncode}"),
                        replay_started_at=replay_started_at,
                        queue_wait_ms=queue_wait_ms,
                        failure_payload={
                            "phase": "coverage_reset",
                            "step_index": idx,
                            "message_preview": preview_text,
                            "command": self._command_payload(reset_res),
                            "per_message_reset": self.config.per_message_reset,
                        },
                    )

            replay_res = run_command(
                self.config.render_command(
                    self.config.replay_cmd,
                    seed_path=str(prefix_path),
                    protocol=self.config.protocol,
                    host=self.config.replay_host,
                    port=self.config.replay_port,
                ),
                timeout=self.config.replay_timeout_sec or self.config.command_timeout_sec,
            )
            snapshot, capture_payload, capture_res = self._capture_snapshot(seed_id=seed.seed_id, step_index=idx)
            if self.config.replay_cleanup_cmd:
                run_command(self.config.render_command(self.config.replay_cleanup_cmd, seed_path=str(prefix_path)), timeout=self.config.replay_cleanup_timeout_sec or self.config.command_timeout_sec)

            if replay_res.returncode != 0:
                return self._build_failure_result(
                    seed=seed,
                    deltas=deltas,
                    last_snapshot=prev_snapshot,
                    step_index=idx,
                    reason=_result_reason("replay-failed", step_index=idx, detail=f"rc={replay_res.returncode}"),
                    replay_started_at=replay_started_at,
                    queue_wait_ms=queue_wait_ms,
                    failure_payload={
                        "phase": "replay",
                        "step_index": idx,
                        "message_preview": preview_text,
                        "command": self._command_payload(replay_res),
                    },
                )

            capture_error = ""
            if capture_res.returncode != 0:
                capture_error = f"rc={capture_res.returncode}"
            elif capture_payload.get("error"):
                capture_error = str(capture_payload.get("error"))
            if capture_error:
                return self._build_failure_result(
                    seed=seed,
                    deltas=deltas,
                    last_snapshot=prev_snapshot,
                    step_index=idx,
                    reason=_result_reason("coverage-capture-failed", step_index=idx, detail=capture_error),
                    replay_started_at=replay_started_at,
                    queue_wait_ms=queue_wait_ms,
                    failure_payload={
                        "phase": "coverage_capture",
                        "step_index": idx,
                        "message_preview": preview_text,
                        "command": self._command_payload(capture_res),
                        "capture_payload": capture_payload,
                    },
                )

            delta_lines = sorted(snapshot.lines - prev_snapshot.lines)
            delta_branches = sorted(snapshot.branches - prev_snapshot.branches)
            hit_boundary, hit_vuln = self.knowledge.hit_targets_for_lines(set(snapshot.lines))
            deltas.append(
                MessageDelta(
                    step_index=idx,
                    method=method_name,
                    message_preview=preview_text,
                    delta_lines=delta_lines,
                    cumulative_lines=sorted(snapshot.lines),
                    delta_branches=delta_branches,
                    cumulative_branches=sorted(snapshot.branches),
                    hit_boundary_target_ids=hit_boundary,
                    hit_vuln_target_ids=hit_vuln,
                )
            )
            prev_snapshot = snapshot
            self.logger.log(
                "B",
                replay_label,
                seed_id=seed.seed_id,
                step_index=idx,
                rc=replay_res.returncode,
                delta_lines=len(delta_lines),
                delta_branches=len(delta_branches),
                replay_mode=mode,
            )

        return self._build_success_result(
            seed=seed,
            deltas=deltas,
            snapshot=prev_snapshot,
            replay_started_at=replay_started_at,
            queue_wait_ms=queue_wait_ms,
            replay_port=self.config.replay_port,
        )

    def _replay_seed_stream(self, seed: SeedRecord) -> CoverageReplayResult:
        raw = load_seed_file(seed.queue_path)
        replay_started_at = time.time()
        replay_enqueued_at = float(seed.metadata.get("replay_enqueued_at") or 0.0)
        queue_wait_ms = max(0.0, (replay_started_at - replay_enqueued_at) * 1000.0) if replay_enqueued_at > 0 else 0.0
        actual_sha1 = body_sha1(raw)
        expected_sha1 = str(seed.metadata.get("expected_sha1") or seed.body_sha1 or "").strip()
        if expected_sha1 and actual_sha1 != expected_sha1:
            return self._build_failure_result(
                seed=seed,
                deltas=[],
                last_snapshot=CoverageSnapshot(),
                step_index=0,
                reason=_result_reason("seed-hash-mismatch", step_index=0, detail=f"expected={expected_sha1},actual={actual_sha1}"),
                replay_started_at=replay_started_at,
                queue_wait_ms=queue_wait_ms,
                failure_payload={
                    "phase": "seed_hash",
                    "expected_sha1": expected_sha1,
                    "actual_sha1": actual_sha1,
                    "queue_path": seed.queue_path,
                },
            )

        messages = split_seed_messages(self.config.protocol, raw)
        if not messages:
            return self._build_failure_result(
                seed=seed,
                deltas=[],
                last_snapshot=CoverageSnapshot(),
                step_index=0,
                reason=_result_reason("seed-empty", step_index=0),
                replay_started_at=replay_started_at,
                queue_wait_ms=queue_wait_ms,
                failure_payload={"phase": "split_seed", "queue_path": seed.queue_path},
            )

        trace_path = self.config.resolved_temp_dir / f"{seed.seed_id}.stream-trace.json"
        replay_timeout = self._stream_replay_timeout(seed=seed, message_count=len(messages))
        capture_timeout = float(getattr(self.config, "coverage_capture_timeout_sec", 0) or getattr(self.config, "command_timeout_sec", 120) or 120)
        safe_capture_timeout = min(capture_timeout, max(15.0, replay_timeout - 15.0))
        env = dict(self.config.coverage_capture_env)
        env.update({
            "S2AFL_TRACE_PATH": str(trace_path),
            "S2AFL_CAPTURE_TIMEOUT_SEC": str(safe_capture_timeout),
        })
        if self.config.replay_prepare_cmd:
            prepare_res = run_command(
                self.config.render_command(self.config.replay_prepare_cmd, seed_path=seed.queue_path),
                timeout=self.config.replay_prepare_timeout_sec or self.config.command_timeout_sec,
            )
            if prepare_res.returncode != 0:
                return self._build_failure_result(
                    seed=seed,
                    deltas=[],
                    last_snapshot=CoverageSnapshot(),
                    step_index=0,
                    reason=_result_reason("replay-prepare-failed", step_index=0, detail=f"rc={prepare_res.returncode}"),
                    replay_started_at=replay_started_at,
                    queue_wait_ms=queue_wait_ms,
                    failure_payload={"phase": "replay_prepare", "command": self._command_payload(prepare_res)},
                )

        if self.config.coverage_reset_cmd:
            reset_res = run_command(
                self.config.render_command(self.config.coverage_reset_cmd, seed_path=seed.queue_path),
                timeout=self.config.coverage_reset_timeout_sec or self.config.command_timeout_sec,
            )
            if reset_res.returncode != 0:
                return self._build_failure_result(
                    seed=seed,
                    deltas=[],
                    last_snapshot=CoverageSnapshot(),
                    step_index=0,
                    reason=_result_reason("coverage-reset-failed", step_index=0, detail=f"rc={reset_res.returncode}"),
                    replay_started_at=replay_started_at,
                    queue_wait_ms=queue_wait_ms,
                    failure_payload={
                        "phase": "coverage_reset",
                        "command": self._command_payload(reset_res),
                        "per_message_reset": self.config.per_message_reset,
                    },
                )

        replay_res = run_command(
            self.config.render_command(
                self.config.replay_cmd,
                seed_path=seed.queue_path,
                protocol=self.config.protocol,
                host=self.config.replay_host,
                port=self.config.replay_port,
            ),
            env=env,
            timeout=replay_timeout,
        )
        if self.config.replay_cleanup_cmd:
            run_command(
                self.config.render_command(self.config.replay_cleanup_cmd, seed_path=seed.queue_path),
                timeout=self.config.replay_cleanup_timeout_sec or self.config.command_timeout_sec,
            )

        stdout_payload = try_load_json(replay_res.stdout)
        if not isinstance(stdout_payload, dict):
            stdout_payload = {}
        actual_replay_port = int(stdout_payload.get("port") or self.config.replay_port or 0)
        effective_trace_path = Path(str(stdout_payload.get("trace_path") or trace_path))
        if not effective_trace_path.exists():
            deadline = time.time() + 1.0
            while time.time() < deadline and not effective_trace_path.exists():
                time.sleep(0.05)
        if not effective_trace_path.exists():
            reason = _result_reason("stream-trace-missing", step_index=0)
            if replay_res.returncode == 124:
                reason = _result_reason("replay-timeout", step_index=0, detail=f"timeout={replay_timeout}")
            return self._build_failure_result(
                seed=seed,
                deltas=[],
                last_snapshot=CoverageSnapshot(),
                step_index=0,
                reason=reason,
                replay_started_at=replay_started_at,
                queue_wait_ms=queue_wait_ms,
                replay_port=actual_replay_port,
                failure_payload={
                    "phase": "stream_trace",
                    "trace_path": str(effective_trace_path),
                    "command": self._command_payload(replay_res),
                    "timeout_sec": replay_timeout,
                    "capture_timeout_sec": safe_capture_timeout,
                },
            )

        try:
            trace_payload = json.loads(effective_trace_path.read_text(encoding="utf-8"))
        except Exception as exc:
            return self._build_failure_result(
                seed=seed,
                deltas=[],
                last_snapshot=CoverageSnapshot(),
                step_index=0,
                reason=_result_reason("stream-trace-parse-failed", step_index=0, detail=str(exc)),
                replay_started_at=replay_started_at,
                queue_wait_ms=queue_wait_ms,
                replay_port=actual_replay_port,
                failure_payload={"phase": "stream_trace", "trace_path": str(effective_trace_path), "command": self._command_payload(replay_res)},
            )

        steps = list(trace_payload.get("steps") or [])
        success_prefix_witness = _extract_success_prefix_witness(trace_payload, messages)
        prev_snapshot = CoverageSnapshot()
        deltas: list[MessageDelta] = []
        for default_idx, step in enumerate(steps):
            step_index = int(step.get("step_index") or default_idx)
            capture_rc = int(step.get("capture_returncode") or 0)
            capture_payload = step.get("capture_payload") if isinstance(step.get("capture_payload"), dict) else {}
            snapshot = _normalize_snapshot(capture_payload)
            method_name = str(step.get("method") or (message_method(messages[step_index]) if step_index < len(messages) else ""))
            preview_text = str(step.get("message_preview") or (message_preview(messages[step_index]) if step_index < len(messages) else ""))
            send_error = str(step.get("send_error") or step.get("response_error") or "").strip()
            if send_error:
                if prev_snapshot.lines or prev_snapshot.branches:
                    break
                return self._build_failure_result(
                    seed=seed,
                    deltas=deltas,
                    last_snapshot=snapshot,
                    step_index=step_index,
                    reason=_result_reason("replay-send-failed", step_index=step_index, detail=send_error),
                    replay_started_at=replay_started_at,
                    queue_wait_ms=queue_wait_ms,
                    replay_port=actual_replay_port,
                    failure_payload={"phase": "stream_send", "step": step, "command": self._command_payload(replay_res)},
                )
            if capture_rc != 0 or capture_payload.get("error"):
                detail = str(capture_payload.get("error") or f"rc={capture_rc}")
                if prev_snapshot.lines or prev_snapshot.branches:
                    break
                return self._build_failure_result(
                    seed=seed,
                    deltas=deltas,
                    last_snapshot=snapshot,
                    step_index=step_index,
                    reason=_result_reason("coverage-capture-failed", step_index=step_index, detail=detail),
                    replay_started_at=replay_started_at,
                    queue_wait_ms=queue_wait_ms,
                    replay_port=actual_replay_port,
                    failure_payload={"phase": "coverage_capture", "step": step, "command": self._command_payload(replay_res)},
                )

            delta_lines = sorted(snapshot.lines - prev_snapshot.lines)
            delta_branches = sorted(snapshot.branches - prev_snapshot.branches)
            hit_boundary, hit_vuln = self.knowledge.hit_targets_for_lines(set(snapshot.lines))
            deltas.append(
                MessageDelta(
                    step_index=step_index,
                    method=method_name,
                    message_preview=preview_text,
                    delta_lines=delta_lines,
                    cumulative_lines=sorted(snapshot.lines),
                    delta_branches=delta_branches,
                    cumulative_branches=sorted(snapshot.branches),
                    hit_boundary_target_ids=hit_boundary,
                    hit_vuln_target_ids=hit_vuln,
                )
            )
            prev_snapshot = snapshot
            self.logger.log(
                "B",
                "seed message replayed",
                seed_id=seed.seed_id,
                step_index=step_index,
                rc=replay_res.returncode,
                delta_lines=len(delta_lines),
                delta_branches=len(delta_branches),
                replay_mode="stream",
            )

        if len(steps) < len(messages):
            sender_error = str(trace_payload.get("sender_error") or "").strip()
            detail = f"steps={len(steps)},messages={len(messages)}"
            if sender_error:
                detail = f"{detail},sender_error={sender_error}"
            if prev_snapshot.lines or prev_snapshot.branches:
                return self._build_success_result(
                    seed=seed,
                    deltas=deltas,
                    snapshot=prev_snapshot,
                    replay_started_at=replay_started_at,
                    queue_wait_ms=queue_wait_ms,
                    replay_port=actual_replay_port,
                    success_prefix_witness=success_prefix_witness,
                )
            return self._build_failure_result(
                seed=seed,
                deltas=deltas,
                last_snapshot=prev_snapshot,
                step_index=len(steps),
                reason=_result_reason("stream-incomplete", step_index=len(steps), detail=detail),
                replay_started_at=replay_started_at,
                queue_wait_ms=queue_wait_ms,
                replay_port=actual_replay_port,
                failure_payload={"phase": "stream_trace", "trace_path": str(effective_trace_path), "command": self._command_payload(replay_res)},
            )

        if replay_res.returncode != 0:
            detail = f"rc={replay_res.returncode}"
            if replay_res.returncode == 124:
                detail = f"timeout={replay_timeout}"
            if prev_snapshot.lines or prev_snapshot.branches:
                return self._build_success_result(
                    seed=seed,
                    deltas=deltas,
                    snapshot=prev_snapshot,
                    replay_started_at=replay_started_at,
                    queue_wait_ms=queue_wait_ms,
                    replay_port=actual_replay_port,
                    success_prefix_witness=success_prefix_witness,
                )
            return self._build_failure_result(
                seed=seed,
                deltas=deltas,
                last_snapshot=prev_snapshot,
                step_index=max(0, len(steps) - 1),
                reason=_result_reason("replay-failed", step_index=max(0, len(steps) - 1), detail=detail),
                replay_started_at=replay_started_at,
                queue_wait_ms=queue_wait_ms,
                replay_port=actual_replay_port,
                failure_payload={"phase": "replay", "command": self._command_payload(replay_res), "trace_path": str(effective_trace_path)},
            )

        return self._build_success_result(
            seed=seed,
            deltas=deltas,
            snapshot=prev_snapshot,
            replay_started_at=replay_started_at,
            queue_wait_ms=queue_wait_ms,
            replay_port=actual_replay_port,
            success_prefix_witness=success_prefix_witness,
        )

    def _stream_replay_timeout(self, *, seed: SeedRecord, message_count: int) -> float:
        base_timeout = float(getattr(self.config, "replay_timeout_sec", 0) or getattr(self.config, "command_timeout_sec", 120) or 120)
        per_message = float(getattr(self.config, "stream_replay_timeout_per_message_sec", 5.0) or 5.0)
        capture_budget = float(getattr(self.config, "coverage_capture_timeout_sec", 0) or 0.0)
        estimated_timeout = 30.0 + max(1, message_count) * per_message + capture_budget
        timeout = max(base_timeout, estimated_timeout)
        if seed.metadata.get("is_initial_seed"):
            initial_cap = float(getattr(self.config, "initial_replay_timeout_sec", 0) or timeout)
            return max(timeout, initial_cap if initial_cap > 0 else timeout)
        cap = float(getattr(self.config, "stream_replay_timeout_cap_sec", 0) or timeout)
        return min(timeout, cap) if cap > 0 else timeout

    def _build_success_result(
        self,
        *,
        seed: SeedRecord,
        deltas: list[MessageDelta],
        snapshot: CoverageSnapshot,
        replay_started_at: float,
        queue_wait_ms: float,
        replay_port: int | None = None,
        success_prefix_witness: dict[str, object] | None = None,
    ) -> CoverageReplayResult:
        measurement_lane = str(seed.metadata.get("measurement_lane") or "coverage")
        global_lines_before = self.state.covered_line_keys()
        global_branches_before = self.state.covered_branch_keys()
        global_new_lines = set(snapshot.lines) - global_lines_before
        global_new_branches = set(snapshot.branches) - global_branches_before
        new_branch_keys = sorted(global_new_branches)
        replay_accepted = bool(snapshot.lines or snapshot.branches)
        if measurement_lane == "coverage":
            self.state.note_covered_lines(seed.seed_id, set(snapshot.lines))
            self.state.note_covered_branches(seed.seed_id, set(snapshot.branches))
            self.state.mark_seed_replayed(seed.seed_id)
        witness_metadata = dict(success_prefix_witness or {})
        if witness_metadata:
            witness_metadata["replay_witness_updated_at"] = time.time()
            self.state.update_seed_metadata(seed.seed_id, witness_metadata)
        if measurement_lane == "coverage" and bool(seed.metadata.get("from_sync_partner")):
            self.state.update_seed_metadata(
                seed.seed_id,
                {
                    "first_gen_replayed": True,
                    "first_gen_replayed_at": time.time(),
                    "first_gen_new_line_count": len(global_new_lines),
                    "first_gen_new_branch_count": len(global_new_branches),
                    "first_gen_new_edge": bool(global_new_lines or global_new_branches),
                },
            )

        hit_boundary, hit_vuln = self._collect_hit_targets(deltas)
        flipped_boundary = self._detect_boundary_flips(seed=seed, snapshot=snapshot, deltas=deltas)
        scheduler_accepted = self._scheduler_accepts_replay(
            measurement_lane=measurement_lane,
            replay_accepted=replay_accepted,
            global_new_lines=len(global_new_lines),
            global_new_branches=len(global_new_branches),
            flipped_boundary_count=len(flipped_boundary),
        )
        if scheduler_accepted:
            result_reason = "ok"
        elif not replay_accepted:
            result_reason = "empty-coverage"
        elif measurement_lane == "generated-handoff":
            result_reason = "handoff-no-new-coverage"
        else:
            result_reason = f"{measurement_lane}-not-scheduler-accepted"
        result = CoverageReplayResult(
            seed_id=seed.seed_id,
            queue_path=seed.queue_path,
            measurement_lane=measurement_lane,
            accepted=scheduler_accepted,
            reason=result_reason,
            message_deltas=deltas,
            seed_total_lines=len(snapshot.lines),
            seed_new_lines=len(global_new_lines),
            seed_total_branches=len(snapshot.branches),
            seed_new_branches=len(global_new_branches),
            hit_boundary_target_ids=hit_boundary,
            hit_vuln_target_ids=hit_vuln,
            flipped_boundary_target_ids=flipped_boundary,
            replay_accepted=replay_accepted,
            scheduler_accepted=scheduler_accepted,
            global_new_lines=len(global_new_lines),
            global_new_branches=len(global_new_branches),
        )
        self._record_replay_health(result=result)
        self._record_seed_replay_observation(seed=seed, result=result, replay_started_at=replay_started_at, queue_wait_ms=queue_wait_ms)
        if measurement_lane != "coverage":
            lane_key = measurement_lane.replace('-', '_')
            self.state.update_seed_metadata(
                seed.seed_id,
                {
                    f"{lane_key}_replayed": True,
                    f"{lane_key}_replayed_at": time.time(),
                    f"{lane_key}_replay_accepted": replay_accepted,
                    f"{lane_key}_scheduler_accepted": scheduler_accepted,
                    f"{lane_key}_global_new_line_count": len(global_new_lines),
                    f"{lane_key}_global_new_branch_count": len(global_new_branches),
                },
            )
        self.state.record_event(
            kind="coverage_replay",
            subject=self.config.subject,
            protocol=self.config.protocol,
            seed_id=seed.seed_id,
            payload={
                "seed": {
                    "seed_id": seed.seed_id,
                    "queue_path": seed.queue_path,
                    "origin": seed.origin,
                    "methods": seed.methods,
                    "is_initial_seed": bool(seed.metadata.get("is_initial_seed")),
                    "replay_reason": seed.metadata.get("replay_reason", ""),
                    "task_kind": seed.metadata.get("task_kind", ""),
                    "target_id": seed.metadata.get("target_id", ""),
                    "context_kind": seed.metadata.get("context_kind", ""),
                    "expected_sha1": seed.metadata.get("expected_sha1", ""),
                    "replay_enqueued_at": seed.metadata.get("replay_enqueued_at", 0.0),
                    "replay_enqueued_via": seed.metadata.get("replay_enqueued_via", ""),
                    "measurement_lane": seed.metadata.get("measurement_lane", "coverage"),
                },
                "accepted": result.accepted,
                "replay_accepted": result.replay_accepted,
                "scheduler_accepted": result.scheduler_accepted,
                "reason": result.reason,
                "replay_port": int(replay_port or self.config.replay_port or 0),
                "seed_total_lines": result.seed_total_lines,
                "seed_new_lines": result.seed_new_lines,
                "seed_total_branches": result.seed_total_branches,
                "seed_new_branches": result.seed_new_branches,
                "global_new_lines": result.global_new_lines,
                "global_new_branches": result.global_new_branches,
                "new_branch_keys": new_branch_keys,
                "success_prefix_witness": witness_metadata,
                "replay_started_at": replay_started_at,
                "queue_wait_ms": queue_wait_ms,
                "hit_boundary_target_ids": result.hit_boundary_target_ids,
                "hit_vuln_target_ids": result.hit_vuln_target_ids,
                "flipped_boundary_target_ids": result.flipped_boundary_target_ids,
                "message_deltas": _serialize_message_deltas(deltas),
            },
        )
        if result.flipped_boundary_target_ids:
            self.logger.log(
                "B",
                "boundary target flipped",
                seed_id=seed.seed_id,
                target_ids=",".join(result.flipped_boundary_target_ids),
                replay_reason=str(seed.metadata.get("replay_reason") or "direct"),
                measurement_lane=measurement_lane,
            )
            if measurement_lane != "coverage":
                for target_id in result.flipped_boundary_target_ids:
                    self.state.mark_target_analyzed(target_id, result=f"branch-flipped:{result.seed_id}")
                self.state.update_metric("last_boundary_flip_at", time.time())
                self.state.record_event(
                    kind="boundary_flip_confirmation",
                    subject=self.config.subject,
                    protocol=self.config.protocol,
                    seed_id=seed.seed_id,
                    payload={
                        "seed_id": seed.seed_id,
                        "target_ids": result.flipped_boundary_target_ids,
                        "measurement_lane": measurement_lane,
                        "replay_reason": seed.metadata.get("replay_reason", ""),
                    },
                )
        if (
            seed.metadata.get("target_id", "").startswith("boundary:")
            and seed.metadata.get("missing_branch_key")
            and result.seed_new_branches > 0
            and not result.flipped_boundary_target_ids
        ):
            self.state.record_event(
                kind="boundary_miss_diagnostics",
                subject=self.config.subject,
                protocol=self.config.protocol,
                seed_id=seed.seed_id,
                payload={
                    "seed_id": seed.seed_id,
                    "target_id": seed.metadata.get("target_id", ""),
                    "missing_branch_key": seed.metadata.get("missing_branch_key", ""),
                    "new_branch_keys": new_branch_keys,
                    "seed_new_branches": result.seed_new_branches,
                    "queue_wait_ms": queue_wait_ms,
                    "context_kind": seed.metadata.get("context_kind", ""),
                    "scheduler_reason": seed.metadata.get("scheduler_reason", ""),
                },
            )
        if measurement_lane == "coverage":
            self._note_replay_progress(
                seed=seed,
                seed_new_lines=result.seed_new_lines,
                seed_new_branches=result.seed_new_branches,
            )
        return result

    @staticmethod
    def _scheduler_accepts_replay(
        *,
        measurement_lane: str,
        replay_accepted: bool,
        global_new_lines: int,
        global_new_branches: int,
        flipped_boundary_count: int,
    ) -> bool:
        if not replay_accepted:
            return False
        if measurement_lane == "coverage":
            return True
        if measurement_lane == "generated-handoff":
            return bool(global_new_lines > 0 or global_new_branches > 0 or flipped_boundary_count > 0)
        return False

    def _record_seed_replay_observation(
        self,
        *,
        seed: SeedRecord,
        result: CoverageReplayResult,
        replay_started_at: float,
        queue_wait_ms: float,
    ) -> None:
        self.state.record_seed_observation(
            seed_id=seed.seed_id,
            stage="replay-success" if result.replay_accepted else "replay-empty",
            lane=result.measurement_lane,
            queue_path=seed.queue_path,
            task_id=str(seed.metadata.get("task_id") or ""),
            target_id=str(seed.metadata.get("target_id") or ""),
            module=str(seed.metadata.get("task_kind") or seed.metadata.get("source") or ""),
            payload={
                "replay_accepted": result.replay_accepted,
                "scheduler_accepted": result.scheduler_accepted,
                "reason": result.reason,
                "seed_total_lines": result.seed_total_lines,
                "global_new_lines": result.global_new_lines,
                "seed_total_branches": result.seed_total_branches,
                "global_new_branches": result.global_new_branches,
                "hit_boundary_target_ids": result.hit_boundary_target_ids,
                "hit_vuln_target_ids": result.hit_vuln_target_ids,
                "flipped_boundary_target_ids": result.flipped_boundary_target_ids,
                "queue_wait_ms": queue_wait_ms,
            },
            created_at=replay_started_at,
        )

    def _record_replay_health(self, *, result: CoverageReplayResult) -> None:
        if not bool(getattr(self.config, "replay_health_check_enabled", True)):
            return
        metric = self.state.get_metric("replay_health", {}) or {}
        window_size = max(1, int(getattr(self.config, "replay_health_window_size", 64) or 64))
        min_samples = max(1, int(getattr(self.config, "replay_health_min_samples", 16) or 16))
        threshold = float(getattr(self.config, "replay_health_failure_rate_threshold", 0.75) or 0.75)
        recent = list(metric.get("recent") or [])[-(window_size - 1):]
        recent.append(1 if result.replay_accepted else 0)
        total = int(metric.get("total") or 0) + 1
        failures = int(metric.get("failures") or 0) + (0 if result.replay_accepted else 1)
        recent_failures = sum(1 for item in recent if not int(item))
        failure_rate = recent_failures / max(len(recent), 1)
        degraded = len(recent) >= min_samples and failure_rate >= threshold
        payload = {
            "total": total,
            "failures": failures,
            "recent": recent,
            "recent_count": len(recent),
            "recent_failures": recent_failures,
            "recent_failure_rate": failure_rate,
            "degraded": degraded,
            "last_reason": result.reason,
            "last_lane": result.measurement_lane,
            "updated_at": time.time(),
        }
        self.state.update_metric("replay_health", payload)
        if degraded and not bool(metric.get("degraded")):
            self.state.record_event(
                kind="replay_health_degraded",
                subject=self.config.subject,
                protocol=self.config.protocol,
                seed_id=result.seed_id,
                payload=payload,
            )
            self.logger.log("B", "replay health degraded", failure_rate=failure_rate, recent_count=len(recent), reason=result.reason)

    def _note_replay_progress(self, *, seed: SeedRecord, seed_new_lines: int, seed_new_branches: int) -> None:
        now = time.time()
        if seed.metadata.get("is_initial_seed"):
            progress = self.state.get_metric(
                "initial_replay_progress",
                {"expected_count": 0, "seed_names": [], "completed_seed_names": [], "completed": False, "started_at": 0.0, "completed_at": 0.0},
            )
            completed_seed_names = list(progress.get("completed_seed_names") or [])
            completed_name = str(seed.origin or seed.seed_id)
            if completed_name not in completed_seed_names:
                completed_seed_names.append(completed_name)
            expected_count = int(progress.get("expected_count") or 0)
            completed = bool(progress.get("completed")) or (expected_count > 0 and len(completed_seed_names) >= expected_count)
            completed_at = float(progress.get("completed_at") or 0.0)
            if completed and completed_at <= 0.0:
                completed_at = now
                self.logger.log(
                    "B",
                    "initial seed replay phase completed",
                    completed_seed_count=len(completed_seed_names),
                    expected_count=expected_count,
                )
            self.state.update_metric(
                "initial_replay_progress",
                {
                    "expected_count": expected_count,
                    "seed_names": list(progress.get("seed_names") or []),
                    "completed_seed_names": completed_seed_names,
                    "completed": completed,
                    "started_at": float(progress.get("started_at") or 0.0),
                    "completed_at": completed_at,
                },
            )
        if seed_new_lines > 0 or seed_new_branches > 0:
            self.state.update_metric("last_new_coverage_at", now)
            self.logger.log(
                "B",
                "new global coverage observed",
                seed_id=seed.seed_id,
                seed_new_lines=seed_new_lines,
                seed_new_branches=seed_new_branches,
            )

    def _capture_snapshot(self, *, seed_id: str, step_index: int) -> tuple[CoverageSnapshot, dict, CommandResult]:
        argv = self.config.render_command(
            self.config.coverage_capture_cmd,
            seed_id=seed_id,
            step_index=step_index,
        )
        env = dict(self.config.coverage_capture_env)
        result = run_command(argv, env=env, timeout=self.config.coverage_capture_timeout_sec or self.config.command_timeout_sec)
        payload = try_load_json(result.stdout)
        if payload is None:
            out = result.stdout.strip()
            path = Path(out)
            if out and path.exists():
                payload = json.loads(path.read_text(encoding="utf-8"))
            else:
                payload = {"lines": [], "branches": [], "stdout": result.stdout, "stderr": result.stderr}
        if not isinstance(payload, dict):
            payload = {"lines": [], "branches": [], "raw_payload": payload}
        return _normalize_snapshot(payload), payload, result

    @staticmethod
    def _command_payload(result: CommandResult) -> dict:
        return {
            "argv": list(result.argv),
            "returncode": int(result.returncode),
            "stdout": result.stdout,
            "stderr": result.stderr,
        }

    @staticmethod
    def _collect_hit_targets(deltas: list[MessageDelta]) -> tuple[list[str], list[str]]:
        hit_boundary = []
        hit_vuln = []
        for delta in deltas:
            for target_id in delta.hit_boundary_target_ids:
                if target_id not in hit_boundary:
                    hit_boundary.append(target_id)
            for target_id in delta.hit_vuln_target_ids:
                if target_id not in hit_vuln:
                    hit_vuln.append(target_id)
        return hit_boundary, hit_vuln

    @staticmethod
    def _detect_boundary_flips(*, seed: SeedRecord, snapshot: CoverageSnapshot, deltas: list[MessageDelta]) -> list[str]:
        target_id = str(seed.metadata.get("target_id") or "").strip()
        missing_branch_key = str(seed.metadata.get("missing_branch_key") or "").strip()
        if not target_id.startswith("boundary:") or not missing_branch_key:
            return []
        if missing_branch_key not in snapshot.branches:
            return []
        return [target_id]

    def _build_failure_result(
        self,
        *,
        seed: SeedRecord,
        deltas: list[MessageDelta],
        last_snapshot: CoverageSnapshot,
        step_index: int,
        reason: str,
        replay_started_at: float,
        queue_wait_ms: float,
        replay_port: int | None = None,
        failure_payload: dict,
    ) -> CoverageReplayResult:
        hit_boundary, hit_vuln = self._collect_hit_targets(deltas)
        self.state.record_event(
            kind="coverage_replay",
            subject=self.config.subject,
            protocol=self.config.protocol,
            seed_id=seed.seed_id,
            payload={
                "seed": {
                    "seed_id": seed.seed_id,
                    "queue_path": seed.queue_path,
                    "origin": seed.origin,
                    "methods": seed.methods,
                    "is_initial_seed": bool(seed.metadata.get("is_initial_seed")),
                    "replay_reason": seed.metadata.get("replay_reason", ""),
                    "task_kind": seed.metadata.get("task_kind", ""),
                    "target_id": seed.metadata.get("target_id", ""),
                    "context_kind": seed.metadata.get("context_kind", ""),
                    "expected_sha1": seed.metadata.get("expected_sha1", ""),
                    "replay_enqueued_at": seed.metadata.get("replay_enqueued_at", 0.0),
                    "replay_enqueued_via": seed.metadata.get("replay_enqueued_via", ""),
                    "measurement_lane": seed.metadata.get("measurement_lane", "coverage"),
                },
                "accepted": False,
                "replay_accepted": False,
                "scheduler_accepted": False,
                "reason": reason,
                "replay_port": int(replay_port or self.config.replay_port or 0),
                "seed_total_lines": len(last_snapshot.lines),
                "seed_new_lines": 0,
                "seed_total_branches": len(last_snapshot.branches),
                "seed_new_branches": 0,
                "replay_started_at": replay_started_at,
                "queue_wait_ms": queue_wait_ms,
                "hit_boundary_target_ids": hit_boundary,
                "hit_vuln_target_ids": hit_vuln,
                "message_deltas": _serialize_message_deltas(deltas),
                "failure": failure_payload,
            },
        )
        self.logger.log("B", "seed replay failed", seed_id=seed.seed_id, step_index=step_index, reason=reason)
        if str(seed.metadata.get("measurement_lane") or "coverage") == "coverage":
            self._note_replay_progress(seed=seed, seed_new_lines=0, seed_new_branches=0)
        result = CoverageReplayResult(
            seed_id=seed.seed_id,
            queue_path=seed.queue_path,
            measurement_lane=str(seed.metadata.get("measurement_lane") or "coverage"),
            accepted=False,
            reason=reason,
            message_deltas=deltas,
            seed_total_lines=len(last_snapshot.lines),
            seed_new_lines=0,
            seed_total_branches=len(last_snapshot.branches),
            seed_new_branches=0,
            hit_boundary_target_ids=hit_boundary,
            hit_vuln_target_ids=hit_vuln,
            flipped_boundary_target_ids=[],
            replay_accepted=False,
            scheduler_accepted=False,
            global_new_lines=0,
            global_new_branches=0,
        )
        self._record_replay_health(result=result)
        self.state.record_seed_observation(
            seed_id=seed.seed_id,
            stage="replay-failed",
            lane=result.measurement_lane,
            queue_path=seed.queue_path,
            task_id=str(seed.metadata.get("task_id") or ""),
            target_id=str(seed.metadata.get("target_id") or ""),
            module=str(seed.metadata.get("task_kind") or seed.metadata.get("source") or ""),
            payload={
                "reason": reason,
                "step_index": step_index,
                "queue_wait_ms": queue_wait_ms,
                "failure": failure_payload,
            },
            created_at=replay_started_at,
        )
        return result
