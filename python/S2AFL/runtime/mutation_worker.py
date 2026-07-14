"""LLM mutation worker for workflow2 runtime.

The worker consumes scheduler tasks one by one, asks the configured LLM for a
concrete mutation plan, repairs malformed candidates when possible, and injects
accepted seeds back into AFLNet without breaking multi-message protocol order.
"""

from __future__ import annotations

import json
import os
import ast
import re
import shutil
import threading
import time
import traceback
from pathlib import Path
from typing import Any

from .aflnet import AFLNetSyncInjector
from .config import RuntimeConfig
from .knowledge_loader import RuntimeKnowledge
from .llm import RuntimeLLMClient
from .logging_utils import RuntimeLogger
from .mutation_executor import GeneratedSeedCandidate, SpecDrivenMutationExecutor
from .models import SeedRecord
from .protocol_policy import function_allows_single_message, get_protocol_policy
from .seed_utils import body_sha1, load_seed_file, message_method, parse_markdown_seed_block, split_seed_messages
from .state_db import RuntimeStateDB


_DECISION_RE = re.compile(r"^\s*DECISION\s*:\s*(GENERATE|SKIP)\s*$", re.IGNORECASE | re.MULTILINE)
_REASON_RE = re.compile(r"^\s*REASON\s*:\s*(.+)$", re.IGNORECASE | re.MULTILINE)
_SAFE_TAG_RE = re.compile(r"[^A-Za-z0-9._-]+")
_AGENT_PLAN_MAX_TOKENS = 1100
_AGENT_REVISE_MAX_TOKENS = 1100
_AGENT_GENERATE_MAX_TOKENS = 3200
_AGENT_REPAIR_MAX_TOKENS = 3200
_MAX_REPAIR_ATTEMPTS = 2
_TEXT_CLIP = 1600
_NONRECOVERABLE_CRITIC_PREFIXES = (
    "unsupported-trigger-class-",
    "stateful-source-seed-",
)
_NONRECOVERABLE_CRITIC_REASONS = {
    "plan-requested-more-evidence",
}
_SUPPORTED_TRIGGER_CLASSES = {
    "plain_field",
    "state_sequence",
    "overlong_line_error_path",
    "multipart_body_state",
    "missing_delimiter_bounded_slice",
    "size_sensitive_copy",
    "format_string",
}
_UNSUPPORTED_TRIGGER_CLASSES = {
    "temporal_wait",
    "data_channel_fault",
    "filesystem_race",
    "config_policy",
    "external_oracle",
}
_TRIGGER_CLASS_ALIASES = {
    "field": "plain_field",
    "field_value": "plain_field",
    "sequence": "state_sequence",
    "repeat_sequence": "state_sequence",
    "overlong_command": "overlong_line_error_path",
    "long_command": "overlong_line_error_path",
    "multipart": "multipart_body_state",
    "multipart_sdp": "multipart_body_state",
    "unterminated_slice": "missing_delimiter_bounded_slice",
    "missing_delimiter": "missing_delimiter_bounded_slice",
    "delay": "temporal_wait",
    "wait": "temporal_wait",
    "transport_fault": "data_channel_fault",
    "race": "filesystem_race",
}


class MutationWorker(threading.Thread):
    """LLM worker: consume boundary/vuln tasks serially, generate seeds, and inject them."""

    daemon = True

    def __init__(
        self,
        *,
        config: RuntimeConfig,
        state: RuntimeStateDB,
        knowledge: RuntimeKnowledge,
        injector: AFLNetSyncInjector,
        replay_queue,
        flip_confirmation_queue,
        logger: RuntimeLogger,
        stop_event: threading.Event,
    ):
        super().__init__(name="MutationWorker")
        self.config = config
        self.state = state
        self.knowledge = knowledge
        self.injector = injector
        self.replay_queue = replay_queue
        self.flip_confirmation_queue = flip_confirmation_queue
        self.logger = logger
        self._flip_confirmation_targets_seen: set[str] = set()
        self.stop_event = stop_event
        self.llm = RuntimeLLMClient(config)
        self.policy = get_protocol_policy(config.protocol)
        self.executor = SpecDrivenMutationExecutor(protocol=config.protocol, policy=self.policy)
        self.trace_dir = self.logger.log_dir / "mutator_traces"
        self.trace_dir.mkdir(parents=True, exist_ok=True)

    def run(self) -> None:
        self.logger.log("Mutator", "mutation worker started")
        while not self.stop_event.is_set():
            task = self.state.claim_next_task(self.name)
            if not task:
                self.stop_event.wait(1.0)
                continue
            try:
                self._run_task(task)
            except Exception as exc:
                task_id = task.get("task_id", "")
                result = {"reason": f"worker-exception:{type(exc).__name__}: {exc}"}
                if task_id:
                    self.state.finish_task(task_id, "failed", result)
                self.logger.log(
                    "Mutator",
                    "task crashed",
                    task_id=task_id,
                    error=str(exc),
                    traceback=traceback.format_exc(),
                )

    def _task_trace_dir(self, task_id: str) -> Path:
        path = self.trace_dir / (task_id or "unknown-task")
        path.mkdir(parents=True, exist_ok=True)
        return path

    def _write_task_trace(self, task_id: str, name: str, payload: dict[str, Any]) -> None:
        record = {"ts": time.time(), **payload}
        task_dir = self._task_trace_dir(task_id)
        target = task_dir / f"{name}.json"
        target.write_text(json.dumps(record, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        index = self.trace_dir / "index.jsonl"
        with index.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps({"task_id": task_id, "name": name, "path": str(target), "ts": record["ts"]}, ensure_ascii=False) + "\n")

    def _record_llm_usage(self, task: dict[str, Any], llm_result: Any, *, stage: str) -> None:
        module = "boundary" if task.get("kind") == "boundary-generate" else "vuln"
        self.state.add_llm_usage(
            module=module,
            input_tokens=llm_result.input_tokens,
            output_tokens=llm_result.output_tokens,
            reasoning_tokens=llm_result.reasoning_tokens,
            calls=1,
            metadata={
                "subject": self.config.subject,
                "protocol": self.config.protocol,
                "task_id": task.get("task_id", ""),
                "target_id": task.get("target_id", ""),
                "seed_id": task.get("seed_id"),
                "task_kind": task.get("kind", ""),
                "agent_stage": stage,
            },
        )

    def _run_task(self, task: dict[str, Any]) -> None:
        task_id = task["task_id"]
        payload = dict(task.get("payload_json") or {})
        self._write_task_trace(task_id, "00-task", {"task": task, "payload": payload})
        target_row = self.state.get_target_row(task["target_id"])
        seed_row = self.state.get_seed_row(task["seed_id"])
        if not target_row or not seed_row:
            result = {"reason": "missing-target-or-seed"}
            self.state.finish_task(task_id, "failed", result)
            self.logger.log("Mutator", "task failed", task_id=task_id, reason=result["reason"])
            return

        if task.get("kind") == "vuln-generate":
            staged_result = self._try_inject_staged_vuln_seed(task)
            if staged_result is not None:
                self.state.finish_task(task_id, "completed", staged_result)
                self.logger.log(
                    "Mutator",
                    "staged vuln seed injected",
                    task_id=task_id,
                    injected_path=staged_result["injected_path"],
                    source_seed=staged_result.get("staged_seed_name", ""),
                )
                return

        context_seed = self._prepare_context_seed(seed_row)
        if task.get("kind") == "boundary-generate" and context_seed.get("ok"):
            context_seed = self._retarget_boundary_context_seed(seed_row=seed_row, target_row=target_row, context_seed=context_seed)
            self._downgrade_boundary_payload_if_needed(task=task, payload=payload, context_seed=context_seed)
        if not context_seed["ok"]:
            result = {"reason": context_seed["reason"]}
            self.state.finish_task(task_id, "completed", result)
            if task.get("kind") not in {"boundary-generate", "vuln-generate"}:
                self.state.mark_target_analyzed(task["target_id"], result=f"skip:{result['reason']}")
            self._write_task_trace(task_id, "01-context", {
                "target_row": target_row,
                "seed_row": seed_row,
                "context_seed": context_seed,
            })
            self._write_task_trace(task_id, "99-final", {"status": "completed", "result": result})
            self.logger.log("Mutator", "task skipped", task_id=task_id, reason=result["reason"])
            return

        seed_text = context_seed["seed_text"]
        messages = split_seed_messages(self.config.protocol, seed_text)
        step_index = self._resolve_task_step_index(task=task, payload=payload, target_row=target_row, messages=messages)
        if step_index > 0:
            upgraded_context_seed = self._retarget_stateful_context_seed(
                seed_row=seed_row,
                context_seed=context_seed,
                required_prefix_messages=step_index,
            )
            if upgraded_context_seed.get("seed_text") and upgraded_context_seed.get("seed_text") != context_seed.get("seed_text"):
                context_seed = upgraded_context_seed
                seed_text = context_seed["seed_text"]
                messages = split_seed_messages(self.config.protocol, seed_text)
                step_index = self._resolve_task_step_index(task=task, payload=payload, target_row=target_row, messages=messages)
        context = self.knowledge.seed_context_for_task(
            target_row=target_row,
            seed_text=seed_text,
            messages=messages,
            step_index=step_index,
        )
        context = self._enrich_context_with_replay_contract(context, context_seed)
        boundary_context_error = self._validate_boundary_context(task=task, payload=payload, target_row=target_row, context=context, context_seed=context_seed)
        self._write_task_trace(task_id, "01-context", {
            "target_row": target_row,
            "seed_row": seed_row,
            "message_count": len(messages),
            "step_index": step_index,
            "context": context,
            "context_seed": {k: v for k, v in context_seed.items() if k != "seed_text"},
            "boundary_context_error": boundary_context_error,
        })
        if boundary_context_error:
            result = {"reason": boundary_context_error}
            self.state.finish_task(task_id, "failed", result)
            self._write_task_trace(task_id, "99-final", {"status": "failed", "result": result})
            self.logger.log("Mutator", "task failed", task_id=task_id, reason=result["reason"])
            return
        agent_result = self._run_agent(task, target_row, context, payload, seed_text)
        if not agent_result["ok"]:
            result = {
                "reason": agent_result["reason"],
                "decision": agent_result.get("decision", "SKIP"),
                "input_tokens": agent_result["input_tokens"],
                "output_tokens": agent_result["output_tokens"],
                "reasoning_tokens": agent_result["reasoning_tokens"],
                "agent_stage": agent_result.get("agent_stage", ""),
                "finish_reason": agent_result.get("finish_reason", ""),
            }
            self.state.finish_task(task_id, "failed", result)
            if task.get("kind") not in {"boundary-generate", "vuln-generate"}:
                self.state.mark_target_analyzed(task["target_id"], result=f"failed:{result['reason']}")
            self._write_task_trace(task_id, "99-final", {"status": "failed", "result": result})
            self.logger.log("Mutator", "task failed", task_id=task_id, reason=result["reason"], agent_stage=result["agent_stage"])
            return

        if agent_result["decision"] == "SKIP":
            result = {
                "reason": agent_result["reason"] or "agent-declined",
                "decision": "SKIP",
                "input_tokens": agent_result["input_tokens"],
                "output_tokens": agent_result["output_tokens"],
                "reasoning_tokens": agent_result["reasoning_tokens"],
                "agent_stage": agent_result.get("agent_stage", "plan"),
                "finish_reason": agent_result.get("finish_reason", ""),
            }
            self.state.finish_task(task_id, "completed", result)
            if task.get("kind") not in {"boundary-generate", "vuln-generate"}:
                self.state.mark_target_analyzed(task["target_id"], result=f"skip:{result['reason']}")
            elif task.get("kind") == "boundary-generate":
                self._maybe_retire_boundary_target(task, result)
            self._write_task_trace(task_id, "99-final", {"status": "completed", "result": result})
            self.logger.log("Mutator", "task skipped", task_id=task_id, reason=result["reason"], agent_stage=result["agent_stage"])
            return

        normalized_candidates = list(agent_result.get("mutated_seeds") or [])
        if not normalized_candidates:
            normalized_candidates = [agent_result["mutated_seed"]]
        inject_limit = max(1, min(len(normalized_candidates), int(agent_result.get("inject_limit") or 1)))
        origin_base = self._safe_origin_tag(task["kind"], task["target_id"])
        injected_paths: list[str] = []
        for idx, normalized_candidate in enumerate(normalized_candidates[:inject_limit]):
            origin_tag = origin_base if inject_limit == 1 else f"{origin_base}-{idx:02d}"
            candidate_hash = body_sha1(normalized_candidate)
            injected = self.injector.inject_seed(normalized_candidate, origin_tag=origin_tag)
            injected_paths.append(str(injected))
            self._enqueue_generated_seed(normalized_candidate, injected, task=task, payload=payload, expected_sha1=candidate_hash)
            self.state.record_event(
                kind="seed_injected",
                subject=self.config.subject,
                protocol=self.config.protocol,
                seed_id=task["seed_id"],
                payload={
                    "task_id": task_id,
                    "target_id": task["target_id"],
                    "task_kind": task["kind"],
                    "injected_path": str(injected),
                    "reason": agent_result["reason"] or "generated",
                    "repair_attempts": agent_result.get("repair_attempts", 0),
                    "candidate_index": idx,
                },
            )
        result = {
            "reason": agent_result["reason"] or "generated",
            "decision": "GENERATE",
            "injected_path": injected_paths[0],
            "injected_paths": injected_paths,
            "injected_count": len(injected_paths),
            "input_tokens": agent_result["input_tokens"],
            "output_tokens": agent_result["output_tokens"],
            "reasoning_tokens": agent_result["reasoning_tokens"],
            "repair_attempts": agent_result.get("repair_attempts", 0),
            "agent_stage": agent_result.get("agent_stage", "execute"),
        }
        self.state.finish_task(task_id, "completed", result)
        if task.get("kind") not in {"boundary-generate", "vuln-generate"}:
            self.state.mark_target_analyzed(task["target_id"], result=f"generated:{Path(injected_paths[0]).name}")
        self._write_task_trace(task_id, "99-final", {"status": "completed", "result": result, "normalized_candidates": normalized_candidates[:inject_limit]})
        self.logger.log(
            "Mutator",
            "task completed",
            task_id=task_id,
            injected_count=len(injected_paths),
            injected_path=injected_paths[0],
            repair_attempts=result["repair_attempts"],
        )

    def _downgrade_boundary_payload_if_needed(self, *, task: dict[str, Any], payload: dict[str, Any], context_seed: dict[str, Any]) -> None:
        if task.get("kind") != "boundary-generate":
            return
        if str(payload.get("reason") or "") != "uncovered-branch-side":
            return
        context_kind = str(context_seed.get("boundary_context_kind") or payload.get("context_kind") or "").strip()
        if context_kind == "branch-exact":
            return
        original_reason = payload.get("reason", "")
        payload["reason"] = "stagnation-boundary-target"
        payload["context_kind"] = context_kind or "retargeted"
        payload["downgraded_from_reason"] = original_reason
        payload.pop("missing_branch_key", None)
        payload.pop("covered_branch_key", None)
        payload.pop("covered_branch_side", None)
        payload.pop("missing_branch_side", None)
        context_seed["boundary_context_downgraded"] = True
        self.state.record_event(
            kind="boundary_context_downgraded",
            subject=self.config.subject,
            protocol=self.config.protocol,
            seed_id=task.get("seed_id"),
            payload={
                "task_id": task.get("task_id", ""),
                "target_id": task.get("target_id", ""),
                "from_reason": original_reason,
                "to_reason": payload["reason"],
                "context_kind": payload["context_kind"],
            },
        )

    def _run_agent(
        self,
        task: dict[str, Any],
        target_row: dict[str, Any],
        context: dict[str, Any],
        payload: dict[str, Any],
        seed_text: str,
    ) -> dict[str, Any]:
        usage = {"input_tokens": 0, "output_tokens": 0, "reasoning_tokens": 0}
        critic_fallback_findings: list[dict[str, Any]] = []

        plan_result = self._plan_mutation(task, target_row, context, payload)
        self._write_task_trace(task["task_id"], "10-plan-result", plan_result)
        self._merge_usage(usage, plan_result)
        if not plan_result["ok"]:
            return {**plan_result, **usage}
        if plan_result["decision"] == "SKIP":
            return {**plan_result, **usage}

        plan_payload = self._sanitize_plan_payload(plan_result.get("payload") or {}, context, target_row, task)
        self._write_task_trace(task["task_id"], "11-plan-sanitized", {"plan_payload": plan_payload})

        quality_findings = self._plan_quality_findings(plan_payload, context, target_row, task)
        quality_findings.extend(self._plan_effect_findings(seed_text, context, plan_payload, task.get("kind", "")))
        self._write_task_trace(task["task_id"], "13-plan-critic", {"findings": quality_findings})
        if self._has_hard_plan_findings(quality_findings):
            mechanical_revision = self._mechanically_revise_plan(task, target_row, context, plan_payload, quality_findings)
            if mechanical_revision is not None:
                revised_payload, revised_mode = mechanical_revision
                revised_findings = self._plan_quality_findings(revised_payload, context, target_row, task)
                self._write_task_trace(
                    task["task_id"],
                    "14-plan-revise-mechanical",
                    {"mode": revised_mode, "plan_payload": revised_payload, "findings": revised_findings},
                )
                if not self._has_hard_plan_findings(revised_findings):
                    plan_payload = revised_payload
                    quality_findings = revised_findings
            if self._has_hard_plan_findings(quality_findings):
                revise_result = self._revise_plan(task, target_row, context, payload, plan_payload, quality_findings)
                self._write_task_trace(task["task_id"], "14-plan-revise-result", revise_result)
                self._merge_usage(usage, revise_result)
                if revise_result.get("ok") and revise_result.get("decision") != "SKIP":
                    revised_payload = self._sanitize_plan_payload(revise_result.get("payload") or {}, context, target_row, task)
                    revised_findings = self._plan_quality_findings(revised_payload, context, target_row, task)
                    self._write_task_trace(
                        task["task_id"],
                        "15-plan-revise-sanitized",
                        {"plan_payload": revised_payload, "findings": revised_findings},
                    )
                    if not self._has_hard_plan_findings(revised_findings):
                        plan_payload = revised_payload
                        quality_findings = revised_findings
            if self._has_hard_plan_findings(quality_findings):
                fallback_attempt = self._try_execution_fallback(
                    task,
                    target_row,
                    context,
                    payload,
                    seed_text,
                    plan_payload,
                    trigger_reason="critic-hard-findings",
                    trace_name_prefix="17-critic-execution-fallback",
                )
                if fallback_attempt is not None:
                    self._write_task_trace(task["task_id"], "17-critic-execution-fallback", fallback_attempt)
                    fallback_result = fallback_attempt["result"]
                    if fallback_result.get("ok") and fallback_result.get("decision") != "SKIP":
                        return {
                            "ok": True,
                            "decision": "GENERATE",
                            "reason": fallback_result.get("reason") or plan_result.get("reason") or "generated-from-fallback",
                            "mutated_seed": fallback_result["mutated_seeds"][0],
                            "mutated_seeds": fallback_result["mutated_seeds"],
                            "candidate_summaries": fallback_result.get("candidate_summaries", []),
                            "inject_limit": fallback_result.get("inject_limit", 1),
                            "agent_stage": "execute-fallback",
                            "repair_attempts": 0,
                            **usage,
                        }
                if self._critic_findings_allow_synthesis(quality_findings):
                    critic_fallback_findings = list(quality_findings)
                    self._write_task_trace(
                        task["task_id"],
                        "16-plan-critic-fallback",
                        {"findings": critic_fallback_findings, "mode": "synthesis-only"},
                    )
                else:
                    hard_reasons = [item.get("reason", "plan-quality-rejected") for item in quality_findings if item.get("severity") == "hard"]
                    return {
                        "ok": True,
                        "decision": "SKIP",
                        "reason": hard_reasons[0] if hard_reasons else "plan-quality-rejected",
                        "agent_stage": "critic",
                        "finish_reason": plan_result.get("finish_reason", ""),
                        **usage,
                    }

        if critic_fallback_findings:
            synthesis_result = self._synthesize_seed_candidate(
                task,
                target_row,
                context,
                payload,
                seed_text,
                plan_payload,
                critic_findings=critic_fallback_findings,
            )
            synthesis_result["executor_fallback_reason"] = "critic-hard-findings"
            self._write_task_trace(task["task_id"], "19-synthesis-result", synthesis_result)
            self._merge_usage(usage, synthesis_result)
            if synthesis_result.get("ok") and synthesis_result.get("decision") != "SKIP":
                return {
                    "ok": True,
                    "decision": "GENERATE",
                    "reason": synthesis_result.get("reason") or plan_result.get("reason") or "generated-by-agent",
                    "mutated_seed": synthesis_result["mutated_seed"],
                    "mutated_seeds": [synthesis_result["mutated_seed"]],
                    "candidate_summaries": synthesis_result.get("candidate_summaries", []),
                    "inject_limit": 1,
                    "agent_stage": synthesis_result.get("agent_stage", "generate"),
                    "repair_attempts": synthesis_result.get("repair_attempts", 0),
                    **usage,
                }
            hard_reasons = [item.get("reason", "plan-quality-rejected") for item in quality_findings if item.get("severity") == "hard"]
            return {
                "ok": True,
                "decision": "SKIP",
                "reason": synthesis_result.get("reason") or (hard_reasons[0] if hard_reasons else "plan-quality-rejected"),
                "agent_stage": synthesis_result.get("agent_stage", "generate"),
                "finish_reason": plan_result.get("finish_reason", ""),
                **usage,
            }

        execution_result = self._execute_plan_candidates(task, target_row, context, payload, seed_text, plan_payload)
        self._write_task_trace(task["task_id"], "20-executor-result", execution_result)
        if execution_result.get("ok") and execution_result.get("decision") != "SKIP":
            return {
                "ok": True,
                "decision": "GENERATE",
                "reason": execution_result.get("reason") or plan_result.get("reason") or "generated-from-spec",
                "mutated_seed": execution_result["mutated_seeds"][0],
                "mutated_seeds": execution_result["mutated_seeds"],
                "candidate_summaries": execution_result.get("candidate_summaries", []),
                "inject_limit": execution_result.get("inject_limit", 1),
                "agent_stage": "execute",
                "repair_attempts": 0,
                **usage,
            }

        fallback_attempt = self._try_execution_fallback(
            task,
            target_row,
            context,
            payload,
            seed_text,
            plan_payload,
            trigger_reason=str(execution_result.get("reason") or ""),
            trace_name_prefix="18-execution-fallback",
        )
        if fallback_attempt is not None:
            self._write_task_trace(task["task_id"], "18-execution-fallback", fallback_attempt)
            fallback_result = fallback_attempt["result"]
            if fallback_result.get("ok") and fallback_result.get("decision") != "SKIP":
                return {
                    "ok": True,
                    "decision": "GENERATE",
                    "reason": fallback_result.get("reason") or plan_result.get("reason") or "generated-from-fallback",
                    "mutated_seed": fallback_result["mutated_seeds"][0],
                    "mutated_seeds": fallback_result["mutated_seeds"],
                    "candidate_summaries": fallback_result.get("candidate_summaries", []),
                    "inject_limit": fallback_result.get("inject_limit", 1),
                    "agent_stage": "execute-fallback",
                    "repair_attempts": 0,
                    **usage,
                }
            if fallback_result.get("decision") == "SKIP":
                return {**fallback_result, "finish_reason": plan_result.get("finish_reason", ""), **usage}
            execution_result = fallback_result

        if execution_result.get("decision") == "SKIP":
            return {**execution_result, "finish_reason": plan_result.get("finish_reason", ""), **usage}

        synthesis_result = self._synthesize_seed_candidate(
            task,
            target_row,
            context,
            payload,
            seed_text,
            plan_payload,
            critic_findings=critic_fallback_findings,
        )
        synthesis_result["executor_fallback_reason"] = execution_result.get("reason", "")
        self._write_task_trace(task["task_id"], "19-synthesis-result", synthesis_result)
        self._merge_usage(usage, synthesis_result)
        if synthesis_result.get("ok") and synthesis_result.get("decision") != "SKIP":
            return {
                "ok": True,
                "decision": "GENERATE",
                "reason": synthesis_result.get("reason") or plan_result.get("reason") or "generated-by-agent",
                "mutated_seed": synthesis_result["mutated_seed"],
                "mutated_seeds": [synthesis_result["mutated_seed"]],
                "candidate_summaries": synthesis_result.get("candidate_summaries", []),
                "inject_limit": 1,
                "agent_stage": synthesis_result.get("agent_stage", "generate"),
                "repair_attempts": synthesis_result.get("repair_attempts", 0),
                **usage,
            }
        return {**execution_result, "finish_reason": plan_result.get("finish_reason", ""), **usage}

    def _synthesize_seed_candidate(
        self,
        task: dict[str, Any],
        target_row: dict[str, Any],
        context: dict[str, Any],
        payload: dict[str, Any],
        seed_text: str,
        plan_payload: dict[str, Any],
        *,
        critic_findings: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        generate_result = self._generate_candidate(
            task,
            target_row,
            context,
            payload,
            seed_text,
            plan_payload,
            critic_findings=critic_findings,
        )
        if not generate_result.get("ok"):
            return generate_result
        if generate_result.get("decision") == "SKIP":
            return generate_result

        candidate = generate_result.get("candidate")
        repair_attempts = 0
        repair_history: list[dict[str, Any]] = []
        normalized: str | None = None
        validation_error = ""
        candidate_hash = ""
        duplicate_reason = ""
        while True:
            normalized, validation_error = self._validate_candidate_seed(
                candidate,
                original_seed=seed_text,
                plan_payload=plan_payload,
                context=context,
                target_row=target_row,
            )
            candidate_hash = body_sha1(normalized) if normalized else ""
            duplicate_reason = ""
            if normalized and self.state.has_seed_body_sha1(candidate_hash):
                duplicate_reason = "seed-duplicate-known"
            if normalized and not duplicate_reason:
                break
            if repair_attempts >= _MAX_REPAIR_ATTEMPTS:
                break
            repair_attempts += 1
            failure_reason = validation_error or duplicate_reason or "agent-seed-invalid"
            repair_result = self._repair_candidate(
                task,
                target_row,
                context,
                payload,
                seed_text,
                plan_payload,
                candidate or "",
                failure_reason,
                repair_attempts,
                critic_findings=critic_findings,
            )
            repair_history.append(
                {
                    "attempt": repair_attempts,
                    "ok": repair_result.get("ok"),
                    "decision": repair_result.get("decision"),
                    "reason": repair_result.get("reason", ""),
                    "validation_error": failure_reason,
                }
            )
            self._merge_usage(generate_result, repair_result)
            if not repair_result.get("ok") or repair_result.get("decision") == "SKIP":
                break
            candidate = repair_result.get("candidate")
        if not normalized or duplicate_reason:
            return {
                "ok": False,
                "decision": "GENERATE",
                "reason": validation_error or duplicate_reason or "agent-seed-invalid",
                "agent_stage": "generate",
                "repair_attempts": repair_attempts,
                "repair_history": repair_history,
                "candidate_summaries": [
                    {
                        "summary": "agent-full-seed",
                        "valid": False,
                        "validation_error": validation_error or duplicate_reason or "agent-seed-invalid",
                        "body_sha1": candidate_hash,
                    }
                ],
                "input_tokens": generate_result.get("input_tokens", 0),
                "output_tokens": generate_result.get("output_tokens", 0),
                "reasoning_tokens": generate_result.get("reasoning_tokens", 0),
            }

        return {
            "ok": True,
            "decision": "GENERATE",
            "reason": generate_result.get("reason") or "agent-full-seed",
            "mutated_seed": normalized,
            "agent_stage": "generate",
            "repair_attempts": repair_attempts,
            "repair_history": repair_history,
            "candidate_summaries": [
                {
                    "summary": "agent-full-seed",
                    "valid": True,
                    "validation_error": "",
                    "body_sha1": candidate_hash,
                }
            ],
            "input_tokens": generate_result.get("input_tokens", 0),
            "output_tokens": generate_result.get("output_tokens", 0),
            "reasoning_tokens": generate_result.get("reasoning_tokens", 0),
        }

    def _execute_plan_candidates(
        self,
        task: dict[str, Any],
        target_row: dict[str, Any],
        context: dict[str, Any],
        payload: dict[str, Any],
        seed_text: str,
        plan_payload: dict[str, Any],
        *,
        candidates_trace_name: str = "12-executor-candidates",
        validation_trace_name: str = "21-executor-validation",
    ) -> dict[str, Any]:
        seed_messages = split_seed_messages(self.config.protocol, seed_text)
        if not seed_messages:
            return {
                "ok": False,
                "decision": "GENERATE",
                "reason": "seed-parse-failed",
                "agent_stage": "execute",
                "input_tokens": 0,
                "output_tokens": 0,
                "reasoning_tokens": 0,
            }
        plan_payload = dict(plan_payload)
        operators = list(plan_payload.get("operators") or [])
        if not operators:
            explicit_empty = bool(plan_payload.get("operators_explicitly_empty"))
            parse_error = str(plan_payload.get("payload_parse_error") or "").strip()
            reason = "plan-has-no-valid-operators"
            decision = "GENERATE"
            if explicit_empty and not parse_error:
                reason = "plan-produced-empty-operators"
                decision = "SKIP"
            return {
                "ok": decision == "SKIP",
                "decision": decision,
                "reason": reason,
                "agent_stage": "execute",
                "input_tokens": 0,
                "output_tokens": 0,
                "reasoning_tokens": 0,
                "operator_rejections": list(plan_payload.get("sanitized_operator_rejections") or []),
                "payload_parse_error": parse_error,
            }
        target_index = int(plan_payload.get("target_message_index", context.get("step_index", 0)) or 0)
        if target_index < 0 or target_index >= len(seed_messages):
            return {
                "ok": False,
                "decision": "GENERATE",
                "reason": "target-index-out-of-range",
                "agent_stage": "execute",
                "input_tokens": 0,
                "output_tokens": 0,
                "reasoning_tokens": 0,
            }
        allow_single = bool(plan_payload.get("allow_single_message"))
        required_success_prefix = 0 if allow_single else max(0, min(len(seed_messages) - 1, target_index, int(plan_payload.get("required_success_prefix_messages") or 0)))
        preserve_prefix = 0 if allow_single else max(
            required_success_prefix,
            max(0, min(len(seed_messages) - 1, target_index, int(plan_payload.get("preserve_prefix_messages") or 0))),
        )
        plan_payload["target_message_index"] = target_index
        plan_payload["required_success_prefix_messages"] = required_success_prefix
        plan_payload["preserve_prefix_messages"] = preserve_prefix
        for item in operators:
            msg_index = item.get("msg_index")
            if msg_index is None:
                continue
            try:
                msg_index = int(msg_index)
            except (TypeError, ValueError):
                return {
                    "ok": False,
                    "decision": "GENERATE",
                    "reason": "operator-msg-index-invalid",
                    "agent_stage": "execute",
                    "input_tokens": 0,
                    "output_tokens": 0,
                    "reasoning_tokens": 0,
                }
            if msg_index < 0 or msg_index >= len(seed_messages):
                return {
                    "ok": False,
                    "decision": "GENERATE",
                    "reason": "operator-msg-index-out-of-range",
                    "agent_stage": "execute",
                    "input_tokens": 0,
                    "output_tokens": 0,
                    "reasoning_tokens": 0,
                }
            if msg_index < preserve_prefix:
                return {
                    "ok": False,
                    "decision": "GENERATE",
                    "reason": "operator-targets-preserved-prefix",
                    "agent_stage": "execute",
                    "input_tokens": 0,
                    "output_tokens": 0,
                    "reasoning_tokens": 0,
                }
        generated = self.executor.execute(
            seed_text=seed_text,
            context=context,
            plan_payload=plan_payload,
            task_kind=task.get("kind", ""),
        )
        self._write_task_trace(
            task["task_id"],
            candidates_trace_name,
            {
                "count": len(generated),
                "selector_rejections": list(plan_payload.get("selector_rejections") or []),
                "candidates": [
                    {"summary": item.summary, "mutated_fields": item.mutated_fields, "seed_text": item.seed_text}
                    for item in generated
                ],
            },
        )
        degradation = self._detect_execution_degradation(seed_text, plan_payload, generated)
        if degradation is not None:
            return {
                "ok": False,
                "decision": "GENERATE",
                "reason": "execution-degraded",
                "agent_stage": "execute",
                "input_tokens": 0,
                "output_tokens": 0,
                "reasoning_tokens": 0,
                "degradation": degradation,
                "selector_rejections": list(plan_payload.get("selector_rejections") or []),
            }
        if not generated:
            empty_diagnostic = self.executor.explain_empty_generation(
                seed_text=seed_text,
                context=context,
                plan_payload=plan_payload,
                task_kind=task.get("kind", ""),
            )
            return {
                "ok": False,
                "decision": "GENERATE",
                "reason": str((empty_diagnostic or {}).get("reason") or "executor-produced-no-candidates"),
                "agent_stage": "execute",
                "input_tokens": 0,
                "output_tokens": 0,
                "reasoning_tokens": 0,
                "selector_rejections": list(plan_payload.get("selector_rejections") or []),
                "empty_generation": empty_diagnostic or {},
            }
        valid: list[str] = []
        candidate_summaries: list[dict[str, Any]] = []
        errors: list[dict[str, Any]] = []
        seen_hashes: set[str] = set()
        for idx, candidate in enumerate(generated):
            normalized_candidate, validation_error = self._validate_candidate_seed(
                candidate.seed_text,
                original_seed=seed_text,
                plan_payload=plan_payload,
                context=context,
                target_row=target_row,
            )
            candidate_hash = body_sha1(normalized_candidate) if normalized_candidate else ""
            duplicate_reason = ""
            if normalized_candidate:
                if candidate_hash in seen_hashes:
                    duplicate_reason = "seed-duplicate-in-batch"
                elif self.state.has_seed_body_sha1(candidate_hash):
                    duplicate_reason = "seed-duplicate-known"
                else:
                    seen_hashes.add(candidate_hash)
            candidate_summaries.append(
                {
                    "index": idx,
                    "summary": candidate.summary,
                    "mutated_fields": candidate.mutated_fields,
                    "valid": bool(normalized_candidate) and not duplicate_reason,
                    "validation_error": validation_error or duplicate_reason,
                    "body_sha1": candidate_hash or "",
                }
            )
            if normalized_candidate and not duplicate_reason:
                valid.append(normalized_candidate)
            else:
                errors.append({"summary": candidate.summary, "error": validation_error or duplicate_reason or "candidate-invalid"})
        self._write_task_trace(task["task_id"], validation_trace_name, {"candidate_summaries": candidate_summaries, "errors": errors})
        if not valid:
            return {
                "ok": False,
                "decision": "GENERATE",
                "reason": errors[0]["error"] if errors else "executor-produced-only-invalid-candidates",
                "agent_stage": "execute",
                "input_tokens": 0,
                "output_tokens": 0,
                "reasoning_tokens": 0,
            }
        inject_limit = max(1, min(len(valid), int(plan_payload.get("inject_limit") or 1)))
        return {
            "ok": True,
            "decision": "GENERATE",
            "reason": str(plan_payload.get("reason") or payload.get("reason") or "generated-from-spec"),
            "mutated_seeds": valid,
            "candidate_summaries": candidate_summaries,
            "inject_limit": inject_limit,
            "agent_stage": "execute",
            "input_tokens": 0,
            "output_tokens": 0,
            "reasoning_tokens": 0,
        }

    def _plan_quality_findings(self, plan_payload: dict[str, Any], context: dict[str, Any], target_row: dict[str, Any], task: dict[str, Any]) -> list[dict[str, Any]]:
        if str(plan_payload.get("decision") or "").strip().upper() == "SKIP":
            return []
        findings: list[dict[str, Any]] = []
        if plan_payload.get("needs_evidence"):
            findings.append({"severity": "hard", "reason": "plan-requested-more-evidence"})
        hypothesis = plan_payload.get("target_hypothesis") if isinstance(plan_payload.get("target_hypothesis"), dict) else {}
        trigger_class = self._normalize_trigger_class(plan_payload.get("trigger_class") or hypothesis.get("trigger_class"))
        if not trigger_class:
            findings.append({"severity": "warn", "reason": "missing-trigger-class"})
        elif trigger_class in _UNSUPPORTED_TRIGGER_CLASSES:
            findings.append({"severity": "hard", "reason": f"unsupported-trigger-class-{trigger_class}"})
        elif trigger_class not in _SUPPORTED_TRIGGER_CLASSES:
            findings.append({"severity": "warn", "reason": f"unknown-trigger-class-{trigger_class}"})

        required = ("source_condition", "protocol_path", "controlling_field", "target_values", "expected_branch_effect")
        for key in required:
            value = hypothesis.get(key)
            if isinstance(value, list):
                missing = not any(str(item).strip() for item in value)
            else:
                missing = not str(value or "").strip()
            if missing:
                findings.append({"severity": "hard", "reason": f"missing-hypothesis-{key}"})

        try:
            target_message_index = max(0, int(plan_payload.get("target_message_index", context.get("step_index", 0)) or 0))
        except (TypeError, ValueError):
            target_message_index = max(0, int(context.get("step_index", 0) or 0))
        try:
            preserve_prefix = max(0, int(plan_payload.get("preserve_prefix_messages") or 0))
        except (TypeError, ValueError):
            preserve_prefix = 0
        replay_prefix_messages = max(0, int(context.get("replay_prefix_messages") or 0))
        success_prefix_messages = max(0, int(context.get("success_prefix_messages") or 0))
        first_failure_status_step = context.get("replay_first_failure_status_step")
        try:
            first_failure_status_step = None if first_failure_status_step in {None, "", False} else max(0, int(first_failure_status_step))
        except (TypeError, ValueError):
            first_failure_status_step = None
        if target_message_index > 0:
            if replay_prefix_messages <= 0 and success_prefix_messages <= 0:
                findings.append({"severity": "hard", "reason": "stateful-source-seed-has-no-success-prefix", "target_message_index": target_message_index})
            elif replay_prefix_messages < target_message_index:
                findings.append({
                    "severity": "hard",
                    "reason": "stateful-source-seed-prefix-too-short",
                    "target_message_index": target_message_index,
                    "replay_prefix_messages": replay_prefix_messages,
                    "success_prefix_messages": success_prefix_messages,
                })
            if first_failure_status_step is not None and first_failure_status_step < target_message_index:
                findings.append({
                    "severity": "hard",
                    "reason": "stateful-source-seed-hits-failure-before-target",
                    "target_message_index": target_message_index,
                    "failure_step": first_failure_status_step,
                })
            if bool(plan_payload.get("allow_single_message")) or preserve_prefix < target_message_index:
                findings.append({
                    "severity": "hard",
                    "reason": "stateful-plan-drops-success-prefix",
                    "target_message_index": target_message_index,
                    "preserve_prefix_messages": preserve_prefix,
                })

        operators = [item for item in plan_payload.get("operators", []) if isinstance(item, dict)]
        if not operators:
            findings.append({"severity": "hard", "reason": "plan-has-no-operators"})
            return findings

        op_names = {str(item.get("op") or "").strip().lower() for item in operators}
        if op_names == {"set_length"} and not self._target_looks_size_sensitive(target_row, context):
            findings.append({"severity": "hard", "reason": "length-only-without-size-evidence"})
        if trigger_class == "size_sensitive_copy" and op_names == {"set_length"}:
            operator_lengths = []
            for item in operators:
                for value in item.get("values", []):
                    try:
                        operator_lengths.append(int(value))
                    except (TypeError, ValueError):
                        continue
            if len(set(operator_lengths)) < 4:
                findings.append({
                    "severity": "hard",
                    "reason": "size-sensitive-needs-boundary-sweep",
                    "operator_lengths": sorted(set(operator_lengths))[:8],
                    "numeric_hints": self._extract_numeric_hints(
                        hypothesis.get("target_values"),
                        hypothesis.get("source_condition"),
                        hypothesis.get("expected_branch_effect"),
                        hypothesis.get("why_not_length_only"),
                        context.get("source_excerpt"),
                        target_row.get("code"),
                    )[:6],
                })
        if trigger_class == "state_sequence" and not self._plan_has_state_sequence_mechanism(plan_payload, context):
            findings.append({"severity": "hard", "reason": "state-sequence-without-repeat-messages"})
        if trigger_class == "multipart_body_state":
            fields = {str(item.get("field") or "").strip().lower() for item in operators}
            if "body" not in fields or "header:content-type" not in fields:
                findings.append({"severity": "warn", "reason": "multipart-body-without-content-type-and-body"})
        if trigger_class == "missing_delimiter_bounded_slice":
            fields = {str(item.get("field") or "").strip().lower() for item in operators}
            if not any(field.startswith("header:") or field in {"request_uri", "start_line", "body", "argument"} for field in fields):
                findings.append({"severity": "warn", "reason": "missing-delimiter-without-bounded-field"})

        controlling_field = self._normalize_hypothesis_text(hypothesis.get("controlling_field"))
        if controlling_field:
            operator_fields = [self._normalize_hypothesis_text(item.get("field")) for item in operators if item.get("field")]
            if operator_fields and not any(self._fields_look_related(controlling_field, field) for field in operator_fields):
                findings.append({"severity": "warn", "reason": "operator-field-differs-from-hypothesis", "controlling_field": controlling_field, "operator_fields": operator_fields[:4]})

        target_values = hypothesis.get("target_values") if isinstance(hypothesis.get("target_values"), list) else []
        if target_values and all(self._value_looks_generic(str(value)) for value in target_values):
            findings.append({"severity": "warn", "reason": "hypothesis-values-look-generic"})
        return findings

    @staticmethod
    def _has_hard_plan_findings(findings: list[dict[str, Any]]) -> bool:
        return any(item.get("severity") == "hard" for item in findings)

    @staticmethod
    def _critic_findings_allow_synthesis(findings: list[dict[str, Any]]) -> bool:
        hard_reasons = [str(item.get("reason") or "").strip() for item in findings if item.get("severity") == "hard"]
        if not hard_reasons:
            return False
        for reason in hard_reasons:
            if reason in _NONRECOVERABLE_CRITIC_REASONS:
                return False
            if any(reason.startswith(prefix) for prefix in _NONRECOVERABLE_CRITIC_PREFIXES):
                return False
        return True

    @staticmethod
    def _normalize_hypothesis_text(value: Any) -> str:
        return re.sub(r"[^a-z0-9]+", "", str(value or "").strip().lower())

    @staticmethod
    def _normalize_trigger_class(value: Any) -> str:
        normalized = re.sub(r"[^a-z0-9]+", "_", str(value or "").strip().lower()).strip("_")
        return _TRIGGER_CLASS_ALIASES.get(normalized, normalized)

    @classmethod
    def _fields_look_related(cls, left: str, right: str) -> bool:
        if not left or not right:
            return False
        return left == right or left in right or right in left

    @staticmethod
    def _value_looks_generic(value: str) -> bool:
        raw = str(value or "").strip()
        if not raw:
            return True
        lowered = raw.lower()
        if lowered in {"%n", "%s", "%x", "../", "..\\", "\\u0000", ";", "a", "aaaa", "long string", "large string"}:
            return True
        if len(raw) >= 16 and len(set(raw)) <= 2:
            return True
        return False

    def _target_looks_size_sensitive(self, target_row: dict[str, Any], context: dict[str, Any]) -> bool:
        text = " ".join(
            str(value or "")
            for value in (
                target_row.get("code"),
                target_row.get("function_name"),
                target_row.get("relative_path"),
                context.get("source_excerpt"),
            )
        ).lower()
        keywords = (
            "length", "len", "size", "content-length", "buffer", "buf", "overflow",
            "memcpy", "memmove", "strcpy", "strncpy", "strcat", "snprintf", "sprintf",
            "malloc", "realloc", "alloca", "read", "recv", "write", "copy", "format", "printf",
        )
        return any(keyword in text for keyword in keywords)

    @staticmethod
    def _extract_numeric_hints(*values: Any, limit: int = 8) -> list[int]:
        numbers: list[int] = []

        def visit(value: Any) -> None:
            if len(numbers) >= limit:
                return
            if isinstance(value, dict):
                for nested in value.values():
                    visit(nested)
                return
            if isinstance(value, (list, tuple, set)):
                for nested in value:
                    visit(nested)
                return
            text = str(value or "")
            for match in re.finditer(r"(?<![A-Za-z0-9])(\d{2,6})(?![A-Za-z0-9])", text):
                number = int(match.group(1))
                if 1 <= number <= 65536 and number not in numbers:
                    numbers.append(number)
                if len(numbers) >= limit:
                    return

        for value in values:
            visit(value)
            if len(numbers) >= limit:
                break
        return numbers

    def _repeat_count_candidates(self, plan_payload: dict[str, Any]) -> list[int]:
        hypothesis = plan_payload.get("target_hypothesis") if isinstance(plan_payload.get("target_hypothesis"), dict) else {}
        counts: list[int] = []
        for number in self._extract_numeric_hints(
            hypothesis.get("target_values"),
            hypothesis.get("state_requirements"),
            hypothesis.get("protocol_path"),
            plan_payload.get("reason"),
            limit=6,
        ):
            if number <= 1:
                continue
            bounded = max(2, min(32, number))
            if bounded not in counts:
                counts.append(bounded)
        for default in (2, 4, 8):
            if default not in counts:
                counts.append(default)
        return counts[:4]

    def _size_boundary_sweep_values(self, plan_payload: dict[str, Any], context: dict[str, Any], target_row: dict[str, Any]) -> list[int]:
        hypothesis = plan_payload.get("target_hypothesis") if isinstance(plan_payload.get("target_hypothesis"), dict) else {}
        values: list[int] = []
        for number in self._extract_numeric_hints(
            hypothesis.get("target_values"),
            hypothesis.get("source_condition"),
            hypothesis.get("expected_branch_effect"),
            hypothesis.get("why_not_length_only"),
            context.get("source_excerpt"),
            target_row.get("code"),
            limit=8,
        ):
            for candidate in (number - 1, number, number + 1):
                if 1 <= candidate <= 65536 and candidate not in values:
                    values.append(candidate)
                if len(values) >= 8:
                    return values
        for fallback in (255, 256, 511, 512, 1023, 1024, 4095, 4096, 8191, 8192):
            if fallback not in values:
                values.append(fallback)
            if len(values) >= 8:
                break
        return values[:8]

    def _plan_has_state_sequence_mechanism(self, plan_payload: dict[str, Any], context: dict[str, Any]) -> bool:
        operators = plan_payload.get("operators") if isinstance(plan_payload.get("operators"), list) else []
        op_names = {str(item.get("op") or "").strip().lower() for item in operators if isinstance(item, dict)}
        if "repeat_messages" in op_names:
            return True
        try:
            target_index = int(plan_payload.get("target_message_index", context.get("step_index", 0)) or 0)
        except (TypeError, ValueError):
            target_index = int(context.get("step_index", 0) or 0)
        try:
            preserve_prefix = int(plan_payload.get("preserve_prefix_messages") or 0)
        except (TypeError, ValueError):
            preserve_prefix = 0
        methods = context.get("methods") if isinstance(context.get("methods"), list) else []
        message_count = max(len(methods), len(split_seed_messages(self.config.protocol, str(context.get("seed_text") or ""))))
        if message_count <= 1:
            return False
        indices: set[int] = set()
        for item in operators:
            if not isinstance(item, dict):
                continue
            raw_index = item.get("msg_index")
            if raw_index is None:
                continue
            try:
                indices.add(int(raw_index))
            except (TypeError, ValueError):
                continue
        if len(indices) > 1:
            return True
        if any(index > 0 for index in indices):
            return True
        if preserve_prefix > 0 or target_index > 0:
            return True
        hypothesis = plan_payload.get("target_hypothesis") if isinstance(plan_payload.get("target_hypothesis"), dict) else {}
        state_requirements = hypothesis.get("state_requirements") if isinstance(hypothesis.get("state_requirements"), list) else []
        return len(state_requirements) > 1 and message_count > 1 and (preserve_prefix > 0 or target_index > 0)

    def _plan_effect_findings(self, seed_text: str, context: dict[str, Any], plan_payload: dict[str, Any], task_kind: str) -> list[dict[str, Any]]:
        diagnostic = self.executor.explain_empty_generation(
            seed_text=seed_text,
            context=context,
            plan_payload=plan_payload,
            task_kind=task_kind,
        )
        if not diagnostic:
            return []
        reason = str(diagnostic.get("reason") or "").strip()
        if reason != "plan-noop-against-current-seed":
            return []
        finding = {"severity": "hard", "reason": reason}
        details = diagnostic.get("details")
        if isinstance(details, list) and details:
            finding["details"] = details[:4]
        return [finding]

    def _fallback_operator_field(self, context: dict[str, Any], plan_payload: dict[str, Any]) -> str:
        operators = plan_payload.get("operators") if isinstance(plan_payload.get("operators"), list) else []
        for item in operators:
            if not isinstance(item, dict):
                continue
            field = str(item.get("field") or "").strip()
            if field and field != "message_sequence":
                return field
        target_fields = [str(item).strip() for item in plan_payload.get("target_fields", []) if str(item).strip()]
        if target_fields:
            return target_fields[0]
        methods = context.get("methods") if isinstance(context.get("methods"), list) else []
        step_index = max(0, int(context.get("step_index", 0) or 0))
        current_method = str(methods[min(step_index, len(methods) - 1)]).upper() if methods else ""
        if self.policy.message_style == "line-command":
            return "body" if current_method in {item.upper() for item in self.policy.line_body_methods} else "argument"
        return "request_uri"

    def _mechanically_revise_plan(
        self,
        task: dict[str, Any],
        target_row: dict[str, Any],
        context: dict[str, Any],
        plan_payload: dict[str, Any],
        findings: list[dict[str, Any]],
    ) -> tuple[dict[str, Any], str] | None:
        reasons = {str(item.get("reason") or "") for item in findings}
        trigger_class = self._normalize_trigger_class(plan_payload.get("trigger_class"))
        revised = dict(plan_payload)
        required_prefix = self._required_success_prefix_from_context(context, plan_payload)
        if "stateful-plan-drops-success-prefix" in reasons:
            revised["allow_single_message"] = False
            revised["preserve_prefix_messages"] = max(required_prefix, max(0, int(revised.get("preserve_prefix_messages", 0) or 0)))
            revised["required_success_prefix_messages"] = required_prefix
            return revised, "mechanical-preserve-success-prefix"
        if trigger_class == "state_sequence" and "state-sequence-without-repeat-messages" in reasons:
            revised["allow_single_message"] = False
            revised["preserve_prefix_messages"] = min(
                int(revised.get("target_message_index", 0) or 0),
                max(required_prefix, max(0, int(revised.get("preserve_prefix_messages", 0) or 0))),
            )
            revised["required_success_prefix_messages"] = required_prefix
            revised["operators"] = [
                {
                    "field": "message_sequence",
                    "op": "repeat_messages",
                    "values": self._repeat_count_candidates(plan_payload),
                    "msg_index": int(revised.get("target_message_index", 0) or 0),
                }
            ]
            revised["target_fields"] = ["message_sequence"]
            revised["inject_limit"] = max(1, min(3, len(self._repeat_count_candidates(plan_payload))))
            return revised, "mechanical-state-sequence"
        if trigger_class == "size_sensitive_copy" and ({"size-sensitive-needs-boundary-sweep", "length-only-without-size-evidence"} & reasons):
            field = self._fallback_operator_field(context, plan_payload)
            revised["operators"] = [
                {
                    "field": field,
                    "op": "set_length",
                    "values": self._size_boundary_sweep_values(plan_payload, context, target_row),
                    "msg_index": int(revised.get("target_message_index", 0) or 0),
                }
            ]
            revised["target_fields"] = [field]
            revised["inject_limit"] = max(2, min(3, len(revised["operators"][0]["values"])))
            return revised, "mechanical-size-boundary-sweep"
        return None

    def _build_execution_fallback_plan(
        self,
        task: dict[str, Any],
        target_row: dict[str, Any],
        context: dict[str, Any],
        plan_payload: dict[str, Any],
        trigger_reason: str,
    ) -> tuple[dict[str, Any], str] | None:
        trigger_class = self._normalize_trigger_class(plan_payload.get("trigger_class"))
        reason = str(trigger_reason or "")
        required_prefix = self._required_success_prefix_from_context(context, plan_payload)
        if trigger_class == "state_sequence" and (reason in {"execution-degraded", "executor-produced-no-candidates", "critic-hard-findings", "plan-noop-against-current-seed"} or reason.startswith("seed-duplicate")):
            revised = dict(plan_payload)
            revised["allow_single_message"] = False
            revised["preserve_prefix_messages"] = min(
                int(revised.get("target_message_index", 0) or 0),
                max(required_prefix, max(0, int(revised.get("preserve_prefix_messages", 0) or 0))),
            )
            revised["required_success_prefix_messages"] = required_prefix
            revised["operators"] = [
                {
                    "field": "message_sequence",
                    "op": "repeat_messages",
                    "values": self._repeat_count_candidates(plan_payload),
                    "msg_index": int(revised.get("target_message_index", 0) or 0),
                }
            ]
            revised["target_fields"] = ["message_sequence"]
            return revised, "fallback-state-sequence"
        if trigger_class == "size_sensitive_copy" and (reason in {"execution-degraded", "executor-produced-no-candidates", "critic-hard-findings", "seed-duplicate-known", "seed-duplicate-in-batch", "plan-noop-against-current-seed"} or reason.startswith("seed-duplicate")):
            field = self._fallback_operator_field(context, plan_payload)
            revised = dict(plan_payload)
            revised["operators"] = [
                {
                    "field": field,
                    "op": "set_length",
                    "values": self._size_boundary_sweep_values(plan_payload, context, target_row),
                    "msg_index": int(revised.get("target_message_index", 0) or 0),
                }
            ]
            revised["target_fields"] = [field]
            return revised, "fallback-size-boundary-sweep"
        return None

    def _try_execution_fallback(
        self,
        task: dict[str, Any],
        target_row: dict[str, Any],
        context: dict[str, Any],
        payload: dict[str, Any],
        seed_text: str,
        plan_payload: dict[str, Any],
        *,
        trigger_reason: str,
        trace_name_prefix: str,
    ) -> dict[str, Any] | None:
        built = self._build_execution_fallback_plan(task, target_row, context, plan_payload, trigger_reason)
        if built is None:
            return None
        fallback_plan, fallback_mode = built
        result = self._execute_plan_candidates(
            task,
            target_row,
            context,
            payload,
            seed_text,
            fallback_plan,
            candidates_trace_name=f"{trace_name_prefix}-candidates",
            validation_trace_name=f"{trace_name_prefix}-validation",
        )
        return {
            "fallback_mode": fallback_mode,
            "trigger_reason": trigger_reason,
            "plan_payload": fallback_plan,
            "result": result,
        }

    def _detect_execution_degradation(
        self,
        seed_text: str,
        plan_payload: dict[str, Any],
        generated: list[GeneratedSeedCandidate],
    ) -> dict[str, Any] | None:
        operators = plan_payload.get("operators") if isinstance(plan_payload.get("operators"), list) else []
        if not any(str(item.get("op") or "").strip().lower() == "repeat_messages" for item in operators if isinstance(item, dict)):
            return None
        original_regions = split_seed_messages(self.config.protocol, seed_text)
        if not original_regions:
            return None
        target_index = max(0, min(len(original_regions) - 1, int(plan_payload.get("target_message_index", 0) or 0)))
        target_region = original_regions[target_index]
        for candidate in generated:
            regions = split_seed_messages(self.config.protocol, candidate.seed_text)
            if len(regions) <= len(original_regions):
                continue
            if sum(1 for item in regions if item == target_region) >= 2:
                return None
        return {
            "reason": "repeat_messages-no-region-growth",
            "original_region_count": len(original_regions),
            "generated_region_counts": [len(split_seed_messages(self.config.protocol, item.seed_text)) for item in generated[:4]],
            "candidate_summaries": [item.summary for item in generated[:4]],
        }

    def _revise_plan(
        self,
        task: dict[str, Any],
        target_row: dict[str, Any],
        context: dict[str, Any],
        payload: dict[str, Any],
        plan_payload: dict[str, Any],
        findings: list[dict[str, Any]],
    ) -> dict[str, Any]:
        llm_result = self._call_stage(
            task,
            stage="revise-plan",
            system_prompt=(
                "You are the critic-guided revision component of the S2AFL mutation agent. "
                "Fix only the rejected mutation plan. Return exactly one strict JSON object and no markdown."
            ),
            user_prompt=self._build_plan_revision_prompt(task, target_row, context, payload, plan_payload, findings),
            max_tokens=_AGENT_REVISE_MAX_TOKENS,
        )
        if not llm_result.ok:
            return {
                "ok": False,
                "decision": "SKIP",
                "reason": llm_result.error or "llm-failed",
                "status_code": llm_result.status_code,
                "agent_stage": "revise-plan",
                "input_tokens": llm_result.input_tokens,
                "output_tokens": llm_result.output_tokens,
                "reasoning_tokens": llm_result.reasoning_tokens,
                "finish_reason": llm_result.finish_reason,
            }
        response_payload = self._response_payload(llm_result.raw_json, llm_result.content)
        return {
            "ok": True,
            "decision": self._decision_from_response(response_payload, llm_result.content),
            "reason": self._reason_from_response(response_payload, llm_result.content),
            "payload": response_payload,
            "agent_stage": "revise-plan",
            "input_tokens": llm_result.input_tokens,
            "output_tokens": llm_result.output_tokens,
            "reasoning_tokens": llm_result.reasoning_tokens,
            "finish_reason": llm_result.finish_reason,
        }

    def _plan_mutation(
        self,
        task: dict[str, Any],
        target_row: dict[str, Any],
        context: dict[str, Any],
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        llm_result = self._call_stage(
            task,
            stage="plan",
            system_prompt=(
                "You are the planning component of the S2AFL mutation agent. "
                "Reason only about protocol-reachable input mutations. "
                "Return exactly one strict JSON object and no markdown."
            ),
            user_prompt=self._build_plan_prompt(task, target_row, context, payload),
            max_tokens=_AGENT_PLAN_MAX_TOKENS,
        )
        if not llm_result.ok:
            return {
                "ok": False,
                "decision": "SKIP",
                "reason": llm_result.error or "llm-failed",
                "status_code": llm_result.status_code,
                "agent_stage": "plan",
                "input_tokens": llm_result.input_tokens,
                "output_tokens": llm_result.output_tokens,
                "reasoning_tokens": llm_result.reasoning_tokens,
                "finish_reason": llm_result.finish_reason,
            }
        response_payload = self._response_payload(llm_result.raw_json, llm_result.content)
        return {
            "ok": True,
            "decision": self._decision_from_response(response_payload, llm_result.content),
            "reason": self._reason_from_response(response_payload, llm_result.content),
            "payload": response_payload,
            "agent_stage": "plan",
            "input_tokens": llm_result.input_tokens,
            "output_tokens": llm_result.output_tokens,
            "reasoning_tokens": llm_result.reasoning_tokens,
            "finish_reason": llm_result.finish_reason,
        }

    def _generate_candidate(
        self,
        task: dict[str, Any],
        target_row: dict[str, Any],
        context: dict[str, Any],
        payload: dict[str, Any],
        seed_text: str,
        plan_payload: dict[str, Any],
        *,
        critic_findings: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        llm_result = self._call_stage(
            task,
            stage="generate",
            system_prompt=(
                "You are the seed synthesis component of the S2AFL mutation agent. "
                "Return exactly one strict JSON object. "
                "When generating, emit one complete executable seed string only."
            ),
            user_prompt=self._build_generation_prompt(
                task,
                target_row,
                context,
                payload,
                seed_text,
                plan_payload,
                critic_findings=critic_findings,
            ),
            max_tokens=min(self.config.llm_max_tokens, _AGENT_GENERATE_MAX_TOKENS),
        )
        if not llm_result.ok:
            return {
                "ok": False,
                "decision": "SKIP",
                "reason": llm_result.error or "llm-failed",
                "status_code": llm_result.status_code,
                "agent_stage": "generate",
                "input_tokens": llm_result.input_tokens,
                "output_tokens": llm_result.output_tokens,
                "reasoning_tokens": llm_result.reasoning_tokens,
            }
        response_payload = self._response_payload(llm_result.raw_json, llm_result.content)
        return {
            "ok": True,
            "decision": self._decision_from_response(response_payload, llm_result.content),
            "reason": self._reason_from_response(response_payload, llm_result.content),
            "candidate": self._candidate_seed_from_response(response_payload, llm_result.content),
            "agent_stage": "generate",
            "input_tokens": llm_result.input_tokens,
            "output_tokens": llm_result.output_tokens,
            "reasoning_tokens": llm_result.reasoning_tokens,
        }

    def _repair_candidate(
        self,
        task: dict[str, Any],
        target_row: dict[str, Any],
        context: dict[str, Any],
        payload: dict[str, Any],
        seed_text: str,
        plan_payload: dict[str, Any],
        candidate: str,
        validation_error: str,
        attempt: int,
        *,
        critic_findings: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        llm_result = self._call_stage(
            task,
            stage=f"repair-{attempt}",
            system_prompt=(
                "You are the seed repair component of the S2AFL mutation agent. "
                "Fix the candidate so it becomes one valid complete protocol seed while preserving the intended mutation. "
                "Return exactly one strict JSON object."
            ),
            user_prompt=self._build_repair_prompt(
                task,
                target_row,
                context,
                payload,
                seed_text,
                plan_payload,
                candidate,
                validation_error,
                attempt,
                critic_findings=critic_findings,
            ),
            max_tokens=min(self.config.llm_max_tokens, _AGENT_REPAIR_MAX_TOKENS),
        )
        if not llm_result.ok:
            return {
                "ok": False,
                "decision": "SKIP",
                "reason": llm_result.error or "llm-failed",
                "status_code": llm_result.status_code,
                "agent_stage": "repair",
                "input_tokens": llm_result.input_tokens,
                "output_tokens": llm_result.output_tokens,
                "reasoning_tokens": llm_result.reasoning_tokens,
            }
        response_payload = self._response_payload(llm_result.raw_json, llm_result.content)
        return {
            "ok": True,
            "decision": self._decision_from_response(response_payload, llm_result.content),
            "reason": self._reason_from_response(response_payload, llm_result.content),
            "candidate": self._candidate_seed_from_response(response_payload, llm_result.content),
            "agent_stage": "repair",
            "input_tokens": llm_result.input_tokens,
            "output_tokens": llm_result.output_tokens,
            "reasoning_tokens": llm_result.reasoning_tokens,
        }

    def _call_stage(
        self,
        task: dict[str, Any],
        *,
        stage: str,
        system_prompt: str,
        user_prompt: str,
        max_tokens: int,
    ) -> Any:
        self._write_task_trace(task["task_id"], f"llm-{stage}-request", {"stage": stage, "system_prompt": system_prompt, "user_prompt": user_prompt, "max_tokens": max_tokens, "temperature": self.config.llm_temperature})
        llm_result = self.llm.call(
            [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            max_tokens=max_tokens,
            temperature=self.config.llm_temperature,
            force_json=True,
        )
        self._write_task_trace(task["task_id"], f"llm-{stage}-response", {"stage": stage, "ok": llm_result.ok, "status_code": llm_result.status_code, "error": llm_result.error, "input_tokens": llm_result.input_tokens, "output_tokens": llm_result.output_tokens, "reasoning_tokens": llm_result.reasoning_tokens, "finish_reason": llm_result.finish_reason, "content": llm_result.content, "raw_json": llm_result.raw_json})
        self._record_llm_usage(task, llm_result, stage=stage)
        return llm_result

    @staticmethod
    def _merge_usage(total: dict[str, int], update: dict[str, Any]) -> None:
        total["input_tokens"] += int(update.get("input_tokens") or 0)
        total["output_tokens"] += int(update.get("output_tokens") or 0)
        total["reasoning_tokens"] += int(update.get("reasoning_tokens") or 0)

    @staticmethod
    def _boundary_llm_retirement_reason(result: dict[str, Any]) -> str:
        if str(result.get("decision") or "").strip().upper() != "SKIP":
            return ""
        stage = str(result.get("agent_stage") or "").strip().lower()
        if stage not in {"plan", "critic", "generate", "revise-plan"}:
            return ""
        reason = str(result.get("reason") or "").strip()
        lowered = reason.lower()
        hard_markers = (
            "no protocol field controls",
            "not protocol field",
            "not protocol reachable",
            "no protocol path",
            "internal config",
            "runtime config",
            "not protocol controllable",
            "not reachable from protocol",
            "protocol unreachable",
        )
        return reason if any(marker in lowered for marker in hard_markers) else ""

    def _maybe_retire_boundary_target(self, task: dict[str, Any], result: dict[str, Any]) -> None:
        if task.get("kind") != "boundary-generate":
            return
        target_id = str(task.get("target_id") or "").strip()
        if not target_id:
            return
        target_row = self.state.get_target_row(target_id) or {}
        if str(target_row.get("analysis_result") or "").startswith("branch-flipped:"):
            return
        retire_reason = self._boundary_llm_retirement_reason(result)
        if not retire_reason:
            return
        analysis_result = f"protocol-uncontrollable:llm:{retire_reason}"
        self.state.mark_target_analyzed(target_id, result=analysis_result)
        self.state.record_event(
            kind="boundary_target_retired",
            subject=self.config.subject,
            protocol=self.config.protocol,
            seed_id=task.get("seed_id"),
            payload={
                "target_id": target_id,
                "reason": analysis_result,
                "task_id": task.get("task_id", ""),
                "agent_stage": result.get("agent_stage", ""),
            },
        )
        self.logger.log(
            "Mutator",
            "boundary target retired as protocol-uncontrollable",
            task_id=task.get("task_id", ""),
            target_id=target_id,
            reason=retire_reason,
            agent_stage=result.get("agent_stage", ""),
        )

    def _staged_pending_dir(self) -> Path:
        return self.config.resolved_psei_output_dir / "vuln_staging" / "pending"

    def _staged_consumed_dir(self) -> Path:
        return self.config.resolved_psei_output_dir / "vuln_staging" / "consumed"

    def _staged_manifest_path(self) -> Path:
        return self.config.resolved_psei_output_dir / "vuln_staging" / "manifest.jsonl"

    def _append_staged_manifest(self, payload: dict[str, Any]) -> None:
        path = self._staged_manifest_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(payload, ensure_ascii=False) + "\n")

    def _try_inject_staged_vuln_seed(self, task: dict[str, Any]) -> dict[str, Any] | None:
        pending_dir = self._staged_pending_dir()
        if not pending_dir.exists():
            return None
        candidates = [path for path in sorted(pending_dir.iterdir()) if path.is_file()]
        if not candidates:
            return None
        staged_path = candidates[0]
        raw_seed = load_seed_file(staged_path)
        injected = self.injector.inject_seed(raw_seed, origin_tag=f"staged-vuln-{staged_path.stem}")
        consumed_dir = self._staged_consumed_dir()
        consumed_dir.mkdir(parents=True, exist_ok=True)
        consumed_path = consumed_dir / staged_path.name
        shutil.move(str(staged_path), str(consumed_path))
        self._append_staged_manifest(
            {
                "kind": "staged_vuln_seed_injected",
                "task_id": task["task_id"],
                "target_id": task["target_id"],
                "task_kind": task["kind"],
                "source_seed": staged_path.name,
                "consumed_path": str(consumed_path),
                "injected_path": str(injected),
            }
        )
        self.state.record_event(
            kind="seed_injected",
            subject=self.config.subject,
            protocol=self.config.protocol,
            seed_id=task["seed_id"],
            payload={
                "task_id": task["task_id"],
                "target_id": task["target_id"],
                "task_kind": task["kind"],
                "injected_path": str(injected),
                "reason": "startup-quarantined-seed",
                "source_seed": staged_path.name,
                "source_kind": "staged_vuln_seed",
            },
        )
        return {
            "reason": "startup-quarantined-seed",
            "decision": "REUSE_STAGED",
            "injected_path": str(injected),
            "staged_seed_name": staged_path.name,
            "consumed_path": str(consumed_path),
        }


    @staticmethod
    def _seed_row_metadata(seed_row: dict[str, Any] | None) -> dict[str, Any]:
        if not seed_row:
            return {}
        raw = seed_row.get("metadata_json") or "{}"
        if isinstance(raw, dict):
            return dict(raw)
        try:
            parsed = json.loads(raw)
        except Exception:
            return {}
        return dict(parsed) if isinstance(parsed, dict) else {}

    def _seed_metadata_for_text(self, seed_text: str) -> tuple[str, dict[str, Any]]:
        seed_id = body_sha1(seed_text) if seed_text else ""
        if not seed_id or not hasattr(self, "state") or not hasattr(self.state, "get_seed_row"):
            return seed_id, {}
        return seed_id, self._seed_row_metadata(self.state.get_seed_row(seed_id))

    @staticmethod
    def _metadata_int(metadata: dict[str, Any], key: str) -> int:
        try:
            return max(0, int(metadata.get(key) or 0))
        except (TypeError, ValueError):
            return 0

    @classmethod
    def _metadata_replay_prefix_messages(cls, metadata: dict[str, Any]) -> int:
        return cls._metadata_int(metadata, "replay_prefix_messages")

    @classmethod
    def _metadata_success_prefix_messages(cls, metadata: dict[str, Any]) -> int:
        return cls._metadata_int(metadata, "success_prefix_messages")

    @staticmethod
    def _metadata_first_failure_status_step(metadata: dict[str, Any]) -> int | None:
        raw = metadata.get("replay_first_failure_status_step")
        if raw in {None, "", False}:
            return None
        try:
            return max(0, int(raw))
        except (TypeError, ValueError):
            return None

    @classmethod
    def _metadata_has_validated_prefix(cls, metadata: dict[str, Any], required_prefix_messages: int) -> bool:
        if required_prefix_messages <= 0:
            return True
        replay_prefix = cls._metadata_replay_prefix_messages(metadata)
        first_failure = cls._metadata_first_failure_status_step(metadata)
        return replay_prefix >= required_prefix_messages and (first_failure is None or first_failure >= required_prefix_messages)

    def _attach_seed_metadata(self, payload: dict[str, Any]) -> dict[str, Any]:
        result = dict(payload)
        seed_id, metadata = self._seed_metadata_for_text(str(result.get("seed_text") or ""))
        result["seed_id"] = seed_id
        result["metadata"] = metadata
        return result
    def _prepare_context_seed(self, seed_row: dict[str, Any]) -> dict[str, Any]:
        queue_path = Path(str(seed_row.get("queue_path") or ""))
        raw_seed = load_seed_file(queue_path)
        quality = self._context_seed_quality(raw_seed)
        if quality["ok"]:
            return self._attach_seed_metadata({
                "ok": True,
                "seed_text": raw_seed,
                "source": "queue-seed",
                "queue_path": str(queue_path),
                "quality": quality,
            })

        prefix_seed, prefix_meta = self._clean_context_prefix(raw_seed)
        if prefix_seed:
            prefix_quality = self._context_seed_quality(prefix_seed)
            if prefix_quality["ok"]:
                return self._attach_seed_metadata({
                    "ok": True,
                    "seed_text": prefix_seed,
                    "source": "clean-prefix",
                    "queue_path": str(queue_path),
                    "quality": prefix_quality,
                    "fallback": {
                        "reason": quality.get("reason", "context-seed-corrupted"),
                        "message_count_before": prefix_meta.get("message_count_before", 0),
                        "message_count_after": prefix_meta.get("message_count_after", 0),
                    },
                })

        for ancestor_path in self._candidate_ancestor_paths(seed_row):
            try:
                ancestor_seed = load_seed_file(ancestor_path)
            except OSError:
                continue
            ancestor_quality = self._context_seed_quality(ancestor_seed)
            if not ancestor_quality["ok"]:
                continue
            return self._attach_seed_metadata({
                "ok": True,
                "seed_text": ancestor_seed,
                "source": "ancestor-seed",
                "queue_path": str(ancestor_path),
                "quality": ancestor_quality,
                "fallback": {
                    "reason": quality.get("reason", "context-seed-corrupted"),
                    "ancestor_path": str(ancestor_path),
                },
            })

        return {
            "ok": False,
            "reason": f"context-seed-corrupted:{quality.get('reason', 'unknown')}",
            "queue_path": str(queue_path),
            "quality": quality,
        }

    def _target_commands_for_row(self, target_row: dict[str, Any]) -> list[str]:
        raw = target_row.get("commands_json")
        if isinstance(raw, str):
            try:
                commands = json.loads(raw)
            except Exception:
                commands = []
        else:
            commands = list(target_row.get("commands", []))
        result: list[str] = []
        for item in commands:
            text = str(item or "").strip().upper()
            if text and text not in result:
                result.append(text)
        return result

    def _seed_contains_target_command(self, seed_text: str, commands: list[str]) -> bool:
        if not commands:
            return True
        methods = [message_method(msg).upper() for msg in split_seed_messages(self.config.protocol, seed_text) if message_method(msg)]
        return any(method in commands for method in methods)

    def _retarget_boundary_context_seed(self, *, seed_row: dict[str, Any], target_row: dict[str, Any], context_seed: dict[str, Any]) -> dict[str, Any]:
        commands = self._target_commands_for_row(target_row)
        if not commands:
            return context_seed
        seed_text = str(context_seed.get("seed_text") or "")
        if seed_text and self._seed_contains_target_command(seed_text, commands):
            return context_seed
        for ancestor_path in self._candidate_ancestor_paths(seed_row):
            try:
                ancestor_seed = load_seed_file(ancestor_path)
            except OSError:
                continue
            if not self._seed_contains_target_command(ancestor_seed, commands):
                continue
            ancestor_quality = self._context_seed_quality(ancestor_seed)
            if not ancestor_quality.get("ok"):
                continue
            return self._attach_seed_metadata({
                "ok": True,
                "seed_text": ancestor_seed,
                "source": "ancestor-target-command",
                "boundary_context_kind": "ancestor-target-command",
                "queue_path": str(ancestor_path),
                "quality": ancestor_quality,
                "fallback": {
                    "reason": "retargeted-for-boundary-command",
                    "commands": commands,
                    "ancestor_path": str(ancestor_path),
                },
            })
        return {
            "ok": False,
            "reason": f"context-missing-target-command:{commands[0]}",
            "queue_path": str(context_seed.get("queue_path") or seed_row.get("queue_path") or ""),
            "quality": context_seed.get("quality", {}),
            "fallback": {
                "commands": commands,
                "source": context_seed.get("source", "unknown"),
            },
        }


    def _retarget_stateful_context_seed(
        self,
        *,
        seed_row: dict[str, Any],
        context_seed: dict[str, Any],
        required_prefix_messages: int,
    ) -> dict[str, Any]:
        if required_prefix_messages <= 0:
            return context_seed
        metadata = context_seed.get("metadata") if isinstance(context_seed.get("metadata"), dict) else {}
        if self._metadata_has_validated_prefix(metadata, required_prefix_messages):
            return context_seed
        for ancestor_path in self._candidate_ancestor_paths(seed_row):
            try:
                ancestor_seed = load_seed_file(ancestor_path)
            except OSError:
                continue
            ancestor_messages = split_seed_messages(self.config.protocol, ancestor_seed)
            if len(ancestor_messages) <= required_prefix_messages:
                continue
            ancestor_quality = self._context_seed_quality(ancestor_seed)
            if not ancestor_quality.get("ok"):
                continue
            _ancestor_seed_id, ancestor_metadata = self._seed_metadata_for_text(ancestor_seed)
            if not self._metadata_has_validated_prefix(ancestor_metadata, required_prefix_messages):
                continue
            return self._attach_seed_metadata({
                "ok": True,
                "seed_text": ancestor_seed,
                "source": "ancestor-validated-prefix",
                "queue_path": str(ancestor_path),
                "quality": ancestor_quality,
                "fallback": {
                    "reason": "retargeted-for-validated-prefix",
                    "ancestor_path": str(ancestor_path),
                    "required_prefix_messages": required_prefix_messages,
                },
            })
        return context_seed

    def _enrich_context_with_replay_contract(self, context: dict[str, Any], context_seed: dict[str, Any]) -> dict[str, Any]:
        enriched = dict(context)
        metadata = context_seed.get("metadata") if isinstance(context_seed.get("metadata"), dict) else {}
        step_index = max(0, int(enriched.get("step_index", 0) or 0))
        enriched["context_seed_id"] = str(context_seed.get("seed_id") or "")
        enriched["context_seed_source"] = str(context_seed.get("source") or "")
        enriched["replay_prefix_messages"] = self._metadata_replay_prefix_messages(metadata)
        enriched["success_prefix_messages"] = self._metadata_success_prefix_messages(metadata)
        enriched["replay_first_failure_status_step"] = self._metadata_first_failure_status_step(metadata)
        enriched["replay_prefix_methods"] = list(metadata.get("replay_prefix_methods") or [])[:8]
        enriched["replay_prefix_status_codes"] = list(metadata.get("replay_prefix_status_codes") or [])[:8]
        enriched["stateful_required_prefix_messages"] = step_index if step_index > 0 else 0
        return enriched

    @staticmethod
    def _required_success_prefix_from_context(context: dict[str, Any], plan_payload: dict[str, Any]) -> int:
        try:
            target_message_index = max(0, int(plan_payload.get("target_message_index", context.get("step_index", 0)) or 0))
        except (TypeError, ValueError):
            target_message_index = max(0, int(context.get("step_index", 0) or 0))
        if target_message_index <= 0:
            return 0
        try:
            required = max(0, int(context.get("stateful_required_prefix_messages", target_message_index) or 0))
        except (TypeError, ValueError):
            required = target_message_index
        return min(target_message_index, max(required, target_message_index))
    def _resolve_task_step_index(self, *, task: dict[str, Any], payload: dict[str, Any], target_row: dict[str, Any], messages: list[str]) -> int:
        if not messages:
            return 0
        requested = int(payload.get("step_index", min(len(messages) - 1, 0)))
        requested = max(0, min(requested, max(len(messages) - 1, 0)))
        if task.get("kind") != "boundary-generate":
            return requested
        commands = self._target_commands_for_row(target_row)
        if not commands:
            return requested
        for idx, message in enumerate(messages):
            if message_method(message).upper() in commands:
                return idx
        return requested

    def _validate_boundary_context(
        self,
        *,
        task: dict[str, Any],
        payload: dict[str, Any],
        target_row: dict[str, Any],
        context: dict[str, Any],
        context_seed: dict[str, Any] | None = None,
    ) -> str:
        if task.get("kind") != "boundary-generate":
            return ""
        trigger_reason = str(payload.get("reason") or "").strip()
        context_kind = str((context_seed or {}).get("boundary_context_kind") or payload.get("context_kind") or "").strip()
        if trigger_reason == "uncovered-branch-side" and context_kind != "branch-exact":
            return f"boundary-context-not-branch-exact:{context_kind or 'none'}"
        commands = self._target_commands_for_row(target_row)
        if commands:
            methods = [str(method or "").strip().upper() for method in context.get("methods", [])]
            if not any(method in commands for method in methods):
                return f"context-missing-target-command:{commands[0]}"
        return ""

    def _context_seed_quality(self, seed_text: str) -> dict[str, Any]:
        messages = split_seed_messages(self.config.protocol, seed_text)
        if not messages:
            return {"ok": False, "reason": "seed-parse-failed", "message_count": 0}
        for idx, message in enumerate(messages):
            if self._region_without_start_allowed(messages, idx):
                continue
            ok, reason = self._message_structurally_clean(message)
            if not ok:
                return {
                    "ok": False,
                    "reason": reason,
                    "bad_message_index": idx,
                    "message_count": len(messages),
                    "method": message_method(message),
                }
        return {"ok": True, "message_count": len(messages)}

    def _clean_context_prefix(self, seed_text: str) -> tuple[str | None, dict[str, Any]]:
        messages = split_seed_messages(self.config.protocol, seed_text)
        clean: list[str] = []
        for message in messages:
            ok, _reason = self._message_structurally_clean(message)
            if not ok:
                break
            clean.append(message)
        if not clean:
            return None, {"message_count_before": len(messages), "message_count_after": 0}
        if len(clean) == len(messages):
            return seed_text, {"message_count_before": len(messages), "message_count_after": len(clean)}
        return self._render_messages(clean), {
            "message_count_before": len(messages),
            "message_count_after": len(clean),
        }

    def _message_structurally_clean(self, message: str) -> tuple[bool, str]:
        lines = str(message or "").replace("\r\n", "\n").replace("\r", "\n").split("\n")
        first_line = lines[0].strip() if lines else ""
        if not first_line:
            return False, "empty-message-start"
        if not self._message_looks_sendable(message):
            return False, "malformed-message-start"
        method = message_method(message)
        if self.knowledge.templates and not self.knowledge.template_for_method(method):
            return False, f"unknown-protocol-method:{method or '?'}"
        if self._contains_control_bytes(method):
            return False, "method-has-control-bytes"
        if self._contains_control_bytes(first_line):
            return False, "start-line-has-control-bytes"
        if self.policy.message_style == "line-command":
            return True, ""
        parts = first_line.split()
        if len(parts) < 3:
            return False, "short-request-line"
        for line in lines[1:]:
            if line == "":
                break
            if ":" not in line:
                return False, "malformed-header-line"
            name, _value = line.split(":", 1)
            if self._contains_control_bytes(name):
                return False, "header-name-has-control-bytes"
            if not re.fullmatch(r"[A-Za-z][A-Za-z0-9-]{0,63}", name):
                return False, "header-name-invalid"
        return True, ""

    @staticmethod
    def _contains_control_bytes(text: str) -> bool:
        for ch in str(text or ""):
            code = ord(ch)
            if code in (9, 10, 13):
                continue
            if code < 32 or code == 127:
                return True
        return False

    def _candidate_ancestor_paths(self, seed_row: dict[str, Any]) -> list[Path]:
        queue_path = Path(str(seed_row.get("queue_path") or ""))
        queue_dir = queue_path.parent
        candidates: list[Path] = []
        seen: set[str] = set()

        origin = str(seed_row.get("origin") or "")
        if origin.endswith('.raw'):
            baseline = self.config.resolved_afl_input_dir / origin
            if baseline.exists() and baseline.is_file():
                candidates.append(baseline)
                seen.add(str(baseline))

        for src_id in self._source_queue_ids(origin):
            pattern = f"id:{src_id},*"
            for path in sorted(queue_dir.glob(pattern)):
                if not path.is_file():
                    continue
                key = str(path)
                if key in seen or path == queue_path:
                    continue
                candidates.append(path)
                seen.add(key)
        return candidates

    @staticmethod
    def _source_queue_ids(origin: str) -> list[str]:
        text = str(origin or "")
        if not text:
            return []
        head = text.split(",", 1)[0]
        ids: list[str] = []
        for part in head.split("+"):
            part = part.strip()
            if re.fullmatch(r"\d{6}", part) and part not in ids:
                ids.append(part)
        return ids

    @staticmethod
    def _safe_origin_tag(kind: str, target_id: str) -> str:
        raw = f"{kind}-{target_id}"
        sanitized = _SAFE_TAG_RE.sub("_", raw).strip("._-")
        return sanitized or "generated-seed"

    def _should_enqueue_flip_confirmation(self, *, task: dict[str, Any], payload: dict[str, Any]) -> bool:
        if task.get("kind") != "boundary-generate":
            return False
        if self.flip_confirmation_queue is None:
            return False
        target_id = str(task.get("target_id") or "").strip()
        if not target_id:
            return False
        if target_id in self._flip_confirmation_targets_seen:
            return False
        context_kind = str(payload.get("context_kind") or "").strip().lower()
        return context_kind in {"line-hit", "branch-exact"}

    def _enqueue_generated_seed(self, raw_seed: str, injected_path: Path, *, task: dict[str, Any], payload: dict[str, Any], expected_sha1: str) -> None:
        messages = split_seed_messages(self.config.protocol, raw_seed)
        methods = [message_method(msg) for msg in messages if message_method(msg)]
        seed_id = body_sha1(raw_seed)
        emitted_at = time.time()
        metadata = {
            "queue_name": injected_path.name,
            "source": "mutation_worker",
            "task_id": task.get("task_id", ""),
            "task_kind": task.get("kind", ""),
            "target_id": task.get("target_id", ""),
            "replay_reason": "generated-direct",
            "expected_sha1": expected_sha1 or seed_id,
            "context_kind": payload.get("context_kind", ""),
            "scheduler_reason": payload.get("reason", ""),
            "emitted_origin": injected_path.name.split(",orig:", 1)[1] if ",orig:" in injected_path.name else injected_path.name,
            "emitted_queue_path": str(injected_path),
            "emitted_at": emitted_at,
        }
        if task.get("kind") == "boundary-generate":
            if payload.get("missing_branch_key"):
                metadata["missing_branch_key"] = payload.get("missing_branch_key")
            if payload.get("covered_branch_key"):
                metadata["covered_branch_key"] = payload.get("covered_branch_key")
        mode = str(getattr(self.config, "replay_queue_filter_mode", "all") or "all").strip().lower()
        direct_replay = mode == "all"
        handoff_replay = (not direct_replay) and bool(getattr(self.config, "generated_seed_handoff_enabled", True))
        if direct_replay:
            metadata["replay_enqueued_at"] = emitted_at
            metadata["replay_enqueued_via"] = "mutation_worker"
            metadata["measurement_lane"] = "coverage"
        elif handoff_replay:
            metadata["replay_enqueued_at"] = emitted_at
            metadata["replay_enqueued_via"] = "mutation_worker.generated_handoff"
            metadata["measurement_lane"] = "generated-handoff"
        seed = SeedRecord(
            seed_id=seed_id,
            queue_path=str(injected_path),
            origin=metadata["emitted_origin"],
            protocol=self.config.protocol,
            subject=self.config.subject,
            methods=methods,
            message_count=len(messages),
            body_sha1=seed_id,
            size_bytes=len(raw_seed.encode("latin-1", errors="replace")),
            first_seen_at=emitted_at,
            metadata=metadata,
        )
        self.state.upsert_seed(seed)
        self.state.record_seed_observation(
            seed_id=seed.seed_id,
            stage="emitted",
            lane=str(metadata.get("measurement_lane") or ("sync-only" if not direct_replay and not handoff_replay else "coverage")),
            queue_path=seed.queue_path,
            task_id=str(task.get("task_id") or ""),
            target_id=str(task.get("target_id") or ""),
            module=str(task.get("kind") or ""),
            payload={
                "origin": seed.origin,
                "methods": seed.methods,
                "message_count": seed.message_count,
                "expected_sha1": metadata.get("expected_sha1", ""),
                "direct_replay": direct_replay,
                "handoff_replay": handoff_replay,
            },
            created_at=emitted_at,
        )
        self.state.record_event(
            kind="seed_emitted",
            subject=self.config.subject,
            protocol=self.config.protocol,
            seed_id=seed.seed_id,
            payload={
                "seed_id": seed.seed_id,
                "queue_path": seed.queue_path,
                "origin": seed.origin,
                "methods": seed.methods,
                "message_count": seed.message_count,
                "source": "mutation_worker",
                "task_id": task.get("task_id", ""),
                "task_kind": task.get("kind", ""),
                "target_id": task.get("target_id", ""),
                "expected_sha1": metadata.get("expected_sha1", ""),
                "context_kind": metadata.get("context_kind", ""),
                "scheduler_reason": metadata.get("scheduler_reason", ""),
                "missing_branch_key": metadata.get("missing_branch_key", ""),
                "covered_branch_key": metadata.get("covered_branch_key", ""),
                "direct_replay": direct_replay,
            },
        )
        if direct_replay or handoff_replay:
            self.replay_queue.put(seed)
            self.logger.log(
                "D",
                "generated seed queued for replay" if direct_replay else "generated seed queued for handoff replay",
                seed_id=seed.seed_id,
                origin=seed.origin,
                queue_path=seed.queue_path,
                task_kind=task.get("kind", ""),
                expected_sha1=metadata.get("expected_sha1", ""),
                measurement_lane=metadata.get("measurement_lane", "coverage"),
            )
        else:
            queued_for_flip_confirmation = False
            if self._should_enqueue_flip_confirmation(task=task, payload=payload):
                flip_metadata = dict(metadata)
                flip_metadata["replay_reason"] = "flip-confirmation"
                flip_metadata["replay_enqueued_at"] = emitted_at
                flip_metadata["replay_enqueued_via"] = "mutation_worker.flip_confirmation"
                flip_metadata["measurement_lane"] = "flip-confirmation"
                flip_seed = SeedRecord(
                    seed_id=seed.seed_id,
                    queue_path=seed.queue_path,
                    origin=seed.origin,
                    protocol=seed.protocol,
                    subject=seed.subject,
                    methods=list(seed.methods),
                    message_count=seed.message_count,
                    body_sha1=seed.body_sha1,
                    size_bytes=seed.size_bytes,
                    first_seen_at=seed.first_seen_at,
                    metadata=flip_metadata,
                )
                self.flip_confirmation_queue.put(flip_seed)
                self._flip_confirmation_targets_seen.add(str(task.get("target_id") or "").strip())
                self.state.update_seed_metadata(
                    seed.seed_id,
                    {
                        "flip_confirmation_enqueued": True,
                        "flip_confirmation_enqueued_at": emitted_at,
                        "measurement_lane": "flip-confirmation",
                    },
                )
                queued_for_flip_confirmation = True
            self.logger.log(
                "D",
                "generated seed queued for AFLNet sync only",
                seed_id=seed.seed_id,
                origin=seed.origin,
                queue_path=seed.queue_path,
                flip_confirmation_enqueued=queued_for_flip_confirmation,
            )

    @staticmethod
    def _sanitize_json_like_content(content: str) -> str:
        text = str(content or "").strip()
        if not text:
            return text
        fenced = re.match(r"^```(?:json)?\s*(.*?)\s*```$", text, re.DOTALL | re.IGNORECASE)
        if fenced:
            text = fenced.group(1).strip()
        text = re.sub(
            r'"((?:\\.|[^"\\])*)"\s*\+\s*"((?:\\.|[^"\\])*)"\s*\*\s*(\d+)',
            lambda m: json.dumps(
                ast.literal_eval('"' + m.group(1) + '"') + ast.literal_eval('"' + m.group(2) + '"') * int(m.group(3))
            ),
            text,
        )
        text = re.sub(
            r'"((?:\\.|[^"\\])*)"\s*\*\s*(\d+)',
            lambda m: json.dumps(ast.literal_eval('"' + m.group(1) + '"') * int(m.group(2))),
            text,
        )
        text = re.sub(
            r'"((?:\\.|[^"\\])*)"\s*\+\s*"((?:\\.|[^"\\])*)"',
            lambda m: json.dumps(ast.literal_eval('"' + m.group(1) + '"') + ast.literal_eval('"' + m.group(2) + '"')),
            text,
        )
        text = re.sub(r'(?<!\\\\)\\x([0-9A-Fa-f]{2})', lambda m: '\\\\u00' + m.group(1).lower(), text)
        return text

    @classmethod
    def _parse_json_like_payload(cls, content: str) -> tuple[dict[str, Any] | None, str | None]:
        raw = str(content or "").strip()
        if not raw:
            return None, 'empty-content'
        candidates = [raw]
        match = re.search(r"\{.*\}", raw, re.DOTALL)
        if match:
            extracted = match.group(0)
            if extracted != raw:
                candidates.append(extracted)
        seen: set[str] = set()
        last_error = 'content-json-parse-failed'
        for candidate in candidates:
            if candidate in seen:
                continue
            seen.add(candidate)
            try:
                parsed = json.loads(candidate)
                if isinstance(parsed, dict):
                    return parsed, None
            except Exception as exc:
                last_error = str(exc)
            sanitized = cls._sanitize_json_like_content(candidate)
            if sanitized == candidate or sanitized in seen:
                continue
            seen.add(sanitized)
            try:
                parsed = json.loads(sanitized)
                if isinstance(parsed, dict):
                    return parsed, None
            except Exception as exc:
                last_error = str(exc)
        return None, last_error

    @classmethod
    def _response_payload(cls, raw_json: dict[str, Any] | None, text: str) -> dict[str, Any]:
        raw_text = str(text or "").strip()
        if raw_text:
            parsed, _error = cls._parse_json_like_payload(raw_text)
            if isinstance(parsed, dict):
                return parsed
        if isinstance(raw_json, dict):
            direct_decision = str(raw_json.get("decision") or "").strip().upper()
            if direct_decision in {"GENERATE", "SKIP"}:
                return raw_json
            choices = raw_json.get("choices")
            if isinstance(choices, list) and choices:
                first = choices[0] if isinstance(choices[0], dict) else {}
                message = first.get("message") if isinstance(first, dict) else None
                content = message.get("content") if isinstance(message, dict) else None
                if isinstance(content, str) and content.strip():
                    parsed, error = cls._parse_json_like_payload(content)
                    if isinstance(parsed, dict):
                        return parsed
                    return {"__payload_parse_error__": f"content-json-parse-failed:{error}", "__payload_raw_content__": content}
            return raw_json
        if not raw_text:
            return {}
        parsed, _error = cls._parse_json_like_payload(raw_text)
        return parsed if isinstance(parsed, dict) else {}

    @classmethod
    def _decision_from_response(cls, payload: dict[str, Any], text: str) -> str:
        decision = str(payload.get("decision") or "").strip().upper()
        if decision in {"GENERATE", "SKIP"}:
            return decision
        return cls._parse_decision(text)

    @classmethod
    def _reason_from_response(cls, payload: dict[str, Any], text: str) -> str:
        reason = str(payload.get("reason") or "").strip()
        return reason or cls._parse_reason(text)

    @staticmethod
    def _seed_from_message_queue(value: Any) -> str | None:
        if not isinstance(value, list) or not value:
            return None
        parts: list[str] = []
        for item in value:
            if isinstance(item, dict):
                raw_item = item.get("raw") or item.get("message") or item.get("data") or item.get("text")
            else:
                raw_item = item
            if not isinstance(raw_item, str) or not raw_item.strip():
                continue
            parts.append(MutationWorker._decode_literal_seed_escapes(raw_item))
        return "".join(parts) if parts else None

    @staticmethod
    def _candidate_seed_from_response(payload: dict[str, Any], text: str) -> str | None:
        for key in ("mutated_messages", "message_queue", "messages"):
            queued = MutationWorker._seed_from_message_queue(payload.get(key))
            if queued:
                return queued
        for key in ("mutated_seed", "seed", "raw_seed"):
            value = payload.get(key)
            if isinstance(value, str) and value.strip():
                nested = MutationWorker._extract_seed_from_blob(value)
                if nested:
                    return nested
                return value
        return MutationWorker._extract_seed_from_blob(parse_markdown_seed_block(text) or text)

    @staticmethod
    def _extract_seed_from_blob(blob: str | None) -> str | None:
        if not isinstance(blob, str):
            return None
        raw_text = str(blob)
        text = raw_text.strip()
        if not text:
            return None
        try:
            parsed = json.loads(text)
        except Exception:
            parsed = None
        if isinstance(parsed, dict):
            for key in ("mutated_messages", "message_queue", "messages"):
                queued = MutationWorker._seed_from_message_queue(parsed.get(key))
                if queued:
                    return queued
            for key in ("mutated_seed", "seed", "raw_seed"):
                value = parsed.get(key)
                if isinstance(value, str) and value.strip():
                    return MutationWorker._decode_literal_seed_escapes(value)
        for key in ("mutated_seed", "seed", "raw_seed"):
            match = re.search(rf'"{key}"\s*:\s*"((?:\\.|[^"])*)', text, re.DOTALL)
            if match:
                partial = match.group(1)
                if partial.strip():
                    return MutationWorker._decode_literal_seed_escapes(partial)
        if text.startswith("```"):
            fenced = parse_markdown_seed_block(text)
            if fenced:
                return MutationWorker._decode_literal_seed_escapes(fenced)
        return MutationWorker._decode_literal_seed_escapes(raw_text)

    @staticmethod
    def _decode_literal_seed_escapes(text: str) -> str:
        value = str(text or "")
        if not value:
            return value
        if not any(token in value for token in ("\\r", "\\n", "\\t", "\\x", "\\u")):
            return value
        decoded = value.replace("\\r\\n", "\n")
        decoded = decoded.replace("\\n", "\n").replace("\\r", "\r").replace("\\t", "\t")
        decoded = re.sub(r"\\x([0-9A-Fa-f]{2})", lambda m: chr(int(m.group(1), 16)), decoded)
        decoded = re.sub(r"\\u([0-9A-Fa-f]{4})", lambda m: chr(int(m.group(1), 16)), decoded)
        return decoded

    @staticmethod
    def _normalize_seed_text(candidate: str) -> str:
        normalized = candidate.replace("\r\n", "\n").replace("\r", "\n")
        normalized = normalized.lstrip("\n").strip(" \t")
        normalized = normalized.replace("\n", "\r\n")
        if normalized and not normalized.endswith("\r\n"):
            normalized += "\r\n"
        return normalized

    def _render_messages(self, messages: list[str]) -> str:
        return "".join(message for message in messages if message)

    def _trim_to_known_method(self, line: str) -> str:
        raw = str(line or "")
        if not raw:
            return ""
        template_map = getattr(self.knowledge, "templates", {})
        methods = sorted(template_map.keys(), key=len, reverse=True) if isinstance(template_map, dict) else []
        for method in methods:
            match = re.search(rf"(?<![A-Za-z0-9_-])({re.escape(method)})(?=\s|$)", raw)
            if not match:
                continue
            prefix = raw[: match.start(1)]
            if prefix and re.search(r"[A-Za-z0-9]", prefix):
                continue
            return raw[match.start(1) :].lstrip()
        return ""

    def _trim_to_generic_start(self, line: str) -> str:
        raw = str(line or "")
        if not raw:
            return ""
        match = re.search(r"([A-Za-z][A-Za-z0-9_-]{1,31})(?=\s|$)", raw)
        if not match:
            return ""
        prefix = raw[: match.start(1)]
        if prefix and re.search(r"[A-Za-z0-9]", prefix):
            return ""
        return raw[match.start(1) :].lstrip()

    def _message_start_candidate(self, line: str) -> str:
        stripped = str(line or "").strip()
        if not stripped:
            return ""
        known = self._trim_to_known_method(stripped)
        if known:
            return known
        return self._trim_to_generic_start(stripped)

    def _message_looks_sendable(self, line: str) -> bool:
        first_line = str(line or "").splitlines()[0].strip()
        if not first_line:
            return False
        return bool(self._message_start_candidate(first_line))

    def _sanitize_message(self, message: str) -> str:
        raw = str(message or "")
        if not raw.strip():
            return ""
        lines = raw.replace("\r\n", "\n").replace("\r", "\n").split("\n")
        for idx, line in enumerate(lines):
            start_line = self._message_start_candidate(line)
            if not start_line:
                continue
            kept = [start_line]
            kept.extend(lines[idx + 1 :])
            cleaned = "\r\n".join(kept).strip("\r\n")
            if not cleaned:
                return ""
            if raw.endswith("\r\n\r\n"):
                return cleaned + "\r\n\r\n"
            return cleaned + "\r\n"
        return ""

    def _sanitize_seed_candidate(self, candidate: str) -> tuple[str | None, dict[str, Any]]:
        raw = self._normalize_seed_text(candidate)
        messages = split_seed_messages(self.config.protocol, raw)
        if not messages:
            return None, {"message_count_before": 0, "message_count_after": 0, "dropped_messages": 0}
        cleaned_messages: list[str] = []
        dropped = 0
        for msg_idx, message in enumerate(messages):
            if self._region_without_start_allowed(messages, msg_idx):
                cleaned_messages.append(message if message.endswith("\r\n") else self._normalize_seed_text(message))
                continue
            cleaned = self._sanitize_message(message)
            if cleaned:
                cleaned_messages.append(cleaned)
            else:
                dropped += 1
        if not cleaned_messages:
            return None, {
                "message_count_before": len(messages),
                "message_count_after": 0,
                "dropped_messages": dropped,
            }
        return self._render_messages(cleaned_messages), {
            "message_count_before": len(messages),
            "message_count_after": len(cleaned_messages),
            "dropped_messages": dropped,
        }

    def _validate_candidate_seed(
        self,
        candidate: str | None,
        *,
        original_seed: str | None = None,
        plan_payload: dict[str, Any] | None = None,
        context: dict[str, Any] | None = None,
        target_row: dict[str, Any] | None = None,
    ) -> tuple[str | None, str]:
        if not isinstance(candidate, str) or not candidate.strip():
            return None, "empty-generated-seed"
        extracted = self._extract_seed_from_blob(candidate)
        normalized = self._normalize_seed_text(extracted or candidate)
        if not normalized:
            return None, "empty-generated-seed"
        sanitized, _meta = self._sanitize_seed_candidate(normalized)
        if sanitized:
            normalized = sanitized
        messages = split_seed_messages(self.config.protocol, normalized)
        if not messages:
            return None, "seed-parse-failed"
        methods = [
            message_method(msg)
            for msg_idx, msg in enumerate(messages)
            if self._message_looks_sendable(msg)
            and not self._region_without_start_allowed(messages, msg_idx)
        ]
        if not methods:
            return None, "seed-has-no-message-method"
        if self.knowledge.templates:
            unknown = [method for method in methods if not self.knowledge.template_for_method(method)]
            if unknown:
                known = [method for method in methods if self.knowledge.template_for_method(method)]
                if not known:
                    return None, f"unknown-protocol-method:{unknown[0]}"
                filtered = [
                    msg
                    for msg_idx, msg in enumerate(messages)
                    if self.knowledge.template_for_method(message_method(msg))
                    or self._region_without_start_allowed(messages, msg_idx)
                ]
                normalized = self._render_messages(filtered)
                messages = split_seed_messages(self.config.protocol, normalized)
                methods = [
                    message_method(msg)
                    for msg_idx, msg in enumerate(messages)
                    if message_method(msg)
                    and not self._line_body_region_allowed(messages, msg_idx)
                ]
        if original_seed is not None and normalized == self._normalize_seed_text(original_seed):
            return None, "seed-unchanged"
        for msg_idx, msg in enumerate(messages):
            if not self._message_looks_sendable(msg):
                if self._region_without_start_allowed(messages, msg_idx):
                    continue
                return None, "malformed-message-start"
        plan_payload = plan_payload or {}
        allow_single = bool(plan_payload.get("allow_single_message"))
        preserve_prefix = 0 if allow_single else max(0, int(plan_payload.get("preserve_prefix_messages") or 0))
        original_messages: list[str] = []
        if original_seed is not None:
            original_messages = split_seed_messages(self.config.protocol, self._normalize_seed_text(original_seed))
            if preserve_prefix:
                if len(messages) < preserve_prefix or len(original_messages) < preserve_prefix:
                    return None, "prefix-not-preserved"
                if messages[:preserve_prefix] != original_messages[:preserve_prefix]:
                    return None, "prefix-not-preserved"
        if not allow_single and len(messages) < 2:
            return None, "single-message-not-allowed"
        if not allow_single and self.policy.required_prefix_chain:
            if any(method not in set(self.policy.prefix_optional_methods) for method in methods):
                if not self._has_required_prefix_chain(methods):
                    original_methods = [message_method(msg) for msg in original_messages if message_method(msg)]
                    if not original_methods or self._has_required_prefix_chain(original_methods):
                        return None, "missing-login-prefix"
        if self._oversize_message_lines(
            messages,
            int(plan_payload.get("max_line_length") or 4096),
            original_messages=original_messages or None,
            target_message_index=int(plan_payload.get("target_message_index") or 0),
        ):
            return None, "oversize-line"
        if self._generic_repetition_seed(normalized, plan_payload=plan_payload, target_row=target_row, context=context):
            return None, "generic-repetition-seed"
        if self.policy.content_length_validation:
            if not self._content_length_consistent(messages):
                return None, "content-length-mismatch"
        return normalized, ""

    def _generic_repetition_seed(
        self,
        normalized: str,
        *,
        plan_payload: dict[str, Any],
        target_row: dict[str, Any] | None,
        context: dict[str, Any] | None,
    ) -> bool:
        if self._target_looks_size_sensitive(target_row or {}, context or {}):
            return False
        op_names = {str(item.get("op") or "").strip().lower() for item in plan_payload.get("operators", []) if isinstance(item, dict)}
        if op_names and op_names != {"set_length"}:
            return False
        for line in str(normalized or "").splitlines():
            if len(line) < 256:
                continue
            if re.search(r"(.)\1{255,}", line):
                return True
            if re.search(r"(.{3,32})\1{11,}", line):
                return True
        return False

    @staticmethod
    def _oversize_message_lines(
        messages: list[str],
        max_line_length: int,
        *,
        original_messages: list[str] | None = None,
        target_message_index: int | None = None,
    ) -> bool:
        original_messages = list(original_messages or [])
        for msg_idx, message in enumerate(messages):
            original_lines = original_messages[msg_idx].split("\r\n") if msg_idx < len(original_messages) else []
            for line_idx, line in enumerate(message.split("\r\n")):
                if not line or len(line) <= max_line_length:
                    continue
                original_line = original_lines[line_idx] if line_idx < len(original_lines) else None
                if original_line and len(original_line) > max_line_length:
                    if msg_idx == target_message_index:
                        allowed_growth = max(64, min(256, max_line_length // 4))
                        if len(line) <= len(original_line) + allowed_growth:
                            continue
                    elif line == original_line:
                        continue
                return True
        return False

    def _has_required_prefix_chain(self, methods: list[str]) -> bool:
        chain = [item.upper() for item in self.policy.required_prefix_chain]
        if not chain:
            return True
        seen = [method.upper() for method in methods]
        position = -1
        for item in chain:
            try:
                position = next(idx for idx in range(position + 1, len(seen)) if seen[idx] == item)
            except StopIteration:
                return False
        return True

    def _region_without_start_allowed(self, messages: list[str], index: int) -> bool:
        return self._line_body_region_allowed(messages, index) or self._request_body_region_allowed(messages, index)

    def _request_body_region_allowed(self, messages: list[str], index: int) -> bool:
        if self.policy.message_style != "request-style" or index <= 0 or index >= len(messages):
            return False
        previous = str(messages[index - 1] or "")
        if "\r\n\r\n" not in previous:
            return False
        header_blob, inline_body = previous.split("\r\n\r\n", 1)
        if inline_body:
            return False
        match = re.search(r"(?im)^Content-Length:\s*(\d+)\s*$", header_blob)
        if not match:
            return False
        try:
            declared = int(match.group(1))
        except ValueError:
            return False
        if declared <= 0:
            return False
        current = str(messages[index] or "")
        if not current or "\r\n\r\n" in current:
            return False
        lengths = [len(current.encode("latin-1", errors="replace"))]
        lengths.append(len(current.replace("\r\n", "\n").encode("latin-1", errors="replace")))
        if current.endswith("\r\n"):
            lengths.append(len(current[:-2].encode("latin-1", errors="replace")))
        return declared in set(lengths)

    def _line_body_region_allowed(self, messages: list[str], index: int) -> bool:
        body_methods = {item.upper() for item in self.policy.line_body_methods}
        end_markers = {item.strip().upper() for item in self.policy.line_body_end_markers}
        if not body_methods or not end_markers:
            return False
        in_body = False
        for prior in messages[:index]:
            lines = str(prior or "").splitlines()
            first = lines[0].strip() if lines else ""
            upper = first.upper()
            if upper in body_methods:
                in_body = True
                continue
            if in_body and upper in end_markers:
                in_body = False
        if not in_body:
            return False
        lines = str(messages[index] or "").splitlines()
        first = lines[0].strip() if lines else ""
        upper = first.upper()
        return first == "" or upper in end_markers or bool(first)

    def _content_length_consistent(self, messages: list[str]) -> bool:
        for index, message in enumerate(messages):
            if "\r\n\r\n" in message:
                header_blob, body = message.split("\r\n\r\n", 1)
            else:
                header_blob, body = message, ""
            match = re.search(r"(?im)^Content-Length:\s*(\d+)\s*$", header_blob)
            if not match:
                continue
            try:
                declared = int(match.group(1))
            except ValueError:
                return False
            actual = len(body.encode("latin-1", errors="replace"))
            if declared == actual:
                continue
            if actual == 0 and self._request_body_region_allowed(messages, index + 1):
                body_region = str(messages[index + 1] or "")
                lengths = [len(body_region.encode("latin-1", errors="replace"))]
                lengths.append(len(body_region.replace("\r\n", "\n").encode("latin-1", errors="replace")))
                if body_region.endswith("\r\n"):
                    lengths.append(len(body_region[:-2].encode("latin-1", errors="replace")))
                if declared in set(lengths):
                    continue
                actual = lengths[0]
            if declared != actual:
                return False
        return True

    @staticmethod
    def _clip_text(text: str, limit: int = _TEXT_CLIP) -> str:
        value = str(text or "")
        if len(value) <= limit:
            return value or "(empty)"
        return value[:limit] + "\n...[truncated]"

    @staticmethod
    def _format_list(items: list[str], *, none_text: str = "- none") -> str:
        filtered = [str(item).strip() for item in items if str(item or "").strip()]
        return "\n".join(filtered) if filtered else none_text

    def _format_seed_queue(self, seed_text: str, *, limit: int = 10, clip: int = 360) -> str:
        messages = split_seed_messages(self.config.protocol, self._normalize_seed_text(seed_text or ""))
        lines: list[str] = []
        for idx, message in enumerate(messages[:limit]):
            escaped = message.encode("unicode_escape", errors="replace").decode("ascii")
            if len(escaped) > clip:
                escaped = escaped[:clip] + "...[truncated]"
            lines.append(f'- msg[{idx}] bytes={len(message.encode("latin-1", errors="replace"))}: "{escaped}"')
        if len(messages) > limit:
            lines.append(f"- ... {len(messages) - limit} more AFLNet regions omitted")
        return "\n".join(lines) if lines else "- none"

    @staticmethod
    def _compact_json(data: Any) -> str:
        return json.dumps(data, ensure_ascii=False, separators=(",", ":"))

    def _field_evidence_lines(self, context: dict[str, Any]) -> list[str]:
        lines: list[str] = []
        for fact in context.get("field_facts", [])[:6]:
            mapped_vars = []
            for mapping in fact.get("mapped_variables", [])[:2]:
                for variable in mapping.get("variables", [])[:3]:
                    if variable and variable not in mapped_vars:
                        mapped_vars.append(variable)
            lines.append(
                "- field={field} cmd={cmd} vars={vars} tags={tags}".format(
                    field=fact.get("field_name") or "?",
                    cmd=fact.get("parent_command") or "?",
                    vars=",".join(mapped_vars) or "-",
                    tags=",".join(fact.get("risk_tags", [])[:3]) or "-",
                )
            )
        return lines

    def _static_ref_lines(self, context: dict[str, Any]) -> list[str]:
        lines: list[str] = []
        for ref in context.get("static_refs", [])[:6]:
            lines.append(
                "- field={field} cmd={cmd} range={byte_range}".format(
                    field=ref.get("field_name") or "?",
                    cmd=ref.get("command") or "?",
                    byte_range=ref.get("byte_range") or "-",
                )
            )
        return lines

    def _template_lines(self, context: dict[str, Any]) -> list[str]:
        lines: list[str] = []
        for item in context.get("command_templates", [])[:4]:
            summary = str(item.get("constraint_summary") or "").strip()
            if summary:
                lines.append(f"- {summary}")
            else:
                lines.append(f"- {item['command']}: {item['template']}")
        return lines

    def _template_constraint_lines(self, context: dict[str, Any]) -> list[str]:
        lines: list[str] = []
        for item in context.get("template_constraints", [])[:6]:
            if not isinstance(item, dict):
                continue
            method = str(item.get("method") or "?")
            style = str(item.get("message_style") or "?")
            rendered: list[str] = []
            for binding in item.get("bindings", [])[:5]:
                if not isinstance(binding, dict):
                    continue
                placeholders = list(binding.get("canonical_placeholders") or binding.get("placeholder_names") or [])[:4]
                rendered.append(
                    f"{binding.get('mutation_field')}<=({','.join(str(name) for name in placeholders if str(name).strip()) or '-'})"
                )
            lines.append(f"- {method} [{style}]: {'; '.join(rendered) if rendered else '-'}")
        return lines

    def _boundary_goal_lines(self, task: dict[str, Any], payload: dict[str, Any], target_row: dict[str, Any]) -> list[str]:
        if task.get("kind") != "boundary-generate":
            return []
        lines = []
        condition_expr = str(payload.get("condition_expr") or target_row.get("code") or "").strip()
        if condition_expr:
            lines.append(f"- condition: {condition_expr}")
        if payload.get("covered_branch_side") is not None:
            lines.append(f"- covered_side: {payload.get('covered_branch_side')}")
        if payload.get("missing_branch_side") is not None:
            lines.append(f"- target_side: {payload.get('missing_branch_side')}")
        return lines

    def _context_block_for_plan(self, context: dict[str, Any]) -> str:
        methods = ",".join(context.get("methods", [])[:12]) or "-"
        source_excerpt = self._clip_text(context.get("source_excerpt", ""), 2600)
        source_kind = context.get("source_excerpt_kind") or "none"
        source_path = context.get("source_path") or "-"
        all_messages = list(context.get("messages_before", [])) + [context.get("current_message", "")] + list(context.get("messages_after", []))
        sequence_lines = []
        for idx, message in enumerate(all_messages):
            pieces = str(message or "").splitlines()
            first_line = pieces[0] if pieces else "(empty)"
            sequence_lines.append(f"- msg[{idx}]: {first_line}")
        return f"""Seed summary:
- methods: {methods}
- focus_step: {context.get('step_index', 0)}

Message sequence:
{self._format_list(sequence_lines)}

Prefix before current message:
{self._clip_text(context.get('prefix_text', ''))}

Current message:
{self._clip_text(context.get('current_message', ''))}

Remaining messages:
{self._clip_text(''.join(context.get('messages_after', [])))}

Target source excerpt ({source_kind}, {source_path}):
{source_excerpt}
"""

    def _build_plan_prompt(self, task: dict[str, Any], target_row: dict[str, Any], context: dict[str, Any], payload: dict[str, Any]) -> str:
        kind_name = "boundary breakthrough" if task["kind"] == "boundary-generate" else "vulnerability stress"
        return f"""Task kind: {kind_name}
Implementation: {self.config.implementation}
Protocol: {self.config.protocol}
Subject: {self.config.subject}
Evidence mode: {context.get('evidence_mode', 'function')}

Target:
- file: {target_row['relative_path']}
- line: {target_row['line']}
- function: {target_row['function_name']}
- code: {target_row['code']}
- scheduler_reason: {payload.get('reason', '')}

Boundary goal:
{self._format_list(self._boundary_goal_lines(task, payload, target_row))}

Dynamic field evidence:
{self._format_list(self._field_evidence_lines(context))}

Static field evidence:
{self._format_list(self._static_ref_lines(context))}

Relevant templates:
{self._format_list(self._template_lines(context))}

Template-derived mutation fields:
{self._format_list(self._template_constraint_lines(context))}

{self._context_block_for_plan(context)}
Your job:
- Decide whether a realistic protocol-level mutation can influence this target.
- Treat dynamic taint, static taint, CodeQL matches, templates, and target_fields as evidence, not hard constraints.
- Choose the protocol message, field, value, and state strategy yourself; it is valid to ignore suggested fields when source context points elsewhere.
- Produce a mutation specification, not raw seed bytes.
- Keep the preserved prefix messages byte-identical whenever possible.
- Prefer targeted semantic mutations over blind length growth, unless the target code strongly suggests a size-sensitive copy or format path.
- Avoid giant strings unless the target code strongly suggests a size-sensitive copy or format path.
- Before choosing operators, state the causal input hypothesis in target_hypothesis.
- Use only canonical fields that appear in the provided template constraints, static refs, or field facts.
- Every concrete payload or repeated-count idea in target_hypothesis.target_values must also appear in executable operators[].values.
- Return SKIP only when you cannot form any executable, sendable, protocol-consistent mutation hypothesis.
- If the current seed already reaches the target branch or line, treat reachability itself as strong evidence and prefer a bounded exploration plan over SKIP.

Return exactly one JSON object with this minimal schema:
{{
  "decision": "GENERATE" or "SKIP",
  "reason": "under 12 words",
  "trigger_class": "plain_field | state_sequence | overlong_line_error_path | multipart_body_state | missing_delimiter_bounded_slice | size_sensitive_copy | format_string | temporal_wait | data_channel_fault | filesystem_race | config_policy | external_oracle",
  "target_hypothesis": {{
    "trigger_class": "same value as trigger_class",
    "source_condition": "target condition or sink in plain terms",
    "protocol_path": "required protocol state/messages",
    "controlling_field": "protocol field that controls the condition",
    "target_values": ["specific literals, numeric boundaries, or short payloads"],
    "state_requirements": ["messages that must be preserved"],
    "expected_branch_effect": "which boundary side or sink behavior should change",
    "why_not_length_only": "why length-only is or is not justified"
  }},
  "operators": [
    {{"msg_index": 0, "field": "recipient-address", "op": "set_literal", "values": ["specific-value"]}}
  ],
  "target_message_index": 0,
  "state_strategy": {{
    "preserve_prefix_messages": 0,
    "allow_single_message": false
  }},
  "fixups": ["content_length", "cseq"],
  "inject_limit": 2,
  "target_fields": ["optional fallback field names"],
  "needs_evidence": []
}}

One-shot guidance:
- GOOD: if source compares a command, method, header, enum, path token, or numeric constant, use set_literal/set_numeric on that field with the concrete value.
- GOOD: use set_length only when source excerpt shows length, size, buffer copy, allocation, format, or Content-Length-sensitive code.
- GOOD: for stateful targets, use trigger_class=state_sequence and repeat_messages on message_sequence when the hypothesis requires repeated parser passes or repeated state transitions.
- GOOD: for command readers and error loggers, use trigger_class=overlong_line_error_path and target the first command line/argument.
- GOOD: for SIP multipart SDP parser state, use trigger_class=multipart_body_state and mutate both header:Content-Type and body.
- GOOD: for ptr,len slices treated as C strings, use trigger_class=missing_delimiter_bounded_slice and omit the closing delimiter in a bounded header/body field.
- BAD: do not answer every vulnerability with set_length 8192, repeated path segments, or generic A-filled strings.
- BAD: do not use repeat_messages unless target_hypothesis explains the state cycle or repeated parser path.
- BAD: do not simulate repeated commands by concatenating multiple command tokens inside one message argument; duplicate whole AFLNet regions/messages instead.
- BAD: do not mutate a field unless target_hypothesis explains how that field reaches the condition.
- BAD: do not propose a value that is already identical to the current targeted field unless the intended mechanism is explicit region repetition or preserved-state reuse.

Field rules:
- Put operators before any optional keys.
- Prefer explicit selectors in operators. Each operator should usually include msg_index.
- For line-command protocols, prefer canonical placeholder field names from the provided template constraints; otherwise use argument, body, METHOD.argument, or METHOD.body.
- For request-style protocols, field should be one of: request_uri, body, start_line, method, header:Name, message_sequence.
- Use target_fields only as a short fallback hint list when needed.

Rules:
- If there is no executable, sendable, protocol-consistent path, return SKIP.
- If the target requires temporal_wait, data_channel_fault, filesystem_race, config_policy, or external_oracle behavior, return SKIP because the current executor cannot create that effect.
- Keep reason and every string concise.
- Keep target_hypothesis concise but complete; it is used by a local critic before execution.
- preserve_prefix_messages counts the leading messages that must remain byte-identical.
- Do not target any operator at a message index earlier than preserve_prefix_messages.
- If the current context already contains only one runnable message and preserve_prefix_messages is 0, set allow_single_message to true.
- Only use these operators: set_length, inject, append, prepend, set_literal, set_numeric, repeat_messages.
- No markdown. No code fence.
"""

    def _build_plan_revision_prompt(
        self,
        task: dict[str, Any],
        target_row: dict[str, Any],
        context: dict[str, Any],
        payload: dict[str, Any],
        plan_payload: dict[str, Any],
        findings: list[dict[str, Any]],
    ) -> str:
        return f"""The previous mutation plan was rejected by the local critic.

Critic findings:
{self._format_list([self._compact_json(item) for item in findings])}

Previous sanitized plan:
{self._compact_json(plan_payload)}

Revise the plan. Keep the target realistic and protocol-reachable.
- Fix every hard critic finding.
- If the critic says state_sequence needs repeat_messages, revise to op=repeat_messages on message_sequence with numeric repeat counts only.
- If the critic says a size_sensitive_copy plan needs a boundary sweep, revise to numeric set_length boundary values only; do not use natural-language placeholders.
- If the critic says the plan is a no-op against the current seed, choose a concretely different protocol-significant value or region placement; do not reuse the current field value verbatim.
- If no executable, sendable, protocol-consistent mutation hypothesis is defensible, return SKIP.
- Do not use length-only mutation unless the source excerpt clearly supports size/copy/format behavior.
- Return the same JSON schema required below.

{self._build_plan_prompt(task, target_row, context, payload)}
"""

    def _aflnet_region_rule_lines(self) -> list[str]:
        rules = [str(item).strip() for item in self.policy.aflnet_region_rules if str(item).strip()]
        return rules or ["Preserve the current AFLNet region boundaries for this protocol."]

    def _build_generation_prompt(
        self,
        task: dict[str, Any],
        target_row: dict[str, Any],
        context: dict[str, Any],
        payload: dict[str, Any],
        seed_text: str,
        plan_payload: dict[str, Any],
        *,
        critic_findings: list[dict[str, Any]] | None = None,
    ) -> str:
        kind_name = "boundary breakthrough" if task["kind"] == "boundary-generate" else "vulnerability stress"
        critic_block = ""
        if critic_findings:
            critic_block = f"""
Local critic findings on the plan:
{self._format_list([self._compact_json(item) for item in critic_findings])}

Interpretation:
- The plan was too weak or incomplete for strict executor-only use.
- You may still generate a valid seed if you preserve protocol reachability and target intent.
"""
        return f"""Task kind: {kind_name}
Protocol: {self.config.protocol}
Evidence mode: {context.get('evidence_mode', 'function')}
Target file/function/line: {target_row['relative_path']} :: {target_row['function_name']} :: {target_row['line']}
Target code: {target_row['code']}

Boundary goal:
{self._format_list(self._boundary_goal_lines(task, payload, target_row))}

Relevant templates:
{self._format_list(self._template_lines(context))}

Template-derived mutation fields:
{self._format_list(self._template_constraint_lines(context))}

Approved mutation plan:
{self._compact_json(plan_payload)}
{critic_block}

Original full seed:
{seed_text}

Original AFLNet message queue / packet regions:
{self._format_seed_queue(seed_text)}

Generate exactly one complete mutated seed. Treat the plan, taint facts, CodeQL hints, and field names as evidence, not hard constraints.
Think like an agent, not a paraphraser:
- Choose the protocol message, field, value, and state prefix most likely to influence the target, even if that differs from the suggested field.
- Prefer expressing the mutation as a message queue transformation, not a single opaque full-seed rewrite.
- Keep only the protocol messages needed to establish state and deliver the mutation.
- Do not copy opaque AFL garbage lines or corrupted prefixes unless they are intentionally required for the target effect.
- If special bytes are necessary, keep the surrounding message runnable and encode bytes with valid JSON string escapes such as \u0000.
- Prefer a clean executable seed over a noisy verbatim replay of the original fuzzed bytes.
- For boundary tasks, aim to flip the target condition; for vulnerability tasks, stress the vulnerable parser or sink with target-aware values.

Return exactly one JSON object. Prefer mutated_messages, where each item is one complete AFLNet packet/region:
{{
  "decision": "GENERATE" or "SKIP",
  "reason": "one short sentence",
  "mutated_messages": ["complete AFLNet region 0 with explicit \r\n escapes", "complete AFLNet region 1 with explicit \r\n escapes"],
  "mutated_seed": "optional fallback full seed string; use empty string when mutated_messages is present"
}}

AFLNet region boundaries you must preserve:
{self._format_list([f"- {line}" for line in self._aflnet_region_rule_lines()])}

Rules:
- If decision is SKIP, mutated_messages must be [] and mutated_seed must be "".
- If decision is GENERATE, mutated_messages must be a full sendable queue, not a diff and not a fragment.
- For repeated-command or repeated-parser hypotheses, duplicate whole AFLNet regions/messages; do not stuff multiple logical commands into one region.
- Preserve the state-establishing prefix when needed, but keep body-only AFLNet regions only when the current protocol policy allows them.
- The result must be sendable by AFLNet even if some bytes are unusual.
- No markdown. No code fence.
"""

    def _build_repair_prompt(
        self,
        task: dict[str, Any],
        target_row: dict[str, Any],
        context: dict[str, Any],
        payload: dict[str, Any],
        seed_text: str,
        plan_payload: dict[str, Any],
        candidate: str,
        validation_error: str,
        attempt: int,
        *,
        critic_findings: list[dict[str, Any]] | None = None,
    ) -> str:
        kind_name = "boundary breakthrough" if task["kind"] == "boundary-generate" else "vulnerability stress"
        critic_block = ""
        if critic_findings:
            critic_block = f"""
Local critic findings on the plan:
{self._format_list([self._compact_json(item) for item in critic_findings])}
"""
        duplicate_block = ""
        if str(validation_error or "").startswith("seed-duplicate"):
            duplicate_block = """
- The previous candidate exactly matched a known seed body.
- Change at least one protocol-significant region, field, or value while keeping the queue runnable.
- Do not return the original seed or the same message queue with cosmetic-only formatting changes.
"""
        return f"""Task kind: {kind_name}
Protocol: {self.config.protocol}
Repair attempt: {attempt}
Target file/function/line: {target_row['relative_path']} :: {target_row['function_name']} :: {target_row['line']}
Target code: {target_row['code']}
Validation error: {validation_error}
{critic_block}

Boundary goal:
{self._format_list(self._boundary_goal_lines(task, payload, target_row))}

Relevant templates:
{self._format_list(self._template_lines(context))}

Approved mutation plan:
{self._compact_json(plan_payload)}

Original full seed:
{seed_text}

Original AFLNet message queue / packet regions:
{self._format_seed_queue(seed_text)}

Broken candidate seed:
{candidate or '(empty)'}

Fix the candidate so it becomes one sendable complete protocol seed while preserving the mutation intent.
Repair workflow:
- First identify why the candidate is not sendable.
- Keep the useful state-establishing messages and the intended target mutation.
- Remove or rewrite corrupted garbage lines that are not real protocol messages.
- If unusual bytes are intentionally required, keep them inside an otherwise runnable message and encode them with valid JSON escapes such as \u0000.
- If the seed already contains enough useful messages, prefer rewriting only the broken message instead of regenerating everything.
{duplicate_block}

Return exactly one JSON object. Prefer mutated_messages, where each item is one complete AFLNet packet/region:
{{
  "decision": "GENERATE" or "SKIP",
  "reason": "one short sentence",
  "mutated_messages": ["complete AFLNet region 0 with explicit \r\n escapes", "complete AFLNet region 1 with explicit \r\n escapes"],
  "mutated_seed": "optional fallback full seed string; use empty string when mutated_messages is present"
}}

Rules:
- If repair is impossible, return SKIP with mutated_messages=[] and mutated_seed="".
- Preserve the intended target effect.
- Output one full sendable AFLNet queue only.
- The repaired seed must be executable by AFLNet, not necessarily pretty.
- No markdown. No code fence.
"""

    def _default_target_fields(self, context: dict[str, Any]) -> list[str]:
        fields: list[str] = []
        for fact in context.get("field_facts", [])[:4]:
            name = str(fact.get("field_name") or "").strip()
            if name and name not in fields:
                fields.append(name)
        for ref in context.get("static_refs", [])[:4]:
            name = str(ref.get("field_name") or "").strip()
            if name and name not in fields:
                fields.append(name)
        return fields

    @staticmethod
    def _sanitize_text_list(value: Any, limit: int = 6) -> list[str]:
        items = value if isinstance(value, list) else []
        cleaned: list[str] = []
        for item in items[:limit]:
            text = str(item or "").strip()
            if text and text not in cleaned:
                cleaned.append(text)
        return cleaned

    def _sanitize_target_hypothesis(self, payload: dict[str, Any]) -> dict[str, Any]:
        raw = payload.get("target_hypothesis") if isinstance(payload.get("target_hypothesis"), dict) else {}

        def clean_text(key: str, limit: int = 240) -> str:
            return str(raw.get(key) or "").strip()[:limit]

        trigger_class = self._normalize_trigger_class(raw.get("trigger_class") or payload.get("trigger_class"))
        return {
            "trigger_class": trigger_class,
            "source_condition": clean_text("source_condition"),
            "protocol_path": clean_text("protocol_path"),
            "controlling_field": clean_text("controlling_field", limit=160),
            "target_values": self._sanitize_text_list(raw.get("target_values"), limit=8),
            "state_requirements": self._sanitize_text_list(raw.get("state_requirements"), limit=6),
            "expected_branch_effect": clean_text("expected_branch_effect"),
            "why_not_length_only": clean_text("why_not_length_only"),
        }

    def _build_default_operators(self, task: dict[str, Any], target_fields: list[str]) -> list[dict[str, Any]]:
        lengths = self.policy.default_boundary_lengths if task.get("kind") == "boundary-generate" else self.policy.default_vuln_lengths
        field = target_fields[0] if target_fields else "request_uri"
        return [
            {"field": field, "op": "set_length", "values": [int(v) for v in lengths[:4]]},
            {"field": field, "op": "inject", "values": list(self.policy.default_injections[:2])},
        ]

    @staticmethod
    def _normalize_operator_msg_index(raw: Any) -> int | None:
        if raw is None or raw == "":
            return None
        try:
            return max(0, int(raw))
        except (TypeError, ValueError):
            return None

    def _normalize_operator_field(self, field: str) -> str:
        normalized = str(field or "").strip()
        lowered = normalized.lower()
        if lowered in {"request_line", "request-line"}:
            return "start_line"
        if lowered == "method":
            return "method"
        return normalized

    def _sanitize_spec_operators(self, payload: dict[str, Any], task: dict[str, Any], target_fields: list[str]) -> list[dict[str, Any]]:
        raw_items = payload.get("operators") if isinstance(payload.get("operators"), list) else []
        payload["operators_explicitly_empty"] = isinstance(payload.get("operators"), list) and not raw_items
        allowed_ops = {"set_length", "inject", "append", "prepend", "set_literal", "set_numeric", "delete", "repeat_messages"}
        operators: list[dict[str, Any]] = []
        rejected: list[dict[str, Any]] = []
        for index, item in enumerate(raw_items[:4]):
            if not isinstance(item, dict):
                rejected.append({"index": index, "reason": "non-dict-operator", "raw": item})
                continue
            op_name = str(item.get("op") or "").strip().lower()
            field = self._normalize_operator_field(str(item.get("field") or "").strip())
            if op_name == "repeat_messages" and not field:
                field = "message_sequence"
            values = item.get("values") if isinstance(item.get("values"), list) else []
            if op_name not in allowed_ops:
                rejected.append({"index": index, "reason": "unsupported-op", "op": op_name, "field": field, "raw": item})
                continue
            if not field:
                rejected.append({"index": index, "reason": "missing-field", "op": op_name, "raw": item})
                continue
            if not values:
                rejected.append({"index": index, "reason": "missing-values", "op": op_name, "field": field, "raw": item})
                continue
            if op_name == "set_literal" and field.lower().startswith("header:"):
                raw_texts = ["" if value is None else str(value) for value in values[:8]]
                if raw_texts and all(raw_text == "" for raw_text in raw_texts):
                    operator = {"field": field, "op": "delete", "values": ["__delete__"]}
                    msg_index = self._normalize_operator_msg_index(item.get("msg_index"))
                    if msg_index is not None:
                        operator["msg_index"] = msg_index
                    operators.append(operator)
                    continue
            cleaned_values: list[Any] = []
            for value in values[:8]:
                if isinstance(value, (int, float)):
                    cleaned_values.append(int(value))
                    continue
                if value is None:
                    continue
                raw_text = str(value)
                if op_name in {"set_length", "set_numeric", "repeat_messages"}:
                    stripped = raw_text.strip()
                    if stripped:
                        cleaned_values.append(stripped)
                    continue
                if raw_text == "":
                    continue
                cleaned_values.append(raw_text)
            if cleaned_values:
                operator = {"field": field, "op": op_name, "values": cleaned_values}
                msg_index = self._normalize_operator_msg_index(item.get("msg_index"))
                if msg_index is not None:
                    operator["msg_index"] = msg_index
                operators.append(operator)
            else:
                rejected.append({"index": index, "reason": "all-values-filtered", "op": op_name, "field": field, "raw_values": values, "raw": item})
        payload["sanitized_operator_rejections"] = rejected
        if operators:
            return operators
        if task.get("kind") == "boundary-generate":
            return []
        return self._build_default_operators(task, target_fields)

    def _normalize_fixups(self, payload: dict[str, Any]) -> list[str]:
        fixups = []
        for item in self._sanitize_text_list(payload.get("fixups"), limit=6):
            value = item.lower()
            if value not in fixups:
                fixups.append(value)
        for item in self.policy.default_fixups:
            if item not in fixups:
                fixups.append(item)
        return fixups

    def _default_max_line_length(self, operators: list[dict[str, Any]], task: dict[str, Any]) -> int:
        lengths = []
        for item in operators:
            if item.get("op") != "set_length":
                continue
            for value in item.get("values", []):
                try:
                    lengths.append(int(value))
                except (TypeError, ValueError):
                    continue
        base = max(lengths) if lengths else max(self.policy.default_vuln_lengths)
        is_vuln = task.get("kind") == "vuln-generate"
        cap = self.policy.vuln_line_length_cap if is_vuln else self.policy.boundary_line_length_cap
        return max(512, min(cap, max(base * 2, 512)))

    def _sanitize_plan_payload(self, payload: dict[str, Any], context: dict[str, Any], target_row: dict[str, Any], task: dict[str, Any]) -> dict[str, Any]:
        current_method = str(context.get("methods", [""]) [min(int(context.get("step_index", 0) or 0), max(len(context.get("methods", [])) - 1, 0))] if context.get("methods") else "").upper()
        default_allow_single = function_allows_single_message(self.policy, str(target_row.get("function_name") or ""), current_method)
        strategy = payload.get("state_strategy") if isinstance(payload.get("state_strategy"), dict) else {}
        target_fields = self._sanitize_text_list(payload.get("target_fields"), limit=6) or self._default_target_fields(context)
        operators = self._sanitize_spec_operators(payload, task, target_fields)
        payload["sanitized_target_fields"] = list(target_fields)
        preserve_prefix_messages = strategy.get("preserve_prefix_messages", payload.get("preserve_prefix_messages", context.get("step_index", 0)))
        try:
            preserve_prefix_messages = max(0, int(preserve_prefix_messages))
        except (TypeError, ValueError):
            preserve_prefix_messages = max(0, int(context.get("step_index", 0) or 0))
        target_message_index = payload.get("target_message_index", context.get("step_index", 0))
        try:
            target_message_index = max(0, int(target_message_index))
        except (TypeError, ValueError):
            target_message_index = max(0, int(context.get("step_index", 0) or 0))
        preserve_prefix_messages = min(preserve_prefix_messages, target_message_index)
        required_success_prefix_messages = min(target_message_index, self._required_success_prefix_from_context(context, {"target_message_index": target_message_index}))
        allow_single_message = bool(strategy.get("allow_single_message", payload.get("allow_single_message", default_allow_single)))
        single_message_context = max(0, len(context.get("methods", []) or [])) <= 1
        no_prefix_context = target_message_index <= 0 and preserve_prefix_messages <= 0
        if task.get("kind") == "boundary-generate" and single_message_context and no_prefix_context and required_success_prefix_messages <= 0:
            allow_single_message = True
        if required_success_prefix_messages > 0:
            allow_single_message = False
            preserve_prefix_messages = max(preserve_prefix_messages, required_success_prefix_messages)
        if allow_single_message:
            preserve_prefix_messages = 0
        result = {
            "decision": str(payload.get("decision") or "GENERATE").strip().upper() or "GENERATE",
            "reason": str(payload.get("reason") or "").strip(),
            "trigger_class": self._sanitize_target_hypothesis(payload).get("trigger_class", ""),
            "target_hypothesis": self._sanitize_target_hypothesis(payload),
            "needs_evidence": self._sanitize_text_list(payload.get("needs_evidence"), limit=6),
            "mutation_focus": str(payload.get("mutation_focus") or "").strip(),
            "target_fields": target_fields,
            "constraints": self._sanitize_text_list(payload.get("constraints"), limit=6) or [
                "preserve the required prefix sequence",
                "keep protocol structure coherent",
            ],
            "expected_effect": str(payload.get("expected_effect") or self._sanitize_target_hypothesis(payload).get("expected_branch_effect") or "").strip(),
            "target_message_index": target_message_index,
            "preserve_prefix_messages": preserve_prefix_messages,
            "required_success_prefix_messages": required_success_prefix_messages,
            "allow_single_message": bool(allow_single_message),
            "operators": operators,
            "operators_explicitly_empty": bool(payload.get("operators_explicitly_empty")),
            "fixups": self._normalize_fixups(payload),
            "max_candidates": max(1, min(self.policy.max_candidates, int(payload.get("max_candidates") or self.policy.max_candidates))),
            "inject_limit": max(1, min(3, int(payload.get("inject_limit") or (2 if task.get("kind") == "boundary-generate" else 3)))),
        }
        payload_parse_error = str(payload.get("__payload_parse_error__") or "").strip()
        if payload_parse_error:
            result["payload_parse_error"] = payload_parse_error
        result["max_line_length"] = self._default_max_line_length(result["operators"], task)
        return result

    @staticmethod
    def _parse_decision(text: str) -> str:
        match = _DECISION_RE.search(text or "")
        if match:
            return match.group(1).upper()
        json_match = re.search(r'"decision"\s*:\s*"(GENERATE|SKIP)"', text or "", re.IGNORECASE)
        if json_match:
            return json_match.group(1).upper()
        return "SKIP"

    @staticmethod
    def _parse_reason(text: str) -> str:
        match = _REASON_RE.search(text or "")
        if match:
            return match.group(1).strip()
        json_match = re.search(r'"reason"\s*:\s*"([^"]+)"', text or "", re.IGNORECASE)
        return json_match.group(1).strip() if json_match else ""
