"""Spec-driven seed mutation executor."""

from __future__ import annotations

from dataclasses import dataclass
import copy
import re
from typing import Any

from .protocol_policy import ProtocolMutationPolicy
from .seed_utils import message_method, split_seed_messages


@dataclass
class GeneratedSeedCandidate:
    seed_text: str
    summary: str
    mutated_fields: list[str]


@dataclass
class RequestMessage:
    raw: str
    start_line: str
    headers: list[tuple[str, str]]
    body: str

    @property
    def method(self) -> str:
        return message_method(self.start_line)


@dataclass
class LineCommandMessage:
    raw: str
    method: str
    argument: str
    body: str = ""
    raw_start: int = 0
    raw_end: int = 1


FTPMessage = LineCommandMessage
SMTPMessage = LineCommandMessage


class SpecDrivenMutationExecutor:
    """Apply a constrained mutation spec to a seed while preserving protocol structure."""

    def __init__(self, *, protocol: str, policy: ProtocolMutationPolicy):
        self.protocol = str(protocol or "").upper()
        self.policy = policy

    @staticmethod
    def _match_terms(*values: Any) -> set[str]:
        terms: set[str] = set()
        for value in values:
            text = str(value or "").strip().lower()
            if not text:
                continue
            compact = re.sub(r"[^a-z0-9]+", " ", text)
            for token in compact.split():
                if token:
                    terms.add(token)
            collapsed = compact.replace(" ", "")
            if collapsed:
                terms.add(collapsed)
        return terms

    @staticmethod
    def _term_overlap_score(left: set[str], right: set[str]) -> int:
        if not left or not right:
            return 0
        score = len(left & right)
        if score:
            return score
        joined_left = " ".join(sorted(left))
        joined_right = " ".join(sorted(right))
        return 1 if joined_left and joined_right and (joined_left in joined_right or joined_right in joined_left) else 0

    @staticmethod
    def _context_template_constraint_map(context: dict[str, Any]) -> dict[str, dict[str, Any]]:
        result: dict[str, dict[str, Any]] = {}
        for item in context.get("template_constraints", []):
            if not isinstance(item, dict):
                continue
            method = str(item.get("method") or "").strip().upper()
            if method and method not in result:
                result[method] = item
        return result

    def execute(
        self,
        *,
        seed_text: str,
        context: dict[str, Any],
        plan_payload: dict[str, Any],
        task_kind: str,
    ) -> list[GeneratedSeedCandidate]:
        if self.policy.message_style == "line-command":
            candidates = self._execute_line_commands(seed_text=seed_text, context=context, plan_payload=plan_payload, task_kind=task_kind)
        else:
            candidates = self._execute_request_style(seed_text=seed_text, context=context, plan_payload=plan_payload, task_kind=task_kind)
        return self._filter_success_prefix_candidates(seed_text=seed_text, plan_payload=plan_payload, candidates=candidates)

    def _filter_success_prefix_candidates(
        self,
        *,
        seed_text: str,
        plan_payload: dict[str, Any],
        candidates: list[GeneratedSeedCandidate],
    ) -> list[GeneratedSeedCandidate]:
        try:
            required_prefix = max(0, int(plan_payload.get("required_success_prefix_messages") or 0))
        except (TypeError, ValueError):
            required_prefix = 0
        if required_prefix <= 0 or not candidates:
            return candidates
        original_messages = split_seed_messages(self.protocol, seed_text)
        if len(original_messages) < required_prefix:
            return []
        filtered: list[GeneratedSeedCandidate] = []
        for candidate in candidates:
            candidate_messages = split_seed_messages(self.protocol, candidate.seed_text)
            if len(candidate_messages) < required_prefix:
                continue
            if candidate_messages[:required_prefix] != original_messages[:required_prefix]:
                continue
            filtered.append(candidate)
        return filtered

    def explain_empty_generation(
        self,
        *,
        seed_text: str,
        context: dict[str, Any],
        plan_payload: dict[str, Any],
        task_kind: str,
    ) -> dict[str, Any] | None:
        if self.policy.message_style == "line-command":
            return self._explain_empty_line_command_generation(
                seed_text=seed_text,
                context=context,
                plan_payload=plan_payload,
                task_kind=task_kind,
            )
        return self._explain_empty_request_generation(
            seed_text=seed_text,
            context=context,
            plan_payload=plan_payload,
            task_kind=task_kind,
        )

    def _execute_line_commands(
        self,
        *,
        seed_text: str,
        context: dict[str, Any],
        plan_payload: dict[str, Any],
        task_kind: str,
    ) -> list[GeneratedSeedCandidate]:
        raw_messages = split_seed_messages(self.protocol, seed_text)
        messages = self._parse_line_command_messages(raw_messages)
        if not messages:
            return []
        raw_target_index = self._resolve_target_message_index(plan_payload, context, len(raw_messages))
        target_index = self._map_line_command_message_index(messages, raw_target_index)
        raw_preserve_prefix = self._resolve_preserve_prefix(
            plan_payload,
            context,
            messages[target_index].method,
            len(raw_messages),
            raw_target_index,
        )
        preserve_prefix = min(target_index, self._map_line_command_message_index(messages, raw_preserve_prefix))
        candidates = self._apply_line_command_sequence_operators(
            messages=messages,
            target_index=target_index,
            preserve_prefix=preserve_prefix,
            plan_payload=plan_payload,
        )
        seen = {candidate.seed_text for candidate in candidates}
        selectors = self._explicit_line_command_selectors(messages, target_index, preserve_prefix, plan_payload, context)
        if not selectors:
            selectors = self._select_line_command_fields(messages, target_index, preserve_prefix, plan_payload, context)
        if len(candidates) >= int(plan_payload.get("max_candidates") or self.policy.max_candidates):
            return candidates[: int(plan_payload.get("max_candidates") or self.policy.max_candidates)]
        for selector in selectors:
            for candidate in self._apply_line_command_selector(
                raw_messages=raw_messages,
                messages=messages,
                selector=selector,
                target_index=target_index,
                preserve_prefix=preserve_prefix,
                plan_payload=plan_payload,
                task_kind=task_kind,
            ):
                if candidate.seed_text not in seen:
                    candidates.append(candidate)
                    seen.add(candidate.seed_text)
                if len(candidates) >= int(plan_payload.get("max_candidates") or self.policy.max_candidates):
                    return candidates
        return candidates

    def _execute_request_style(
        self,
        *,
        seed_text: str,
        context: dict[str, Any],
        plan_payload: dict[str, Any],
        task_kind: str,
    ) -> list[GeneratedSeedCandidate]:
        raw_messages = split_seed_messages(self.protocol, seed_text)
        messages = [self._parse_request_message(msg) for msg in raw_messages]
        if not messages:
            return []
        target_index = self._resolve_target_message_index(plan_payload, context, len(messages))
        preserve_prefix = self._resolve_preserve_prefix(plan_payload, context, messages[target_index].method, len(messages), target_index)
        selectors = self._explicit_request_selectors(messages, target_index, preserve_prefix, plan_payload)
        if not selectors:
            selectors = self._select_request_fields(messages, target_index, preserve_prefix, plan_payload, context)
        candidates: list[GeneratedSeedCandidate] = []
        seen = set()
        for candidate in self._apply_request_sequence_operators(
            raw_messages=raw_messages,
            messages=messages,
            target_index=target_index,
            preserve_prefix=preserve_prefix,
            plan_payload=plan_payload,
        ):
            if candidate.seed_text not in seen:
                candidates.append(candidate)
                seen.add(candidate.seed_text)
            if len(candidates) >= int(plan_payload.get("max_candidates") or self.policy.max_candidates):
                return candidates
        for selector in selectors:
            for candidate in self._apply_request_selector(
                raw_messages=raw_messages,
                messages=messages,
                selector=selector,
                target_index=target_index,
                preserve_prefix=preserve_prefix,
                plan_payload=plan_payload,
                task_kind=task_kind,
                allow_single=bool(plan_payload.get("allow_single_message")),
            ):
                if candidate.seed_text not in seen:
                    candidates.append(candidate)
                    seen.add(candidate.seed_text)
                if len(candidates) >= int(plan_payload.get("max_candidates") or self.policy.max_candidates):
                    return candidates
        return candidates

    def _parse_line_command_message(self, message: str) -> LineCommandMessage:
        raw = str(message or "")
        lines = raw.split("\r\n")
        first_line = lines[0].strip() if lines else ""
        if not first_line:
            return LineCommandMessage(raw=raw, method="", argument="", body="")
        method = message_method(first_line).strip()
        body_methods = {item.upper() for item in self.policy.line_body_methods}
        if method.upper() in body_methods:
            body = raw[len(first_line):]
            if body.startswith("\r\n"):
                body = body[2:]
            terminator = self.policy.line_body_terminator
            if terminator and body.endswith(terminator):
                body = body[: -len(terminator)]
            return LineCommandMessage(raw=raw, method=method, argument="", body=body)
        if " " in first_line:
            cmd, argument = first_line.split(" ", 1)
        else:
            cmd, argument = first_line, ""
        return LineCommandMessage(raw=raw, method=cmd.strip(), argument=argument, body="")

    def _render_line_command_messages(self, messages: list[LineCommandMessage]) -> str:
        chunks = []
        body_methods = {item.upper() for item in self.policy.line_body_methods}
        terminator = self.policy.line_body_terminator
        for message in messages:
            if message.method.upper() in body_methods:
                body = message.body or ""
                if terminator and not body.endswith(terminator):
                    body = body.rstrip("\r\n") + terminator
                chunks.append(f"{message.method}\r\n" + body)
                continue
            line = message.method
            if message.argument:
                line = f"{line} {message.argument}"
            chunks.append(line + "\r\n")
        return "".join(chunks)

    def _parse_smtp_message(self, message: str) -> SMTPMessage:
        return self._parse_line_command_message(message)

    def _render_smtp_messages(self, messages: list[SMTPMessage]) -> str:
        return self._render_line_command_messages(messages)

    def _parse_line_command_messages(self, raw_messages: list[str]) -> list[LineCommandMessage]:
        messages: list[LineCommandMessage] = []
        body_methods = {item.upper() for item in self.policy.line_body_methods}
        end_markers = {item.strip().upper() for item in self.policy.line_body_end_markers}
        index = 0
        while index < len(raw_messages):
            raw = str(raw_messages[index] or "")
            first_line = raw.splitlines()[0].strip() if raw.splitlines() else ""
            if not first_line:
                index += 1
                continue
            method = message_method(first_line).strip()
            if method.upper() in body_methods and end_markers:
                body_parts: list[str] = []
                end = index + 1
                while end < len(raw_messages):
                    region = str(raw_messages[end] or "")
                    region_lines = region.splitlines()
                    region_first = region_lines[0].strip() if region_lines else ""
                    if region_first.upper() in end_markers:
                        end += 1
                        break
                    body_parts.append(region)
                    end += 1
                messages.append(
                    LineCommandMessage(
                        raw="".join(raw_messages[index:end]),
                        method=method,
                        argument="",
                        body="".join(body_parts),
                        raw_start=index,
                        raw_end=end,
                    )
                )
                index = end
                continue
            parsed = self._parse_line_command_message(raw)
            if not parsed.method:
                index += 1
                continue
            parsed.raw_start = index
            parsed.raw_end = index + 1
            messages.append(parsed)
            index += 1
        return messages

    @staticmethod
    def _map_line_command_message_index(messages: list[LineCommandMessage], raw_index: int) -> int:
        if not messages:
            return 0
        bounded = max(0, raw_index)
        for idx, message in enumerate(messages):
            if message.raw_start <= bounded < message.raw_end:
                return idx
        for idx, message in enumerate(messages):
            if bounded < message.raw_start:
                return max(0, idx - 1)
        return len(messages) - 1

    @staticmethod
    def _parse_request_message(message: str) -> RequestMessage:
        raw = str(message or "")
        if "\r\n\r\n" in raw:
            header_blob, body = raw.split("\r\n\r\n", 1)
        else:
            header_blob, body = raw.rstrip("\r\n"), ""
        lines = header_blob.split("\r\n") if header_blob else []
        start_line = lines[0] if lines else ""
        headers: list[tuple[str, str]] = []
        for line in lines[1:]:
            if ":" not in line:
                continue
            name, value = line.split(":", 1)
            headers.append((name.strip(), value.lstrip()))
        return RequestMessage(raw=raw, start_line=start_line, headers=headers, body=body)

    @staticmethod
    def _request_method_from_start_line(start_line: str) -> str:
        parts = str(start_line or "").split()
        return parts[0] if parts else ""

    @classmethod
    def _render_request_messages(cls, messages: list[RequestMessage], fixups: list[str]) -> str:
        rendered: list[str] = []
        cseq_counter = None
        session_value = None
        for message in messages:
            start_line = message.start_line
            headers = list(message.headers)
            body = message.body
            current_method = cls._request_method_from_start_line(start_line)
            if "cseq" in fixups:
                for idx, (name, value) in enumerate(headers):
                    if name.lower() != "cseq":
                        continue
                    match = re.match(r"\s*(\d+)(.*)", value)
                    if match:
                        if cseq_counter is None:
                            cseq_counter = int(match.group(1))
                        else:
                            cseq_counter += 1
                        suffix = match.group(2)
                        if current_method:
                            method_match = re.match(r"(\s+)([A-Za-z]+)(.*)", suffix)
                            if method_match:
                                suffix = f"{method_match.group(1)}{current_method}{method_match.group(3)}"
                        headers[idx] = (name, f"{cseq_counter}{suffix}")
                    break
            if "session" in fixups:
                for name, value in headers:
                    if name.lower() == "session" and value.strip():
                        session_value = value
                if session_value:
                    headers = [
                        (name, session_value if name.lower() == "session" else value)
                        for name, value in headers
                    ]
            if "content_length" in fixups:
                body_len = len(body.encode("latin-1", errors="replace"))
                found = False
                new_headers: list[tuple[str, str]] = []
                for name, value in headers:
                    if name.lower() == "content-length":
                        new_headers.append((name, str(body_len)))
                        found = True
                    else:
                        new_headers.append((name, value))
                if body or found:
                    headers = new_headers
                    if not found:
                        headers.append(("Content-Length", str(body_len)))
            header_blob = "\r\n".join([start_line] + [f"{name}: {value}" for name, value in headers])
            rendered.append(header_blob + "\r\n\r\n")
            if body:
                rendered.append(body)
        return "".join(rendered)

    def _resolve_target_message_index(self, plan_payload: dict[str, Any], context: dict[str, Any], message_count: int) -> int:
        raw = plan_payload.get("target_message_index", context.get("step_index", 0))
        try:
            idx = int(raw)
        except (TypeError, ValueError):
            idx = int(context.get("step_index", 0) or 0)
        return max(0, min(message_count - 1, idx))

    def _resolve_preserve_prefix(
        self,
        plan_payload: dict[str, Any],
        context: dict[str, Any],
        method: str,
        message_count: int,
        target_index: int,
    ) -> int:
        raw = plan_payload.get("preserve_prefix_messages")
        try:
            idx = int(raw)
        except (TypeError, ValueError):
            idx = int(context.get("step_index", 0) or 0)
        if bool(plan_payload.get("allow_single_message")):
            return 0
        return max(0, min(message_count - 1, target_index, idx))

    def _explicit_line_command_selectors(
        self,
        messages: list[LineCommandMessage],
        target_index: int,
        preserve_prefix: int,
        plan_payload: dict[str, Any],
        context: dict[str, Any],
    ) -> list[dict[str, Any]]:
        selectors: list[dict[str, Any]] = []
        constraint_map = self._context_template_constraint_map(context)
        for item in plan_payload.get("operators", []):
            if not isinstance(item, dict):
                continue
            field = str(item.get("field") or "").strip()
            if not field:
                continue
            msg_index = item.get("msg_index")
            try:
                raw_index = target_index if msg_index is None else int(msg_index)
            except (TypeError, ValueError):
                continue
            index = self._map_line_command_message_index(messages, raw_index)
            if index < 0 or index >= len(messages) or index < preserve_prefix:
                continue
            constraint = constraint_map.get(messages[index].method.upper())
            selector = self._line_command_selector_from_field(messages, index, field, constraint=constraint)
            if selector:
                selectors.append(selector)
        return self._dedupe_selectors(selectors)

    def _build_line_argument_slot_selector(
        self,
        message: LineCommandMessage,
        index: int,
        binding: dict[str, Any],
    ) -> dict[str, Any] | None:
        template = binding.get("line_argument_template") if isinstance(binding, dict) else None
        if not isinstance(template, dict):
            return None
        slot_name = str(binding.get("slot_name") or "").strip()
        slot_canonical = str(binding.get("canonical_slot") or "").strip()
        field_suffix = slot_canonical or slot_name or "argument"
        slot_terms = [
            str(item).strip().lower()
            for item in list(binding.get("placeholder_names") or []) + list(binding.get("canonical_placeholders") or [])
            if str(item).strip()
        ]
        return {
            "kind": "line-arg-slot",
            "message_index": index,
            "field": f"{message.method}.argument:{field_suffix}",
            "base_field": f"{message.method}.argument",
            "slot_name": slot_name,
            "slot_canonical": slot_canonical,
            "slot_terms": slot_terms,
            "slot_count": len(template.get("placeholder_names") or []),
            "argument_template": template,
            "raw_start": message.raw_start,
            "raw_end": message.raw_end,
        }

    def _line_command_selector_from_field(
        self,
        messages: list[LineCommandMessage],
        index: int,
        field: str,
        *,
        constraint: dict[str, Any] | None = None,
    ) -> dict[str, Any] | None:
        message = messages[index]
        normalized = str(field or "").strip()
        lowered = normalized.lower()
        message_method_name = message.method.upper()
        argument_bindings = []
        if isinstance(constraint, dict):
            argument_bindings = [
                item
                for item in constraint.get("bindings", [])
                if isinstance(item, dict) and str(item.get("location") or "").strip().lower() == "argument"
            ]
            for binding in argument_bindings:
                slot_terms = {
                    str(item).strip().lower()
                    for item in list(binding.get("placeholder_names") or []) + list(binding.get("canonical_placeholders") or [])
                    if str(item).strip()
                }
                if lowered in slot_terms:
                    selector = self._build_line_argument_slot_selector(message, index, binding)
                    if selector is not None:
                        return selector
        if lowered in {"argument", f"{message_method_name.lower()}.argument"}:
            if len(argument_bindings) == 1:
                selector = self._build_line_argument_slot_selector(message, index, argument_bindings[0])
                if selector is not None:
                    return selector
            return {
                "kind": "line-arg",
                "message_index": index,
                "field": f"{message.method}.argument",
                "raw_start": message.raw_start,
                "raw_end": message.raw_end,
            }
        if lowered in {"body", f"{message_method_name.lower()}.body"}:
            return {
                "kind": "line-body",
                "message_index": index,
                "field": f"{message.method}.body",
                "raw_start": message.raw_start,
                "raw_end": message.raw_end,
            }
        return None

    def _select_line_command_fields(
        self,
        messages: list[LineCommandMessage],
        target_index: int,
        preserve_prefix: int,
        plan_payload: dict[str, Any],
        context: dict[str, Any],
    ) -> list[dict[str, Any]]:
        selectors: list[dict[str, Any]] = []
        constraint_map = self._context_template_constraint_map(context)
        target_fields = [str(item).strip() for item in plan_payload.get("target_fields", []) if str(item).strip()]
        for raw_field in target_fields:
            query_terms = self._match_terms(raw_field)
            best_score = 0
            best_selector: dict[str, Any] | None = None
            for idx in range(max(0, preserve_prefix), len(messages)):
                method = messages[idx].method.upper()
                constraint = constraint_map.get(method)
                if not constraint:
                    continue
                for binding in constraint.get("bindings", []):
                    if not isinstance(binding, dict):
                        continue
                    location = str(binding.get("location") or "").strip().lower()
                    if location not in {"argument", "body"}:
                        continue
                    score = self._term_overlap_score(query_terms, self._match_terms(*(binding.get("terms") or []), binding.get("mutation_field"), method))
                    if score <= best_score:
                        continue
                    selector = self._line_command_selector_from_field(
                        messages,
                        idx,
                        str(binding.get("canonical_slot") or binding.get("slot_name") or binding.get("mutation_field") or f"{method}.{location}"),
                        constraint=constraint,
                    )
                    if selector is None:
                        continue
                    best_score = score
                    best_selector = selector
            if best_selector is not None:
                selectors.append(best_selector)
        if not selectors:
            target_message = messages[target_index]
            default_field = f"{target_message.method}.body" if target_message.method.upper() in {item.upper() for item in self.policy.line_body_methods} else f"{target_message.method}.argument"
            default_selector = self._line_command_selector_from_field(messages, target_index, default_field, constraint=constraint_map.get(target_message.method.upper()))
            if default_selector is not None:
                selectors.append(default_selector)
        return self._dedupe_selectors(selectors)

    def _apply_line_command_sequence_operators(
        self,
        *,
        messages: list[LineCommandMessage],
        target_index: int,
        preserve_prefix: int,
        plan_payload: dict[str, Any],
    ) -> list[GeneratedSeedCandidate]:
        operators = plan_payload.get("operators") if isinstance(plan_payload.get("operators"), list) else []
        sequence_ops = [
            item
            for item in operators
            if isinstance(item, dict) and str(item.get("op") or "").strip().lower() == "repeat_messages"
        ]
        if not sequence_ops or not messages:
            return []
        max_seed_bytes = self._max_sequence_seed_bytes(plan_payload)
        candidates: list[GeneratedSeedCandidate] = []
        seen = set()
        bounded_target = max(preserve_prefix, min(target_index, len(messages) - 1))
        block = [copy.deepcopy(messages[bounded_target])]
        for item in sequence_ops:
            for count in self._sequence_repeat_counts(item.get("values")):
                mutated = [copy.deepcopy(message) for message in messages[:bounded_target]]
                for _ in range(count):
                    mutated.extend(copy.deepcopy(message) for message in block)
                mutated.extend(copy.deepcopy(message) for message in messages[bounded_target + 1:])
                seed_text = self._render_line_command_messages(mutated)
                if len(seed_text.encode("latin-1", errors="replace")) > max_seed_bytes:
                    continue
                if seed_text in seen:
                    continue
                seen.add(seed_text)
                candidates.append(
                    GeneratedSeedCandidate(
                        seed_text=seed_text,
                        summary=f"{messages[bounded_target].method} repeat_messages x{count}",
                        mutated_fields=["message_sequence"],
                    )
                )
        return candidates

    def _explicit_request_selectors(
        self,
        messages: list[RequestMessage],
        target_index: int,
        preserve_prefix: int,
        plan_payload: dict[str, Any],
    ) -> list[dict[str, Any]]:
        selectors: list[dict[str, Any]] = []
        selector_rejections: list[dict[str, Any]] = []
        for op_index, item in enumerate(plan_payload.get("operators", [])):
            if not isinstance(item, dict):
                continue
            field = str(item.get("field") or "").strip()
            if not field:
                selector_rejections.append({"index": op_index, "reason": "missing-field", "raw": item})
                continue
            msg_index = item.get("msg_index")
            try:
                index = target_index if msg_index is None else int(msg_index)
            except (TypeError, ValueError):
                selector_rejections.append({"index": op_index, "reason": "invalid-msg-index", "field": field, "msg_index": msg_index, "raw": item})
                continue
            if index < 0 or index >= len(messages):
                selector_rejections.append({"index": op_index, "reason": "msg-index-out-of-range", "field": field, "msg_index": index, "raw": item})
                continue
            if index < preserve_prefix:
                selector_rejections.append({"index": op_index, "reason": "msg-index-in-preserved-prefix", "field": field, "msg_index": index, "raw": item})
                continue
            selector = self._request_selector_from_field(index, field)
            if selector:
                selectors.append(selector)
            else:
                selector_rejections.append({"index": op_index, "reason": "selector-unresolved", "field": field, "msg_index": index, "raw": item})
        plan_payload["selector_rejections"] = selector_rejections
        return self._dedupe_selectors(selectors)

    @staticmethod
    def _request_selector_from_field(index: int, field: str) -> dict[str, Any] | None:
        normalized = str(field or "").strip()
        lowered = normalized.lower()
        if lowered in {"request_uri", "argument"}:
            return {"kind": "request-uri", "message_index": index, "field": "request_uri"}
        if lowered == "body":
            return {"kind": "body", "message_index": index, "field": "body"}
        if lowered == "start_line":
            return {"kind": "start-line", "message_index": index, "field": "start_line"}
        if lowered == "method":
            return {"kind": "method", "message_index": index, "field": "method"}
        if lowered in {"request_line", "request-line"}:
            return {"kind": "start-line", "message_index": index, "field": "start_line"}
        if lowered.startswith("header:"):
            header_name = normalized.split(":", 1)[1].strip()
            if header_name:
                return {"kind": "header", "message_index": index, "field": header_name}
        return None

    def _select_request_fields(
        self,
        messages: list[RequestMessage],
        target_index: int,
        preserve_prefix: int,
        plan_payload: dict[str, Any],
        context: dict[str, Any],
    ) -> list[dict[str, Any]]:
        selectors: list[dict[str, Any]] = []
        raw_fields = [str(item or "").strip() for item in plan_payload.get("target_fields", []) if str(item or "").strip()]
        wants_request_uri = False
        for raw_field in raw_fields:
            lowered = raw_field.lower()
            if any(token in lowered for token in ("uri", "url", "path", "target", "request")):
                wants_request_uri = True
            selector = self._resolve_request_selector(messages, target_index, preserve_prefix, raw_field, context)
            if selector:
                selectors.append(selector)
        if not selectors or wants_request_uri:
            selectors.append({"kind": "request-uri", "message_index": target_index, "field": "request_uri"})
        return self._dedupe_selectors(selectors)

    def _resolve_request_selector(
        self,
        messages: list[RequestMessage],
        target_index: int,
        preserve_prefix: int,
        raw_field: str,
        context: dict[str, Any],
    ) -> dict[str, Any] | None:
        field = str(raw_field or "").strip()
        lowered = field.lower()
        if any(token in lowered for token in ("uri", "url", "path", "target", "request")):
            return {"kind": "request-uri", "message_index": target_index, "field": "request_uri"}
        if any(token in lowered for token in ("body", "sdp", "payload")):
            return {"kind": "body", "message_index": target_index, "field": "body"}
        if any(token in lowered for token in ("method",)):
            return {"kind": "method", "message_index": target_index, "field": "method"}
        if any(token in lowered for token in ("request-line", "request_line", "start-line", "start_line")):
            return {"kind": "start-line", "message_index": target_index, "field": "start_line"}

        query_terms = self._match_terms(field)
        best_header: tuple[int, int, str] | None = None
        for idx in range(max(0, preserve_prefix), len(messages)):
            for header_name, _value in messages[idx].headers:
                score = self._term_overlap_score(query_terms, self._match_terms(header_name))
                if score <= 0:
                    continue
                if best_header is None or score > best_header[0]:
                    best_header = (score, idx, header_name)
        if best_header is not None:
            return {"kind": "header", "message_index": best_header[1], "field": best_header[2]}

        constraint_map = self._context_template_constraint_map(context)
        best_binding_score = 0
        best_selector: dict[str, Any] | None = None
        for idx in range(max(0, preserve_prefix), len(messages)):
            method = messages[idx].method.upper()
            constraint = constraint_map.get(method)
            if not constraint:
                continue
            for binding in constraint.get("bindings", []):
                if not isinstance(binding, dict):
                    continue
                score = self._term_overlap_score(query_terms, self._match_terms(*(binding.get("terms") or []), binding.get("mutation_field"), binding.get("header_name")))
                if score <= best_binding_score:
                    continue
                mutation_field = str(binding.get("mutation_field") or "").strip()
                selector = self._request_selector_from_field(idx, mutation_field)
                if selector is None and mutation_field.startswith("header:"):
                    header_name = mutation_field.split(":", 1)[1].strip()
                    selector = {"kind": "header", "message_index": idx, "field": header_name} if header_name else None
                if selector is None:
                    continue
                best_binding_score = score
                best_selector = selector
        return best_selector

    def _apply_line_command_selector(
        self,
        *,
        raw_messages: list[str],
        messages: list[LineCommandMessage],
        selector: dict[str, Any],
        target_index: int,
        preserve_prefix: int,
        plan_payload: dict[str, Any],
        task_kind: str,
    ) -> list[GeneratedSeedCandidate]:
        index = int(selector["message_index"])
        if index < preserve_prefix:
            return []
        message = messages[index]
        selector_kind = str(selector.get("kind") or "")
        is_body = selector_kind.endswith("body")
        fallback_to_argument = False
        if selector_kind == "line-arg-slot":
            original = self._extract_line_argument_slot_value(message.argument, selector)
            if original is None:
                if int(selector.get("slot_count") or 0) == 1:
                    fallback_to_argument = True
                    original = message.argument
                else:
                    return []
        else:
            original = message.body if is_body else message.argument
        values = self._operator_values(original, plan_payload, task_kind, selector=selector)
        candidates: list[GeneratedSeedCandidate] = []
        for op_name, value in values:
            if value == original:
                continue
            mutated = copy.deepcopy(messages)
            if is_body:
                mutated[index].body = value
            elif selector_kind == "line-arg-slot" and not fallback_to_argument:
                updated_argument = self._replace_line_argument_slot_value(mutated[index].argument, selector, value)
                if updated_argument is None:
                    continue
                mutated[index].argument = updated_argument
            else:
                mutated[index].argument = value
            candidates.append(
                GeneratedSeedCandidate(
                    seed_text=self._compose_line_command_seed(raw_messages, mutated, preserve_prefix),
                    summary=f"{selector['field']} {op_name}",
                    mutated_fields=[selector["field"]],
                )
            )
        return candidates

    def _apply_request_selector(
        self,
        *,
        raw_messages: list[str],
        messages: list[RequestMessage],
        selector: dict[str, Any],
        target_index: int,
        preserve_prefix: int,
        plan_payload: dict[str, Any],
        task_kind: str,
        allow_single: bool,
    ) -> list[GeneratedSeedCandidate]:
        index = int(selector["message_index"])
        if index < preserve_prefix:
            return []
        message = messages[index]
        values = self._operator_values(self._current_request_value(message, selector), plan_payload, task_kind, selector=selector)
        candidates: list[GeneratedSeedCandidate] = []
        fixups = [str(item).strip().lower() for item in plan_payload.get("fixups", []) if str(item).strip()]
        for op_name, value in values:
            if value == self._current_request_value(message, selector):
                continue
            mutated = copy.deepcopy(messages)
            self._set_request_value(mutated[index], selector, value)
            if allow_single and preserve_prefix == 0:
                seed_text = self._render_request_messages([mutated[index]], fixups=fixups)
            else:
                seed_text = self._compose_request_seed(raw_messages, mutated, preserve_prefix, fixups)
            candidates.append(
                GeneratedSeedCandidate(
                    seed_text=seed_text,
                    summary=f"{selector['field']} {op_name}",
                    mutated_fields=[selector["field"]],
                )
            )
        return candidates

    def _apply_request_sequence_operators(
        self,
        *,
        raw_messages: list[str],
        messages: list[RequestMessage],
        target_index: int,
        preserve_prefix: int,
        plan_payload: dict[str, Any],
    ) -> list[GeneratedSeedCandidate]:
        operators = plan_payload.get("operators") if isinstance(plan_payload.get("operators"), list) else []
        sequence_ops = [
            item
            for item in operators
            if isinstance(item, dict) and str(item.get("op") or "").strip().lower() == "repeat_messages"
        ]
        if not sequence_ops or not messages:
            return []
        fixups = [str(item).strip().lower() for item in plan_payload.get("fixups", []) if str(item).strip()]
        max_seed_bytes = self._max_sequence_seed_bytes(plan_payload)
        candidates: list[GeneratedSeedCandidate] = []
        seen = set()
        for item in sequence_ops:
            field = str(item.get("field") or "message_sequence").strip().lower()
            block_start, block_end = self._request_sequence_block(messages, target_index, preserve_prefix, field)
            if block_end <= block_start:
                continue
            block = [copy.deepcopy(message) for message in messages[block_start:block_end]]
            for count in self._sequence_repeat_counts(item.get("values")):
                mutated = [copy.deepcopy(message) for message in messages[:block_start]]
                for _ in range(count):
                    mutated.extend(copy.deepcopy(block))
                mutated.extend(copy.deepcopy(message) for message in messages[block_end:])
                seed_text = self._compose_request_seed(raw_messages, mutated, preserve_prefix=0, fixups=fixups)
                if len(seed_text.encode("latin-1", errors="replace")) > max_seed_bytes:
                    continue
                if seed_text in seen:
                    continue
                seen.add(seed_text)
                candidates.append(
                    GeneratedSeedCandidate(
                        seed_text=seed_text,
                        summary=f"message_sequence repeat_messages x{count}",
                        mutated_fields=["message_sequence"],
                    )
                )
        return candidates

    def _request_sequence_block(
        self,
        messages: list[RequestMessage],
        target_index: int,
        preserve_prefix: int,
        field: str,
    ) -> tuple[int, int]:
        start_floor = max(0, min(preserve_prefix, len(messages) - 1))
        target_index = max(start_floor, min(target_index, len(messages) - 1))
        if field in {"target_message", "message"}:
            return target_index, min(len(messages), target_index + 1)
        anchor_methods = {item.upper() for item in self.policy.sequence_anchor_methods}
        terminal_methods = {item.upper() for item in self.policy.sequence_terminal_methods}
        completion_methods = {item.upper() for item in self.policy.sequence_completion_methods}
        if not anchor_methods and not terminal_methods and not completion_methods:
            return target_index, min(len(messages), target_index + 1)
        start = target_index
        for idx in range(target_index, start_floor - 1, -1):
            method = messages[idx].method.upper()
            if method in anchor_methods:
                start = idx
                break
        window_end = min(len(messages), max(target_index + 1, start + 6))
        end = window_end
        for idx in range(target_index, window_end):
            if messages[idx].method.upper() in terminal_methods:
                return start, idx + 1
        for idx in range(target_index, window_end):
            method = messages[idx].method.upper()
            if method in completion_methods:
                end = idx + 1
                break
        return start, end

    @staticmethod
    def _sequence_repeat_counts(raw_values: Any) -> list[int]:
        values = raw_values if isinstance(raw_values, list) else []
        counts: list[int] = []
        for raw in values[:4]:
            try:
                count = int(raw)
            except (TypeError, ValueError):
                continue
            count = max(2, min(32, count))
            if count not in counts:
                counts.append(count)
        return counts or [2, 4, 8]

    @staticmethod
    def _max_sequence_seed_bytes(plan_payload: dict[str, Any]) -> int:
        try:
            configured = int(plan_payload.get("max_seed_bytes") or 32768)
        except (TypeError, ValueError):
            configured = 32768
        return max(2048, min(65536, configured))

    @classmethod
    def _match_line_argument_tokens(
        cls,
        argument: str,
        tokens: list[dict[str, Any]],
        token_index: int,
        position: int,
    ) -> dict[str, str] | None:
        if token_index >= len(tokens):
            return {} if position == len(argument) else None
        token = tokens[token_index]
        if not isinstance(token, dict):
            return None
        if token.get("kind") == "literal":
            literal = str(token.get("text") or "")
            if not argument.startswith(literal, position):
                return None
            return cls._match_line_argument_tokens(argument, tokens, token_index + 1, position + len(literal))
        if token.get("kind") != "placeholder":
            return None
        name = str(token.get("canonical") or token.get("name") or f"slot-{token_index}").strip()
        next_literal = None
        for next_token in tokens[token_index + 1 :]:
            if isinstance(next_token, dict) and next_token.get("kind") == "literal":
                next_literal = str(next_token.get("text") or "")
                break
        if next_literal is None:
            remainder = cls._match_line_argument_tokens(argument, tokens, token_index + 1, len(argument))
            if remainder is None:
                return None
            remainder[name] = argument[position:]
            return remainder
        matches: list[int] = []
        search_pos = position
        while True:
            found = argument.find(next_literal, search_pos)
            if found < 0:
                break
            matches.append(found)
            search_pos = found + 1
        for found in reversed(matches):
            remainder = cls._match_line_argument_tokens(argument, tokens, token_index + 1, found)
            if remainder is None:
                continue
            remainder[name] = argument[position:found]
            return remainder
        return None

    @classmethod
    def _match_line_argument_template(cls, argument: str, selector: dict[str, Any]) -> dict[str, str] | None:
        template = selector.get("argument_template") if isinstance(selector, dict) else None
        if not isinstance(template, dict):
            return None
        tokens = template.get("tokens") if isinstance(template.get("tokens"), list) else []
        if not tokens:
            return None
        return cls._match_line_argument_tokens(str(argument or ""), tokens, 0, 0)

    @classmethod
    def _extract_line_argument_slot_value(cls, argument: str, selector: dict[str, Any]) -> str | None:
        values = cls._match_line_argument_template(argument, selector)
        if values is None:
            return None
        slot_keys = [
            str(selector.get("slot_canonical") or "").strip(),
            str(selector.get("slot_name") or "").strip(),
        ]
        slot_keys.extend(str(item).strip() for item in selector.get("slot_terms", []) if str(item).strip())
        for key in slot_keys:
            if key and key in values:
                return values[key]
        return next(iter(values.values()), None)

    @classmethod
    def _replace_line_argument_slot_value(cls, argument: str, selector: dict[str, Any], replacement: str) -> str | None:
        values = cls._match_line_argument_template(argument, selector)
        template = selector.get("argument_template") if isinstance(selector, dict) else None
        if values is None or not isinstance(template, dict):
            return None
        slot_keys = {
            str(selector.get("slot_canonical") or "").strip(),
            str(selector.get("slot_name") or "").strip(),
        }
        slot_keys.update(str(item).strip() for item in selector.get("slot_terms", []) if str(item).strip())
        rendered: list[str] = []
        for token in template.get("tokens", []):
            if not isinstance(token, dict):
                continue
            if token.get("kind") == "literal":
                rendered.append(str(token.get("text") or ""))
                continue
            name = str(token.get("canonical") or token.get("name") or "").strip()
            if name in slot_keys:
                rendered.append(replacement)
            else:
                rendered.append(values.get(name, ""))
        return "".join(rendered)

    @staticmethod
    def _dedupe_selectors(selectors: list[dict[str, Any]]) -> list[dict[str, Any]]:
        deduped: list[dict[str, Any]] = []
        seen = set()
        for selector in selectors:
            key = (
                selector.get("kind"),
                selector.get("message_index"),
                selector.get("field"),
                selector.get("slot_canonical"),
                selector.get("slot_name"),
            )
            if key in seen:
                continue
            seen.add(key)
            deduped.append(selector)
        return deduped

    @staticmethod
    def _preview_text(value: str, limit: int = 80) -> str:
        text = str(value or "").replace("\r", "\\r").replace("\n", "\\n")
        return text if len(text) <= limit else text[: limit - 3] + "..."

    def _explain_empty_line_command_generation(
        self,
        *,
        seed_text: str,
        context: dict[str, Any],
        plan_payload: dict[str, Any],
        task_kind: str,
    ) -> dict[str, Any] | None:
        raw_messages = split_seed_messages(self.protocol, seed_text)
        messages = self._parse_line_command_messages(raw_messages)
        if not messages:
            return None
        raw_target_index = self._resolve_target_message_index(plan_payload, context, len(raw_messages))
        target_index = self._map_line_command_message_index(messages, raw_target_index)
        raw_preserve_prefix = self._resolve_preserve_prefix(
            plan_payload,
            context,
            messages[target_index].method,
            len(raw_messages),
            raw_target_index,
        )
        preserve_prefix = min(target_index, self._map_line_command_message_index(messages, raw_preserve_prefix))
        selectors = self._explicit_line_command_selectors(
            messages,
            target_index,
            preserve_prefix,
            plan_payload,
            context,
        )
        if not selectors:
            selectors = self._select_line_command_fields(messages, target_index, preserve_prefix, plan_payload, context)
        diagnostics: list[dict[str, Any]] = []
        for selector in selectors:
            index = int(selector.get("message_index", 0) or 0)
            if index < preserve_prefix or index >= len(messages):
                continue
            message = messages[index]
            is_body = str(selector.get("kind") or "").endswith("body")
            original = message.body if is_body else message.argument
            analysis = self._operator_value_analysis(original, plan_payload, task_kind, selector=selector)
            candidate_values = [value for _label, value in analysis.get("values") or []]
            if any(value != original for value in candidate_values):
                return None
            if analysis.get("matched_operator") or candidate_values:
                diagnostics.append(
                    {
                        "field": selector.get("field", ""),
                        "message_index": index,
                        "current_value": self._preview_text(original),
                    }
                )
        if diagnostics:
            return {"reason": "plan-noop-against-current-seed", "details": diagnostics[:4]}
        return None

    def _explain_empty_request_generation(
        self,
        *,
        seed_text: str,
        context: dict[str, Any],
        plan_payload: dict[str, Any],
        task_kind: str,
    ) -> dict[str, Any] | None:
        raw_messages = split_seed_messages(self.protocol, seed_text)
        messages = [self._parse_request_message(msg) for msg in raw_messages]
        if not messages:
            return None
        target_index = self._resolve_target_message_index(plan_payload, context, len(messages))
        preserve_prefix = self._resolve_preserve_prefix(plan_payload, context, messages[target_index].method, len(messages), target_index)
        selectors = self._explicit_request_selectors(messages, target_index, preserve_prefix, plan_payload)
        if not selectors:
            selectors = self._select_request_fields(messages, target_index, preserve_prefix, plan_payload, context)
        diagnostics: list[dict[str, Any]] = []
        for selector in selectors:
            index = int(selector.get("message_index", 0) or 0)
            if index < preserve_prefix or index >= len(messages):
                continue
            original = self._current_request_value(messages[index], selector)
            analysis = self._operator_value_analysis(original, plan_payload, task_kind, selector=selector)
            candidate_values = [value for _label, value in analysis.get("values") or []]
            if any(value != original for value in candidate_values):
                return None
            if analysis.get("matched_operator") or candidate_values:
                diagnostics.append(
                    {
                        "field": selector.get("field", ""),
                        "message_index": index,
                        "current_value": self._preview_text(original),
                    }
                )
        if diagnostics:
            return {"reason": "plan-noop-against-current-seed", "details": diagnostics[:4]}
        return None

    @staticmethod
    def _find_message_with_header(
        messages: list[RequestMessage],
        header_name: str,
        *,
        preferred_index: int | None = None,
        start_index: int = 0,
    ) -> int | None:
        target = header_name.lower()
        if preferred_index is not None and 0 <= preferred_index < len(messages) and preferred_index >= start_index:
            for name, _value in messages[preferred_index].headers:
                if name.lower() == target:
                    return preferred_index
        for idx in range(max(0, start_index), len(messages)):
            message = messages[idx]
            for name, _value in message.headers:
                if name.lower() == target:
                    return idx
        return None

    def _compose_line_command_seed(
        self,
        raw_messages: list[str],
        mutated_messages: list[LineCommandMessage],
        preserve_prefix: int,
    ) -> str:
        prefix_count = max(0, min(preserve_prefix, len(raw_messages), len(mutated_messages)))
        prefix = "".join(raw_messages[:prefix_count])
        suffix = self._render_line_command_messages(mutated_messages[prefix_count:])
        return prefix + suffix

    def _compose_request_seed(
        self,
        raw_messages: list[str],
        mutated_messages: list[RequestMessage],
        preserve_prefix: int,
        fixups: list[str],
    ) -> str:
        prefix_count = max(0, min(preserve_prefix, len(raw_messages), len(mutated_messages)))
        prefix = "".join(raw_messages[:prefix_count])
        suffix = self._render_request_messages(mutated_messages[prefix_count:], fixups=fixups)
        return prefix + suffix

    def _operator_value_analysis(
        self,
        original: str,
        plan_payload: dict[str, Any],
        task_kind: str,
        *,
        selector: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        operators = plan_payload.get("operators") if isinstance(plan_payload.get("operators"), list) else []
        max_length = self._max_mutated_value_length(plan_payload)
        values: list[tuple[str, str]] = []
        matched_operator = False
        hypothesis = plan_payload.get("target_hypothesis") if isinstance(plan_payload.get("target_hypothesis"), dict) else {}
        hypothesis_values = hypothesis.get("target_values") if isinstance(hypothesis.get("target_values"), list) else []
        for item in operators:
            if not isinstance(item, dict):
                continue
            if selector is not None and not self._operator_matches_selector(item, selector, plan_payload):
                continue
            matched_operator = True
            op_name = str(item.get("op") or "").strip().lower()
            raw_values = list(item.get("values") if isinstance(item.get("values"), list) else [])
            trigger_class = str(plan_payload.get("trigger_class") or hypothesis.get("trigger_class") or "").strip().lower()
            if op_name in {"set_literal", "inject", "append", "prepend"} and trigger_class == "format_string" and hypothesis_values:
                seen_hypothesis = {str(v) for v in raw_values}
                for raw in hypothesis_values[:8]:
                    text_value = str(raw or "")
                    if text_value and text_value not in seen_hypothesis:
                        raw_values.append(text_value)
                        seen_hypothesis.add(text_value)
            if op_name == "set_length":
                for raw in raw_values:
                    try:
                        length = int(raw)
                    except (TypeError, ValueError):
                        continue
                    bounded = self._bounded_length(length, max_length)
                    values.append((f"len={bounded}", self._stretch_value(original, bounded, max_length=max_length)))
            elif op_name in {"inject", "append", "prepend"}:
                for raw in raw_values:
                    payload = self._decode_escaped_text(str(raw or ""))
                    if not payload:
                        continue
                    if op_name == "prepend":
                        candidate = payload + original
                        values.append((f"prepend:{payload[:12]}", self._clip_mutated_value(candidate, max_length)))
                    elif op_name == "append":
                        candidate = original + payload
                        values.append((f"append:{payload[:12]}", self._clip_mutated_value(candidate, max_length)))
                    else:
                        candidate = self._inject_value(original, payload)
                        values.append((f"inject:{payload[:12]}", self._clip_mutated_value(candidate, max_length)))
            elif op_name == "set_literal":
                for raw in raw_values:
                    payload = self._decode_escaped_text(str(raw or ""))
                    values.append((f"literal:{str(raw)[:12]}", self._clip_mutated_value(payload, max_length)))
            elif op_name == "delete":
                values.append(("delete", "__DELETE_FIELD__"))
            elif op_name == "set_numeric":
                for raw in raw_values:
                    try:
                        number = int(raw)
                    except (TypeError, ValueError):
                        continue
                    candidate = self._replace_first_integer(original, str(number))
                    values.append((f"num={number}", self._clip_mutated_value(candidate, max_length)))
        if values:
            return {"values": values, "matched_operator": matched_operator}
        if selector is not None and operators:
            return {"values": [], "matched_operator": matched_operator}
        lengths = self.policy.default_boundary_lengths if task_kind == "boundary-generate" else self.policy.default_vuln_lengths
        default_values = []
        seen_lengths = set()
        if task_kind == "boundary-generate":
            selected_lengths = list(lengths[:4])
        else:
            uniq_lengths = list(dict.fromkeys(int(v) for v in lengths))
            selected_lengths = (uniq_lengths[:3] + uniq_lengths[-3:]) if len(uniq_lengths) > 6 else uniq_lengths
        for length in selected_lengths:
            bounded = self._bounded_length(length, max_length)
            if bounded in seen_lengths:
                continue
            seen_lengths.add(bounded)
            default_values.append((f"len={bounded}", self._stretch_value(original, bounded, max_length=max_length)))
        for payload in self.policy.default_injections[:2]:
            candidate = self._inject_value(original, payload)
            default_values.append((f"inject:{payload[:12]}", self._clip_mutated_value(candidate, max_length)))
        return {"values": default_values, "matched_operator": matched_operator}

    def _operator_values(
        self,
        original: str,
        plan_payload: dict[str, Any],
        task_kind: str,
        *,
        selector: dict[str, Any] | None = None,
    ) -> list[tuple[str, str]]:
        return list(self._operator_value_analysis(original, plan_payload, task_kind, selector=selector).get("values") or [])

    @staticmethod
    def _operator_matches_selector(operator: dict[str, Any], selector: dict[str, Any], plan_payload: dict[str, Any]) -> bool:
        op_msg_index = operator.get("msg_index")
        selector_index = int(selector.get("message_index", 0) or 0)
        if op_msg_index is not None and str(op_msg_index).strip() != "":
            try:
                op_index = int(op_msg_index)
                raw_start = selector.get("raw_start")
                raw_end = selector.get("raw_end")
                if raw_start is not None and raw_end is not None:
                    if not (int(raw_start) <= op_index < int(raw_end)):
                        return False
                elif op_index != selector_index:
                    return False
            except (TypeError, ValueError):
                return False

        op_field = str(operator.get("field") or "").strip().lower()
        selector_field = str(selector.get("field") or "").strip().lower()
        selector_kind = str(selector.get("kind") or "").strip().lower()
        if not op_field:
            return False
        if op_field == selector_field:
            return True
        if op_field.startswith("header:"):
            return selector_kind == "header" and op_field.split(":", 1)[1].strip() == selector_field

        alias_map = {
            "username": {"user.argument", "username", "user"},
            "user": {"user.argument", "username", "user"},
            "password": {"pass.argument", "password", "pass"},
            "pass": {"pass.argument", "password", "pass"},
            "range": {"range", "header:range"},
            "session": {"session", "header:session"},
            "transport": {"transport", "header:transport"},
            "cseq": {"cseq", "header:cseq"},
            "branch": {"via", "header:via"},
            "via": {"via", "header:via"},
            "body": {"body"},
            "request_uri": {"request_uri"},
            "request-line": {"start_line"},
            "request_line": {"start_line"},
            "start_line": {"start_line"},
            "method": {"method"},
        }
        if selector_field in alias_map.get(op_field, set()):
            return True

        if op_field in {"argument", "body"}:
            try:
                target_index = int(plan_payload.get("target_message_index", selector_index) or 0)
            except (TypeError, ValueError):
                target_index = selector_index
            raw_start = selector.get("raw_start")
            raw_end = selector.get("raw_end")
            targets_selector = selector_index == target_index
            if raw_start is not None and raw_end is not None:
                try:
                    targets_selector = int(raw_start) <= target_index < int(raw_end)
                except (TypeError, ValueError):
                    targets_selector = selector_index == target_index
            if op_field == "argument" and selector_kind == "request-uri":
                return targets_selector
            if selector_kind in {"line-arg", "line-arg-slot"} and op_field == "argument":
                return targets_selector
            if selector_kind.endswith(op_field) or selector_field.endswith(f".{op_field}"):
                return targets_selector
            return False
        if selector_kind == "line-arg-slot":
            base_field = str(selector.get("base_field") or "").strip().lower()
            slot_terms = {str(item).strip().lower() for item in selector.get("slot_terms", []) if str(item).strip()}
            slot_terms.update(
                {
                    str(selector.get("slot_name") or "").strip().lower(),
                    str(selector.get("slot_canonical") or "").strip().lower(),
                }
            )
            slot_terms.discard("")
            if op_field in slot_terms:
                return True
            if "." in op_field and base_field and op_field == base_field:
                return True
        if "." in op_field:
            return op_field == selector_field or selector_field.endswith(op_field)
        return False

    @staticmethod
    def _stretch_value(original: str, length: int, *, max_length: int | None = None) -> str:
        if max_length is not None:
            length = max(0, min(length, max_length))
        base = original or "A"
        if length <= 0:
            return ""
        if any(token in base for token in ("\r", "\n", "\x00")):
            return "A" * length
        pattern = base if base.strip() else "A"
        repeated = (pattern * ((length // len(pattern)) + 2))[:length]
        return repeated

    @staticmethod
    def _bounded_length(length: int, max_length: int) -> int:
        return max(0, min(int(length), max_length))

    @staticmethod
    def _max_mutated_value_length(plan_payload: dict[str, Any]) -> int:
        try:
            configured = int(plan_payload.get("max_line_length") or 2048)
        except (TypeError, ValueError):
            configured = 2048
        return max(64, configured)

    @staticmethod
    def _clip_mutated_value(value: str, max_length: int) -> str:
        if len(value) <= max_length:
            return value
        return value[:max_length]

    @staticmethod
    def _inject_value(original: str, payload: str) -> str:
        if not original:
            return payload
        mid = len(original) // 2
        return original[:mid] + payload + original[mid:]

    @staticmethod
    def _replace_first_integer(original: str, replacement: str) -> str:
        if not original:
            return replacement
        return re.sub(r"\d+", replacement, original, count=1)

    @staticmethod
    def _decode_escaped_text(value: str) -> str:
        text = str(value or "")
        if not any(token in text for token in ("\\r", "\\n", "\\t", "\\u", "\\x")):
            return text
        text = text.replace("\\r\\n", "\n")
        text = text.replace("\\n", "\n").replace("\\r", "\r").replace("\\t", "\t")
        text = re.sub(r"\\x([0-9A-Fa-f]{2})", lambda m: chr(int(m.group(1), 16)), text)
        text = re.sub(r"\\u([0-9A-Fa-f]{4})", lambda m: chr(int(m.group(1), 16)), text)
        return text

    @staticmethod
    def _current_request_value(message: RequestMessage, selector: dict[str, Any]) -> str:
        kind = selector["kind"]
        if kind == "request-uri":
            parts = message.start_line.split()
            return parts[1] if len(parts) >= 2 else ""
        if kind == "start-line":
            return message.start_line
        if kind == "method":
            parts = message.start_line.split()
            return parts[0] if parts else ""
        if kind == "body":
            return message.body
        field_name = str(selector["field"])
        for name, value in message.headers:
            if name.lower() == field_name.lower():
                return value
        return ""

    @staticmethod
    def _set_request_value(message: RequestMessage, selector: dict[str, Any], value: str) -> None:
        kind = selector["kind"]
        if kind == "request-uri":
            parts = message.start_line.split()
            if len(parts) >= 3:
                parts[1] = value or parts[1]
                message.start_line = " ".join(parts)
            return
        if kind == "start-line":
            message.start_line = value
            return
        if kind == "method":
            parts = message.start_line.split(" ", 1)
            method_value = str(value or "").strip()
            if not method_value:
                return
            if len(parts) == 2:
                message.start_line = method_value + " " + parts[1]
            else:
                message.start_line = method_value
            return
        if kind == "body":
            message.body = value
            return
        field_name = str(selector["field"])
        delete_field = value == "__DELETE_FIELD__"
        updated = False
        new_headers: list[tuple[str, str]] = []
        for name, current in message.headers:
            if name.lower() == field_name.lower():
                updated = True
                if delete_field:
                    continue
                new_headers.append((name, value))
            else:
                new_headers.append((name, current))
        if not updated and not delete_field:
            new_headers.append((field_name, value))
        message.headers = new_headers
