#!/usr/bin/env python3
"""
PSEI seed generation for S2AFL.

This module implements an offline PRMGT-style seed enricher:
  1. Build a request-method graph from an initial sequence corpus.
  2. Complete missing request methods using protocol-aware insertion.
  3. Complete missing edges with bounded graph traversal expansion.

The implementation is deterministic by default, but can switch to an
LLM-guided mode for both sequence insertion and message rendering while
preserving deterministic fallbacks.
"""

from __future__ import annotations

import argparse
import json
from json import JSONDecoder, JSONDecodeError
import os
import random
import re
from copy import deepcopy

from S2AFL.knowledge.field_offset_mapper import build_message_deterministic, call_llm, extract_fields, parse_template
from S2AFL.runtime.seed_utils import split_seed_messages


DEFAULT_MAX_SEQS = 64
DEFAULT_EDGE_INSERTIONS = 2
DEFAULT_LLM_MAX_EXPANSION = 2


def _empty_llm_usage() -> dict[str, int]:
    return {
        "calls": 0,
        "input_tokens": 0,
        "output_tokens": 0,
        "reasoning_tokens": 0,
        "total_tokens": 0,
    }


def _merge_llm_usage(acc: dict[str, int], delta: dict[str, int] | None) -> dict[str, int]:
    if not delta:
        return acc
    for key in ("calls", "input_tokens", "output_tokens", "reasoning_tokens", "total_tokens"):
        acc[key] = int(acc.get(key, 0) or 0) + int(delta.get(key, 0) or 0)
    return acc


def _usage_from_response(response: str | None) -> dict[str, int]:
    parsed = _parse_json_fragment(response or "")
    usage = parsed.get("usage") if isinstance(parsed, dict) else None
    if not isinstance(usage, dict):
        return _empty_llm_usage()
    input_tokens = int(usage.get("prompt_tokens", 0) or 0)
    output_tokens = int(usage.get("completion_tokens", 0) or 0)
    reasoning_tokens = int((usage.get("completion_tokens_details", {}) or {}).get("reasoning_tokens", 0) or 0)
    return {
        "calls": 1,
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "reasoning_tokens": reasoning_tokens,
        "total_tokens": input_tokens + output_tokens,
    }


def _wire_method_allowed(protocol: str, method: str) -> bool:
    proto = protocol.upper()
    normalized = str(method or "").strip()
    if not normalized:
        return False
    if proto == "FTP" and normalized == "OPEN":
        return False
    if proto == "HTTP" and normalized in {"Response", "200 OK", "404 Not Found"}:
        return False
    if proto == "SMTP":
        if normalized.endswith(":"):
            return False
        if normalized in {"Message-Body:", "End-Of-Data", "."}:
            return False
    return True


def _render_template(template_str: str, fill_values: dict[str, str]) -> str:
    parts = parse_template(template_str)
    method = str(parts[0]).strip() if parts else ""
    if len(parts) > 1:
        second = str(parts[1])
        if method and re.match(rf"^\s*{re.escape(method)}\b", second):
            parts = [second.lstrip()] + parts[2:]
    patched = []
    for part in parts:
        text = part
        while "<<" in text and ">>" in text:
            start = text.find("<<")
            end = text.find(">>", start)
            if start < 0 or end < 0:
                break
            field_name = text[start + 2:end]
            text = text[:start] + fill_values.get(field_name, "") + text[end + 2:]
        patched.append(text)
    message, _ = build_message_deterministic(patched)
    message = re.sub(r"[ 	]+\r\n", "\r\n", message)
    if method == "DATA":
        body = str(fill_values.get("message-body") or "test")
        body = body.replace("\r", " ").replace("\n", " ").strip() or "test"
        if not message.endswith("\r\n"):
            message = message.rstrip("\n") + "\r\n"
        message += body + "\r\n.\r\n"
    return message


def _template_visible(template_str: str) -> str:
    return "".join(parse_template(template_str))


def _method_from_message(message: str) -> str:
    first = (message or "").splitlines()[0].strip()
    return first.split()[0] if first else ""


def _sanitize_field_value(value: str) -> str:
    cleaned = str(value or "")
    cleaned = cleaned.replace("\\r", "").replace("\\n", "")
    cleaned = cleaned.replace("\r", "").replace("\n", "")
    return cleaned.strip()


def _load_templates(path: str, protocol: str) -> tuple[dict[str, str], list[str]]:
    try:
        with open(path) as f:
            data = json.load(f)
    except Exception:
        return {}, []
    templates = data.get(protocol, [])
    method_to_template = {}
    ordered_methods = []
    for template_str in templates:
        parts = parse_template(template_str)
        if not parts:
            continue
        method = str(parts[0]).strip()
        if not _wire_method_allowed(protocol, method):
            continue
        method_to_template[method] = template_str
        ordered_methods.append(method)
    return method_to_template, ordered_methods



def _extract_corpus_context(protocol: str, seed_corpus_dir: str | None) -> dict:
    context = {
        "raw_sequences": [],
        "messages_by_method": {},
        "global_values": {
            "paths": [],
            "words": [],
            "numbers": [],
            "ips": [],
            "domains": [],
            "uris": [],
            "emails": [],
            "hosts": [],
            "user_agents": [],
            "accepts": [],
            "connections": [],
            "content_types": [],
            "content_lengths": [],
            "call_ids": [],
            "cseq_numbers": [],
            "tags": [],
            "contact_uris": [],
            "from_uris": [],
            "to_uris": [],
            "sip_uris": [],
            "ports": [],
            "media_ports": [],
            "rtsp_client_ports_start": [],
            "rtsp_client_ports_end": [],
            "session_ids": [],
            "rtsp_urls": [],
            "rtsp_start_times": [],
            "sdp_sess_ids": [],
            "sdp_sess_versions": [],
        },
        "method_args": {},
    }
    if not seed_corpus_dir or not os.path.isdir(seed_corpus_dir):
        return context

    for name in sorted(os.listdir(seed_corpus_dir)):
        path = os.path.join(seed_corpus_dir, name)
        if not os.path.isfile(path):
            continue
        try:
            raw = open(path, "rb").read().decode("latin-1", errors="replace")
        except Exception:
            continue
        context["raw_sequences"].append(raw)
        for msg in split_seed_messages(protocol, raw):
            method = _method_from_message(msg)
            if not method:
                continue
            context["messages_by_method"].setdefault(method, []).append(msg)
            first_line = msg.splitlines()[0] if msg.splitlines() else ""
            parts = first_line.split(maxsplit=1)
            if len(parts) > 1:
                context["method_args"].setdefault(method, []).append(parts[1])
            _update_value_bank(context["global_values"], msg)

    for key in ("messages_by_method", "method_args"):
        for item, values in list(context[key].items()):
            deduped = []
            seen = set()
            for value in values:
                if value in seen:
                    continue
                seen.add(value)
                deduped.append(value)
            context[key][item] = deduped

    for key, values in context["global_values"].items():
        deduped = []
        seen = set()
        for value in values:
            if value in seen:
                continue
            seen.add(value)
            deduped.append(value)
        context["global_values"][key] = deduped

    return context


def _update_value_bank(bank: dict, text: str):
    bank["ips"].extend(re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", text))
    bank["domains"].extend(re.findall(r"\b(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}\b", text))
    bank["emails"].extend(re.findall(r"\b[\w.+-]+@[\w.-]+\b", text))
    bank["uris"].extend(re.findall(r"\b[a-zA-Z]+://[^\s]+|/[^\s\r\n]*", text))
    bank["paths"].extend(re.findall(r"/[^\s\r\n]*", text))
    bank["numbers"].extend(re.findall(r"\b\d+\b", text))
    bank["words"].extend(re.findall(r"\b[A-Za-z_][A-Za-z0-9_.-]*\b", text))
    bank["hosts"].extend(re.findall(r"^Host:\s*(.+)$", text, re.MULTILINE))
    bank["user_agents"].extend(re.findall(r"^User-Agent:\s*(.+)$", text, re.MULTILINE))
    bank["accepts"].extend(re.findall(r"^Accept:\s*(.+)$", text, re.MULTILINE))
    bank["connections"].extend(re.findall(r"^Connection:\s*(.+)$", text, re.MULTILINE))
    bank["content_types"].extend(re.findall(r"^Content-Type:\s*(.+)$", text, re.MULTILINE))
    bank["content_lengths"].extend(re.findall(r"^Content-Length:\s*(\d+)$", text, re.MULTILINE))
    bank["call_ids"].extend(re.findall(r"^Call-ID:\s*(.+)$", text, re.MULTILINE))
    bank["cseq_numbers"].extend(re.findall(r"^CSeq:\s*(\d+)", text, re.MULTILINE))
    bank["tags"].extend(re.findall(r";tag=([^\s;>]+)", text))
    bank["contact_uris"].extend(re.findall(r"^Contact:\s*(.+)$", text, re.MULTILINE))
    bank["from_uris"].extend(re.findall(r"^From:\s*(.+)$", text, re.MULTILINE))
    bank["to_uris"].extend(re.findall(r"^To:\s*(.+)$", text, re.MULTILINE))
    bank["sip_uris"].extend(re.findall(r"sip:[^\s>;]+(?:[:]\d+)?", text))
    bank["ports"].extend(re.findall(r":(\d{2,5})\b", text))
    bank["ports"].extend(re.findall(r"client_port=(\d{2,5})", text))
    bank["ports"].extend(re.findall(r"m=\w+\s+(\d{2,5})\b", text))
    bank["media_ports"].extend(re.findall(r"^m=\w+\s+(\d{2,5})\b", text, re.MULTILINE))
    for start, end in re.findall(r"client_port=(\d{2,5})-(\d{2,5})", text):
        bank["rtsp_client_ports_start"].append(start)
        bank["rtsp_client_ports_end"].append(end)
    bank["session_ids"].extend(re.findall(r"^Session:\s*([^\s;]+)", text, re.MULTILINE))
    bank["rtsp_urls"].extend(re.findall(r"rtsp://[^\s]+", text))
    bank["rtsp_start_times"].extend(re.findall(r"^Range:\s*npt=([0-9.]+)-", text, re.MULTILINE))
    for sess_id, sess_ver in re.findall(r"^o=\S+\s+(\d+)\s+(\d+)\s+IN\s+IP4", text, re.MULTILINE):
        bank["sdp_sess_ids"].append(sess_id)
        bank["sdp_sess_versions"].append(sess_ver)


def _sip_identity_from_corpus(corpus_context: dict) -> tuple[str, str]:
    globals_ = corpus_context["global_values"]
    for candidate in globals_.get("sip_uris", []):
        match = re.search(r"sip:([^@>;\s]+)@([^:;>\s]+)", candidate)
        if match:
            return match.group(1), match.group(2)
    email = globals_.get("emails", [])
    if email and "@" in email[0]:
        local, domain = email[0].split("@", 1)
        return local, domain
    host = globals_.get("hosts", [])
    if host:
        return "user", host[0].split(":")[0]
    ip = globals_.get("ips", [])
    if ip:
        return "user", ip[0]
    return "user", "127.0.0.1"


def _strip_angle_brackets(value: str) -> str:
    cleaned = _sanitize_field_value(value)
    if cleaned.startswith("<") and cleaned.endswith(">"):
        return cleaned[1:-1].strip()
    return cleaned


def _sip_uri(local: str, domain: str, with_brackets: bool = False, port: str | None = None) -> str:
    uri = f"sip:{local}@{domain}"
    if port:
        uri += f":{port}"
    return f"<{uri}>" if with_brackets else uri


def _corpus_value_for(field_name: str, corpus_context: dict) -> str:
    field = field_name.lower()
    globals_ = corpus_context["global_values"]
    method_args = corpus_context["method_args"]
    sip_user, sip_domain = _sip_identity_from_corpus(corpus_context)

    def first(values: list[str], default: str = "") -> str:
        return values[0] if values else default

    if "username" in field or field == "user":
        return first(method_args.get("USER", []), first(globals_["words"]))
    if "password" in field or "credential" in field or "auth" in field:
        return first(method_args.get("PASS", []), first(globals_["words"]))
    if field in {"hostname", "host"}:
        return first(globals_["hosts"], "localhost")
    if field == "user-agent":
        return first(globals_["user_agents"], "S2AFL/1.0")
    if field == "accept-type":
        return first(globals_["accepts"], "*/*")
    if field == "connection-type":
        return first(globals_["connections"], "close")
    if field == "content-type":
        return first(globals_["content_types"], "application/octet-stream")
    if field == "content-length":
        return first(globals_["content_lengths"], "0")
    if field in {"sender", "recipient", "email"}:
        return _strip_angle_brackets(first(globals_["emails"], "ubuntu@ubuntu"))
    if field == "subject":
        return "test"
    if field in {"message-body", "request-body", "response-body", "announcement", "parameter-value"}:
        return "test"
    if field == "call-id":
        return first(globals_["call_ids"], f"1@{sip_domain}")
    if field == "tag":
        return first(globals_["tags"], "1")
    if field == "session-id":
        return first(globals_["session_ids"], "000022B8")
    if field == "start":
        return first(globals_["rtsp_client_ports_start"], "5000")
    if field == "end":
        return first(globals_["rtsp_client_ports_end"], "5001")
    if field == "start-time":
        return first(globals_["rtsp_start_times"], "0.000")
    if field == "sess-id":
        return first(globals_["sdp_sess_ids"], "1")
    if field == "sess-version":
        return first(globals_["sdp_sess_versions"], "1")
    if field == "max-hops":
        return "70"
    if field in {"owner", "media"}:
        return "audio" if field == "media" else "user1"
    if field == "payload":
        return "8"
    if field == "seconds":
        return "120"
    if field == "duration":
        return "1000"
    if field == "tone-code":
        return "1"
    if field == "credentials":
        return "AHRlc3QAdGVzdA=="
    if field == "authentication-method":
        return "PLAIN"
    if "directory" in field or "path" in field:
        return first(globals_["paths"], first(method_args.get("CWD", []), first(globals_["words"])))
    if "filename" in field or "name" in field:
        return first(method_args.get("RETR", []), first(method_args.get("STOR", []), first(globals_["words"])))
    if "host" in field or "ip" in field:
        return first(globals_["ips"], first(globals_["domains"], "127.0.0.1"))
    if "port" in field or field in {"p1", "p2"}:
        if field == "port":
            return first(globals_["media_ports"], first(globals_["ports"], "6000"))
        return first(globals_["ports"], "5060" if "port" in field else "1")
    if field in {"h1", "h2", "h3", "h4"} and globals_["ips"]:
        octets = globals_["ips"][0].split(".")
        idx = int(field[1]) - 1
        if 0 <= idx < len(octets):
            return octets[idx]
    if "sequence" in field:
        return first(globals_["cseq_numbers"], "1")
    if "length" in field or "len" in field:
        return first(globals_["content_lengths"], "0")
    if "id" in field:
        return first(globals_["numbers"], "1")
    if "uri" in field or "url" in field:
        if field == "rtsp-url":
            return first(globals_["rtsp_urls"], "rtsp://127.0.0.1:8554/media")
        if field in {"to-uri", "from-uri"}:
            return first(
                globals_["to_uris"] if field == "to-uri" else globals_["from_uris"],
                _sip_uri(sip_user, sip_domain, with_brackets=True),
            )
        if field == "contact-uri":
            return first(globals_["contact_uris"], _sip_uri(sip_user, sip_domain))
        if field in {"target-uri", "caller-uri"}:
            return _sip_uri(sip_user, sip_domain, with_brackets=True)
        if field in {"request-uri", "target", "recipient", "event-source", "presence-server", "subscriber"}:
            return f"{sip_user}@{sip_domain}"
        return first(globals_["uris"], first(globals_["paths"], "/"))
    if "domain" in field:
        return first(globals_["domains"], sip_domain)
    if "email" in field:
        return _strip_angle_brackets(first(globals_["emails"], "ubuntu@ubuntu"))
    if "command" in field:
        return first(globals_["words"])
    return first(globals_["words"], "seed")


def _template_to_regex(template_str: str) -> tuple[re.Pattern[str], list[str]]:
    fields = []
    pattern = []
    for part in parse_template(template_str):
        pos = 0
        for match in re.finditer(r"<<(\w[\w-]*)>>", part):
            pattern.append(re.escape(part[pos:match.start()]))
            fields.append(match.group(1))
            pattern.append(r"(.*?)")
            pos = match.end()
        pattern.append(re.escape(part[pos:]))
    return re.compile(r"^" + "".join(pattern) + r"$", re.DOTALL), fields


def _extract_fill_values_from_example(template_str: str, message: str) -> dict[str, str] | None:
    try:
        regex, fields = _template_to_regex(template_str)
    except re.error:
        return None
    matched = regex.match(message or "")
    if not matched:
        return None
    values = {}
    for field, value in zip(fields, matched.groups()):
        values[field] = _sanitize_field_value(value)
    return values


def _corpus_fill_values_for_template(method: str, template_str: str, corpus_context: dict) -> dict[str, str]:
    fields = extract_fields(parse_template(template_str))
    same_method_examples = corpus_context.get("messages_by_method", {}).get(method, [])
    partial = {}
    for example in same_method_examples:
        extracted = _extract_fill_values_from_example(template_str, example)
        if extracted:
            for field in fields:
                value = extracted.get(field)
                if value and field not in partial:
                    partial[field] = value
            if all(field in partial and partial.get(field) for field in fields):
                break
    if len(fields) == 1:
        for example in same_method_examples:
            first_line = example.splitlines()[0].strip() if example.splitlines() else ""
            if first_line == method:
                partial.setdefault(fields[0], "")

    fill_values = {}
    for field in fields:
        fill_values[field] = _sanitize_field_value(
            partial.get(field, _corpus_value_for(field, corpus_context))
        )
    return fill_values


def _normalize_fill_values(protocol: str, template_str: str, fill_values: dict[str, str], corpus_context: dict) -> dict[str, str]:
    visible = _template_visible(template_str)
    normalized = {k: _sanitize_field_value(v) for k, v in fill_values.items()}
    sip_user, sip_domain = _sip_identity_from_corpus(corpus_context)
    globals_ = corpus_context["global_values"]

    def first_numeric(values: list[str], default: str) -> str:
        for value in values:
            if str(value).isdigit():
                return str(value)
        return default

    def first_large_port(values: list[str], default: str) -> str:
        for value in values:
            if str(value).isdigit() and int(value) >= 1024:
                return str(value)
        return default

    for field, value in list(normalized.items()):
        placeholder = f"<<{field}>>"
        if f"<{placeholder}>" in visible:
            value = _strip_angle_brackets(value)
        if f"sip:{placeholder}" in visible and value.startswith("sip:"):
            value = value[4:]
        if field == "user" and (not value or value.isupper()):
            value = sip_user
        if field == "domain" and (not value or value.isupper()):
            value = sip_domain
        if protocol.upper() == "SIP" and field in {"user", "recipient"} and ("@" in value or value.startswith("sip:")):
            match = re.search(r"(?:sip:)?([^@>;\s]+)", value)
            if match:
                value = match.group(1)
        if field in {"domain"} and "@" in value:
            value = value.split("@", 1)[1]
        if field in {"to-URI", "from-URI"}:
            value = re.sub(r";tag=.*$", "", value)
        if field in {"to-URI", "from-URI"} and "sip:" not in value:
            value = _sip_uri(sip_user, sip_domain, with_brackets=True)
        if field == "contact-URI" and "sip:" not in value:
            value = _sip_uri(sip_user, sip_domain)
        if field in {"request-URI", "target", "event-source", "presence-server", "subscriber"} and value.startswith("<sip:"):
            inner = _strip_angle_brackets(value)
            value = inner[4:] if inner.startswith("sip:") else inner
        if field in {"sender", "recipient", "email"}:
            value = _strip_angle_brackets(value)
        if field == "host" and (not value or value == _method_from_message(value)):
            value = "localhost"
        if field == "user-agent" and (not value or value == _method_from_message(value)):
            value = "S2AFL/1.0"
        if field == "accept-type" and (not value or value == _method_from_message(value)):
            value = "*/*"
        if field == "connection-type" and (not value or value == _method_from_message(value)):
            value = "close"
        if field == "content-type" and (not value or value == _method_from_message(value)):
            value = "application/octet-stream"
        if field == "content-type" and "RTSP/1.0" in visible and "Accept:" in visible:
            value = "application/sdp"
        if field in {"sequence-number", "sess-id", "sess-version", "length", "max-hops", "seconds", "duration", "payload"} and not str(value).isdigit():
            if field == "sequence-number":
                value = first_numeric(globals_.get("cseq_numbers", []), "1")
            elif field == "length":
                value = first_numeric(globals_.get("content_lengths", []), "0")
            elif field == "max-hops":
                value = "70"
            elif field == "seconds":
                value = "120"
            elif field == "duration":
                value = "1000"
            elif field == "payload":
                value = "8"
            else:
                value = "1"
        if field == "port" and (not str(value).isdigit() or int(str(value)) < 1024):
            value = first_large_port(globals_.get("ports", []), "6000")
        if field in {"request-URI", "target", "event-source", "presence-server", "subscriber"} and (
            not value or value.isupper() or "@" not in value
        ):
            value = f"{sip_user}@{sip_domain}"
        normalized[field] = value

    return normalized


def _adjust_length_fields(template_str: str, fill_values: dict[str, str]) -> dict[str, str]:
    fields = extract_fields(parse_template(template_str))
    length_fields = [field for field in fields if field.lower() in {"content-length", "length"}]
    if not length_fields:
        return fill_values
    rendered = _render_template(template_str, fill_values)
    if "\r\n\r\n" in rendered:
        body = rendered.split("\r\n\r\n", 1)[1]
        body_len = len(body.encode("latin-1", errors="replace"))
    else:
        body_len = 0
    updated = dict(fill_values)
    for field in length_fields:
        updated[field] = str(body_len)
    return updated


def _protocol_consistent_value_bindings(
    protocol: str,
    sequence: list[str],
    method_to_template: dict[str, str],
    template_defaults: dict[str, dict],
) -> dict[str, str]:
    bindings: dict[str, str] = {}
    for method in sequence:
        template = method_to_template.get(method)
        if not template:
            continue
        default_entry = template_defaults.get(method, {})
        defaults = default_entry.get("field_values", {}) or {}
        for field in extract_fields(parse_template(template)):
            if field in bindings:
                continue
            value = _sanitize_field_value(defaults.get(field, ""))
            if value:
                bindings[field] = value
    proto = protocol.upper()
    if proto == "RTSP":
        url = bindings.get("rtsp-url", "")
        if url:
            bindings.setdefault("redirect-url", url)
    if proto == "SIP":
        user = bindings.get("user", "user")
        domain = bindings.get("domain", "127.0.0.1")
        for field in ("request-URI", "target", "subscriber", "event-source", "presence-server"):
            bindings.setdefault(field, f"{user}@{domain}")
    return bindings


def _bindings_for_method(
    protocol: str,
    method: str,
    sequence_index: int,
    template: str,
    base_bindings: dict[str, str],
    default_entry: dict,
) -> dict[str, str]:
    fields = extract_fields(parse_template(template))
    values = {field: _sanitize_field_value((default_entry.get("field_values", {}) or {}).get(field, "")) for field in fields}
    for field in fields:
        if base_bindings.get(field):
            values[field] = base_bindings[field]
    if "sequence-number" in fields:
        values["sequence-number"] = str(sequence_index + 1)
    if "sess-version" in fields:
        values["sess-version"] = str(sequence_index + 1)
    if protocol.upper() == "RTSP" and method in {"PLAY", "PAUSE", "TEARDOWN", "GET_PARAMETER", "SET_PARAMETER", "RECORD"}:
        if base_bindings.get("session-id"):
            values["session-id"] = base_bindings["session-id"]
    if protocol.upper() == "SIP" and "call-id" in fields and base_bindings.get("call-id"):
        values["call-id"] = base_bindings["call-id"]
    if protocol.upper() == "HTTP":
        if "uri" in fields and base_bindings.get("uri"):
            values["uri"] = base_bindings["uri"]
        if "host" in fields and base_bindings.get("host"):
            values["host"] = base_bindings["host"]
    return _adjust_length_fields(template, values)


def _method_hints(all_methods: list[str]) -> str:
    _ = all_methods
    return (
        "Preserve protocol-state coherence using only the evidence in the original seed sequence, "
        "same-method examples, and request templates. Keep counters and identifiers consistent across "
        "related requests, keep cleanup or termination requests near the logical end unless the original "
        "sequence shows otherwise, and avoid introducing standalone header/body fragments that are not "
        "complete requests."
    )


def _load_initial_sequences(path: str | None, method_order: list[str]) -> list[list[str]]:
    if not path or not os.path.exists(path):
        return _bootstrap_sequences(method_order)

    with open(path) as f:
        data = json.load(f)

    sequences = data.get("sequences", data)
    normalized = []
    for seq in sequences:
        if not seq:
            continue
        methods = []
        for item in seq:
            if isinstance(item, dict):
                if item.get("method"):
                    methods.append(item["method"])
                elif item.get("message"):
                    methods.append(_method_from_message(item["message"]))
            elif isinstance(item, str):
                methods.append(item if item.isupper() else _method_from_message(item))
        methods = [m for m in methods if m]
        if methods:
            normalized.append(methods)
    return normalized or _bootstrap_sequences(method_order)


def _bootstrap_sequences(method_order: list[str]) -> list[list[str]]:
    if not method_order:
        return []
    protocol_hint = set(method_order)
    if {"USER", "PASS"}.issubset(protocol_hint):
        return [
            ["OPEN", "USER", "PASS", "PWD", "QUIT"] if "OPEN" in protocol_hint else ["USER", "PASS", "PWD", "QUIT"],
            ["OPEN", "USER", "PASS", "LIST", "QUIT"] if "OPEN" in protocol_hint else ["USER", "PASS", "LIST", "QUIT"],
        ]
    if {"OPTIONS", "DESCRIBE", "SETUP", "PLAY"}.issubset(protocol_hint):
        return [["OPTIONS", "DESCRIBE", "SETUP", "PLAY", "TEARDOWN"]]
    if {"HELO", "MAIL", "RCPT", "DATA"}.issubset(protocol_hint):
        return [["HELO", "MAIL", "RCPT", "DATA", "QUIT"]]
    if {"GET", "POST"}.issubset(protocol_hint):
        return [["GET"], ["POST"]]
    return [method_order[: min(5, len(method_order))]]


def _build_graph(sequences: list[list[str]]) -> tuple[set[str], set[tuple[str, str]]]:
    nodes = set()
    edges = set()
    for seq in sequences:
        for idx, method in enumerate(seq):
            nodes.add(method)
            if idx + 1 < len(seq):
                edges.add((method, seq[idx + 1]))
    return nodes, edges


def _edges_of_sequence(sequence: list[str]) -> set[tuple[str, str]]:
    return {
        (sequence[idx], sequence[idx + 1])
        for idx in range(len(sequence) - 1)
    }


def _phase2_complete_methods(
    sequences: list[list[str]],
    all_methods: list[str],
    rng: random.Random,
    method_to_template: dict[str, str],
    template_defaults: dict[str, dict],
    corpus_context: dict,
) -> tuple[list[list[str]], list[dict], dict[str, int]]:
    covered, _ = _build_graph(sequences)
    uncovered = [m for m in all_methods if m not in covered]
    operations = []
    llm_usage = _empty_llm_usage()

    while uncovered:
        sample_size = 2 if len(uncovered) > 1 else 1
        selected = rng.sample(uncovered, k=sample_size)
        uncovered = [m for m in uncovered if m not in selected]
        anchor = sequences[rng.randrange(len(sequences))] if sequences else []
        new_seq, llm_meta, usage = _generate_methods_completion_sequence(
            protocol_methods=all_methods,
            method_to_template=method_to_template,
            template_defaults=template_defaults,
            base_sequence=anchor,
            target_methods=selected,
            corpus_context=corpus_context,
        )
        _merge_llm_usage(llm_usage, usage)
        sequences.append(new_seq if new_seq else selected)
        operations.append(
            {
                "phase": 2,
                "action": "insert_missing_methods",
                "methods": selected,
                "method": selected[0],
                "base_sequence": anchor,
                "result_sequence": new_seq if new_seq else selected,
                **llm_meta,
            }
        )

    return _dedupe_sequences(sequences), operations, llm_usage


def _phase3_complete_edges(
    sequences: list[list[str]],
    all_methods: list[str],
    rng: random.Random,
    method_to_template: dict[str, str],
    template_defaults: dict[str, dict],
    corpus_context: dict,
    max_insertions_per_edge: int = DEFAULT_EDGE_INSERTIONS,
    max_sequences: int = DEFAULT_MAX_SEQS,
    use_llm: bool = False,
) -> tuple[list[list[str]], list[dict], dict[str, int]]:
    _ = rng, max_insertions_per_edge, max_sequences
    _, existing_edges = _build_graph(sequences)
    operations = []
    llm_usage = _empty_llm_usage()
    repeatable = list(all_methods)
    target_edges = {(src, dst) for src in repeatable for dst in repeatable}
    seen_sequences = {tuple(seq) for seq in sequences}

    progress = True
    while progress and len(existing_edges) < len(target_edges):
        progress = False
        snapshot = list(_dedupe_sequences(sequences))
        for base in snapshot:
            occurrence_index: dict[str, int] = {}
            for insert_after, src in enumerate(base):
                occurrence_index[src] = occurrence_index.get(src, 0) + 1
                missing_dsts = [dst for dst in repeatable if (src, dst) not in existing_edges]
                if not missing_dsts:
                    continue

                for dst in missing_dsts:
                    new_seq, llm_meta, usage = _generate_edge_completion_sequence(
                        protocol_methods=all_methods,
                        method_to_template=method_to_template,
                        template_defaults=template_defaults,
                        base_sequence=base,
                        src=src,
                        dst=dst,
                        insert_after=insert_after,
                        corpus_context=corpus_context,
                        use_llm=use_llm,
                    )
                    new_edges = _edges_of_sequence(new_seq)
                    seq_key = tuple(new_seq)
                    if not _sequence_semantics_valid(new_seq, all_methods):
                        continue
                    if new_seq == base or (src, dst) not in new_edges or seq_key in seen_sequences:
                        continue
                    _merge_llm_usage(llm_usage, usage)
                    sequences.append(new_seq)
                    seen_sequences.add(seq_key)
                    existing_edges.update(new_edges)
                    operations.append(
                        {
                            "phase": 3,
                            "action": "insert_missing_edge",
                            "edge": [src, dst],
                            "base_sequence": base,
                            "result_sequence": new_seq,
                            "source_occurrence": occurrence_index[src],
                            "insert_after_index": insert_after,
                            **llm_meta,
                        }
                    )
                    progress = True
        if not progress:
            break

    return _dedupe_sequences(sequences), operations, llm_usage


def _pick_insertion_index(sequence: list[str], method: str, method_order: list[str] | None = None) -> int:
    if not sequence:
        return 0
    if method_order and method in method_order:
        target_rank = method_order.index(method)
        for idx, existing in enumerate(sequence):
            if existing in method_order and method_order.index(existing) > target_rank:
                return idx
        return len(sequence)
    # Favor inserting pre-auth methods early and destructive methods late.
    if method in {"OPEN", "AUTH", "USER", "HELO", "EHLO", "OPTIONS", "DESCRIBE"}:
        return min(1, len(sequence))
    if method in {"QUIT", "TEARDOWN", "BYE"}:
        return len(sequence)
    return max(1, len(sequence) // 2)


def _is_subsequence(base: list[str], candidate: list[str]) -> bool:
    if not base:
        return True
    it = iter(candidate)
    return all(any(item == current for current in it) for item in base)


def _has_edge(sequence: list[str], src: str, dst: str) -> bool:
    return any(sequence[i] == src and sequence[i + 1] == dst for i in range(len(sequence) - 1))


def _sequence_family(allowed_methods: list[str]) -> str:
    method_set = set(allowed_methods)
    if {"OPTIONS", "DESCRIBE", "SETUP", "PLAY"}.issubset(method_set):
        return "RTSP"
    if {"HELO", "MAIL", "RCPT", "DATA"}.issubset(method_set):
        return "SMTP"
    if {"REGISTER", "INVITE", "ACK", "BYE"}.intersection(method_set):
        return "SIP"
    return "GENERIC"


def _sequence_semantics_valid(candidate: list[str], allowed_methods: list[str]) -> bool:
    family = _sequence_family(allowed_methods)
    if family == "RTSP":
        saw_describe = False
        saw_setup = False
        session_methods = {"PLAY", "PAUSE", "TEARDOWN", "GET_PARAMETER", "SET_PARAMETER", "RECORD"}
        for method in candidate:
            if method == "DESCRIBE":
                saw_describe = True
            if method == "SETUP":
                if "DESCRIBE" in candidate and not saw_describe:
                    return False
                saw_setup = True
            if method in session_methods and not saw_setup:
                return False
        return True
    if family == "SMTP":
        saw_mail = False
        saw_rcpt = False
        for method in candidate:
            if method == "MAIL":
                saw_mail = True
            elif method == "RCPT":
                if not saw_mail:
                    return False
                saw_rcpt = True
            elif method == "DATA":
                if not (saw_mail and saw_rcpt):
                    return False
        return True
    return True


def _parse_json_fragment(text: str) -> dict | None:
    payload = (text or '').strip()
    if not payload:
        return None
    try:
        data = json.loads(payload)
        return data if isinstance(data, dict) else None
    except Exception:
        pass

    decoder = JSONDecoder()
    for start, ch in enumerate(payload):
        if ch != '{':
            continue
        try:
            data, end = decoder.raw_decode(payload[start:])
        except JSONDecodeError:
            continue
        if isinstance(data, dict):
            trailing = payload[start + end:].strip()
            if trailing and not trailing.startswith(('```',)):
                return data
            return data
    return None


def _validate_field_values(method: str, template_str: str, fill_values: dict[str, str]) -> bool:
    fields = extract_fields(parse_template(template_str))
    if not isinstance(fill_values, dict):
        return False
    for field in fields:
        if field not in fill_values:
            return False
    try:
        rendered = _render_template(
            template_str,
            {field: _sanitize_field_value(fill_values.get(field, "")) for field in fields},
        )
    except Exception:
        return False
    return _method_from_message(rendered) == method


def _validate_sequence_candidate(
    candidate: list[str],
    allowed_methods: list[str],
    base_sequence: list[str],
    required_methods: list[str],
    require_edge: tuple[str, str] | None = None,
) -> bool:
    if not candidate or any(method not in allowed_methods for method in candidate):
        return False
    if not _is_subsequence(base_sequence, candidate):
        return False
    if any(method not in candidate for method in required_methods):
        return False
    if require_edge and not _has_edge(candidate, require_edge[0], require_edge[1]):
        return False
    if len(candidate) > len(base_sequence) + DEFAULT_LLM_MAX_EXPANSION + len(required_methods):
        return False
    if not _sequence_semantics_valid(candidate, allowed_methods):
        return False
    return True


def _sequence_context_for_prompt(
    sequence: list[str],
    method_to_template: dict[str, str],
    template_defaults: dict[str, dict],
    corpus_context: dict,
) -> str:
    rendered = []
    example_offsets: dict[str, int] = {}
    messages_by_method = corpus_context.get("messages_by_method", {})
    for method in sequence:
        examples = messages_by_method.get(method, [])
        offset = example_offsets.get(method, 0)
        if offset < len(examples):
            rendered.append(str(examples[offset]).rstrip())
            example_offsets[method] = offset + 1
            continue
        if method in method_to_template:
            template = method_to_template[method]
            default_entry = template_defaults.get(method, {})
            fill_values = _adjust_length_fields(template, default_entry.get("field_values", {}))
            rendered.append(_render_template(template, fill_values).rstrip())
            continue
        rendered.append(method)
    return "\n\n".join(item for item in rendered if item)


def _method_descriptions_for_prompt(
    methods: list[str],
    method_to_template: dict[str, str],
    template_defaults: dict[str, dict],
) -> str:
    lines = []
    for method in methods:
        template = method_to_template.get(method)
        if template:
            default_entry = template_defaults.get(method, {})
            fill_values = _adjust_length_fields(template, default_entry.get("field_values", {}))
            snippet = _render_template(template, fill_values).splitlines()[0].strip()
            lines.append(f"- {method}: {snippet}")
        else:
            lines.append(f"- {method}")
    return "\n".join(lines)


def _build_chatafl_style_completion_prompt(
    protocol_methods: list[str],
    method_to_template: dict[str, str],
    template_defaults: dict[str, dict],
    base_sequence: list[str],
    target_methods: list[str],
    corpus_context: dict,
) -> str:
    sequence_text = _sequence_context_for_prompt(base_sequence, method_to_template, template_defaults, corpus_context)
    target_text = ", ".join(target_methods)
    return f"""The following is one sequence of client requests:
{sequence_text}

Please add the {target_text} client requests in the proper locations, and keep the original client requests in the same relative order.

Known client request methods:
{', '.join(protocol_methods)}

Reference request templates for the missing client requests:
{_method_descriptions_for_prompt(target_methods, method_to_template, template_defaults)}

Constraints:
- Preserve the original base sequence as a subsequence.
- Use only methods from the known client request method set.
- Insert every missing target method at least once.
- Add at most {DEFAULT_LLM_MAX_EXPANSION} extra helper methods if they are necessary for a coherent protocol session.
- Keep resource identifiers, paths, URLs, session identifiers, and similar cross-request fields coherent unless the original evidence clearly changes them.
- Keep sequence counters and other ordered identifiers monotonic and internally consistent across the whole sequence.
- Do not emit partial headers, body-only fragments, or free-form text as standalone requests; every sequence element must correspond to one full request method.
- Follow this session-order hint: {_method_hints(protocol_methods)}

Return JSON only in this shape:
{{"sequence": ["METHOD1", "METHOD2"], "reason": "short explanation"}}"""


def _build_prmgt_edge_prompt(
    protocol_methods: list[str],
    method_to_template: dict[str, str],
    template_defaults: dict[str, dict],
    base_sequence: list[str],
    src: str,
    dst: str,
    insert_after: int | None,
    corpus_context: dict,
) -> str:
    sequence_text = _sequence_context_for_prompt(base_sequence, method_to_template, template_defaults, corpus_context)
    occurrence = (insert_after + 1) if insert_after is not None else 1
    return f"""The following is one sequence of client requests:
{sequence_text}

This sequence already exists, but the request-method graph still misses the directed transition {src} -> {dst}.
Please insert the {dst} client request after an appropriate occurrence of {src} so that the modified sequence contains the transition {src} -> {dst}, while preserving the original client requests in the same relative order.

Focus on the {occurrence} occurrence position of {src} in the current base sequence when choosing the insertion point.

Known client request methods:
{', '.join(protocol_methods)}

Reference request templates for the key request methods:
{_method_descriptions_for_prompt([src, dst], method_to_template, template_defaults)}

Constraints:
- Preserve the original base sequence as a subsequence.
- Ensure that {src} is immediately followed by {dst} at least once in the result.
- Use only methods from the known client request method set.
- Add at most {DEFAULT_LLM_MAX_EXPANSION} extra helper methods if they are necessary for a coherent protocol session.
- Keep resource identifiers, paths, URLs, session identifiers, and similar cross-request fields coherent unless the original evidence clearly changes them.
- Keep sequence counters and other ordered identifiers monotonic and internally consistent across the whole sequence.
- Do not emit partial headers, body-only fragments, or free-form text as standalone requests; every sequence element must correspond to one full request method.
- Follow this session-order hint: {_method_hints(protocol_methods)}

Return JSON only in this shape:
{{"sequence": ["METHOD1", "METHOD2"], "reason": "short explanation"}}"""


def _generate_methods_completion_sequence(
    protocol_methods: list[str],
    method_to_template: dict[str, str],
    template_defaults: dict[str, dict],
    base_sequence: list[str],
    target_methods: list[str],
    corpus_context: dict,
) -> tuple[list[str], dict, dict[str, int]]:
    fallback = base_sequence[:]
    for target_method in target_methods:
        fallback.insert(_pick_insertion_index(fallback, target_method, protocol_methods), target_method)
    prompt = _build_chatafl_style_completion_prompt(
        protocol_methods=protocol_methods,
        method_to_template=method_to_template,
        template_defaults=template_defaults,
        base_sequence=base_sequence,
        target_methods=target_methods,
        corpus_context=corpus_context,
    )
    try:
        response = call_llm(prompt, max_tokens=768)
    except Exception as exc:
        return fallback, {
            "generation_mode": "deterministic-fallback",
            "prompt_style": "chatafl-insert+prmgt",
            "llm_reason": f"llm-exception:{type(exc).__name__}",
        }, _empty_llm_usage()
    usage = _usage_from_response(response)
    parsed = _parse_json_fragment(response or "")
    candidate = parsed.get("sequence") if parsed else None
    if isinstance(candidate, list) and _validate_sequence_candidate(
        candidate,
        protocol_methods,
        base_sequence,
        target_methods,
    ):
        return candidate, {
            "generation_mode": "llm-chatafl-style-insert",
            "prompt_style": "chatafl-insert+prmgt",
            "llm_reason": parsed.get("reason", ""),
        }, usage
    return fallback, {
        "generation_mode": "deterministic-fallback",
        "prompt_style": "chatafl-insert+prmgt",
        "llm_reason": parsed.get("reason", "") if parsed else "",
    }, usage


def _generate_edge_completion_sequence(
    protocol_methods: list[str],
    method_to_template: dict[str, str],
    template_defaults: dict[str, dict],
    base_sequence: list[str],
    src: str,
    dst: str,
    insert_after: int | None,
    corpus_context: dict,
    use_llm: bool,
) -> tuple[list[str], dict, dict[str, int]]:
    fallback = _insert_after_position(base_sequence, insert_after, dst) if insert_after is not None else _insert_after_first(base_sequence, src, dst)
    if not _sequence_semantics_valid(fallback, protocol_methods):
        fallback = base_sequence[:]
    if not use_llm:
        return fallback, {
            "generation_mode": "deterministic-fallback",
            "prompt_style": "deterministic-edge-completion",
            "llm_reason": "llm-disabled",
        }, _empty_llm_usage()
    prompt = _build_prmgt_edge_prompt(
        protocol_methods=protocol_methods,
        method_to_template=method_to_template,
        template_defaults=template_defaults,
        base_sequence=base_sequence,
        src=src,
        dst=dst,
        insert_after=insert_after,
        corpus_context=corpus_context,
    )
    try:
        response = call_llm(prompt, max_tokens=768)
    except Exception as exc:
        return fallback, {
            "generation_mode": "deterministic-fallback",
            "prompt_style": "chatafl-insert+prmgt",
            "llm_reason": f"llm-exception:{type(exc).__name__}",
        }, _empty_llm_usage()
    usage = _usage_from_response(response)
    parsed = _parse_json_fragment(response or "")
    candidate = parsed.get("sequence") if parsed else None
    if isinstance(candidate, list) and _validate_sequence_candidate(
        candidate,
        protocol_methods,
        base_sequence,
        [src, dst],
        require_edge=(src, dst),
    ):
        return candidate, {
            "generation_mode": "llm-prmgt-edge-completion",
            "prompt_style": "chatafl-insert+prmgt",
            "llm_reason": parsed.get("reason", ""),
        }, usage
    return fallback, {
        "generation_mode": "deterministic-fallback",
        "prompt_style": "chatafl-insert+prmgt",
        "llm_reason": parsed.get("reason", "") if parsed else "",
    }, usage


def _find_sequence_with_method(sequences: list[list[str]], method: str) -> list[str] | None:
    for seq in sequences:
        if method in seq:
            return seq
    return None


def _insert_after_first(sequence: list[str], src: str, dst: str) -> list[str]:
    new_seq = sequence[:]
    for idx, method in enumerate(new_seq):
        if method == src:
            new_seq.insert(idx + 1, dst)
            return new_seq
    return new_seq


def _insert_after_position(sequence: list[str], index: int, method: str) -> list[str]:
    if index < 0:
        index = -1
    new_seq = sequence[:]
    new_seq.insert(min(index + 1, len(new_seq)), method)
    return new_seq


def _dedupe_sequences(sequences: list[list[str]]) -> list[list[str]]:
    seen = set()
    result = []
    for seq in sequences:
        key = tuple(seq)
        if key in seen:
            continue
        seen.add(key)
        result.append(seq)
    return result


def _generate_template_field_values_llm(
    protocol: str,
    method: str,
    template: str,
    corpus_context: dict,
) -> tuple[dict[str, str] | None, str, dict[str, int]]:
    fields = extract_fields(parse_template(template))
    if not fields:
        return {}, "template-no-fields", _empty_llm_usage()
    same_method_examples = corpus_context.get("messages_by_method", {}).get(method, [])[:3]
    prompt = f"""You are preparing canonical default field values for one protocol request template.

PROTOCOL: {protocol}
CURRENT METHOD: {method}

ORIGINAL SEED SEQUENCES:
{json.dumps(corpus_context.get("raw_sequences", [])[:3], ensure_ascii=False, indent=2)}

ORIGINAL EXAMPLES FOR THIS METHOD:
{json.dumps(same_method_examples, ensure_ascii=False, indent=2)}

TEMPLATE:
{_template_visible(template)}

FIELDS:
{json.dumps(fields)}

Task:
- Infer one semantically correct default value for each field in this template.
- Prefer values consistent with ORIGINAL EXAMPLES FOR THIS METHOD.
- If examples are incomplete, infer a plausible default from the surrounding original seed corpus.
- Keep field choices compatible with sequence-wide consistency constraints such as stable resource identifiers, monotonic counters, coherent session identifiers, and correct body-length relationships.
- Do not generate attack payloads, overlong strings, or mutation-style boundary values.
- Each value must fit naturally into the template as a normal baseline seed value.

Return JSON only in this shape:
{{"field_values": {{"field1": "value1"}}, "reason": "short explanation"}}"""
    try:
        response = call_llm(prompt, max_tokens=512)
    except Exception as exc:
        return None, f"llm-exception:{type(exc).__name__}", _empty_llm_usage()
    usage = _usage_from_response(response)
    parsed = _parse_json_fragment(response or "")
    candidate = parsed.get("field_values") if parsed else None
    if not isinstance(candidate, dict):
        return None, "", usage
    cleaned = {field: _sanitize_field_value(candidate.get(field, "")) for field in fields}
    if not _validate_field_values(method, template, cleaned):
        return None, parsed.get("reason", "") if parsed else "", usage
    return cleaned, parsed.get("reason", "") if parsed else "", usage


def _build_template_default_value_map(
    protocol: str,
    method_to_template: dict[str, str],
    corpus_context: dict,
    use_llm_defaults: bool = False,
) -> tuple[dict[str, dict], dict[str, int]]:
    defaults = {}
    llm_usage = _empty_llm_usage()
    for method, template in method_to_template.items():
        corpus_values = _normalize_fill_values(
            protocol,
            template,
            _corpus_fill_values_for_template(method, template, corpus_context),
            corpus_context,
        )
        selected_values = corpus_values
        generation_mode = "corpus-derived"
        llm_reason = ""
        if use_llm_defaults and extract_fields(parse_template(template)):
            llm_values, llm_reason, usage = _generate_template_field_values_llm(
                protocol=protocol,
                method=method,
                template=template,
                corpus_context=corpus_context,
            )
            _merge_llm_usage(llm_usage, usage)
            if llm_values:
                selected_values = _normalize_fill_values(
                    protocol,
                    template,
                    llm_values,
                    corpus_context,
                )
                generation_mode = "llm-template-defaults"
            else:
                generation_mode = "corpus-derived-fallback"
        defaults[method] = {
            "field_values": selected_values,
            "generation_mode": generation_mode,
            "llm_reason": llm_reason,
        }
    return defaults, llm_usage


def _render_sequence_messages(
    protocol: str,
    sequence: list[str],
    method_to_template: dict[str, str],
    template_defaults: dict[str, dict],
) -> list[dict]:
    rendered = []
    base_bindings = _protocol_consistent_value_bindings(
        protocol,
        sequence,
        method_to_template,
        template_defaults,
    )
    for index, method in enumerate(sequence):
        template = method_to_template.get(method)
        if not template:
            continue
        default_entry = template_defaults.get(method, {})
        fill_values = _bindings_for_method(
            protocol,
            method,
            index,
            template,
            base_bindings,
            default_entry,
        )
        message = _render_template(template, fill_values)
        for field, value in fill_values.items():
            if value and field not in base_bindings:
                base_bindings[field] = value
        rendered.append(
            {
                "method": method,
                "template": template,
                "message": message,
                "generation_mode": default_entry.get("generation_mode", "corpus-derived"),
                "field_values": fill_values,
                "llm_reason": default_entry.get("llm_reason", ""),
            }
        )
    return rendered


def generate_seeds(
    protocol: str,
    templates_file: str,
    initial_sequences_file: str | None = None,
    seed_corpus_dir: str | None = None,
    seed: int = 1337,
    max_sequences: int = DEFAULT_MAX_SEQS,
    use_llm_messages: bool = False,
) -> dict:
    _ = max_sequences
    rng = random.Random(seed)
    method_to_template, all_methods = _load_templates(templates_file, protocol)
    corpus_context = _extract_corpus_context(protocol, seed_corpus_dir)
    sequences = _load_initial_sequences(initial_sequences_file, all_methods)
    initial_sequences = deepcopy(sequences)
    initial_nodes, initial_edges = _build_graph(sequences)

    template_defaults, template_llm_usage = _build_template_default_value_map(
        protocol,
        method_to_template,
        corpus_context,
        use_llm_defaults=use_llm_messages,
    )

    llm_expanded_sequences, phase2_ops, phase2_llm_usage = _phase2_complete_methods(
        sequences,
        all_methods,
        rng,
        method_to_template,
        template_defaults,
        corpus_context,
    )
    traversal_interpolated_sequences, phase3_ops, phase3_llm_usage = _phase3_complete_edges(
        llm_expanded_sequences,
        all_methods,
        rng,
        method_to_template,
        template_defaults,
        corpus_context,
        use_llm=False,
    )

    final_nodes, final_edges = _build_graph(traversal_interpolated_sequences)
    target_directed_edges = len(all_methods) * len(all_methods)
    graph_completed = len(final_edges) == target_directed_edges

    initial_keys = {tuple(seq) for seq in initial_sequences}
    llm_all_keys = {tuple(seq) for seq in llm_expanded_sequences}
    llm_only_sequences = [seq for seq in llm_expanded_sequences if tuple(seq) not in initial_keys]
    traversal_only_sequences = [seq for seq in traversal_interpolated_sequences if tuple(seq) not in llm_all_keys]

    original_rendered = [
        {
            "methods": seq,
            "messages": _render_sequence_messages(
                protocol,
                seq,
                method_to_template,
                template_defaults,
            ),
        }
        for seq in initial_sequences
    ]
    llm_expanded_rendered = [
        {
            "methods": seq,
            "messages": _render_sequence_messages(
                protocol,
                seq,
                method_to_template,
                template_defaults,
            ),
        }
        for seq in llm_only_sequences
    ]
    traversal_rendered = [
        {
            "methods": seq,
            "messages": _render_sequence_messages(
                protocol,
                seq,
                method_to_template,
                template_defaults,
            ),
        }
        for seq in traversal_only_sequences
    ]
    rendered_sequences = original_rendered + llm_expanded_rendered + traversal_rendered

    return {
        "protocol": protocol,
        "strategy": "PSEI-sequence-llm-plus-template-rendering" if use_llm_messages else "PSEI-sequence-llm-plus-template-rendering",
        "seed": seed,
        "seed_corpus_dir": seed_corpus_dir,
        "llm_guided_sequence": True,
        "llm_guided_template_defaults": use_llm_messages,
        "stats": {
            "template_methods": len(all_methods),
            "initial_sequence_count": len(initial_sequences),
            "llm_expanded_sequence_count": len(llm_only_sequences),
            "traversal_interpolated_sequence_count": len(traversal_only_sequences),
            "final_sequence_count": len(traversal_interpolated_sequences),
            "export_sequence_count": len(rendered_sequences),
            "initial_nodes": len(initial_nodes),
            "final_nodes": len(final_nodes),
            "initial_edges": len(initial_edges),
            "final_edges": len(final_edges),
            "target_directed_edges": target_directed_edges,
            "graph_completed": graph_completed,
            "missing_methods_filled": len(phase2_ops),
            "missing_edges_filled": len(phase3_ops),
            "sequence_cap_applied": False,
            "llm_usage": {
                "psei": {
                    "calls": int(template_llm_usage.get("calls", 0)) + int(phase2_llm_usage.get("calls", 0)) + int(phase3_llm_usage.get("calls", 0)),
                    "input_tokens": int(template_llm_usage.get("input_tokens", 0)) + int(phase2_llm_usage.get("input_tokens", 0)) + int(phase3_llm_usage.get("input_tokens", 0)),
                    "output_tokens": int(template_llm_usage.get("output_tokens", 0)) + int(phase2_llm_usage.get("output_tokens", 0)) + int(phase3_llm_usage.get("output_tokens", 0)),
                    "reasoning_tokens": int(template_llm_usage.get("reasoning_tokens", 0)) + int(phase2_llm_usage.get("reasoning_tokens", 0)) + int(phase3_llm_usage.get("reasoning_tokens", 0)),
                    "total_tokens": int(template_llm_usage.get("total_tokens", 0)) + int(phase2_llm_usage.get("total_tokens", 0)) + int(phase3_llm_usage.get("total_tokens", 0)),
                },
                "psei_template_defaults": template_llm_usage,
                "psei_phase2": phase2_llm_usage,
                "psei_phase3": phase3_llm_usage,
            },
        },
        "template_default_values": template_defaults,
        "graph": {
            "all_methods": all_methods,
            "initial_nodes": sorted(initial_nodes),
            "final_nodes": sorted(final_nodes),
            "initial_edges": sorted([list(e) for e in initial_edges]),
            "final_edges": sorted([list(e) for e in final_edges]),
        },
        "phase2_operations": phase2_ops,
        "phase3_operations": phase3_ops,
        "initial_sequences": initial_sequences,
        "llm_expanded_method_sequences": llm_expanded_sequences,
        "traversal_interpolated_method_sequences": traversal_interpolated_sequences,
        "original_sequences": original_rendered,
        "llm_expanded_sequences": llm_expanded_rendered,
        "traversal_interpolated_sequences": traversal_rendered,
        "enriched_sequences": rendered_sequences,
    }


def main():
    p = argparse.ArgumentParser(description="S2AFL PSEI seed generator")
    p.add_argument("--protocol", required=True)
    p.add_argument("--templates-file", required=True)
    p.add_argument("--initial-sequences")
    p.add_argument("--seed-corpus-dir")
    p.add_argument("--seed", type=int, default=1337)
    p.add_argument("--max-sequences", type=int, default=DEFAULT_MAX_SEQS)
    p.add_argument("--llm-messages", action="store_true", help="Use LLM only for per-template default field values; final messages are always rendered by template interpolation")
    p.add_argument("-o", "--output", required=True)
    args = p.parse_args()

    result = generate_seeds(
        protocol=args.protocol,
        templates_file=args.templates_file,
        initial_sequences_file=args.initial_sequences,
        seed_corpus_dir=args.seed_corpus_dir,
        seed=args.seed,
        max_sequences=args.max_sequences,
        use_llm_messages=args.llm_messages,
    )

    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    with open(args.output, "w") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)
    print(json.dumps(result["stats"], indent=2, ensure_ascii=False))
    print(f"Written -> {args.output}")


if __name__ == "__main__":
    main()
