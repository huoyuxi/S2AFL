#!/usr/bin/env python3
from __future__ import annotations

"""
Generate concrete protocol messages from templates.

MODE 1 (--deterministic, default): replace <<FIELD>> with sample values.
    Guaranteed to match template format → exact byte offsets.

MODE 2 (--llm): ask LLM to generate message with realistic values.
    Better diversity but format may deviate from template.

Output: knowledge/data/facts/field_offset_map.json
"""

import argparse
import ast
import json
import os
import re
import socket
import sys
import time


from S2AFL.core.templates import DEFAULT_TEMPLATE_CATALOG, resolve_template_catalog_path
from S2AFL.llm_shared import call_text_prompt


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

_FIELD_PATTERN = re.compile(r"<<([A-Za-z0-9_-]+)>>")


def parse_template(template: str) -> list[str]:
    clean = template.replace("\r\n", "\\r\\n").replace("\r", "\\r").replace("\n", "\\n")
    value = ast.literal_eval(clean)
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise ValueError('template must decode to list[str]')
    return value


def extract_fields(parts: list[str]) -> list[str]:
    fields: list[str] = []
    for part in parts:
        for field in _FIELD_PATTERN.findall(part):
            if field not in fields:
                fields.append(field)
    return fields


def _sample_value(field_name: str) -> str:
    name = field_name.lower()
    if 'host' in name or 'domain' in name:
        return 'example.com'
    if 'ip' in name or 'addr' in name:
        return '127.0.0.1'
    if 'port' in name:
        return '2121'
    if 'user' in name or 'login' in name:
        return 'alice'
    if 'pass' in name or 'auth' in name:
        return 'example-password'
    if 'mail' in name:
        return 'user@example.com'
    if 'path' in name or 'file' in name or 'dir' in name or 'name' in name:
        return '/tmp/file.txt'
    if 'uri' in name or 'url' in name:
        return 'rtsp://example.com/media'
    if 'call' in name and 'id' in name:
        return 'call-0001'
    if 'tag' in name:
        return 'tag0001'
    if 'branch' in name:
        return 'z9hG4bK-0001'
    if 'transport' in name:
        return 'TCP'
    if 'type' in name:
        return 'A'
    if 'mode' in name:
        return 'I'
    if 'len' in name or 'size' in name or 'count' in name or 'num' in name or 'seq' in name or 'id' in name:
        return '1'
    return 'value'


def build_message_deterministic(parts: list[str]) -> tuple[str, dict[str, tuple[int, int]]]:
    rendered: list[str] = []
    offsets: dict[str, tuple[int, int]] = {}
    cursor = 0
    for part in parts:
        last = 0
        chunk_parts: list[str] = []
        for match in _FIELD_PATTERN.finditer(part):
            literal = part[last:match.start()]
            if literal:
                chunk_parts.append(literal)
                cursor += len(literal)
            field_name = match.group(1)
            value = _sample_value(field_name)
            offsets[field_name] = (cursor, cursor + len(value))
            chunk_parts.append(value)
            cursor += len(value)
            last = match.end()
        tail = part[last:]
        if tail:
            chunk_parts.append(tail)
            cursor += len(tail)
        rendered.append(''.join(chunk_parts))
    return ''.join(rendered), offsets


def call_llm(prompt: str, max_tokens: int = 4096) -> str | None:
    return call_text_prompt(prompt, max_tokens=max_tokens, temperature=0.0)


def build_llm_prompt(protocol: str, parts: list[str], fields: list[str]) -> str:
    """Build prompt asking LLM to generate a concrete protocol message."""
    display = []
    for p in parts:
        display.append(re.sub(r"<<(\w[\w-]*)>>", r"<\1>", p))
    template_visible = "".join(display)

    hints = []
    for f in fields:
        fl = f.lower()
        if "host" in fl or "ip" in fl: h = "IP addr like 192.168.1.100"
        elif "port" in fl: h = "port like 2121"
        elif "user" in fl: h = "username like alice"
        elif "pass" in fl: h = "credential like example-password"
        elif "file" in fl or "path" in fl or "name" in fl or "dir" in fl: h = "path like /pub/data.txt"
        elif "id" in fl or "seq" in fl or "num" in fl: h = "number like 1"
        elif "len" in fl or "size" in fl: h = "number like 1024"
        elif "uri" in fl or "url" in fl: h = "URI"
        elif "domain" in fl: h = "domain like example.com"
        elif "cmd" in fl: h = "command name"
        else: h = "appropriate value"
        hints.append(f"  <{f}> = {h}")

    return f"""You are a protocol fuzzer. Generate exactly ONE valid {protocol} request message.

TEMPLATE:
{template_visible}

Replace each placeholder:
{chr(10).join(hints)}

Output ONLY the raw protocol message. No markdown, no explanation, no code fences."""


# ---------------------------------------------------------------------------
# Network send
# ---------------------------------------------------------------------------

def send_message(host: str, port: int, message: str, timeout: float = 3.0) -> tuple[bool, str]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((host, port))
        sock.sendall(message.encode("latin-1", errors="replace"))
        resp = b""
        while True:
            try:
                c = sock.recv(4096)
                if not c: break
                resp += c
            except socket.timeout:
                break
        return True, resp.decode("latin-1", errors="replace")
    except Exception as e:
        return False, str(e)
    finally:
        sock.close()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def parse_args(argv: list[str] | None = None):
    parser = argparse.ArgumentParser(description="Generate concrete messages from a shared template catalog")
    parser.add_argument("--templates-file", default=str(DEFAULT_TEMPLATE_CATALOG),
                        help="Shared template catalog JSON file")
    parser.add_argument("--output-dir", default="",
                        help="Optional output directory for generated field facts")
    parser.add_argument("--llm", action="store_true", help="Use LLM mode when rendering messages")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None):
    args = parse_args(argv)
    project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    templates_file = str(resolve_template_catalog_path(args.templates_file))
    output_dir = args.output_dir or os.path.join(project_root, "knowledge/data/facts")
    os.makedirs(output_dir, exist_ok=True)

    use_llm = args.llm
    host = os.environ.get("S2AFL_TARGET_HOST", "127.0.0.1")
    port = int(os.environ.get("S2AFL_TARGET_PORT", "2121"))

    with open(templates_file) as f:
        all_templates = json.load(f)

    all_results = {}

    for protocol, templates in all_templates.items():
        print(f"\n{'='*60}")
        print(f"PROTOCOL: {protocol}  {'(LLM mode)' if use_llm else '(deterministic)'}")
        print(f"{'='*60}")

        entries = []
        for tmpl_str in templates:
            try:
                parts = parse_template(tmpl_str)
            except (ValueError, SyntaxError):
                continue

            fields = extract_fields(parts)
            if not fields:
                continue

            cmd = parts[0].strip()

            if use_llm:
                # LLM mode: prompt → generate → send
                prompt = build_llm_prompt(protocol, parts, fields)
                response = call_llm(prompt)
                if not response:
                    continue
                response = re.sub(r"^```[a-zA-Z]*\s*\n?", "", response)
                response = re.sub(r"\n?```$", "", response).strip()
                # For offsets in LLM mode, use deterministic to get reference offsets
                _, offsets = build_message_deterministic(parts)
                message = response
            else:
                message, offsets = build_message_deterministic(parts)

            # Send
            ok, resp = send_message(host, port, message)
            first_line = resp.split("\r\n")[0].strip() if ok else resp

            print(f"  [{cmd:6s}] {len(fields)} fields | send={'OK' if ok else 'FAIL'}")
            for fname, off in sorted(offsets.items(), key=lambda x: x[1]):
                if off[1] > off[0] and off[0] < len(message):
                    v = message[off[0]:off[1]]
                    print(f"    {fname:20s} [{off[0]:3d}:{off[1]:3d}] = {repr(v)}")
            if resp:
                print(f"    Response: {first_line[:80]}")

            entries.append({
                "command": cmd,
                "message": message,
                "message_len": len(message),
                "message_hex": message.encode("latin-1", errors="replace").hex(),
                "field_offsets": {f: off for f, off in offsets.items()},
                "send_success": ok,
                "response_first_line": first_line,
            })

            if use_llm:
                time.sleep(0.3)

        all_results[protocol] = entries

    output_path = os.path.join(output_dir, "field_offset_map.json")
    with open(output_path, "w") as f:
        json.dump(all_results, f, indent=2, ensure_ascii=False)
    print(f"\nDone → {output_path}")
    return all_results


if __name__ == "__main__":
    main()
