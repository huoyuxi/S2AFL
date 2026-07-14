"""Seed parsing and rendering helpers for workflow2 runtime."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

from .protocol_policy import get_protocol_policy


def _request_content_length(header_blob: bytes) -> int:
    match = re.search(rb"(?:^|\r\n)Content-Length:\s*(\d+)\b", header_blob, re.IGNORECASE)
    if not match:
        return 0
    try:
        return max(0, int(match.group(1)))
    except (TypeError, ValueError):
        return 0


def _split_request_style_messages(raw_text: str) -> list[str]:
    """Split request-style seeds into complete requests, keeping Content-Length bodies attached."""
    data = raw_text.encode("latin-1", errors="replace")
    size = len(data)
    cursor = 0
    chunks: list[str] = []
    while cursor < size:
        header_end = data.find(b"\r\n\r\n", cursor)
        if header_end < 0:
            tail = data[cursor:]
            if tail.strip():
                chunks.append(tail.decode("latin-1", errors="replace"))
            break
        message_end = header_end + 4
        body_length = _request_content_length(data[cursor:header_end])
        if body_length > 0:
            message_end = min(size, message_end + body_length)
        chunk = data[cursor:message_end]
        if chunk.strip():
            chunks.append(chunk.decode("latin-1", errors="replace"))
        cursor = message_end
    return chunks


def _split_crlf_messages(raw_text: str) -> list[str]:
    """Split line-command seeds on every CRLF, matching AFLNet FTP/SMTP."""
    data = raw_text.encode("latin-1", errors="replace")
    size = len(data)
    cursor = 0
    chunks: list[str] = []
    while cursor < size:
        line_end = data.find(b"\r\n", cursor)
        if line_end < 0:
            tail = data[cursor:]
            if tail.strip():
                chunks.append(tail.decode("latin-1", errors="replace"))
            break
        chunk = data[cursor:line_end + 2]
        chunks.append(chunk.decode("latin-1", errors="replace"))
        cursor = line_end + 2
    return chunks


def _split_method_boundary_messages(raw_text: str, method_prefixes: tuple[str, ...]) -> list[str]:
    data = raw_text.encode("latin-1", errors="replace")
    if not data:
        return []
    chunks: list[str] = []
    cur_start = 0
    cur_end = 0
    mem = bytearray()
    byte_count = 0
    size = len(data)
    while byte_count < size:
        mem.append(data[byte_count])
        byte_count += 1
        encoded_prefixes = [prefix.encode("latin-1", errors="replace") for prefix in method_prefixes if prefix]
        next_is_method = any(data[byte_count:].startswith(prefix) for prefix in encoded_prefixes)
        if len(mem) > 1 and mem[-2] == 0x0D and mem[-1] == 0x0A and next_is_method:
            chunk = data[cur_start : cur_end + 1]
            if chunk.strip():
                chunks.append(chunk.decode("latin-1", errors="replace"))
            mem = bytearray()
            cur_start = cur_end + 1
            cur_end = cur_start
            continue
        cur_end += 1
        if cur_end == size - 1:
            chunk = data[cur_start : cur_end + 1]
            if chunk.strip():
                chunks.append(chunk.decode("latin-1", errors="replace"))
            break
    return chunks


def split_seed_messages(protocol: str, raw_text: str) -> list[str]:
    """Split `.raw` content into messages using AFLNet region rules."""
    policy = get_protocol_policy(protocol)
    if policy.message_style == "line-command":
        return _split_crlf_messages(raw_text or "")

    if policy.request_region_start_methods:
        return _split_method_boundary_messages(raw_text or "", policy.request_region_start_methods)

    if policy.message_style == "request-style":
        return _split_request_style_messages(raw_text or "")

    chunks: list[str] = []
    buf: list[str] = []
    for line in raw_text.split("\r\n"):
        buf.append(line)
        if line == "":
            candidate = "\r\n".join(buf).strip("\r\n")
            if candidate:
                chunks.append(candidate + "\r\n\r\n")
            buf = []
    tail = "\r\n".join(buf).strip("\r\n")
    if tail:
        chunks.append(tail + "\r\n")
    return [chunk for chunk in chunks if chunk.strip()]


def prefix_messages(messages: list[str], step_index: int) -> str:
    """Return the prefix message sequence used by prefix replay."""
    return "".join(messages[: step_index + 1])


def message_method(message: str) -> str:
    """Extract the first method/command token from one message."""
    lines = (message or "").splitlines()
    first = lines[0].strip() if lines else ""
    return first.split()[0] if first else ""


def message_preview(message: str, limit: int = 120) -> str:
    """Build a clipped single-line preview for logs and task context."""
    text = re.sub(r"\s+", " ", message.strip())
    return text[:limit]


def load_seed_file(path: str | Path) -> str:
    return Path(path).read_bytes().decode("latin-1", errors="replace")


def body_sha1(text: str) -> str:
    return hashlib.sha1(text.encode("latin-1", errors="replace")).hexdigest()


def parse_markdown_seed_block(text: str) -> str | None:
    """Extract a raw seed from a fenced code block in the LLM response."""
    match = re.search(r"```(?:raw|text|seed|json)?\s*(.*?)```", text, re.DOTALL | re.IGNORECASE)
    if match:
        return match.group(1).strip("\n")
    stripped = text.strip()
    if stripped and "\n" in stripped:
        return stripped
    return None
