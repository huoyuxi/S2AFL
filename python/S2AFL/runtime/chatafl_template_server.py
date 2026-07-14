"""In-process ChatAFL grammar template server."""

from __future__ import annotations

import ast
import json
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from .config import RuntimeConfig
from .logging_utils import RuntimeLogger

_RE_OPTIONAL_FIELD = re.compile(r"\[\s*(<<[^>]+>>)\s*\]")
_RE_GRAMMAR_ALL = re.compile(r"For the ([A-Za-z0-9_-]+) protocol, all of client request templates are :")
_RE_GRAMMAR_OTHER = re.compile(r"For the ([A-Za-z0-9_-]+) protocol, other templates of client requests are:")


def _normalize_template_line(proto: str, index: int, raw_line: str) -> str:
    escaped = raw_line.replace("\r\n", "\\r\\n").replace("\r", "\\r").replace("\n", "\\n")
    parsed = ast.literal_eval(escaped)
    if not isinstance(parsed, list):
        raise ValueError(f"{proto}[{index}] did not parse to a list")
    normalized = [_RE_OPTIONAL_FIELD.sub(r"\1", item) if isinstance(item, str) else item for item in parsed]
    rendered = json.dumps(normalized, ensure_ascii=False)
    first_array = rendered[: rendered.find("]") + 1]
    if json.loads(first_array) != normalized:
        raise ValueError(f"{proto}[{index}] is incompatible with ChatAFL legacy parser")
    return rendered


def _load_templates(path: Path) -> dict[str, str]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    parsed: dict[str, str] = {}
    for proto, lines in raw.items():
        if not isinstance(lines, list):
            raise RuntimeError(f"Template set {proto!r} is not a list")
        rendered = []
        for index, line in enumerate(lines):
            if not isinstance(line, str):
                raise RuntimeError(f"Template {proto}[{index}] is not a string")
            rendered.append(_normalize_template_line(proto, index, line))
        parsed[proto.upper()] = "\n".join(rendered)
    return parsed


def _parse_payload(raw_body: str) -> dict[str, Any] | None:
    try:
        payload = json.loads(raw_body)
        if isinstance(payload, dict) and "prompt" in payload:
            return payload
    except json.JSONDecodeError:
        pass

    prompt_match = re.search(r'"prompt":\s*"', raw_body)
    if not prompt_match:
        return None
    prompt_start = prompt_match.end()
    end_match = re.search(r'",\s*"max_tokens"\s*:', raw_body[prompt_start:])
    if not end_match:
        end_match = re.search(r'",\s*"temperature"\s*:', raw_body[prompt_start:])
    if not end_match:
        return None
    return {"prompt": raw_body[prompt_start : prompt_start + end_match.start()]}


def _protocol_from_prompt(prompt: str) -> str | None:
    match = _RE_GRAMMAR_ALL.search(prompt) or _RE_GRAMMAR_OTHER.search(prompt)
    if not match:
        return None
    return match.group(1).upper()


def _chatafl_response(content: str) -> bytes:
    return json.dumps({"choices": [{"text": content, "message": {"content": content}}]}).encode("utf-8")


class _ReusableThreadingHTTPServer(ThreadingHTTPServer):
    allow_reuse_address = True


class ChatAFLTemplateServer:
    """Small HTTP server used only for ChatAFL startup grammar templates."""

    def __init__(self, config: RuntimeConfig, logger: RuntimeLogger):
        self.config = config
        self.logger = logger
        self.host = str(getattr(config, "chatafl_template_host", "127.0.0.1") or "127.0.0.1")
        self.port = int(getattr(config, "chatafl_template_port", 12134) or 12134)
        self._server: _ReusableThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._templates: dict[str, str] = {}

    def start(self) -> None:
        if not bool(getattr(self.config, "enable_chatafl_template_server", True)):
            self.logger.log("TemplateServer", "ChatAFL template server disabled")
            return
        if self._server is not None:
            return
        self._templates = _load_templates(self.config.resolved_templates_file)
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                if self.path != "/chat":
                    self.send_error(404)
                    return
                raw = self.rfile.read(int(self.headers.get("Content-Length", "0"))).decode("utf-8", errors="ignore")
                payload = _parse_payload(raw)
                protocol = _protocol_from_prompt(str(payload.get("prompt", ""))) if payload else None
                answer = outer._templates.get(protocol or "")
                if answer is None:
                    outer.logger.log("TemplateServer", "template request rejected", path=self.path, protocol=protocol or "")
                    self.send_error(400)
                    return
                body = _chatafl_response(answer)
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                outer.logger.log("TemplateServer", "template request served", protocol=protocol, bytes=len(answer))

            def log_message(self, fmt: str, *args: object) -> None:
                return

        self._server = _ReusableThreadingHTTPServer((self.host, self.port), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, name="chatafl-template-server", daemon=True)
        self._thread.start()
        self.logger.log(
            "TemplateServer",
            "ChatAFL template server started",
            host=self.host,
            port=self.port,
            protocols=sorted(self._templates),
        )

    def stop(self) -> None:
        server = self._server
        if server is None:
            return
        self.logger.log("TemplateServer", "stopping ChatAFL template server", host=self.host, port=self.port)
        server.shutdown()
        server.server_close()
        if self._thread:
            self._thread.join(timeout=5)
        self._server = None
        self._thread = None
