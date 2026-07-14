"""Runtime logging helpers.

This logger keeps two output streams:
1. Human-readable `runtime.log`
2. Post-processing-friendly `events.jsonl`
"""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path
from typing import Any


class RuntimeLogger:
    """Thread-safe runtime logger."""

    def __init__(self, log_dir: Path):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self._text_path = self.log_dir / "runtime.log"
        self._jsonl_path = self.log_dir / "events.jsonl"
        self._lock = threading.Lock()

    def log(self, actor: str, message: str, **fields: Any) -> None:
        """Write a readable text log entry and optionally attach fields to JSONL."""
        now = time.time()
        prefix = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now))
        line = f"[{prefix}] [{actor}] {message}"
        if fields:
            suffix = " ".join(f"{key}={value!r}" for key, value in sorted(fields.items()))
            line = f"{line} {suffix}"
        with self._lock:
            with self._text_path.open("a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        print(line, flush=True)

    def event(self, actor: str, kind: str, payload: dict[str, Any]) -> None:
        """Write one structured event record."""
        record = {
            "ts": time.time(),
            "actor": actor,
            "kind": kind,
            "payload": payload,
        }
        with self._lock:
            with self._jsonl_path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(record, ensure_ascii=False) + "\n")

