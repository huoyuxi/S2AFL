"""Helpers for rendering and executing external commands."""

from __future__ import annotations

import json
import os
import signal
import subprocess
import time
from dataclasses import dataclass
from typing import Any


@dataclass
class CommandResult:
    argv: list[str]
    returncode: int
    stdout: str
    stderr: str


def run_command(
    argv: list[str],
    *,
    env: dict[str, str] | None = None,
    cwd: str | None = None,
    timeout: int | float | None = None,
) -> CommandResult:
    """Run an external command and return a normalized result object."""
    merged_env = None
    if env is not None:
        merged_env = dict(os.environ)
        merged_env.update(env)

    proc = subprocess.Popen(
        argv,
        env=merged_env,
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    try:
        stdout, stderr = proc.communicate(timeout=timeout)
        return CommandResult(
            argv=list(argv),
            returncode=proc.returncode,
            stdout=stdout or "",
            stderr=stderr or "",
        )
    except subprocess.TimeoutExpired:
        deadline = time.monotonic() + 2.0
        try:
            os.killpg(proc.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        except PermissionError:
            pass
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                break
            time.sleep(0.05)
        if proc.poll() is None:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except PermissionError:
                pass
        stdout, stderr = proc.communicate()
        timeout_text = f"command timed out after {timeout} seconds"
        stderr = stderr or ""
        if stderr:
            stderr = f"{stderr}\n{timeout_text}"
        else:
            stderr = timeout_text
        return CommandResult(
            argv=list(argv),
            returncode=124,
            stdout=stdout or "",
            stderr=stderr,
        )


def try_load_json(text: str) -> dict[str, Any] | list[Any] | None:
    """Try to parse stdout as JSON."""
    text = (text or "").strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None
