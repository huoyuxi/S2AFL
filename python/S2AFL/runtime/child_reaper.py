"""Runtime helper that reaps orphaned zombie descendants on Linux."""

from __future__ import annotations

import ctypes
import os
import threading
from pathlib import Path
from typing import Callable

from .logging_utils import RuntimeLogger

_PR_SET_CHILD_SUBREAPER = 36


class ChildProcessReaper:
    """Promote the runtime to a Linux subreaper and reap orphan zombies."""

    def __init__(
        self,
        *,
        logger: RuntimeLogger,
        managed_pid_supplier: Callable[[], set[int]] | None = None,
        poll_interval_sec: float = 1.0,
    ) -> None:
        self.logger = logger
        self.managed_pid_supplier = managed_pid_supplier or (lambda: set())
        self.poll_interval_sec = max(float(poll_interval_sec), 0.1)
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._enabled = False
        self._total_reaped = 0

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        if os.name != "posix" or not Path("/proc").exists():
            self.logger.log("Reaper", "child subreaper unavailable on this platform")
            return
        if not self._enable_subreaper():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run, name="runtime-child-reaper", daemon=True)
        self._thread.start()
        self._enabled = True
        self.logger.log(
            "Reaper",
            "child subreaper started",
            pid=os.getpid(),
            poll_interval_sec=self.poll_interval_sec,
        )

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=max(self.poll_interval_sec * 2.0, 2.0))
            self._thread = None
        if self._enabled:
            self._reap_orphan_zombies()
            self.logger.log("Reaper", "child subreaper stopped", total_reaped=self._total_reaped)
        self._enabled = False

    def _enable_subreaper(self) -> bool:
        libc = ctypes.CDLL(None, use_errno=True)
        prctl = getattr(libc, "prctl", None)
        if prctl is None:
            self.logger.log("Reaper", "libc.prctl is unavailable; child subreaper disabled")
            return False
        result = prctl(_PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0)
        if result != 0:
            err = ctypes.get_errno()
            self.logger.log("Reaper", "failed to enable child subreaper", errno=err)
            return False
        return True

    def _run(self) -> None:
        while not self._stop_event.wait(self.poll_interval_sec):
            self._reap_orphan_zombies()

    def _reap_orphan_zombies(self) -> int:
        managed = self._managed_pids()
        reaped = 0
        reaped += self._reap_waitable_children(managed)
        for pid in self._zombie_children():
            if pid in managed:
                continue
            try:
                waited_pid, _ = os.waitpid(pid, os.WNOHANG)
            except ChildProcessError:
                continue
            except OSError:
                continue
            if waited_pid > 0:
                reaped += 1
        if reaped:
            self._total_reaped += reaped
            self.logger.log("Reaper", "reaped orphan zombies", count=reaped, total_reaped=self._total_reaped)
        return reaped

    def _reap_waitable_children(self, managed: set[int]) -> int:
        """Reap any dead child visible to the current subreaper, not just direct /proc zombies."""
        if not hasattr(os, "waitid") or not hasattr(os, "P_ALL") or not hasattr(os, "WNOWAIT"):
            return 0
        options = os.WEXITED | os.WNOHANG | os.WNOWAIT
        reaped = 0
        while True:
            try:
                info = os.waitid(os.P_ALL, 0, options)
            except ChildProcessError:
                break
            except OSError:
                break
            if info is None:
                break
            pid = int(getattr(info, "si_pid", 0) or 0)
            if pid <= 0:
                break
            if pid in managed:
                break
            try:
                waited_pid, _ = os.waitpid(pid, os.WNOHANG)
            except ChildProcessError:
                continue
            except OSError:
                continue
            if waited_pid <= 0:
                break
            reaped += 1
        return reaped

    def _managed_pids(self) -> set[int]:
        try:
            return {int(pid) for pid in self.managed_pid_supplier() if int(pid) > 0}
        except Exception as exc:
            self.logger.log("Reaper", "managed pid supplier failed", error=repr(exc))
            return set()

    def _zombie_children(self) -> list[int]:
        current_pid = os.getpid()
        zombies: list[int] = []
        for stat_path in Path("/proc").glob("[0-9]*/stat"):
            try:
                pid, state, ppid = self._parse_proc_stat(stat_path.read_text(encoding="utf-8", errors="ignore"))
            except (OSError, ValueError):
                continue
            if ppid == current_pid and state == "Z":
                zombies.append(pid)
        return zombies

    def _parse_proc_stat(self, text: str) -> tuple[int, str, int]:
        close_idx = text.rfind(")")
        if close_idx <= 0:
            raise ValueError("malformed /proc stat")
        prefix = text[:close_idx]
        pid_text = prefix.split(" ", 1)[0]
        suffix = text[close_idx + 2 :].split()
        if len(suffix) < 2:
            raise ValueError("malformed /proc stat suffix")
        return int(pid_text), suffix[0], int(suffix[1])
