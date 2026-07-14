"""AFLNet process management and sync-based seed injection."""

from __future__ import annotations

import os
import re
import signal
import subprocess
import time
from pathlib import Path
from typing import Any

from .command_utils import run_command
from .config import RuntimeConfig
from .logging_utils import RuntimeLogger
from .seed_utils import body_sha1

_AFL_READY_MARKERS = (
    "all set and ready to roll!",
    "entering queue cycle",
)


class AFLNetSyncInjector:
    """Inject new seeds through AFLNet's sync sibling queue."""

    def __init__(self, config: RuntimeConfig, logger: RuntimeLogger):
        self.config = config
        self.logger = logger
        self._counter = 0
        self.config.resolved_partner_queue_dir.mkdir(parents=True, exist_ok=True)

    def inject_seed(self, raw_seed: str, origin_tag: str) -> Path:
        """Write a new seed into `agent-sync/queue/` so AFLNet can import it automatically."""
        payload = raw_seed.encode("latin-1", errors="replace")
        expected_sha1 = body_sha1(raw_seed)
        while True:
            path = self.config.resolved_partner_queue_dir / f"id:{self._counter:06d},orig:{origin_tag}"
            self._counter += 1
            if not path.exists():
                break
        tmp_path = path.with_name(path.name + '.tmp')
        tmp_path.write_bytes(payload)
        os.replace(tmp_path, path)
        actual_payload = path.read_bytes()
        actual_sha1 = body_sha1(actual_payload.decode("latin-1", errors="replace"))
        if actual_payload != payload or actual_sha1 != expected_sha1:
            raise RuntimeError(f"seed-hash-mismatch:{expected_sha1}:{actual_sha1}:{path}")
        self.logger.log("Injector", "seed injected", path=str(path), origin=origin_tag, body_sha1=expected_sha1)
        return path


class AFLNetRuntime:
    """Start, stop, and inspect AFLNet runtime state."""

    def __init__(self, config: RuntimeConfig, logger: RuntimeLogger):
        self.config = config
        self.logger = logger
        self._target_proc: subprocess.Popen[str] | None = None
        self._fuzzer_proc: subprocess.Popen[str] | None = None
        self._opened_logs: list[object] = []

    def start(self) -> None:
        """Start the target and afl-fuzz according to the runtime configuration."""
        self.config.ensure_directories()
        env = self.runtime_env()
        if self.config.target_start_cmd:
            argv = self.config.render_command(self.config.target_start_cmd)
            stdout, stderr = self._open_process_logs("target")
            cwd = self.config.resolved_target_start_cwd
            self.logger.log("AFLNet", "starting target", argv=argv, cwd=str(cwd) if cwd else "")
            self._target_proc = subprocess.Popen(
                argv,
                text=True,
                env=env,
                cwd=str(cwd) if cwd else None,
                stdout=stdout,
                stderr=stderr,
                start_new_session=True,
            )
            time.sleep(2)

        if self.config.afl_fuzz_cmd:
            argv = self._sanitize_afl_fuzz_argv(self.config.render_command(self.config.afl_fuzz_cmd))
            stdout, stderr = self._open_process_logs("afl-fuzz")
            cwd = self.config.resolved_afl_fuzz_cwd
            self.logger.log("AFLNet", "starting afl-fuzz", argv=argv, cwd=str(cwd) if cwd else "")
            self._fuzzer_proc = subprocess.Popen(
                argv,
                text=True,
                env=env,
                cwd=str(cwd) if cwd else None,
                stdout=stdout,
                stderr=stderr,
                start_new_session=True,
            )

    def _sanitize_afl_fuzz_argv(self, argv: list[str]) -> list[str]:
        """Sanitize known invalid arguments that can stall AFLNet."""
        sanitized = list(argv)
        for idx, item in enumerate(sanitized[:-1]):
            if item != '-w':
                continue
            raw_value = sanitized[idx + 1]
            try:
                timeout_us = int(str(raw_value).strip())
            except ValueError:
                continue
            if timeout_us >= 1_000_000:
                sanitized[idx + 1] = '999999'
                self.logger.log(
                    'AFLNet',
                    'adjusted invalid afl-fuzz -w timeout',
                    original=raw_value,
                    adjusted=sanitized[idx + 1],
                )
        return sanitized

    def cleanup_stale_fuzzers(self) -> list[dict[str, Any]]:
        """Clean up stale AFL/target processes for the same subject to avoid port and directory conflicts."""
        stale = self.find_stale_fuzzers() + self.find_stale_targets()
        for item in stale:
            self.logger.log(
                "AFLNet",
                item["log_message"],
                pid=item["pid"],
                pgid=item["pgid"],
                cmd=item["cmd"],
            )
            self._terminate_process_group_by_pid(item["pid"], item["label"], pgid=item.get("pgid"))
        return stale

    def _process_snapshot(self) -> list[dict[str, Any]]:
        try:
            result = subprocess.run(
                ["ps", "-eo", "pid=,pgid=,stat=,args="],
                check=True,
                capture_output=True,
                text=True,
            )
        except Exception as exc:
            self.logger.log("AFLNet", "failed to inspect running processes", error=repr(exc))
            return []

        rows: list[dict[str, Any]] = []
        for raw_line in result.stdout.splitlines():
            line = raw_line.strip()
            if not line:
                continue
            parts = line.split(None, 3)
            if len(parts) < 4:
                continue
            pid_text, pgid_text, stat_text, cmd = parts
            try:
                pid = int(pid_text)
                pgid = int(pgid_text)
            except ValueError:
                continue
            rows.append({"pid": pid, "pgid": pgid, "state": stat_text, "cmd": cmd})
        return rows

    def find_stale_fuzzers(self) -> list[dict[str, Any]]:
        """Find stale afl-fuzz processes still running for the current subject."""
        subject_markers = {
            str(self.config.resolved_afl_input_dir.parent),
            str(self.config.resolved_afl_output_dir.parent),
            f"{self.config.subject}/",
            f"/{self.config.subject}",
        }
        stale: list[dict[str, Any]] = []
        current_pid = os.getpid()
        for item in self._process_snapshot():
            pid = int(item["pid"])
            cmd = str(item["cmd"])
            state = str(item.get("state", ""))
            if pid == current_pid or state.startswith("Z"):
                continue
            argv0 = cmd.split(None, 1)[0] if cmd else ""
            argv0_name = Path(argv0).name if argv0 else ""
            if argv0_name != "afl-fuzz":
                continue
            if not any(marker in cmd for marker in subject_markers):
                continue
            stale.append({**item, "label": "stale afl-fuzz", "log_message": "killing stale afl-fuzz"})
        return stale

    def find_stale_targets(self) -> list[dict[str, Any]]:
        """Find orphan target processes so daemon leftovers do not keep ports busy."""
        patterns = [str(item).strip() for item in (self.config.stale_target_cmd_substrings or []) if str(item).strip()]
        if not patterns:
            return []
        basenames = {Path(pattern).name for pattern in patterns if Path(pattern).name}
        stale: list[dict[str, Any]] = []
        current_pid = os.getpid()
        for item in self._process_snapshot():
            pid = int(item["pid"])
            cmd = str(item["cmd"])
            state = str(item.get("state", ""))
            if pid == current_pid or state.startswith("Z"):
                continue
            if "afl-fuzz" in cmd:
                continue
            argv0 = cmd.split(None, 1)[0] if cmd else ""
            argv0_name = Path(argv0).name if argv0 else ""
            matched = argv0 in patterns or (argv0_name and argv0_name in basenames)
            if not matched:
                continue
            stale.append({**item, "label": "stale target process", "log_message": "killing stale target process"})
        return stale

    def stop(self) -> None:
        """Stop target/afl-fuzz and clean stale processes for the same subject."""
        self._terminate_process_group(self._fuzzer_proc, "afl-fuzz")
        self._terminate_process_group(self._target_proc, "target process")
        if self.config.target_stop_cmd:
            argv = self.config.render_command(self.config.target_stop_cmd)
            cwd = self.config.resolved_target_stop_cwd
            self.logger.log("AFLNet", "running target stop cmd", argv=argv, cwd=str(cwd) if cwd else "")
            run_command(argv, timeout=self.config.target_stop_timeout_sec, cwd=str(cwd) if cwd else None)
        self._cleanup_stale_targets_on_stop()
        for handle in self._opened_logs:
            try:
                handle.close()
            except Exception:
                pass
        self._opened_logs.clear()
        self._fuzzer_proc = None
        self._target_proc = None

    def _open_process_logs(self, prefix: str) -> tuple[object, object]:
        stdout = open(self.log_path(prefix, "stdout"), "a", encoding="utf-8")
        stderr = open(self.log_path(prefix, "stderr"), "a", encoding="utf-8")
        self._opened_logs.extend([stdout, stderr])
        return stdout, stderr

    def _cleanup_stale_targets_on_stop(self) -> None:
        """Scan for leftover target processes again at shutdown so a failed dry run does not leave orphans behind."""
        stale_targets = self.find_stale_targets()
        seen_pgids: set[int] = set()
        for item in stale_targets:
            pgid = int(item.get("pgid") or item["pid"])
            if pgid in seen_pgids:
                continue
            seen_pgids.add(pgid)
            self.logger.log(
                "AFLNet",
                "cleaning stale target process during stop",
                pid=item["pid"],
                pgid=pgid,
                cmd=item["cmd"],
            )
            self._terminate_process_group_by_pid(item["pid"], "stale target process", pgid=pgid)

    def _terminate_process_group(self, proc: subprocess.Popen[str] | None, label: str) -> None:
        if not proc or proc.poll() is not None:
            return
        self.logger.log("AFLNet", f"stopping {label}", pid=proc.pid)
        if not self._signal_process_group(proc.pid, signal.SIGTERM):
            return
        try:
            proc.wait(timeout=10)
            return
        except subprocess.TimeoutExpired:
            self.logger.log("AFLNet", f"force killing {label}", pid=proc.pid)
        if not self._signal_process_group(proc.pid, signal.SIGKILL):
            return
        proc.wait(timeout=5)

    def _terminate_process_group_by_pid(self, pid: int, label: str, *, pgid: int | None = None) -> None:
        group_or_pid = int(pgid) if pgid else pid
        if not self._signal_process_group(group_or_pid, signal.SIGTERM):
            return
        try:
            self._wait_external_pid_exit(pid, timeout=10.0)
            return
        except TimeoutError:
            self.logger.log("AFLNet", f"force killing {label}", pid=pid, pgid=group_or_pid)
        if not self._signal_process_group(group_or_pid, signal.SIGKILL):
            return
        self._wait_external_pid_exit(pid, timeout=5.0)

    def _signal_process_group(self, pid: int, sig: int) -> bool:
        try:
            os.killpg(pid, sig)
            return True
        except ProcessLookupError:
            return False
        except PermissionError:
            return False
        except Exception:
            try:
                os.kill(pid, sig)
                return True
            except ProcessLookupError:
                return False
            except PermissionError:
                return False

    def _wait_external_pid_exit(self, pid: int, timeout: float) -> None:
        deadline = time.time() + max(timeout, 0.0)
        while time.time() < deadline:
            proc_stat = Path(f"/proc/{pid}/stat")
            if not proc_stat.exists():
                return
            try:
                parts = proc_stat.read_text(encoding="utf-8", errors="ignore").split()
            except OSError:
                return
            if len(parts) >= 3 and parts[2] == "Z":
                return
            time.sleep(0.1)
        raise TimeoutError(f"pid {pid} did not exit within {timeout} seconds")

    def log_path(self, prefix: str, stream: str) -> Path:
        return self.config.resolved_log_dir / f"{prefix}.{stream}.log"

    def target_started(self) -> bool:
        return self._target_proc is not None

    def target_alive(self) -> bool:
        return bool(self._target_proc and self._target_proc.poll() is None)

    def target_returncode(self) -> int | None:
        if not self._target_proc:
            return None
        return self._target_proc.poll()

    def fuzzer_started(self) -> bool:
        return self._fuzzer_proc is not None

    def fuzzer_alive(self) -> bool:
        return bool(self._fuzzer_proc and self._fuzzer_proc.poll() is None)

    def fuzzer_returncode(self) -> int | None:
        if not self._fuzzer_proc:
            return None
        return self._fuzzer_proc.poll()

    def managed_pids(self) -> set[int]:
        managed: set[int] = set()
        for proc in (self._target_proc, self._fuzzer_proc):
            if proc and proc.pid > 0:
                managed.add(proc.pid)
        return managed

    def parse_fuzzer_stats(self) -> dict[str, Any]:
        """Read key/value pairs from `fuzzer_stats`."""
        path = self.config.resolved_fuzzer_out_dir / "fuzzer_stats"
        if not path.exists():
            return {}
        result: dict[str, Any] = {}
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            if ":" not in line:
                continue
            key, value = line.split(":", 1)
            result[key.strip()] = value.strip()
        return result

    def parse_plot_data(self) -> dict[str, Any]:
        """Read the last line of AFLNet `plot_data` as key metrics."""
        path = self.config.resolved_fuzzer_out_dir / "plot_data"
        if not path.exists():
            return {}
        lines = [line.strip() for line in path.read_text(encoding="utf-8", errors="ignore").splitlines() if line.strip()]
        if len(lines) < 2:
            return {}
        last = lines[-1]
        if re.match(r"^\d", lines[0]):
            header = [
                "unix_time",
                "cycles_done",
                "cur_path",
                "paths_total",
                "pending_total",
                "pending_favs",
                "map_size",
                "unique_crashes",
                "unique_hangs",
                "max_depth",
                "execs_per_sec",
                "n_nodes",
                "n_edges",
                "chat_times",
            ]
        else:
            header = lines[0].lstrip("# ").split(",")
            if last.startswith("#"):
                return {}
        values = [item.strip() for item in last.split(",")]
        if len(values) < len(header):
            return {}
        return dict(zip(header, values))

    def current_bitmap_state(self) -> tuple[str, str]:
        """Extract the bitmap/paths signature used for stagnation detection."""
        plot = self.parse_plot_data()
        if plot:
            return plot.get("map_size", ""), plot.get("paths_total", "")
        stats = self.parse_fuzzer_stats()
        return stats.get("bitmap_cvg", ""), stats.get("paths_total", "")

    def fuzzer_ready(self) -> bool:
        """Whether AFLNet has finished dry run and entered the main fuzzing loop."""
        if self.parse_plot_data():
            return True
        queue_dir = self.config.resolved_fuzzer_out_dir / "queue"
        if queue_dir.exists():
            for path in queue_dir.iterdir():
                if not path.is_file() or not path.name.startswith("id:"):
                    continue
                if ",orig:" not in path.name:
                    return True
        path = self.log_path("afl-fuzz", "stdout")
        if not path.exists():
            return False
        text = path.read_text(encoding="utf-8", errors="ignore").lower()
        return any(marker in text for marker in _AFL_READY_MARKERS)

    def runtime_env(self) -> dict[str, str]:
        env = dict(os.environ)
        for key in self.config.afl_env_unset:
            env.pop(str(key), None)
        env["AFL_SYNC_DIR"] = str(self.config.resolved_sync_dir)
        env["AFL_FUZZER_OUT_DIR"] = str(self.config.resolved_fuzzer_out_dir)
        # When reusing a container, do not assume the AFL environment baked into the Dockerfile is still present.
        # Set the common AFLNet runtime environment explicitly so afl-fuzz does not exit early because of core_pattern /
        # CPU frequency / CPU-affinity checks during startup.
        env.setdefault("AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES", "1")
        env.setdefault("AFL_SKIP_CPUFREQ", "1")
        env.setdefault("AFL_NO_AFFINITY", "1")
        env.setdefault("AFL_NO_UI", "1")
        for key, value in self.config.afl_env.items():
            env[str(key)] = str(value)
        compat_ld_path = self._prepare_runtime_compat_libs()
        if compat_ld_path:
            current = env.get("LD_LIBRARY_PATH", "")
            env["LD_LIBRARY_PATH"] = (
                f"{compat_ld_path}:{current}" if current else compat_ld_path
            )
        return env

    def _prepare_runtime_compat_libs(self) -> str:
        """Provide a compat shim only when afl-fuzz has an unresolved json-c SONAME."""
        if not self.config.afl_fuzz_cmd:
            return ""
        try:
            afl_argv = self.config.render_command(self.config.afl_fuzz_cmd)
        except Exception as exc:
            self.logger.log("AFLNet", "skipped runtime compat check", reason="render_failed", error=str(exc))
            return ""
        if not afl_argv:
            return ""

        afl_path = afl_argv[0]
        try:
            ldd = subprocess.run(
                ["ldd", afl_path],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                check=False,
            )
        except OSError as exc:
            self.logger.log(
                "AFLNet",
                "skipped runtime compat check",
                reason="ldd_failed",
                error=str(exc),
                afl_path=afl_path,
            )
            return ""

        missing_sonames = {
            match.group(1)
            for match in re.finditer(r"\b(libjson-c\.so\.[45])\s+=>\s+not found\b", ldd.stdout or "")
        }
        if not missing_sonames:
            return ""

        json5_candidates = (
            Path("/lib/x86_64-linux-gnu/libjson-c.so.5"),
            Path("/usr/lib/x86_64-linux-gnu/libjson-c.so.5"),
        )
        json4_candidates = (
            Path("/lib/x86_64-linux-gnu/libjson-c.so.4"),
            Path("/usr/lib/x86_64-linux-gnu/libjson-c.so.4"),
        )
        has_json5 = next((path for path in json5_candidates if path.exists()), None)
        has_json4 = next((path for path in json4_candidates if path.exists()), None)
        if not has_json5 and not has_json4:
            return ""

        compat_dir = self.config.resolved_temp_dir / "afl-lib-compat"
        compat_dir.mkdir(parents=True, exist_ok=True)

        created = []
        if "libjson-c.so.5" in missing_sonames and has_json4:
            shim = compat_dir / "libjson-c.so.5"
            if shim.exists() or shim.is_symlink():
                shim.unlink()
            shim.symlink_to(has_json4)
            created.append(("libjson-c.so.5", has_json4, shim))
        if "libjson-c.so.4" in missing_sonames and has_json5:
            shim = compat_dir / "libjson-c.so.4"
            if shim.exists() or shim.is_symlink():
                shim.unlink()
            shim.symlink_to(has_json5)
            created.append(("libjson-c.so.4", has_json5, shim))

        for missing, source, shim in created:
            self.logger.log(
                "AFLNet",
                "prepared runtime compat library shim",
                missing=missing,
                source=str(source),
                shim=str(shim),
                afl_path=afl_path,
            )
        return str(compat_dir) if created else ""
