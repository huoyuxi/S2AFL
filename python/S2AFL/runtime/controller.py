"""Top-level workflow2 runtime controller."""

from __future__ import annotations

import json
import queue
import re
import shutil
import threading
import time
from pathlib import Path
from typing import Any

from .aflnet import AFLNetRuntime, AFLNetSyncInjector
from .child_reaper import ChildProcessReaper
from .chatafl_template_server import ChatAFLTemplateServer
from .config import RuntimeConfig
from .coverage_replay import CoverageReplayWorker
from .knowledge_loader import RuntimeKnowledge
from .logging_utils import RuntimeLogger
from .mutation_worker import MutationWorker
from .psei_bootstrap import prepare_initial_corpus, quarantine_seed_file, startup_quarantined_seed_names, startup_seed_preflight_ok
from .queue_watcher import QueueWatcher, inject_bootstrap_sync_seeds
from .scheduler import MutationScheduler
from .state_db import RuntimeStateDB

_ORIG_PATTERN = re.compile(r'orig:([^,\s\'\"]+)')
_RAW_PATTERN = re.compile(r'([A-Za-z0-9_.-]+\.raw)')
_DRY_RUN_PATTERN = re.compile(r"Attempting dry run with 'id:\d+,orig:([^,\s'\"]+)'")
_ENVIRONMENTAL_STARTUP_MARKERS = (
    "another instance of afl-fuzz",
    "program abort : pipe at the beginning of 'core_pattern'",
    "unable to bind socket on local source port",
    "no server states have been detected",
)

_FORKSERVER_LOST_MARKERS = (
    "unable to communicate with fork server",
    "fork server is misbehaving",
)

_PRE_INPUT_CRASH_MARKERS = (
    "before receiving any input",
    "fork server crashed with signal",
)

_STARTUP_RETRYABLE_FAILURE_KINDS = {"seed_candidate", "timeout", "forkserver_lost", "environmental", "unknown"}
_STARTUP_RETRY_LIMIT = 3
_STARTUP_SEED_CANDIDATE_RETRY_LIMIT = 16
_STARTUP_READY_POLL_INTERVAL_SEC = 0.25
_STARTUP_SYNC_RECOVERY_COPY_LIMIT = 32
_STARTUP_READY_STABILIZE_SEC = 5.0


class RuntimeController:
    """Primary workflow2 runtime controller."""

    def __init__(self, config: RuntimeConfig):
        self.config = config
        self.config.ensure_directories()
        self.logger = RuntimeLogger(self.config.resolved_log_dir)
        self.state = RuntimeStateDB(self.config.resolved_state_dir / "runtime_state.sqlite3")
        self.knowledge = RuntimeKnowledge(
            implementation=self.config.implementation,
            protocol=self.config.protocol,
            templates_file=self.config.resolved_templates_file,
            include_function_boundary_targets=bool(getattr(self.config, "enable_guess_boundary_targets", False)),
        )
        self.knowledge.load()
        self.template_server = ChatAFLTemplateServer(self.config, self.logger)
        self.runtime = AFLNetRuntime(self.config, self.logger)
        self.injector = AFLNetSyncInjector(self.config, self.logger)
        self.reaper = ChildProcessReaper(logger=self.logger, managed_pid_supplier=self._managed_runtime_pids)

        self.stop_event = threading.Event()
        self.replay_queue: queue.Queue = queue.Queue()
        self.flip_confirmation_queue: queue.Queue = queue.Queue()
        self.coverage_result_queue: queue.Queue = queue.Queue()
        self.threads: list[threading.Thread] = []
        self._stop_lock = threading.Lock()
        self._stopped = False
        self._stop_reason = ""
        self._fatal_error = ""
        self._started_at: float | None = None
        self._bootstrap_summary: dict[str, Any] = {}
        self._import_health_checked = False
        self._coverage_focus_allowlist_path: Path | None = None

    def bootstrap(self) -> None:
        self.logger.log("Controller", "bootstrap start")
        if not self.config.enable_bootstrap:
            self.state.update_metric("psei_summary", {"skipped": True, "reason": "enable_bootstrap=false"})
            self.logger.log("Controller", "bootstrap skipped", experiment_label=self.config.experiment_label)
            return
        summary = prepare_initial_corpus(self.config, self.logger, self.state)
        self._bootstrap_summary = dict(summary)
        self.state.update_metric("psei_summary", summary)
        initial_seed_names = list(summary.get("initial_seed_names") or [])
        self.state.update_metric(
            "initial_replay_progress",
            {
                "expected_count": len(initial_seed_names),
                "seed_names": initial_seed_names,
                "completed_seed_names": [],
                "completed": len(initial_seed_names) == 0,
                "started_at": time.time(),
                "completed_at": time.time() if not initial_seed_names else 0.0,
            },
        )
        self.state.update_metric("last_new_coverage_at", 0.0)
        target_catalog_size = self.knowledge.target_catalog_size()
        self.state.update_metric("target_count", {"count": 0, "catalog_count": target_catalog_size, "materialization": "lazy"})
        self.state.update_metric("last_bitmap_change_ts", time.time())
        self._prepare_coverage_focus_allowlist()
        self.logger.log(
            "Controller",
            "bootstrap done",
            targets=0,
            target_catalog_size=target_catalog_size,
            target_materialization="lazy",
            afl_input_dir=str(self.config.resolved_afl_input_dir),
        )

    def _prepare_coverage_focus_allowlist(self) -> None:
        focus_files = self.knowledge.coverage_focus_relative_paths()
        if not focus_files:
            return
        allowlist_path = self.config.resolved_temp_dir / 'coverage-focus-files.txt'
        allowlist_path.write_text('\n'.join(focus_files) + '\n', encoding='utf-8')
        self._coverage_focus_allowlist_path = allowlist_path
        self.config.coverage_capture_env = dict(self.config.coverage_capture_env)
        self.config.coverage_capture_env['S2AFL_COVERAGE_FILE_ALLOWLIST'] = str(allowlist_path)
        self.state.update_metric(
            'coverage_focus_files',
            {'path': str(allowlist_path), 'count': len(focus_files), 'files': focus_files[:128]},
        )
        self.logger.log(
            'Controller',
            'coverage focus allowlist prepared',
            path=str(allowlist_path),
            file_count=len(focus_files),
        )

    def start(self) -> None:
        self._started_at = time.time()
        self.reaper.start()
        self.bootstrap()
        self.template_server.start()
        injection_timing = self._bootstrap_sync_injection_timing()
        if injection_timing == "before-afl":
            self._inject_bootstrap_sync_seeds(phase="before-afl")
        else:
            self._bootstrap_summary["sync_injected"] = False
            self._bootstrap_summary["sync_injected_before_afl"] = False
            self._bootstrap_summary["bootstrap_sync_injection_timing"] = injection_timing
            self.logger.log("Controller", "bootstrap sync injection deferred", timing=injection_timing)
        self._start_aflnet_with_recovery()
        if injection_timing == "after-afl":
            self._inject_bootstrap_sync_seeds(phase="after-afl")
        self._start_threads()

    def _bootstrap_sync_injection_timing(self) -> str:
        timing = str(getattr(self.config, "bootstrap_sync_injection_timing", "before-afl") or "before-afl").strip().lower()
        if timing not in {"before-afl", "after-afl"}:
            self.logger.log("Controller", "invalid bootstrap sync injection timing; using before-afl", timing=timing)
            return "before-afl"
        return timing

    def _inject_bootstrap_sync_seeds(self, *, phase: str) -> dict[str, object]:
        bootstrap_sync_summary = inject_bootstrap_sync_seeds(
            config=self.config,
            state=self.state,
            injector=self.injector,
            logger=self.logger,
            bootstrap_sync_seed_dir=str((self._bootstrap_summary or {}).get("sync_seed_dir", "")),
        )
        injected = bool(
            not bootstrap_sync_summary.get("skipped")
            and int(bootstrap_sync_summary.get("count", 0) or 0) > 0
        )
        self._bootstrap_summary["sync_injected"] = injected
        self._bootstrap_summary["sync_injected_before_afl"] = bool(injected and phase == "before-afl")
        self._bootstrap_summary["sync_injected_after_afl"] = bool(injected and phase == "after-afl")
        self._bootstrap_summary["bootstrap_sync_injection_timing"] = phase
        return bootstrap_sync_summary

    def request_stop(self, reason: str) -> None:
        reason_text = str(reason or "stop requested").strip() or "stop requested"
        if not self._stop_reason:
            self._stop_reason = reason_text
        if not self.stop_event.is_set():
            self.logger.log("Controller", "stop requested", reason=self._stop_reason)
            self.stop_event.set()

    def run_forever(self, *, duration_sec: float | None = None) -> None:
        deadline = None
        duration_value = None
        if duration_sec is not None:
            duration_value = float(duration_sec)
            if duration_value <= 0:
                raise ValueError("duration_sec must be > 0")
        try:
            self.start()
            if duration_value is not None:
                deadline = time.time() + duration_value
            self.logger.log(
                "Controller",
                "runtime started",
                duration_sec=duration_sec,
                run_tag=self.config.run_tag,
                afl_output_dir=str(self.config.resolved_afl_output_dir),
                state_dir=str(self.config.resolved_state_dir),
                log_dir=str(self.config.resolved_log_dir),
            )
            while not self.stop_event.is_set():
                fatal = self._check_runtime_health()
                if fatal:
                    self._fatal_error = fatal
                    self.request_stop(fatal)
                    break
                if deadline is not None and time.time() >= deadline:
                    self.request_stop(f"duration expired after {int(duration_value)} seconds")
                    break
                self.stop_event.wait(1.0)
        except KeyboardInterrupt:
            self.request_stop("keyboard interrupt received")
        finally:
            self.stop()
        if self._fatal_error:
            raise RuntimeError(self._fatal_error)

    def stop(self) -> None:
        with self._stop_lock:
            if self._stopped:
                return
            self._stopped = True
        self.stop_event.set()
        self.logger.log("Controller", "stopping runtime", reason=self._stop_reason or "normal shutdown")
        self.runtime.stop()
        self.template_server.stop()
        for thread in self.threads:
            thread.join(timeout=5)
        self.reaper.stop()
        self.logger.log("Controller", "runtime stopped", reason=self._stop_reason or "normal shutdown")

    def _managed_runtime_pids(self) -> set[int]:
        return self.runtime.managed_pids()

    def _start_threads(self) -> None:
        self.threads = []
        initial_seed_names = set(self._bootstrap_summary.get("initial_seed_names") or [])
        bootstrap_sync_seed_dir = str((self._bootstrap_summary or {}).get("sync_seed_dir", ""))
        bootstrap_sync_already_injected = bool((self._bootstrap_summary or {}).get("sync_injected_before_afl"))
        if self.config.enable_queue_watcher:
            watcher = QueueWatcher(
                config=self.config,
                state=self.state,
                runtime=self.runtime,
                injector=self.injector,
                replay_queue=self.replay_queue,
                logger=self.logger,
                stop_event=self.stop_event,
                bootstrap_sync_seed_dir=bootstrap_sync_seed_dir,
                initial_seed_names=initial_seed_names,
                bootstrap_sync_already_injected=bootstrap_sync_already_injected,
            )
            watcher.start()
            self.threads.append(watcher)
        if self.config.enable_coverage_replay:
            replay_worker = CoverageReplayWorker(
                worker_id=1,
                config=self.config,
                state=self.state,
                runtime=self.runtime,
                knowledge=self.knowledge,
                replay_queue=self.replay_queue,
                result_queue=self.coverage_result_queue,
                logger=self.logger,
                stop_event=self.stop_event,
            )
            replay_worker.start()
            self.threads.append(replay_worker)
        if self.config.enable_scheduler:
            scheduler = MutationScheduler(
                config=self.config,
                state=self.state,
                knowledge=self.knowledge,
                coverage_queue=self.coverage_result_queue,
                logger=self.logger,
                stop_event=self.stop_event,
            )
            scheduler.start()
            self.threads.append(scheduler)
        if self.config.enable_mutation:
            mutator = MutationWorker(
                config=self.config,
                state=self.state,
                knowledge=self.knowledge,
                injector=self.injector,
                replay_queue=self.replay_queue,
                flip_confirmation_queue=self.flip_confirmation_queue,
                logger=self.logger,
                stop_event=self.stop_event,
            )
            mutator.start()
            self.threads.append(mutator)

    def _start_aflnet_with_recovery(self) -> None:
        expected_seed_name, expected_seed_count = self._startup_seed_inventory()
        if expected_seed_count <= 0:
            raise RuntimeError(
                "afl input dir is empty before starting afl-fuzz; "
                f"baseline_seed_dir={self.config.resolved_baseline_seed_dir} "
                f"seed_delivery_mode={self.config.psei_seed_delivery_mode} "
                f"psei_output_dir={self.config.resolved_psei_output_dir}"
            )
        for attempt in range(max(_STARTUP_RETRY_LIMIT, _STARTUP_SEED_CANDIDATE_RETRY_LIMIT)):
            expected_seed_name, expected_seed_count = self._startup_seed_inventory()
            if expected_seed_count <= 0:
                raise RuntimeError("all afl input seeds were quarantined during startup recovery")
            stale = self.runtime.cleanup_stale_fuzzers()
            if stale:
                self.logger.log(
                    "Controller",
                    "removed stale subject processes before startup",
                    attempt=attempt,
                    count=len(stale),
                    pids=[item["pid"] for item in stale],
                )
            stdout_offset = self._log_offset("afl-fuzz", "stdout")
            stderr_offset = self._log_offset("afl-fuzz", "stderr")
            self.runtime.start()
            startup_status = self._wait_for_afl_startup_ready()
            if startup_status == "ready":
                self.logger.log(
                    "Controller",
                    "afl-fuzz process accepted as started",
                    expected_seed_count=expected_seed_count,
                    startup_policy="fuzzer-ready",
                    startup_attempt=attempt,
                )
                return

            details = self._collect_startup_failure_details(
                attempt,
                stdout_offset,
                stderr_offset,
                startup_status,
                expected_seed_name,
                expected_seed_count,
            )
            self.runtime.stop()
            recovered = self._recover_startup_seed_candidates(details)
            if recovered:
                details["recovered_seed_paths"] = recovered
            quarantined = self._quarantine_startup_seed(details)
            if quarantined:
                details["quarantined_seed_paths"] = quarantined
            self._write_startup_error_summary(details)
            retryable = details.get("failure_kind") in _STARTUP_RETRYABLE_FAILURE_KINDS
            attempt_limit = _STARTUP_SEED_CANDIDATE_RETRY_LIMIT if details.get("failure_kind") == "seed_candidate" else _STARTUP_RETRY_LIMIT
            if attempt + 1 >= attempt_limit or not retryable:
                raise RuntimeError(
                    "afl-fuzz exited during startup: "
                    f"kind={details.get('failure_kind')} "
                    f"reason={details.get('failure_reason')} "
                    f"seed={details.get('current_seed_name') or '-'} "
                    f"returncode={details.get('returncode')}"
                )
            self._reset_aflnet_output_for_retry(next_attempt=attempt + 1, details=details)

    def _reset_aflnet_output_for_retry(self, *, next_attempt: int, details: dict[str, Any]) -> None:
        sync_dir = self.config.resolved_afl_output_dir
        if sync_dir.exists():
            shutil.rmtree(sync_dir, ignore_errors=True)
        self.config.ensure_directories()
        self.injector._counter = 0
        injection_timing = self._bootstrap_sync_injection_timing()
        if injection_timing == "before-afl":
            self._inject_bootstrap_sync_seeds(phase="before-afl")
        else:
            self._bootstrap_summary["sync_injected"] = False
            self._bootstrap_summary["sync_injected_before_afl"] = False
            self._bootstrap_summary["bootstrap_sync_injection_timing"] = injection_timing
            self.logger.log("Controller", "bootstrap sync injection deferred on retry", timing=injection_timing)
        self.logger.log(
            "Controller",
            "retrying afl-fuzz startup after early exit",
            next_attempt=next_attempt,
            failure_kind=details.get("failure_kind", ""),
            current_seed_name=details.get("current_seed_name", ""),
            returncode=details.get("returncode"),
            afl_output_dir=str(sync_dir),
        )

    def _log_offset(self, prefix: str, stream: str) -> int:
        path = self.runtime.log_path(prefix, stream)
        if not path.exists():
            return 0
        return path.stat().st_size

    def _read_log_text_since(self, prefix: str, stream: str, offset: int) -> str:
        path = self.runtime.log_path(prefix, stream)
        if not path.exists():
            return ""
        with path.open("r", encoding="utf-8", errors="ignore") as fh:
            fh.seek(offset)
            return fh.read()

    def _startup_seed_inventory(self) -> tuple[str, int]:
        paths = [path for path in self.config.resolved_afl_input_dir.iterdir() if path.is_file()]
        if not paths:
            return "", 0
        newest = max(paths, key=lambda path: (path.stat().st_mtime_ns, path.name))
        return newest.name, len(paths)

    def _wait_for_afl_startup_ready(self) -> str:
        timeout_sec = max(float(getattr(self.config, "startup_ready_timeout_sec", 30) or 30), 1.0)
        deadline = time.time() + timeout_sec
        ready_since = 0.0
        while time.time() < deadline:
            if self.runtime.fuzzer_ready():
                if ready_since <= 0.0:
                    ready_since = time.time()
                elif time.time() - ready_since >= _STARTUP_READY_STABILIZE_SEC:
                    return "ready"
            else:
                ready_since = 0.0
            if not self.runtime.fuzzer_alive():
                return "process_exited"
            if (
                self.config.monitor_target_process
                and self.config.target_start_cmd
                and self.runtime.target_started()
                and not self.runtime.target_alive()
            ):
                return "target_exited"
            time.sleep(_STARTUP_READY_POLL_INTERVAL_SEC)
        if self.runtime.fuzzer_ready() and ready_since > 0.0 and time.time() - ready_since >= _STARTUP_READY_STABILIZE_SEC:
            return "ready"
        if not self.runtime.fuzzer_alive():
            return "process_exited"
        if (
            self.config.monitor_target_process
            and self.config.target_start_cmd
            and self.runtime.target_started()
            and not self.runtime.target_alive()
        ):
            return "target_exited"
        return "timeout"

    def _collect_startup_failure_details(
        self,
        attempt: int,
        stdout_offset: int,
        stderr_offset: int,
        failure_reason: str,
        expected_seed_name: str,
        expected_seed_count: int,
    ) -> dict:
        stderr_path = self.runtime.log_path("afl-fuzz", "stderr")
        stdout_path = self.runtime.log_path("afl-fuzz", "stdout")
        stderr_text = self._read_log_text_since("afl-fuzz", "stderr", stderr_offset)
        stdout_text = self._read_log_text_since("afl-fuzz", "stdout", stdout_offset)
        seed_names = self._extract_seed_names(stderr_text)
        if not seed_names:
            seed_names = self._extract_seed_names(stdout_text)
        current_seed_name = self._extract_current_seed_name(stderr_text) or self._extract_current_seed_name(stdout_text)
        failure_kind = self._classify_startup_failure(stderr_text, stdout_text, current_seed_name, failure_reason)
        details = {
            "attempt": attempt,
            "returncode": self.runtime.fuzzer_returncode(),
            "failure_reason": failure_reason,
            "failure_kind": failure_kind,
            "startup_expected_seed_name": expected_seed_name,
            "startup_expected_seed_count": expected_seed_count,
            "current_seed_name": current_seed_name,
            "recovery_seed_name": current_seed_name if failure_kind == "seed_candidate" else "",
            "stderr_path": str(stderr_path),
            "stdout_path": str(stdout_path),
            "stderr_text": stderr_text,
            "stdout_text": stdout_text,
            "matched_seed_count": len(seed_names),
            "matched_seed_names": seed_names[:32],
            "quarantined_seed_paths": [],
            "recovered_seed_paths": [],
        }
        self._append_startup_error_event(details)
        self.logger.log(
            "Controller",
            "afl-fuzz exited during startup",
            attempt=attempt,
            returncode=details["returncode"],
            failure_reason=failure_reason,
            failure_kind=failure_kind,
            startup_expected_seed_name=expected_seed_name,
            startup_expected_seed_count=expected_seed_count,
            current_seed_name=current_seed_name,
            matched_seed_count=len(seed_names),
        )
        return details

    def _extract_seed_names(self, text: str) -> list[str]:
        names: list[str] = []
        for match in _ORIG_PATTERN.findall(text or ""):
            name = Path(match).name.strip("'\" ,")
            if name and name not in names:
                names.append(name)
        for match in _RAW_PATTERN.findall(text or ""):
            name = Path(match).name.strip("'\" ,")
            if name and name not in names:
                names.append(name)
        return names

    def _extract_current_seed_name(self, text: str) -> str:
        matches = _DRY_RUN_PATTERN.findall(text or "")
        if not matches:
            return ""
        return Path(matches[-1]).name.strip("'\" ,")

    def _classify_startup_failure(
        self,
        stderr_text: str,
        stdout_text: str,
        current_seed_name: str,
        failure_reason: str,
    ) -> str:
        if failure_reason == "timeout":
            return "timeout"
        combined = f"{stderr_text}\n{stdout_text}".lower()
        if failure_reason == "target_exited":
            return "environmental"
        if any(marker in combined for marker in _PRE_INPUT_CRASH_MARKERS):
            return "forkserver_lost"
        if any(marker in combined for marker in _FORKSERVER_LOST_MARKERS):
            return "forkserver_lost"
        if any(marker in combined for marker in _ENVIRONMENTAL_STARTUP_MARKERS):
            return "environmental"
        if current_seed_name:
            return "seed_candidate"
        return "unknown"

    def _recover_startup_seed_candidates(self, details: dict[str, Any]) -> list[str]:
        if details.get("failure_kind") != "seed_candidate":
            return []
        if int(details.get("startup_expected_seed_count") or 0) > 1:
            return []
        delivery_mode = str(getattr(self.config, "psei_seed_delivery_mode", "afl-input") or "afl-input").strip().lower()
        if delivery_mode != "sync":
            return []
        sync_seed_dir = Path(str((self._bootstrap_summary or {}).get("sync_seed_dir", "")).strip())
        if not sync_seed_dir.exists() or not sync_seed_dir.is_dir():
            return []

        seed_name = str(details.get("current_seed_name") or "").strip()
        staged_paths: list[str] = []
        excluded_names = startup_quarantined_seed_names(self.config)
        if seed_name:
            excluded_names.add(seed_name)
            seed_path = self.config.resolved_afl_input_dir / seed_name
            if seed_path.exists() and seed_path.is_file():
                staged_path = quarantine_seed_file(
                    self.config,
                    seed_path,
                    reason="startup_quarantine",
                    logger=self.logger,
                    metadata={
                        "returncode": details.get("returncode"),
                        "failure_reason": details.get("failure_reason", ""),
                        "failure_kind": details.get("failure_kind", ""),
                        "stderr_excerpt": details.get("stderr_text", "")[-2000:],
                        "stdout_excerpt": details.get("stdout_text", "")[-2000:],
                        "startup_sync_recovery": True,
                    },
                )
                staged_paths.append(str(staged_path))

        recovered_paths: list[str] = []
        rejected_count = 0
        for candidate in sorted(sync_seed_dir.iterdir()):
            if len(recovered_paths) >= _STARTUP_SYNC_RECOVERY_COPY_LIMIT:
                break
            if not candidate.is_file():
                continue
            if candidate.name in excluded_names:
                continue
            dst = self.config.resolved_afl_input_dir / candidate.name
            if dst.exists():
                continue
            ok, payload = startup_seed_preflight_ok(self.config, candidate)
            if not ok:
                rejected_count += 1
                excluded_names.add(candidate.name)
                quarantine_seed_file(
                    self.config,
                    candidate,
                    reason="startup_quarantine",
                    logger=self.logger,
                    metadata={
                        "server_rc": int(payload.get("server_rc", -1)),
                        "replay_rc": int(payload.get("replay_rc", payload.get("command_returncode", -1))),
                        "stdout": str(payload.get("stdout", ""))[-2000:],
                        "stderr": str(payload.get("stderr", ""))[-2000:],
                        "startup_sync_recovery": True,
                        "preflight_candidate": True,
                    },
                    copy_only=True,
                )
                continue
            shutil.copy2(candidate, dst)
            recovered_paths.append(str(dst))

        if recovered_paths or rejected_count:
            self.logger.log(
                "Controller",
                "recovered startup afl-input corpus from sync seeds",
                crashed_seed=seed_name,
                staged_count=len(staged_paths),
                recovered_count=len(recovered_paths),
                rejected_count=rejected_count,
                sync_seed_dir=str(sync_seed_dir),
                copy_limit=_STARTUP_SYNC_RECOVERY_COPY_LIMIT,
            )
        return staged_paths + recovered_paths

    def _append_startup_error_event(self, details: dict) -> None:
        path = self.config.resolved_psei_output_dir / "startup_error_events.jsonl"
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(details, ensure_ascii=False) + "\n")

    def _quarantine_startup_seed(self, details: dict[str, Any]) -> list[str]:
        if details.get("failure_kind") != "seed_candidate":
            return []
        seed_name = str(details.get("current_seed_name") or "").strip()
        if not seed_name:
            return []
        if int(details.get("startup_expected_seed_count") or 0) <= 1:
            self.logger.log(
                "Controller",
                "skipping startup seed quarantine for singleton corpus",
                seed=seed_name,
                failure_kind=details.get("failure_kind", ""),
            )
            return []
        seed_path = self.config.resolved_afl_input_dir / seed_name
        if not seed_path.exists() or not seed_path.is_file():
            return []
        staged_path = quarantine_seed_file(
            self.config,
            seed_path,
            reason="startup_quarantine",
            logger=self.logger,
            metadata={
                "returncode": details.get("returncode"),
                "failure_reason": details.get("failure_reason", ""),
                "failure_kind": details.get("failure_kind", ""),
                "stderr_excerpt": details.get("stderr_text", "")[-2000:],
                "stdout_excerpt": details.get("stdout_text", "")[-2000:],
            },
        )
        return [str(staged_path)]

    def _write_startup_error_summary(self, details: dict) -> None:
        summary = {
            "attempt": details.get("attempt"),
            "returncode": details.get("returncode"),
            "failure_reason": details.get("failure_reason", ""),
            "failure_kind": details.get("failure_kind", ""),
            "startup_expected_seed_name": details.get("startup_expected_seed_name", ""),
            "startup_expected_seed_count": details.get("startup_expected_seed_count", 0),
            "current_seed_name": details.get("current_seed_name", ""),
            "recovery_seed_name": details.get("recovery_seed_name", ""),
            "matched_seed_count": details.get("matched_seed_count", 0),
            "matched_seed_names": details.get("matched_seed_names", []),
            "quarantined_seed_paths": details.get("quarantined_seed_paths", []),
            "recovered_seed_paths": details.get("recovered_seed_paths", []),
            "stderr_path": details.get("stderr_path", ""),
            "stdout_path": details.get("stdout_path", ""),
            "stderr_excerpt": details.get("stderr_text", "")[-2000:],
            "stdout_excerpt": details.get("stdout_text", "")[-2000:],
        }
        path = self.config.resolved_psei_output_dir / "startup_error_summary.json"
        path.write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    def _check_runtime_health(self) -> str | None:
        import_health_error = self._check_import_health_gate()
        if import_health_error:
            return import_health_error
        if self.runtime.fuzzer_started() and not self.runtime.fuzzer_alive():
            return f"afl-fuzz exited unexpectedly (returncode={self.runtime.fuzzer_returncode()})"
        if (
            self.config.monitor_target_process
            and self.config.target_start_cmd
            and self.runtime.target_started()
            and not self.runtime.target_alive()
        ):
            return f"target process exited unexpectedly (returncode={self.runtime.target_returncode()})"
        return None

    def _check_import_health_gate(self) -> str | None:
        if not bool(getattr(self.config, "import_health_check_enabled", True)):
            return None
        if self._import_health_checked or self._started_at is None:
            return None
        window_sec = max(float(getattr(self.config, "import_health_check_window_sec", 300) or 300), 1.0)
        if time.time() - self._started_at < window_sec:
            return None
        stats = self.runtime.parse_fuzzer_stats()
        try:
            paths_imported = int(str(stats.get("paths_imported", "0") or "0").strip() or "0")
        except ValueError:
            paths_imported = 0
        try:
            cycles_done = int(str(stats.get("cycles_done", "0") or "0").strip() or "0")
        except ValueError:
            cycles_done = 0
        try:
            cur_path = int(str(stats.get("cur_path", "0") or "0").strip() or "0")
        except ValueError:
            cur_path = 0
        try:
            execs_done = int(str(stats.get("execs_done", "0") or "0").strip() or "0")
        except ValueError:
            execs_done = 0
        queue_dir = self.config.resolved_fuzzer_out_dir / "queue"
        sync_queue_count = 0
        if queue_dir.exists():
            try:
                sync_queue_count = sum(1 for path in queue_dir.iterdir() if path.is_file() and f"sync:{self.config.afl_sync_partner_id}" in path.name)
            except OSError:
                sync_queue_count = 0
        synced_cursor = self.config.resolved_fuzzer_out_dir / ".synced" / self.config.afl_sync_partner_id
        synced_exists = synced_cursor.exists()
        synced_cursor_value = self._read_sync_cursor_value(synced_cursor)
        sync_cursor_progress = synced_cursor_value > 0
        min_imported = max(int(getattr(self.config, "import_health_min_paths_imported", 1) or 1), 0)
        require_synced = bool(getattr(self.config, "import_health_require_synced_cursor", True))
        effective_imported = max(paths_imported, sync_queue_count)
        sync_opportunity_reached = bool(sync_cursor_progress or effective_imported > 0 or cycles_done > 0)
        if not sync_opportunity_reached:
            self.state.update_metric(
                "import_health",
                {
                    "status": "observing",
                    "checked_at": time.time(),
                    "window_sec": window_sec,
                    "paths_imported": paths_imported,
                    "effective_paths_imported": effective_imported,
                    "sync_queue_count": sync_queue_count,
                    "synced_cursor_exists": synced_exists,
                    "synced_cursor_value": synced_cursor_value,
                    "partner_id": self.config.afl_sync_partner_id,
                    "degraded": False,
                    "min_paths_imported": min_imported,
                    "require_synced_cursor": require_synced,
                    "sync_opportunity_reached": False,
                    "cycles_done": cycles_done,
                    "cur_path": cur_path,
                    "execs_done": execs_done,
                },
            )
            self.logger.log(
                "Controller",
                "import health still observing before first sync opportunity",
                paths_imported=paths_imported,
                effective_paths_imported=effective_imported,
                sync_queue_count=sync_queue_count,
                synced_cursor_exists=synced_exists,
                synced_cursor_value=synced_cursor_value,
                cycles_done=cycles_done,
                cur_path=cur_path,
                execs_done=execs_done,
                partner_id=self.config.afl_sync_partner_id,
                window_sec=window_sec,
            )
            return None
        self._import_health_checked = True
        degraded = effective_imported < min_imported or (require_synced and not sync_cursor_progress and effective_imported <= 0)
        payload = {
            "status": "degraded" if degraded else "healthy",
            "checked_at": time.time(),
            "window_sec": window_sec,
            "paths_imported": paths_imported,
            "effective_paths_imported": effective_imported,
            "sync_queue_count": sync_queue_count,
            "synced_cursor_exists": synced_exists,
            "synced_cursor_value": synced_cursor_value,
            "partner_id": self.config.afl_sync_partner_id,
            "degraded": degraded,
            "min_paths_imported": min_imported,
            "require_synced_cursor": require_synced,
            "sync_opportunity_reached": True,
            "cycles_done": cycles_done,
            "cur_path": cur_path,
            "execs_done": execs_done,
        }
        self.state.update_metric("import_health", payload)
        self.state.record_event(
            kind="import_health_check",
            subject=self.config.subject,
            protocol=self.config.protocol,
            payload=payload,
        )
        if degraded:
            self.logger.log(
                "Controller",
                "import health degraded",
                paths_imported=paths_imported,
                effective_paths_imported=effective_imported,
                sync_queue_count=sync_queue_count,
                synced_cursor_exists=synced_exists,
                synced_cursor_value=synced_cursor_value,
                execs_done=execs_done,
                partner_id=self.config.afl_sync_partner_id,
                window_sec=window_sec,
            )
            return f"import health degraded (paths_imported={paths_imported}, synced_cursor={synced_exists})"
        self.logger.log(
            "Controller",
            "import health healthy",
            paths_imported=paths_imported,
            effective_paths_imported=effective_imported,
            sync_queue_count=sync_queue_count,
            synced_cursor_exists=synced_exists,
            synced_cursor_value=synced_cursor_value,
            execs_done=execs_done,
            partner_id=self.config.afl_sync_partner_id,
            window_sec=window_sec,
        )
        return None

    @staticmethod
    def _read_sync_cursor_value(path: Path) -> int:
        if not path.exists():
            return 0
        try:
            raw = path.read_bytes()
        except OSError:
            return 0
        if not raw:
            return 0
        stripped = raw.strip(b"\x00\r\n\t ")
        if stripped:
            try:
                return int(stripped.decode("ascii", errors="strict"))
            except (UnicodeDecodeError, ValueError):
                pass
        if set(raw) == {0}:
            return 0
        width = min(len(raw), 8)
        return int.from_bytes(raw[:width], byteorder="little", signed=False)

    def _llm_usage_module_summary(self, module: str) -> dict[str, int]:
        keys = ("calls", "input_tokens", "output_tokens", "reasoning_tokens", "total_tokens")
        payload: dict[str, int] = {}
        for key in keys:
            value = self.state.get_metric(f"llm_usage.{module}.{key}", 0)
            try:
                payload[key] = int(value or 0)
            except (TypeError, ValueError):
                payload[key] = 0
        return payload

    def dump_runtime_summary(self, path: str | Path, *, extra: dict[str, Any] | None = None) -> dict[str, Any]:
        llm_usage_summary = {
            "psei": self._llm_usage_module_summary("psei"),
            "boundary": self._llm_usage_module_summary("boundary"),
            "vuln": self._llm_usage_module_summary("vuln"),
        }
        llm_usage_summary["total"] = {
            key: llm_usage_summary["psei"].get(key, 0) + llm_usage_summary["boundary"].get(key, 0) + llm_usage_summary["vuln"].get(key, 0)
            for key in ("calls", "input_tokens", "output_tokens", "reasoning_tokens", "total_tokens")
        }
        summary = {
            "implementation": self.config.implementation,
            "protocol": self.config.protocol,
            "subject": self.config.subject,
            "run_tag": self.config.run_tag,
            "started_at": self._started_at,
            "stop_reason": self._stop_reason,
            "fatal_error": self._fatal_error,
            "stop_requested": self.stop_event.is_set(),
            "afl_fuzz_started": self.runtime.fuzzer_started(),
            "afl_fuzz_alive": self.runtime.fuzzer_alive(),
            "afl_fuzz_returncode": self.runtime.fuzzer_returncode(),
            "target_started": self.runtime.target_started(),
            "target_alive": self.runtime.target_alive(),
            "target_returncode": self.runtime.target_returncode(),
            "state_db": str(self.state.db_path),
            "psei_output_dir": str(self.config.resolved_psei_output_dir),
            "afl_input_dir": str(self.config.resolved_afl_input_dir),
            "afl_output_dir": str(self.config.resolved_afl_output_dir),
            "fuzzer_out_dir": str(self.config.resolved_fuzzer_out_dir),
            "sync_partner_queue": str(self.config.resolved_afl_output_dir / self.config.afl_sync_partner_id / "queue"),
            "state_dir": str(self.config.resolved_state_dir),
            "log_dir": str(self.config.resolved_log_dir),
            "temp_dir": str(self.config.resolved_temp_dir),
            "experiment_label": self.config.experiment_label,
            "llm_usage_summary": llm_usage_summary,
            "import_health": self.state.get_metric("import_health", {}) or {},
            "replay_health": self.state.get_metric("replay_health", {}) or {},
            "module_toggles": {
                "enable_bootstrap": bool(self.config.enable_bootstrap),
                "enable_queue_watcher": bool(self.config.enable_queue_watcher),
                "enable_coverage_replay": bool(self.config.enable_coverage_replay),
                "enable_scheduler": bool(self.config.enable_scheduler),
                "enable_mutation": bool(self.config.enable_mutation),
                "enable_boundary_tasks": bool(self.config.enable_boundary_tasks),
                "enable_vuln_tasks": bool(self.config.enable_vuln_tasks),
            },
        }
        if extra:
            summary.update(extra)
        summary["summary_pid"] = self.runtime._fuzzer_proc.pid if self.runtime._fuzzer_proc else None
        summary["heartbeat_at"] = time.time()
        output_path = Path(path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        return summary
