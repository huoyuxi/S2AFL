"""Run the workflow2 replay worker against a watched seed directory only."""

from __future__ import annotations

import queue
import threading
import time
from pathlib import Path

from .config import RuntimeConfig
from .coverage_replay import CoverageReplayWorker
from .knowledge_loader import RuntimeKnowledge
from .logging_utils import RuntimeLogger
from .models import CoverageReplayResult, SeedRecord
from .seed_utils import body_sha1, load_seed_file, message_method, split_seed_messages
from .state_db import RuntimeStateDB


class SeedDirectoryWatcher(threading.Thread):
    """Watch a directory and enqueue every existing/new seed file once."""

    daemon = True

    def __init__(
        self,
        *,
        config: RuntimeConfig,
        state: RuntimeStateDB,
        watch_dir: Path,
        replay_queue: "queue.Queue[SeedRecord]",
        logger: RuntimeLogger,
        stop_event: threading.Event,
        poll_interval_sec: float,
    ):
        super().__init__(name="SeedDirectoryWatcher")
        self.config = config
        self.state = state
        self.watch_dir = watch_dir
        self.replay_queue = replay_queue
        self.logger = logger
        self.stop_event = stop_event
        self.poll_interval_sec = poll_interval_sec
        self._known_paths: set[str] = set()

    def run(self) -> None:
        self.logger.log("ReplayWatch", "seed directory watcher started", watch_dir=str(self.watch_dir))
        while not self.stop_event.is_set():
            self._scan_once()
            self.stop_event.wait(self.poll_interval_sec)

    def _scan_once(self) -> None:
        if not self.watch_dir.exists():
            return
        for path in sorted(self.watch_dir.iterdir()):
            if not path.is_file():
                continue
            if path.name.startswith('.'):
                continue
            key = str(path)
            if key in self._known_paths:
                continue
            try:
                size = path.stat().st_size
            except OSError:
                continue
            if size <= 0:
                continue

            raw = load_seed_file(path)
            messages = split_seed_messages(self.config.protocol, raw)
            methods = [message_method(msg) for msg in messages if message_method(msg)]
            seed = SeedRecord(
                seed_id=body_sha1(raw),
                queue_path=str(path),
                origin=path.name,
                protocol=self.config.protocol,
                subject=self.config.subject,
                methods=methods,
                message_count=len(messages),
                body_sha1=body_sha1(raw),
                size_bytes=size,
                first_seen_at=time.time(),
                metadata={"watched_path": str(path), "watch_dir": str(self.watch_dir)},
            )
            self.state.upsert_seed(seed)
            self.state.record_event(
                kind="watched_seed_discovered",
                subject=self.config.subject,
                protocol=self.config.protocol,
                seed_id=seed.seed_id,
                payload={
                    "seed_id": seed.seed_id,
                    "queue_path": seed.queue_path,
                    "origin": seed.origin,
                    "methods": seed.methods,
                    "message_count": seed.message_count,
                    "watch_dir": str(self.watch_dir),
                },
            )
            self.replay_queue.put(seed)
            self._known_paths.add(key)
            self.logger.log(
                "ReplayWatch",
                "new watched seed discovered",
                seed_id=seed.seed_id,
                origin=seed.origin,
                methods=",".join(seed.methods),
                queue_path=str(path),
            )


class ReplayResultCollector(threading.Thread):
    """Drain replay results so the queue stays bounded and logs stay visible."""

    daemon = True

    def __init__(
        self,
        *,
        result_queue: "queue.Queue[CoverageReplayResult]",
        logger: RuntimeLogger,
        stop_event: threading.Event,
    ):
        super().__init__(name="ReplayResultCollector")
        self.result_queue = result_queue
        self.logger = logger
        self.stop_event = stop_event

    def run(self) -> None:
        self.logger.log("ReplayWatch", "replay result collector started")
        while not self.stop_event.is_set():
            try:
                result = self.result_queue.get(timeout=0.2)
            except queue.Empty:
                continue
            self.logger.log(
                "ReplayWatch",
                "seed replay result",
                seed_id=result.seed_id,
                accepted=result.accepted,
                reason=result.reason,
                seed_total_lines=result.seed_total_lines,
                seed_total_branches=result.seed_total_branches,
                message_count=len(result.message_deltas),
            )
            self.result_queue.task_done()


class ReplayMonitorController:
    """Run only the watched-dir -> replay worker pipeline, without AFLNet/C/D."""

    def __init__(
        self,
        config: RuntimeConfig,
        *,
        watch_dir: str | Path | None = None,
        poll_interval_sec: float | None = None,
    ):
        self.config = config
        self.config.ensure_directories()
        self.logger = RuntimeLogger(self.config.resolved_log_dir)
        self.state = RuntimeStateDB(self.config.resolved_state_dir / 'runtime_state.sqlite3')
        self.knowledge = RuntimeKnowledge(
            implementation=self.config.implementation,
            protocol=self.config.protocol,
            templates_file=self.config.resolved_templates_file,
        )
        self.knowledge.load()
        if watch_dir is None:
            resolved_watch_dir = self.config.resolved_afl_input_dir
        else:
            watch_path = Path(watch_dir)
            resolved_watch_dir = watch_path if watch_path.is_absolute() else self.config.resolve(str(watch_path))
        self.watch_dir = resolved_watch_dir
        self.poll_interval_sec = float(poll_interval_sec or self.config.queue_scan_interval_sec)
        self.stop_event = threading.Event()
        self.replay_queue: queue.Queue[SeedRecord] = queue.Queue()
        self.result_queue: queue.Queue[CoverageReplayResult] = queue.Queue()
        self.threads: list[threading.Thread] = []

    def start(self) -> None:
        self.watch_dir.mkdir(parents=True, exist_ok=True)
        watcher = SeedDirectoryWatcher(
            config=self.config,
            state=self.state,
            watch_dir=self.watch_dir,
            replay_queue=self.replay_queue,
            logger=self.logger,
            stop_event=self.stop_event,
            poll_interval_sec=self.poll_interval_sec,
        )
        self.threads.append(watcher)

        for worker_id in range(max(int(self.config.replay_parallelism), 1)):
            worker = CoverageReplayWorker(
                worker_id=worker_id,
                config=self.config,
                state=self.state,
                knowledge=self.knowledge,
                replay_queue=self.replay_queue,
                result_queue=self.result_queue,
                logger=self.logger,
                stop_event=self.stop_event,
            )
            self.threads.append(worker)

        collector = ReplayResultCollector(
            result_queue=self.result_queue,
            logger=self.logger,
            stop_event=self.stop_event,
        )
        self.threads.append(collector)

        for thread in self.threads:
            thread.start()
        self.logger.log(
            "ReplayWatch",
            "replay monitor started",
            watch_dir=str(self.watch_dir),
            replay_parallelism=max(int(self.config.replay_parallelism), 1),
            poll_interval_sec=self.poll_interval_sec,
        )

    def run_forever(self) -> None:
        self.start()
        try:
            while not self.stop_event.is_set():
                self.stop_event.wait(1.0)
        except KeyboardInterrupt:
            self.logger.log("ReplayWatch", "keyboard interrupt received")
        finally:
            self.stop()

    def stop(self) -> None:
        if self.stop_event.is_set():
            return
        self.stop_event.set()
        self.logger.log("ReplayWatch", "stopping replay monitor")
        for thread in self.threads:
            thread.join(timeout=5)
        self.logger.log("ReplayWatch", "replay monitor stopped")
