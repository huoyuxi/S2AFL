"""Thread A: monitor AFLNet queue changes and fuzzing progress."""

from __future__ import annotations

import json
import queue
import re
import shutil
import threading
import time
from pathlib import Path

from .aflnet import AFLNetRuntime, AFLNetSyncInjector
from .config import RuntimeConfig
from .logging_utils import RuntimeLogger
from .models import SeedRecord
from .seed_utils import body_sha1, load_seed_file, message_method, split_seed_messages
from .state_db import RuntimeStateDB
from .psei_bootstrap import startup_quarantined_seed_names


def inject_bootstrap_sync_seeds(
    *,
    config: RuntimeConfig,
    state: RuntimeStateDB,
    injector: AFLNetSyncInjector,
    logger: RuntimeLogger,
    bootstrap_sync_seed_dir: str,
    seed_limit: int = 0,
) -> dict[str, object]:
    """Inject bootstrap seeds into `agent-sync/queue` for immediate AFL import."""
    mode = str(getattr(config, "psei_seed_delivery_mode", "afl-input") or "afl-input").strip().lower()
    if mode != "sync":
        return {"count": 0, "failed_count": 0, "dir": "", "seed_ids": [], "skipped": True, "reason": "delivery-mode"}
    if not bootstrap_sync_seed_dir:
        logger.log("A", "bootstrap sync seed dir missing", sync_seed_dir="")
        return {"count": 0, "failed_count": 0, "dir": "", "seed_ids": [], "skipped": True, "reason": "missing-dir"}

    sync_seed_dir = Path(bootstrap_sync_seed_dir)
    if not sync_seed_dir.exists():
        logger.log("A", "bootstrap sync seed dir missing", sync_seed_dir=str(sync_seed_dir))
        return {
            "count": 0,
            "failed_count": 0,
            "dir": str(sync_seed_dir),
            "seed_ids": [],
            "skipped": True,
            "reason": "missing-path",
        }

    excluded_names = startup_quarantined_seed_names(config)
    injected = 0
    failed = 0
    skipped_quarantined = 0
    discovered_seed_ids: list[str] = []
    for seed_path in sorted(sync_seed_dir.iterdir()):
        if seed_limit > 0 and injected >= seed_limit:
            break
        if not seed_path.is_file():
            continue
        if seed_path.name in excluded_names:
            skipped_quarantined += 1
            continue
        try:
            raw_seed = load_seed_file(seed_path)
            injected_path = injector.inject_seed(raw_seed, origin_tag=seed_path.name)
            injected += 1
            seed_id = body_sha1(raw_seed)
            discovered_seed_ids.append(seed_id)
            messages = split_seed_messages(config.protocol, raw_seed)
            methods = [message_method(msg) for msg in messages if message_method(msg)]
            seed = SeedRecord(
                seed_id=seed_id,
                queue_path=str(injected_path),
                origin=seed_path.name,
                protocol=config.protocol,
                subject=config.subject,
                methods=methods,
                message_count=len(messages),
                body_sha1=seed_id,
                size_bytes=len(raw_seed.encode("latin-1", errors="replace")),
                first_seen_at=time.time(),
                metadata={
                    "queue_name": injected_path.name,
                    "source": "bootstrap_sync_injector",
                    "agent_seed_discovered": True,
                    "agent_seed_discovered_at": time.time(),
                    "agent_seed_queue_name": injected_path.name,
                    "agent_seed_queue_path": str(injected_path),
                    "agent_seed_partner": config.afl_sync_partner_id,
                    "bootstrap_sync_preinjected": True,
                },
            )
            state.upsert_seed(seed)
        except Exception as exc:
            failed += 1
            logger.log(
                "A",
                "bootstrap sync seed injection failed",
                seed_path=str(seed_path),
                error=repr(exc),
            )

    summary = {
        "count": injected,
        "failed_count": failed,
        "skipped_quarantined_count": skipped_quarantined,
        "dir": str(sync_seed_dir),
        "seed_ids": discovered_seed_ids,
        "skipped": False,
    }
    state.update_metric("bootstrap_sync_seed_injected", summary)
    logger.log(
        "A",
        "bootstrap sync seeds injected",
        count=injected,
        failed_count=failed,
        skipped_quarantined_count=skipped_quarantined,
        sync_seed_dir=str(sync_seed_dir),
    )
    return summary


def inject_async_staged_seeds(
    *,
    config: RuntimeConfig,
    state: RuntimeStateDB,
    injector: AFLNetSyncInjector,
    logger: RuntimeLogger,
    async_seed_dir: str,
    async_injected_dir: str,
    batch_size: int,
) -> dict[str, object]:
    mode = str(getattr(config, "psei_seed_delivery_mode", "afl-input") or "afl-input").strip().lower()
    if mode != "async":
        return {"count": 0, "failed_count": 0, "dir": "", "seed_ids": [], "skipped": True, "reason": "delivery-mode"}
    pending_dir = Path(async_seed_dir)
    if not async_seed_dir or not pending_dir.exists():
        return {"count": 0, "failed_count": 0, "dir": str(pending_dir), "seed_ids": [], "skipped": True, "reason": "missing-path"}
    injected_dir = Path(async_injected_dir)
    injected_dir.mkdir(parents=True, exist_ok=True)
    excluded_names = startup_quarantined_seed_names(config)
    injected = 0
    failed = 0
    seed_ids: list[str] = []
    limit = max(int(batch_size or 0), 1)
    for seed_path in sorted(pending_dir.iterdir()):
        if injected >= limit:
            break
        if not seed_path.is_file() or seed_path.name in excluded_names:
            continue
        try:
            raw_seed = load_seed_file(seed_path)
            injected_path = injector.inject_seed(raw_seed, origin_tag=seed_path.name)
            seed_id = body_sha1(raw_seed)
            seed_ids.append(seed_id)
            messages = split_seed_messages(config.protocol, raw_seed)
            methods = [message_method(msg) for msg in messages if message_method(msg)]
            seed = SeedRecord(
                seed_id=seed_id,
                queue_path=str(injected_path),
                origin=seed_path.name,
                protocol=config.protocol,
                subject=config.subject,
                methods=methods,
                message_count=len(messages),
                body_sha1=seed_id,
                size_bytes=len(raw_seed.encode("latin-1", errors="replace")),
                first_seen_at=time.time(),
                metadata={
                    "queue_name": injected_path.name,
                    "source": "psei_async_injector",
                    "agent_seed_discovered": True,
                    "agent_seed_discovered_at": time.time(),
                    "agent_seed_queue_name": injected_path.name,
                    "agent_seed_queue_path": str(injected_path),
                    "agent_seed_partner": config.afl_sync_partner_id,
                    "psei_async_injected": True,
                    "psei_async_source_name": seed_path.name,
                },
            )
            state.upsert_seed(seed)
            shutil.move(str(seed_path), str(injected_dir / seed_path.name))
            injected += 1
        except Exception as exc:
            failed += 1
            logger.log("A", "psei async seed injection failed", seed_path=str(seed_path), error=repr(exc))

    summary = {
        "count": injected,
        "failed_count": failed,
        "dir": str(pending_dir),
        "injected_dir": str(injected_dir),
        "seed_ids": seed_ids,
        "skipped": False,
    }
    state.update_metric("psei_async_seed_injected", summary)
    if injected or failed:
        logger.log(
            "A",
            "psei async seeds injected",
            count=injected,
            failed_count=failed,
            async_seed_dir=str(pending_dir),
            injected_dir=str(injected_dir),
            batch_size=limit,
        )
    return summary

class QueueWatcher(threading.Thread):
    """Thread A: monitor queue changes and bitmap progress."""

    daemon = True

    def __init__(
        self,
        *,
        config: RuntimeConfig,
        state: RuntimeStateDB,
        runtime: AFLNetRuntime,
        injector: AFLNetSyncInjector,
        replay_queue: "queue.Queue[SeedRecord]",
        logger: RuntimeLogger,
        stop_event: threading.Event,
        bootstrap_sync_seed_dir: str = "",
        initial_seed_names: set[str] | None = None,
        bootstrap_sync_already_injected: bool = False,
    ):
        super().__init__(name="QueueWatcher")
        self.config = config
        self.state = state
        self.runtime = runtime
        self.injector = injector
        self.replay_queue = replay_queue
        self.logger = logger
        self.stop_event = stop_event
        self.bootstrap_sync_seed_dir = str(bootstrap_sync_seed_dir or "")
        self.initial_seed_names = set(initial_seed_names or set())
        self.bootstrap_sync_already_injected = bool(bootstrap_sync_already_injected)
        self._known_paths: set[str] = set()
        self._last_metrics_poll = 0.0
        self._last_bitmap_signature = ("", "")
        self._import_health_initialized = False
        self._async_seed_dir = str(getattr(self.config, "resolved_psei_async_seed_dir", "") or "")
        self._async_injected_dir = str(getattr(self.config, "resolved_psei_async_injected_dir", "") or "")
        self._last_async_inject_at = 0.0
        self._async_started_at = time.time()

    def run(self) -> None:
        self.logger.log("A", "queue watcher started")
        if not self.bootstrap_sync_already_injected:
            self._inject_bootstrap_sync_seeds_once()
        self._initialize_import_health_metrics()
        while not self.stop_event.is_set():
            self._scan_queue()
            self._scan_faults()
            self._maybe_inject_async_seeds()
            self._poll_metrics()
            self.stop_event.wait(self.config.queue_scan_interval_sec)

    def _queue_dir(self) -> Path:
        return self.config.resolved_fuzzer_out_dir / "queue"

    def _fault_dir_specs(self) -> list[tuple[str, str, Path]]:
        return [
            ("crash", "replayable", self.config.resolved_replayable_crashes_dir),
            ("hang", "replayable", self.config.resolved_replayable_hangs_dir),
            ("crash", "standard", self.config.resolved_fuzzer_crashes_dir),
            ("hang", "standard", self.config.resolved_fuzzer_hangs_dir),
        ]

    def _existing_seed_metadata(self, seed_id: str) -> dict:
        row = self.state.get_seed_row(seed_id)
        if not row:
            return {}
        raw = row.get("metadata_json") or "{}"
        if isinstance(raw, dict):
            return dict(raw)
        try:
            parsed = json.loads(raw)
        except Exception:
            return {}
        return dict(parsed) if isinstance(parsed, dict) else {}

    @staticmethod
    def _seed_row_metadata(row: dict[str, object] | None) -> dict:
        if not row:
            return {}
        raw = row.get("metadata_json") or "{}"
        if isinstance(raw, dict):
            return dict(raw)
        try:
            parsed = json.loads(raw)
        except Exception:
            return {}
        return dict(parsed) if isinstance(parsed, dict) else {}

    @staticmethod
    def _parse_afl_filename(name: str) -> dict[str, object]:
        info: dict[str, object] = {"id": "", "orig": "", "src_ids": [], "attrs": {}}
        for part in [item.strip() for item in str(name or "").split(",") if item.strip()]:
            if ":" not in part:
                continue
            key, value = part.split(":", 1)
            if key == "id":
                info["id"] = value
            elif key == "orig":
                info["orig"] = value
            elif key == "src":
                src_ids: list[str] = []
                for token in re.split(r"[^0-9]+", value):
                    token = token.strip()
                    if re.fullmatch(r"\d{6}", token) and token not in src_ids:
                        src_ids.append(token)
                info["src_ids"] = src_ids
            else:
                attrs = dict(info.get("attrs") or {})
                attrs[key] = value
                info["attrs"] = attrs
        return info

    def _resolve_fault_ancestry(self, queue_name: str) -> dict[str, object]:
        parsed = self._parse_afl_filename(queue_name)
        matched_rows: list[dict[str, object]] = []
        seen_seed_ids: set[str] = set()

        def _add_rows(rows: list[dict[str, object]]) -> None:
            for row in rows:
                seed_id = str(row.get("seed_id") or "").strip()
                if not seed_id or seed_id in seen_seed_ids:
                    continue
                seen_seed_ids.add(seed_id)
                matched_rows.append(row)

        for src_id in list(parsed.get("src_ids") or []):
            _add_rows(self.state.find_seed_rows_by_queue_token(f"id:{src_id}"))
        orig_name = str(parsed.get("orig") or "").strip()
        if orig_name:
            _add_rows(self.state.find_seed_rows_by_origin(orig_name))

        parent_seed_ids: list[str] = []
        parent_task_ids: list[str] = []
        parent_target_ids: list[str] = []
        parent_origins: list[str] = []
        parent_queue_names: list[str] = []
        for row in matched_rows:
            seed_id = str(row.get("seed_id") or "").strip()
            origin = str(row.get("origin") or "").strip()
            meta = self._seed_row_metadata(row)
            task_id = str(meta.get("task_id") or "").strip()
            target_id = str(meta.get("target_id") or "").strip()
            queue_name = str(meta.get("queue_name") or "").strip()
            if seed_id and seed_id not in parent_seed_ids:
                parent_seed_ids.append(seed_id)
            if task_id and task_id not in parent_task_ids:
                parent_task_ids.append(task_id)
            if target_id and target_id not in parent_target_ids:
                parent_target_ids.append(target_id)
            if origin and origin not in parent_origins:
                parent_origins.append(origin)
            if queue_name and queue_name not in parent_queue_names:
                parent_queue_names.append(queue_name)

        return {
            "fault_src_queue_ids": list(parsed.get("src_ids") or []),
            "fault_orig_name": orig_name,
            "fault_parent_seed_ids": parent_seed_ids,
            "fault_parent_task_ids": parent_task_ids,
            "fault_parent_target_ids": parent_target_ids,
            "fault_parent_origins": parent_origins,
            "fault_parent_queue_names": parent_queue_names,
            "fault_parent_match_count": len(parent_seed_ids),
        }

    def _inject_bootstrap_sync_seeds_once(self) -> None:
        inject_bootstrap_sync_seeds(
            config=self.config,
            state=self.state,
            injector=self.injector,
            logger=self.logger,
            bootstrap_sync_seed_dir=self.bootstrap_sync_seed_dir,
            seed_limit=max(int(getattr(self.config, "bootstrap_sync_seed_limit", 0) or 0), 0),
        )

    def _maybe_inject_async_seeds(self) -> None:
        mode = str(getattr(self.config, "psei_seed_delivery_mode", "afl-input") or "afl-input").strip().lower()
        if mode != "async":
            return
        now = time.time()
        start_delay = max(float(getattr(self.config, "psei_async_start_delay_sec", 10.0) or 0.0), 0.0)
        if now - self._async_started_at < start_delay:
            return
        interval = max(float(getattr(self.config, "psei_async_inject_interval_sec", 10.0) or 0.0), 0.0)
        if interval > 0 and self._last_async_inject_at > 0 and now - self._last_async_inject_at < interval:
            return
        summary = inject_async_staged_seeds(
            config=self.config,
            state=self.state,
            injector=self.injector,
            logger=self.logger,
            async_seed_dir=self._async_seed_dir,
            async_injected_dir=self._async_injected_dir,
            batch_size=max(int(getattr(self.config, "psei_async_batch_size", 1) or 1), 1),
        )
        if not summary.get("skipped"):
            self._last_async_inject_at = now

    def _initialize_import_health_metrics(self) -> None:
        if self._import_health_initialized:
            return
        self._import_health_initialized = True
        self.state.update_metric(
            "import_health",
            {
                "status": "pending",
                "checked_at": 0.0,
                "window_sec": int(getattr(self.config, "import_health_check_window_sec", 300) or 300),
                "paths_imported": 0,
                "synced_cursor_exists": False,
                "partner_id": self.config.afl_sync_partner_id,
                "degraded": False,
            },
        )

    def _mark_agent_seed_discovered(self, *, seed_id: str, queue_name: str, queue_path: str) -> None:
        self.state.update_seed_metadata(
            seed_id,
            {
                "agent_seed_discovered": True,
                "agent_seed_discovered_at": time.time(),
                "agent_seed_queue_name": queue_name,
                "agent_seed_queue_path": queue_path,
                "agent_seed_partner": self.config.afl_sync_partner_id,
            },
        )

    def _mark_agent_seed_imported(self, *, seed_id: str, queue_name: str, queue_path: str) -> None:
        self.state.update_seed_metadata(
            seed_id,
            {
                "imported_into_fuzzer_queue": True,
                "imported_into_fuzzer_queue_at": time.time(),
                "imported_queue_name": queue_name,
                "imported_queue_path": queue_path,
                "retained_after_calibration": True,
            },
        )

    def _scan_queue(self) -> None:
        qdir = self._queue_dir()
        if not qdir.exists():
            return
        for path in sorted(qdir.iterdir()):
            if not path.is_file():
                continue
            if not path.name.startswith("id:"):
                continue
            if str(path) in self._known_paths:
                continue
            try:
                size = path.stat().st_size
            except OSError:
                continue
            if size <= 0:
                continue

            raw = load_seed_file(path)
            seed_id = body_sha1(raw)
            messages = split_seed_messages(self.config.protocol, raw)
            methods = [message_method(msg) for msg in messages if message_method(msg)]
            origin = self._origin_from_name(path.name)
            is_initial_seed = (",orig:" in path.name) and (origin in self.initial_seed_names)
            replay_reason = "initial" if is_initial_seed else ("+cov" if "+cov" in path.name else "")
            from_sync_partner = "sync:" in path.name
            existing_metadata = self._existing_seed_metadata(seed_id)
            metadata = dict(existing_metadata)
            metadata.update(
                {
                    "queue_name": path.name,
                    "source": metadata.get("source") or "queue_watcher",
                    "discovered_via": "fuzzer_queue",
                    "is_initial_seed": is_initial_seed,
                    "replay_reason": replay_reason,
                    "from_sync_partner": from_sync_partner,
                    "fuzzer_queue_path": str(path),
                    "fuzzer_queue_seen_at": time.time(),
                }
            )
            should_replay = self._should_enqueue_for_replay(path.name, is_initial_seed=is_initial_seed)
            if should_replay:
                metadata["replay_enqueued_at"] = time.time()
                metadata["replay_enqueued_via"] = "queue_watcher"
            seed = SeedRecord(
                seed_id=seed_id,
                queue_path=str(path),
                origin=origin,
                protocol=self.config.protocol,
                subject=self.config.subject,
                methods=methods,
                message_count=len(messages),
                body_sha1=seed_id,
                size_bytes=size,
                first_seen_at=time.time(),
                metadata=metadata,
            )
            self.state.upsert_seed(seed)
            self.state.record_seed_observation(
                seed_id=seed.seed_id,
                stage="afl-imported" if from_sync_partner else ("initial-queue" if is_initial_seed else "queue-discovered"),
                lane="coverage",
                queue_path=str(path),
                task_id=str(metadata.get("task_id") or ""),
                target_id=str(metadata.get("target_id") or ""),
                module=str(metadata.get("task_kind") or metadata.get("source") or ""),
                payload={
                    "queue_name": path.name,
                    "origin": origin,
                    "from_sync_partner": from_sync_partner,
                    "is_initial_seed": is_initial_seed,
                    "replay_enqueued": should_replay,
                },
            )
            if from_sync_partner:
                self._mark_agent_seed_imported(seed_id=seed.seed_id, queue_name=path.name, queue_path=str(path))
            self.state.record_event(
                kind="queue_seed_discovered",
                subject=self.config.subject,
                protocol=self.config.protocol,
                seed_id=seed.seed_id,
                payload={
                    "seed_id": seed.seed_id,
                    "queue_path": seed.queue_path,
                    "origin": seed.origin,
                    "queue_name": path.name,
                    "methods": seed.methods,
                    "message_count": seed.message_count,
                    "is_initial_seed": is_initial_seed,
                    "replay_reason": replay_reason or "none",
                    "from_sync_partner": from_sync_partner,
                    "source": "queue_watcher",
                },
            )
            if should_replay:
                self.replay_queue.put(seed)
            self._known_paths.add(str(path))
            self.logger.log(
                "A",
                "new queue seed discovered",
                seed_id=seed.seed_id,
                origin=seed.origin,
                methods=",".join(seed.methods),
                queue_path=str(path),
                replay_enqueued=should_replay,
                replay_reason=replay_reason or "none",
            )

    def _scan_faults(self) -> None:
        for fault_kind, fault_family, directory in self._fault_dir_specs():
            if not directory.exists():
                continue
            for path in sorted(directory.iterdir()):
                if not path.is_file() or not path.name.startswith("id:"):
                    continue
                if str(path) in self._known_paths:
                    continue
                try:
                    size = path.stat().st_size
                except OSError:
                    continue
                if size <= 0:
                    continue
                raw = load_seed_file(path)
                seed_id = body_sha1(raw)
                messages = split_seed_messages(self.config.protocol, raw)
                methods = [message_method(msg) for msg in messages if message_method(msg)]
                ancestry = self._resolve_fault_ancestry(path.name)
                metadata = dict(self._existing_seed_metadata(seed_id))
                metadata.update(
                    {
                        "source": metadata.get("source") or "queue_watcher",
                        "discovered_via": f"fault:{fault_family}:{fault_kind}",
                        "fault_kind": fault_kind,
                        "fault_family": fault_family,
                        "fault_path": str(path),
                        "fault_queue_name": path.name,
                        "fault_seen_at": time.time(),
                        **ancestry,
                    }
                )
                existing_row = self.state.get_seed_row(seed_id)
                if existing_row:
                    self.state.update_seed_metadata(seed_id, metadata)
                else:
                    seed = SeedRecord(
                        seed_id=seed_id,
                        queue_path=str(path),
                        origin=str(ancestry.get("fault_orig_name") or self._origin_from_name(path.name) or "fault"),
                        protocol=self.config.protocol,
                        subject=self.config.subject,
                        methods=methods,
                        message_count=len(messages),
                        body_sha1=seed_id,
                        size_bytes=size,
                        first_seen_at=time.time(),
                        metadata=metadata,
                    )
                    self.state.upsert_seed(seed)
                self.state.record_seed_observation(
                    seed_id=seed_id,
                    stage=f"fault-{fault_family}-{fault_kind}",
                    lane="fault",
                    queue_path=str(path),
                    module=str(metadata.get("task_kind") or metadata.get("source") or ""),
                    payload={
                        "fault_kind": fault_kind,
                        "fault_family": fault_family,
                        "queue_name": path.name,
                        **ancestry,
                    },
                )
                self.state.record_event(
                    kind="fault_seed_discovered",
                    subject=self.config.subject,
                    protocol=self.config.protocol,
                    seed_id=seed_id,
                    payload={
                        "seed_id": seed_id,
                        "fault_kind": fault_kind,
                        "fault_family": fault_family,
                        "fault_path": str(path),
                        "queue_name": path.name,
                        "size_bytes": size,
                        "methods": methods,
                        "message_count": len(messages),
                        "source": "queue_watcher",
                        **ancestry,
                    },
                )
                self._known_paths.add(str(path))
                self.logger.log(
                    "A",
                    "fault seed discovered",
                    seed_id=seed_id,
                    fault_kind=fault_kind,
                    fault_family=fault_family,
                    fault_path=str(path),
                    parent_matches=int(ancestry.get("fault_parent_match_count") or 0),
                )

    def _poll_metrics(self) -> None:
        now = time.time()
        if now - self._last_metrics_poll < self.config.metrics_poll_interval_sec:
            return
        self._last_metrics_poll = now

        stats = self.runtime.parse_fuzzer_stats()
        plot = self.runtime.parse_plot_data()
        self.state.update_metric("fuzzer_stats", stats)
        self.state.update_metric("plot_data_last", plot)
        imported_count = 0
        try:
            imported_count = int(str(stats.get("paths_imported", "0") or "0").strip() or "0")
        except ValueError:
            imported_count = 0
        synced_cursor = self.config.resolved_fuzzer_out_dir / ".synced" / self.config.afl_sync_partner_id
        imported_rows = self.state.find_seed_rows_by_metadata_field("imported_into_fuzzer_queue", True)
        retained_count = len(imported_rows)
        self.state.update_metric(
            "import_health",
            {
                "status": "observing",
                "checked_at": now,
                "window_sec": int(getattr(self.config, "import_health_check_window_sec", 300) or 300),
                "paths_imported": imported_count,
                "retained_seed_count": retained_count,
                "synced_cursor_exists": synced_cursor.exists(),
                "partner_id": self.config.afl_sync_partner_id,
                "degraded": False,
            },
        )
        bitmap_signature = self.runtime.current_bitmap_state()
        if bitmap_signature != self._last_bitmap_signature:
            self._last_bitmap_signature = bitmap_signature
            self.state.update_metric("last_bitmap_change_ts", now)
            self.state.record_event(
                kind="bitmap_progress",
                subject=self.config.subject,
                protocol=self.config.protocol,
                payload={
                    "bitmap_signature": bitmap_signature,
                    "fuzzer_stats": stats,
                    "plot_data": plot,
                },
            )
            self.logger.log("A", "bitmap changed", map_size=bitmap_signature[0], paths_total=bitmap_signature[1])

    def _should_enqueue_for_replay(self, queue_name: str, *, is_initial_seed: bool) -> bool:
        mode = str(getattr(self.config, "replay_queue_filter_mode", "all") or "all").strip().lower()
        if mode == "all":
            return True
        if mode == "interesting-only":
            return is_initial_seed or ("+cov" in queue_name)
        return True

    @staticmethod
    def _origin_from_name(name: str) -> str:
        if ",orig:" in name:
            return name.split(",orig:", 1)[1]
        if ",src:" in name:
            return name.split(",src:", 1)[1]
        return "queue"
