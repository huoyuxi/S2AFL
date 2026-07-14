"""Persistent sqlite state for workflow2 runtime.

Design goals:
1. Let all runtime threads share one persistent state store instead of relying only on memory.
2. Keep the primary `events` / `tasks` tables compatible with `experiments/workflow2/runtime_metrics.py`.
3. Add `seeds`, `targets`, `metrics`, `coverage_lines`, and related tables to support online scheduling.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
import uuid
from pathlib import Path
from typing import Any

from .models import SeedRecord, TargetRecord


class RuntimeStateDB:
    """Thread-safe sqlite wrapper."""

    def __init__(self, db_path: Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.executescript(
                """
                PRAGMA journal_mode=WAL;
                PRAGMA synchronous=NORMAL;

                CREATE TABLE IF NOT EXISTS events (
                    event_id TEXT PRIMARY KEY,
                    kind TEXT NOT NULL,
                    subject TEXT NOT NULL,
                    protocol TEXT NOT NULL,
                    seed_id TEXT,
                    payload_json TEXT NOT NULL,
                    created_at REAL NOT NULL
                );

                CREATE TABLE IF NOT EXISTS tasks (
                    task_id TEXT PRIMARY KEY,
                    kind TEXT NOT NULL,
                    protocol TEXT NOT NULL,
                    subject TEXT NOT NULL,
                    seed_id TEXT,
                    target_id TEXT,
                    attempt INTEGER NOT NULL DEFAULT 1,
                    status TEXT NOT NULL,
                    leased_by TEXT,
                    priority REAL NOT NULL DEFAULT 0,
                    payload_json TEXT NOT NULL,
                    result_json TEXT NOT NULL DEFAULT '{}',
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL
                );

                CREATE TABLE IF NOT EXISTS seeds (
                    seed_id TEXT PRIMARY KEY,
                    queue_path TEXT NOT NULL,
                    origin TEXT NOT NULL,
                    protocol TEXT NOT NULL,
                    subject TEXT NOT NULL,
                    methods_json TEXT NOT NULL,
                    message_count INTEGER NOT NULL,
                    body_sha1 TEXT NOT NULL,
                    size_bytes INTEGER NOT NULL,
                    first_seen_at REAL NOT NULL,
                    last_replayed_at REAL NOT NULL DEFAULT 0,
                    metadata_json TEXT NOT NULL DEFAULT '{}'
                );

                CREATE TABLE IF NOT EXISTS targets (
                    target_id TEXT PRIMARY KEY,
                    kind TEXT NOT NULL,
                    implementation TEXT NOT NULL,
                    protocol TEXT NOT NULL,
                    relative_path TEXT NOT NULL,
                    line INTEGER NOT NULL,
                    function_name TEXT NOT NULL,
                    code TEXT NOT NULL,
                    field_names_json TEXT NOT NULL,
                    commands_json TEXT NOT NULL,
                    evidence_score INTEGER NOT NULL,
                    info_rank INTEGER NOT NULL,
                    first_activation_ts REAL NOT NULL DEFAULT 0,
                    analyzed INTEGER NOT NULL DEFAULT 0,
                    analysis_result TEXT NOT NULL DEFAULT '',
                    source_payload_json TEXT NOT NULL DEFAULT '{}'
                );

                CREATE TABLE IF NOT EXISTS coverage_lines (
                    line_key TEXT PRIMARY KEY,
                    relative_path TEXT NOT NULL,
                    line INTEGER NOT NULL,
                    first_seed_id TEXT,
                    first_seen_at REAL NOT NULL,
                    last_seed_id TEXT,
                    last_seen_at REAL NOT NULL,
                    hit_count INTEGER NOT NULL DEFAULT 1
                );

                CREATE TABLE IF NOT EXISTS coverage_branches (
                    branch_key TEXT PRIMARY KEY,
                    first_seed_id TEXT,
                    first_seen_at REAL NOT NULL,
                    last_seed_id TEXT,
                    last_seen_at REAL NOT NULL,
                    hit_count INTEGER NOT NULL DEFAULT 1
                );

                CREATE TABLE IF NOT EXISTS metrics (
                    metric_name TEXT PRIMARY KEY,
                    metric_value TEXT NOT NULL,
                    updated_at REAL NOT NULL
                );

                CREATE TABLE IF NOT EXISTS seed_observations (
                    observation_id TEXT PRIMARY KEY,
                    seed_id TEXT NOT NULL,
                    stage TEXT NOT NULL,
                    lane TEXT NOT NULL DEFAULT '',
                    queue_path TEXT NOT NULL DEFAULT '',
                    task_id TEXT NOT NULL DEFAULT '',
                    target_id TEXT NOT NULL DEFAULT '',
                    module TEXT NOT NULL DEFAULT '',
                    payload_json TEXT NOT NULL DEFAULT '{}',
                    created_at REAL NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_seeds_body_sha1 ON seeds(body_sha1);
                CREATE INDEX IF NOT EXISTS idx_tasks_status_priority ON tasks(status, priority, created_at);
                CREATE INDEX IF NOT EXISTS idx_seed_observations_seed_stage ON seed_observations(seed_id, stage, created_at);
                """
            )

    def record_event(
        self,
        *,
        kind: str,
        subject: str,
        protocol: str,
        payload: dict[str, Any],
        seed_id: str | None = None,
        created_at: float | None = None,
    ) -> str:
        """Insert one event record compatible with the `events` table."""
        event_id = f"evt-{uuid.uuid4().hex[:16]}"
        ts = time.time() if created_at is None else created_at
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT INTO events(event_id, kind, subject, protocol, seed_id, payload_json, created_at) "
                "VALUES(?, ?, ?, ?, ?, ?, ?)",
                (event_id, kind, subject, protocol, seed_id, json.dumps(payload, ensure_ascii=False), ts),
            )
        return event_id

    def upsert_seed(self, seed: SeedRecord) -> None:
        """Record a newly discovered seed from the AFL queue."""
        with self._lock, self._connect() as conn:
            row = conn.execute("SELECT metadata_json FROM seeds WHERE seed_id=?", (seed.seed_id,)).fetchone()
            existing_meta: dict[str, Any] = {}
            if row and row["metadata_json"]:
                try:
                    parsed = json.loads(row["metadata_json"])
                    if isinstance(parsed, dict):
                        existing_meta = parsed
                except Exception:
                    existing_meta = {}
            merged_meta = dict(existing_meta)
            merged_meta.update(seed.metadata or {})
            conn.execute(
                """
                INSERT INTO seeds(
                    seed_id, queue_path, origin, protocol, subject, methods_json,
                    message_count, body_sha1, size_bytes, first_seen_at, metadata_json
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(seed_id) DO UPDATE SET
                    queue_path=excluded.queue_path,
                    origin=excluded.origin,
                    metadata_json=excluded.metadata_json
                """,
                (
                    seed.seed_id,
                    seed.queue_path,
                    seed.origin,
                    seed.protocol,
                    seed.subject,
                    json.dumps(seed.methods, ensure_ascii=False),
                    seed.message_count,
                    seed.body_sha1,
                    seed.size_bytes,
                    seed.first_seen_at,
                    json.dumps(merged_meta, ensure_ascii=False),
                ),
            )

    def mark_seed_replayed(self, seed_id: str, when: float | None = None) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                "UPDATE seeds SET last_replayed_at=? WHERE seed_id=?",
                (time.time() if when is None else when, seed_id),
            )

    def record_seed_observation(
        self,
        *,
        seed_id: str,
        stage: str,
        lane: str = '',
        queue_path: str = '',
        task_id: str = '',
        target_id: str = '',
        module: str = '',
        payload: dict[str, Any] | None = None,
        created_at: float | None = None,
    ) -> str:
        """Append one lifecycle observation for a content-addressed seed."""
        observation_id = f"obs-{uuid.uuid4().hex[:16]}"
        ts = time.time() if created_at is None else created_at
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO seed_observations(
                    observation_id, seed_id, stage, lane, queue_path, task_id,
                    target_id, module, payload_json, created_at
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    observation_id,
                    seed_id,
                    str(stage or ''),
                    str(lane or ''),
                    str(queue_path or ''),
                    str(task_id or ''),
                    str(target_id or ''),
                    str(module or ''),
                    json.dumps(payload or {}, ensure_ascii=False),
                    ts,
                ),
            )
        return observation_id

    def get_seed_row(self, seed_id: str) -> dict[str, Any] | None:
        with self._lock, self._connect() as conn:
            row = conn.execute("SELECT * FROM seeds WHERE seed_id=?", (seed_id,)).fetchone()
        return dict(row) if row else None

    def update_seed_metadata(self, seed_id: str, metadata_updates: dict[str, Any]) -> None:
        with self._lock, self._connect() as conn:
            row = conn.execute("SELECT metadata_json FROM seeds WHERE seed_id=?", (seed_id,)).fetchone()
            if not row:
                return
            existing_meta: dict[str, Any] = {}
            if row["metadata_json"]:
                try:
                    parsed = json.loads(row["metadata_json"])
                    if isinstance(parsed, dict):
                        existing_meta = parsed
                except Exception:
                    existing_meta = {}
            merged_meta = dict(existing_meta)
            merged_meta.update(metadata_updates or {})
            conn.execute(
                "UPDATE seeds SET metadata_json=? WHERE seed_id=?",
                (json.dumps(merged_meta, ensure_ascii=False), seed_id),
            )

    def find_seed_rows_by_queue_token(self, queue_token: str) -> list[dict[str, Any]]:
        if not queue_token:
            return []
        pattern = f"%{queue_token}%"
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                """
                SELECT * FROM seeds
                WHERE queue_path LIKE ?
                   OR metadata_json LIKE ?
                ORDER BY first_seen_at ASC
                """,
                (pattern, pattern),
            ).fetchall()
        return [dict(row) for row in rows]

    def find_seed_rows_by_origin(self, origin: str) -> list[dict[str, Any]]:
        if not origin:
            return []
        pattern = f'%"{origin}"%'
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                """
                SELECT * FROM seeds
                WHERE origin=?
                   OR metadata_json LIKE ?
                ORDER BY first_seen_at ASC
                """,
                (origin, pattern),
            ).fetchall()
        return [dict(row) for row in rows]

    def find_seed_rows_by_metadata_field(self, key: str, value: Any) -> list[dict[str, Any]]:
        if not key:
            return []
        if isinstance(value, bool):
            value_repr = 'true' if value else 'false'
            pattern = f'%"{key}": {value_repr}%'
        elif isinstance(value, (int, float)) and not isinstance(value, bool):
            pattern = f'%"{key}": {value}%'
        else:
            pattern = f'%"{key}": "{value}"%'
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                """
                SELECT * FROM seeds
                WHERE metadata_json LIKE ?
                ORDER BY first_seen_at ASC
                """,
                (pattern,),
            ).fetchall()
        return [dict(row) for row in rows]

    def has_seed_body_sha1(self, body_sha1: str) -> bool:
        with self._lock, self._connect() as conn:
            row = conn.execute("SELECT 1 FROM seeds WHERE body_sha1=? LIMIT 1", (body_sha1,)).fetchone()
        return row is not None

    def list_unreplayed_seed_rows(self) -> list[dict[str, Any]]:
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM seeds WHERE last_replayed_at=0 ORDER BY first_seen_at ASC"
            ).fetchall()
        return [dict(row) for row in rows]

    def upsert_target(self, target: TargetRecord) -> None:
        """Register static boundary/vulnerability targets in the state database."""
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO targets(
                    target_id, kind, implementation, protocol, relative_path, line,
                    function_name, code, field_names_json, commands_json, evidence_score,
                    info_rank, first_activation_ts, analyzed, analysis_result, source_payload_json
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(target_id) DO UPDATE SET
                    field_names_json=excluded.field_names_json,
                    commands_json=excluded.commands_json,
                    evidence_score=excluded.evidence_score,
                    info_rank=excluded.info_rank,
                    source_payload_json=excluded.source_payload_json
                """,
                (
                    target.target_id,
                    target.kind,
                    target.implementation,
                    target.protocol,
                    target.relative_path,
                    target.line,
                    target.function,
                    target.code,
                    json.dumps(target.field_names, ensure_ascii=False),
                    json.dumps(target.commands, ensure_ascii=False),
                    target.evidence_score,
                    target.info_rank,
                    target.first_activation_ts,
                    1 if target.analyzed else 0,
                    target.analysis_result,
                    json.dumps(target.source_payload, ensure_ascii=False),
                ),
            )

    def upsert_targets(self, targets: list[TargetRecord]) -> None:
        """Register many static targets in one sqlite transaction."""
        if not targets:
            return
        rows = [
            (
                target.target_id,
                target.kind,
                target.implementation,
                target.protocol,
                target.relative_path,
                target.line,
                target.function,
                target.code,
                json.dumps(target.field_names, ensure_ascii=False),
                json.dumps(target.commands, ensure_ascii=False),
                target.evidence_score,
                target.info_rank,
                target.first_activation_ts,
                1 if target.analyzed else 0,
                target.analysis_result,
                json.dumps(target.source_payload, ensure_ascii=False),
            )
            for target in targets
        ]
        with self._lock, self._connect() as conn:
            conn.executemany(
                """
                INSERT INTO targets(
                    target_id, kind, implementation, protocol, relative_path, line,
                    function_name, code, field_names_json, commands_json, evidence_score,
                    info_rank, first_activation_ts, analyzed, analysis_result, source_payload_json
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(target_id) DO UPDATE SET
                    field_names_json=excluded.field_names_json,
                    commands_json=excluded.commands_json,
                    evidence_score=excluded.evidence_score,
                    info_rank=excluded.info_rank,
                    source_payload_json=excluded.source_payload_json
                """,
                rows,
            )

    def activate_target(self, target_id: str, activated_at: float | None = None) -> None:
        """Record the first time a target becomes eligible for analysis."""
        ts = time.time() if activated_at is None else activated_at
        with self._lock, self._connect() as conn:
            conn.execute(
                "UPDATE targets SET first_activation_ts=CASE WHEN first_activation_ts=0 THEN ? ELSE first_activation_ts END "
                "WHERE target_id=?",
                (ts, target_id),
            )

    def mark_target_analyzed(self, target_id: str, result: str) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                "UPDATE targets SET analyzed=1, analysis_result=? WHERE target_id=?",
                (result, target_id),
            )

    def set_target_analysis_result(self, target_id: str, result: str) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                "UPDATE targets SET analysis_result=? WHERE target_id=?",
                (result, target_id),
            )

    def get_target_row(self, target_id: str) -> dict[str, Any] | None:
        with self._lock, self._connect() as conn:
            row = conn.execute("SELECT * FROM targets WHERE target_id=?", (target_id,)).fetchone()
        return dict(row) if row else None

    def list_candidate_targets(self, kind: str) -> list[dict[str, Any]]:
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM targets WHERE kind=? AND analyzed=0 ORDER BY info_rank ASC, first_activation_ts ASC, line ASC",
                (kind,),
            ).fetchall()
        return [dict(row) for row in rows]

    def has_active_task_for_target(self, target_id: str, *, kind: str | None = None) -> bool:
        with self._lock, self._connect() as conn:
            if kind:
                row = conn.execute(
                    "SELECT 1 FROM tasks WHERE target_id=? AND kind=? AND status IN ('pending','leased') LIMIT 1",
                    (target_id, kind),
                ).fetchone()
            else:
                row = conn.execute(
                    "SELECT 1 FROM tasks WHERE target_id=? AND status IN ('pending','leased') LIMIT 1",
                    (target_id,),
                ).fetchone()
        return row is not None

    def count_tasks_for_target(self, target_id: str, *, kind: str | None = None) -> int:
        with self._lock, self._connect() as conn:
            if kind:
                row = conn.execute(
                    "SELECT COUNT(*) AS cnt FROM tasks WHERE target_id=? AND kind=?",
                    (target_id, kind),
                ).fetchone()
            else:
                row = conn.execute(
                    "SELECT COUNT(*) AS cnt FROM tasks WHERE target_id=?",
                    (target_id,),
                ).fetchone()
        return int(row['cnt'] if row and row['cnt'] is not None else 0)

    def count_tasks_for_target_module(self, target_id: str, *, kind: str, module: str) -> int:
        with self._lock, self._connect() as conn:
            row = conn.execute(
                """
                SELECT COUNT(*) AS cnt
                FROM tasks AS t
                LEFT JOIN seeds AS s ON s.seed_id=t.seed_id
                WHERE t.target_id=?
                  AND t.kind=?
                  AND COALESCE(json_extract(s.metadata_json, '$.task_kind'), '')=?
                """,
                (target_id, kind, module),
            ).fetchone()
        return int(row['cnt'] if row and row['cnt'] is not None else 0)

    def task_batch_status_counts(self, batch_id: str, *, kind: str | None = None) -> dict[str, int]:
        if not batch_id:
            return {}
        with self._lock, self._connect() as conn:
            if kind:
                rows = conn.execute(
                    """
                    SELECT status, COUNT(*) AS cnt
                    FROM tasks
                    WHERE kind=?
                      AND COALESCE(json_extract(payload_json, '$.batch_id'), '')=?
                    GROUP BY status
                    """,
                    (kind, batch_id),
                ).fetchall()
            else:
                rows = conn.execute(
                    """
                    SELECT status, COUNT(*) AS cnt
                    FROM tasks
                    WHERE COALESCE(json_extract(payload_json, '$.batch_id'), '')=?
                    GROUP BY status
                    """,
                    (batch_id,),
                ).fetchall()
        counts = {str(row['status']): int(row['cnt']) for row in rows}
        counts['total'] = sum(counts.values())
        return counts

    def has_task_for_target_seed(self, target_id: str, seed_id: str, *, kind: str | None = None) -> bool:
        if not target_id or not seed_id:
            return False
        with self._lock, self._connect() as conn:
            if kind:
                row = conn.execute(
                    "SELECT 1 FROM tasks WHERE target_id=? AND seed_id=? AND kind=? LIMIT 1",
                    (target_id, seed_id, kind),
                ).fetchone()
            else:
                row = conn.execute(
                    "SELECT 1 FROM tasks WHERE target_id=? AND seed_id=? LIMIT 1",
                    (target_id, seed_id),
                ).fetchone()
        return row is not None

    def recent_boundary_skip_streak(self, target_id: str, *, limit: int) -> list[dict[str, Any]]:
        if limit <= 0:
            return []
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                """
                SELECT task_id, status, result_json, updated_at, created_at
                FROM tasks
                WHERE target_id=?
                  AND kind='boundary-generate'
                  AND status IN ('completed', 'failed')
                ORDER BY updated_at DESC, created_at DESC
                LIMIT ?
                """,
                (target_id, int(limit)),
            ).fetchall()
        items: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            try:
                result = json.loads(item.get('result_json') or '{}')
            except Exception:
                result = {}
            item['result_json'] = result if isinstance(result, dict) else {}
            if str(item['result_json'].get('decision') or '').strip().upper() != 'SKIP':
                return []
            if str(item['result_json'].get('finish_reason') or '').strip().lower() == 'length':
                return []
            items.append(item)
        return items if len(items) >= int(limit) else []

    def create_task(
        self,
        *,
        kind: str,
        protocol: str,
        subject: str,
        seed_id: str,
        target_id: str,
        priority: float,
        payload: dict[str, Any],
    ) -> str:
        """Create a pending task."""
        task_id = f"tsk-{uuid.uuid4().hex[:16]}"
        now = time.time()
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO tasks(
                    task_id, kind, protocol, subject, seed_id, target_id, attempt,
                    status, leased_by, priority, payload_json, result_json, created_at, updated_at
                ) VALUES(?, ?, ?, ?, ?, ?, 1, 'pending', '', ?, ?, '{}', ?, ?)
                """,
                (
                    task_id,
                    kind,
                    protocol,
                    subject,
                    seed_id,
                    target_id,
                    priority,
                    json.dumps(payload, ensure_ascii=False),
                    now,
                    now,
                ),
            )
        return task_id

    def claim_next_task(self, worker_name: str) -> dict[str, Any] | None:
        """Claim one pending task by priority."""
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM tasks WHERE status='pending' ORDER BY priority ASC, created_at ASC LIMIT 1"
            ).fetchone()
            if not row:
                return None
            conn.execute(
                "UPDATE tasks SET status='leased', leased_by=?, updated_at=? WHERE task_id=?",
                (worker_name, time.time(), row["task_id"]),
            )
        item = dict(row)
        item["payload_json"] = json.loads(item.get("payload_json") or "{}")
        item["result_json"] = json.loads(item.get("result_json") or "{}")
        return item

    def finish_task(self, task_id: str, status: str, result: dict[str, Any]) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                "UPDATE tasks SET status=?, result_json=?, updated_at=? WHERE task_id=?",
                (status, json.dumps(result, ensure_ascii=False), time.time(), task_id),
            )

    def add_llm_usage(
        self,
        *,
        module: str,
        input_tokens: int = 0,
        output_tokens: int = 0,
        reasoning_tokens: int = 0,
        calls: int = 1,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        total_tokens = int(input_tokens or 0) + int(output_tokens or 0)
        payload = {
            "module": module,
            "calls": int(calls or 0),
            "input_tokens": int(input_tokens or 0),
            "output_tokens": int(output_tokens or 0),
            "reasoning_tokens": int(reasoning_tokens or 0),
            "total_tokens": total_tokens,
        }
        if metadata:
            payload.update(metadata)
        with self._lock, self._connect() as conn:
            updates = {
                "calls": int(calls or 0),
                "input_tokens": int(input_tokens or 0),
                "output_tokens": int(output_tokens or 0),
                "reasoning_tokens": int(reasoning_tokens or 0),
                "total_tokens": total_tokens,
            }
            for key, delta in updates.items():
                metric_name = f"llm_usage.{module}.{key}"
                row = conn.execute(
                    "SELECT metric_value FROM metrics WHERE metric_name=?",
                    (metric_name,),
                ).fetchone()
                current = 0
                if row:
                    try:
                        current = int(json.loads(row["metric_value"]))
                    except Exception:
                        current = 0
                conn.execute(
                    """
                    INSERT INTO metrics(metric_name, metric_value, updated_at)
                    VALUES(?, ?, ?)
                    ON CONFLICT(metric_name) DO UPDATE SET
                        metric_value=excluded.metric_value,
                        updated_at=excluded.updated_at
                    """,
                    (metric_name, json.dumps(current + delta, ensure_ascii=False), time.time()),
                )
        self.record_event(
            kind="llm_usage",
            subject=payload.get("subject", ""),
            protocol=payload.get("protocol", ""),
            seed_id=payload.get("seed_id"),
            payload=payload,
        )

    def update_metric(self, name: str, value: Any) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO metrics(metric_name, metric_value, updated_at)
                VALUES(?, ?, ?)
                ON CONFLICT(metric_name) DO UPDATE SET
                    metric_value=excluded.metric_value,
                    updated_at=excluded.updated_at
                """,
                (name, json.dumps(value, ensure_ascii=False), time.time()),
            )

    def get_metric(self, name: str, default: Any = None) -> Any:
        with self._lock, self._connect() as conn:
            row = conn.execute("SELECT metric_value FROM metrics WHERE metric_name=?", (name,)).fetchone()
        if not row:
            return default
        return json.loads(row["metric_value"])

    def note_covered_lines(self, seed_id: str, lines: set[str]) -> None:
        """Update the global line-coverage table."""
        now = time.time()
        with self._lock, self._connect() as conn:
            for line_key in lines:
                relative_path, line_no = line_key.rsplit(":", 1)
                row = conn.execute(
                    "SELECT hit_count FROM coverage_lines WHERE line_key=?",
                    (line_key,),
                ).fetchone()
                if row:
                    conn.execute(
                        "UPDATE coverage_lines SET last_seed_id=?, last_seen_at=?, hit_count=hit_count+1 WHERE line_key=?",
                        (seed_id, now, line_key),
                    )
                else:
                    conn.execute(
                        """
                        INSERT INTO coverage_lines(
                            line_key, relative_path, line, first_seed_id, first_seen_at,
                            last_seed_id, last_seen_at, hit_count
                        ) VALUES(?, ?, ?, ?, ?, ?, ?, 1)
                        """,
                        (line_key, relative_path, int(line_no), seed_id, now, seed_id, now),
                    )

    def note_covered_branches(self, seed_id: str, branches: set[str]) -> None:
        now = time.time()
        with self._lock, self._connect() as conn:
            for branch_key in branches:
                row = conn.execute(
                    "SELECT hit_count FROM coverage_branches WHERE branch_key=?",
                    (branch_key,),
                ).fetchone()
                if row:
                    conn.execute(
                        "UPDATE coverage_branches SET last_seed_id=?, last_seen_at=?, hit_count=hit_count+1 WHERE branch_key=?",
                        (seed_id, now, branch_key),
                    )
                else:
                    conn.execute(
                        """
                        INSERT INTO coverage_branches(
                            branch_key, first_seed_id, first_seen_at, last_seed_id, last_seen_at, hit_count
                        ) VALUES(?, ?, ?, ?, ?, 1)
                        """,
                        (branch_key, seed_id, now, seed_id, now),
                    )

    def covered_line_keys(self) -> set[str]:
        with self._lock, self._connect() as conn:
            rows = conn.execute("SELECT line_key FROM coverage_lines").fetchall()
        return {row["line_key"] for row in rows}

    def covered_branch_keys(self) -> set[str]:
        with self._lock, self._connect() as conn:
            rows = conn.execute("SELECT branch_key FROM coverage_branches").fetchall()
        return {row["branch_key"] for row in rows}

    def latest_events(self, kind: str, limit: int = 20) -> list[dict[str, Any]]:
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM events WHERE kind=? ORDER BY created_at DESC LIMIT ?",
                (kind, limit),
            ).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            item["payload_json"] = json.loads(item.get("payload_json") or "{}")
            result.append(item)
        return result
