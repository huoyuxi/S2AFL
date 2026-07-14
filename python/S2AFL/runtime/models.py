"""Runtime dataclasses shared by workflow2 workers."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class SeedRecord:
    """Standardized representation of one seed discovered in the AFLNet queue."""

    seed_id: str
    queue_path: str
    origin: str
    protocol: str
    subject: str
    methods: list[str]
    message_count: int
    body_sha1: str
    size_bytes: int
    first_seen_at: float
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class CoverageSnapshot:
    """Standardized result of one coverage snapshot."""

    lines: set[str] = field(default_factory=set)
    branches: set[str] = field(default_factory=set)
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass
class MessageDelta:
    """Per-message contribution to the observed coverage delta."""

    step_index: int
    method: str
    message_preview: str
    delta_lines: list[str]
    cumulative_lines: list[str]
    delta_branches: list[str]
    cumulative_branches: list[str]
    hit_boundary_target_ids: list[str] = field(default_factory=list)
    hit_vuln_target_ids: list[str] = field(default_factory=list)
    flipped_boundary_target_ids: list[str] = field(default_factory=list)


@dataclass
class CoverageReplayResult:
    """Coverage result produced after replaying one seed end to end."""

    seed_id: str
    queue_path: str
    measurement_lane: str
    accepted: bool
    reason: str
    message_deltas: list[MessageDelta]
    seed_total_lines: int
    seed_new_lines: int
    seed_total_branches: int
    seed_new_branches: int
    hit_boundary_target_ids: list[str] = field(default_factory=list)
    hit_vuln_target_ids: list[str] = field(default_factory=list)
    flipped_boundary_target_ids: list[str] = field(default_factory=list)
    replay_accepted: bool = False
    scheduler_accepted: bool = False
    global_new_lines: int = 0
    global_new_branches: int = 0


@dataclass
class TargetRecord:
    """Schedulable boundary/vulnerability target."""

    target_id: str
    kind: str
    implementation: str
    protocol: str
    relative_path: str
    line: int
    function: str
    code: str
    field_names: list[str]
    commands: list[str]
    evidence_score: int
    info_rank: int
    first_activation_ts: float = 0.0
    analyzed: bool = False
    analysis_result: str = ""
    source_payload: dict[str, Any] = field(default_factory=dict)


@dataclass
class MutationTask:
    """LLM-generated mutation task."""

    task_id: str
    kind: str
    target_id: str
    seed_id: str
    protocol: str
    subject: str
    implementation: str
    priority_score: tuple[int, float]
    payload: dict[str, Any] = field(default_factory=dict)
