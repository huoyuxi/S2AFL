"""Workflow2 runtime configuration.

This configuration layer is the public contract between the Python workflow and
user-specific benchmark environments. Paths stay relative to `python/S2AFL/` by
default so the released repository does not depend on any author-local layout.

This module defines all runtime paths, commands, and policy knobs in one place.
Design principles:
1. Runtime logic does not hardcode one protocol implementation; it reads everything from configuration.
2. Target-specific start, replay, and coverage commands are expressed as configurable templates.
3. All paths support resolution relative to the `S2AFL/` root.
"""

from __future__ import annotations

import json
import os
import shlex
try:
    import tomllib
except ModuleNotFoundError:
    tomllib = None
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from S2AFL.core.templates import DEFAULT_TEMPLATE_CATALOG, resolve_s2afl_path
from S2AFL.knowledge.implementation_registry import implementation_protocol


def _as_list(value: str | list[str] | None) -> list[str]:
    """Normalize a command configuration into an argv list."""
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value]
    text = str(value).strip()
    if not text:
        return []
    return shlex.split(text)


def _load_json_env(name: str, default: dict[str, Any]) -> dict[str, Any]:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return dict(default)
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"invalid JSON in {name}: {exc.msg} at line {exc.lineno} column {exc.colno}") from exc
    if not isinstance(data, dict):
        raise RuntimeError(f"{name} must be a JSON object")
    return data


@dataclass
class RuntimeConfig:
    """Complete runtime configuration for workflow2.

    No protocol-specific command is hardcoded in this configuration object.
    The runtime is responsible only for:
    - starting AFLNet, replay, and coverage collection from configuration
    - scheduling tasks based on the knowledge base and observed coverage
    """

    implementation: str
    protocol: str
    subject: str
    run_tag: str = ""

    templates_file: str = str(DEFAULT_TEMPLATE_CATALOG)
    baseline_seed_dir: str = ""
    initial_sequences_file: str = ""
    seed_corpus_dir: str = ""
    psei_output_dir: str = "output/workflow2/runtime/psei"
    psei_working_seed_dir: str = "output/workflow2/runtime/seed_corpus"
    psei_max_sequences: int = 64
    psei_use_llm_messages: bool = True
    psei_seed: int = 1337
    startup_validate_initial_seeds: bool = False
    startup_ready_timeout_sec: int = 30
    startup_ok_server_rcs: list[int] = field(default_factory=lambda: [124])

    afl_input_dir: str = "output/workflow2/runtime/afl_input"
    afl_output_dir: str = "output/workflow2/runtime/afl_out"
    afl_sync_id: str = "fuzzer01"
    afl_sync_partner_id: str = "agent-sync"
    afl_fuzz_cwd: str = ""
    afl_fuzz_cmd: list[str] = field(default_factory=list)
    target_start_cwd: str = ""
    target_start_cmd: list[str] = field(default_factory=list)
    target_stop_cwd: str = ""
    target_stop_cmd: list[str] = field(default_factory=list)
    stale_target_cmd_substrings: list[str] = field(default_factory=list)
    replay_prepare_cmd: list[str] = field(default_factory=list)
    replay_cleanup_cmd: list[str] = field(default_factory=list)
    replay_cmd: list[str] = field(default_factory=list)
    coverage_reset_cmd: list[str] = field(default_factory=list)
    coverage_capture_cmd: list[str] = field(default_factory=list)
    coverage_capture_env: dict[str, str] = field(default_factory=dict)
    afl_env: dict[str, str] = field(default_factory=dict)
    afl_env_unset: list[str] = field(default_factory=list)
    enable_chatafl_template_server: bool = True
    chatafl_template_host: str = "127.0.0.1"
    chatafl_template_port: int = 12134

    fuzz_host: str = "127.0.0.1"
    fuzz_port: int = 0
    replay_host: str = "127.0.0.1"
    replay_port: int = 0
    first_resp_timeout_us: int = 1000000
    followup_resp_timeout_ms: int = 1000

    state_dir: str = "output/workflow2/runtime/state"
    log_dir: str = "output/workflow2/runtime/logs"
    temp_dir: str = "output/workflow2/runtime/tmp"
    queue_scan_interval_sec: float = 2.0
    metrics_poll_interval_sec: float = 5.0
    replay_poll_interval_sec: float = 0.2
    stagnation_window_sec: int = 300
    per_message_reset: bool = False
    replay_prefix_mode: str = "stream"
    replay_parallelism: int = 1
    psei_seed_delivery_mode: str = "afl-input"
    bootstrap_sync_injection_timing: str = "before-afl"
    bootstrap_sync_preflight_enabled: bool = True
    bootstrap_sync_seed_limit: int = 0
    psei_async_seed_dir: str = ""
    psei_async_injected_dir: str = ""
    psei_async_batch_size: int = 1
    psei_async_inject_interval_sec: float = 10.0
    psei_async_start_delay_sec: float = 10.0
    replay_queue_filter_mode: str = "interesting-only"
    generated_seed_handoff_enabled: bool = True
    command_timeout_sec: int = 120
    replay_prepare_timeout_sec: int = 30
    coverage_reset_timeout_sec: int = 30
    replay_timeout_sec: int = 120
    initial_replay_timeout_sec: int = 1800
    stream_replay_timeout_per_message_sec: float = 5.0
    stream_replay_timeout_cap_sec: int = 1800
    coverage_capture_timeout_sec: int = 120
    replay_cleanup_timeout_sec: int = 30
    target_stop_timeout_sec: int = 30
    monitor_target_process: bool = True
    import_health_check_enabled: bool = True
    import_health_check_window_sec: int = 300
    import_health_min_paths_imported: int = 1
    import_health_require_synced_cursor: bool = True
    replay_health_check_enabled: bool = True
    replay_health_window_size: int = 64
    replay_health_min_samples: int = 16
    replay_health_failure_rate_threshold: float = 0.75
    scheduler_pause_on_replay_degraded: bool = True

    llm_provider: str = field(default_factory=lambda: os.environ.get("LLM_PROVIDER", os.environ.get("LLM_PROFILE", "deepseek")))
    llm_config_file: str = field(default_factory=lambda: os.environ.get("S2AFL_LLM_CONFIG", "experiments/llm_profiles.json"))
    llm_model: str = field(default_factory=lambda: os.environ.get("LLM_MODEL", ""))
    llm_api_key_env: str = "LLM_API_KEY"
    llm_api_url: str = field(default_factory=lambda: os.environ.get("LLM_API_URL", ""))
    llm_timeout_sec: int = field(default_factory=lambda: int(os.environ.get("LLM_TIMEOUT_SEC", os.environ.get("COT_TEMPLATE_TIMEOUT", "120"))))
    llm_max_tokens: int = 4096
    llm_temperature: float = 0.0
    llm_extra_body: dict[str, Any] = field(default_factory=lambda: _load_json_env("LLM_EXTRA_BODY", {}))
    llm_response_format: str = field(default_factory=lambda: os.environ.get("LLM_RESPONSE_FORMAT", "none"))

    max_boundary_tasks: int = 20
    max_boundary_attempts_per_target: int = 3
    enable_guess_boundary_targets: bool = True
    max_guess_boundary_tasks: int = 5
    max_vuln_tasks: int = 3
    max_vuln_generated_extra_tasks_per_target: int = 2
    one_shot_per_target: bool = True
    boundary_frontier_radius: int = 3
    boundary_min_frontier_score: float = 0.5

    enable_bootstrap: bool = True
    enable_queue_watcher: bool = True
    enable_coverage_replay: bool = True
    enable_scheduler: bool = True
    enable_mutation: bool = True
    enable_boundary_tasks: bool = True
    enable_vuln_tasks: bool = True
    experiment_label: str = "full"

    @classmethod
    def from_file(cls, path: str | os.PathLike[str]) -> "RuntimeConfig":
        """Load runtime configuration from a TOML or JSON file."""
        cfg_path = resolve_s2afl_path(path)
        raw = cfg_path.read_bytes()
        if cfg_path.suffix.lower() == ".json":
            data = json.loads(raw.decode("utf-8"))
        else:
            if tomllib is None:
                raise RuntimeError("TOML config requires Python 3.11+ or tomllib/tomli. Use a JSON config in this environment.")
            data = tomllib.loads(raw.decode("utf-8"))
        return cls.from_mapping(data)

    @classmethod
    def from_mapping(cls, data: dict[str, Any]) -> "RuntimeConfig":
        """Build a configuration object from a plain dictionary."""
        payload = dict(data)
        # Backward compatibility: phase-2 PSEI now always uses LLM, so the
        # removed legacy toggle should be ignored instead of breaking startup.
        payload.pop("psei_use_llm", None)
        # Let CLI/env overrides win over values persisted in JSON runtime configs.
        env_llm_provider = os.environ.get("LLM_PROVIDER", "").strip()
        if env_llm_provider:
            payload["llm_provider"] = env_llm_provider
        env_llm_config = os.environ.get("S2AFL_LLM_CONFIG", "").strip()
        if env_llm_config:
            payload["llm_config_file"] = env_llm_config
        if "protocol" not in payload and payload.get("implementation"):
            payload["protocol"] = implementation_protocol(payload["implementation"])
        payload["afl_fuzz_cmd"] = _as_list(payload.get("afl_fuzz_cmd"))
        payload["target_start_cmd"] = _as_list(payload.get("target_start_cmd"))
        payload["target_stop_cmd"] = _as_list(payload.get("target_stop_cmd"))
        payload["stale_target_cmd_substrings"] = [str(item) for item in (payload.get("stale_target_cmd_substrings") or [])]
        payload["replay_prepare_cmd"] = _as_list(payload.get("replay_prepare_cmd"))
        payload["replay_cleanup_cmd"] = _as_list(payload.get("replay_cleanup_cmd"))
        payload["replay_cmd"] = _as_list(payload.get("replay_cmd"))
        payload["coverage_reset_cmd"] = _as_list(payload.get("coverage_reset_cmd"))
        payload["coverage_capture_cmd"] = _as_list(payload.get("coverage_capture_cmd"))
        payload.setdefault("coverage_capture_env", {})
        payload.setdefault("afl_env", {})
        payload["afl_env_unset"] = [str(item) for item in (payload.get("afl_env_unset") or [])]
        payload.setdefault("llm_extra_body", _load_json_env("LLM_EXTRA_BODY", {}))
        return cls(**payload)

    def apply_run_tag(self, run_tag: str) -> None:
        """Attach per-run isolation directories so old runtime output is not reused."""
        tag = str(run_tag or "").strip()
        if not tag:
            raise ValueError('run_tag must not be empty')
        if self.run_tag == tag:
            return
        if self.run_tag:
            raise RuntimeError(f'run_tag already set: {self.run_tag}')
        self.run_tag = tag
        for attr in (
            'psei_output_dir',
            'psei_working_seed_dir',
            'afl_input_dir',
            'afl_output_dir',
            'state_dir',
            'log_dir',
            'temp_dir',
        ):
            base = Path(str(getattr(self, attr)))
            setattr(self, attr, str(base / tag))

    def resolve(self, path: str | os.PathLike[str]) -> Path:
        """Resolve a configured relative path into an absolute path under `S2AFL/`."""
        return resolve_s2afl_path(path)

    @property
    def resolved_templates_file(self) -> Path:
        return self.resolve(self.templates_file)

    @property
    def resolved_baseline_seed_dir(self) -> Path:
        return self.resolve(self.baseline_seed_dir)

    @property
    def resolved_initial_sequences_file(self) -> Path | None:
        if not self.initial_sequences_file:
            return None
        return self.resolve(self.initial_sequences_file)

    @property
    def resolved_seed_corpus_dir(self) -> Path | None:
        if not self.seed_corpus_dir:
            return None
        return self.resolve(self.seed_corpus_dir)

    @property
    def resolved_psei_output_dir(self) -> Path:
        return self.resolve(self.psei_output_dir)

    @property
    def resolved_psei_working_seed_dir(self) -> Path:
        return self.resolve(self.psei_working_seed_dir)

    @property
    def resolved_psei_async_seed_dir(self) -> Path:
        if self.psei_async_seed_dir:
            return self.resolve(self.psei_async_seed_dir)
        return self.resolved_psei_output_dir / "async_pending"

    @property
    def resolved_psei_async_injected_dir(self) -> Path:
        if self.psei_async_injected_dir:
            return self.resolve(self.psei_async_injected_dir)
        return self.resolved_psei_output_dir / "async_injected"

    @property
    def resolved_afl_input_dir(self) -> Path:
        return self.resolve(self.afl_input_dir)

    @property
    def resolved_afl_output_dir(self) -> Path:
        return self.resolve(self.afl_output_dir)

    @property
    def resolved_state_dir(self) -> Path:
        return self.resolve(self.state_dir)

    @property
    def resolved_log_dir(self) -> Path:
        return self.resolve(self.log_dir)

    @property
    def resolved_temp_dir(self) -> Path:
        return self.resolve(self.temp_dir)

    @property
    def resolved_sync_dir(self) -> Path:
        """Parent directory for AFLNet sync output.

        `afl_output_dir` is treated as the sync root.
        The actual fuzzer output lives under `<sync_dir>/<afl_sync_id>/...`.
        """
        return self.resolved_afl_output_dir

    @property
    def resolved_fuzzer_out_dir(self) -> Path:
        return self.resolved_sync_dir / self.afl_sync_id

    @property
    def resolved_partner_queue_dir(self) -> Path:
        return self.resolved_sync_dir / self.afl_sync_partner_id / "queue"

    @property
    def resolved_replayable_crashes_dir(self) -> Path:
        return self.resolved_fuzzer_out_dir / "replayable-crashes"

    @property
    def resolved_replayable_hangs_dir(self) -> Path:
        return self.resolved_fuzzer_out_dir / "replayable-hangs"

    @property
    def resolved_fuzzer_crashes_dir(self) -> Path:
        return self.resolved_fuzzer_out_dir / "crashes"

    @property
    def resolved_fuzzer_hangs_dir(self) -> Path:
        return self.resolved_fuzzer_out_dir / "hangs"

    @property
    def resolved_afl_fuzz_cwd(self) -> Path | None:
        if not self.afl_fuzz_cwd:
            return None
        return self.resolve(self.afl_fuzz_cwd)

    @property
    def resolved_target_start_cwd(self) -> Path | None:
        if not self.target_start_cwd:
            return None
        return self.resolve(self.target_start_cwd)

    @property
    def resolved_target_stop_cwd(self) -> Path | None:
        if not self.target_stop_cwd:
            return None
        return self.resolve(self.target_stop_cwd)

    def ensure_directories(self) -> None:
        """Create all directories required by the runtime."""
        for path in [
            self.resolved_psei_output_dir,
            self.resolved_psei_working_seed_dir,
            self.resolved_psei_async_seed_dir,
            self.resolved_psei_async_injected_dir,
            self.resolved_afl_input_dir,
            self.resolved_sync_dir,
            self.resolved_partner_queue_dir,
            self.resolved_replayable_crashes_dir,
            self.resolved_replayable_hangs_dir,
            self.resolved_fuzzer_crashes_dir,
            self.resolved_fuzzer_hangs_dir,
            self.resolved_state_dir,
            self.resolved_log_dir,
            self.resolved_temp_dir,
        ]:
            path.mkdir(parents=True, exist_ok=True)

    def command_params(self, **extra: Any) -> dict[str, Any]:
        """Template parameters available during command rendering."""
        params = {
            "implementation": self.implementation,
            "protocol": self.protocol,
            "subject": self.subject,
            "run_tag": self.run_tag,
            "s2afl_root": str(Path(__file__).resolve().parents[2]),
            "fuzz_host": self.fuzz_host,
            "fuzz_port": self.fuzz_port,
            "replay_host": self.replay_host,
            "replay_port": self.replay_port,
            "first_resp_timeout_us": self.first_resp_timeout_us,
            "followup_resp_timeout_ms": self.followup_resp_timeout_ms,
            "afl_input_dir": str(self.resolved_afl_input_dir),
            "afl_output_dir": str(self.resolved_afl_output_dir),
            "afl_sync_dir": str(self.resolved_sync_dir),
            "afl_fuzzer_out_dir": str(self.resolved_fuzzer_out_dir),
            "afl_sync_id": self.afl_sync_id,
            "afl_sync_partner_id": self.afl_sync_partner_id,
            "partner_queue_dir": str(self.resolved_partner_queue_dir),
            "state_dir": str(self.resolved_state_dir),
            "log_dir": str(self.resolved_log_dir),
            "temp_dir": str(self.resolved_temp_dir),
        }
        params.update(extra)
        return params

    def render_command(self, argv: list[str], **extra: Any) -> list[str]:
        """Render configured command templates with `{name}` substitution."""
        params = self.command_params(**extra)
        return [part.format(**params) for part in argv]
