"""Bootstrap workflow2 by generating, screening, and exporting PSEI seeds.

This module implements the public PSEI path described in the paper: it extends
the baseline corpus, optionally quarantines unstable candidates, and prepares the
async handoff directory consumed by the AFLNet-side runtime.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path
import time
from typing import Any

from S2AFL.psei.export_seeds import export_seed_json
from S2AFL.psei.seed_gen import generate_seeds

from .command_utils import run_command, try_load_json
from .config import RuntimeConfig
from .logging_utils import RuntimeLogger
from .state_db import RuntimeStateDB


def _copy_seed_dir(src: Path, dst: Path) -> int:
    dst.mkdir(parents=True, exist_ok=True)
    count = 0
    for path in sorted(src.iterdir()):
        if not path.is_file():
            continue
        shutil.copy2(path, dst / path.name)
        count += 1
    return count


def _stage_psei_async_seeds(config: RuntimeConfig, sync_seed_dir: Path) -> dict[str, Any]:
    async_dir = config.resolved_psei_async_seed_dir
    injected_dir = config.resolved_psei_async_injected_dir
    if async_dir.exists():
        for old in async_dir.iterdir():
            if old.is_file():
                old.unlink()
    else:
        async_dir.mkdir(parents=True, exist_ok=True)
    injected_dir.mkdir(parents=True, exist_ok=True)

    copied = 0
    names: list[str] = []
    for seed_path in sorted(sync_seed_dir.iterdir()):
        if not seed_path.is_file():
            continue
        shutil.copy2(seed_path, async_dir / seed_path.name)
        copied += 1
        names.append(seed_path.name)

    manifest = {
        "seed_delivery_mode": str(config.psei_seed_delivery_mode or "").strip().lower(),
        "async_seed_dir": str(async_dir),
        "async_injected_dir": str(injected_dir),
        "seed_count": copied,
        "seed_names": names,
        "prepared_at": time.time(),
    }
    (config.resolved_psei_output_dir / "psei_async_summary.json").write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return manifest


def _staging_root(config: RuntimeConfig) -> Path:
    return config.resolved_psei_output_dir / "vuln_staging"


def _staging_pending_dir(config: RuntimeConfig) -> Path:
    return _staging_root(config) / "pending"


def _staging_consumed_dir(config: RuntimeConfig) -> Path:
    return _staging_root(config) / "consumed"


def _staging_manifest_path(config: RuntimeConfig) -> Path:
    return _staging_root(config) / "manifest.jsonl"


def _append_manifest(config: RuntimeConfig, payload: dict[str, Any]) -> None:
    root = _staging_root(config)
    root.mkdir(parents=True, exist_ok=True)
    with _staging_manifest_path(config).open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(payload, ensure_ascii=False) + "\n")


def quarantine_seed_file(
    config: RuntimeConfig,
    seed_path: Path,
    *,
    reason: str,
    logger: RuntimeLogger | None = None,
    metadata: dict[str, Any] | None = None,
    copy_only: bool = False,
) -> Path:
    pending_dir = _staging_pending_dir(config)
    pending_dir.mkdir(parents=True, exist_ok=True)
    staged_path = pending_dir / seed_path.name
    if copy_only:
        shutil.copy2(seed_path, staged_path)
    else:
        shutil.move(str(seed_path), str(staged_path))
    payload = {
        "kind": reason,
        "seed_name": seed_path.name,
        "original_path": str(seed_path),
        "staged_path": str(staged_path),
        "copy_only": bool(copy_only),
    }
    if metadata:
        payload.update(metadata)
    _append_manifest(config, payload)
    if logger is not None:
        logger.log("PSEI", "seed quarantined", seed=seed_path.name, staged_path=str(staged_path), reason=reason)
    return staged_path


def startup_quarantined_seed_names(config: RuntimeConfig) -> set[str]:
    names: set[str] = set()
    pending_dir = _staging_pending_dir(config)
    if pending_dir.exists():
        for path in pending_dir.iterdir():
            if path.is_file():
                names.add(path.name)

    manifest_path = _staging_manifest_path(config)
    if not manifest_path.exists():
        return names
    try:
        with manifest_path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    payload = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if str(payload.get("kind") or "").strip() != "startup_quarantine":
                    continue
                seed_name = str(payload.get("seed_name") or "").strip()
                if seed_name:
                    names.add(seed_name)
    except OSError:
        return names
    return names

def _preflight_seed(config: RuntimeConfig, seed_path: Path) -> dict[str, Any]:
    if config.replay_prepare_cmd:
        run_command(config.render_command(config.replay_prepare_cmd, seed_path=str(seed_path)), timeout=config.replay_prepare_timeout_sec or config.command_timeout_sec)
    if config.coverage_reset_cmd:
        run_command(config.render_command(config.coverage_reset_cmd, seed_path=str(seed_path)), timeout=config.coverage_reset_timeout_sec or config.command_timeout_sec)
    result = run_command(
        config.render_command(
            config.replay_cmd,
            seed_path=str(seed_path),
            protocol=config.protocol,
            host=config.replay_host,
            port=config.replay_port,
        ),
        timeout=config.replay_timeout_sec or config.command_timeout_sec,
    )
    if config.replay_cleanup_cmd:
        run_command(config.render_command(config.replay_cleanup_cmd, seed_path=str(seed_path)), timeout=config.replay_cleanup_timeout_sec or config.command_timeout_sec)

    parsed = try_load_json(result.stdout)
    if isinstance(parsed, dict):
        payload = dict(parsed)
    else:
        payload = {}
    payload.setdefault("command_returncode", result.returncode)
    payload.setdefault("stdout", result.stdout.strip())
    payload.setdefault("stderr", result.stderr.strip())
    payload.setdefault("seed_path", str(seed_path))
    return payload


def startup_seed_preflight_ok(config: RuntimeConfig, seed_path: Path) -> tuple[bool, dict[str, Any]]:
    payload = _preflight_seed(config, seed_path)
    ok_server_rcs = {int(value) for value in config.startup_ok_server_rcs}
    server_rc = int(payload.get("server_rc", -1))
    return server_rc in ok_server_rcs, payload

def _screen_initial_seed_corpus(config: RuntimeConfig, logger: RuntimeLogger) -> dict[str, Any]:
    pending_dir = _staging_pending_dir(config)
    consumed_dir = _staging_consumed_dir(config)
    pending_dir.mkdir(parents=True, exist_ok=True)
    consumed_dir.mkdir(parents=True, exist_ok=True)

    kept = 0
    quarantined = 0
    records: list[dict[str, Any]] = []
    ok_server_rcs = {int(value) for value in config.startup_ok_server_rcs}

    for seed_path in sorted(config.resolved_afl_input_dir.iterdir()):
        if not seed_path.is_file():
            continue
        payload = _preflight_seed(config, seed_path)
        server_rc = int(payload.get("server_rc", -1))
        ok = server_rc in ok_server_rcs
        record = {
            "seed_name": seed_path.name,
            "seed_path": str(seed_path),
            "server_rc": server_rc,
            "replay_rc": int(payload.get("replay_rc", payload.get("command_returncode", -1))),
            "kept": ok,
            "stdout": payload.get("stdout", ""),
            "stderr": payload.get("stderr", ""),
        }
        if ok:
            kept += 1
            records.append(record)
            continue

        staged_path = quarantine_seed_file(
            config,
            seed_path,
            reason="startup_quarantine",
            logger=logger,
            metadata={
                "server_rc": server_rc,
                "replay_rc": record["replay_rc"],
                "stdout": record["stdout"],
                "stderr": record["stderr"],
            },
        )
        quarantined += 1
        record["kept"] = False
        record["staged_path"] = str(staged_path)
        records.append(record)

    if kept <= 0:
        raise RuntimeError("all initial seeds were quarantined during startup preflight")

    summary = {
        "kept_count": kept,
        "quarantined_count": quarantined,
        "pending_dir": str(pending_dir),
        "consumed_dir": str(consumed_dir),
        "records": records,
    }
    (config.resolved_psei_output_dir / "startup_screening_summary.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return summary


def prepare_initial_corpus(config: RuntimeConfig, logger: RuntimeLogger, state: RuntimeStateDB | None = None) -> dict:
    """Prepare the initial seed directory before AFLNet startup."""
    config.ensure_directories()
    baseline_dir = config.resolved_baseline_seed_dir
    afl_input_dir = config.resolved_afl_input_dir
    psei_output_dir = config.resolved_psei_output_dir
    psei_output_dir.mkdir(parents=True, exist_ok=True)

    for old in afl_input_dir.iterdir() if afl_input_dir.exists() else []:
        if old.is_file():
            old.unlink()

    baseline_count = _copy_seed_dir(baseline_dir, afl_input_dir)
    logger.log("PSEI", "baseline seeds copied", baseline_dir=str(baseline_dir), count=baseline_count)

    result = generate_seeds(
        protocol=config.protocol,
        templates_file=str(config.resolved_templates_file),
        initial_sequences_file=str(config.resolved_initial_sequences_file) if config.resolved_initial_sequences_file else None,
        seed_corpus_dir=str(config.resolved_seed_corpus_dir or baseline_dir),
        seed=config.psei_seed,
        max_sequences=config.psei_max_sequences,
        use_llm_messages=config.psei_use_llm_messages,
    )
    seed_json_path = psei_output_dir / f"{config.protocol}_psei_seeds.json"
    seed_json_path.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    raw_dir = psei_output_dir / "raw"
    export_result = export_seed_json(str(seed_json_path), str(raw_dir), prefix="enriched")
    sync_seed_dir = raw_dir / "all"
    enriched_count = sum(1 for path in sync_seed_dir.iterdir() if path.is_file())
    delivery_mode = str(config.psei_seed_delivery_mode or "afl-input").strip().lower()
    injected_via_afl_input = 0
    async_summary: dict[str, Any] | None = None
    if delivery_mode == "afl-input":
        injected_via_afl_input = _copy_seed_dir(sync_seed_dir, afl_input_dir)
    elif delivery_mode == "async":
        async_summary = _stage_psei_async_seeds(config, sync_seed_dir)
    logger.log(
        "PSEI",
        "enriched seeds exported",
        seed_json=str(seed_json_path),
        raw_dir=str(raw_dir),
        enriched_count=enriched_count,
        delivery_mode=config.psei_seed_delivery_mode,
        afl_input_injected_count=injected_via_afl_input,
        async_seed_count=int((async_summary or {}).get("seed_count", 0) or 0),
    )

    llm_usage = ((result.get("stats") or {}).get("llm_usage") or {})
    psei_usage = llm_usage.get("psei") or {}
    if state is not None and psei_usage:
        state.add_llm_usage(
            module="psei",
            input_tokens=int(psei_usage.get("input_tokens", 0) or 0),
            output_tokens=int(psei_usage.get("output_tokens", 0) or 0),
            reasoning_tokens=int(psei_usage.get("reasoning_tokens", 0) or 0),
            calls=int(psei_usage.get("calls", 0) or 0),
            metadata={"subject": config.subject, "protocol": config.protocol},
        )

    screening_summary: dict[str, Any] = {
        "kept_count": baseline_count + injected_via_afl_input,
        "quarantined_count": 0,
        "pending_dir": str(_staging_pending_dir(config)),
        "consumed_dir": str(_staging_consumed_dir(config)),
        "records": [],
    }
    if config.startup_validate_initial_seeds:
        screening_summary = _screen_initial_seed_corpus(config, logger)
        logger.log(
            "PSEI",
            "startup seed screening done",
            kept_count=screening_summary.get("kept_count", 0),
            quarantined_count=screening_summary.get("quarantined_count", 0),
        )

    final_initial_seed_names = [path.name for path in sorted(afl_input_dir.iterdir()) if path.is_file()]
    summary = {
        "baseline_count": baseline_count,
        "initial_seed_names": final_initial_seed_names,
        "psei_stats": result.get("stats", {}),
        "seed_json": str(seed_json_path),
        "export_result": export_result,
        "seed_counts": {
            "baseline_copied": baseline_count,
            "original": export_result.get("original_files", 0),
            "llm_expanded": export_result.get("llm_expanded_files", 0),
            "traversal_interpolated": export_result.get("traversal_interpolated_files", 0),
            "all": export_result.get("written_files", 0),
        },
        "enriched_count": enriched_count,
        "afl_input_injected_count": injected_via_afl_input,
        "seed_delivery_mode": config.psei_seed_delivery_mode,
        "sync_seed_dir": str(sync_seed_dir),
        "async_seed_dir": str((async_summary or {}).get("async_seed_dir", "")),
        "async_injected_dir": str((async_summary or {}).get("async_injected_dir", "")),
        "async_seed_count": int((async_summary or {}).get("seed_count", 0) or 0),
        "afl_input_dir": str(afl_input_dir),
        "startup_screening": screening_summary,
    }
    (psei_output_dir / "runtime_summary.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return summary
