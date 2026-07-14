"""Standalone debug helpers for workflow2 runtime interfaces."""

from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Any

from .aflnet import AFLNetRuntime
from .command_utils import run_command, try_load_json
from .config import RuntimeConfig
from .coverage_replay import _normalize_snapshot
from .logging_utils import RuntimeLogger
from .psei_bootstrap import prepare_initial_corpus


_DRY_RUN_PATTERN = re.compile(r"Attempting dry run with 'id:\d+,orig:([^,\s'\"]+)'")


def _startup_seed_inventory(config: RuntimeConfig) -> tuple[str, int]:
    paths = [path for path in config.resolved_afl_input_dir.iterdir() if path.is_file()]
    if not paths:
        return "", 0
    newest = max(paths, key=lambda path: (path.stat().st_mtime_ns, path.name))
    return newest.name, len(paths)


def _read_log_text_since(path: Path, offset: int) -> str:
    if not path.exists():
        return ""
    with path.open("r", encoding="utf-8", errors="ignore") as fh:
        fh.seek(offset)
        return fh.read()


def _extract_current_seed_name(text: str) -> str:
    matches = _DRY_RUN_PATTERN.findall(text or "")
    if not matches:
        return ""
    return Path(matches[-1]).name.strip("'\" ,")


def _tail_text(path: Path, limit: int = 4000) -> str:
    if not path.exists():
        return ""
    text = path.read_text(encoding="utf-8", errors="ignore")
    if len(text) <= limit:
        return text
    return text[-limit:]


def _gcda_summary(config: RuntimeConfig) -> dict[str, Any]:
    if not config.coverage_reset_cmd:
        return {"gcda_dir": "", "gcda_count": 0, "gcda_files": []}
    gcov_dir = ""
    if len(config.coverage_reset_cmd) >= 2:
        gcov_dir = config.coverage_reset_cmd[1]
    if not gcov_dir:
        return {"gcda_dir": "", "gcda_count": 0, "gcda_files": []}
    base = Path(gcov_dir)
    files = sorted(str(p) for p in base.glob("*.gcda"))
    return {
        "gcda_dir": str(base),
        "gcda_count": len(files),
        "gcda_files": files[:20],
    }


def debug_aflnet_startup(
    config: RuntimeConfig,
    *,
    bootstrap: bool = False,
    logger: RuntimeLogger | None = None,
) -> dict[str, Any]:
    """Debug AFLNet startup until the main fuzzing loop is confirmed."""
    config.ensure_directories()
    logger = logger or RuntimeLogger(config.resolved_log_dir)

    bootstrap_summary = None
    if bootstrap:
        logger.log("DebugAFLNet", "bootstrap requested")
        bootstrap_summary = prepare_initial_corpus(config, logger, None)

    runtime = AFLNetRuntime(config, logger)
    started_at = time.time()
    runtime.start()

    stable = False
    fuzz_detected = False
    fuzz_detect_reason = "waiting_for_last_seed"
    max_wait_sec = 180.0
    try:
        stdout_path = runtime.log_path("afl-fuzz", "stdout")
        stderr_path = runtime.log_path("afl-fuzz", "stderr")
        stdout_offset = stdout_path.stat().st_size if stdout_path.exists() else 0
        stderr_offset = stderr_path.stat().st_size if stderr_path.exists() else 0
        expected_seed_name, expected_seed_count = _startup_seed_inventory(config)
        current_seed_name = ""
        next_status_log_at = time.time() + 30.0
        while True:
            if not runtime.fuzzer_alive():
                fuzz_detect_reason = "fuzzer_exited"
                break
            stdout_text = _read_log_text_since(stdout_path, stdout_offset)
            stderr_text = _read_log_text_since(stderr_path, stderr_offset)
            current_seed_name = _extract_current_seed_name(stdout_text) or _extract_current_seed_name(stderr_text)
            combined = f"{stdout_text}\n{stderr_text}"
            observed_seed_names = re.findall(_DRY_RUN_PATTERN, combined)
            if expected_seed_count > 0 and len(set(observed_seed_names)) >= expected_seed_count:
                fuzz_detected = True
                fuzz_detect_reason = "startup_seed_loaded"
                logger.log(
                    "DebugAFLNet",
                    "afl-fuzz loaded startup corpus",
                    expected_seed_name=expected_seed_name,
                    expected_seed_count=expected_seed_count,
                    observed_seed_count=len(set(observed_seed_names)),
                    current_seed_name=current_seed_name,
                )
                break
            now = time.time()
            if now - started_at >= max_wait_sec:
                fuzz_detect_reason = "timeout"
                break
            if now >= next_status_log_at:
                logger.log(
                    "DebugAFLNet",
                    "waiting for afl-fuzz startup corpus load",
                    expected_seed_name=expected_seed_name,
                    expected_seed_count=expected_seed_count,
                    observed_seed_count=len(set(observed_seed_names)),
                    current_seed_name=current_seed_name,
                )
                next_status_log_at = now + 30.0
            time.sleep(0.2)
        stable = runtime.fuzzer_alive()
        stats = runtime.parse_fuzzer_stats()
        plot = runtime.parse_plot_data()
        queue_dir = config.resolved_fuzzer_out_dir / "queue"
        queue_files = []
        if queue_dir.exists():
            queue_files = [p.name for p in sorted(queue_dir.iterdir()) if p.is_file()][:50]
        result = {
            "stable": stable,
            "fuzz_detected": fuzz_detected,
            "fuzz_detect_reason": fuzz_detect_reason,
            "max_wait_sec": max_wait_sec,
            "expected_last_seed_name": expected_seed_name,
            "expected_seed_count": expected_seed_count,
            "last_observed_seed_name": current_seed_name,
            "elapsed_sec": round(time.time() - started_at, 3),
            "returncode": runtime.fuzzer_returncode(),
            "fuzzer_alive": runtime.fuzzer_alive(),
            "fuzzer_stats_exists": (config.resolved_fuzzer_out_dir / "fuzzer_stats").exists(),
            "plot_data_exists": (config.resolved_fuzzer_out_dir / "plot_data").exists(),
            "fuzzer_stats": stats,
            "plot_data_last": plot,
            "queue_dir": str(queue_dir),
            "queue_count": len(queue_files),
            "queue_files": queue_files,
            "stdout_path": str(stdout_path),
            "stderr_path": str(stderr_path),
            "stdout_tail": _tail_text(stdout_path),
            "stderr_tail": _tail_text(stderr_path),
            "bootstrap_summary_path": str(config.resolved_psei_output_dir / "runtime_summary.json") if bootstrap_summary else "",
        }
        return result
    finally:
        runtime.stop()



def debug_replay_coverage(
    config: RuntimeConfig,
    *,
    seed_path: str,
    step_index: int | None = None,
    logger: RuntimeLogger | None = None,
) -> dict[str, Any]:
    """Debug replay and coverage capture for a single seed only."""
    config.ensure_directories()
    logger = logger or RuntimeLogger(config.resolved_log_dir)

    raw_path = Path(seed_path)
    if not raw_path.is_absolute():
        raw_path = (Path.cwd() / raw_path).resolve()
    if not raw_path.exists():
        raise FileNotFoundError(f"seed not found: {raw_path}")

    effective_seed = raw_path
    raw_text = raw_path.read_text(encoding="latin-1", errors="ignore")
    if step_index is not None:
        from .seed_utils import prefix_messages, split_seed_messages

        messages = split_seed_messages(config.protocol, raw_text)
        if step_index < 0 or step_index >= len(messages):
            raise ValueError(f"step_index out of range: {step_index} >= {len(messages)}")
        prefix_raw = prefix_messages(messages, step_index)
        prefix_path = config.resolved_temp_dir / f"debug-prefix-{raw_path.stem}-{step_index:03d}.raw"
        prefix_path.write_bytes(prefix_raw.encode("latin-1", errors="replace"))
        effective_seed = prefix_path

    prepare_res = None
    cleanup_res = None
    reset_res = None
    if config.replay_prepare_cmd:
        prepare_res = run_command(config.render_command(config.replay_prepare_cmd, seed_path=str(effective_seed)), timeout=config.replay_prepare_timeout_sec or config.command_timeout_sec)
    if config.coverage_reset_cmd:
        reset_res = run_command(config.render_command(config.coverage_reset_cmd, seed_path=str(effective_seed)), timeout=config.coverage_reset_timeout_sec or config.command_timeout_sec)

    gcda_before = _gcda_summary(config)
    replay_res = run_command(
        config.render_command(
            config.replay_cmd,
            seed_path=str(effective_seed),
            protocol=config.protocol,
            host=config.replay_host,
            port=config.replay_port,
        ),
        timeout=config.replay_timeout_sec or config.command_timeout_sec,
    )
    capture_res = run_command(
        config.render_command(
            config.coverage_capture_cmd,
            seed_path=str(effective_seed),
            step_index=step_index if step_index is not None else -1,
        ),
        env=dict(config.coverage_capture_env),
        timeout=config.coverage_capture_timeout_sec or config.command_timeout_sec,
    )
    gcda_after = _gcda_summary(config)
    if config.replay_cleanup_cmd:
        cleanup_res = run_command(config.render_command(config.replay_cleanup_cmd, seed_path=str(effective_seed)), timeout=config.replay_cleanup_timeout_sec or config.command_timeout_sec)

    payload = try_load_json(capture_res.stdout)
    if payload is None:
        payload = {
            "lines": [],
            "branches": [],
            "capture_stdout": capture_res.stdout,
            "capture_stderr": capture_res.stderr,
        }
    snapshot = _normalize_snapshot(payload if isinstance(payload, dict) else {"lines": [], "branches": []})

    result = {
        "seed_path": str(raw_path),
        "effective_seed_path": str(effective_seed),
        "step_index": step_index,
        "prepare": None if prepare_res is None else {
            "argv": prepare_res.argv,
            "returncode": prepare_res.returncode,
            "stdout": prepare_res.stdout,
            "stderr": prepare_res.stderr,
        },
        "coverage_reset": None if reset_res is None else {
            "argv": reset_res.argv,
            "returncode": reset_res.returncode,
            "stdout": reset_res.stdout,
            "stderr": reset_res.stderr,
        },
        "replay": {
            "argv": replay_res.argv,
            "returncode": replay_res.returncode,
            "stdout": replay_res.stdout,
            "stderr": replay_res.stderr,
        },
        "coverage_capture": {
            "argv": capture_res.argv,
            "returncode": capture_res.returncode,
            "stdout": capture_res.stdout,
            "stderr": capture_res.stderr,
        },
        "cleanup": None if cleanup_res is None else {
            "argv": cleanup_res.argv,
            "returncode": cleanup_res.returncode,
            "stdout": cleanup_res.stdout,
            "stderr": cleanup_res.stderr,
        },
        "gcda_before": gcda_before,
        "gcda_after": gcda_after,
        "captured_line_count": len(snapshot.lines),
        "captured_branch_count": len(snapshot.branches),
        "captured_lines_sample": sorted(snapshot.lines)[:50],
        "captured_branches_sample": sorted(snapshot.branches)[:50],
        "capture_payload": payload,
    }
    return result
