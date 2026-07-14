#!/usr/bin/env python3
from __future__ import annotations

import atexit
import json
import os
import re
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

BUILD_DIR = Path(sys.argv[1]) if len(sys.argv) > 1 else Path('.')
ROOT_DIR = Path(sys.argv[2]) if len(sys.argv) > 2 else BUILD_DIR
GCOVR_EXTRA_ARGS = sys.argv[3:]
TMP_PREFIX = 's2afl-gcovr-'
TMP_JSON: Path | None = None


def _stale_temp_age_sec() -> float:
    raw = os.environ.get('S2AFL_GCOVR_STALE_SEC', '').strip()
    if not raw:
        return 900.0
    try:
        return max(0.0, float(raw))
    except ValueError:
        return 900.0


def _gcovr_timeout_sec() -> float:
    raw = os.environ.get('S2AFL_GCOVR_TIMEOUT_SEC', '').strip()
    if not raw:
        raw = os.environ.get('S2AFL_CAPTURE_TIMEOUT_SEC', '').strip()
    if not raw:
        return 0.0
    try:
        return max(0.0, float(raw))
    except ValueError:
        return 0.0


def _unlink_tmp(path: Path | None) -> None:
    if path is None:
        return
    try:
        path.unlink(missing_ok=True)
    except Exception:
        pass


def _cleanup_current_tmp() -> None:
    global TMP_JSON
    _unlink_tmp(TMP_JSON)
    TMP_JSON = None


def _sweep_stale_temp_jsons(build_dir: Path, *, active_path: Path | None = None) -> int:
    removed = 0
    min_age_sec = _stale_temp_age_sec()
    now = time.time()
    for path in build_dir.glob(f'{TMP_PREFIX}*.json'):
        if active_path is not None and path == active_path:
            continue
        try:
            age_sec = max(0.0, now - path.stat().st_mtime)
        except FileNotFoundError:
            continue
        except Exception:
            continue
        if age_sec < min_age_sec:
            continue
        try:
            path.unlink()
            removed += 1
        except FileNotFoundError:
            continue
        except Exception:
            continue
    return removed


def _handle_termination(signum: int, _frame) -> None:
    _cleanup_current_tmp()
    raise SystemExit(128 + signum)


def _register_cleanup_handlers() -> None:
    atexit.register(_cleanup_current_tmp)
    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGQUIT):
        try:
            signal.signal(sig, _handle_termination)
        except Exception:
            continue


def _gcda_source_candidates(build_dir: Path, gcda_path: Path) -> list[str]:
    try:
        rel = gcda_path.relative_to(build_dir).as_posix()
    except ValueError:
        rel = gcda_path.as_posix()
    stem = rel[:-5] if rel.endswith('.gcda') else rel
    return [f'{stem}{suffix}' for suffix in ('.c', '.cc', '.cpp', '.cxx', '.m', '.mm')]


def load_allowlist(path_text: str) -> list[str]:
    path = Path(path_text.strip()) if path_text and path_text.strip() else None
    if path is None or not path.exists():
        return []
    items: list[str] = []
    for raw_line in path.read_text(encoding='utf-8', errors='ignore').splitlines():
        line = raw_line.strip().replace('\\', '/')
        if line and line not in items:
            items.append(line)
    return items


def partition_gcovr_args(argv: list[str]) -> tuple[list[str], list[str]]:
    filters: list[str] = []
    passthrough: list[str] = []
    idx = 0
    while idx < len(argv):
        arg = argv[idx]
        if arg == '--filter' and idx + 1 < len(argv):
            filters.append(argv[idx + 1])
            idx += 2
            continue
        passthrough.append(arg)
        idx += 1
    return filters, passthrough


def discover_search_paths(build_dir: Path, *, allowed_relative_paths: list[str] | None = None) -> tuple[list[str], int, int]:
    gcda_files = sorted(build_dir.rglob('*.gcda'))
    if allowed_relative_paths:
        allowed = {item.replace('\\', '/').strip() for item in allowed_relative_paths if item and item.strip()}
        matched = [
            path
            for path in gcda_files
            if any(candidate in allowed for candidate in _gcda_source_candidates(build_dir, path))
        ]
        if matched:
            gcda_files = matched
    collapsed: list[str] = []
    for parent in sorted(path.parent.as_posix() for path in gcda_files):
        if any(parent == existing or parent.startswith(existing + '/') for existing in collapsed):
            continue
        collapsed.append(parent)
    return collapsed, len(collapsed), len(gcda_files)


def normalize_file_name(root_dir: Path, name: str) -> str:
    text = (name or '').replace('\\', '/').strip()
    if not text:
        return text
    path = Path(text)
    if path.is_absolute():
        try:
            return path.relative_to(root_dir).as_posix()
        except Exception:
            return path.as_posix()
    if text.startswith('./'):
        text = text[2:]
    return text


def emit_error(message: str, *, stdout: str = '', stderr: str = '') -> int:
    print(json.dumps({'lines': [], 'branches': [], 'error': message, 'stdout': stdout, 'stderr': stderr}))
    return 0


def main() -> int:
    global TMP_JSON
    _register_cleanup_handlers()
    if not BUILD_DIR.exists():
        return emit_error(f'missing build dir: {BUILD_DIR}')
    if not ROOT_DIR.exists():
        return emit_error(f'missing root dir: {ROOT_DIR}')
    _sweep_stale_temp_jsons(BUILD_DIR)
    allowlist = load_allowlist(os.environ.get('S2AFL_COVERAGE_FILE_ALLOWLIST', ''))
    search_paths, gcda_dir_count, gcda_file_count = discover_search_paths(BUILD_DIR, allowed_relative_paths=allowlist)
    started_at = time.monotonic()
    if not search_paths:
        print(json.dumps({
            'lines': [],
            'branches': [],
            'raw_report': '',
            'gcovr_returncode': 0,
            'gcovr_stdout': '',
            'gcovr_stderr': '',
            'elapsed_sec': time.monotonic() - started_at,
            'gcda_dir_count': 0,
            'gcda_file_count': 0,
            'gcda_search_paths': [],
            'coverage_allowlist_count': len(allowlist),
        }, ensure_ascii=False))
        return 0

    tmp = tempfile.NamedTemporaryFile(prefix=TMP_PREFIX, suffix='.json', dir=str(BUILD_DIR), delete=False)
    TMP_JSON = Path(tmp.name)
    tmp.close()

    configured_filters, passthrough_args = partition_gcovr_args(GCOVR_EXTRA_ARGS)
    if allowlist:
        filter_args: list[str] = []
        for relative_path in allowlist:
            normalized = relative_path.replace('\\', '/').lstrip('./')
            filter_args.extend(['--filter', rf'(^|.*/){re.escape(normalized)}$'])
    else:
        filter_args = []
        for pattern in configured_filters:
            filter_args.extend(['--filter', pattern])
    cmd = ['gcovr', '-j', '1', '--gcov-ignore-parse-errors', '-r', str(ROOT_DIR), '--json', '-o', str(TMP_JSON), *filter_args, *passthrough_args, *search_paths]
    try:
        gcovr_timeout = _gcovr_timeout_sec()
        try:
            proc = subprocess.run(
                cmd,
                cwd=str(BUILD_DIR),
                capture_output=True,
                text=True,
                timeout=gcovr_timeout if gcovr_timeout > 0 else None,
            )
        except subprocess.TimeoutExpired as exc:
            return emit_error(
                f'gcovr-timeout:{gcovr_timeout}',
                stdout=exc.stdout or '',
                stderr=exc.stderr or '',
            )
        except FileNotFoundError as exc:
            return emit_error(f'gcovr-not-found: {exc}')
        except Exception as exc:
            return emit_error(f'gcovr-run-failed: {exc}')

        elapsed_sec = time.monotonic() - started_at
        if proc.returncode != 0 and not TMP_JSON.exists():
            return emit_error(proc.stderr.strip() or proc.stdout.strip() or f'gcovr rc={proc.returncode}', stdout=proc.stdout, stderr=proc.stderr)

        try:
            payload = json.loads(TMP_JSON.read_text(encoding='utf-8')) if TMP_JSON.exists() else {'files': []}
        except Exception as exc:
            return emit_error(f'json-parse-failed: {exc}', stdout=proc.stdout, stderr=proc.stderr)

        lines: list[str] = []
        branches: list[str] = []
        for file_entry in payload.get('files', []) or []:
            rel = normalize_file_name(ROOT_DIR, str(file_entry.get('file') or ''))
            if not rel:
                continue
            for line_entry in file_entry.get('lines', []) or []:
                if bool(line_entry.get('gcovr/noncode')):
                    continue
                line_no = int(line_entry.get('line_number') or 0)
                if line_no <= 0:
                    continue
                count = int(line_entry.get('count') or 0)
                if count > 0:
                    lines.append(f'{rel}:{line_no}')
                for idx, branch_entry in enumerate(line_entry.get('branches', []) or []):
                    bcount = int(branch_entry.get('count') or 0)
                    if bcount > 0:
                        branches.append(f'{rel}:{line_no}:{idx}')

        result = {
            'lines': sorted(set(lines)),
            'branches': sorted(set(branches)),
            'raw_report': '',
            'gcovr_returncode': proc.returncode,
            'gcovr_stdout': proc.stdout,
            'gcovr_stderr': proc.stderr,
            'elapsed_sec': elapsed_sec,
            'gcda_dir_count': gcda_dir_count,
            'gcda_file_count': gcda_file_count,
            'gcda_search_paths': search_paths,
            'coverage_allowlist_count': len(allowlist),
        }
        print(json.dumps(result, ensure_ascii=False))
        return 0
    finally:
        _cleanup_current_tmp()
        _sweep_stale_temp_jsons(BUILD_DIR)


if __name__ == '__main__':
    raise SystemExit(main())
