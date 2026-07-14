#!/usr/bin/env python3
from __future__ import annotations

import atexit
import json
import os
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

GCOV_DIR = Path(sys.argv[1]) if len(sys.argv) > 1 else Path('./build/Source/Release')
ROOT_DIR = Path(sys.argv[2]) if len(sys.argv) > 2 else Path('./build/Source')
TMP_PREFIX = 's2afl-lightftp-gcovr-'
TMP_JSON: Path | None = None


def _stale_temp_age_sec() -> float:
    raw = os.environ.get('S2AFL_GCOVR_STALE_SEC', '').strip()
    if not raw:
        return 900.0
    try:
        return max(0.0, float(raw))
    except ValueError:
        return 900.0


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


def _sweep_stale_temp_jsons(gcov_dir: Path, *, active_path: Path | None = None) -> int:
    removed = 0
    min_age_sec = _stale_temp_age_sec()
    now = time.time()
    for path in gcov_dir.glob(f'{TMP_PREFIX}*.json'):
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


def normalize_file_name(name: str) -> str:
    text = (name or '').replace('\\', '/').strip()
    if not text:
        return text
    if text.startswith('Source/'):
        return text
    if text.startswith('./'):
        text = text[2:]
    return f'Source/{text}'


def emit_error(message: str, *, stdout: str = '', stderr: str = '') -> int:
    print(json.dumps({'lines': [], 'branches': [], 'error': message, 'stdout': stdout, 'stderr': stderr}))
    return 0


def main() -> int:
    global TMP_JSON
    _register_cleanup_handlers()
    if not GCOV_DIR.exists():
        return emit_error(f'missing dir: {GCOV_DIR}')
    if not ROOT_DIR.exists():
        return emit_error(f'missing root dir: {ROOT_DIR}')
    _sweep_stale_temp_jsons(GCOV_DIR)
    tmp = tempfile.NamedTemporaryFile(prefix=TMP_PREFIX, suffix='.json', dir=str(GCOV_DIR), delete=False)
    TMP_JSON = Path(tmp.name)
    tmp.close()

    cmd = ['gcovr', '-r', str(ROOT_DIR), '--json-pretty', '-o', str(TMP_JSON)]
    try:
        try:
            proc = subprocess.run(cmd, cwd=str(GCOV_DIR), capture_output=True, text=True)
        except FileNotFoundError as exc:
            return emit_error(f'gcovr-not-found: {exc}')
        except Exception as exc:
            return emit_error(f'gcovr-run-failed: {exc}')

        if proc.returncode != 0 and not TMP_JSON.exists():
            return emit_error(proc.stderr.strip() or proc.stdout.strip() or f'gcovr rc={proc.returncode}', stdout=proc.stdout, stderr=proc.stderr)

        try:
            payload = json.loads(TMP_JSON.read_text(encoding='utf-8')) if TMP_JSON.exists() else {'files': []}
        except Exception as exc:
            return emit_error(f'json-parse-failed: {exc}', stdout=proc.stdout, stderr=proc.stderr)

        lines: list[str] = []
        branches: list[str] = []
        for file_entry in payload.get('files', []) or []:
            rel = normalize_file_name(str(file_entry.get('file') or ''))
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
        }
        print(json.dumps(result, ensure_ascii=False))
        return 0
    finally:
        _cleanup_current_tmp()
        _sweep_stale_temp_jsons(GCOV_DIR)


if __name__ == '__main__':
    raise SystemExit(main())
