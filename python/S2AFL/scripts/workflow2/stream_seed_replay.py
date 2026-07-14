#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import shutil
import signal
import importlib
import json
import re
import socket
import subprocess
import sys
import time
from pathlib import Path


def _load_seed_utils():
    repo_root = Path(__file__).resolve().parents[3]
    repo_root_str = str(repo_root)
    if repo_root_str not in sys.path:
        sys.path.insert(0, repo_root_str)
    return importlib.import_module("S2AFL.runtime.seed_utils")


seed_utils = _load_seed_utils()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Incrementally replay one workflow2 seed and capture per-step coverage.")
    default_capture_timeout = 0.0
    try:
        default_capture_timeout = float(os.environ.get("S2AFL_CAPTURE_TIMEOUT_SEC", "0") or "0")
    except ValueError:
        default_capture_timeout = 0.0
    parser.add_argument("--seed-path", required=True)
    parser.add_argument("--protocol", required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--trace-path", required=True)
    parser.add_argument("--transport", choices=("tcp", "udp"), default="tcp")
    parser.add_argument("--banner", choices=("none", "ftp", "smtp"), default="none")
    parser.add_argument("--local-port", type=int, default=0)
    parser.add_argument("--startup-delay", type=float, default=0.3)
    parser.add_argument("--inter-message-delay", type=float, default=0.1)
    parser.add_argument("--response-timeout", type=float, default=0.5)
    parser.add_argument("--reconnect-on-close", action="store_true")
    parser.add_argument("--gcov-flush-pid", type=int, default=0)
    parser.add_argument("--gcov-flush-timeout", type=float, default=5.0)
    parser.add_argument("--gcov-copy-from", default="")
    parser.add_argument("--gcov-copy-to", default="")
    parser.add_argument("--capture-timeout", type=float, default=default_capture_timeout)
    parser.add_argument("--capture-cmd", nargs=argparse.REMAINDER, required=True)
    return parser.parse_args()


def normalize_rtsp_urls(message: str, port: int) -> str:
    return re.sub(r"rtsp://([^/:\s]+):\d+", lambda m: f"rtsp://{m.group(1)}:{port}", message)


def _read_until_quiet(sock: socket.socket, *, timeout: float) -> tuple[bytes, bool]:
    sock.settimeout(timeout)
    chunks: list[bytes] = []
    peer_closed = False
    while True:
        try:
            data = sock.recv(4096)
        except socket.timeout:
            break
        if not data:
            peer_closed = True
            break
        chunks.append(data)
    return b"".join(chunks), peer_closed


def _read_http_like(sock: socket.socket, *, timeout: float) -> tuple[bytes, bool]:
    sock.settimeout(timeout)
    data = bytearray()
    peer_closed = False
    while b"\r\n\r\n" not in data:
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            return bytes(data), peer_closed
        if not chunk:
            return bytes(data), True
        data.extend(chunk)
    header_blob, body = bytes(data).split(b"\r\n\r\n", 1)
    headers = header_blob.decode("latin-1", errors="replace").split("\r\n")
    content_length = None
    connection_close = False
    for line in headers[1:]:
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        if key.strip().lower() == "connection" and value.strip().lower() == "close":
            connection_close = True
        if key.strip().lower() == "content-length":
            try:
                content_length = int(value.strip())
            except ValueError:
                content_length = None
            break
    if content_length is not None:
        while len(body) < content_length:
            try:
                chunk = sock.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                peer_closed = True
                break
            body += chunk
        return header_blob + b"\r\n\r\n" + body, peer_closed or connection_close
    tail, tail_closed = _read_until_quiet(sock, timeout=timeout)
    return header_blob + b"\r\n\r\n" + body + tail, peer_closed or tail_closed or connection_close


def _capture_snapshot(capture_cmd: list[str], *, timeout: float | None = None) -> tuple[int, dict]:
    started_at = time.monotonic()
    capture_env = dict(os.environ)
    if timeout is not None and timeout > 0:
        capture_env.setdefault('S2AFL_CAPTURE_TIMEOUT_SEC', str(timeout))
        capture_env.setdefault('S2AFL_GCOVR_TIMEOUT_SEC', str(timeout))
    try:
        proc = subprocess.run(capture_cmd, capture_output=True, text=True, timeout=timeout, env=capture_env)
    except subprocess.TimeoutExpired as exc:
        payload = {
            "lines": [],
            "branches": [],
            "error": f"capture-timeout:{timeout}",
            "gcovr_stdout": exc.stdout or "",
            "gcovr_stderr": exc.stderr or "",
            "elapsed_sec": time.monotonic() - started_at,
        }
        return 124, payload
    payload: dict
    try:
        payload = json.loads((proc.stdout or "").strip() or "{}")
        if not isinstance(payload, dict):
            payload = {"raw_payload": payload}
    except json.JSONDecodeError:
        text = (proc.stdout or "").strip()
        maybe_path = Path(text)
        if text and maybe_path.exists():
            try:
                payload = json.loads(maybe_path.read_text(encoding="utf-8"))
            except Exception as exc:
                payload = {"error": f"trace-json-load-failed: {exc}", "stdout": proc.stdout, "stderr": proc.stderr}
        else:
            payload = {"error": "capture-json-parse-failed", "stdout": proc.stdout, "stderr": proc.stderr}
    payload.setdefault("gcovr_stdout", proc.stdout)
    payload.setdefault("gcovr_stderr", proc.stderr)
    payload.setdefault("elapsed_sec", time.monotonic() - started_at)
    return proc.returncode, payload




def _descendant_pids(root_pid: int) -> list[int]:
    children: dict[int, list[int]] = {}
    for stat_path in Path("/proc").glob("[0-9]*/stat"):
        try:
            text = stat_path.read_text(encoding="utf-8", errors="replace")
            rparen = text.rfind(")")
            if rparen < 0:
                continue
            fields = text[rparen + 2 :].split()
            if len(fields) < 2:
                continue
            pid = int(stat_path.parent.name)
            ppid = int(fields[1])
            children.setdefault(ppid, []).append(pid)
        except Exception:
            continue
    result: list[int] = []
    stack = list(children.get(root_pid, []))
    while stack:
        pid = stack.pop()
        result.append(pid)
        stack.extend(children.get(pid, []))
    return result


def _flush_gcov(pid: int, *, timeout: float) -> dict:
    if pid <= 0:
        return {"enabled": False}
    targets = [pid, *_descendant_pids(pid)]
    signaled: list[int] = []
    errors: list[str] = []
    try:
        os.killpg(pid, signal.SIGUSR2)
        signaled.append(-pid)
    except ProcessLookupError:
        pass
    except PermissionError as exc:
        errors.append(f"pgid:{pid}:permission:{exc}")
    except Exception as exc:
        errors.append(f"pgid:{pid}:failed:{exc}")
    for target in targets:
        try:
            os.kill(target, signal.SIGUSR2)
            signaled.append(target)
        except ProcessLookupError:
            continue
        except PermissionError as exc:
            errors.append(f"{target}:permission:{exc}")
        except Exception as exc:
            errors.append(f"{target}:failed:{exc}")
    time.sleep(max(0.0, min(timeout, 0.2)))
    if signaled:
        return {"enabled": True, "returncode": 0, "signal": "SIGUSR2", "pids": signaled, "errors": errors}
    return {"enabled": True, "returncode": 1, "error": "gcov-flush-no-process", "pids": targets, "errors": errors}


def _copy_gcov_files(src_root: str, dst_root: str) -> dict:
    if not src_root or not dst_root:
        return {"enabled": False}
    src = Path(src_root)
    dst = Path(dst_root)
    if not src.exists():
        return {"enabled": True, "copied": 0, "error": f"missing-source:{src}"}
    copied = 0
    errors: list[str] = []
    for path in src.rglob("*.gcda"):
        try:
            rel = path.relative_to(src)
            target = dst / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, target)
            copied += 1
        except Exception as exc:
            if len(errors) < 5:
                errors.append(f"{path}:{exc}")
    return {"enabled": True, "copied": copied, "errors": errors}


def _connect_tcp(host: str, port: int, *, banner: str, timeout: float) -> socket.socket:
    sock = socket.create_connection((host, port), timeout=max(timeout, 1.0))
    if banner != "none":
        _read_until_quiet(sock, timeout=timeout)
    return sock


def _connect_tcp_with_retry(host: str, port: int, *, banner: str, timeout: float, deadline: float) -> socket.socket:
    last_error: OSError | None = None
    while time.monotonic() < deadline:
        try:
            return _connect_tcp(host, port, banner=banner, timeout=timeout)
        except OSError as exc:
            last_error = exc
            time.sleep(0.1)
    if last_error is not None:
        raise last_error
    raise ConnectionError(f"connect timeout for {host}:{port}")


def _response_reader(protocol: str):
    proto = protocol.upper()
    if proto in {"HTTP", "DAAP", "HTTP/1.1", "DAAP-HTTP", "RTSP"}:
        return _read_http_like
    return _read_until_quiet


def main() -> int:
    args = parse_args()
    seed_path = Path(args.seed_path)
    trace_path = Path(args.trace_path)
    capture_cmd = list(args.capture_cmd)
    if capture_cmd and capture_cmd[0] == "--":
        capture_cmd = capture_cmd[1:]
    if not capture_cmd:
        raise SystemExit("missing --capture-cmd payload")
    capture_timeout = args.capture_timeout if args.capture_timeout and args.capture_timeout > 0 else None

    raw = seed_path.read_bytes().decode("latin-1", errors="replace")
    messages = seed_utils.split_seed_messages(args.protocol, raw)
    if args.protocol.upper() == "RTSP":
        messages = [normalize_rtsp_urls(message, args.port) for message in messages]
    trace_path.parent.mkdir(parents=True, exist_ok=True)

    steps: list[dict] = []
    status = 0
    sender_error = ""
    response_reader = _response_reader(args.protocol)
    sock: socket.socket | None = None
    connect_deadline = time.monotonic() + max(2.0, args.startup_delay + args.response_timeout + 1.0)
    replay_started_at = time.monotonic()

    def ensure_tcp() -> socket.socket:
        nonlocal sock
        if sock is not None:
            return sock
        sock = _connect_tcp_with_retry(
            args.host,
            args.port,
            banner=args.banner,
            timeout=args.response_timeout,
            deadline=connect_deadline,
        )
        return sock

    def close_tcp() -> None:
        nonlocal sock
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
            sock = None

    try:
        time.sleep(max(0.0, args.startup_delay))
        if args.transport == "tcp":
            ensure_tcp()
        elif args.transport == "udp":
            udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            if args.local_port > 0:
                udp_sock.bind((args.host, args.local_port))
            udp_sock.settimeout(args.response_timeout)
            sock = udp_sock
        else:
            raise RuntimeError(f"unsupported transport: {args.transport}")

        for idx, message in enumerate(messages):
            method_name = seed_utils.message_method(message)
            preview_text = seed_utils.message_preview(message)
            send_error = ""
            response_error = ""
            response_preview = ""
            try:
                if args.transport == "tcp":
                    try:
                        ensure_tcp().sendall(message.encode("latin-1", errors="replace"))
                    except OSError as exc:
                        if not args.reconnect_on_close:
                            raise
                        close_tcp()
                        ensure_tcp().sendall(message.encode("latin-1", errors="replace"))
                    response_bytes, should_reconnect = response_reader(ensure_tcp(), timeout=args.response_timeout)
                    if args.reconnect_on_close and (should_reconnect or not response_bytes):
                        close_tcp()
                else:
                    assert sock is not None
                    sock.sendto(message.encode("latin-1", errors="replace"), (args.host, args.port))
                    try:
                        response_bytes = sock.recv(4096)
                    except socket.timeout:
                        response_bytes = b""
                response_preview = seed_utils.message_preview(response_bytes.decode("latin-1", errors="replace"))
            except Exception as exc:
                send_error = str(exc)
                response_error = str(exc)
                response_bytes = b""
                status = 1

            flush_payload = _flush_gcov(args.gcov_flush_pid, timeout=args.gcov_flush_timeout)
            copy_payload = _copy_gcov_files(args.gcov_copy_from, args.gcov_copy_to)
            capture_started_at = time.monotonic()
            capture_rc, capture_payload = _capture_snapshot(capture_cmd, timeout=capture_timeout)
            step_record = {
                "step_index": idx,
                "method": method_name,
                "message_preview": preview_text,
                "response_preview": response_preview,
                "send_error": send_error,
                "response_error": response_error,
                "gcov_flush": flush_payload,
                "gcov_copy": copy_payload,
                "capture_returncode": capture_rc,
                "capture_elapsed_sec": time.monotonic() - capture_started_at,
                "capture_payload": capture_payload,
            }
            steps.append(step_record)
            if capture_rc != 0 or capture_payload.get("error") or send_error:
                status = 1
                if send_error:
                    sender_error = send_error
                elif capture_payload.get("error"):
                    sender_error = str(capture_payload.get("error"))
                else:
                    sender_error = f"capture-rc={capture_rc}"
                break
            time.sleep(max(0.0, args.inter_message_delay))
    except Exception as exc:
        status = 1
        sender_error = str(exc)
    finally:
        close_tcp()

    trace = {
        "protocol": args.protocol,
        "host": args.host,
        "port": args.port,
        "local_port": args.local_port,
        "capture_timeout": args.capture_timeout,
        "replay_elapsed_sec": time.monotonic() - replay_started_at,
        "message_count": len(messages),
        "steps": steps,
        "sender_error": sender_error,
        "status": "ok" if status == 0 else "failed",
    }
    trace_path.write_text(json.dumps(trace, ensure_ascii=False), encoding="utf-8")
    print(json.dumps({"trace_path": str(trace_path), "step_count": len(steps), "status": trace["status"]}, ensure_ascii=False))
    return status


if __name__ == "__main__":
    raise SystemExit(main())
