#!/usr/bin/env python3
"""
Export S2AFL PSEI seed JSON into AFLNet/ChatAFL raw seed files.

Output layout:
  - original/
  - llm_expanded/
  - traversal_interpolated/
  - all/
"""

from __future__ import annotations

import argparse
import json
import os
import shutil


def _normalize_message_payload(protocol: str, message: str) -> str:
    proto = str(protocol or "").upper()
    text = str(message or "")
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    normalized = text.replace("\n", "\r\n")
    if proto == "FTP":
        return normalized.rstrip("\r\n") + "\r\n"
    if proto == "SMTP":
        body = normalized.rstrip("\r\n")
        if body.upper().startswith("DATA\r\n"):
            if not body.endswith("\r\n.\r\n"):
                if body.endswith("\r\n."):
                    body += "\r\n"
                elif body.endswith("."):
                    body = body[:-1] + "\r\n.\r\n"
                else:
                    body += "\r\n.\r\n"
            return body
        return body + "\r\n"
    if proto in {"RTSP", "HTTP", "SIP", "DAAP", "HTTP/1.1", "DAAP-HTTP"}:
        body = normalized
        if "\r\n\r\n" in body:
            head, tail = body.split("\r\n\r\n", 1)
            return head.rstrip("\r\n") + "\r\n\r\n" + tail
        return body.rstrip("\r\n") + "\r\n\r\n"
    return normalized


def _sequence_payload(protocol: str, messages) -> str:
    return "".join(_normalize_message_payload(protocol, msg.get("message", "")) for msg in messages)


def _reset_dir(path: str) -> None:
    if os.path.isdir(path):
        shutil.rmtree(path)
    os.makedirs(path, exist_ok=True)


def _write_sequence_bucket(protocol, sequences, output_dir, file_prefix):
    os.makedirs(output_dir, exist_ok=True)
    written = []
    for idx, seq in enumerate(sequences):
        messages = seq.get("messages", [])
        payload = _sequence_payload(protocol, messages)
        if not payload:
            continue
        out_path = os.path.join(output_dir, f"{file_prefix}_{idx:03d}.raw")
        with open(out_path, "wb") as f:
            f.write(payload.encode("latin-1", errors="replace"))
        written.append(
            {
                "path": out_path,
                "methods": seq.get("methods", []),
                "bytes": len(payload.encode("latin-1", errors="replace")),
            }
        )
    return written


def _copy_seed_bucket(seed_dir: str, output_dir: str):
    os.makedirs(output_dir, exist_ok=True)
    written = []
    for name in sorted(os.listdir(seed_dir)):
        src = os.path.join(seed_dir, name)
        if not os.path.isfile(src):
            continue
        dst = os.path.join(output_dir, name)
        shutil.copy2(src, dst)
        written.append(
            {
                "path": dst,
                "methods": [],
                "bytes": os.path.getsize(dst),
            }
        )
    return written


def export_seed_json(seed_json_path: str, output_dir: str, prefix: str | None = None) -> dict:
    with open(seed_json_path) as f:
        data = json.load(f)

    protocol = data.get("protocol", "UNKNOWN")
    file_prefix = prefix or protocol.lower()
    seed_corpus_dir = data.get("seed_corpus_dir") or ""

    os.makedirs(output_dir, exist_ok=True)

    original_dir = os.path.join(output_dir, "original")
    llm_dir = os.path.join(output_dir, "llm_expanded")
    traversal_dir = os.path.join(output_dir, "traversal_interpolated")
    all_dir = os.path.join(output_dir, "all")
    for bucket_dir in (original_dir, llm_dir, traversal_dir, all_dir):
        _reset_dir(bucket_dir)

    if seed_corpus_dir and os.path.isdir(seed_corpus_dir):
        original = _copy_seed_bucket(seed_corpus_dir, original_dir)
        original_source = "seed_corpus_dir"
    else:
        original = _write_sequence_bucket(protocol, data.get("original_sequences", []), original_dir, f"{file_prefix}_orig")
        original_source = "rendered_original_sequences"

    llm_expanded = _write_sequence_bucket(protocol, data.get("llm_expanded_sequences", []), llm_dir, f"{file_prefix}_llm")
    traversal = _write_sequence_bucket(protocol, data.get("traversal_interpolated_sequences", []), traversal_dir, f"{file_prefix}_trav")

    all_written = []
    for bucket in (original, llm_expanded, traversal):
        for entry in bucket:
            src = entry["path"]
            name = os.path.basename(src)
            dst = os.path.join(all_dir, name)
            if os.path.exists(dst):
                raise ValueError(f"duplicate seed filename across export buckets: {name}")
            shutil.copy2(src, dst)
            merged = dict(entry)
            merged["path"] = dst
            all_written.append(merged)

    return {
        "protocol": protocol,
        "seed_json": seed_json_path,
        "output_dir": output_dir,
        "original_dir": original_dir,
        "llm_expanded_dir": llm_dir,
        "traversal_interpolated_dir": traversal_dir,
        "all_dir": all_dir,
        "original_source": original_source,
        "written_files": len(all_written),
        "original_files": len(original),
        "llm_expanded_files": len(llm_expanded),
        "traversal_interpolated_files": len(traversal),
        "files": all_written,
    }


def main():
    p = argparse.ArgumentParser(description="Export PSEI seed JSON into AFLNet raw seeds")
    p.add_argument("input", help="PSEI seed JSON file")
    p.add_argument("-o", "--output-dir", required=True, help="Directory for .raw seed files")
    p.add_argument("--prefix", help="Filename prefix")
    args = p.parse_args()

    result = export_seed_json(args.input, args.output_dir, args.prefix)
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
