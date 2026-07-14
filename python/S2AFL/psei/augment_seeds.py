#!/usr/bin/env python3
"""
Backup an original AFL seed directory and create an augmented copy with
offline-generated S2AFL seeds added in.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil


def augment_seed_directory(
    original_dir: str,
    generated_dir: str,
    output_dir: str,
    backup_dir: str | None = None,
) -> dict:
    if not os.path.isdir(original_dir):
        raise FileNotFoundError(f"original seed dir not found: {original_dir}")
    if not os.path.isdir(generated_dir):
        raise FileNotFoundError(f"generated seed dir not found: {generated_dir}")

    backup_dir = backup_dir or f"{original_dir.rstrip(os.sep)}.bak"

    if not os.path.exists(backup_dir):
        shutil.copytree(original_dir, backup_dir)

    if os.path.exists(output_dir):
        shutil.rmtree(output_dir)
    shutil.copytree(original_dir, output_dir)

    copied = []
    for name in sorted(os.listdir(generated_dir)):
        src = os.path.join(generated_dir, name)
        if not os.path.isfile(src):
            continue
        if not name.endswith(".raw"):
            continue
        dst = os.path.join(output_dir, name)
        if os.path.exists(dst):
            base, ext = os.path.splitext(name)
            idx = 1
            while True:
                candidate = os.path.join(output_dir, f"{base}_s2afl_{idx}{ext}")
                if not os.path.exists(candidate):
                    dst = candidate
                    break
                idx += 1
        shutil.copy2(src, dst)
        copied.append(dst)

    return {
        "original_dir": original_dir,
        "backup_dir": backup_dir,
        "generated_dir": generated_dir,
        "output_dir": output_dir,
        "original_files": len([x for x in os.listdir(original_dir) if x.endswith(".raw")]),
        "generated_files_added": len(copied),
        "final_files": len([x for x in os.listdir(output_dir) if x.endswith(".raw")]),
        "added_files": copied,
    }


def main():
    p = argparse.ArgumentParser(description="Backup and augment an AFL seed directory")
    p.add_argument("--original-dir", required=True)
    p.add_argument("--generated-dir", required=True)
    p.add_argument("--output-dir", required=True)
    p.add_argument("--backup-dir")
    args = p.parse_args()

    result = augment_seed_directory(
        original_dir=args.original_dir,
        generated_dir=args.generated_dir,
        output_dir=args.output_dir,
        backup_dir=args.backup_dir,
    )
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
