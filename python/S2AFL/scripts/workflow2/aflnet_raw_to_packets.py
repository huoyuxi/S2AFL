#!/usr/bin/env python3
"""Convert workflow2 textual seeds into AFLNet length-prefixed packets."""

from __future__ import annotations

import importlib
import struct
import sys
from pathlib import Path


def main() -> int:
    if len(sys.argv) != 4:
        print("usage: aflnet_raw_to_packets.py <raw_seed> <packet_seed> <protocol>", file=sys.stderr)
        return 2

    raw_path = Path(sys.argv[1])
    out_path = Path(sys.argv[2])
    protocol = sys.argv[3]

    repo_root = Path(__file__).resolve().parents[3]
    repo_root_str = str(repo_root)
    if repo_root_str not in sys.path:
        sys.path.insert(0, repo_root_str)
    seed_utils = importlib.import_module("S2AFL.runtime.seed_utils")

    raw = raw_path.read_bytes().decode("latin-1", errors="replace")
    messages = seed_utils.split_seed_messages(protocol, raw)
    if not messages:
        print(f"no replayable messages in {raw_path}", file=sys.stderr)
        return 1

    with out_path.open("wb") as out:
        for message in messages:
            data = message.encode("latin-1", errors="replace")
            if not data:
                continue
            out.write(struct.pack("<I", len(data)))
            out.write(data)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
