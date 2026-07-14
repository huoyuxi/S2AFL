#!/usr/bin/env python3
"""
implementation_registry.py

Central registry for implementation-level metadata and directory layout rules in S2AFL.

Design goals:
1. Store dynamic taint, static scan, CodeQL, and vulnerability facts per implementation.
2. Let runtime code and offline preprocessing read from the same implementation list.
3. Normalize knowledge-layer scanner inputs under `S2AFL/implementations/src/...`.

Notes:
- The implementation list is defined in one module instead of being duplicated across scripts.
- Some implementations, such as BFTPD, may not yet have a normalized standalone source tree in the workspace,
  but the release still keeps their knowledge-directory skeleton so callers do not need to change later.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path


S2AFL_ROOT = Path(__file__).resolve().parent.parent
PROJECT_ROOT = S2AFL_ROOT.parent
KNOWLEDGE_ROOT = S2AFL_ROOT / "knowledge"
KNOWLEDGE_DATA_ROOT = KNOWLEDGE_ROOT / "data"
IMPLEMENTATIONS_ROOT = S2AFL_ROOT / "implementations"
IMPLEMENTATION_SRC_ROOT = IMPLEMENTATIONS_ROOT / "src"
LEGACY_SRC_ROOT = S2AFL_ROOT / "agent" / "data" / "src"
DYNAMIC_TAINT_MAPPING_ROOT = S2AFL_ROOT / "output" / "dynamic_taint_mapping"
LEGACY_RESULTS_ROOT = S2AFL_ROOT / "output" / "results"
RESULTS_ROOT = DYNAMIC_TAINT_MAPPING_ROOT


# Use implementation names as stable primary keys and uppercase protocol names.
IMPLEMENTATIONS: dict[str, dict] = {
    "LightFTP": {
        "protocol": "FTP",
        "source_candidates": [
            LEGACY_SRC_ROOT / "FTP" / "LightFTP",
        ],
        "source_relpath": Path("FTP") / "LightFTP",
        "notes": "LightFTP target source tree",
    },
    "BFTPD": {
        "protocol": "FTP",
        "source_candidates": [],
        "source_relpath": Path("FTP") / "BFTPD",
        "notes": "Dynamic taint exists, but a normalized standalone source tree is not yet located in the workspace.",
    },
    "ProFTPD": {
        "protocol": "FTP",
        "source_candidates": [
            LEGACY_SRC_ROOT / "FTP" / "proftpd",
        ],
        "source_relpath": Path("FTP") / "ProFTPD",
        "notes": "Canonicalized from legacy folder name proftpd",
    },
    "PureFTPD": {
        "protocol": "FTP",
        "source_candidates": [
            LEGACY_SRC_ROOT / "FTP" / "pure-ftpd",
        ],
        "source_relpath": Path("FTP") / "PureFTPD",
        "notes": "Canonicalized from legacy folder name pure-ftpd",
    },
    "DAAPD": {
        "protocol": "DAAP",
        "source_candidates": [
            LEGACY_SRC_ROOT / "FTP" / "forked-daapd",
        ],
        "source_relpath": Path("DAAP") / "DAAPD",
        "notes": "Source tree is forked-daapd / Owntone, protocol is DAAP rather than FTP.",
    },
    "Lighttpd1": {
        "protocol": "HTTP",
        "source_candidates": [
            LEGACY_SRC_ROOT / "HTTP" / "lighttpd1",
        ],
        "source_relpath": Path("HTTP") / "Lighttpd1",
        "notes": "HTTP implementation kept for completeness of the KB",
    },
    "Live555": {
        "protocol": "RTSP",
        "source_candidates": [
            LEGACY_SRC_ROOT / "RTSP" / "live",
        ],
        "source_relpath": Path("RTSP") / "Live555",
        "notes": "Canonicalized from legacy folder name live",
    },
    "Kamailio": {
        "protocol": "SIP",
        "source_candidates": [
            LEGACY_SRC_ROOT / "SIP" / "kamailio",
        ],
        "source_relpath": Path("SIP") / "Kamailio",
        "notes": "Canonicalized from legacy folder name kamailio",
    },
    "Exim": {
        "protocol": "SMTP",
        "source_candidates": [
            LEGACY_SRC_ROOT / "SMTP" / "exim",
        ],
        "source_relpath": Path("SMTP") / "Exim",
        "notes": "Canonicalized from legacy folder name exim",
    },
}


def implementation_names() -> list[str]:
    """Return implementation names in a stable sorted order."""
    return sorted(IMPLEMENTATIONS.keys())


def implementation_meta(implementation: str) -> dict:
    """Return the registry entry for one implementation."""
    if implementation not in IMPLEMENTATIONS:
        raise KeyError(f"Unknown implementation: {implementation}")
    meta = dict(IMPLEMENTATIONS[implementation])
    meta["implementation"] = implementation
    return meta


def implementation_protocol(implementation: str) -> str:
    """Return the protocol associated with an implementation."""
    return implementation_meta(implementation)["protocol"]


def implementation_source_dir(implementation: str) -> Path:
    """Return the normalized source-tree path for an implementation."""
    relpath = implementation_meta(implementation)["source_relpath"]
    return IMPLEMENTATION_SRC_ROOT / relpath


def implementation_data_dir(implementation: str) -> Path:
    """Return the per-implementation knowledge root."""
    return KNOWLEDGE_DATA_ROOT / "implementations" / implementation


def implementation_metadata_path(implementation: str) -> Path:
    """Return the metadata file path for an implementation."""
    return implementation_data_dir(implementation) / "metadata.json"


def implementation_dynamic_dir(implementation: str) -> Path:
    """Return the dynamic-taint knowledge directory."""
    return implementation_data_dir(implementation) / "dynamic_taint"


def implementation_static_dir(implementation: str) -> Path:
    """Return the static-scan knowledge directory."""
    return implementation_data_dir(implementation) / "static_scan"


def implementation_codeql_dir(implementation: str) -> Path:
    """Return the normalized CodeQL output directory."""
    return implementation_data_dir(implementation) / "codeql"


def implementation_vul_dir(implementation: str) -> Path:
    """Return the per-implementation vulnerability/boundary facts directory."""
    return implementation_data_dir(implementation) / "vul"


def compatibility_vul_dir(implementation: str) -> Path:
    """Return the legacy-compatible per-implementation vulnerability directory."""
    return KNOWLEDGE_DATA_ROOT / "vuln" / implementation


def compatibility_codeql_dir(implementation: str) -> Path:
    """Return the legacy-compatible per-implementation CodeQL directory."""
    return KNOWLEDGE_DATA_ROOT / "codeql" / implementation


def ensure_knowledge_layout(implementation: str) -> dict[str, Path]:
    """
    Create the knowledge-directory skeleton for one implementation.

    This lets dynamic taint, static scan, and CodeQL importers write into one shared layout without repeating mkdir logic.
    """
    paths = {
        "data": implementation_data_dir(implementation),
        "dynamic_taint": implementation_dynamic_dir(implementation),
        "static_scan": implementation_static_dir(implementation),
        "codeql": implementation_codeql_dir(implementation),
        "vul": implementation_vul_dir(implementation),
        "compat_vul": compatibility_vul_dir(implementation),
        "compat_codeql": compatibility_codeql_dir(implementation),
    }
    for path in paths.values():
        path.mkdir(parents=True, exist_ok=True)
    return paths


def resolve_existing_source(implementation: str) -> Path | None:
    """Resolve the first source-tree candidate that exists in the workspace."""
    for candidate in implementation_meta(implementation).get("source_candidates", []):
        if candidate.exists():
            return candidate
    return None


def sync_one_source_tree(implementation: str, overwrite: bool = False) -> dict:
    """
    Sync one legacy source tree into `implementations/src`.

    This is purely a filesystem organization step and does not rewrite source content.
    """
    meta = implementation_meta(implementation)
    src = resolve_existing_source(implementation)
    dst = implementation_source_dir(implementation)
    dst.parent.mkdir(parents=True, exist_ok=True)

    result = {
        "implementation": implementation,
        "protocol": meta["protocol"],
        "source_found": bool(src),
        "source_src": str(src) if src else None,
        "source_dst": str(dst),
        "copied": False,
        "already_exists": dst.exists(),
    }

    if not src:
        return result

    if dst.exists() and not overwrite:
        result["copied"] = False
        return result

    if dst.exists() and overwrite:
        shutil.rmtree(dst)

    shutil.copytree(src, dst, symlinks=True)
    result["copied"] = True
    result["already_exists"] = False
    return result


def write_metadata(implementation: str) -> Path:
    """Write implementation metadata into the knowledge directory."""
    meta = implementation_meta(implementation)
    source_dir = implementation_source_dir(implementation)
    paths = ensure_knowledge_layout(implementation)
    payload = {
        "implementation": implementation,
        "protocol": meta["protocol"],
        "source_dir": str(source_dir),
        "source_exists": source_dir.exists(),
        "dynamic_taint_dir": str(paths["dynamic_taint"]),
        "static_scan_dir": str(paths["static_scan"]),
        "codeql_dir": str(paths["codeql"]),
        "vul_dir": str(paths["vul"]),
        "notes": meta.get("notes", ""),
    }
    path = implementation_metadata_path(implementation)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n")
    return path


def sync_all_sources(overwrite: bool = False) -> list[dict]:
    """Sync all implementation source trees and refresh their metadata files."""
    results = []
    for implementation in implementation_names():
        ensure_knowledge_layout(implementation)
        result = sync_one_source_tree(implementation, overwrite=overwrite)
        write_metadata(implementation)
        results.append(result)
    return results
