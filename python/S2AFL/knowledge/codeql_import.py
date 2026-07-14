#!/usr/bin/env python3
"""
codeql_import.py

Convert raw or partially normalized CodeQL output into the shared S2AFL schema.

Goals:
1. Persist data per implementation so later queries do not need filename heuristics.
2. Reuse the same location, field-reference, and variable-flow schema as dynamic taint and static scan.
3. Keep compatibility with legacy `queries.field_candidates / boundary_candidates / vuln_candidates`
   layouts so existing intermediate outputs remain usable.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .implementation_registry import (
    KNOWLEDGE_DATA_ROOT,
    ensure_knowledge_layout,
    implementation_codeql_dir,
    implementation_meta,
    implementation_source_dir,
)
from .schema import SCHEMA_VERSION, make_field_ref, make_program_point, make_variable_flow


CODEQL_SCHEMA_VERSION = "s2afl-codeql-v2"


def _list(value) -> list:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _normalize_related_functions(entry: dict) -> list[str]:
    """Normalize related-function fields across several CodeQL intermediate formats."""
    return [x for x in _list(entry.get("related_functions") or entry.get("functions")) if x]


def _normalize_mapped_variables(entry: dict) -> list[dict]:
    """Normalize mapped-variable records from legacy field-candidate payloads."""
    flows = []
    for mv in entry.get("mapped_variables", []):
        flows.append(
            make_variable_flow(
                function=mv.get("function"),
                relation=mv.get("relation", "dataflow"),
                variables=_list(mv.get("variables") or mv.get("variable")),
                all_variables=_list(mv.get("all_variables")),
                source="codeql_static",
                path=_list(mv.get("path")),
                distance=mv.get("distance"),
            )
        )
    return flows


def _normalize_point_entry(
    *,
    entry: dict,
    point_type: str,
    implementation: str,
    protocol: str,
    source_root: Path,
    default_field_name: str | None = None,
    default_command: str | None = None,
) -> dict:
    """Convert one CodeQL boundary/vuln/candidate record into a program point."""
    field_refs = []
    if default_field_name:
        field_refs.append(make_field_ref(default_field_name, default_command))
    for ref in _list(entry.get("candidate_fields") or entry.get("fields")):
        if isinstance(ref, dict):
            field_refs.append(
                make_field_ref(
                    field_name=ref.get("field_name") or ref.get("field", ""),
                    command=ref.get("command"),
                    byte_range=ref.get("byte_range"),
                )
            )
        else:
            field_refs.append(make_field_ref(str(ref)))

    return make_program_point(
        point_type=point_type,
        implementation=implementation,
        protocol=protocol,
        source_root=source_root,
        relative_path=entry.get("file"),
        line=entry.get("line"),
        function=entry.get("function"),
        source="codeql_static",
        variables=_list(entry.get("variables") or entry.get("reachable_variables") or entry.get("variable")),
        field_refs=field_refs,
        cwe=entry.get("cwe"),
        vuln_func=entry.get("vuln_func"),
        description=entry.get("description"),
        condition=entry.get("condition"),
        code=entry.get("code") or entry.get("condition"),
        match_level="codeql",
        tags=[point_type],
    )


def normalize_codeql_json(
    data: dict,
    implementation: str | None = None,
    protocol: str | None = None,
) -> dict:
    """Normalize raw or legacy CodeQL JSON into the v2 release structure."""
    if "queries" in data and "implementation" in data:
        implementation = implementation or data.get("implementation")
        protocol = protocol or data.get("protocol")
        source_root = implementation_source_dir(implementation)
        result = {
            "schema_version": CODEQL_SCHEMA_VERSION,
            "generated_by": data.get("generated_by", "s2afl-codeql-importer"),
            "implementation": implementation,
            "protocol": protocol,
            "source_dir": str(source_root),
            "queries": {
                "field_candidates": [],
                "boundary_candidates": [],
                "vuln_candidates": [],
            },
        }

        for entry in data.get("queries", {}).get("field_candidates", []):
            field_name = entry.get("field_name") or entry.get("field")
            command = entry.get("command")
            mapped_variables = _normalize_mapped_variables(entry)
            boundary_points = [
                _normalize_point_entry(
                    entry=bp,
                    point_type="boundary",
                    implementation=implementation,
                    protocol=protocol,
                    source_root=source_root,
                    default_field_name=field_name,
                    default_command=command,
                )
                for bp in _list(entry.get("boundary_points"))
            ]
            vuln_points = [
                _normalize_point_entry(
                    entry=vp,
                    point_type="vulnerability",
                    implementation=implementation,
                    protocol=protocol,
                    source_root=source_root,
                    default_field_name=field_name,
                    default_command=command,
                )
                for vp in _list(entry.get("vuln_points"))
            ]
            result["queries"]["field_candidates"].append(
                {
                    "field_name": field_name,
                    "command": command,
                    "related_functions": _normalize_related_functions(entry),
                    "mapped_variables": mapped_variables,
                    "boundary_points": boundary_points,
                    "vuln_points": vuln_points,
                }
            )

        for entry in data.get("queries", {}).get("boundary_candidates", []):
            result["queries"]["boundary_candidates"].append(
                _normalize_point_entry(
                    entry=entry,
                    point_type="boundary",
                    implementation=implementation,
                    protocol=protocol,
                    source_root=source_root,
                )
            )

        for entry in data.get("queries", {}).get("vuln_candidates", []):
            result["queries"]["vuln_candidates"].append(
                _normalize_point_entry(
                    entry=entry,
                    point_type="vulnerability",
                    implementation=implementation,
                    protocol=protocol,
                    source_root=source_root,
                )
            )
        return result

    implementation = implementation or data.get("implementation") or data.get("target") or "UNKNOWN"
    protocol = protocol or data.get("protocol") or implementation_meta(implementation).get("protocol", "UNKNOWN")
    source_root = implementation_source_dir(implementation)

    result = {
        "schema_version": CODEQL_SCHEMA_VERSION,
        "generated_by": "s2afl-codeql-importer",
        "implementation": implementation,
        "protocol": protocol,
        "source_dir": str(source_root),
        "queries": {
            "field_candidates": [],
            "boundary_candidates": [],
            "vuln_candidates": [],
        },
    }

    for entry in data.get("field_candidates") or data.get("fields") or []:
        field_name = entry.get("field_name") or entry.get("field")
        result["queries"]["field_candidates"].append(
            {
                "field_name": field_name,
                "command": entry.get("command"),
                "related_functions": _normalize_related_functions(entry),
                "mapped_variables": _normalize_mapped_variables(entry),
                "boundary_points": [
                    _normalize_point_entry(
                        entry=bp,
                        point_type="boundary",
                        implementation=implementation,
                        protocol=protocol,
                        source_root=source_root,
                        default_field_name=field_name,
                        default_command=entry.get("command"),
                    )
                    for bp in _list(entry.get("boundary_points"))
                ],
                "vuln_points": [
                    _normalize_point_entry(
                        entry=vp,
                        point_type="vulnerability",
                        implementation=implementation,
                        protocol=protocol,
                        source_root=source_root,
                        default_field_name=field_name,
                        default_command=entry.get("command"),
                    )
                    for vp in _list(entry.get("vuln_points"))
                ],
            }
        )

    for entry in data.get("boundary_candidates", []):
        result["queries"]["boundary_candidates"].append(
            _normalize_point_entry(
                entry=entry,
                point_type="boundary",
                implementation=implementation,
                protocol=protocol,
                source_root=source_root,
            )
        )

    for entry in data.get("vuln_candidates", []):
        result["queries"]["vuln_candidates"].append(
            _normalize_point_entry(
                entry=entry,
                point_type="vulnerability",
                implementation=implementation,
                protocol=protocol,
                source_root=source_root,
            )
        )

    return result


def convert_file(
    input_path: str,
    output_path: str | None = None,
    implementation: str | None = None,
    protocol: str | None = None,
) -> dict:
    """Convert one file and optionally write the normalized output."""
    with open(input_path) as f:
        data = json.load(f)
    normalized = normalize_codeql_json(data, implementation=implementation, protocol=protocol)
    if output_path:
        output = Path(output_path)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(normalized, indent=2, ensure_ascii=False) + "\n")
    return normalized


def import_codeql_for_implementation(
    input_path: str | Path,
    implementation: str,
    protocol: str | None = None,
) -> dict:
    """Import CodeQL results for one implementation and refresh compatibility copies."""
    protocol = protocol or implementation_meta(implementation)["protocol"]
    ensure_knowledge_layout(implementation)
    normalized = convert_file(str(input_path), implementation=implementation, protocol=protocol)

    per_impl_path = implementation_codeql_dir(implementation) / "normalized_codeql.json"
    compat_dir = KNOWLEDGE_DATA_ROOT / "codeql" / implementation
    compat_dir.mkdir(parents=True, exist_ok=True)
    compat_path = compat_dir / "normalized_codeql.json"
    flat_compat_path = KNOWLEDGE_DATA_ROOT / "codeql" / f"{implementation}.json"

    text = json.dumps(normalized, indent=2, ensure_ascii=False) + "\n"
    per_impl_path.write_text(text)
    compat_path.write_text(text)
    flat_compat_path.write_text(text)

    return {
        "implementation": implementation,
        "protocol": protocol,
        "written": [
            str(per_impl_path),
            str(compat_path),
            str(flat_compat_path),
        ],
        "field_candidates": len(normalized["queries"]["field_candidates"]),
        "boundary_candidates": len(normalized["queries"]["boundary_candidates"]),
        "vuln_candidates": len(normalized["queries"]["vuln_candidates"]),
    }


def main():
    parser = argparse.ArgumentParser(description="Normalize CodeQL JSON into the S2AFL unified schema")
    parser.add_argument("input", help="Raw or normalized CodeQL JSON")
    parser.add_argument("-o", "--output", help="Optional direct output path")
    parser.add_argument("--implementation")
    parser.add_argument("--protocol")
    parser.add_argument("--per-implementation", action="store_true", help="Write into S2AFL per-implementation directories")
    args = parser.parse_args()

    if args.per_implementation:
        if not args.implementation:
            parser.error("--implementation is required with --per-implementation")
        result = import_codeql_for_implementation(args.input, implementation=args.implementation, protocol=args.protocol)
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return

    normalized = convert_file(
        args.input,
        output_path=args.output,
        implementation=args.implementation,
        protocol=args.protocol,
    )
    print(json.dumps(normalized, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
