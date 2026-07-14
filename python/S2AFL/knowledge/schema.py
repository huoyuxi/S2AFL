#!/usr/bin/env python3
"""
schema.py

Shared schema helpers for normalized knowledge-layer JSON payloads.

Instead of introducing a large class hierarchy, this module provides factory helpers so that:
- dynamic-taint import
- static scan
- CodeQL import
- runtime knowledge retrieval
can all reuse one consistent location/evidence/field-fact structure.
"""

from __future__ import annotations

from pathlib import Path


SCHEMA_VERSION = "s2afl-kb-v2"


def _as_posix(path: str | Path | None) -> str | None:
    """Normalize serialized paths to POSIX form to avoid platform differences."""
    if path is None:
        return None
    return Path(path).as_posix()


def make_location(
    *,
    implementation: str,
    protocol: str,
    source_root: str | Path | None,
    relative_path: str | Path | None,
    line: int | None = None,
    column: int | None = None,
    function: str | None = None,
    code: str | None = None,
) -> dict:
    """
    Build a normalized source-location record.

    This is the core primitive used by the entire knowledge layer. Both static and dynamic evidence attach to it.
    """
    return {
        "implementation": implementation,
        "protocol": protocol,
        "source_root": _as_posix(source_root),
        "relative_path": _as_posix(relative_path),
        "line": line,
        "column": column,
        "function": function,
        "code": code,
    }


def make_program_point(
    *,
    point_type: str,
    implementation: str,
    protocol: str,
    source_root: str | Path | None,
    relative_path: str | Path | None,
    line: int | None,
    function: str | None,
    source: str,
    variables: list[str] | None = None,
    field_refs: list[dict] | None = None,
    cwe: str | None = None,
    vuln_func: str | None = None,
    description: str | None = None,
    condition: str | None = None,
    condition_expr: str | None = None,
    code: str | None = None,
    match_level: str | None = None,
    tags: list[str] | None = None,
) -> dict:
    """Build a normalized program-point record for boundary, vulnerability, or taint use."""
    return {
        "type": point_type,
        "location": make_location(
            implementation=implementation,
            protocol=protocol,
            source_root=source_root,
            relative_path=relative_path,
            line=line,
            function=function,
            code=code or condition,
        ),
        "source": source,
        "variables": list(variables or []),
        "field_refs": list(field_refs or []),
        "cwe": cwe,
        "vuln_func": vuln_func,
        "description": description,
        "condition": condition,
        "condition_expr": condition_expr,
        "match_level": match_level,
        "tags": list(tags or []),
    }


def make_variable_flow(
    *,
    function: str | None,
    relation: str,
    variables: list[str] | None = None,
    all_variables: list[str] | None = None,
    source: str,
    ida_ea: str | None = None,
    taint_offsets_in_field: list[int] | None = None,
    path: list[str] | None = None,
    distance: int | None = None,
) -> dict:
    """Build a normalized dynamic/static variable-flow record."""
    return {
        "function": function,
        "relation": relation,
        "variables": list(variables or []),
        "all_variables": list(all_variables or []),
        "source": source,
        "ida_ea": ida_ea,
        "taint_offsets_in_field": list(taint_offsets_in_field or []),
        "path": list(path or []),
        "distance": distance,
    }


def make_field_ref(field_name: str, command: str | None = None, byte_range: list[int] | None = None) -> dict:
    """Build a normalized field reference for reverse links from program points."""
    return {
        "field_name": field_name,
        "command": command,
        "byte_range": list(byte_range or []),
    }


def make_field_fact(
    *,
    implementation: str,
    protocol: str,
    field_name: str,
    command: str,
    byte_range: list[int] | None = None,
    template: str | None = None,
    filled_message: str | None = None,
    field_role: str | None = None,
    handler_function: str | None = None,
    related_functions: list[str] | None = None,
    mapped_variables: list[dict] | None = None,
    program_points: list[dict] | None = None,
    risk_tags: list[str] | None = None,
    evidence_sources: list[str] | None = None,
    mutation_priority: str | None = None,
) -> dict:
    """Build a normalized field fact consumed directly by runtime logic and KG queries."""
    return {
        "schema_version": SCHEMA_VERSION,
        "implementation": implementation,
        "protocol": protocol,
        "field_name": field_name,
        "parent_command": command,
        "byte_range": list(byte_range or []),
        "template": template,
        "filled_message": filled_message,
        "field_role": field_role,
        "handler_function": handler_function,
        "related_functions": list(related_functions or []),
        "mapped_variables": list(mapped_variables or []),
        "program_points": list(program_points or []),
        "risk_tags": list(risk_tags or []),
        "evidence_sources": list(evidence_sources or []),
        "mutation_priority": mutation_priority,
    }
