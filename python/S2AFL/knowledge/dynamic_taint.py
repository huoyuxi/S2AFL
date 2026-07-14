#!/usr/bin/env python3
"""
dynamic_taint.py

Import the instrumented dynamic-taint JSON described in the paper into the knowledge layer.

Inputs:
- `output/dynamic_taint_mapping/*_field_variable_map.json`
- `output/dynamic_taint_mapping/*_field_vars.json`
- legacy compatibility with `output/results/...`

Outputs:
- `knowledge/data/implementations/<Impl>/dynamic_taint/...`
- a normalized field-facts JSON that can later be merged with static-scan and CodeQL evidence.
"""

from __future__ import annotations

import glob
import json
import shutil
from pathlib import Path

from .implementation_registry import (
    LEGACY_RESULTS_ROOT,
    RESULTS_ROOT,
    ensure_knowledge_layout,
    implementation_meta,
    implementation_names,
    implementation_source_dir,
)
from .schema import SCHEMA_VERSION, make_field_fact, make_variable_flow


def _role(field_name: str) -> str:
    """Infer a coarse semantic role from the field name for later mutation ranking."""
    fl = (field_name or "").lower()
    if any(kw in fl for kw in ("length", "size", "count", "len", "max")):
        return "length"
    if "port" in fl:
        return "port"
    if any(kw in fl for kw in ("host", "ip", "domain", "uri", "url", "address")):
        return "address"
    if any(kw in fl for kw in ("user", "pass", "auth", "key", "token", "credential")):
        return "credential"
    if any(kw in fl for kw in ("file", "path", "name", "dir")):
        return "filename"
    if any(kw in fl for kw in ("command", "cmd", "method")):
        return "command"
    if any(kw in fl for kw in ("tag", "id", "seq", "num", "call", "branch")):
        return "identifier"
    return "parameter"


def _priority(role: str, risk_tags: list[str]) -> str:
    """Assign a baseline priority before static evidence refines it later."""
    if risk_tags:
        return "high"
    if role in ("length", "port", "filename", "credential"):
        return "medium"
    return "low"


def _guess_risk_tags(field_name: str, mapped_variables: list[dict]) -> list[str]:
    """Bootstrap lightweight risk tags from dynamic-taint evidence alone."""
    tags = set()
    lower_name = (field_name or "").lower()
    if any(token in lower_name for token in ("len", "size", "count", "max")):
        tags.add("length-sensitive")
    if any(token in lower_name for token in ("path", "file", "dir")):
        tags.add("path-sensitive")
    for flow in mapped_variables:
        for var in flow.get("variables", []):
            lower_var = (var or "").lower()
            if any(token in lower_var for token in ("len", "size", "count", "max")):
                tags.add("length-sensitive")
            if any(token in lower_var for token in ("path", "file", "dir")):
                tags.add("path-sensitive")
    return sorted(tags)


def _prefer_new_then_legacy(filename: str) -> Path:
    new_path = RESULTS_ROOT / filename
    if new_path.exists():
        return new_path
    legacy_path = LEGACY_RESULTS_ROOT / filename
    if legacy_path.exists():
        return legacy_path
    return new_path


def field_map_path(implementation: str) -> Path:
    """Locate the main dynamic-taint result for one implementation."""
    return _prefer_new_then_legacy(f"{implementation}_field_variable_map.json")


def field_vars_path(implementation: str) -> Path:
    """Locate the auxiliary dynamic-taint result for one implementation."""
    return _prefer_new_then_legacy(f"{implementation}_field_vars.json")


def normalize_dynamic_taint(data: dict) -> dict:
    """Normalize raw dynamic-taint JSON into a field-fact list."""
    implementation = data.get("implementation")
    if not implementation:
        raise ValueError("dynamic taint json missing implementation")
    meta = implementation_meta(implementation)
    protocol = data.get("protocol") or meta["protocol"]

    facts = []
    for mapping in data.get("field_mappings", []):
        command = mapping.get("command", "")
        template = mapping.get("template", "")
        filled_message = mapping.get("filled_message", "")
        for field in mapping.get("fields", []):
            flows = []
            related_functions = []
            handler_function = None
            for func in field.get("functions", []):
                flow = make_variable_flow(
                    function=func.get("function"),
                    relation=func.get("relation", "dataflow"),
                    variables=func.get("variables", []),
                    all_variables=func.get("all_variables", []),
                    source="dynamic_taint",
                    ida_ea=func.get("ida_ea"),
                    taint_offsets_in_field=func.get("taint_offsets_in_field", []),
                )
                flows.append(flow)
                if flow["function"]:
                    related_functions.append(flow["function"])
                if flow["relation"] == "handler" and flow["function"] and not handler_function:
                    handler_function = flow["function"]

            field_name = field.get("field_name", "")
            risk_tags = _guess_risk_tags(field_name, flows)
            field_role = _role(field_name)
            facts.append(
                make_field_fact(
                    implementation=implementation,
                    protocol=protocol,
                    field_name=field_name,
                    command=command,
                    byte_range=field.get("byte_range", []),
                    template=template,
                    filled_message=filled_message,
                    field_role=field_role,
                    handler_function=handler_function,
                    related_functions=sorted(set(related_functions)),
                    mapped_variables=flows,
                    program_points=[],
                    risk_tags=risk_tags,
                    evidence_sources=["dynamic_taint"],
                    mutation_priority=_priority(field_role, risk_tags),
                )
            )

    return {
        "schema_version": SCHEMA_VERSION,
        "generated_by": "s2afl-dynamic-taint-import",
        "implementation": implementation,
        "protocol": protocol,
        "source_dir": str(implementation_source_dir(implementation)),
        "field_fact_count": len(facts),
        "facts": facts,
    }


def import_dynamic_taint_for_implementation(implementation: str) -> dict:
    """Import and persist dynamic-taint results for one implementation."""
    paths = ensure_knowledge_layout(implementation)
    fmap = field_map_path(implementation)
    fvars = field_vars_path(implementation)
    result = {
        "implementation": implementation,
        "protocol": implementation_meta(implementation)["protocol"],
        "field_variable_map_found": fmap.exists(),
        "field_vars_found": fvars.exists(),
        "normalized_written": None,
    }
    if not fmap.exists():
        return result

    target_map = paths["dynamic_taint"] / "field_variable_map.json"
    shutil.copy2(fmap, target_map)

    if fvars.exists():
        shutil.copy2(fvars, paths["dynamic_taint"] / "field_vars.json")

    with fmap.open() as f:
        normalized = normalize_dynamic_taint(json.load(f))

    normalized_path = paths["dynamic_taint"] / "normalized_field_facts.json"
    normalized_path.write_text(json.dumps(normalized, indent=2, ensure_ascii=False) + "\n")
    result["normalized_written"] = str(normalized_path)
    result["field_fact_count"] = normalized["field_fact_count"]
    return result


def import_all_dynamic_taint() -> list[dict]:
    """Import dynamic-taint results for all registered implementations."""
    results = []
    for implementation in implementation_names():
        results.append(import_dynamic_taint_for_implementation(implementation))
    return results


def discover_dynamic_taint_inputs() -> list[str]:
    """List dynamic-taint mapping files already present in the workspace."""
    found = set(glob.glob(str(RESULTS_ROOT / "*_field_variable_map.json")))
    found.update(glob.glob(str(LEGACY_RESULTS_ROOT / "*_field_variable_map.json")))
    return sorted(found)
