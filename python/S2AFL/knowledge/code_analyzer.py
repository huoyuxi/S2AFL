#!/usr/bin/env python3
"""
code_analyzer.py

Scan source code per implementation, extract boundary/vulnerability points, and align them with dynamic-taint field mappings.

This release does not try to produce a flat JSON that merely looks like CodeQL output.
Instead, it emits normalized program points and field facts that the full knowledge layer can reuse.

Inputs:
- `S2AFL/implementations/src/<PROTO>/<Impl>/...`
- `output/dynamic_taint_mapping/<Impl>_field_variable_map.json`

Outputs:
- `knowledge/data/implementations/<Impl>/static_scan/static_scan.json`
- `knowledge/data/implementations/<Impl>/vul/boundary_vuln_map.json`
- legacy compatibility path: `knowledge/data/facts/<Impl>_boundary_vuln_map.json`
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

from .implementation_registry import (
    KNOWLEDGE_DATA_ROOT,
    ensure_knowledge_layout,
    implementation_meta,
    implementation_source_dir,
    implementation_static_dir,
    implementation_vul_dir,
)
from .schema import SCHEMA_VERSION, make_field_ref, make_program_point


_VULN_PATTERNS = [
    (r"\bstrcpy\s*\(", "strcpy", "CWE-120", "buffer overflow: unbounded copy"),
    (r"\bstrncpy\s*\(", "strncpy", "CWE-120", "buffer overflow: missing null terminator"),
    (r"\bsprintf\s*\(", "sprintf", "CWE-120", "buffer overflow: unbounded format"),
    (r"\bvsprintf\s*\(", "vsprintf", "CWE-120", "buffer overflow: unbounded format"),
    (r"\bgets\s*\(", "gets", "CWE-120", "buffer overflow: unbounded stdin read"),
    (r"\bstrcat\s*\(", "strcat", "CWE-120", "buffer overflow: unbounded concat"),
    (r"\bstrncat\s*\(", "strncat", "CWE-120", "buffer overflow: length miscalculation"),
    (r"\bmemcpy\s*\(", "memcpy", "CWE-120", "buffer overflow: check size parameter"),
    (r"\bmemmove\s*\(", "memmove", "CWE-120", "buffer overflow: check size parameter"),
    (r"\bscanf\s*\(", "scanf", "CWE-120", "buffer overflow: unbounded input"),
    (r"\bsscanf\s*\(", "sscanf", "CWE-120", "buffer overflow: unbounded input parse"),
    (r"\brecv\s*\(", "recv", "CWE-20", "tainted input from network"),
    (r"\brecvfrom\s*\(", "recvfrom", "CWE-20", "tainted input from network"),
    (r"\bread\s*\(", "read", "CWE-20", "tainted input from fd"),
    (r"\bfgets\s*\(", "fgets", "CWE-20", "tainted input from file/stream"),
    (r"\batoi\s*\(", "atoi", "CWE-190", "integer overflow: no error checking"),
    (r"\bstrtol\s*\(", "strtol", "CWE-190", "integer conversion: check overflow"),
    (r"\bstrtoul\s*\(", "strtoul", "CWE-190", "integer conversion: check overflow"),
    (r"\bmalloc\s*\(", "malloc", "CWE-789", "memory allocation: size from input"),
    (r"\brealloc\s*\(", "realloc", "CWE-789", "memory reallocation: size from input"),
    (r"\brealpath\s*\(", "realpath", "CWE-22", "path traversal"),
    (r"\baccess\s*\(", "access", "CWE-367", "TOCTOU race condition"),
    (r"\bchmod\s*\(", "chmod", "CWE-732", "incorrect permission assignment"),
    (r"\bchown\s*\(", "chown", "CWE-732", "incorrect permission assignment"),
    (r"\bexecl\s*\(", "execl", "CWE-78", "OS command injection"),
    (r"\bexecv\s*\(", "execv", "CWE-78", "OS command injection"),
    (r"\bsystem\s*\(", "system", "CWE-78", "OS command injection"),
    (r"\bpopen\s*\(", "popen", "CWE-78", "OS command injection"),
    (r"\bsnprintf\s*\(", "snprintf", "CWE-134", "format string: check size"),
    (r"\bfprintf\s*\(", "fprintf", "CWE-134", "format string: check format"),
    (r"\bprintf\s*\(", "printf", "CWE-134", "format string: check format"),
]

_BOUNDARY_REGEX = re.compile(r"\bif\s*\(([^)]+)\)")

_NOISE_VARS = {
    "int", "char", "void", "const", "if", "else", "for", "while", "return",
    "sizeof", "struct", "unsigned", "static", "extern", "volatile", "auto",
    "NULL", "true", "false", "long", "short", "signed", "double", "float",
    "i", "j", "k", "n", "x", "y", "z", "rc", "rv", "ret", "err", "ok",
}

_SOURCE_SUFFIXES = {".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".hh"}


def _find_function_at_line(file_lines: list[str], line_idx: int) -> str | None:
    """Walk backward to infer the function that owns the current line."""
    for i in range(line_idx, -1, -1):
        stripped = file_lines[i].strip()
        if not stripped:
            continue
        match = re.match(
            r"^(?:(?:static|const|unsigned|signed|extern|inline)\s+)*"
            r"(?:\w+(?:\s+\*+)?\s+)+?"
            r"(\w+)\s*\([^)]*\)\s*\{?\s*$",
            stripped,
        )
        if not match:
            continue
        name = match.group(1)
        if name in {"if", "while", "for", "switch", "return", "sizeof"}:
            continue
        if "{" in stripped:
            return name
        for j in range(i + 1, min(i + 3, len(file_lines))):
            next_line = file_lines[j].strip()
            if next_line == "{":
                return name
            if next_line:
                break
        if re.match(r"^[A-Za-z_]\w*$", name):
            return name
    return None


def _extract_variables(code_line: str) -> list[str]:
    """Extract variable names from a code line that may map back to protocol fields."""
    found = set(re.findall(r"\b([A-Za-z_]\w{2,})\b", code_line))
    return sorted(v for v in found if v not in _NOISE_VARS)


def _iter_source_files(source_dir: Path):
    """Iterate over likely source files."""
    for path in source_dir.rglob("*"):
        if path.is_file() and path.suffix.lower() in _SOURCE_SUFFIXES:
            yield path


def _load_field_map(field_map_path: Path) -> dict:
    with field_map_path.open() as f:
        return json.load(f)


def _build_field_index(field_map: dict) -> tuple[dict[str, list[dict]], dict[str, list[dict]]]:
    """
    Build two reverse indices:
    1. `function@variable -> field refs`
    2. `function -> handler field refs`
    """
    by_var: dict[str, list[dict]] = {}
    by_func_handler: dict[str, list[dict]] = {}
    for command_map in field_map.get("field_mappings", []):
        command = command_map.get("command", "")
        for field in command_map.get("fields", []):
            field_ref = make_field_ref(
                field_name=field.get("field_name", ""),
                command=command,
                byte_range=field.get("byte_range", []),
            )
            for func in field.get("functions", []):
                function = func.get("function", "")
                relation = func.get("relation", "")
                if relation == "handler":
                    by_func_handler.setdefault(function, []).append(field_ref)
                for variable in func.get("variables", []):
                    base_var = variable.split("->")[0].split(".")[0]
                    for name in {variable, base_var}:
                        by_var.setdefault(f"{function}@{name}", []).append(field_ref)
    return by_var, by_func_handler


def _resolve_fields(
    *,
    function: str,
    variables: list[str],
    by_var: dict[str, list[dict]],
    by_func_handler: dict[str, list[dict]],
) -> tuple[list[dict], str]:
    """Try precise variable-level matching first, then fall back to handler-level matching."""
    matches: list[dict] = []
    for variable in variables:
        matches.extend(by_var.get(f"{function}@{variable}", []))
    if matches:
        return _dedupe_dicts(matches), "variable"
    return _dedupe_dicts(by_func_handler.get(function, [])), "handler" if function in by_func_handler else "none"


def _dedupe_dicts(items: list[dict]) -> list[dict]:
    """Deduplicate items while preserving order."""
    seen = set()
    result = []
    for item in items:
        key = json.dumps(item, sort_keys=True, ensure_ascii=False)
        if key in seen:
            continue
        seen.add(key)
        result.append(item)
    return result


def scan_sources(source_dir: str | Path, implementation: str, protocol: str) -> dict:
    """Scan one implementation and return normalized program points."""
    source_dir = Path(source_dir)
    files = {}
    by_function = {}
    program_points = []

    for source_file in _iter_source_files(source_dir):
        relative_path = source_file.relative_to(source_dir).as_posix()
        try:
            lines = source_file.read_text(errors="ignore").splitlines()
        except Exception:
            continue

        file_boundary = []
        file_vuln = []
        for idx, line in enumerate(lines):
            stripped = line.strip()
            if not stripped or stripped.startswith("//") or stripped.startswith("/*"):
                continue

            boundary_match = _BOUNDARY_REGEX.search(stripped)
            vuln_hit = None
            for pattern, vuln_func, cwe, description in _VULN_PATTERNS:
                if re.search(pattern, stripped):
                    vuln_hit = (vuln_func, cwe, description)
                    break
            if not boundary_match and vuln_hit is None:
                continue

            function = _find_function_at_line(lines, idx) or "unknown"
            variables = _extract_variables(stripped)

            if boundary_match:
                point = make_program_point(
                    point_type="boundary",
                    implementation=implementation,
                    protocol=protocol,
                    source_root=source_dir,
                    relative_path=relative_path,
                    line=idx + 1,
                    function=function,
                    source="static_scan",
                    variables=variables,
                    condition=stripped,
                    condition_expr=boundary_match.group(1),
                    code=stripped,
                    tags=["boundary"],
                )
                file_boundary.append(point)
                program_points.append(point)
                by_function.setdefault(function, {"boundary_points": [], "vuln_points": []})
                by_function[function]["boundary_points"].append(point)

            if vuln_hit is not None:
                vuln_func, cwe, description = vuln_hit
                point = make_program_point(
                    point_type="vulnerability",
                    implementation=implementation,
                    protocol=protocol,
                    source_root=source_dir,
                    relative_path=relative_path,
                    line=idx + 1,
                    function=function,
                    source="static_scan",
                    variables=variables,
                    cwe=cwe,
                    vuln_func=vuln_func,
                    description=description,
                    code=stripped,
                    tags=[cwe, vuln_func],
                )
                file_vuln.append(point)
                program_points.append(point)
                by_function.setdefault(function, {"boundary_points": [], "vuln_points": []})
                by_function[function]["vuln_points"].append(point)

        if file_boundary or file_vuln:
            files[relative_path] = {
                "boundary_points": file_boundary,
                "vuln_points": file_vuln,
            }

    return {
        "schema_version": SCHEMA_VERSION,
        "generated_by": "s2afl-static-code-analyzer",
        "implementation": implementation,
        "protocol": protocol,
        "source_dir": str(source_dir),
        "files": files,
        "by_function": by_function,
        "program_points": program_points,
    }


def match_to_fields(scan_result: dict, field_map_file: str | Path) -> list[dict]:
    """Associate static-scan points with dynamic-taint field mappings."""
    field_map = _load_field_map(Path(field_map_file))
    by_var, by_func_handler = _build_field_index(field_map)
    matches = []
    for point in scan_result.get("program_points", []):
        function = point.get("location", {}).get("function") or "unknown"
        variables = point.get("variables", [])
        field_refs, match_level = _resolve_fields(
            function=function,
            variables=variables,
            by_var=by_var,
            by_func_handler=by_func_handler,
        )
        merged = dict(point)
        merged["field_refs"] = field_refs
        merged["match_level"] = match_level
        matches.append(merged)
    return matches


def write_outputs(
    *,
    implementation: str,
    protocol: str,
    source_dir: Path,
    scan_result: dict,
    matches: list[dict],
) -> dict:
    """Write static-scan and boundary/vulnerability mapping results per implementation."""
    ensure_knowledge_layout(implementation)
    static_dir = implementation_static_dir(implementation)
    vul_dir = implementation_vul_dir(implementation)

    static_scan_path = static_dir / "static_scan.json"
    boundary_map_path = vul_dir / "boundary_vuln_map.json"
    legacy_boundary_map_path = KNOWLEDGE_DATA_ROOT / "facts" / f"{implementation}_boundary_vuln_map.json"

    static_payload = {
        "schema_version": SCHEMA_VERSION,
        "generated_by": scan_result["generated_by"],
        "implementation": implementation,
        "protocol": protocol,
        "source_dir": str(source_dir),
        "scan_stats": {
            "files_scanned": len(scan_result.get("files", {})),
            "functions_found": len(scan_result.get("by_function", {})),
            "boundary_points": sum(len(x["boundary_points"]) for x in scan_result.get("files", {}).values()),
            "vuln_points": sum(len(x["vuln_points"]) for x in scan_result.get("files", {}).values()),
        },
        "files": scan_result.get("files", {}),
        "by_function": scan_result.get("by_function", {}),
        "program_points": scan_result.get("program_points", []),
    }
    static_scan_path.write_text(json.dumps(static_payload, indent=2, ensure_ascii=False) + "\n")

    match_payload = {
        "schema_version": SCHEMA_VERSION,
        "generated_by": "s2afl-static-code-analyzer",
        "implementation": implementation,
        "protocol": protocol,
        "source_dir": str(source_dir),
        "scan_stats": static_payload["scan_stats"],
        "matches": matches,
    }
    boundary_map_path.write_text(json.dumps(match_payload, indent=2, ensure_ascii=False) + "\n")
    legacy_boundary_map_path.parent.mkdir(parents=True, exist_ok=True)
    legacy_boundary_map_path.write_text(json.dumps(match_payload, indent=2, ensure_ascii=False) + "\n")

    return {
        "static_scan_path": str(static_scan_path),
        "boundary_map_path": str(boundary_map_path),
        "legacy_boundary_map_path": str(legacy_boundary_map_path),
    }


def analyze_implementation(implementation: str, field_map_path: str | Path | None = None) -> dict:
    """Run the full scan/match/write pipeline for one implementation."""
    meta = implementation_meta(implementation)
    source_dir = implementation_source_dir(implementation)
    if not source_dir.exists():
        return {
            "implementation": implementation,
            "protocol": meta["protocol"],
            "source_exists": False,
            "field_map_exists": bool(field_map_path and Path(field_map_path).exists()),
            "written": {},
        }

    field_map_path = Path(field_map_path) if field_map_path else Path(
        Path(__file__).resolve().parent.parent / "output" / "dynamic_taint_mapping" / f"{implementation}_field_variable_map.json"
    )
    if not field_map_path.exists():
        return {
            "implementation": implementation,
            "protocol": meta["protocol"],
            "source_exists": True,
            "field_map_exists": False,
            "written": {},
        }

    scan_result = scan_sources(source_dir, implementation=implementation, protocol=meta["protocol"])
    matches = match_to_fields(scan_result, field_map_path)
    written = write_outputs(
        implementation=implementation,
        protocol=meta["protocol"],
        source_dir=source_dir,
        scan_result=scan_result,
        matches=matches,
    )
    return {
        "implementation": implementation,
        "protocol": meta["protocol"],
        "source_exists": True,
        "field_map_exists": True,
        "files_scanned": len(scan_result.get("files", {})),
        "program_points": len(scan_result.get("program_points", [])),
        "matches": len(matches),
        "written": written,
    }


def main():
    parser = argparse.ArgumentParser(description="S2AFL static source analysis + field matching")
    parser.add_argument("--implementation", help="Implementation name registered in S2AFL")
    parser.add_argument("--source-dir", help="Optional source directory override")
    parser.add_argument("--field-map", help="Optional field_variable_map.json override")
    parser.add_argument("-o", "--output", help="Compatibility output path override for boundary_vuln_map.json")
    args = parser.parse_args()

    if args.implementation:
        result = analyze_implementation(args.implementation, field_map_path=args.field_map)
        if args.output and result.get("written", {}).get("boundary_map_path"):
            src = Path(result["written"]["boundary_map_path"])
            Path(args.output).write_text(src.read_text())
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return

    if not args.source_dir or not args.field_map:
        parser.error("either --implementation or both --source-dir and --field-map are required")

    source_dir = Path(args.source_dir)
    with open(args.field_map) as f:
        field_map = json.load(f)
    implementation = field_map.get("implementation") or "UNKNOWN"
    protocol = field_map.get("protocol") or "UNKNOWN"
    scan_result = scan_sources(source_dir, implementation=implementation, protocol=protocol)
    matches = match_to_fields(scan_result, args.field_map)
    payload = {
        "schema_version": SCHEMA_VERSION,
        "generated_by": "s2afl-static-code-analyzer",
        "implementation": implementation,
        "protocol": protocol,
        "source_dir": str(source_dir),
        "scan_stats": {
            "files_scanned": len(scan_result.get("files", {})),
            "functions_found": len(scan_result.get("by_function", {})),
            "boundary_points": sum(len(x["boundary_points"]) for x in scan_result.get("files", {}).values()),
            "vuln_points": sum(len(x["vuln_points"]) for x in scan_result.get("files", {}).values()),
            "field_matches": len(matches),
        },
        "matches": matches,
    }
    if args.output:
        Path(args.output).write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n")
    print(json.dumps(payload, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
