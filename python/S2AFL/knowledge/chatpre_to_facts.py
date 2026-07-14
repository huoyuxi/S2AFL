#!/usr/bin/env python3
from __future__ import annotations

"""
chatpre_to_facts.py — Convert ChatPRE field_offset_map.json to S2AFL field_code_facts.json

Input:  ChatPRE field_offset_map.json  (the format you just confirmed)
Output: knowledge/data/facts/field_code_facts.json

Usage:
    python3 chatpre_to_facts.py <field_offset_map.json> [-o output.json]
"""

import json
import os
import sys


_VULN_FUNCS = {
    "strcpy", "strncpy", "sprintf", "vsprintf", "gets",
    "memcpy", "memmove", "strcat", "strncat", "snprintf",
    "read", "recv", "recvfrom", "fgets", "scanf", "sscanf",
    "realpath", "access", "open", "fopen",
}

_BOUNDARY_PATTERNS = {
    "strcmp", "strncmp", "strcasecmp", "strncasecmp",
    "memcmp", "strlen", "sizeof", "if", "switch",
}

_C_NOISE = {
    "__saved_registers", "__return_address",
    "var_8", "var_18", "var_60", "var_98",
}


def _role(field_name: str) -> str:
    fl = field_name.lower()
    if any(kw in fl for kw in ("length", "size", "count", "len", "max")): return "length"
    if any(kw in fl for kw in ("port",)): return "port"
    if any(kw in fl for kw in ("host", "ip", "domain", "uri", "url", "address")): return "address"
    if any(kw in fl for kw in ("user", "pass", "auth", "key", "token", "credential")): return "credential"
    if any(kw in fl for kw in ("file", "path", "name", "dir")): return "filename"
    if any(kw in fl for kw in ("command", "cmd", "method")): return "command"
    if any(kw in fl for kw in ("tag", "id", "seq", "num", "call", "branch")): return "identifier"
    return "parameter"


def _priority(role: str, risk_tags: list[str]) -> str:
    if risk_tags:
        return "high"
    if role in ("length", "port", "filename", "credential"):
        return "medium"
    return "low"


def _detect_risk(func_name: str, variables: list[str]) -> tuple[list[str], list[str]]:
    """Detect vuln/boundary indicators from function name and variable names."""
    vuln = []
    boundary = []
    fn_lower = func_name.lower()
    for vf in _VULN_FUNCS:
        if vf in fn_lower:
            vuln.append(vf)
    for v in variables:
        vl = v.lower()
        for vf in _VULN_FUNCS:
            if vf in vl and vf not in vuln:
                vuln.append(vf)
        for bp in _BOUNDARY_PATTERNS:
            if bp in vl and bp not in boundary:
                boundary.append(bp)
    return vuln, boundary


def convert(chatpre_file: str) -> dict:
    with open(chatpre_file) as f:
        data = json.load(f)

    proto = data.get("protocol", "UNKNOWN")
    facts = []

    for mapping in data.get("field_mappings", []):
        command = mapping.get("command", "")
        template = mapping.get("template", "")
        message = mapping.get("filled_message", "")

        for field in mapping.get("fields", []):
            fname = field.get("field_name", "")
            byte_range = field.get("byte_range", [0, 0])
            role = _role(fname)

            mapped_vars = []
            all_risk = []
            handler = None
            related_funcs = []

            for func in field.get("functions", []):
                fn_name = func.get("function", "")
                relation = func.get("relation", "")
                variables = func.get("variables", [])

                related_funcs.append(fn_name)

                if relation == "handler":
                    handler = fn_name

                for v in variables:
                    if v in _C_NOISE:
                        continue
                    mapped_vars.append({
                        "name": v,
                        "function": fn_name,
                        "relation": relation,
                    })

                # Risk detection
                vuln, boundary = _detect_risk(fn_name, variables)
                all_risk.extend(vuln)
                if boundary:
                    all_risk.append("boundary")

            # Deduplicate
            seen = set()
            deduped = []
            for mv in mapped_vars:
                k = (mv["name"], mv["function"])
                if k not in seen:
                    seen.add(k)
                    deduped.append(mv)

            risk_tags = list(set(all_risk))
            facts.append({
                "protocol": proto,
                "field_name": fname,
                "field_role": role,
                "parent_command": command,
                "byte_range": byte_range,
                "filled_message": message,
                "mutation_priority": _priority(role, risk_tags),
                "mapped_variables": deduped,
                "handler_function": handler,
                "related_functions": related_funcs,
                "risk_tags": risk_tags,
                "template": template,
            })

    return {proto: facts}


def main():
    import argparse
    p = argparse.ArgumentParser(description="ChatPRE → S2AFL facts converter")
    p.add_argument("input", help="ChatPRE field_offset_map.json")
    p.add_argument("-o", "--output", default=None,
                   help="Output path (default: knowledge/data/facts/field_code_facts.json)")
    args = p.parse_args()

    project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    if args.output is None:
        args.output = os.path.join(project_root, "knowledge/data/facts/field_code_facts.json")

    result = convert(args.input)

    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    with open(args.output, "w") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)

    proto = list(result.keys())[0]
    facts = result[proto]
    print(f"Protocol: {proto}")
    print(f"Fields:   {len(facts)}")
    print(f"  with handler: {sum(1 for x in facts if x['handler_function'])}")
    print(f"  with risk:    {sum(1 for x in facts if x['risk_tags'])}")
    print(f"  total vars:   {sum(len(x['mapped_variables']) for x in facts)}")
    print(f"Written → {args.output}")


if __name__ == "__main__":
    main()
