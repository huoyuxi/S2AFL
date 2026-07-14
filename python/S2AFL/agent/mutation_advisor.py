from __future__ import annotations

"""
mutation_advisor.py — S2AFL runtime mutation engine.

Given an uncovered code branch during fuzzing, determines the best protocol
field to mutate via direct lookup + LLM reasoning.

Supplies both:
  - Targeted advice: given a specific code line/function → which field, how
  - VSAM/SBGM context: all high-risk / boundary fields for a protocol

Data sources (all offline, no CodeBERT, no embedding):
  - flawfinder → CWE-categorized vulnerability lines (generated_protocol_src_vuln.json)
  - ChatPRE → field ↔ variable ↔ function mapping (field_variable_map.json)
  - Static source scan → boundary conditions per function (boundary_vuln_map.json)
"""

import json
import os
import re
import time
from collections import defaultdict

from S2AFL.llm_shared import call_text_prompt



# ---------------------------------------------------------------------------
# LLM
# ---------------------------------------------------------------------------

def call_llm(prompt: str, max_tokens: int = 4096) -> str | None:
    return call_text_prompt(prompt, max_tokens=max_tokens, temperature=0.3)


# ---------------------------------------------------------------------------
# Vuln knowledge base (flawfinder)
# ---------------------------------------------------------------------------

_NOISE_VARS = {
    "int", "char", "void", "const", "if", "else", "for", "while",
    "return", "sizeof", "struct", "unsigned", "static", "NULL", "true",
    "false", "i", "j", "k", "n", "rc", "rv", "ret", "err", "ok",
    "__saved_registers", "__return_address",
}


class VulnKB:
    """Load flawfinder CWE results, provide per-function lookup."""

    def __init__(self, vuln_db_file: str, protocol: str):
        self.protocol = protocol
        self._by_cwe: dict[str, list[str]] = defaultdict(list)
        self._by_func: dict[str, list[dict]] = defaultdict(list)
        self._all: list[str] = []
        if vuln_db_file and os.path.exists(vuln_db_file):
            self._load(vuln_db_file)

    def _load(self, path: str):
        with open(path) as f:
            db = json.load(f)
        proto_upper = self.protocol.upper()
        for key, cwes in db.items():
            if proto_upper not in key.upper():
                continue
            for cwe, lines in cwes.items():
                for line in lines:
                    normalized = re.sub(r"\s+", " ", line).strip()
                    if not normalized:
                        continue
                    self._all.append(normalized)
                    self._by_cwe[cwe].append(normalized)
                    m = re.match(r"^\s*(\w+)", normalized)
                    func = m.group(1) if m else "unknown"
                    self._by_func[func].append({"code": normalized, "cwe": cwe})

    def by_function(self, func: str) -> list[dict]:
        return self._by_func.get(func, [])

    def all_lines(self) -> list[str]:
        return self._all

    def __bool__(self):
        return len(self._all) > 0


# ---------------------------------------------------------------------------
# Field mapper (ChatPRE field_variable_map.json)
# ---------------------------------------------------------------------------

class FieldMapper:
    """Reverse index: variable@function or function → protocol field."""

    def __init__(self, field_map_file: str):
        with open(field_map_file) as f:
            data = json.load(f)
        self.mappings = data.get("field_mappings", [])
        self.protocol = data.get("protocol", "?")
        self._var_idx: dict[str, list[dict]] = defaultdict(list)
        self._func_idx: dict[str, list[dict]] = defaultdict(list)
        self._cmd_fields: dict[str, list[dict]] = defaultdict(list)
        self._all_fields: list[dict] = []
        self._build()

    def _build(self):
        for cmd in self.mappings:
            command = cmd.get("command", "")
            for field in cmd.get("fields", []):
                fname = field.get("field_name", "")
                br = field.get("byte_range", [0, 0])
                entry = {"field_name": fname, "command": command, "byte_range": br}
                self._cmd_fields[command].append(entry)
                self._all_fields.append(entry)
                for func in field.get("functions", []):
                    fn = func.get("function", "")
                    rel = func.get("relation", "")
                    fe = {**entry, "relation": rel}
                    for v in func.get("variables", []):
                        self._var_idx[f"{fn}@{v}"].append(fe)
                    self._func_idx[fn].append(fe)

    def by_variable(self, var: str, func: str = None) -> list[dict]:
        if func:
            return self._var_idx.get(f"{func}@{var}", [])
        results = []
        for k, v in self._var_idx.items():
            if k.endswith(f"@{var}"):
                results.extend(v)
        return results

    def by_function(self, func: str, relation: str = None) -> list[dict]:
        entries = self._func_idx.get(func, [])
        return [e for e in entries if not relation or e["relation"] == relation]

    def handler_for(self, func: str) -> dict | None:
        entries = self.by_function(func, "handler")
        return entries[0] if entries else None

    def all_fields(self) -> list[dict]:
        return self._all_fields


# ---------------------------------------------------------------------------
# Boundary/Vuln map (code_analyzer.py output)
# ---------------------------------------------------------------------------

class BoundaryVulnMap:
    """Load boundary_vuln_map.json for O(1) function/line → field lookup."""

    def __init__(self, bv_map_file: str = None):
        self._by_func: dict[str, list[dict]] = defaultdict(list)
        if bv_map_file and os.path.exists(bv_map_file):
            self._load(bv_map_file)

    @staticmethod
    def _target_fields(entry: dict) -> list[dict]:
        if entry.get("target_fields"):
            return entry.get("target_fields", [])
        if entry.get("field_refs"):
            refs = []
            for ref in entry.get("field_refs", []):
                refs.append({
                    "field_name": ref.get("field_name"),
                    "command": ref.get("command"),
                })
            return refs
        return []

    def _load(self, path: str):
        with open(path) as f:
            data = json.load(f)
        for m in data.get("matches", []):
            func = m.get("function") or m.get("location", {}).get("function") or "unknown"
            normalized = dict(m)
            normalized["target_fields"] = self._target_fields(m)
            self._by_func[func].append(normalized)

    def for_function(self, func: str) -> list[dict]:
        return self._by_func.get(func, [])

    def __bool__(self):
        return len(self._by_func) > 0


# ---------------------------------------------------------------------------
# MutationAdvisor
# ---------------------------------------------------------------------------

class MutationAdvisor:
    """
    Runtime mutation engine.
      1. Targeted: advise(code_line, function) → {field, command, strategy}
      2. Context: build_vsam_context(protocol) / build_sbgm_context(protocol)
    """

    def __init__(
        self,
        field_map_file: str,
        vuln_db_file: str = None,
        bv_map_file: str = None,
        protocol: str = "FTP",
    ):
        self.mapper = FieldMapper(field_map_file)
        self.vuln_kb = VulnKB(vuln_db_file, protocol) if vuln_db_file else None
        self.bv_map = BoundaryVulnMap(bv_map_file) if bv_map_file else None
        self.protocol = protocol

    # ----------------------------------------------------------------
    # Targeted advice
    # ----------------------------------------------------------------

    def _extract_vars(self, code_line: str) -> list[str]:
        vars_found = set(re.findall(r"\b([a-zA-Z_]\w{2,})\b", code_line))
        base_vars = set()
        for v in vars_found:
            if "->" in v:
                base_vars.add(v.split("->")[0])
            if "." in v:
                base_vars.add(v.split(".")[0])
        return sorted((vars_found | base_vars) - _NOISE_VARS)

    def _find_candidates(self, code_line: str, function: str = None) -> list[tuple]:
        """Find candidate fields matching a code line."""
        candidates = set()
        variables = self._extract_vars(code_line)

        # Variable-level match
        for v in variables:
            for entry in self.mapper.by_variable(v, function):
                candidates.add((entry["field_name"], entry["command"], entry["relation"]))

        # Function handler match
        if function:
            handler = self.mapper.handler_for(function)
            if handler:
                candidates.add((handler["field_name"], handler["command"], "handler"))

        # Function-level fallback (all fields flowing through this function)
        if not candidates and function:
            for entry in self.mapper.by_function(function):
                candidates.add((entry["field_name"], entry["command"], entry.get("relation", "")))

        # Boundary map match
        if not candidates and function and self.bv_map:
            for bv in self.bv_map.for_function(function):
                for tf in bv.get("target_fields", []):
                    candidates.add((tf["field_name"], tf["command"], "boundary_map"))

        # Global fallback
        if not candidates:
            for entry in self.mapper.all_fields():
                candidates.add((entry["field_name"], entry["command"], "global"))

        return sorted(candidates)

    def advise(self, code_line: str, function: str = None) -> dict:
        """Main entry: uncovered branch → mutation target."""
        code_clean = re.sub(r"\s+", " ", code_line).strip()
        ranked = self._find_candidates(code_clean, function)

        if not ranked:
            return {
                "field_name": None, "command": None,
                "strategy": "unknown", "confidence": "low",
                "description": "No field mapping found",
            }

        # Related vulnerability patterns
        vuln_lines = []
        if self.vuln_kb:
            vuln_lines = self.vuln_kb.by_function(function) if function else []
            if not vuln_lines:
                variables = self._extract_vars(code_clean)
                for v in variables:
                    for line in self.vuln_kb.all_lines():
                        if v in line and line not in [x["code"] for x in vuln_lines]:
                            vuln_lines.append({"code": line, "cwe": "?"})

        candidates_str = "\n".join(
            f"  {f} (command={c}, relation={r})" for f, c, r in ranked[:10]
        )
        vuln_str = "\n".join(
            f"  [{v.get('cwe', '?')}] {v.get('code', str(v))[:120]}"
            for v in vuln_lines[:5]
        ) if vuln_lines else "(none)"

        prompt = f"""Protocol fuzzing mutation advisor.

CODE (uncovered branch):
  {code_clean}

FUNCTION: {function or 'unknown'}
PROTOCOL: {self.protocol}

CANDIDATE FIELDS (from taint analysis):
{candidates_str}

RELATED VULNERABILITY PATTERNS (flawfinder):
{vuln_str}

Which field is the single best target for mutation to reach the uncovered branch?
Respond JSON only:
{{"field":"<field_name>","command":"<cmd>","strategy":"<overflow|underflow|boundary|injection|fuzz>","description":"<one sentence>","confidence":"<high|medium|low>"}}"""

        response = call_llm(prompt)
        if not response:
            f, c, r = ranked[0]
            return {
                "field_name": f, "command": c, "strategy": "boundary",
                "description": f"Fallback: {code_clean}", "confidence": "low",
            }

        try:
            result = json.loads(response)
        except json.JSONDecodeError:
            m = re.search(r"\{[^}]+\}", response, re.DOTALL)
            result = json.loads(m.group()) if m else {}

        return {
            "field_name": result.get("field", ranked[0][0]),
            "command": result.get("command", ranked[0][1]),
            "strategy": result.get("strategy", "boundary"),
            "description": result.get("description", response[:200]),
            "confidence": result.get("confidence", "medium"),
        }

    # ----------------------------------------------------------------
    # VSAM / SBGM context builders (for stall prompt augmentation)
    # ----------------------------------------------------------------

    def build_vsam_context(self, max_fields: int = 5) -> str:
        """Build VSAM context: fields with vulnerability risk, ranked."""
        # Build field → {variables, handler} from ChatPRE data
        field_info = {}
        for cmd_map in self.mapper.mappings:
            command = cmd_map.get("command", "")
            for field in cmd_map.get("fields", []):
                fname = field.get("field_name", "")
                variables = set()
                handler = None
                for func in field.get("functions", []):
                    if func.get("relation") == "handler":
                        handler = func.get("function")
                    for v in func.get("variables", []):
                        if v not in _NOISE_VARS:
                            variables.add(v)
                field_info[fname] = {
                    "command": command, "variables": variables,
                    "handler": handler,
                }

        # Score each field by vuln relevance
        scored = []
        for fname, info in field_info.items():
            score = 0
            evidence = []

            # Check boundary_vuln_map for vulnerability points in handler
            if self.bv_map and info["handler"]:
                for bv in self.bv_map.for_function(info["handler"]):
                    if bv["type"] == "vulnerability":
                        score += 2
                        evidence.append(bv.get("vuln_func", "?"))

            # Check flawfinder: any field variable appears in a vuln line
            if self.vuln_kb:
                for line in self.vuln_kb.all_lines():
                    for v in info["variables"]:
                        if v in line:
                            score += 1
                            evidence.append("flawfinder")
                            break

            if score > 0:
                scored.append({
                    "field_name": fname, "command": info["command"],
                    "score": score,
                    "evidence": list(set(evidence))[:3],
                    "handler": info["handler"],
                })

        scored.sort(key=lambda x: x["score"], reverse=True)
        top = scored[:max_fields]
        if not top:
            return ""

        parts = ["[VSAM] Vulnerability-aware field guidance:"]
        for f in top:
            ev = ", ".join(f["evidence"]) if f["evidence"] else "taint path"
            parts.append(
                f"  {f['field_name']} ({f['command']}) — "
                f"{ev} (handler={f['handler']})"
            )
        return "\n".join(parts)

    def build_sbgm_context(self, max_fields: int = 5) -> str:
        """Build SBGM context: fields with boundary conditions."""
        fields = []
        if self.bv_map:
            for func, bv_list in self.bv_map._by_func.items():
                handler = self.mapper.handler_for(func)
                if handler:
                    boundary_count = sum(
                        len(bv.get("target_fields", []))
                        for bv in bv_list
                        if bv["type"] == "boundary"
                    )
                    if boundary_count > 0:
                        fields.append({
                            **handler,
                            "boundary_count": boundary_count,
                            "function": func,
                        })

        fields.sort(key=lambda x: x["boundary_count"], reverse=True)
        top = fields[:max_fields]
        if not top:
            return ""

        parts = ["[SBGM] Boundary-guided mutation targets:"]
        for f in top:
            parts.append(f"  {f['field_name']} ({f['command']}) — "
                         f"{f['boundary_count']} boundaries in {f['function']}")
        return "\n".join(parts)

    def augment_stall_prompt(self, prompt: str,
                             vsam: bool = True, sbgm: bool = False) -> str:
        """Augment a stall prompt with VSAM/SBGM guidance."""
        parts = []
        if vsam:
            ctx = self.build_vsam_context()
            if ctx:
                parts.append(ctx)
        if sbgm:
            ctx = self.build_sbgm_context()
            if ctx:
                parts.append(ctx)
        if not parts:
            return prompt
        return prompt + "\n\n" + "\n\n".join(parts)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    import argparse
    p = argparse.ArgumentParser(description="S2AFL Mutation Advisor")
    p.add_argument("field_map", help="ChatPRE field_variable_map.json")
    p.add_argument("--vuln-db", help="flawfinder generated_protocol_src_vuln.json")
    p.add_argument("--bv-map", help="boundary_vuln_map.json (from code_analyzer.py)")
    p.add_argument("--protocol", required=True)
    p.add_argument("--code", "-c", default=None, help="Uncovered branch code line")
    p.add_argument("--function", "-f", default=None)
    p.add_argument("--vsam", action="store_true", help="Print VSAM context")
    p.add_argument("--sbgm", action="store_true", help="Print SBGM context")
    args = p.parse_args()

    advisor = MutationAdvisor(args.field_map, args.vuln_db, args.bv_map, args.protocol)

    if args.vsam:
        print(advisor.build_vsam_context())
    elif args.sbgm:
        print(advisor.build_sbgm_context())
    elif args.code:
        result = advisor.advise(args.code, args.function)
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        p.print_help()


if __name__ == "__main__":
    main()
