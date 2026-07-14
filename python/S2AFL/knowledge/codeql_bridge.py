"""
Unified KG loader for merging dynamic taint evidence with static evidence.

This release prefers the per-implementation knowledge layout:
- dynamic_taint: `knowledge/data/implementations/<Impl>/dynamic_taint/...`
- static_scan:   `knowledge/data/implementations/<Impl>/static_scan/...`
- codeql:        `knowledge/data/implementations/<Impl>/codeql/...`
- vul:           `knowledge/data/implementations/<Impl>/vul/...`

Compatibility behavior:
- When the new layout is absent, fall back to legacy `output/results`, `knowledge/data/codeql`, and
  `knowledge/data/facts/*_boundary_vuln_map.json`.
"""

from __future__ import annotations

import glob
import json
from collections import defaultdict
from pathlib import Path

from .dynamic_taint import normalize_dynamic_taint
from .implementation_registry import (
    KNOWLEDGE_DATA_ROOT,
    LEGACY_RESULTS_ROOT,
    RESULTS_ROOT,
    implementation_data_dir,
    implementation_meta,
    implementation_names,
)


def _norm_text(value: str) -> str:
    return " ".join((value or "").split())


def _role(field_name: str) -> str:
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


def _priority(role: str, risk_tags: list[str], evidence_strength: int) -> str:
    if evidence_strength >= 4 or len(risk_tags) >= 4:
        return "high"
    if evidence_strength >= 2 or role in ("length", "port", "filename", "credential"):
        return "medium"
    return "low"


class S2AFLKnowledgeGraph:
    """Knowledge graph that merges dynamic taint and static evidence."""

    def __init__(
        self,
        results_dir: str | None = None,
        facts_dir: str | None = None,
        vuln_db_path: str | None = None,
        codeql_dir: str | None = None,
    ):
        kb_dir = Path(__file__).resolve().parent
        self.results_dir = Path(results_dir) if results_dir else RESULTS_ROOT
        self.facts_dir = Path(facts_dir) if facts_dir else KNOWLEDGE_DATA_ROOT / "facts"
        self.vuln_db_path = Path(vuln_db_path) if vuln_db_path else KNOWLEDGE_DATA_ROOT / "vuln" / "generated_protocol_src_vuln.json"
        self.codeql_dir = Path(codeql_dir) if codeql_dir else KNOWLEDGE_DATA_ROOT / "codeql"

        self._facts_by_impl: dict[str, list[dict]] = {}
        self._by_field: dict[str, dict[str, dict]] = {}
        self._by_command: dict[str, dict[str, list[dict]]] = {}
        self._by_risk: dict[str, dict[str, list[dict]]] = {}
        self._by_protocol: dict[str, list[dict]] = defaultdict(list)
        self._boundary_index: dict[str, dict[str, list[dict]]] = defaultdict(lambda: defaultdict(list))
        self._vuln_db: dict = {}
        self._codeql_results: dict[str, dict] = {}
        self._codeql_field_index: dict[str, dict[str, dict]] = defaultdict(dict)

    @property
    def implementations(self) -> list[str]:
        return sorted(self._facts_by_impl.keys())

    def load(self):
        self._facts_by_impl.clear()
        self._by_field.clear()
        self._by_command.clear()
        self._by_risk.clear()
        self._by_protocol.clear()
        self._boundary_index.clear()
        self._codeql_results.clear()
        self._codeql_field_index.clear()
        self._load_vuln_db()
        self._load_boundary_maps()
        self._load_codeql_dir()
        self._load_results_dir()
        self._build_indices()

    def _load_vuln_db(self):
        self._vuln_db = {}
        if self.vuln_db_path.exists():
            with self.vuln_db_path.open() as f:
                self._vuln_db = json.load(f)

    def _load_boundary_maps(self):
        for implementation in implementation_names():
            new_path = implementation_data_dir(implementation) / "vul" / "boundary_vuln_map.json"
            legacy_path = self.facts_dir / f"{implementation}_boundary_vuln_map.json"
            path = new_path if new_path.exists() else legacy_path
            if not path.exists():
                continue
            try:
                with path.open() as f:
                    data = json.load(f)
            except Exception:
                continue
            for match in data.get("matches", []):
                func = match.get("location", {}).get("function") or match.get("function") or "unknown"
                self._boundary_index[implementation][func].append(match)

    def _load_results_dir(self):
        for implementation in implementation_names():
            normalized_path = implementation_data_dir(implementation) / "dynamic_taint" / "normalized_field_facts.json"
            raw_path = self.results_dir / f"{implementation}_field_variable_map.json"
            legacy_raw_path = LEGACY_RESULTS_ROOT / f"{implementation}_field_variable_map.json"

            if normalized_path.exists():
                try:
                    with normalized_path.open() as f:
                        data = json.load(f)
                except Exception:
                    continue
                self._facts_by_impl[implementation] = data.get("facts", [])
                continue

            candidate_raw_path = raw_path if raw_path.exists() else legacy_raw_path
            if candidate_raw_path.exists():
                try:
                    with candidate_raw_path.open() as f:
                        data = json.load(f)
                except Exception:
                    continue
                normalized = normalize_dynamic_taint(data)
                self._facts_by_impl[implementation] = normalized.get("facts", [])

    def _load_codeql_dir(self):
        for implementation in implementation_names():
            candidates = [
                implementation_data_dir(implementation) / "codeql" / "normalized_codeql.json",
                self.codeql_dir / implementation / "normalized_codeql.json",
                self.codeql_dir / f"{implementation}.json",
            ]
            path = next((candidate for candidate in candidates if candidate.exists()), None)
            if not path:
                continue
            try:
                with path.open() as f:
                    data = json.load(f)
            except Exception:
                continue
            self._codeql_results[implementation] = data
            self._index_codeql_result(implementation, data)

    def _index_codeql_result(self, implementation: str, data: dict):
        per_field = self._codeql_field_index[implementation]
        for query_name, entries in data.get("queries", {}).items():
            for entry in entries:
                field_name = entry.get("field_name")
                if not field_name:
                    continue
                bucket = per_field.setdefault(
                    field_name,
                    {
                        "candidates": [],
                        "boundary_points": [],
                        "vuln_points": [],
                        "related_functions": set(),
                        "mapped_variables": [],
                        "query_names": set(),
                    },
                )
                bucket["query_names"].add(query_name)
                bucket["candidates"].append(entry)
                for fn_name in entry.get("related_functions", []):
                    bucket["related_functions"].add(fn_name)
                for mv in entry.get("mapped_variables", []):
                    bucket["mapped_variables"].append(mv)
                for bp in entry.get("boundary_points", []):
                    bucket["boundary_points"].append(bp)
                for vp in entry.get("vuln_points", []):
                    bucket["vuln_points"].append(vp)

    def _normalize_codeql_variables(self, mapped_variables: list[dict]) -> list[dict]:
        normalized = []
        for entry in mapped_variables:
            normalized.append(
                {
                    "source": "codeql_static",
                    "function": entry.get("function"),
                    "relation": entry.get("relation", "dataflow"),
                    "variables": list(entry.get("variables", [])),
                    "all_variables": list(entry.get("all_variables", [])),
                    "path": list(entry.get("path", [])),
                    "distance": entry.get("distance"),
                }
            )
        return normalized

    def _collect_program_points(
        self,
        implementation: str,
        dynamic_related_functions: list[str],
        codeql_info: dict,
    ) -> tuple[list[dict], list[dict]]:
        boundary_points = []
        vuln_points = []

        for fn_name in dynamic_related_functions:
            for entry in self._boundary_index.get(implementation, {}).get(fn_name, []):
                self._append_program_point(entry, boundary_points, vuln_points, source="static_scan")

        for bp in codeql_info.get("boundary_points", []):
            point = dict(bp)
            point.setdefault("source", "codeql_static")
            boundary_points.append(point)

        for vp in codeql_info.get("vuln_points", []):
            point = dict(vp)
            point.setdefault("source", "codeql_static")
            vuln_points.append(point)

        return self._dedupe_dicts(boundary_points), self._dedupe_dicts(vuln_points)

    @staticmethod
    def _append_program_point(entry: dict, boundary_points: list[dict], vuln_points: list[dict], source: str):
        location = entry.get("location", {})
        point = {
            "line": location.get("line") or entry.get("line"),
            "function": location.get("function") or entry.get("function"),
            "variables": list(entry.get("variables", [])),
            "file": location.get("relative_path") or entry.get("file"),
            "match_level": entry.get("match_level"),
            "source": source,
        }
        if entry.get("type") == "boundary":
            point["condition"] = entry.get("condition")
            boundary_points.append(point)
        elif entry.get("type") == "vulnerability":
            point["code"] = location.get("code") or entry.get("code")
            point["cwe"] = entry.get("cwe")
            point["description"] = entry.get("description")
            point["vuln_func"] = entry.get("vuln_func")
            vuln_points.append(point)

    def _lookup_flawfinder(
        self,
        protocol: str,
        implementation: str,
        related_functions: list[str],
        mapped_variables: list[dict],
    ) -> list[str]:
        keys = [protocol.upper(), implementation.upper()]
        pool = []
        for key, cwes in self._vuln_db.items():
            key_upper = key.upper()
            if not any(token in key_upper for token in keys):
                continue
            for lines in cwes.values():
                pool.extend(lines)

        var_names = set()
        for entry in mapped_variables:
            for name in entry.get("variables", []):
                var_names.add(name)

        matches = []
        for line in pool:
            compact = _norm_text(line)
            if not compact:
                continue
            if any(fn and fn in compact for fn in related_functions) or any(v and v in compact for v in var_names):
                matches.append(compact)
        return self._dedupe_preserve(matches)[:20]

    def _build_evidence(
        self,
        implementation: str,
        field_name: str,
        dynamic_variables: list[dict],
        static_variables: list[dict],
        boundary_points: list[dict],
        vuln_points: list[dict],
        flawfinder_matches: list[str],
        codeql_candidates: list[dict],
    ) -> dict:
        dynamic_boundary = [p for p in boundary_points if p.get("source") != "codeql_static"]
        static_boundary = [p for p in boundary_points if p.get("source") == "codeql_static"]
        dynamic_vuln = [p for p in vuln_points if p.get("source") != "codeql_static"]
        static_vuln = [p for p in vuln_points if p.get("source") == "codeql_static"]

        dynamic_handler = self._primary_handler(dynamic_variables)
        static_handler = self._primary_handler(static_variables)
        merged_handler = dynamic_handler or static_handler

        dynamic_strength = self._evidence_strength(
            len(dynamic_variables), len(dynamic_boundary), len(dynamic_vuln), 0, len(flawfinder_matches)
        )
        static_strength = self._evidence_strength(
            len(static_variables), len(static_boundary), len(static_vuln), len(codeql_candidates), 0
        )
        merged_strength = dynamic_strength + static_strength + (1 if dynamic_strength and static_strength else 0)

        return {
            "dynamic": {
                "source": "dynamic_taint",
                "implementation": implementation,
                "field_name": field_name,
                "mapped_variables": self._dedupe_dicts(dynamic_variables),
                "boundary_points": self._dedupe_dicts(dynamic_boundary),
                "vuln_points": self._dedupe_dicts(dynamic_vuln),
                "flawfinder_matches": list(flawfinder_matches),
                "confidence": "high" if dynamic_variables else "low",
                "strength": dynamic_strength,
                "primary_handler": dynamic_handler,
            },
            "static": {
                "source": "codeql_static",
                "implementation": implementation,
                "field_name": field_name,
                "mapped_variables": self._dedupe_dicts(static_variables),
                "boundary_points": self._dedupe_dicts(static_boundary),
                "vuln_points": self._dedupe_dicts(static_vuln),
                "codeql_candidates": self._dedupe_dicts(codeql_candidates),
                "confidence": "medium" if (static_variables or codeql_candidates) else "low",
                "strength": static_strength,
                "primary_handler": static_handler,
            },
            "merged": {
                "source": "merged",
                "implementation": implementation,
                "field_name": field_name,
                "mapped_variables": self._dedupe_dicts(dynamic_variables + static_variables),
                "boundary_points": self._dedupe_dicts(boundary_points),
                "vuln_points": self._dedupe_dicts(vuln_points),
                "flawfinder_matches": list(flawfinder_matches),
                "codeql_candidates": self._dedupe_dicts(codeql_candidates),
                "confidence": self._merged_confidence(dynamic_strength, static_strength),
                "strength": merged_strength,
                "primary_handler": merged_handler,
                "sources": self._merged_sources(dynamic_variables, static_variables, codeql_candidates),
            },
        }

    @staticmethod
    def _evidence_strength(
        variable_count: int,
        boundary_count: int,
        vuln_count: int,
        codeql_count: int,
        flawfinder_count: int,
    ) -> int:
        return (
            min(variable_count, 3)
            + min(boundary_count, 3)
            + min(vuln_count * 2, 4)
            + min(codeql_count, 2)
            + (1 if flawfinder_count else 0)
        )

    @staticmethod
    def _merged_confidence(dynamic_strength: int, static_strength: int) -> str:
        if dynamic_strength and static_strength:
            return "high"
        if dynamic_strength >= 2 or static_strength >= 3:
            return "medium"
        return "low"

    @staticmethod
    def _merged_sources(dynamic_variables: list[dict], static_variables: list[dict], codeql_candidates: list[dict]) -> list[str]:
        sources = []
        if dynamic_variables:
            sources.append("dynamic_taint")
        if static_variables or codeql_candidates:
            sources.append("codeql_static")
        return sources

    @staticmethod
    def _primary_handler(mapped_variables: list[dict]) -> str | None:
        for entry in mapped_variables:
            if entry.get("relation") == "handler" and entry.get("function"):
                return entry["function"]
        return mapped_variables[0].get("function") if mapped_variables else None

    def _collect_risk_tags(self, evidence: dict) -> list[str]:
        tags = set()
        merged = evidence["merged"]
        if merged.get("boundary_points"):
            tags.add("boundary")
        for point in merged.get("vuln_points", []):
            if point.get("cwe"):
                tags.add(point["cwe"])
            if point.get("vuln_func"):
                tags.add(point["vuln_func"])
        if merged.get("flawfinder_matches"):
            tags.add("flawfinder-hit")
        for entry in merged.get("mapped_variables", []):
            for name in entry.get("variables", []):
                lower = (name or "").lower()
                if any(token in lower for token in ("len", "size", "count")):
                    tags.add("length-sensitive")
                if any(token in lower for token in ("path", "file", "dir")):
                    tags.add("path-sensitive")
        if "dynamic_taint" in merged.get("sources", []) and "codeql_static" in merged.get("sources", []):
            tags.add("cross-validated")
        return sorted(tags)

    def _build_indices(self):
        for impl, facts in self._facts_by_impl.items():
            self._by_field[impl] = {}
            self._by_command[impl] = defaultdict(list)
            self._by_risk[impl] = defaultdict(list)
            for fact in facts:
                field_name = fact.get("field_name", "")
                command = fact.get("parent_command", "")
                protocol = fact.get("protocol", "")
                codeql_info = self._codeql_field_index.get(impl, {}).get(field_name, {})
                dynamic_variables = [mv for mv in fact.get("mapped_variables", []) if mv.get("source") == "dynamic_taint"]
                static_variables = self._normalize_codeql_variables(codeql_info.get("mapped_variables", []))
                boundary_points, vuln_points = self._collect_program_points(
                    impl,
                    fact.get("related_functions", []),
                    codeql_info,
                )
                flawfinder_matches = self._lookup_flawfinder(
                    protocol,
                    impl,
                    fact.get("related_functions", []),
                    dynamic_variables + static_variables,
                )
                evidence = self._build_evidence(
                    implementation=impl,
                    field_name=field_name,
                    dynamic_variables=dynamic_variables,
                    static_variables=static_variables,
                    boundary_points=boundary_points,
                    vuln_points=vuln_points,
                    flawfinder_matches=flawfinder_matches,
                    codeql_candidates=codeql_info.get("candidates", []),
                )
                merged_fact = dict(fact)
                merged_fact["field_role"] = merged_fact.get("field_role") or _role(field_name)
                merged_fact["boundary_points"] = evidence["merged"]["boundary_points"]
                merged_fact["vuln_points"] = evidence["merged"]["vuln_points"]
                merged_fact["flawfinder_matches"] = evidence["merged"]["flawfinder_matches"]
                merged_fact["mapped_variables"] = evidence["merged"]["mapped_variables"]
                merged_fact["risk_tags"] = self._collect_risk_tags(evidence)
                merged_fact["mutation_priority"] = _priority(
                    merged_fact["field_role"],
                    merged_fact["risk_tags"],
                    evidence["merged"]["strength"],
                )
                merged_fact["evidence"] = evidence
                merged_fact["dynamic_evidence"] = evidence["dynamic"]
                merged_fact["static_evidence"] = evidence["static"]
                merged_fact["merged_evidence"] = evidence["merged"]
                merged_fact["codeql_candidates"] = codeql_info.get("candidates", [])

                self._by_field[impl][field_name] = merged_fact
                self._by_command[impl][command].append(merged_fact)
                self._by_protocol[protocol].append(merged_fact)
                for tag in merged_fact.get("risk_tags", []):
                    self._by_risk[impl][tag].append(merged_fact)
            self._facts_by_impl[impl] = list(self._by_field[impl].values())

    def _resolve_impl(self, target: str) -> str | None:
        if target in self._facts_by_impl:
            return target
        candidates = [
            impl for impl, facts in self._facts_by_impl.items()
            if facts and facts[0].get("protocol") == target
        ]
        if len(candidates) == 1:
            return candidates[0]
        return None

    def get_high_risk_fields(self, target: str, min_priority: str = "medium") -> list[dict]:
        impl = self._resolve_impl(target)
        if not impl:
            return []
        order = {"low": 0, "medium": 1, "high": 2}
        threshold = order.get(min_priority, 1)
        result = []
        for fact in self._facts_by_impl.get(impl, []):
            if order.get(fact.get("mutation_priority", "low"), 0) >= threshold:
                result.append(fact)
        return sorted(result, key=lambda x: (x.get("mutation_priority", "low"), len(x.get("risk_tags", []))), reverse=True)

    def get_boundary_fields(self, target: str) -> list[dict]:
        impl = self._resolve_impl(target)
        if not impl:
            return []
        return [fact for fact in self._facts_by_impl.get(impl, []) if fact.get("boundary_points")]

    def get_codeql_candidates(self, target: str, query_name: str = "field_candidates") -> list[dict]:
        impl = self._resolve_impl(target)
        if not impl:
            return []
        return list(self._codeql_results.get(impl, {}).get("queries", {}).get(query_name, []))

    @staticmethod
    def _dedupe_preserve(items: list[str]) -> list[str]:
        seen = set()
        result = []
        for item in items:
            if item in seen:
                continue
            seen.add(item)
            result.append(item)
        return result

    @staticmethod
    def _dedupe_dicts(items: list[dict]) -> list[dict]:
        seen = set()
        result = []
        for item in items:
            key = json.dumps(item, sort_keys=True, ensure_ascii=False)
            if key in seen:
                continue
            seen.add(key)
            result.append(item)
        return result
