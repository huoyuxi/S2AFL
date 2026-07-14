"""Runtime knowledge loader for workflow2.

This module turns workflow1 knowledge artifacts into structures that the runtime can consume directly:
- templates
- dynamic taint field facts
- static boundary / vuln program points
- target catalog
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Any

from S2AFL.core.templates import decode_template_parts, load_template_catalog, summarize_template_constraint, template_constraint_for_entry
from S2AFL.knowledge.implementation_registry import (
    compatibility_codeql_dir,
    compatibility_vul_dir,
    implementation_data_dir,
    implementation_source_dir,
    resolve_existing_source,
)

from .models import TargetRecord
from .seed_utils import message_method


def line_key(relative_path: str, line: int) -> str:
    return f"{relative_path}:{int(line)}"


class RuntimeKnowledge:
    """Runtime knowledge view for workflow2."""

    _GUESS_REACHABLE_TOKENS = (
        "msg",
        "buf",
        "buffer",
        "payload",
        "body",
        "header",
        "hdr",
        "uri",
        "method",
        "request",
        "reply",
        "param",
        "token",
        "command",
        "parse_",
    )

    def __init__(
        self,
        implementation: str,
        protocol: str,
        templates_file: str | Path,
        *,
        include_function_boundary_targets: bool = False,
    ):
        self.implementation = implementation
        self.protocol = protocol.upper()
        self.templates_file = templates_file
        self.include_function_boundary_targets = bool(include_function_boundary_targets)

        self.templates: dict[str, str] = {}
        self.field_facts: list[dict[str, Any]] = []
        self.boundary_vuln_matches: list[dict[str, Any]] = []
        self.codeql_program_points: list[dict[str, Any]] = []
        self.static_program_points: list[dict[str, Any]] = []

        self._facts_by_field: dict[str, list[dict[str, Any]]] = defaultdict(list)
        self._facts_by_function: dict[str, list[dict[str, Any]]] = defaultdict(list)
        self._target_ids_by_line: dict[str, list[str]] = defaultdict(list)
        self._point_by_target_id: dict[str, dict[str, Any]] = {}
        self._materialized_target_ids: set[str] = set()
        self._function_lines: dict[str, set[int]] = defaultdict(set)
        self._points_by_function: dict[str, list[dict[str, Any]]] = defaultdict(list)
        self._source_root: Path | None = None
        self._source_lines_cache: dict[str, list[str]] = {}
        self._source_path_cache: dict[str, Path | None] = {}
        self._function_source_paths_cache: dict[str, list[str]] = {}
        self._coverage_focus_files_cache: list[str] | None = None

    @property
    def implementation_dir(self) -> Path:
        return implementation_data_dir(self.implementation)

    @property
    def source_root(self) -> Path | None:
        if self._source_root is not None:
            return self._source_root
        primary = implementation_source_dir(self.implementation)
        if primary.exists():
            self._source_root = primary
            return self._source_root
        fallback = resolve_existing_source(self.implementation)
        self._source_root = fallback if fallback and fallback.exists() else None
        return self._source_root

    def _resolve_source_file(self, relative_path: str) -> Path | None:
        rel = str(relative_path or '').strip()
        if not rel:
            return None
        if rel in self._source_path_cache:
            return self._source_path_cache[rel]
        root = self.source_root
        result: Path | None = None
        if root and root.exists():
            candidate = root / rel
            if candidate.exists():
                result = candidate
            else:
                name = Path(rel).name
                matches = list(root.rglob(name))[:2]
                if len(matches) == 1:
                    result = matches[0]
        self._source_path_cache[rel] = result
        return result

    def _load_source_lines(self, path: Path) -> list[str]:
        key = str(path)
        cached = self._source_lines_cache.get(key)
        if cached is not None:
            return cached
        try:
            lines = path.read_text(encoding='utf-8', errors='replace').splitlines()
        except OSError:
            lines = []
        self._source_lines_cache[key] = lines
        return lines

    @staticmethod
    def _render_source_lines(lines: list[str], *, start: int, end: int, target_line: int) -> str:
        rendered = []
        for idx in range(start, end + 1):
            marker = '>>' if idx + 1 == target_line else '  '
            rendered.append(f'{marker} {idx + 1:04d}: {lines[idx]}')
        return '\n'.join(rendered)

    def _source_excerpt_for_target(self, relative_path: str, line_no: int, function_name: str) -> tuple[str, str, str]:
        source_path = self._resolve_source_file(relative_path)
        if source_path is None:
            return '', 'none', ''
        lines = self._load_source_lines(source_path)
        if not lines or line_no <= 0 or line_no > len(lines):
            return '', 'none', str(source_path)

        target_idx = line_no - 1
        func_pattern = re.compile(rf'\b{re.escape(function_name)}\s*\(') if function_name and function_name != 'unknown' else None
        start_idx = max(0, target_idx - 20)
        end_idx = min(len(lines) - 1, target_idx + 20)
        excerpt_kind = 'target-window'

        if func_pattern is not None:
            signature_idx = None
            for idx in range(max(0, target_idx - 120), min(len(lines), target_idx + 1)):
                if func_pattern.search(lines[idx]):
                    signature_idx = idx
            if signature_idx is not None:
                brace_seen = False
                balance = 0
                function_end = None
                for idx in range(signature_idx, min(len(lines), signature_idx + 400)):
                    line = lines[idx]
                    if '{' in line:
                        brace_seen = True
                    balance += line.count('{')
                    balance -= line.count('}')
                    if brace_seen and balance <= 0 and idx > signature_idx:
                        function_end = idx
                        break
                if function_end is not None:
                    if function_end - signature_idx + 1 <= 80:
                        start_idx = signature_idx
                        end_idx = function_end
                        excerpt_kind = 'function'
                    else:
                        start_idx = max(signature_idx, target_idx - 24)
                        end_idx = min(function_end, start_idx + 79)
                        excerpt_kind = 'function-slice'

        excerpt = self._render_source_lines(lines, start=start_idx, end=end_idx, target_line=line_no)
        return excerpt, excerpt_kind, str(source_path)

    @staticmethod
    def _looks_like_function_definition(lines: list[str], start_idx: int, function_name: str) -> bool:
        """Return True when the lines around start_idx resemble a function definition."""
        if start_idx < 0 or start_idx >= len(lines):
            return False
        signature = lines[start_idx].strip()
        if not signature:
            return False
        definition_pattern = re.compile(
            rf'^\s*(?:(?:static|inline|extern|const|volatile|unsigned|signed|short|long|register|struct\s+\w+|union\s+\w+|enum\s+\w+|[A-Za-z_]\w*|\*+)\s+)*\*?\s*{re.escape(function_name)}\s*\('
        )
        if not definition_pattern.match(signature):
            return False

        combined = signature
        for idx in range(start_idx + 1, min(len(lines), start_idx + 6)):
            stripped = lines[idx].strip()
            if not stripped:
                continue
            combined = f'{combined} {stripped}'
            if '{' in stripped or ';' in stripped:
                break
        if ';' in combined and ('{' not in combined or combined.index(';') < combined.index('{')):
            return False
        return '{' in combined

    def _relative_paths_for_function(self, function_name: str) -> list[str]:
        name = str(function_name or '').strip()
        if not name or name == 'unknown':
            return []
        cached = self._function_source_paths_cache.get(name)
        if cached is not None:
            return list(cached)

        results: set[str] = set()
        for point in self._points_by_function.get(name, []):
            location = point.get('location', {})
            relative_path = str(location.get('relative_path') or '').strip()
            if relative_path:
                results.add(relative_path)

        root = self.source_root
        if root and root.exists():
            func_pattern = re.compile(rf'\b{re.escape(name)}\s*\(')
            suffixes = {'.c', '.cc', '.cpp', '.cxx', '.m', '.mm'}
            for source_path in root.rglob('*'):
                if source_path.suffix.lower() not in suffixes or not source_path.is_file():
                    continue
                rel = source_path.relative_to(root).as_posix()
                if rel in results:
                    continue
                lines = self._load_source_lines(source_path)
                if not lines:
                    continue
                for idx, line in enumerate(lines):
                    if not func_pattern.search(line):
                        continue
                    if not self._looks_like_function_definition(lines, idx, name):
                        continue
                    results.add(rel)
                    break

        resolved = sorted(results)
        self._function_source_paths_cache[name] = resolved
        return list(resolved)

    def _allow_function_only_boundary_target(self, relative_path: str, line_no: int) -> bool:
        """Cheap lane gate for guess-only targets.

        We only admit function-level boundary points when their immediate source
        neighborhood still appears to touch message-derived data. This keeps the
        lane small and avoids flooding replay with obvious global/config gates.
        """
        source_path = self._resolve_source_file(relative_path)
        if source_path is None:
            return False
        lines = self._load_source_lines(source_path)
        if not lines or line_no <= 0 or line_no > len(lines):
            return False
        target_idx = line_no - 1
        start_idx = max(0, target_idx - 2)
        end_idx = min(len(lines) - 1, target_idx + 1)
        snippet = "\n".join(lines[start_idx : end_idx + 1]).lower()
        return any(token in snippet for token in self._GUESS_REACHABLE_TOKENS)

    def load(self) -> None:
        """Load templates, dynamic-taint facts, and static program points."""
        catalog = load_template_catalog(self.templates_file)
        for entry in catalog.get(self.protocol, []):
            try:
                template = decode_template_parts(entry)
            except Exception:
                continue
            if not template:
                continue
            method = str(template[0]).strip()
            self.templates[method] = entry

        facts_path = self.implementation_dir / "dynamic_taint" / "normalized_field_facts.json"
        if facts_path.exists():
            data = json.loads(facts_path.read_text(encoding="utf-8"))
            self.field_facts = list(data.get("facts", []))
        for fact in self.field_facts:
            self._facts_by_field[fact.get("field_name", "")].append(fact)
            for func in fact.get("related_functions", []):
                self._facts_by_function[func].append(fact)
            handler = fact.get("handler_function")
            if handler:
                self._facts_by_function[handler].append(fact)

        boundary_path = self.implementation_dir / "vul" / "boundary_vuln_map.json"
        if not boundary_path.exists():
            # Fall back to the legacy knowledge layout so runtime targets do not disappear after a directory migration.
            legacy_boundary_path = compatibility_vul_dir(self.implementation) / "boundary_vuln_map.json"
            if legacy_boundary_path.exists():
                boundary_path = legacy_boundary_path
        if boundary_path.exists():
            data = json.loads(boundary_path.read_text(encoding="utf-8"))
            self.boundary_vuln_matches = list(data.get("matches", []))
        self.codeql_program_points = self._load_codeql_program_points()
        self.static_program_points = self._dedupe_program_points(list(self.boundary_vuln_matches) + list(self.codeql_program_points))
        self._index_program_points()

    def _load_codeql_program_points(self) -> list[dict[str, Any]]:
        candidates = [
            self.implementation_dir / "codeql" / "normalized_codeql.json",
            compatibility_codeql_dir(self.implementation) / "normalized_codeql.json",
            compatibility_codeql_dir(self.implementation).parent / f"{self.implementation}.json",
        ]
        path = next((candidate for candidate in candidates if candidate.exists()), None)
        if not path:
            return []
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return []

        points: list[dict[str, Any]] = []
        for entries in data.get("queries", {}).values():
            for entry in entries:
                field_name = str(entry.get("field_name") or "").strip()
                field_refs = self._codeql_field_refs(field_name)
                related_functions = list(entry.get("related_functions", []))
                mapped_variables = list(entry.get("mapped_variables", []))
                for bp in entry.get("boundary_points", []):
                    points.append(
                        {
                            "type": "boundary",
                            "source": "codeql_static",
                            "match_level": "codeql",
                            "field_refs": field_refs,
                            "related_functions": related_functions,
                            "mapped_variables": mapped_variables,
                            "variables": list(bp.get("variables", [])),
                            "condition": bp.get("condition") or "",
                            "location": {
                                "relative_path": bp.get("file") or "",
                                "line": int(bp.get("line") or 0),
                                "function": bp.get("function") or "unknown",
                                "code": bp.get("condition") or "",
                            },
                        }
                    )
                for vp in entry.get("vuln_points", []):
                    points.append(
                        {
                            "type": "vulnerability",
                            "source": "codeql_static",
                            "match_level": "codeql",
                            "field_refs": field_refs,
                            "related_functions": related_functions,
                            "mapped_variables": mapped_variables,
                            "variables": list(vp.get("variables", [])),
                            "cwe": vp.get("cwe") or "",
                            "description": vp.get("description") or "",
                            "location": {
                                "relative_path": vp.get("file") or "",
                                "line": int(vp.get("line") or 0),
                                "function": vp.get("function") or "unknown",
                                "code": vp.get("code") or "",
                            },
                        }
                    )
        return points

    def _codeql_field_refs(self, field_name: str) -> list[dict[str, Any]]:
        if not field_name:
            return []
        refs: list[dict[str, Any]] = []
        for fact in self._facts_by_field.get(field_name, []):
            ref = {
                "field_name": field_name,
                "command": fact.get("parent_command") or "",
            }
            if ref not in refs:
                refs.append(ref)
        if refs:
            return refs
        return [{"field_name": field_name, "command": ""}]

    @staticmethod
    def _dedupe_program_points(points: list[dict[str, Any]]) -> list[dict[str, Any]]:
        seen = set()
        result = []
        for point in points:
            location = point.get("location", {})
            key = json.dumps(
                {
                    "type": point.get("type"),
                    "file": location.get("relative_path"),
                    "line": location.get("line"),
                    "function": location.get("function"),
                    "code": location.get("code") or point.get("condition") or "",
                },
                sort_keys=True,
                ensure_ascii=False,
            )
            if key in seen:
                continue
            seen.add(key)
            result.append(point)
        return result

    def template_for_method(self, method: str) -> str | None:
        return self.templates.get(method)

    def related_facts_for_point(self, point: dict[str, Any]) -> list[dict[str, Any]]:
        """Find the most relevant dynamic-taint field facts for one program point."""
        field_names = []
        for ref in point.get("field_refs", []):
            name = ref.get("field_name")
            if name:
                field_names.append(name)
        result: list[dict[str, Any]] = []
        for field_name in field_names:
            result.extend(self._facts_by_field.get(field_name, []))
        if result:
            return self._dedupe_facts(result)
        function = point.get("location", {}).get("function") or "unknown"
        return self._dedupe_facts(self._facts_by_function.get(function, []))

    @staticmethod
    def _static_field_refs(point: dict[str, Any]) -> list[dict[str, Any]]:
        refs = point.get("field_refs", [])
        if not isinstance(refs, list):
            return []
        return [ref for ref in refs if isinstance(ref, dict)]

    def _dynamic_facts_for_static_refs(self, point: dict[str, Any]) -> list[dict[str, Any]]:
        """Use only static field refs to fetch dynamic facts, without function-level fallback."""
        result: list[dict[str, Any]] = []
        for ref in self._static_field_refs(point):
            field_name = ref.get("field_name")
            if field_name:
                result.extend(self._facts_by_field.get(field_name, []))
        return self._dedupe_facts(result)

    def _function_facts_for_point(self, point: dict[str, Any]) -> list[dict[str, Any]]:
        """Fall back to dynamic facts associated with the enclosing function."""
        function = point.get("location", {}).get("function") or "unknown"
        return self._dedupe_facts(self._facts_by_function.get(function, []))

    def _evidence_bundle_for_point(self, point: dict[str, Any]) -> dict[str, Any]:
        """Build a unified evidence view for a target.

        Priority:
        - dynamic: dynamic field facts exist, regardless of whether static refs also exist
        - static: only static refs exist
        - function: only function location / condition text remains
        """
        static_refs = self._static_field_refs(point)
        dynamic_from_static = self._dynamic_facts_for_static_refs(point)
        function_facts = []
        if not dynamic_from_static:
            function_facts = self._function_facts_for_point(point)
        dynamic_facts = dynamic_from_static or function_facts
        if dynamic_facts:
            evidence_mode = "dynamic"
            info_rank = 0
        elif static_refs:
            evidence_mode = "static"
            info_rank = 1
        else:
            evidence_mode = "function"
            info_rank = 2
        return {
            "static_refs": static_refs,
            "dynamic_facts": dynamic_facts,
            "function_facts": function_facts,
            "evidence_mode": evidence_mode,
            "info_rank": info_rank,
        }

    @staticmethod
    def _point_kind(point: dict[str, Any]) -> str:
        return "boundary" if point.get("type") == "boundary" else "vuln"

    @staticmethod
    def _point_line_keys(relative_path: str, line: int) -> list[str]:
        keys = [line_key(relative_path, line), f'{Path(relative_path).name}:{line}']
        return [key for idx, key in enumerate(keys) if key and key not in keys[:idx]]

    def _target_id_for_point(self, point: dict[str, Any]) -> str:
        location = point.get("location", {})
        relative_path = location.get("relative_path") or ""
        line = int(location.get("line") or 0)
        return f'{self._point_kind(point)}:{relative_path}:{line}'

    def _index_program_points(self) -> None:
        self._target_ids_by_line.clear()
        self._point_by_target_id.clear()
        self._function_lines.clear()
        self._points_by_function.clear()
        for point in self.static_program_points:
            location = point.get("location", {})
            relative_path = str(location.get("relative_path") or "").strip()
            function = location.get("function") or "unknown"
            line = int(location.get("line") or 0)
            if line:
                self._function_lines[function].add(line)
            self._points_by_function[function].append(point)
            if not relative_path or not line:
                continue
            target_id = self._target_id_for_point(point)
            self._point_by_target_id[target_id] = point
            for key in self._point_line_keys(relative_path, line):
                self._target_ids_by_line[key].append(target_id)

    def target_catalog_size(self) -> int:
        return len(self._point_by_target_id)

    def _build_target_record(self, point: dict[str, Any]) -> TargetRecord | None:
        location = point.get("location", {})
        relative_path = location.get("relative_path") or ""
        line = int(location.get("line") or 0)
        if not relative_path or not line:
            return None
        kind = self._point_kind(point)
        evidence = self._evidence_bundle_for_point(point)
        static_refs = list(evidence["static_refs"])
        facts = list(evidence["dynamic_facts"])
        field_names = []
        commands = []
        evidence_score = 0
        template_bonus = 0
        for ref in static_refs:
            field_name = ref.get("field_name")
            command = ref.get("command")
            if field_name and field_name not in field_names:
                field_names.append(field_name)
            if command and command not in commands:
                commands.append(command)
        for fact in facts:
            field_name = fact.get("field_name")
            command = fact.get("parent_command")
            if field_name and field_name not in field_names:
                field_names.append(field_name)
            if command and command not in commands:
                commands.append(command)
            if fact.get("mapped_variables"):
                evidence_score += 2
            if fact.get("risk_tags"):
                evidence_score += 1
            if command and self.template_for_method(command):
                template_bonus += 1
        info_rank = int(evidence["info_rank"])
        if kind == "vuln" and info_rank == 0 and not (commands and template_bonus):
            info_rank = 1
        if kind == "boundary" and info_rank == 2:
            boundary_lane = "guess"
        else:
            boundary_lane = "strict"
        return TargetRecord(
            target_id=self._target_id_for_point(point),
            kind=kind,
            implementation=self.implementation,
            protocol=self.protocol,
            relative_path=relative_path,
            line=line,
            function=location.get("function") or "unknown",
            code=location.get("code") or point.get("condition") or "",
            field_names=field_names,
            commands=commands,
            evidence_score=evidence_score,
            info_rank=info_rank,
            source_payload={
                "program_point": point,
                "field_facts": facts,
                "static_refs": static_refs,
                "function_facts": evidence["function_facts"],
                "evidence_mode": evidence["evidence_mode"],
                "boundary_lane": boundary_lane,
                "match_level": point.get("match_level", "none"),
            },
        )

    def materialize_targets_by_id(self, target_ids: list[str]) -> list[TargetRecord]:
        records: list[TargetRecord] = []
        for target_id in target_ids:
            if target_id in self._materialized_target_ids:
                continue
            point = self._point_by_target_id.get(target_id)
            if not point:
                continue
            record = self._build_target_record(point)
            if record is None:
                continue
            self._materialized_target_ids.add(target_id)
            records.append(record)
        return records

    @staticmethod
    def _covered_line_numbers(covered_lines: set[str]) -> dict[str, set[int]]:
        by_file: dict[str, set[int]] = defaultdict(set)
        for key in covered_lines:
            try:
                rel, line_str = key.rsplit(':', 1)
                line_no = int(line_str)
            except (ValueError, TypeError):
                continue
            by_file[rel].add(line_no)
            by_file[Path(rel).name].add(line_no)
        return by_file

    @staticmethod
    def _covered_branch_lines(covered_branches: set[str]) -> set[str]:
        keys: set[str] = set()
        for branch_key in covered_branches:
            try:
                rel, line_str, _side = branch_key.rsplit(':', 2)
                line_no = int(line_str)
            except (ValueError, TypeError):
                continue
            keys.add(f'{rel}:{line_no}')
            keys.add(f'{Path(rel).name}:{line_no}')
        return keys

    def materialize_boundary_targets_for_coverage(
        self,
        *,
        covered_lines: set[str],
        covered_branches: set[str],
        radius: int = 3,
        limit: int = 4096,
    ) -> list[TargetRecord]:
        covered_by_file = self._covered_line_numbers(covered_lines)
        covered_branch_lines = self._covered_branch_lines(covered_branches)
        records: list[TargetRecord] = []
        for point in self.static_program_points:
            if point.get("type") != "boundary":
                continue
            target_id = self._target_id_for_point(point)
            if target_id in self._materialized_target_ids:
                continue
            location = point.get("location", {})
            relative_path = str(location.get("relative_path") or "").strip()
            line = int(location.get("line") or 0)
            if not relative_path or not line:
                continue
            line_keys = self._point_line_keys(relative_path, line)
            touched = any(key in covered_branch_lines for key in line_keys)
            nearby = False
            if not touched:
                for file_key in {relative_path, Path(relative_path).name}:
                    lines = covered_by_file.get(file_key, set())
                    if not lines:
                        continue
                    if line in lines or any((line + offset) in lines for offset in range(-radius, radius + 1) if offset != 0):
                        nearby = True
                        break
            if not touched and not nearby:
                continue
            record = self._build_target_record(point)
            if record is None:
                continue
            self._materialized_target_ids.add(target_id)
            records.append(record)
            if limit > 0 and len(records) >= limit:
                break
        return records

    def build_targets(self) -> list[TargetRecord]:
        """Build schedulable targets from static boundary/vulnerability program points."""
        targets: list[TargetRecord] = []
        for point in self.static_program_points:
            record = self._build_target_record(point)
            if record is None:
                continue
            self._materialized_target_ids.add(record.target_id)
            targets.append(record)
        return targets

    def coverage_focus_relative_paths(self) -> list[str]:
        """Return source files most worth tracking during replay coverage capture."""
        cached = self._coverage_focus_files_cache
        if cached is not None:
            return list(cached)

        dynamic_functions: set[str] = set()
        for fact in self.field_facts:
            handler = str(fact.get("handler_function") or "").strip()
            if handler:
                dynamic_functions.add(handler)
            for func in fact.get("related_functions", []) or []:
                name = str(func or "").strip()
                if name:
                    dynamic_functions.add(name)

        files: set[str] = set()
        for function_name in dynamic_functions:
            files.update(self._relative_paths_for_function(function_name))

        for point in self.static_program_points:
            location = point.get("location", {})
            relative_path = str(location.get("relative_path") or "").strip()
            if not relative_path:
                continue
            function_name = str(location.get("function") or "").strip()
            evidence = self._evidence_bundle_for_point(point)
            if evidence["static_refs"] or evidence["dynamic_facts"] or function_name in dynamic_functions:
                files.add(relative_path)

        result = sorted(files)
        self._coverage_focus_files_cache = result
        return list(result)

    def hit_targets_for_lines(self, lines: set[str]) -> tuple[list[str], list[str]]:
        """Map covered line sets back to boundary/vulnerability targets.

        Support both full-path and basename matching to bridge differences between static analysis and gcovr
        when their directory prefixes do not match.
        """
        boundary_ids: list[str] = []
        vuln_ids: list[str] = []
        for key in lines:
            for target_id in self._target_ids_by_line.get(key, []):
                if target_id.startswith("boundary:") and target_id not in boundary_ids:
                    boundary_ids.append(target_id)
                if target_id.startswith("vuln:") and target_id not in vuln_ids:
                    vuln_ids.append(target_id)
            # Basename fallback: gcovr may report keys like ftpserv.c:291 while
            # the index stores Source/ftpserv.c:291.
            try:
                _, line_str = key.rsplit(":", 1)
                file_key = f"{Path(key.rsplit(':', 1)[0]).name}:{line_str}"
            except (ValueError, IndexError):
                continue
            if file_key == key:
                continue
            for target_id in self._target_ids_by_line.get(file_key, []):
                if target_id.startswith("boundary:") and target_id not in boundary_ids:
                    boundary_ids.append(target_id)
                if target_id.startswith("vuln:") and target_id not in vuln_ids:
                    vuln_ids.append(target_id)
        return boundary_ids, vuln_ids

    def boundary_branch_state(self, target_row: dict[str, Any], covered_branches: set[str]) -> dict[str, Any] | None:
        """Determine whether one side of a boundary has been covered while the other remains uncovered.

        Support full-path and basename matching to handle ROOT_DIR mismatches between static analysis and gcovr.
        """
        rel = target_row["relative_path"]
        line_no = int(target_row["line"])
        prefixes = [f"{rel}:{line_no}:", f"{Path(rel).name}:{line_no}:"]
        if prefixes[0] == prefixes[1]:
            prefixes.pop()

        seen_sides: set[int] = set()
        matched_prefix = prefixes[0]
        for branch_key in covered_branches:
            remaining = None
            for prefix in prefixes:
                if branch_key.startswith(prefix):
                    remaining = branch_key[len(prefix):]
                    matched_prefix = prefix
                    break
            if remaining is None:
                continue
            try:
                seen_sides.add(int(remaining))
            except ValueError:
                continue

        binary_sides = {side for side in seen_sides if side in (0, 1)}
        if len(binary_sides) != 1:
            return None

        covered_side = next(iter(binary_sides))
        missing_side = 1 - covered_side
        return {
            "covered_side": covered_side,
            "missing_side": missing_side,
            "covered_branch_key": f"{matched_prefix}{covered_side}",
            "missing_branch_key": f"{matched_prefix}{missing_side}",
        }

    def frontier_score(self, target_row: dict[str, Any], covered_lines: set[str], radius: int = 3) -> float:
        """Estimate whether a boundary target currently lies near the coverage frontier."""
        rel = target_row["relative_path"]
        line_no = int(target_row["line"])
        keys = [line_key(rel, line_no), f"{Path(rel).name}:{line_no}"]
        if keys[0] == keys[1]:
            keys.pop()
        if any(k in covered_lines for k in keys):
            return 0.0

        nearby = 0
        for offset in range(-radius, radius + 1):
            if offset == 0:
                continue
            neighbors = [line_key(rel, line_no + offset), f"{Path(rel).name}:{line_no + offset}"]
            if neighbors[0] == neighbors[1]:
                neighbors.pop()
            if any(n in covered_lines for n in neighbors):
                nearby += 1

        function = target_row["function_name"]
        function_lines = self._function_lines.get(function, set())
        covered_in_function = 0
        if function_lines:
            for ln in function_lines:
                fn_keys = [line_key(rel, ln), f"{Path(rel).name}:{ln}"]
                if fn_keys[0] == fn_keys[1]:
                    fn_keys.pop()
                if any(fk in covered_lines for fk in fn_keys):
                    covered_in_function += 1

        if nearby == 0 and covered_in_function == 0:
            return 0.0
        return nearby + (covered_in_function / max(len(function_lines), 1))

    def seed_context_for_task(
        self,
        *,
        target_row: dict[str, Any],
        seed_text: str,
        messages: list[str],
        step_index: int,
    ) -> dict[str, Any]:
        """Assemble context for an LLM mutation task."""
        source_payload = json.loads(target_row.get("source_payload_json") or "{}") if isinstance(target_row.get("source_payload_json"), str) else target_row.get("source_payload", {})
        facts = list(source_payload.get("field_facts", []))
        static_refs = list(source_payload.get("static_refs", []))
        function_facts = list(source_payload.get("function_facts", []))
        evidence_mode = str(source_payload.get("evidence_mode") or "function")
        commands = json.loads(target_row.get("commands_json") or "[]") if isinstance(target_row.get("commands_json"), str) else list(target_row.get("commands", []))
        command_templates = []
        for command in commands:
            template = self.template_for_method(command)
            if template:
                constraint = template_constraint_for_entry(self.protocol, template)
                command_templates.append({
                    "command": command,
                    "template": template,
                    "constraint": constraint,
                    "constraint_summary": summarize_template_constraint(constraint),
                })
        seed_lines = seed_text.splitlines()
        seed_head_lines = [f"{idx + 1:02d}: {line}" for idx, line in enumerate(seed_lines[:20])]
        prefix_text = "".join(messages[:step_index]) if 0 <= step_index <= len(messages) else ""
        source_excerpt, source_excerpt_kind, source_path = self._source_excerpt_for_target(
            str(target_row.get("relative_path") or ""),
            int(target_row.get("line") or 0),
            str(target_row.get("function_name") or target_row.get("function") or "unknown"),
        )
        methods = [message_method(msg) for msg in messages if message_method(msg)]

        return {
            "seed_text": seed_text,
            "messages_before": messages[:step_index],
            "current_message": messages[step_index] if 0 <= step_index < len(messages) else "",
            "messages_after": messages[step_index + 1:] if 0 <= step_index < len(messages) else [],
            "field_facts": facts,
            "static_refs": static_refs,
            "function_facts": function_facts,
            "evidence_mode": evidence_mode,
            "command_templates": command_templates,
            "template_constraints": [item.get("constraint", {}) for item in command_templates if isinstance(item, dict)],
            "seed_head_lines": seed_head_lines,
            "prefix_text": prefix_text,
            "step_index": step_index,
            "methods": methods,
            "source_excerpt": source_excerpt,
            "source_excerpt_kind": source_excerpt_kind,
            "source_path": source_path,
        }

    @staticmethod
    def _dedupe_facts(facts: list[dict[str, Any]]) -> list[dict[str, Any]]:
        seen = set()
        result = []
        for fact in facts:
            key = json.dumps(
                {
                    "field_name": fact.get("field_name"),
                    "command": fact.get("parent_command"),
                    "related_functions": fact.get("related_functions", []),
                },
                sort_keys=True,
                ensure_ascii=False,
            )
            if key in seen:
                continue
            seen.add(key)
            result.append(fact)
        return result
