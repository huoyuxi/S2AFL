#!/usr/bin/env python3
"""
S2AFL unified CLI.

Commands:
  gen-messages    Generate field offset map from templates
  gen-seeds       Generate enriched initial seed sequences (PSEI)
  export-seeds    Export PSEI seed JSON into AFLNet raw seed files
  augment-seeds   Backup baseline seeds and create an augmented seed directory
  sync-impls      Sync implementation source trees into S2AFL/implementations/src
  import-dyntaint Import instrumented dynamic taint JSON into the knowledge layer
  scan-sources    Run static source analysis + field matching
  convert         Convert ChatPRE field_variable_map.json → field_code_facts.json
  import-codeql   Normalize raw CodeQL JSON into KG schema
  advise          Query mutation advisor (boundary/vuln → field)
  kg              Inspect normalized KG / reserved CodeQL interface
  vsam            Print VSAM context
  sbgm            Print SBGM context
"""

from __future__ import annotations

import argparse
import json
import os
import re
import signal
import socket
import sys
import threading
import time
from datetime import datetime
from pathlib import Path

from S2AFL.core.templates import DEFAULT_TEMPLATE_CATALOG
from S2AFL.knowledge.implementation_registry import (
    IMPLEMENTATION_SRC_ROOT,
    KNOWLEDGE_DATA_ROOT,
    RESULTS_ROOT,
    implementation_names,
    implementation_protocol,
)

CLI_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(CLI_DIR)
DATA_DIR = os.path.join(PROJECT_ROOT, "knowledge", "data")
RESULTS_DIR = str(RESULTS_ROOT)




def _runtime_instance_tag() -> str:
    raw = (os.environ.get("S2AFL_RUN_INSTANCE") or os.environ.get("HOSTNAME") or socket.gethostname() or "host").strip()
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "-", raw).strip("-._")
    if not safe:
        safe = "host"
    return safe[:12]


def _runtime_run_tag(subject: str) -> str:
    ts = datetime.now().strftime('%Y%m%d-%H%M%S')
    return f"{ts}-{subject}-{_runtime_instance_tag()}-p{os.getpid()}"


def _latest_runtime_summary_path(subject: str) -> Path:
    return Path(PROJECT_ROOT) / 'output' / 'workflow2' / 'runtime' / f'latest_run_summary.{subject}.json'


def _install_runtime_signal_handlers(controller):
    previous = {}

    def _handler(signum, _frame):
        try:
            signame = signal.Signals(signum).name
        except Exception:
            signame = str(signum)
        controller.request_stop(f'signal received: {signame}')

    for signum in (signal.SIGINT, signal.SIGTERM):
        previous[signum] = signal.getsignal(signum)
        signal.signal(signum, _handler)
    return previous


def _restore_runtime_signal_handlers(previous):
    for signum, handler in previous.items():
        signal.signal(signum, handler)


def _runtime_summary_extra(args, run_tag: str, status: str) -> dict[str, object]:
    return {
        'requested_duration_sec': args.duration_sec,
        'config_path': args.config,
        'requested_run_tag': run_tag,
        'status': status,
        'summary_pid': os.getpid(),
        'heartbeat_at': time.time(),
    }

def _apply_llm_cli_overrides(args) -> None:
    provider = getattr(args, 'llm_provider', '') or ''
    config_path = getattr(args, 'llm_config', '') or ''
    if provider:
        os.environ['LLM_PROVIDER'] = provider
    if config_path:
        os.environ['S2AFL_LLM_CONFIG'] = config_path


def _field_map_for(protocol: str) -> str | None:
    """Auto-detect field_variable_map.json for a protocol or implementation name."""
    for f in os.listdir(RESULTS_DIR) if os.path.isdir(RESULTS_DIR) else []:
        if protocol.lower() in f.lower() and f.endswith("_field_variable_map.json"):
            return os.path.join(RESULTS_DIR, f)
    return None


def cmd_gen_messages(args):
    _apply_llm_cli_overrides(args)
    from S2AFL.knowledge.field_offset_mapper import main as gen
    sys.argv = ["field_offset_mapper"]
    if args.templates:
        sys.argv.extend(["--templates-file", args.templates])
    if args.output_dir:
        sys.argv.extend(["--output-dir", args.output_dir])
    if args.llm:
        sys.argv.append("--llm")
    gen()


def cmd_gen_templates(args):
    _apply_llm_cli_overrides(args)
    from S2AFL.core.template_builder import main as gen

    sys.argv = [
        "template_builder",
        "--protocol", args.protocol,
        "--model", args.model,
        "--consistency-count", str(args.consistency_count),
        "--max-template-regen", str(args.max_template_regen),
        "--max-reflection-rounds", str(args.max_reflection_rounds),
        "--temperature", str(args.temperature),
        "--max-tokens", str(args.max_tokens),
    ]
    if args.output_dir:
        sys.argv.extend(["--output-dir", args.output_dir])
    if args.catalog_out:
        sys.argv.extend(["--catalog-out", args.catalog_out])
    gen()


def cmd_gen_seeds(args):
    _apply_llm_cli_overrides(args)
    from S2AFL.psei.seed_gen import generate_seeds

    templates_file = args.templates or str(DEFAULT_TEMPLATE_CATALOG)
    output = args.output or os.path.join(PROJECT_ROOT, "output", "seeds", f"{args.protocol}_psei_seeds.json")
    result = generate_seeds(
        protocol=args.protocol,
        templates_file=templates_file,
        initial_sequences_file=args.initial_sequences,
        seed_corpus_dir=args.seed_corpus_dir,
        seed=args.seed,
        max_sequences=args.max_sequences,
        use_llm_messages=args.llm_messages,
    )
    os.makedirs(os.path.dirname(output), exist_ok=True)
    with open(output, "w") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)
    print(json.dumps(result["stats"], indent=2, ensure_ascii=False))
    print(f"Written -> {output}")


def cmd_export_seeds(args):
    from S2AFL.psei.export_seeds import export_seed_json

    result = export_seed_json(args.input, args.output_dir, args.prefix)
    print(json.dumps(result, indent=2, ensure_ascii=False))


def cmd_augment_seeds(args):
    from S2AFL.psei.augment_seeds import augment_seed_directory

    result = augment_seed_directory(
        original_dir=args.original_dir,
        generated_dir=args.generated_dir,
        output_dir=args.output_dir,
        backup_dir=args.backup_dir,
    )
    print(json.dumps(result, indent=2, ensure_ascii=False))


def cmd_sync_impls(args):
    from S2AFL.knowledge import sync_all_sources

    result = sync_all_sources(overwrite=args.overwrite)
    print(json.dumps({
        "implementation_root": str(IMPLEMENTATION_SRC_ROOT),
        "results": result,
    }, indent=2, ensure_ascii=False))


def cmd_import_dyntaint(args):
    from S2AFL.knowledge import import_all_dynamic_taint, import_dynamic_taint_for_implementation

    if args.implementation:
        result = import_dynamic_taint_for_implementation(args.implementation)
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return
    result = import_all_dynamic_taint()
    print(json.dumps({
        "results_dir": RESULTS_DIR,
        "results": result,
    }, indent=2, ensure_ascii=False))


def cmd_scan_sources(args):
    from S2AFL.knowledge.code_analyzer import analyze_implementation, main as scan_main

    if args.implementation:
        result = analyze_implementation(args.implementation, field_map_path=args.field_map)
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return

    sys.argv = ["code_analyzer"]
    if args.source:
        sys.argv.extend(["--source-dir", args.source])
    if args.field_map:
        sys.argv.extend(["--field-map", args.field_map])
    if args.output:
        sys.argv.extend(["-o", args.output])
    scan_main()


def cmd_convert(args):
    from S2AFL.knowledge.chatpre_to_facts import convert

    input_file = args.input or _field_map_for(args.protocol or "LightFTP")
    output = args.output or os.path.join(DATA_DIR, "facts", "field_code_facts.json")

    result = convert(input_file)
    os.makedirs(os.path.dirname(output), exist_ok=True)
    with open(output, "w") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)
    proto = list(result.keys())[0]
    print(f"Converted {proto}: {len(result[proto])} fields -> {output}")


def cmd_advise(args):
    _apply_llm_cli_overrides(args)
    from S2AFL.agent.mutation_advisor import MutationAdvisor

    field_map = args.field_map or _field_map_for(args.protocol or "LightFTP")
    vuln_db = args.vuln_db or os.path.join(DATA_DIR, "vuln", "generated_protocol_src_vuln.json")
    bv_map = args.bv_map or os.path.join(DATA_DIR, "facts", f"{args.protocol or 'LightFTP'}_boundary_vuln_map.json")

    advisor = MutationAdvisor(field_map, vuln_db, bv_map, args.protocol or "FTP")

    if args.vsam:
        print(advisor.build_vsam_context())
    if args.sbgm:
        print(advisor.build_sbgm_context())
    if args.vsam or args.sbgm:
        return

    if not args.code:
        print("ERROR: --code is required for advise mode")
        sys.exit(1)
    result = advisor.advise(args.code, args.function)
    print(json.dumps(result, indent=2, ensure_ascii=False))


def cmd_import_codeql(args):
    from S2AFL.knowledge import convert_codeql_file, import_codeql_for_implementation

    if args.per_implementation:
        if not args.implementation:
            raise SystemExit("--implementation is required with --per-implementation")
        result = import_codeql_for_implementation(
            args.input,
            implementation=args.implementation,
            protocol=args.protocol,
        )
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return

    output = args.output
    if not output:
        name = args.implementation or os.path.basename(args.input).replace(".json", "")
        output = os.path.join(DATA_DIR, "codeql", f"{name}.json")

    result = convert_codeql_file(
        args.input,
        output_path=output,
        implementation=args.implementation,
        protocol=args.protocol,
    )
    print(json.dumps(
        {
            "written": output,
            "implementation": result.get("implementation"),
            "protocol": result.get("protocol"),
            "field_candidates": len(result.get("queries", {}).get("field_candidates", [])),
        },
        indent=2,
        ensure_ascii=False,
    ))


def cmd_kg(args):
    from S2AFL.knowledge import KnowledgeBase

    kb = KnowledgeBase(
        results_dir=args.results_dir or RESULTS_DIR,
        facts_dir=os.path.join(DATA_DIR, "facts"),
        vuln_db_path=args.vuln_db or os.path.join(DATA_DIR, "vuln", "generated_protocol_src_vuln.json"),
        codeql_dir=args.codeql_dir or os.path.join(DATA_DIR, "codeql"),
    )
    kb.load()

    if args.list_impls:
        print(json.dumps(kb.implementations, indent=2, ensure_ascii=False))
        return

    target = args.implementation or args.protocol
    if not target:
        print(json.dumps(
            {
                "implementations": kb.implementations,
                "protocols": kb.protocols,
            },
            indent=2,
            ensure_ascii=False,
        ))
        return

    summary = {
        "target": target,
        "high_risk_fields": [
            {
                "field_name": x.get("field_name"),
                "command": x.get("parent_command"),
                "risk_tags": x.get("risk_tags", []),
                "evidence_sources": x.get("merged_evidence", {}).get("sources", []),
                "evidence_confidence": x.get("merged_evidence", {}).get("confidence"),
            }
            for x in kb.get_high_risk_fields(target, min_priority="low")[: args.limit]
        ],
        "boundary_fields": [
            {
                "field_name": x.get("field_name"),
                "command": x.get("parent_command"),
                "boundary_points": len(x.get("boundary_points", [])),
                "evidence_sources": x.get("merged_evidence", {}).get("sources", []),
            }
            for x in kb.get_boundary_fields(target)[: args.limit]
        ],
        "codeql_candidates": kb.get_codeql_candidates(target, args.query_name)[: args.limit],
    }
    print(json.dumps(summary, indent=2, ensure_ascii=False))


def cmd_run_runtime(args):
    _apply_llm_cli_overrides(args)
    from S2AFL.runtime import RuntimeConfig, RuntimeController

    config = RuntimeConfig.from_file(args.config)
    run_tag = args.run_tag or _runtime_run_tag(config.subject)
    config.apply_run_tag(run_tag)
    controller = RuntimeController(config)

    latest_summary = _latest_runtime_summary_path(config.subject)
    run_summary = controller.config.resolved_log_dir / 'run_summary.json'

    def _write_summaries(status: str) -> None:
        extra = _runtime_summary_extra(args, run_tag, status)
        controller.dump_runtime_summary(latest_summary, extra=extra)
        controller.dump_runtime_summary(run_summary, extra=extra)
        if args.dump_summary:
            controller.dump_runtime_summary(args.dump_summary, extra=extra)

    _write_summaries('starting')
    heartbeat_stop = threading.Event()
    status_ref = {'status': 'running'}

    def _heartbeat_loop() -> None:
        while not heartbeat_stop.wait(30.0):
            _write_summaries(status_ref['status'])

    heartbeat_thread = threading.Thread(target=_heartbeat_loop, name='runtime-summary-heartbeat', daemon=True)
    heartbeat_thread.start()
    previous_handlers = _install_runtime_signal_handlers(controller)
    status = 'completed'
    try:
        _write_summaries('running')
        controller.run_forever(duration_sec=args.duration_sec)
    except Exception:
        status = 'failed'
        status_ref['status'] = status
        raise
    finally:
        status_ref['status'] = status
        heartbeat_stop.set()
        heartbeat_thread.join(timeout=2)
        _write_summaries(status)
        _restore_runtime_signal_handlers(previous_handlers)


def cmd_debug_aflnet(args):
    _apply_llm_cli_overrides(args)
    from S2AFL.runtime import RuntimeConfig
    from S2AFL.runtime.debug_tools import debug_aflnet_startup

    result = debug_aflnet_startup(
        RuntimeConfig.from_file(args.config),
        bootstrap=args.bootstrap,
    )
    text = json.dumps(result, indent=2, ensure_ascii=False)
    print(text)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")


def cmd_debug_replay(args):
    _apply_llm_cli_overrides(args)
    from S2AFL.runtime import RuntimeConfig
    from S2AFL.runtime.debug_tools import debug_replay_coverage

    result = debug_replay_coverage(
        RuntimeConfig.from_file(args.config),
        seed_path=args.seed,
        step_index=args.step_index,
    )
    text = json.dumps(result, indent=2, ensure_ascii=False)
    print(text)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")


def cmd_run_replay_worker(args):
    _apply_llm_cli_overrides(args)
    from S2AFL.runtime import RuntimeConfig
    from S2AFL.runtime.replay_monitor import ReplayMonitorController

    controller = ReplayMonitorController(
        RuntimeConfig.from_file(args.config),
        watch_dir=args.watch_dir,
        poll_interval_sec=args.poll_interval,
    )
    controller.run_forever()


def main():
    p = argparse.ArgumentParser(description="S2AFL unified CLI")
    sub = p.add_subparsers(dest="command")

    sp = sub.add_parser("gen-messages", help="Generate field offset map from templates")
    sp.add_argument("--templates", help="Shared template catalog JSON file")
    sp.add_argument("--output-dir", help="Optional output directory for generated field facts")
    sp.add_argument("--llm", action="store_true", help="Use LLM mode when rendering messages")
    sp.add_argument("--llm-provider", help="Shared LLM profile name, for example deepseek, gpt.lightftp, qwen.kamailio")
    sp.add_argument("--llm-config", help="Path to shared LLM profile JSON")

    sp = sub.add_parser("gen-templates", help="Generate protocol templates with the shared core builder")
    sp.add_argument("--protocol", required=True)
    sp.add_argument("--model", default=os.environ.get("LLM_MODEL", "deepseek-v4-flash"))
    sp.add_argument("--consistency-count", type=int, default=1)
    sp.add_argument("--max-template-regen", type=int, default=2)
    sp.add_argument("--max-reflection-rounds", type=int, default=3)
    sp.add_argument("--temperature", type=float, default=0.2)
    sp.add_argument("--max-tokens", type=int, default=8192)
    sp.add_argument("--output-dir")
    sp.add_argument("--catalog-out", help="Optional shared template catalog JSON file to update")
    sp.add_argument("--llm-provider", help="Shared LLM profile name, for example deepseek, gpt.lightftp, qwen.kamailio")
    sp.add_argument("--llm-config", help="Path to shared LLM profile JSON")

    sp = sub.add_parser("gen-seeds", help="Generate enriched initial seed sequences (PSEI)")
    sp.add_argument("--protocol", required=True)
    sp.add_argument("--templates")
    sp.add_argument("--initial-sequences")
    sp.add_argument("--seed-corpus-dir", help="Original raw seed corpus directory used as LLM/corpus context")
    sp.add_argument("--seed", type=int, default=1337)
    sp.add_argument("--max-sequences", type=int, default=64)
    sp.add_argument("--llm-messages", action="store_true", help="Use LLM-guided per-template default field values, then render messages by template interpolation")
    sp.add_argument("-o", "--output")
    sp.add_argument("--llm-provider", help="Shared LLM profile name, for example deepseek, gpt.lightftp, qwen.kamailio")
    sp.add_argument("--llm-config", help="Path to shared LLM profile JSON")

    sp = sub.add_parser("export-seeds", help="Export PSEI seed JSON into AFLNet raw seed files")
    sp.add_argument("input", help="PSEI seed JSON file")
    sp.add_argument("-o", "--output-dir", required=True)
    sp.add_argument("--prefix")

    sp = sub.add_parser("augment-seeds", help="Backup baseline seeds and create an augmented seed directory")
    sp.add_argument("--original-dir", required=True)
    sp.add_argument("--generated-dir", required=True)
    sp.add_argument("--output-dir", required=True)
    sp.add_argument("--backup-dir")

    sp = sub.add_parser("sync-impls", help="Sync implementation source trees into S2AFL/implementations/src")
    sp.add_argument("--overwrite", action="store_true")

    sp = sub.add_parser("import-dyntaint", help="Import dynamic taint JSON into the per-implementation knowledge layout")
    sp.add_argument("--implementation", choices=implementation_names())

    sp = sub.add_parser("scan-sources", help="Static source analysis + field matching")
    sp.add_argument("--implementation", choices=implementation_names())
    sp.add_argument("--source", help="Source directory override")
    sp.add_argument("--field-map", help="ChatPRE field_variable_map.json override")
    sp.add_argument("--protocol", help="Protocol name for compatibility mode")
    sp.add_argument("-o", "--output")

    sp = sub.add_parser("convert", help="Convert ChatPRE -> field_code_facts.json")
    sp.add_argument("--input", help="ChatPRE field_variable_map.json")
    sp.add_argument("--protocol")
    sp.add_argument("-o", "--output")

    sp = sub.add_parser("import-codeql", help="Normalize raw CodeQL JSON into KG schema")
    sp.add_argument("input", help="Raw or normalized CodeQL JSON")
    sp.add_argument("--implementation", choices=implementation_names())
    sp.add_argument("--protocol")
    sp.add_argument("--per-implementation", action="store_true")
    sp.add_argument("-o", "--output")

    sp = sub.add_parser("advise", help="Mutation advisor query")
    sp.add_argument("--field-map")
    sp.add_argument("--vuln-db")
    sp.add_argument("--bv-map")
    sp.add_argument("--protocol")
    sp.add_argument("--code", "-c", default=None)
    sp.add_argument("--function", "-f")
    sp.add_argument("--vsam", action="store_true")
    sp.add_argument("--sbgm", action="store_true")
    sp.add_argument("--llm-provider", help="Shared LLM profile name, for example deepseek, gpt.lightftp, qwen.kamailio")
    sp.add_argument("--llm-config", help="Path to shared LLM profile JSON")

    sp = sub.add_parser("kg", help="Inspect normalized KG / CodeQL bridge")
    sp.add_argument("--protocol")
    sp.add_argument("--implementation")
    sp.add_argument("--results-dir")
    sp.add_argument("--vuln-db")
    sp.add_argument("--codeql-dir")
    sp.add_argument("--query-name", default="field_candidates")
    sp.add_argument("--limit", type=int, default=5)
    sp.add_argument("--list-impls", action="store_true")

    sp = sub.add_parser("run-runtime", help="Run the full workflow2 runtime controller")
    sp.add_argument("--config", required=True, help="Runtime TOML/JSON config file")
    sp.add_argument("--duration-sec", type=float, help="Optional maximum runtime in seconds; workflow2 will stop itself cleanly at the deadline")
    sp.add_argument("--run-tag", help="Optional explicit run tag; defaults to a timestamped tag")
    sp.add_argument("--dump-summary", help="Optional path for a small runtime summary JSON")
    sp.add_argument("--llm-provider", help="Shared LLM profile name, for example deepseek, gpt.lightftp, qwen.kamailio")
    sp.add_argument("--llm-config", help="Path to shared LLM profile JSON")

    sp = sub.add_parser("debug-aflnet", help="Debug AFLNet startup and dry-run only")
    sp.add_argument("--config", required=True, help="Runtime TOML/JSON config file")
    sp.add_argument("--bootstrap", action="store_true", help="Regenerate and rescreen the initial corpus before startup debug")
    sp.add_argument("--output")
    sp.add_argument("--llm-provider", help="Shared LLM profile name, for example deepseek, gpt.lightftp, qwen.kamailio")
    sp.add_argument("--llm-config", help="Path to shared LLM profile JSON")

    sp = sub.add_parser("debug-replay", help="Debug one replay and one coverage capture only")
    sp.add_argument("--config", required=True, help="Runtime TOML/JSON config file")
    sp.add_argument("--seed", required=True, help="Raw seed path")
    sp.add_argument("--step-index", type=int)
    sp.add_argument("--output")
    sp.add_argument("--llm-provider", help="Shared LLM profile name, for example deepseek, gpt.lightftp, qwen.kamailio")
    sp.add_argument("--llm-config", help="Path to shared LLM profile JSON")

    sp = sub.add_parser("run-replay-worker", help="Watch a seed directory and continuously replay every existing/new seed")
    sp.add_argument("--config", required=True, help="Runtime TOML/JSON config file")
    sp.add_argument("--watch-dir", help="Seed directory to watch; defaults to config afl_input_dir")
    sp.add_argument("--poll-interval", type=float, help="Directory polling interval in seconds")
    sp.add_argument("--llm-provider", help="Shared LLM profile name, for example deepseek, gpt.lightftp, qwen.kamailio")
    sp.add_argument("--llm-config", help="Path to shared LLM profile JSON")

    args = p.parse_args()

    if args.command == "gen-messages":
        cmd_gen_messages(args)
    elif args.command == "gen-templates":
        cmd_gen_templates(args)
    elif args.command == "gen-seeds":
        cmd_gen_seeds(args)
    elif args.command == "export-seeds":
        cmd_export_seeds(args)
    elif args.command == "augment-seeds":
        cmd_augment_seeds(args)
    elif args.command == "sync-impls":
        cmd_sync_impls(args)
    elif args.command == "import-dyntaint":
        cmd_import_dyntaint(args)
    elif args.command == "scan-sources":
        cmd_scan_sources(args)
    elif args.command == "convert":
        cmd_convert(args)
    elif args.command == "import-codeql":
        cmd_import_codeql(args)
    elif args.command == "advise":
        cmd_advise(args)
    elif args.command == "kg":
        cmd_kg(args)
    elif args.command == "run-runtime":
        cmd_run_runtime(args)
    elif args.command == "debug-aflnet":
        cmd_debug_aflnet(args)
    elif args.command == "debug-replay":
        cmd_debug_replay(args)
    elif args.command == "run-replay-worker":
        cmd_run_replay_worker(args)
    else:
        p.print_help()


if __name__ == "__main__":
    main()
