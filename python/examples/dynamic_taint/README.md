# Dynamic Taint Example

This directory contains a safe public example of the dynamic-taint mapping format consumed by `python3 run.py import-dyntaint`.

What it demonstrates:

- the top-level `implementation` / `protocol` metadata expected by the importer
- one trace-oriented `trace_summary` block for documentation only
- `field_mappings` entries that connect protocol fields to handler/dataflow variables
- per-field byte ranges and taint offsets in the same shape produced by the internal tooling

What it does not include:

- real experiment outputs
- private runtime logs
- crash-triggering inputs
- author-local paths or credentials

Usage:

```bash
mkdir -p S2AFL/output/dynamic_taint_mapping
cp examples/dynamic_taint/LightFTP_field_variable_map.sample.json \
  S2AFL/output/dynamic_taint_mapping/LightFTP_field_variable_map.json
python3 run.py import-dyntaint --implementation LightFTP
```

The `trace_summary` section is illustrative only. The importer ignores it, but it helps readers understand how a trace can align with the normalized `field_mappings` payload used by the released workflow.
