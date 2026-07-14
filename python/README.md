# S2AFL Python Workflow

This directory contains the current public Python workflow for S2AFL. It is the part of the repository that implements the knowledge-guided runtime, the PSEI seed-enhancement path, and the semantics-aware mutation logic described in the paper.

## Modules

- `run.py`: CLI entrypoint.
- `S2AFL/cli/`: command dispatch for offline generation and runtime execution.
- `S2AFL/psei/`: Protocol Syntax-Enhanced Initialization.
- `S2AFL/runtime/`: workflow2 runtime controller, replay, scheduler, and mutation worker.
- `S2AFL/knowledge/`: knowledge import, normalization, lookup, and implementation metadata.
- `S2AFL/core/`: shared template catalog handling and template-generation helpers.
- `S2AFL/scripts/workflow2/`: replay and coverage helper scripts.
- `examples/`: minimal seeds and placeholder target scripts that users can adapt.

## Installation

```bash
cd python
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
```

## Secrets and model configuration

Do not edit source files to add keys. Use environment variables instead.

```bash
cp .env.example .env
```

or export the variables manually:

```bash
export DEEPSEEK_API_KEY="example-api-key"
export OPENAI_API_KEY="example-api-key"
export QWEN_API_KEY="example-api-key"
```

The profile template is `S2AFL/experiments/llm_profiles.json`.

## Minimum example

Validate the CLI:

```bash
python3 run.py --help
```

Validate the public runtime config:

```bash
python3 S2AFL/experiments/workflow2/validate_runtime_configs.py \
  --config S2AFL/experiments/workflow2/runtime_config.public.example.toml
```

Generate seeds from the included LightFTP example corpus:

```bash
python3 run.py gen-seeds \
  --protocol FTP \
  --seed-corpus-dir examples/seeds/lightftp \
  -o output/seeds/lightftp_psei.json
```

Export them into AFLNet raw seeds:

```bash
python3 run.py export-seeds \
  output/seeds/lightftp_psei.json \
  -o output/exported_seeds/lightftp
```

## Public runtime example

The public config file is:

- `S2AFL/experiments/workflow2/runtime_config.public.example.toml`

What you still need to replace:

- `afl_fuzz_cmd`
- target start and stop commands
- replay prepare and cleanup commands
- coverage reset and capture commands

The placeholder scripts in `examples/scripts/` are intentionally non-destructive and only document the expected interface.

## Dynamic taint sample

The public release includes a safe illustrative mapping under `examples/dynamic_taint/`. It is not a real experiment artifact; instead, it shows the `field_variable_map.json` bridge format used to connect message fields, handler functions, and taint-flow evidence. The sample also includes a small trace summary so readers can align the mapping with related taint-trace workflows without exposing private logs.

Import the sample into the normalized knowledge layout with:

```bash
mkdir -p S2AFL/output/dynamic_taint_mapping
cp examples/dynamic_taint/LightFTP_field_variable_map.sample.json \
  S2AFL/output/dynamic_taint_mapping/LightFTP_field_variable_map.json
python3 run.py import-dyntaint --implementation LightFTP
```

The importer only requires `*_field_variable_map.json`. Auxiliary `*_field_vars.json` files are optional and are intentionally omitted from this public example.

## Adapting to your own target

To run the workflow on your own implementation, you usually need to:

- place the normalized source tree under `S2AFL/implementations/src/<PROTO>/<Impl>/`
- copy and edit `S2AFL/experiments/workflow2/runtime_config.public.example.toml`
- replace the placeholder replay, coverage, and target lifecycle commands
- provide a seed corpus compatible with the target protocol
- optionally import dynamic taint, static scan, or CodeQL outputs before enabling the full scheduler

The included examples document the expected file formats and command interfaces, but they are not a full deployment recipe for every target.

## Notes on the released implementation

- Relative paths in runtime configs are interpreted relative to `python/S2AFL/`.
- The public workflow expects AFLNet async seed handoff mode for runtime injection.
- Output directories are created under `python/output/` and should remain untracked.
- The repository includes only non-sensitive template and configuration data.

## Known limitations

- The example configuration is a safe template, not a turnkey full benchmark deployment.
- Some knowledge-layer commands expect users to prepare implementation source trees or taint-analysis outputs separately.
- Full reproduction of the paper results requires benchmark-side infrastructure outside this subdirectory.

## FAQ

**Why does `import-dyntaint` accept the sample even though there is no `*_field_vars.json` file?**

Only `*_field_variable_map.json` is required by the importer. The auxiliary `*_field_vars.json` file is optional and is omitted from the public example on purpose.

**Can I use another LLM provider?**

Yes, as long as you provide a compatible profile in `S2AFL/experiments/llm_profiles.json` and export the matching environment variables.

**Does this directory contain full benchmark automation for S2AFL itself?**

No. This directory contains the released Python workflow. The top-level `benchmark/` directory keeps the retained AFLNet-oriented container path for smoke testing and environment setup.

## Relation to the benchmark tree

The released Python workflow is the public S2AFL implementation in this repository. The top-level `benchmark/` directory is kept for AFLNet-oriented container smoke runs and target preparation, not as a second copy of the S2AFL runtime.
