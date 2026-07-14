# S2AFL

**S2AFL** is the public release of an LLM-enhanced protocol fuzzing framework. It augments AFLNet-based stateful fuzzing with three semantics-aware components introduced in the EMSE paper:

- **PSEI** — Protocol Syntax-Enhanced Initialization
- **SBGM** — Semantic Boundary-Guided Mutation
- **VSAM** — Vulnerability Semantics-Aware Mutation

This repository is organized for public inspection and reproduction. It retains the code needed to understand and rerun the released workflow, while excluding private credentials, machine-specific paths, generated experiment outputs, crash corpora, and other non-releasable artifacts.

---

## Table of Contents

- [Relation to the Paper](#relation-to-the-paper)
- [Repository Layout](#repository-layout)
- [What Is and Is Not Included](#what-is-and-is-not-included)
- [Requirements](#requirements)
- [Installation](#installation)
- [Configuration](#configuration)
- [Quick Start](#quick-start)
- [Benchmark Reproduction](#benchmark-reproduction)
- [Inputs and Outputs](#inputs-and-outputs)
- [Using Your Own Targets](#using-your-own-targets)
- [Reproducing the Full Paper Workflow](#reproducing-the-full-paper-workflow)
- [FAQ](#faq)
- [Known Limitations](#known-limitations)
- [Security and Privacy](#security-and-privacy)
- [Citation](#citation)
- [License](#license)
- [Support](#support)

---

## Relation to the Paper

This repository corresponds to the **EMSE revision** of the S2AFL paper. The mapping between the paper's components and the source tree is as follows:

| Component | Description | Location |
| --- | --- | --- |
| **PSEI** | Protocol Syntax-Enhanced Initialization | `python/S2AFL/psei/` and the runtime bootstrap flow |
| **SBGM** | Semantic Boundary-Guided Mutation | `python/S2AFL/runtime/scheduler.py` and related runtime modules |
| **VSAM** | Vulnerability Semantics-Aware Mutation | `python/S2AFL/runtime/mutation_worker.py` with the knowledge layer |
| **AFLNet integration** | AFLNet-based runtime integration | `python/S2AFL/runtime/aflnet.py` and the benchmark scripts |

---

## Repository Layout

```text
.
├── README.md
├── LICENSE
├── aflnet/                     # AFLNet baseline used by the released workflow
├── benchmark/                  # ProFuzzBench-based benchmark automation and target layouts
├── python/                     # Public Python workflow for S2AFL
│   ├── run.py
│   ├── requirements.txt
│   ├── .env.example
│   ├── examples/
│   └── S2AFL/
├── deps.sh
├── setup.sh
├── run.sh
├── analyze.sh
├── clean_all.sh
└── clean_contain.sh
```

---

## What Is and Is Not Included

### Included

- The public Python workflow for knowledge loading, seed enhancement, runtime scheduling, replay, and mutation orchestration.
- The AFLNet source required by the released execution path.
- Benchmark scripts and target wrappers for AFLNet-based smoke runs and environment inspection.
- Safe configuration templates and minimal example seeds.

### Not Included

- Real API keys or private service credentials.
- Author-specific absolute paths.
- Raw experimental outputs, logs, intermediate result bundles, and caches.
- Vulnerability-triggering samples and other security-sensitive data unsuitable for public release.
- Private review materials and unpublished collaboration information.

---

## Requirements

- **OS:** Linux
- **Python:** 3.11 or newer (recommended)
- **Toolchain:** `make`, `gcc` or `clang`, Bash
- **Containers:** Docker (for benchmark-based reproduction)
- **Optional:** `requests` (for the Python LLM client fallback path)

---

## Installation

### Option 1 — Python workflow only

Use this option to inspect or run the Python workflow without building the benchmark images.

```bash
git clone git@github.com:huoyuxi/S2AFL.git
cd S2AFL/python
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
```

### Option 2 — Python workflow plus benchmark

```bash
cd /path/to/S2AFL
./deps.sh
./setup.sh
```

`setup.sh` copies the retained `aflnet/` tree into each benchmark subject directory and then builds the benchmark images. In this public release, benchmark container automation is kept on the AFLNet path only; the released S2AFL workflow itself is the Python code under `python/`.

---

## Configuration

### LLM Credentials and Secrets

> **Never hardcode keys in source files.** Copy `python/.env.example` to a local `.env`, or export the variables manually.

Supported environment variables:

| Variable | Purpose |
| --- | --- |
| `DEEPSEEK_API_KEY` | DeepSeek API key |
| `OPENAI_API_KEY` | OpenAI API key |
| `QWEN_API_KEY` | Qwen API key |
| `LLM_PROVIDER` | Selects the active LLM provider |
| `S2AFL_LLM_CONFIG` | Path to a custom LLM configuration |

The public profile template is stored at `python/S2AFL/experiments/llm_profiles.json`.

### AFLNet Path

The runtime config expects an AFLNet-compatible binary via `afl_fuzz_cmd`. The public example points to `../aflnet/afl-fuzz`, relative to `python/S2AFL/`.

### Runtime Config

Start from the public template:

```text
python/S2AFL/experiments/workflow2/runtime_config.public.example.toml
```

It uses only relative paths and safe placeholder scripts.

---

## Quick Start

### 1. Inspect the Python CLI

```bash
cd python
python3 run.py --help
```

### 2. Validate the public runtime config

```bash
cd python
python3 S2AFL/experiments/workflow2/validate_runtime_configs.py \
  --config S2AFL/experiments/workflow2/runtime_config.public.example.toml
```

### 3. Generate PSEI seeds from the minimal sample corpus

```bash
cd python
python3 run.py gen-seeds \
  --protocol FTP \
  --seed-corpus-dir examples/seeds/lightftp \
  -o output/seeds/lightftp_psei.json
```

### 4. Export the generated seeds to AFLNet raw inputs

```bash
cd python
python3 run.py export-seeds \
  output/seeds/lightftp_psei.json \
  -o output/exported_seeds/lightftp
```

---

## Benchmark Reproduction

### Build the benchmark images

```bash
./setup.sh
```

### Run a short smoke experiment

The retained benchmark automation currently accepts `aflnet` as the fuzzer argument:

```bash
./run.sh 1 5 pure-ftpd aflnet
```

### Analyze the results

```bash
./analyze.sh pure-ftpd 5
```

---

## Inputs and Outputs

### Main Inputs

- Protocol templates under `python/S2AFL/knowledge/data/templates/`
- Baseline seeds under `python/examples/seeds/`, or a user-provided seed corpus
- Runtime configuration under `python/S2AFL/experiments/workflow2/`
- The AFLNet binary path in `afl_fuzz_cmd`

### Main Outputs

- Python workflow outputs under `python/output/`
- Benchmark results under `benchmark/results-*`
- Analysis summaries (CSV and PNG) generated by `analyze.sh`

> These generated outputs are intentionally git-ignored and should not be committed.

---

## Using Your Own Targets

To adapt the released workflow to another protocol implementation:

1. Place or sync the target source tree under `python/S2AFL/implementations/src/<PROTO>/<Impl>/`.
2. Derive a runtime config from `runtime_config.public.example.toml`.
3. Replace the target start/stop, replay, and coverage commands with wrappers for your environment.
4. Provide your own baseline seeds under `python/examples/seeds/`, or another seed corpus directory.
5. *(Optional)* Import dynamic-taint or static-analysis outputs before enabling the full runtime.

The repository ships no hidden target-specific assets beyond the included examples. If a subject needs extra harnessing, you must supply that setup yourself.

---

## Reproducing the Full Paper Workflow

This public repository supports inspection of the released implementation and limited reruns of the released workflow. **Full paper reproduction additionally requires:**

- target-specific benchmark environments,
- locally prepared or institutionally managed runtime infrastructure,
- user-supplied LLM credentials, and
- for some analyses, non-public vulnerability-related intermediate data that are intentionally excluded here.

Use the public workflow for:

- code inspection,
- interface validation,
- template and seed-generation experiments, and
- benchmark smoke runs.

---

## FAQ

**Where should I put my own taint or analysis outputs?**

Use the per-implementation layout under `python/S2AFL/output/` and `python/S2AFL/knowledge/data/implementations/`, following the examples documented in `python/README.md`.

---

## Known Limitations

- The Python workflow is research code and expects users to adapt the target start, stop, replay, and coverage commands to their own environment.
- The retained benchmark automation targets only the AFLNet-based container path; it does not package the older in-container `s2afl`, `s2afl-s1`, or `s2afl-s2` forks, which were removed from this public tree.
- Some benchmark targets still rely on container-internal path conventions inherited from ProFuzzBench.
- The public release does not include every internal artifact used during the paper revision process.
- LLM-backed generation quality depends on the selected model and the available protocol knowledge.

---

## Security and Privacy

- No real keys or private credentials are included.
- No author-specific absolute paths are required by the public examples.
- Generated logs, outputs, and vulnerability-triggering artifacts should be reviewed before any further redistribution.

---

## Citation

If you use this repository, please cite the public S2AFL paper once its bibliographic metadata becomes available. Until then, cite the upstream **AFLNet** and **ProFuzzBench** papers that this release builds on, and treat the manuscript sources in this workspace as draft materials rather than a published DOI record.

---

## License

This repository is released under the **Apache-2.0** license. Third-party components retain their own notices and license terms where applicable.

---

## Support

Please use **GitHub Issues** for release-related questions, reproduction problems, or bug reports.
