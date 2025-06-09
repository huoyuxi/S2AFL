# S2AFL Artifact: Semantics-Driven Protocol Fuzzing Framework

**S2AFL** is a protocol fuzzer guided by large language models (LLMs), designed to enhance vulnerability discovery in network protocol implementations. It is built on top of [AFLNet](https://github.com/aflnet/aflnet) , [ChatAFL)](https://github.com/ChatAFLndss/ChatAFL)and [ProFuzzBench](https://github.com/profuzzbench/profuzzbench), with semantic-aware enhancements that address long-standing limitations in seed diversity, structure-awareness, and boundary constraint handling.

This repository includes a fully-configured artifact for reproducible experiments and streamlined protocol fuzzing using pre-integrated Docker workflows.

------

## ✨ Key Features

S2AFL tightly integrates LLM-based semantic understanding with source-level analysis, introducing three novel components:

- **VSAM (Vulnerability Semantic-Aware Mutation)**: Prioritizes mutations targeting high-risk code regions.
- **PSEI (Protocol Syntax-Enhanced Initialization)**: Generates syntactically valid and semantically meaningful seeds by analyzing protocol grammars and state transitions.
- **SBGM (Semantic Boundary-Guided Mutation)**: Maintains fuzzing momentum by directing mutations toward uncovered boundary conditions.

All components are supported by a **Retrieval-Augmented Generation (RAG)** mechanism, which bridges natural language protocol documentation and source code for fine-grained semantic alignment.

S2AFL uses a lightweight Python-based agent as a middleware, connecting fuzzers with a locally hosted LLM backend (e.g., Tongyi Qianwen Code-72B on Ollama), enabling dynamic LLM interaction during fuzzing.

------

## 🗂️ Directory Structure

```
S2AFL-Artifact
├── aflnet/             # Modified AFLNet with state tracking support
├── Agent/              # Implement a workflow agent for semantic fuzzing
├── benchmark/          # Adapted ProFuzzBench including Lighttpd 1.4
├── S2AFL/              # Core implementation with all proposed techniques
├── S2AFL-S1/           # Ablation variant: structure-aware mutation only
├── S2AFL-S2/           # Ablation variant: mutation + seed enrichment
├── deps.sh             # Dependency installation script
├── setup.sh            # Environment setup and Docker build
├── run.sh              # Script for launching fuzzing experiments
├── analyse.sh          # Coverage and result visualization
├── clean_all.sh        # Clean all containers and data
├── clean_contain.sh    # Clean specific containers only
└── README.md           # This documentation
```

------

## 🚀 Quick Start

### 1️⃣ Install Dependencies

```
./deps.sh
```

Requires:

- Docker
- Python 3 with `pandas` and `matplotlib`
- Bash

------

### 2️⃣ Build Docker Images (≈ 40 min)

```
./setup.sh
```

This sets up Docker images for all fuzzers and protocol targets.

------

### 3️⃣ Run Fuzzing Experiments

```
./run.sh <num_containers> <duration_in_minutes> <targets> <fuzzers>
```

Example:

```
./run.sh 1 1440 pure-ftpd S2AFL 
```

Runs S2AFL for 24 hours on `pure-ftpd` using 1 container. Use `all` to include all subjects or fuzzers:

```
./run.sh 3 1440 lightftp,bftpd,proftpd,pure-ftpd,exim,live555,kamailio s2afl,aflnet,s2afl-s1,s2afl-s2
```

Results will appear in `benchmark/result-<target>`.

------

### 4️⃣ Analyze Results

```
./analyze.sh <targets> <duration>
```

Example:

```
./analyze.sh exim 240
```

Creates `.csv` and `.png` output in `res_<target>` showing coverage over time.

------

### 5️⃣ Clean Up

To clean all resources:

```
./clean_all.sh
```

To remove specific containers:

```
./clean_contain.sh lightftp,bftpd,proftpd,pure-ftpd,exim,live555,kamailio
```

------

## 🔍 Feature Internals

### 📘 LLM Grammar Generation

- Located in `setup_llm_grammars` within `afl-fuzz.c`, and helpers in `chat-llm.c`
- Output in `protocol-grammars/`

------

### 🌱 Enriched Seeds

- Located in `get_seeds_with_message_types` in `afl-fuzz.c`
- Enriched seeds found in `queue/`, prefixed by `id:...,orig:enriched_`

------

### 📡 State-Stall Interaction

When fuzzing enters a stagnant state, LLMs are prompted via logic in:

```
if (uninteresting_times >= UNINTERESTING_THRESHOLD && chat_times < CHATTING_THRESHOLD)
```

Logs are saved in `stall-interactions/` as `request-<id>` / `response-<id>`.

------

## 🧪 Experiment Reproduction

### Compare Against Baselines (5 min human + 180 compute-hours)

```
./run.sh 3 1440 lightftp,bftpd,proftpd,pure-ftpd,exim,live555,kamailio S2AFL,aflnet,S2AFL-S1,S2AFL-S2
./analyze.sh lightftp,bftpd,proftpd,pure-ftpd,exim,live555,kamailio 1440
```

------

### Ablation Study (5 min human + 180 compute-hours)

```
./run.sh 5 240 proftpd,exim S2AFL,S2AFL-S1,S2AFL-S2
./analyze.sh proftpd,exim 240
```

All results are saved under `res_<target>` folders.

------

## ⚙️ Configuration

### Parameter Tuning

Key config files:

- `config.h`: core fuzzing parameters (`EPSILON_CHOICE`, `CHATTING_THRESHOLD`)
- `chat-llm.h`: LLM-specific settings (retries, enrichment size, etc.)

------

### Add New Subjects

Follow [ProFuzzBench instructions](https://github.com/profuzzbench/profuzzbench#1-how-do-i-extend-profuzzbench) for extending benchmark targets. Lighttpd 1.4 is included as an example.

------

## 📌 Technical Note

S2AFL integrates a Python-based agent that acts as a middleware between the fuzzer and LLMs. The system uses Ollama to serve **Tongyi Qianwen Code-72B**, which handles semantic synthesis, prompt orchestration, and runtime decisions.

