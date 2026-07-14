#!/bin/bash
set -euo pipefail

PFBENCH="$PWD/benchmark"

for subject in ./benchmark/subjects/*/*; do
  rm -rf "$subject/aflnet"
  cp -r aflnet "$subject/aflnet"
done

# The public release keeps benchmark container builds on the AFLNet path.
# The current S2AFL workflow is released separately under ./python.

cd "$PFBENCH"
"$PFBENCH/scripts/execution/profuzzbench_build_all.sh"
