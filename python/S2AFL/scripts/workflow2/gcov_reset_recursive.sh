#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -lt 1 ]; then
  echo "usage: gcov_reset_recursive.sh <dir> [dir ...]" >&2
  exit 2
fi

for target in "$@"; do
  [ -e "$target" ] || continue
  chmod -R u+w "$target" >/dev/null 2>&1 || true
  find "$target" -type f \( -name '*.gcda' -o -name 'cov.json' -o -name 'cov.raw.json' -o -name 'gcovr-report.json' -o -name 's2afl-gcovr-*.json' -o -name 's2afl-*-gcovr-*.json' \) -delete >/dev/null 2>&1 || true
 done
