#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
fail=0
for f in harden-ubuntu.sh harden-docker.sh lib/common.sh lib/modules/*.sh; do
  if ! bash -n "$f"; then
    echo "FAIL $f"
    fail=1
  fi
done
if [[ "$fail" -eq 0 ]]; then
  echo SYNTAX_OK
  exit 0
fi
exit 1
