#!/usr/bin/env bash
# Phase 5 competitive benchmark — full re-execution.
# Rebuilds Aegis from the pinned source tree and re-runs all scanners x corpora.
# Usage: ./rerun.sh [--only SCANNER] [--only-corpus CORPUS] [--runs N]
set -euo pipefail

AE="$HOME/workspace/aegis-engine"
cd "$AE"

echo "== git state =="
git branch --show-current
HEAD_SHA=$(git rev-parse --short HEAD)
echo "HEAD=$HEAD_SHA"
if [ "$HEAD_SHA" != "0c28621" ]; then
  echo "WARNING: HEAD is $HEAD_SHA, expected 0c28621 (Phase 5 was run on 0c28621)" >&2
fi
if [ -n "$(git status --porcelain -- internal/ cmd/ 2>/dev/null)" ]; then
  echo "WARNING: uncommitted changes under internal/ or cmd/ — benchmark would not be on clean source" >&2
fi

echo "== building aegis =="
export PATH="$HOME/workspace/toolchain/go/bin:$PATH"
go build -o /tmp/aegis-p5 ./cmd/aegis/
/tmp/aegis-p5 doctor

echo "== scanner versions =="
"$HOME/workspace/.venv-checkov/bin/checkov" --version
"$HOME/workspace/bin/kics" version | head -1
trivy --version | head -1

echo "== running benchmark =="
python3 docs/audit/raw/phase5/run_phase5.py "$@"
echo "== done: results in docs/audit/raw/phase5/*.json =="
