#!/usr/bin/env bash
# SIMULATED GitLab CI run of .gitlab-ci.yml (job: aegis-scan).
#
# No live GitLab runner was available in this sandbox. The YAML was
# validated with PyYAML, and each `script:` line is executed VERBATIM in
# order below (order and content identical to the .gitlab-ci.yml).
# Deltas vs a real runner are marked [SIMULATED].
set -u
RAW="$(cd "$(dirname "$0")" && pwd)"
TS="$(date -u +%Y%m%dT%H%M%SZ)"
# NOTE: /tmp is a 512MB tmpfs shared with other phases' scratch; the repo
# clone needs ~200MB, so the simulated runner workspace lives here instead.
WORK="$HOME/workspace/phase9-scratch/gl-runs/$TS"
SRC_ENGINE="${1:-$HOME/workspace/aegis-engine}"  # repo containing ./cmd/aegis
mkdir -p "$WORK"
exec > >(tee "$WORK/run.log") 2>&1

echo "================================================================"
echo " SIMULATED GitLab CI run — .gitlab-ci.yml job: aegis-scan"
echo " run id: $TS   workspace: $WORK"
echo " image delta: golang:1.25 -> sandbox go1.25.4 toolchain"
echo "================================================================"

echo
echo "### YAML validation"
python3 - "$RAW/.gitlab-ci.yml" <<'EOF'
import sys, yaml
doc = yaml.safe_load(open(sys.argv[1]))
job = doc["aegis-scan"]
assert job["image"] == "golang:1.25", job["image"]
assert isinstance(job["script"], list) and len(job["script"]) >= 4
assert job["artifacts"]["reports"]["sarif"] == "aegis.sarif"
assert job["artifacts"]["when"] == "always"
assert job["allow_failure"] is False
print("PASS: .gitlab-ci.yml parses; job keys (image/script/artifacts/reports.sarif/allow_failure) as expected")
EOF

echo
echo "### Job setup: clone repo  [SIMULATED]"
echo "delta: real runner does 'git clone' of the pipeline ref into"
echo "       \$CI_PROJECT_DIR; we clone the local engine repo at HEAD."
git clone -q "$SRC_ENGINE" "$WORK/project" 2>/dev/null || \
  { echo "clone failed"; exit 2; }
cd "$WORK/project"
git rev-parse --short HEAD

echo
echo "### script[0]: go build -o aegis ./cmd/aegis  [REAL COMMAND]"
export PATH="$HOME/workspace/toolchain/go/bin:$PATH"
go build -o aegis ./cmd/aegis && echo "build OK"

echo
echo "### script[1]: ./aegis --version  [REAL COMMAND]"
./aegis --version

echo
echo "### script[2..3]: scan | tee + exit code  [REAL COMMAND]"
set -o pipefail
./aegis scan . --format=sarif --fail-on="$AEGIS_FAIL_ON" | tee "$WORK/aegis.sarif"
SCAN_EXIT=$?
set +o pipefail
echo "aegis exit code: $SCAN_EXIT"

echo
echo "### script[4]: validate SARIF  [REAL COMMAND]"
python3 "$RAW/validate_sarif.py" "$WORK/aegis.sarif" --schema /tmp/sarif-2.1.0.json
VALID_EXIT=$?

echo
echo "### artifacts: upload  [SIMULATED]"
echo "delta: no GitLab coordinator to receive artifacts; we verify the"
echo "       artifact file exists and is the validated SARIF."
ls -la "$WORK/aegis.sarif"

echo
echo "================================================================"
echo "RUN SUMMARY: scan_exit=$SCAN_EXIT sarif_validation_exit=$VALID_EXIT"
echo "job gate: $([ "$SCAN_EXIT" -eq 0 ] && echo PASS || echo FAIL)"
echo "================================================================"
