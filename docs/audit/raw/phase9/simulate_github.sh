#!/usr/bin/env bash
# SIMULATED GitHub Actions run of aegis-demo.yml (consumer pattern).
#
# A live run was not possible: `act` (v0.2.89, installed during this audit)
# cannot execute jobs without a Docker daemon, and none exists in this
# sandbox (/var/run/docker.sock absent, no `docker` binary; installing a
# full Docker daemon is out of scope per the audit brief).
#
# Each workflow step below is executed IN ORDER in a clean directory.
# Steps marked [SIMULATED] name the exact delta vs a real ubuntu-latest
# runner; the aegis invocations themselves run for real.
set -u
RAW="$(cd "$(dirname "$0")" && pwd)"
RUN_ROOT="/tmp/phase9/gh-runs"
TS="$(date -u +%Y%m%dT%H%M%SZ)"
WORK="$RUN_ROOT/$TS"
SRC_REPO="${1:-/tmp/phase9/test-repo}"   # scratch copy of tests/demos/aws-security-demo
LOG="$WORK/run.log"
mkdir -p "$WORK"
exec > >(tee "$WORK/run.log") 2>&1

echo "================================================================"
echo " SIMULATED GitHub Actions run — workflow: aegis-demo.yml"
echo " run id: $TS   workspace: $WORK"
echo " runner image delta: ubuntu-latest -> this sandbox (Ubuntu 24.04)"
echo "================================================================"

echo
echo "### Step 1/5: actions/checkout@v4  [SIMULATED]"
echo "delta: real step does 'git clone' of the PR ref; here we copy the"
echo "       scratch test-repo tree (same file bytes, no .git metadata)."
mkdir -p "$WORK/ws/repo"
cp -r "$SRC_REPO/." "$WORK/ws/repo/"
echo "checked out $(find "$WORK/ws/repo" -type f | wc -l) files"

echo
echo "### Step 2/5: Install aegis  [SIMULATED]"
echo "delta: real step curls the v1.0.0 release binary from GitHub releases;"
echo "       no release is published yet, so we stage the audited build"
echo "       (/tmp/aegis-p9 = go build of HEAD 0c28621, branch"
echo "       fix/demo-defects-d1-d3) as the binary under test."
cp /tmp/aegis-p9 "$WORK/ws/repo/aegis"
chmod +x "$WORK/ws/repo/aegis"
(cd "$WORK/ws/repo" && ./aegis --version)

echo
echo "### Step 3/5: Scan with Aegis  [REAL COMMAND]"
echo "delta: none — identical invocation to the workflow."
echo "cmd: ./aegis scan . --format=sarif --fail-on=high | tee aegis.sarif"
cd "$WORK/ws/repo"
set -o pipefail
./aegis scan . --format=sarif --fail-on=high | tee "$WORK/ws/repo/aegis.sarif" > /dev/null
SCAN_EXIT=$?
set +o pipefail
echo "aegis exit code: $SCAN_EXIT"
cp "$WORK/ws/repo/aegis.sarif" "$WORK/aegis.sarif"

echo
echo "### Step 4/5: Validate SARIF  [SIMULATED — local equivalent]"
echo "delta: the workflow validates locally; the authoritative check is"
echo "       GitHub's server-side validation on upload. We run both the"
echo "       official SARIF 2.1.0 schema and GitHub's structural rules."
python3 "$RAW/validate_sarif.py" "$WORK/aegis.sarif" --schema /tmp/sarif-2.1.0.json
VALID_EXIT=$?

echo
echo "### Step 5/5: github/codeql-action/upload-sarif@v3  [SIMULATED]"
echo "delta: cannot POST to the code-scanning API without a real GitHub"
echo "       repo + token. Step 4's validation is the checkable part of"
echo "       what upload-sarif + GitHub verify server-side."
echo "result: SKIPPED (no live GitHub API in sandbox)"

echo
echo "================================================================"
echo "RUN SUMMARY: scan_exit=$SCAN_EXIT sarif_validation_exit=$VALID_EXIT"
echo "log: $LOG"
echo "sarif: $WORK/aegis.sarif"
echo "================================================================"
