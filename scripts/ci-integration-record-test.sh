#!/usr/bin/env bash
# Offline workflow-wiring and recorder proofs. An optional saved job JSON
# tests the former workflow, where no record-check step meant no refusal.
set -eu
root=$(cd "$(dirname "$0")/.." && pwd -P)
scratch=$(mktemp -d /tmp/ci-integration-test.XXXXXX)
trap 'rm -rf "$scratch"' EXIT
if [ "$#" -eq 0 ]; then
	yq -o=json '.jobs.integration' "$root/.github/workflows/ci.yml" > "$scratch/job.json"
else
	cp "$1" "$scratch/job.json"
fi
python3 - "$scratch/job.json" "$scratch/check.sh" <<'PY'
import json, sys
from pathlib import Path
job = json.loads(Path(sys.argv[1]).read_text())
checks = [s['run'] for s in job['steps'] if s.get('name') == "Require this run's integration record"]
Path(sys.argv[2]).write_text('\n'.join(checks) + '\n')
print('workflow record-check steps:', len(checks))
PY
mkdir -p "$scratch/repo/scripts"
cp "$root/scripts/ci-integration-record.sh" "$root/scripts/ci-record.sh" "$root/scripts/gate-witness.sh" "$scratch/repo/scripts/"
cd "$scratch/repo"
cat > Makefile <<'MAKE'
.PHONY: test-db ci-integration-test rulefloor-integration
test-db ci-integration-test rulefloor-integration:
	@printf '%s\n' '$@' >> "$$TRACE"
	@echo 'check OK: fixture $@'
	@if [ "$${FAIL_TARGET:-}" = '$@' ]; then exit 7; fi
MAKE
printf '/GATE-RUN.ci-integration.txt\n' > .gitignore
git -c init.defaultBranch=main init -q
git add -- Makefile .gitignore scripts
git -c user.name=Fixture -c user.email=fixture@example.invalid -c commit.gpgsign=false commit -qm fixture
export GITHUB_SERVER_URL=https://github.com GITHUB_REPOSITORY=identuum/fixture
export GITHUB_RUN_ID=123 GITHUB_RUN_ATTEMPT=2 GITHUB_JOB=integration
export GITHUB_SHA=$(git rev-parse HEAD) TRACE="$scratch/trace"
record=GATE-RUN.ci-integration.txt
run() { bash scripts/ci-integration-record.sh "$@"; }
assert() {
	local label=$1; shift
	if "$@"; then echo "PASS $label"; else echo "FAIL $label"; exit 1; fi
}
run init > "$scratch/run.log" 2>&1
assert 'single declared plan' grep -qx 'plan: test-db ci-integration-test rulefloor-integration' "$record"
assert 'partial scope explicit' grep -q 'green is not a whole-job verdict' "$record"
result=0
run step ci-integration-test >> "$scratch/run.log" 2>&1 || result=$?
assert 'reordering refused' test "$result" -ne 0
assert 'reordering executed nothing' test ! -e "$TRACE"
run step test-db >> "$scratch/run.log" 2>&1
run step ci-integration-test >> "$scratch/run.log" 2>&1
# The real installer remains a GitHub step here. This marker proves that
# the driver can resume after infrastructure, without moving or rerunning it.
printf 'rulefloor-installation\n' >> "$TRACE"
run step rulefloor-integration >> "$scratch/run.log" 2>&1
run finalize >> "$scratch/run.log" 2>&1
assert 'green record' grep -qx 'result: green' "$record"
assert 'commit tie' grep -qx "tree: commit=$GITHUB_SHA" "$record"
assert 'commands run once in their original order' test "$(cat "$TRACE")" = "$(printf 'test-db\nci-integration-test\nrulefloor-installation\nrulefloor-integration')"
cp "$record" "$scratch/green"
failures=0
check_case() {
	local name=$1 expected=$2 actual=0
	bash "$scratch/check.sh" > "$scratch/check.log" 2>&1 || actual=$?
	if { [ "$expected" = pass ] && [ "$actual" -eq 0 ]; } || { [ "$expected" = refuse ] && [ "$actual" -ne 0 ]; }; then
		echo "PASS $name: expected=$expected exit=$actual"
	else
		echo "FAIL $name: expected=$expected exit=$actual"; failures=$((failures + 1))
	fi
}
check_case present pass
rm "$record"
check_case absent refuse
: > "$record"
check_case empty refuse
cp "$scratch/green" "$record"
GITHUB_RUN_ID=124 check_case wrong-run refuse
cp "$scratch/green" "$record"
echo 'GREEN RECORD: local fixture commands only, not a CI integration run'
cat "$record"
rm "$record"
: > "$TRACE"
run init > "$scratch/red.log" 2>&1
run step test-db >> "$scratch/red.log" 2>&1
result=0
FAIL_TARGET=ci-integration-test run step ci-integration-test >> "$scratch/red.log" 2>&1 || result=$?
assert 'failed Make target propagates' test "$result" -eq 2
result=0
run step rulefloor-integration >> "$scratch/red.log" 2>&1 || result=$?
assert 'no target after failure' test "$result" -ne 0
assert 'later target did not execute' test "$(wc -l < "$TRACE" | tr -d ' ')" -eq 2
result=0
run finalize >> "$scratch/red.log" 2>&1 || result=$?
assert 'incomplete plan finalizes red' test "$result" -ne 0
assert 'failed target recorded' grep -qx 'target: ci-integration-test exit=2' "$record"
assert 'red verdict recorded' grep -qx 'result: red' "$record"
assert 'red record retains current provenance' bash scripts/ci-record.sh check "$record"
[ "$failures" -eq 0 ] || { echo "ci-integration record tests: $failures failure(s)"; exit 1; }
echo 'check OK: CI integration record contract tests'
