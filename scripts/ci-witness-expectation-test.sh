#!/usr/bin/env bash
# Exercise the real CLI and the partial integration record's real producer.
# --baseline omits expectation flags, which the former CLI did not offer.
set -eu
root=$(cd "$(dirname "$0")/.." && pwd -P)
binary=$1
baseline=${2:-}
scratch=$(mktemp -d /tmp/ci-witness-expectation.XXXXXX)
trap 'rm -rf "$scratch"' EXIT
mkdir "$scratch/repo"
cd "$scratch/repo"
cat > Makefile <<'MAKE'
.PHONY: test-db ci-integration-test rulefloor-integration
test-db ci-integration-test rulefloor-integration:
	@true
MAKE
printf '/GATE-RUN.ci.txt\n/GATE-RUN.ci-integration.txt\n/GATE-RUN.red.txt\n' > .gitignore
git -c init.defaultBranch=main init -q
git add -- Makefile .gitignore
commit() { git -c user.name=Fixture -c user.email=fixture@example.invalid -c commit.gpgsign=false commit -qm "$1"; }
commit fixture
export GITHUB_SERVER_URL=https://github.com GITHUB_REPOSITORY=identuum/fixture
export GITHUB_RUN_ID=123 GITHUB_RUN_ATTEMPT=2 GITHUB_JOB=verify GATE_WITNESS_TIE=commit
export GITHUB_SHA=$(git rev-parse HEAD)
gate='identuum-idp-oss make ci-verify'
plan='tool-versions repo-green rulefloor-check'
bash "$root/scripts/ci-record.sh" produce bash "$root/scripts/gate-witness.sh" run GATE-RUN.ci.txt "$gate" tool-versions=true repo-green=true rulefloor-check=true > "$scratch/producer.log" 2>&1
bash "$root/scripts/ci-record.sh" check GATE-RUN.ci.txt >> "$scratch/producer.log" 2>&1
cp GATE-RUN.ci.txt CI-WITNESS.txt
git add -- CI-WITNESS.txt
commit 'synthetic verify claim'
# This is the actual integration driver's artifact, not a renamed Verify record.
export GITHUB_JOB=integration GITHUB_SHA=$(git rev-parse HEAD)
bash "$root/scripts/ci-integration-record.sh" init >> "$scratch/producer.log" 2>&1
for target in test-db ci-integration-test rulefloor-integration; do
	bash "$root/scripts/ci-integration-record.sh" step "$target" >> "$scratch/producer.log" 2>&1
done
bash "$root/scripts/ci-integration-record.sh" finalize >> "$scratch/producer.log" 2>&1
cp GATE-RUN.ci-integration.txt PARTIAL-CLAIM.txt
git add -- PARTIAL-CLAIM.txt
commit 'synthetic integration claim'
found_gate=$(sed -n 's/^gate: //p' PARTIAL-CLAIM.txt)
export GITHUB_JOB=verify GITHUB_SHA=$(git rev-parse HEAD)
red_exit=0
bash "$root/scripts/ci-record.sh" produce bash "$root/scripts/gate-witness.sh" run GATE-RUN.red.txt "$gate" tool-versions=true 'repo-green=exit 7' rulefloor-check=true >> "$scratch/producer.log" 2>&1 || red_exit=$?
[ "$red_exit" -ne 0 ] || { echo 'fixture failed to produce a red record'; exit 1; }
bash "$root/scripts/ci-record.sh" check GATE-RUN.red.txt >> "$scratch/producer.log" 2>&1
cp GATE-RUN.red.txt RED-CLAIM.txt
git add -- RED-CLAIM.txt
commit 'synthetic red claim'
failures=0
check() {
	local label=$1; shift
	if "$@"; then echo "PASS $label"; else echo "FAIL $label"; failures=$((failures + 1)); fi
}
case_run() {
	local name=$1 record=$2 expected_exit=$3 expected_plan=$4 actual=0
	local args=(--repo . --record "$record")
	if [ "$baseline" != --baseline ]; then args+=(--expect-gate "$gate" --expect-plan "$expected_plan"); fi
	"$binary" "${args[@]}" > "$scratch/verdict" 2>&1 || actual=$?
	echo "$name: exit=$actual"
	cat "$scratch/verdict"
	check "$name exit" test "$actual" -eq "$expected_exit"
}
case_run right-green CI-WITNESS.txt 0 "$plan"
check 'right-green accepted' grep -q "check OK: ci-witness $gate green" "$scratch/verdict"
case_run wrong-gate PARTIAL-CLAIM.txt 1 "$plan"
check 'wrong-gate names expected' grep -Fq "expected gate \"$gate\"" "$scratch/verdict"
check 'wrong-gate names found' grep -Fq "found \"$found_gate\"" "$scratch/verdict"
case_run drifted-plan CI-WITNESS.txt 0 "$plan mint-decide"
check 'drifted-plan reported' grep -Fq 'PLAN DRIFT' "$scratch/verdict"
check 'drifted-plan names the difference' grep -Fq 'mint-decide' "$scratch/verdict"
case_run right-red RED-CLAIM.txt 1 "$plan"
check 'right-red remains red' grep -Fq 'result is "red"' "$scratch/verdict"
case_run missing MISSING.txt 0 "$plan"
check 'missing remains no claim' grep -Fq 'NO CI RECORD' "$scratch/verdict"
if [ "$baseline" != --baseline ]; then
	actual=0
	"$binary" --repo . --record CI-WITNESS.txt > "$scratch/verdict" 2>&1 || actual=$?
	check 'omitting expectations cannot bypass refusal' test "$actual" -ne 0
fi
[ "$failures" -eq 0 ] || { echo "ci-witness expectation tests: $failures failure(s)"; exit 1; }
echo 'check OK: CI witness caller expectation proofs'
