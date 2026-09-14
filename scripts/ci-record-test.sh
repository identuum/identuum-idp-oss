#!/usr/bin/env bash
# Offline contract tests. --legacy runs the old workflow's stamp verbatim.
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
checker="$root/scripts/ci-record.sh"
scratch=$(mktemp -d /tmp/ci-record-test.XXXXXX)
trap 'rm -rf "$scratch"' EXIT
export GITHUB_SERVER_URL=https://github.com GITHUB_REPOSITORY=identuum/fixture
export GITHUB_RUN_ID=123 GITHUB_RUN_ATTEMPT=2 GITHUB_JOB=verify
export GITHUB_SHA=0123456789012345678901234567890123456789
identity="$GITHUB_SERVER_URL/$GITHUB_REPOSITORY/actions/runs/$GITHUB_RUN_ID attempt=$GITHUB_RUN_ATTEMPT sha=$GITHUB_SHA"
context="ci-context: $identity job=$GITHUB_JOB"
legacy=${2:-}
cd "$scratch"
failures=0
record() {
	printf 'schema: gate-run.v1\ngate: fixture\ncites: declared plan; %s\nplan: one\nresult: green\n' "$1" > GATE-RUN.ci.txt
}
check_case() {
	local name=$1 expected=$2 actual=0
	if [ -n "$legacy" ]; then
		bash "$legacy" > output.txt 2>&1 || actual=$?
	else
		bash "$checker" check GATE-RUN.ci.txt > output.txt 2>&1 || actual=$?
	fi
	if { [ "$expected" = pass ] && [ "$actual" -eq 0 ]; } || { [ "$expected" = refuse ] && [ "$actual" -ne 0 ]; }; then
		echo "PASS $name: expected=$expected exit=$actual"
	else
		echo "FAIL $name: expected=$expected exit=$actual"
		failures=$((failures + 1))
	fi
}
record "$context"
check_case present pass
rm GATE-RUN.ci.txt
check_case absent refuse
: > GATE-RUN.ci.txt
check_case empty refuse
record "${context/\/runs\/123 /\/runs\/122 }"
check_case other-run refuse
record "${context/attempt=2/attempt=1}"
check_case other-attempt refuse
record "${context/sha=$GITHUB_SHA/sha=ffffffffffffffffffffffffffffffffffffffff}"
check_case other-head refuse
record "${context/job=verify/job=integration}"
check_case other-job refuse
record "$context"
printf 'ci-run: %s\n' "${identity/\/runs\/123 /\/runs\/122 }" >> GATE-RUN.ci.txt
check_case conflicting-stamp refuse
record "$context"
printf 'cites: duplicate; %s\n' "$context" >> GATE-RUN.ci.txt
check_case duplicate-context refuse
printf 'cites: %s\n' "$context" > GATE-RUN.ci.txt
check_case malformed refuse
if [ -z "$legacy" ]; then
	# Exercise the unchanged real recorder on synthetic tracked content only.
	# No checkout, ignored cache or local credential is copied into this fixture.
	git -c init.defaultBranch=main init -q
	printf 'GATE-RUN.ci.txt\noutput.txt\n' > .gitignore
	printf 'synthetic gate fixture\n' > fixture.txt
	git add -- .gitignore fixture.txt
	git -c user.name=Fixture -c user.email=fixture@example.invalid -c commit.gpgsign=false commit -qm fixture
	export GITHUB_SHA=$(git rev-parse HEAD) GATE_WITNESS_TIE=commit
	for result in 0 7; do
		rm -f GATE-RUN.ci.txt
		actual=0
		# gate-witness run normalizes a failed target to recorder exit 1.
		expected=0
		if [ "$result" -ne 0 ]; then expected=1; fi
		bash "$checker" produce bash "$root/scripts/gate-witness.sh" run GATE-RUN.ci.txt fixture "one=exit $result" > output.txt 2>&1 || actual=$?
		if [ "$actual" -eq "$expected" ]; then echo "PASS producer-target-$result: recorder exit=$actual";
		else echo "FAIL producer-target-$result: recorder exit=$actual"; failures=$((failures + 1)); fi
		if grep -qx "target: one exit=$result" GATE-RUN.ci.txt; then echo "PASS recorded-target-$result";
		else echo "FAIL recorded-target-$result"; failures=$((failures + 1)); fi
		check_case "producer-record-$result" pass
	done
	# Rechecking an already stamped record must neither duplicate nor bless it anew.
	check_case recheck pass
	if [ "$(grep -c '^ci-run:' GATE-RUN.ci.txt)" -eq 1 ]; then echo 'PASS one-provenance-stamp';
	else echo 'FAIL one-provenance-stamp'; failures=$((failures + 1)); fi
	actual=0
	before=$(git hash-object GATE-RUN.ci.txt)
	bash "$checker" produce bash "$root/scripts/gate-witness.sh" run GATE-RUN.ci.txt fixture 'one=true' > output.txt 2>&1 || actual=$?
	if [ "$actual" -ne 0 ]; then echo "PASS existing-record-producer: exit=$actual";
	else echo 'FAIL existing-record-producer'; failures=$((failures + 1)); fi
	if [ "$before" = "$(git hash-object GATE-RUN.ci.txt)" ]; then echo 'PASS refused-record-unchanged';
	else echo 'FAIL refused-record-unchanged'; failures=$((failures + 1)); fi
fi
[ "$failures" -eq 0 ] || { echo "ci-record tests: $failures failure(s)"; exit 1; }
echo 'check OK: ci-record contract tests'
