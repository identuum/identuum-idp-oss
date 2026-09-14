#!/usr/bin/env bash
# The CI job's recorded Make targets, in their existing order. Workflow steps
# select entries here; they do not carry another command list. Infrastructure
# remains between those steps and is explicitly outside this record's scope.
set -eu
root=$(cd "$(dirname "$0")/.." && pwd -P)
record=GATE-RUN.ci-integration.txt
plan=(
	'test-db=make test-db'
	'ci-integration-test=make ci-integration-test'
	'rulefloor-integration=make rulefloor-integration'
)
names=()
for entry in "${plan[@]}"; do names+=("${entry%%=*}"); done
refuse() { echo "ci-integration-record: REFUSED — $*" >&2; exit 1; }
export GATE_WITNESS_TIE=commit
case "${1:-}" in
init)
	[ "$#" -eq 1 ] || refuse 'expected init'
	export GATE_WITNESS_CITES='scripts/ci-integration-record.sh declares only the three Make targets in the Integration Tests job; excludes service provisioning, checkout, Go setup, cache actions, PostgreSQL readiness wait, rulefloor installation/version checks, and artifact delivery; green is not a whole-job verdict'
	exec bash "$root/scripts/ci-record.sh" produce bash "$root/scripts/gate-witness.sh" init "$record" 'identuum-idp-oss CI integration targets (partial job record)' "${names[@]}"
	;;
step|finalize)
	bash "$root/scripts/ci-record.sh" check "$record"
	[ "$(grep '^plan:' "$record" || true)" = "plan: ${names[*]}" ] || refuse 'record does not carry this plan'
	! grep -q '^result:' "$record" || refuse 'record is already finalized'
	if [ "$1" = finalize ]; then
		[ "$#" -eq 1 ] || refuse 'expected finalize'
		exec bash "$root/scripts/gate-witness.sh" finalize "$record"
	fi
	[ "$#" -eq 2 ] || refuse 'expected step <target>'
	completed=$(grep -c '^target:' "$record" || true)
	[ "$completed" -lt "${#plan[@]}" ] || refuse 'all planned targets have already run'
	[ "$2" = "${names[$completed]}" ] || refuse "next target is ${names[$completed]}, not $2"
	if grep '^target:' "$record" | grep -v ' exit=0$' >/dev/null; then refuse 'a previous target failed'; fi
	exec bash "$root/scripts/gate-witness.sh" step "$record" "${plan[$completed]}"
	;;
*) refuse 'expected init, step or finalize';;
esac
