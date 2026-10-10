#!/usr/bin/env bash
# The CI job's recorded Make targets, in their existing order. Workflow steps
# select entries here; they do not carry another command list. Infrastructure
# remains between those steps and is explicitly outside this record's scope.
set -eu
refuse() { echo "ci-integration-record: REFUSED — $*" >&2; exit 1; }
# OSS-MINT-GUARD-2 (review OSS-MINT-ISOLATION M3, judge ruling Q1(a)): this
# records the hosted job's targets against the runner's own service database
# on 5513, the one place a test run may use that port. It runs only there,
# refusing before git, lictor, a record or a Make target. Locally, use
# `DEV_PG_HOST_PORT=<scratch port> make verify-integration`.
if [ "${CI:-}" != true ] || [ "${GITHUB_ACTIONS:-}" != true ]; then
	refuse 'this recorder runs only in the hosted CI job (CI=true and GITHUB_ACTIONS=true); locally run DEV_PG_HOST_PORT=<scratch port> make verify-integration'
fi
root=$(cd "$(dirname "$0")/.." && pwd -P)
record=GATE-RUN.ci-integration.txt
# lictor hands a step only its environment allowlist, so the hosted markers
# reach each target's test-db-endpoint guard as make arguments.
plan=(
	'test-db=make test-db CI=true GITHUB_ACTIONS=true'
	'ci-integration-test=make ci-integration-test CI=true GITHUB_ACTIONS=true'
	'rulefloor-integration=make rulefloor-integration CI=true GITHUB_ACTIONS=true'
)
names=()
for entry in "${plan[@]}"; do names+=("${entry%%=*}"); done
# OSS-LICTOR-ADOPT-B: the recorder is lictor's stepwise witness (PROJECT_DESC
# §4 row 5), pinned by the workflow's LICTOR_VERSION; its records are
# byte-identical to gate-witness.sh's for this shape. Its provenance is argv
# (--cites, --tie), never GATE_WITNESS_* environment.
lictor=${LICTOR:-lictor}
# The record is the CALLER's, as it was with gate-witness.sh: the repository
# the job (or a fixture) runs in, not the directory this script lives in.
repo=$(git rev-parse --show-toplevel)
witness() { "$lictor" witness "$1" --repo "$repo" --record "$record" --tie commit "${@:2}"; }
case "${1:-}" in
init)
	[ "$#" -eq 1 ] || refuse 'expected init'
	exec bash "$root/scripts/ci-record.sh" produce "$lictor" witness init --repo "$repo" --record "$record" \
		--label 'identuum-idp-oss CI integration targets (partial job record)' --tie commit \
		--cites 'scripts/ci-integration-record.sh declares only the three Make targets in the Integration Tests job; excludes service provisioning, checkout, Go setup, cache actions, PostgreSQL readiness wait, rulefloor installation/version checks, and artifact delivery; green is not a whole-job verdict' \
		-- "${names[@]}"
	;;
step|finalize)
	bash "$root/scripts/ci-record.sh" check "$record"
	[ "$(grep '^plan:' "$record" || true)" = "plan: ${names[*]}" ] || refuse 'record does not carry this plan'
	! grep -q '^result:' "$record" || refuse 'record is already finalized'
	if [ "$1" = finalize ]; then
		[ "$#" -eq 1 ] || refuse 'expected finalize'
		witness finalize; exit $?
	fi
	[ "$#" -eq 2 ] || refuse 'expected step <target>'
	completed=$(grep -c '^target:' "$record" || true)
	[ "$completed" -lt "${#plan[@]}" ] || refuse 'all planned targets have already run'
	[ "$2" = "${names[$completed]}" ] || refuse "next target is ${names[$completed]}, not $2"
	if grep '^target:' "$record" | grep -v ' exit=0$' >/dev/null; then refuse 'a previous target failed'; fi
	witness step -- "${plan[$completed]}"; exit $?
	;;
*) refuse 'expected init, step or finalize';;
esac
