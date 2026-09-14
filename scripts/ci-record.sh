#!/usr/bin/env bash
# Bind the recorder's citation to this CI invocation before it runs. Checking
# only a file's existence and stamping it afterwards would bless stale output.
# This is provenance against accidental reuse, not a signature. The existing
# ci-witness judge still owns target completeness and the gate's verdict.
set -eu
refuse() { echo "ci-record: REFUSED — $*" >&2; exit 1; }
for name in GITHUB_SERVER_URL GITHUB_REPOSITORY GITHUB_RUN_ID GITHUB_RUN_ATTEMPT GITHUB_SHA GITHUB_JOB; do
	value=${!name:-}
	[ -n "$value" ] || refuse "$name is missing"
	case "$value" in *$'\n'*|*$'\r'*) refuse "$name must be one line";; esac
done
identity="$GITHUB_SERVER_URL/$GITHUB_REPOSITORY/actions/runs/$GITHUB_RUN_ID attempt=$GITHUB_RUN_ATTEMPT sha=$GITHUB_SHA"
context="ci-context: $identity job=$GITHUB_JOB"
case "${1:-}" in
produce)
	shift
	[ "$#" -ge 6 ] && [ "$1" = bash ] || refuse 'expected a Bash recorder run or init invocation'
	case "$3" in run|init) ;; *) refuse 'expected recorder run or init mode';; esac
	# CI starts clean. Never let an old record stand in for a producer that
	# refuses to mint; leave such a file untouched and fail the job explicitly.
	[ ! -e "$4" ] && [ ! -L "$4" ] || refuse "record already exists before this invocation: $4"
	export GATE_WITNESS_CITES="${GATE_WITNESS_CITES:-CI gate invocation}; $context"
	exec "$@"
	;;
check)
	[ "$#" -eq 2 ] || refuse 'expected check <record>'
	record=$2
	[ -f "$record" ] && [ ! -L "$record" ] || refuse "record is absent or not a regular file: $record"
	[ -s "$record" ] || refuse "record is empty: $record"
	[ "$(grep -c '^schema: gate-run.v1$' "$record" || true)" = 1 ] || refuse 'not a gate-run.v1 record'
	citation=$(grep '^cites:' "$record" || true)
	case "$citation" in *$'\n'*) refuse 'multiple producer citations';; esac
	case "$citation" in *"; $context") ;; *) refuse 'producer context does not match this run, attempt, commit and job';; esac
	stamp=$(grep '^ci-run:' "$record" || true)
	[ -z "$stamp" ] || [ "$stamp" = "ci-run: $identity" ] || refuse 'conflicting or duplicate CI provenance'
	# Only a producer-bound record may gain the legacy provenance field that
	# downstream ci-witness consumes. Red and interrupted records keep it too.
	if [ -z "$stamp" ]; then printf 'ci-run: %s\n' "$identity" >> "$record"; fi
	echo "check OK: ci-record — $record belongs to this run, attempt, commit and job"
	;;
*) refuse 'expected produce or check';;
esac
