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
	# TWO recorder forms, one per driver that reaches here. The BASH form is
	# unchanged: scripts/ci-integration-record.sh drives init/step/finalize
	# through it. The JUDGE form arrived with THE-RUN-HALF, when ci-verify
	# moved to `lictor witness run`. The judge reads NO environment by its own
	# ruling (lictor PROJECT_DESC.md §3, no hidden inputs), so where the Bash
	# form is handed its provenance through GATE_WITNESS_CITES and
	# GATE_WITNESS_TIE, this driver composes the same two facts into the argv.
	# Nothing is relaxed: every refusal below is made for both forms.
	[ "$#" -ge 6 ] || refuse 'expected a Bash recorder or judge run or init invocation'
	if [ "$1" = bash ]; then
		case "$3" in run|init) ;; *) refuse 'expected recorder run or init mode';; esac
		# CI starts clean. Never let an old record stand in for a producer that
		# refuses to mint; leave such a file untouched and fail the job explicitly.
		[ ! -e "$4" ] && [ ! -L "$4" ] || refuse "record already exists before this invocation: $4"
		export GATE_WITNESS_CITES="${GATE_WITNESS_CITES:-CI gate invocation}; $context"
		exec "$@"
	fi
	[ "$2" = witness ] || refuse 'expected a Bash recorder or judge run or init invocation'
	case "$3" in run|init) ;; *) refuse 'expected recorder run or init mode';; esac
	# The record is named by a FLAG here, not by position, so the guard above
	# follows --record. An unnamed record is refused rather than guessed.
	argv=(); plan=(); record=""; cited=0; tied=0
	while [ "$#" -gt 0 ]; do
		case "$1" in
		--record|-record)
			[ "$#" -ge 2 ] || refuse 'the record flag needs a value'
			record=$2; argv+=("$1" "$2"); shift 2 ;;
		--cites|-cites)
			[ "$#" -ge 2 ] || refuse 'the cites flag needs a value'
			cited=1; argv+=("$1" "$2; $context"); shift 2 ;;
		--tie|-tie)
			[ "$#" -ge 2 ] || refuse 'the tie flag needs a value'
			tied=1; argv+=("$1" "$2"); shift 2 ;;
		--)
			shift; plan=("$@"); break ;;
		*)
			argv+=("$1"); shift ;;
		esac
	done
	[ -n "$record" ] || refuse 'invocation names no record'
	[ "$cited" -eq 1 ] || argv+=(--cites "CI gate invocation; $context")
	[ "$tied" -eq 1 ] || argv+=(--tie "${GATE_WITNESS_TIE:-commit}")
	[ ! -e "$record" ] && [ ! -L "$record" ] || refuse "record already exists before this invocation: $record"
	if [ "${#plan[@]}" -gt 0 ]; then exec "${argv[@]}" -- "${plan[@]}"; fi
	exec "${argv[@]}"
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
