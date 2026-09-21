#!/usr/bin/env bash
# Wrap an existing recorder invocation, replacing only its record argument.
# The Make recipe still owns the plan, label, dependencies and failure mode.
set -u

# TWO recorder forms reach here since THE-RUN-HALF (2026-09-21), one per
# recipe that drives one. `verify` still drives the Bash complete-run
# recorder, which names its record POSITIONALLY; `ci-verify` and
# `verify-integration` drive the pinned judge, `lictor witness run --repo ABS
# --record PATH ...`, which names it with a FLAG. Nothing else differs: each
# form's plan, label, ordering and failure mode stay the recipe's. The
# gate-witness.sh run form this wrapper also took until THE-RUN-HALF is gone
# with the two recipes that drove it: a branch no recipe enters is a branch
# nothing proves. gate-witness.sh itself is untouched and still owns check,
# --selftest and --sync-check, and scripts/ci-record.sh still drives its run.
[ "$#" -ge 4 ] || { echo "verify-check: expected a recorder invocation" >&2; exit 2; }
driver=()
positional=0
if [ "$1" = bash ]; then
	driver=("$1" "$2")
	case "${2##*/}" in
	verify-all.sh) shift 2 ;;
	*) echo "verify-check: unsupported recorder driver" >&2; exit 2 ;;
	esac
	shift # Discard the usual in-tree record path, retaining every other argument.
	positional=1
else
	[ "$2" = witness ] && [ "$3" = run ] || { echo "verify-check: unsupported recorder driver" >&2; exit 2; }
fi
root=$(git rev-parse --show-toplevel) || exit 2
scratch=$(mktemp -d /tmp/identuum-verify-check.XXXXXX) || exit 2
cleanup() { rm -rf "$scratch"; }
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
scratch=$(cd "$scratch" && pwd -P) || exit 2
case "$scratch/" in "$root/"*) echo "verify-check: temporary record must be outside the working tree" >&2; exit 2;; esac

if [ "$positional" = 1 ]; then
	driver+=("$scratch/record.txt" "$@")
else
	# Retain every argument but the in-tree record path. The plan after `--`
	# is passed through untouched.
	replaced=0
	while [ "$#" -gt 0 ]; do
		case "$1" in
		--record|-record)
			[ "$#" -ge 2 ] || { echo "verify-check: the record flag needs a value" >&2; exit 2; }
			driver+=("$1" "$scratch/record.txt"); replaced=1; shift 2 ;;
		--)
			driver+=("$@"); break ;;
		*)
			driver+=("$1"); shift ;;
		esac
	done
	[ "$replaced" -eq 1 ] || { echo "verify-check: the invocation names no record to replace" >&2; exit 2; }
fi

echo "NON-MINTING: external diagnostic record; no witness is minted"
result=0
"${driver[@]}" || result=$?
if [ -s "$scratch/record.txt" ]; then
	cat "$scratch/record.txt"
fi
echo "NON-MINTING: driver exit=$result; external record discarded"
exit "$result"
