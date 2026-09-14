#!/usr/bin/env bash
# Wrap an existing recorder invocation, replacing only its record argument.
# The Make recipe still owns the plan, label, dependencies and failure mode.
set -u

[ "$#" -ge 4 ] && [ "$1" = bash ] || { echo "verify-check: expected a Bash recorder invocation" >&2; exit 2; }
driver=("$1" "$2")
case "${2##*/}" in
verify-all.sh) shift 2 ;;
gate-witness.sh)
	[ "$3" = run ] || { echo "verify-check: expected recorder run mode" >&2; exit 2; }
	driver+=(run); shift 3 ;;
*) echo "verify-check: unsupported recorder driver" >&2; exit 2 ;;
esac
shift # Discard the usual in-tree record path, retaining every other argument.
root=$(git rev-parse --show-toplevel) || exit 2
scratch=$(mktemp -d /tmp/identuum-verify-check.XXXXXX) || exit 2
cleanup() { rm -rf "$scratch"; }
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
scratch=$(cd "$scratch" && pwd -P) || exit 2
case "$scratch/" in "$root/"*) echo "verify-check: temporary record must be outside the working tree" >&2; exit 2;; esac

echo "NON-MINTING: external diagnostic record; no witness is minted"
result=0
"${driver[@]}" "$scratch/record.txt" "$@" || result=$?
if [ -s "$scratch/record.txt" ]; then
	cat "$scratch/record.txt"
fi
echo "NON-MINTING: driver exit=$result; external record discarded"
exit "$result"
