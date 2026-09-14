#!/usr/bin/env bash
# Drive ONE caller-declared plan through the shared recorder's public
# stepwise interface. Keep its byte-pinned writer, reader and verdict rules.
# A failing command does not prevent independent commands from being judged.
set -u

[ "$#" -ge 3 ] || { echo "usage: verify-all.sh record label [--requires target:prerequisite] -- name=command ..." >&2; exit 2; }
record="$1"; label="$2"; shift 2
witness="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/gate-witness.sh"
dependencies=()
while [ "${1:-}" = --requires ]; do
	[ "$#" -ge 2 ] || exit 2
	dependencies+=("$2"); shift 2
done
[ "${1:-}" = -- ] || { echo "verify-all: missing plan separator --" >&2; exit 2; }
shift
[ "$#" -gt 0 ] || { echo "verify-all: empty plan" >&2; exit 2; }

# Validate the dependency graph before opening a record. Dependencies must
# name earlier plan entries, so missing prerequisites and cycles are refused.
names=()
seen=" "
for entry in "$@"; do
	name="${entry%%=*}"
	if [[ "$entry" != *=* || ! "$name" =~ ^[a-zA-Z0-9_-]+$ || "$seen" == *" $name "* ]]; then
		echo "verify-all: invalid or duplicate plan entry: $name" >&2; exit 2
	fi
	names+=("$name"); seen+="$name "
done
for dependency in "${dependencies[@]}"; do
	name="${dependency%%:*}"; prerequisite="${dependency#*:}"
	case "$seen" in *" $name "*) ;; *) echo "verify-all: unknown dependent $name" >&2; exit 2;; esac
	prior=" "
	for candidate in "${names[@]}"; do
		[ "$candidate" = "$name" ] && break
		prior+="$candidate "
	done
	case "$prior" in *" $prerequisite "*) ;; *) echo "verify-all: $name requires an earlier planned target: $prerequisite" >&2; exit 2;; esac
done

# init intentionally permits dirty stepwise clients. This local driver must
# retain run's stricter rule: dirty WORK is evaluated, but never minted.
# Gate records themselves are excluded exactly as in work_state.
dirty=$(git status --porcelain -- . ":(exclude)$record" ':(exclude)GATE-RUN*.txt') || exit 2
target="$record"
scratch=""
if [ -n "$dirty" ]; then
	scratch=$(mktemp "${TMPDIR:-/tmp}/verify-all-unminted.XXXXXX") || exit 2
	target="$scratch"
	echo "GATE-WITNESS NOT MINTING: dirty work; $record remains untouched" >&2
fi
cleanup() { [ -z "$scratch" ] || rm -f "$scratch"; }
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
bash "$witness" init "$target" "$label" "${names[@]}" || exit $?

overall=0
for entry in "$@"; do
	name="${entry%%=*}"
	reason=""
	for dependency in "${dependencies[@]}"; do
		[ "${dependency%%:*}" = "$name" ] || continue
		prerequisite="${dependency#*:}"
		if ! grep -q "^target: $prerequisite exit=0$" "$target"; then
			status=$(sed -n "s/^target: $prerequisite exit=//p" "$target")
			reason="dependency $prerequisite recorded exit=${status:-missing}"
			break
		fi
	done
	if [ -n "$reason" ]; then
		# 125 is an explicit not-run result, never a pass. The recorder
		# captures this reason as evidence and finalizes the run RED.
		printf -v command 'printf "%%s\\n" %q; exit 125' "check FAILED: NOT-RUN $name: $reason"
		entry="$name=$command"
	fi
	bash "$witness" step "$target" "$entry" || overall=1
done
bash "$witness" finalize "$target" || overall=1
if [ -n "$scratch" ]; then
	# Preserve the complete diagnostic record in the output, without
	# replacing the last committed-head record with evidence of dirty work.
	cat "$target"
	echo "GATE-WITNESS NOT MINTED: dirty work; $record is untouched"
fi
exit "$overall"
