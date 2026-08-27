#!/usr/bin/env bash
# gate-witness.sh — a committed run record behind the gate entry points
# (THE-UNWITNESSED-GREEN, 2026-08-28).
#
# WHY THIS EXISTS
# ---------------
# Gate results were the only claims in this workspace with no artifact behind
# them. A ledger has RULE-FLOOR.md, an install route has its gate, a tool
# version is printed and asserted — but "make verify EXIT 0" was a sentence in
# a report. Three reports stated gate facts that were false, and one of them
# ("biome clean" at c8f4386) stayed false for three slices because a run that
# stopped early left nothing that read INCOMPLETE.
#
# WHAT IT DOES
# ------------
# `run` drives a gate's targets one at a time and writes GATE-RUN.txt
# INCREMENTALLY: header and plan first, then one `target: NAME exit=N` line as
# each target finishes. A run that dies mid-way leaves a record whose plan
# names targets with no recorded run — INCOMPLETE, never green. On full
# success it appends the tree digest and `result: green`. `check` re-reads a
# record: unplanned-but-missing targets, nonzero exits, a missing result line,
# or a tree digest that no longer matches all FAIL.
#
# THE TRAP AND ITS SOLUTION (self-exclusion)
# ------------------------------------------
# The record is committed, so it cannot contain a hash of a tree that contains
# itself — that is a fixed point with no solution. So the digest covers every
# tracked and untracked-non-ignored file EXCEPT the record: the record
# witnesses the tree AROUND it, and the record itself is witnessed by the git
# commit that carries both. Nothing is self-referential.
#
# NOT FORGERY-PROOF, ON PURPOSE
# -----------------------------
# Every input here is local and the writer holds the pen: a hostile writer can
# fabricate a green record, digests included. This is a WITNESS a reader can
# check — re-run the gate on the tree the record names and compare — not a
# signature. It proves that a green claim is tied to an identifiable tree and
# that an interrupted or red run cannot read as green BY ACCIDENT. It cannot
# prove the commands actually executed, that output was not edited, or that
# the clock was honest.
#
# THREE COPIES, ONE WITNESS
# -------------------------
# Master: wiki/tools/gate-witness.sh. Vendored byte-identical copies:
# identuum-idp-oss/scripts/gate-witness.sh, identuum-ui/scripts/gate-witness.sh
# (single-repo checkouts have no ../wiki sibling). `--sync-check` holds all
# three and the digest recorded in wiki/contracts/gate-witness.master.sha256
# identical, and runs inside `wiki make check`.
#
# Modes:
#   run <record> <label> <name=command>...   drive a gate, write the record
#   check <repo-dir> <record>                verify a record against its tree
#   --selftest                               prove the teeth on a throwaway repo
#   --sync-check                             hold the three copies identical
#
# Test hook: GATE_WITNESS_ABORT_AFTER=N makes `run` die (exit 143) after N
# targets WITHOUT finalizing the record — a deterministic stand-in for a
# killed run, used by the selftest and red-proofs.
set -u

if command -v shasum >/dev/null 2>&1; then
	SHA256="shasum -a 256"
else
	SHA256="sha256sum"
fi

# Digest of the working tree minus the record (see THE TRAP above).
# Content-based, not commit-based: committing the same bytes does not change
# it, editing any tracked or untracked-non-ignored file does.
tree_digest() {
	local repo="$1" rec="$2"
	(
		cd "$repo" || { echo "NO-REPO"; exit 0; }
		local list existing="" f
		list=$( { git ls-files --cached --exclude-standard -- . ":(exclude)$rec"
			git ls-files --others --exclude-standard -- . ":(exclude)$rec"
			} 2>/dev/null | LC_ALL=C sort -u )
		while IFS= read -r f; do
			[ -f "$f" ] && existing+="$f"$'\n'
		done <<<"$list"
		existing="${existing%$'\n'}"
		if [ -z "$existing" ]; then echo "EMPTY-TREE"; exit 0; fi
		paste -d ' ' \
			<(printf '%s\n' "$existing" | git hash-object --stdin-paths) \
			<(printf '%s\n' "$existing") | $SHA256 | awk '{print $1}'
	)
}

now_utc() { date -u +%Y-%m-%dT%H:%M:%SZ; }

# Lines worth keeping verbatim: the counts and summaries the tools print.
# NOT a cap — every matching line is recorded. A tool whose count line does
# not match this pattern is simply not summarized (its exit code still is);
# that limitation is stated in the header of every record this writes.
EVIDENCE_RE='^check OK:|Tests  [0-9]|Test Files |wiki freshness:|sync violations:|SELFTEST OK|gate-witness OK:'

run_mode() {
	[ $# -ge 3 ] || { echo "usage: gate-witness.sh run <record> <label> <name=command>..." >&2; exit 2; }
	local rec="$1" label="$2"; shift 2
	local tmp; tmp=$(mktemp -d "${TMPDIR:-/tmp}/gate-witness.XXXXXX")
	# shellcheck disable=SC2064 — expand now: $tmp is function-local and the
	# trap fires after the function's scope is gone.
	trap "rm -rf '$tmp'" EXIT
	{
		echo "schema: gate-run.v1"
		echo "gate: $label"
		echo "note: evidence lines are the tools' own summary lines; a summary format this script does not match is recorded only as an exit code"
		echo "repo-head: $(git rev-parse --short HEAD 2>/dev/null || echo none)$(git status --porcelain 2>/dev/null | grep -q . && echo ' (dirty)')"
		echo "started: $(now_utc)"
		local e
		printf 'plan:'
		for e in "$@"; do printf ' %s' "${e%%=*}"; done
		printf '\n'
	} >"$rec"
	local overall=0 n=0 name cmd ec okpkgs
	for e in "$@"; do
		name="${e%%=*}"; cmd="${e#*=}"
		echo "==> gate-witness: $name"
		bash -c "$cmd" 2>&1 | tee "$tmp/out.log"
		ec=${PIPESTATUS[0]}
		n=$((n + 1))
		if [ "$name" = "tool-versions" ]; then
			sed 's/^/tool: /' "$tmp/out.log" >>"$rec"
		fi
		grep -E "$EVIDENCE_RE" "$tmp/out.log" 2>/dev/null | sed "s/^/evidence: [$name] /" >>"$rec" || true
		# go-test package lines only: `ok <pkg> <dur>s` or `(cached)` — the
		# duration requirement keeps other tools' leading-"ok" summary lines
		# (e.g. wiki-freshness rows) out of this count.
		okpkgs=$(grep -c -E '^ok[[:space:]]+\S+[[:space:]]+([0-9.]+s|\(cached\))' "$tmp/out.log" 2>/dev/null || true)
		[ "${okpkgs:-0}" -gt 0 ] && echo "evidence: [$name] go packages ok: $okpkgs" >>"$rec"
		echo "target: $name exit=$ec" >>"$rec"
		if [ -n "${GATE_WITNESS_ABORT_AFTER:-}" ] && [ "$n" -ge "$GATE_WITNESS_ABORT_AFTER" ]; then
			echo "gate-witness: ABORTED by GATE_WITNESS_ABORT_AFTER=$GATE_WITNESS_ABORT_AFTER (record left unfinalized)" >&2
			exit 143
		fi
		if [ "$ec" -ne 0 ]; then overall=1; break; fi
	done
	echo "finished: $(now_utc)" >>"$rec"
	if [ "$overall" -eq 0 ]; then
		echo "tree: sha256=$(tree_digest . "$rec")" >>"$rec"
		echo "result: green" >>"$rec"
	else
		echo "result: red" >>"$rec"
	fi
	return "$overall"
}

check_mode() {
	[ $# -eq 2 ] || { echo "usage: gate-witness.sh check <repo-dir> <record>" >&2; exit 2; }
	local repo="$1" rec="$2" path="$1/$2" bad=0 label plan name line ec recorded actual
	if [ ! -f "$path" ]; then
		echo "GATE-WITNESS FAIL: no record at $path — the gate has never left evidence here"
		return 1
	fi
	head -1 "$path" | grep -q '^schema: gate-run\.v1$' || {
		echo "GATE-WITNESS FAIL: $path is not a gate-run.v1 record"
		return 1
	}
	label=$(sed -n 's/^gate: //p' "$path" | head -1)
	plan=$(sed -n 's/^plan: //p' "$path" | head -1)
	if [ -z "$plan" ]; then
		echo "GATE-WITNESS FAIL: $path has no plan line"
		return 1
	fi
	for name in $plan; do
		if ! grep -q "^target: $name exit=" "$path"; then
			echo "GATE-WITNESS INCOMPLETE: target '$name' has no recorded run in $path — the run stopped early"
			bad=1
		fi
	done
	while IFS= read -r line; do
		name=${line#target: }; name=${name% exit=*}
		ec=${line##*exit=}
		if [ "$ec" != "0" ]; then
			echo "GATE-WITNESS RED: target '$name' recorded exit=$ec in $path"
			bad=1
		fi
	done < <(grep '^target: ' "$path")
	if ! grep -q '^result: green$' "$path"; then
		[ "$bad" -eq 0 ] && echo "GATE-WITNESS INCOMPLETE: $path carries no 'result: green' line (run never finalized)"
		bad=1
	fi
	if [ "$bad" -eq 0 ]; then
		recorded=$(sed -n 's/^tree: sha256=//p' "$path" | tail -1)
		actual=$(tree_digest "$repo" "$rec")
		if [ "$recorded" != "$actual" ]; then
			echo "GATE-WITNESS STALE: $path claims sha256=$recorded but the tree is sha256=$actual — the tree changed after the recorded run"
			bad=1
		fi
	fi
	if [ "$bad" -eq 0 ]; then
		echo "gate-witness OK: '$label' green on the tree it claims ($(grep -c '^target: ' "$path") targets)"
	fi
	return "$bad"
}

sync_check() {
	local script_dir wiki_dir master digest_file bad=0 copy recorded actual
	script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
	wiki_dir=$(dirname "$script_dir")
	master="${BASH_SOURCE[0]}"
	digest_file="$wiki_dir/contracts/gate-witness.master.sha256"
	for copy in "$wiki_dir/../identuum-idp-oss/scripts/gate-witness.sh" \
		"$wiki_dir/../identuum-ui/scripts/gate-witness.sh"; do
		if [ ! -f "$copy" ]; then
			echo "  VIOLATION  vendored gate-witness copy MISSING: $copy"
			bad=$((bad + 1))
		elif ! cmp -s "$master" "$copy"; then
			echo "  VIOLATION  vendored gate-witness copy DIVERGES from the master: $copy (its repo's verify is witnessed by something else)"
			bad=$((bad + 1))
		fi
	done
	if [ ! -f "$digest_file" ]; then
		echo "  VIOLATION  recorded master digest MISSING: $digest_file"
		bad=$((bad + 1))
	else
		recorded=$(awk '{print $1}' "$digest_file")
		actual=$($SHA256 "$master" | awk '{print $1}')
		if [ "$recorded" != "$actual" ]; then
			echo "  VIOLATION  recorded master digest STALE: $digest_file says $recorded, master is $actual"
			bad=$((bad + 1))
		fi
	fi
	echo "gate-witness sync: master + 2 vendored copies + recorded digest"
	echo "gate-witness sync violations: $bad"
	[ "$bad" -eq 0 ]
}

selftest() {
	local self tmp fails=0
	self=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")
	tmp=$(mktemp -d "${TMPDIR:-/tmp}/gate-witness-selftest.XXXXXX")
	# shellcheck disable=SC2064 — expand now, same reason as run_mode.
	trap "rm -rf '$tmp'" EXIT
	(
		cd "$tmp" || exit 9
		git init -q .
		echo alpha >f.txt
		git add f.txt

		# 1 FIRE: no record at all
		bash "$self" check . GATE-RUN.txt >/dev/null 2>&1 && { echo "SELFTEST FAIL 1: missing record passed"; exit 1; }

		# 2 PASS: green run then check
		bash "$self" run GATE-RUN.txt "selftest gate" 'a=true' 'b=true' >/dev/null 2>&1 || { echo "SELFTEST FAIL 2a: green run exited nonzero"; exit 1; }
		bash "$self" check . GATE-RUN.txt >/dev/null 2>&1 || { echo "SELFTEST FAIL 2b: fresh green record did not pass"; exit 1; }

		# 3 FIRE: tracked file altered after the run — STALE
		echo beta >>f.txt
		bash "$self" check . GATE-RUN.txt 2>&1 | grep -q 'GATE-WITNESS STALE' || { echo "SELFTEST FAIL 3: altered tracked file did not read STALE"; exit 1; }
		printf 'alpha\n' >f.txt

		# 4 FIRE: new untracked file after the run — STALE (the digest sees it)
		echo stray >stray.txt
		bash "$self" check . GATE-RUN.txt 2>&1 | grep -q 'GATE-WITNESS STALE' || { echo "SELFTEST FAIL 4: new untracked file did not read STALE"; exit 1; }
		rm stray.txt
		bash "$self" check . GATE-RUN.txt >/dev/null 2>&1 || { echo "SELFTEST FAIL 4b: restored tree did not pass again"; exit 1; }

		# 5 FIRE: a red target — run exits nonzero and check reads RED
		bash "$self" run GATE-RUN.txt "selftest gate" 'a=true' 'b=false' >/dev/null 2>&1 && { echo "SELFTEST FAIL 5a: red run exited zero"; exit 1; }
		bash "$self" check . GATE-RUN.txt 2>&1 | grep -q 'GATE-WITNESS RED' || { echo "SELFTEST FAIL 5b: red record did not read RED"; exit 1; }

		# 6 FIRE: a run cut before its last target — check NAMES the missing target
		GATE_WITNESS_ABORT_AFTER=1 bash "$self" run GATE-RUN.txt "selftest gate" 'a=true' 'b=true' >/dev/null 2>&1
		[ $? -eq 143 ] || { echo "SELFTEST FAIL 6a: abort hook did not exit 143"; exit 1; }
		bash "$self" check . GATE-RUN.txt 2>&1 | grep -q "INCOMPLETE: target 'b' has no recorded run" || { echo "SELFTEST FAIL 6b: cut run did not name the missing target"; exit 1; }

		exit 0
	) || fails=1
	if [ "$fails" -eq 0 ]; then
		echo "SELFTEST OK — 6 case(s): fire (missing, stale x2, red, incomplete) and pass both proven"
		return 0
	fi
	return 1
}

case "${1:-}" in
run)
	shift
	run_mode "$@"
	;;
check)
	shift
	check_mode "$@"
	;;
--selftest)
	selftest
	;;
--sync-check)
	sync_check
	;;
*)
	echo "usage: gate-witness.sh run|check|--selftest|--sync-check" >&2
	exit 2
	;;
esac
