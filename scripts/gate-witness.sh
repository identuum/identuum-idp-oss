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
#   init <record> <label> <name>...          open a record: header + plan only
#   step <record> <name=command>             run ONE planned target, append it
#   finalize <record>                        close a record; green only if every
#                                            planned target recorded exit=0
#   check <repo-dir> <record>                verify a record against its tree
#   --selftest                               prove the teeth on a throwaway repo
#   --sync-check                             hold the three copies identical
#
# init/step/finalize exist for CI jobs that have no single entry point (the
# ui job is discrete workflow steps interleaved with setup actions that a
# wrapper cannot run): the workflow declares the plan once in its init step,
# each shell step routes through `step`, and `finalize` refuses to write
# `result: green` unless every planned step actually recorded exit=0 — so a
# job that died mid-way uploads a record that reads INCOMPLETE, never green.
#
# THE CI TIE (THE-UNWITNESSED-MIRROR, 2026-08-28): GATE_WITNESS_TIE=commit
# makes finalize record `tree: commit=<full sha>` instead of the content
# digest. CI cannot commit its record, so the committed-alongside witness
# chain does not exist there; but a CI checkout IS an unmodified commit, so
# the commit SHA pins the tree content exactly as the local digest does —
# provided the tree is still clean at finalize, which the record checks and
# `check` enforces. GATE_WITNESS_CITES adds a `cites:` line naming the ONE
# place the expected target set is declared, so a reader comparing the local
# and CI records can tell an INTENDED subtraction from a run that stopped
# early: absent-from-plan is declared, in-plan-but-unrecorded is INCOMPLETE.
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

# repo_state <repo-dir> <exclude-path> — "<short-sha>[ (dirty)]", where dirty
# ignores ONLY the excluded record file (the record being written is not
# evidence against the tree it is about to witness).
repo_state() {
	local repo="$1" rec="$2"
	(
		cd "$repo" || { echo none; exit 0; }
		local head dirty
		head=$(git rev-parse --short HEAD 2>/dev/null || echo none)
		dirty=$(git status --porcelain -- . ":(exclude)$rec" 2>/dev/null | grep -q . && echo ' (dirty)')
		echo "$head$dirty"
	)
}

write_header() { # <record> <label> <plan name>...
	local rec="$1" label="$2"; shift 2
	{
		echo "schema: gate-run.v1"
		echo "gate: $label"
		echo "note: evidence lines are the tools' own summary lines; a summary format this script does not match is recorded only as an exit code"
		[ -n "${GATE_WITNESS_CITES:-}" ] && echo "cites: $GATE_WITNESS_CITES"
		echo "repo-head: $(repo_state . "$rec")"
		echo "started: $(now_utc)"
		local n
		printf 'plan:'
		for n in "$@"; do printf ' %s' "$n"; done
		printf '\n'
	} >"$rec"
}

record_one() { # <record> <name> <command> — returns the command's exit
	local rec="$1" name="$2" cmd="$3" out ec okpkgs t0 t1
	out=$(mktemp "${TMPDIR:-/tmp}/gate-witness-out.XXXXXX")
	echo "==> gate-witness: $name"
	t0=$(date +%s)
	bash -c "$cmd" 2>&1 | tee "$out"
	ec=${PIPESTATUS[0]}
	t1=$(date +%s)
	if [ "$name" = "tool-versions" ]; then
		sed 's/^/tool: /' "$out" >>"$rec"
	fi
	grep -E "$EVIDENCE_RE" "$out" 2>/dev/null | sed "s/^/evidence: [$name] /" >>"$rec" || true
	# go-test package lines only: `ok <pkg> <dur>s` or `(cached)` — the
	# duration requirement keeps other tools' leading-"ok" summary lines
	# (e.g. wiki-freshness rows) out of this count.
	okpkgs=$(grep -c -E '^ok[[:space:]]+\S+[[:space:]]+([0-9.]+s|\(cached\))' "$out" 2>/dev/null || true)
	[ "${okpkgs:-0}" -gt 0 ] && echo "evidence: [$name] go packages ok: $okpkgs" >>"$rec"
	# THE-SLOW-RITUAL: wall clock per target, on its OWN line. The `target:`
	# line's shape is load-bearing — finalize_into greps `^target: N exit=0$`
	# anchored, and check_mode reads everything after the last `exit=` — so a
	# suffix there would silently break both. A separate line adds the number
	# without touching either parser, and a run that dies inside a target
	# leaves no elapsed line at all, which is the honest record.
	echo "elapsed: $name $((t1 - t0))s" >>"$rec"
	echo "target: $name exit=$ec" >>"$rec"
	rm -f "$out"
	return "$ec"
}

finalize_into() { # <record> — green ONLY if every planned target recorded exit=0
	local rec="$1" plan name all=0
	plan=$(sed -n 's/^plan: //p' "$rec" | head -1)
	for name in $plan; do
		grep -q "^target: $name exit=0$" "$rec" || all=1
	done
	echo "finished: $(now_utc)" >>"$rec"
	if [ "$all" -eq 0 ]; then
		if [ "${GATE_WITNESS_TIE:-digest}" = "commit" ]; then
			echo "tie-note: CI cannot commit this record, so the committed-alongside witness chain does not exist here; the checkout IS an unmodified commit, so the full commit SHA below pins the tree content exactly as the local digest does — valid only while the tree stays clean, which check enforces" >>"$rec"
			echo "tree: commit=$(git rev-parse HEAD 2>/dev/null || echo none)$(git status --porcelain 2>/dev/null | grep -q . && echo ' (dirty-at-finalize)')" >>"$rec"
		else
			echo "tree: sha256=$(tree_digest . "$rec")" >>"$rec"
		fi
		# THE-STALE-WITNESS (two-repo witness): a gate that exercises MORE
		# than this repo must pin every repo it exercised. Each entry in
		# GATE_WITNESS_XREPO ("name=path", space-separated) records that
		# sibling's HEAD, dirty state and content digest at finalize time;
		# check verifies all of them against the siblings as they are NOW.
		if [ -n "${GATE_WITNESS_XREPO:-}" ]; then
			local xr xname xpath
			for xr in $GATE_WITNESS_XREPO; do
				xname="${xr%%=*}"; xpath="${xr#*=}"
				# The exclusion must be a RELATIVE never-existing name: an
				# absolute path makes git's pathspec fail, the file list
				# comes back empty, and BOTH sides compute EMPTY-TREE — a
				# digest comparison with no teeth (caught live at the first
				# two-repo mint; check also refuses EMPTY-TREE outright).
				echo "xrepo: $xname head=$(repo_state "$xpath" "GATE-RUN.txt") tree=sha256:$(tree_digest "$xpath" ".gate-witness-nonexistent")" >>"$rec"
			done
		fi
		echo "result: green" >>"$rec"
	else
		echo "result: red" >>"$rec"
	fi
	return "$all"
}

run_mode() {
	[ $# -ge 3 ] || { echo "usage: gate-witness.sh run <record> <label> <name=command>..." >&2; exit 2; }
	local rec="$1" label="$2"; shift 2
	local names=() e
	for e in "$@"; do names+=("${e%%=*}"); done
	write_header "$rec" "$label" "${names[@]}"
	local overall=0 n=0 name cmd
	for e in "$@"; do
		name="${e%%=*}"; cmd="${e#*=}"
		record_one "$rec" "$name" "$cmd" || overall=1
		n=$((n + 1))
		if [ -n "${GATE_WITNESS_ABORT_AFTER:-}" ] && [ "$n" -ge "$GATE_WITNESS_ABORT_AFTER" ]; then
			echo "gate-witness: ABORTED by GATE_WITNESS_ABORT_AFTER=$GATE_WITNESS_ABORT_AFTER (record left unfinalized)" >&2
			exit 143
		fi
		[ "$overall" -ne 0 ] && break
	done
	finalize_into "$rec" || true
	return "$overall"
}

init_mode() {
	[ $# -ge 3 ] || { echo "usage: gate-witness.sh init <record> <label> <plan name>..." >&2; exit 2; }
	local rec="$1" label="$2"; shift 2
	write_header "$rec" "$label" "$@"
}

step_mode() {
	[ $# -eq 2 ] || { echo "usage: gate-witness.sh step <record> <name=command>" >&2; exit 2; }
	local rec="$1" name="${2%%=*}" cmd="${2#*=}"
	if [ ! -f "$rec" ]; then
		echo "gate-witness: no record at $rec — run init first" >&2
		return 2
	fi
	record_one "$rec" "$name" "$cmd"
}

finalize_mode() {
	[ $# -eq 1 ] || { echo "usage: gate-witness.sh finalize <record>" >&2; exit 2; }
	if [ ! -f "$1" ]; then
		echo "gate-witness: no record at $1 — nothing to finalize" >&2
		return 2
	fi
	finalize_into "$1"
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
		if grep -q '^tree: commit=' "$path"; then
			recorded=$(sed -n 's/^tree: commit=//p' "$path" | tail -1)
			case "$recorded" in
			*dirty-at-finalize*)
				echo "GATE-WITNESS FAIL: $path is commit-tied but was finalized on a dirty tree — the SHA does not pin what actually ran"
				bad=1
				;;
			esac
			if [ "$bad" -eq 0 ]; then
				actual=$(cd "$repo" && git rev-parse HEAD 2>/dev/null || echo none)
				if [ "$recorded" != "$actual" ]; then
					echo "GATE-WITNESS STALE: $path claims commit=$recorded but HEAD is $actual — the checkout is no longer the recorded commit"
					bad=1
				elif (cd "$repo" && git status --porcelain 2>/dev/null | grep -q .); then
					echo "GATE-WITNESS STALE: $path is commit-tied to $recorded but the tree is dirty — its content no longer equals that commit"
					bad=1
				fi
			fi
		else
			recorded=$(sed -n 's/^tree: sha256=//p' "$path" | tail -1)
			actual=$(tree_digest "$repo" "$rec")
			if [ "$recorded" != "$actual" ]; then
				echo "GATE-WITNESS STALE: $path claims sha256=$recorded but the tree is sha256=$actual — the tree changed after the recorded run"
				bad=1
			fi
		fi
	fi
	# THE-STALE-WITNESS: the digest proves CONTENT; these prove the NAME. A
	# record that admits a dirty mint, or names any commit but the current
	# clean HEAD, fails — with one allowance: a tracked record cannot live
	# inside the commit it witnesses, so HEAD may be exactly one commit
	# beyond the recorded one PROVIDED that commit changed nothing but the
	# record itself (the witness commit).
	if [ "$bad" -eq 0 ] && ! grep -q '^tree: commit=' "$path"; then
		local rechead reclean curhead
		rechead=$(sed -n 's/^repo-head: //p' "$path" | head -1)
		case "$rechead" in
		*' (dirty)')
			echo "GATE-WITNESS DIRTY-MINT: $path was minted on a dirty tree ($rechead) — commit first, mint at clean HEAD"
			bad=1
			;;
		none | '') : ;; # no git at mint time — nothing to compare
		*)
			rechead=$(cd "$repo" && git rev-parse --verify --quiet "$rechead^{commit}" || echo unknown)
			curhead=$(cd "$repo" && git rev-parse HEAD 2>/dev/null || echo none)
			reclean=$(cd "$repo" && git status --porcelain -- . ":(exclude)$rec" 2>/dev/null | grep -c . || true)
			if [ "$rechead" = "unknown" ]; then
				echo "GATE-WITNESS STALE-HEAD: $path names a commit this repository does not have"
				bad=1
			elif [ "${reclean:-0}" -ne 0 ]; then
				echo "GATE-WITNESS DIRTY-NOW: the tree at $repo has changes beyond $rec — the record cannot witness a moving tree"
				bad=1
			elif [ "$rechead" != "$curhead" ]; then
				# The ONLY tolerated divergence: HEAD is the witness commit —
				# the DIRECT CHILD of the recorded commit, changing nothing
				# but the record file. Anything else (a later work commit, an
				# empty commit stacked on top) is a stale name.
				if [ "$(cd "$repo" && git rev-parse HEAD~1 2>/dev/null)" != "$rechead" ] ||
					[ "$(cd "$repo" && git diff --name-only "$rechead" HEAD 2>/dev/null)" != "$rec" ]; then
					echo "GATE-WITNESS STALE-HEAD: $path names $(echo "$rechead" | cut -c1-7) but HEAD is $(echo "$curhead" | cut -c1-7) and it is not the record's own witness commit — re-mint at the current clean HEAD"
					bad=1
				fi
			fi
			;;
		esac
	fi
	# Verify every sibling repo the record pins (the two-repo witness).
	if [ "$bad" -eq 0 ]; then
		local xline xname xhead xdigest xdir xcur
		while IFS= read -r xline; do
			xname=$(echo "$xline" | sed -n 's/^xrepo: \([^ ]*\) .*/\1/p')
			xhead=$(echo "$xline" | sed -n 's/.* head=\(.*\) tree=sha256:.*/\1/p')
			xdigest=$(echo "$xline" | sed -n 's/.*tree=sha256:\(.*\)$/\1/p')
			xdir="$repo/../$xname"
			case "$xhead" in
			*' (dirty)')
				echo "GATE-WITNESS DIRTY-MINT: $path pinned $xname at a dirty tree ($xhead) — the gate cannot say which $xname it exercised"
				bad=1
				continue
				;;
			esac
			if [ ! -d "$xdir/.git" ] && [ ! -f "$xdir/.git" ]; then
				echo "GATE-WITNESS FAIL: $path pins sibling $xname but $xdir is not a git repository"
				bad=1
				continue
			fi
			xcur=$(cd "$xdir" && git rev-parse --short HEAD 2>/dev/null || echo none)
			if [ "$(cd "$xdir" && git rev-parse --verify --quiet "$xhead^{commit}")" != "$(cd "$xdir" && git rev-parse HEAD 2>/dev/null)" ]; then
				echo "GATE-WITNESS STALE-XREPO: $path pins $xname at $xhead but its HEAD is $xcur — the sibling moved after the run"
				bad=1
			elif (cd "$xdir" && git status --porcelain -- . ":(exclude)GATE-RUN.txt" 2>/dev/null | grep -q .); then
				echo "GATE-WITNESS DIRTY-NOW: sibling $xname has uncommitted changes — the record cannot witness a moving tree"
				bad=1
			elif ! echo "$xdigest" | grep -qE '^[0-9a-f]{64}$'; then
				# A recorded EMPTY-TREE (or garbage) would recompute to the
				# same value and "match" — a pin with no teeth. Refuse it.
				echo "GATE-WITNESS FAIL: $path pins $xname with a vacuous digest ($xdigest) — the record does not actually pin that repo's content; re-mint"
				bad=1
			elif [ "$(tree_digest "$xdir" ".gate-witness-nonexistent")" != "$xdigest" ]; then
				echo "GATE-WITNESS STALE-XREPO: $xname content no longer matches the digest $path recorded"
				bad=1
			fi
		done < <(grep '^xrepo: ' "$path")
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
		# THE-STALE-WITNESS: check now refuses a record minted on a dirty
		# tree or naming anything but the current clean HEAD, so the
		# fixture commits its base before any run.
		git -c user.name=selftest -c user.email=selftest@local -c commit.gpgsign=false commit -qm base0

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

		# 7 PASS: init/step/finalize round-trip (the no-single-entry-point shape)
		bash "$self" init GATE-RUN.txt "selftest stepwise" a b >/dev/null 2>&1 || { echo "SELFTEST FAIL 7a: init failed"; exit 1; }
		bash "$self" step GATE-RUN.txt 'a=true' >/dev/null 2>&1 || { echo "SELFTEST FAIL 7b: step a failed"; exit 1; }
		bash "$self" step GATE-RUN.txt 'b=true' >/dev/null 2>&1 || { echo "SELFTEST FAIL 7c: step b failed"; exit 1; }
		bash "$self" finalize GATE-RUN.txt >/dev/null 2>&1 || { echo "SELFTEST FAIL 7d: finalize of a complete green run failed"; exit 1; }
		bash "$self" check . GATE-RUN.txt >/dev/null 2>&1 || { echo "SELFTEST FAIL 7e: stepwise green record did not pass"; exit 1; }

		# 8 FIRE: finalize REFUSES green when a planned step never ran
		bash "$self" init GATE-RUN.txt "selftest stepwise" a b >/dev/null 2>&1
		bash "$self" step GATE-RUN.txt 'a=true' >/dev/null 2>&1
		bash "$self" finalize GATE-RUN.txt >/dev/null 2>&1 && { echo "SELFTEST FAIL 8a: finalize wrote green with a planned step missing"; exit 1; }
		grep -q '^result: red$' GATE-RUN.txt || { echo "SELFTEST FAIL 8b: unfinished stepwise record is not red"; exit 1; }
		bash "$self" check . GATE-RUN.txt 2>&1 | grep -q "INCOMPLETE: target 'b'" || { echo "SELFTEST FAIL 8c: check did not name the unrun step"; exit 1; }

		# 10 FIRE (THE-STALE-WITNESS): a green mint on a DIRTY tree fails check
		echo drift >>f.txt
		bash "$self" run GATE-RUN.txt "selftest gate" 'a=true' >/dev/null 2>&1
		bash "$self" check . GATE-RUN.txt 2>&1 | grep -q 'GATE-WITNESS DIRTY-MINT' || { echo "SELFTEST FAIL 10: dirty mint did not fail check"; exit 1; }
		git checkout -q -- f.txt

		# 11 PASS: clean mint, then the WITNESS COMMIT (record only) still passes
		bash "$self" run GATE-RUN.txt "selftest gate" 'a=true' >/dev/null 2>&1 || { echo "SELFTEST FAIL 11a: clean green run exited nonzero"; exit 1; }
		bash "$self" check . GATE-RUN.txt >/dev/null 2>&1 || { echo "SELFTEST FAIL 11b: clean-HEAD mint did not pass pre-commit"; exit 1; }
		git add GATE-RUN.txt
		git -c user.name=selftest -c user.email=selftest@local -c commit.gpgsign=false commit -qm witness
		bash "$self" check . GATE-RUN.txt >/dev/null 2>&1 || { echo "SELFTEST FAIL 11c: the witness commit (record only) did not pass"; exit 1; }

		# 12 FIRE: HEAD moves beyond the witness commit — STALE-HEAD even though
		# the content digest is unchanged (an empty commit)
		git -c user.name=selftest -c user.email=selftest@local -c commit.gpgsign=false commit -qm next --allow-empty
		bash "$self" check . GATE-RUN.txt 2>&1 | grep -q 'GATE-WITNESS STALE-HEAD' || { echo "SELFTEST FAIL 12: moved HEAD with unchanged content did not read STALE-HEAD"; exit 1; }
		git reset -q --hard HEAD~1

		# 13 the TWO-REPO witness: the record pins a sibling; the sibling moving
		# or dirtying fails check. Fixture repos live OUTSIDE this selftest
		# repo's work tree so they cannot dirty it.
		xtmp=$(mktemp -d "${TMPDIR:-/tmp}/gate-witness-xrepo.XXXXXX")
		mkdir -p "$xtmp/main2" "$xtmp/sib"
		(cd "$xtmp/sib" && git init -q . && echo s >s.txt && git add s.txt && git -c user.name=selftest -c user.email=selftest@local -c commit.gpgsign=false commit -qm sib0)
		(cd "$xtmp/main2" && git init -q . && echo m >m.txt && git add m.txt && git -c user.name=selftest -c user.email=selftest@local -c commit.gpgsign=false commit -qm main0)
		(cd "$xtmp/main2" && GATE_WITNESS_XREPO="sib=../sib" bash "$self" run GATE-RUN.txt "selftest xrepo gate" 'a=true' >/dev/null 2>&1) || { echo "SELFTEST FAIL 13a: xrepo run failed"; exit 1; }
		grep -q '^xrepo: sib head=' "$xtmp/main2/GATE-RUN.txt" || { echo "SELFTEST FAIL 13b: record carries no xrepo pin"; exit 1; }
		grep -qE '^xrepo: sib head=.* tree=sha256:[0-9a-f]{64}$' "$xtmp/main2/GATE-RUN.txt" || { echo "SELFTEST FAIL 13b2: xrepo digest is not a real sha (EMPTY-TREE regression)"; exit 1; }
		bash "$self" check "$xtmp/main2" GATE-RUN.txt >/dev/null 2>&1 || { echo "SELFTEST FAIL 13c: fresh xrepo record did not pass"; exit 1; }
		(cd "$xtmp/sib" && git -c user.name=selftest -c user.email=selftest@local -c commit.gpgsign=false commit -qm sibnext --allow-empty)
		bash "$self" check "$xtmp/main2" GATE-RUN.txt 2>&1 | grep -q 'GATE-WITNESS STALE-XREPO' || { echo "SELFTEST FAIL 13d: moved sibling did not read STALE-XREPO"; exit 1; }
		(cd "$xtmp/sib" && git reset -q --hard HEAD~1)
		echo dirt >>"$xtmp/sib/s.txt"
		bash "$self" check "$xtmp/main2" GATE-RUN.txt 2>&1 | grep -q 'GATE-WITNESS DIRTY-NOW' || { echo "SELFTEST FAIL 13e: dirty sibling did not fail"; exit 1; }
		# a mint while the SIBLING is dirty must record it and fail check
		(cd "$xtmp/main2" && GATE_WITNESS_XREPO="sib=../sib" bash "$self" run GATE-RUN.txt "selftest xrepo gate" 'a=true' >/dev/null 2>&1)
		bash "$self" check "$xtmp/main2" GATE-RUN.txt 2>&1 | grep -q 'GATE-WITNESS DIRTY-MINT' || { echo "SELFTEST FAIL 13f: sibling-dirty mint did not fail"; exit 1; }
		rm -rf "$xtmp"

		# 9 commit-tie (the CI shape): green pins HEAD; a new commit reads STALE
		git rm -q --cached GATE-RUN.txt
		echo 'GATE-RUN.txt' >.gitignore
		git add -A
		git -c user.name=selftest -c user.email=selftest@local -c commit.gpgsign=false commit -qm base
		GATE_WITNESS_TIE=commit bash "$self" run GATE-RUN.txt "selftest ci gate" 'a=true' >/dev/null 2>&1 || { echo "SELFTEST FAIL 9a: commit-tie run failed"; exit 1; }
		grep -q '^tree: commit=' GATE-RUN.txt || { echo "SELFTEST FAIL 9b: commit-tie record has no commit line"; exit 1; }
		bash "$self" check . GATE-RUN.txt >/dev/null 2>&1 || { echo "SELFTEST FAIL 9c: fresh commit-tie record did not pass"; exit 1; }
		git -c user.name=selftest -c user.email=selftest@local -c commit.gpgsign=false commit -qm next --allow-empty
		bash "$self" check . GATE-RUN.txt 2>&1 | grep -q 'GATE-WITNESS STALE:.*commit=' || { echo "SELFTEST FAIL 9d: HEAD moved but commit-tie did not read STALE"; exit 1; }

		exit 0
	) || fails=1
	if [ "$fails" -eq 0 ]; then
		echo "SELFTEST OK — 13 case(s): fire (missing, stale x3, red, incomplete x2, dirty-mint x2, stale-head, stale-xrepo, dirty-sibling) and pass (run, stepwise, witness-commit, xrepo, commit-tie) proven"
		return 0
	fi
	return 1
}

case "${1:-}" in
run)
	shift
	run_mode "$@"
	;;
init)
	shift
	init_mode "$@"
	;;
step)
	shift
	step_mode "$@"
	;;
finalize)
	shift
	finalize_mode "$@"
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
	echo "usage: gate-witness.sh run|init|step|finalize|check|--selftest|--sync-check" >&2
	exit 2
	;;
esac
