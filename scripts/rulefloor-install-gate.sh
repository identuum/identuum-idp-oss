#!/usr/bin/env bash
#
# rulefloor-install-gate.sh — every CI rulefloor install uses the ONE
# declared route.
#
# WHY THIS EXISTS
# ---------------
# THE-SECOND-INSTALL (2026-08-27): two slices "unified" the rulefloor
# install and a THIRD site survived both — the idp-oss Integration job
# kept `go install ...@v0.6.0` under a comment claiming parity with the
# verify job. Two install methods, two versions, one ledger, in one
# file. Hand sweeps missed it twice; this gate makes the class
# unaddable.
#
# THE CONTRACT (per workflow file, both repos):
#   - `go install` of rulefloor is BANNED anywhere (module-proxy
#     artifact chain, no version stamp — self-reports "dev").
#   - `brew install` of rulefloor is BANNED in workflows (tap-HEAD is
#     unpinned).
#   - Any rulefloor tarball fetch must derive its tag from
#     ${RULEFLOOR_VERSION} — a HARDCODED /archive/refs/tags/vN.N.N is a
#     violation (an independent literal is how the circular stamp
#     happened).
#   - Any `-X main.version=` ldflags stamp must derive from
#     ${RULEFLOOR_VERSION} — a literal stamp is the circular-assert
#     defect itself (URL derived, stamp hardcoded: the binary reports
#     the stale literal and the version assert still passes). This gate
#     previously NAMED that class in this header without testing for it
#     (THE-UNGATED-STAMP).
#   - A workflow that uses the derived route declares RULEFLOOR_VERSION
#     exactly ONCE (the workflow-level env). Zero declarations with a
#     use, or two declarations, both fail.
#   - Comment lines are exempt from EVERY pattern: a gate must not
#     forbid describing what it forbids.
#
# WHAT IT CANNOT SEE: installs in files outside .github/workflows of
# the two scanned repos (Makefiles and dev machines are the local
# gate's world); obfuscated invocations that never write the string
# "rulefloor" on the install line.
#
# USAGE   rulefloor-install-gate.sh [WORKFLOW_DIR ...]
#           default: ../identuum-idp-oss/.github/workflows and
#                    ../identuum-ui/.github/workflows
#         rulefloor-install-gate.sh --selftest
# EXIT    0 all installs on the declared route | 1 violation | 2 cannot evaluate

set -uo pipefail

SELF_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
WIKI_DIR="$(dirname -- "$SELF_DIR")"

check_dirs() {
	local bad=0 files=0 dir f
	for dir in "$@"; do
		[ -d "$dir" ] || { echo "CANNOT-EVALUATE: workflow dir missing: $dir"; return 2; }
		for f in "$dir"/*.yml "$dir"/*.yaml; do
			[ -f "$f" ] || continue
			files=$((files + 1))
			local rel="${f#"$WIKI_DIR/../"}"

			while IFS=: read -r ln line; do
				[ -z "$ln" ] && continue
				[[ "$line" =~ ^[[:space:]]*# ]] && continue
				echo "  VIOLATION  $rel:$ln banned go-install route: $(echo "$line" | sed 's/^[[:space:]]*//')"
				bad=$((bad + 1))
			done < <(grep -nE 'go install [^#]*rulefloor' "$f" || true)

			while IFS=: read -r ln line; do
				[ -z "$ln" ] && continue
				[[ "$line" =~ ^[[:space:]]*# ]] && continue
				echo "  VIOLATION  $rel:$ln banned brew-install route: $(echo "$line" | sed 's/^[[:space:]]*//')"
				bad=$((bad + 1))
			done < <(grep -nE 'brew install [^#]*rulefloor' "$f" || true)

			while IFS=: read -r ln line; do
				[ -z "$ln" ] && continue
				[[ "$line" =~ ^[[:space:]]*# ]] && continue
				echo "  VIOLATION  $rel:$ln hardcoded tarball tag (must derive from \${RULEFLOOR_VERSION}): $(echo "$line" | sed 's/^[[:space:]]*//')"
				bad=$((bad + 1))
			done < <(grep -nE 'rulefloor/archive/refs/tags/v[0-9]' "$f" || true)

			while IFS=: read -r ln line; do
				[ -z "$ln" ] && continue
				[[ "$line" =~ ^[[:space:]]*# ]] && continue
				case "$line" in *'-X main.version=${RULEFLOOR_VERSION}'*) continue ;; esac
				echo "  VIOLATION  $rel:$ln ldflags stamp does not derive from \${RULEFLOOR_VERSION} (the circular-assert defect): $(echo "$line" | sed 's/^[[:space:]]*//')"
				bad=$((bad + 1))
			done < <(grep -nE -- '-X main\.version=' "$f" || true)

			local uses decls
			uses="$(grep -cE 'rulefloor/archive/refs/tags/\$\{RULEFLOOR_VERSION\}' "$f")" || true
			decls="$(grep -cE '^[[:space:]]*RULEFLOOR_VERSION:' "$f")" || true
			if [ "${uses:-0}" -gt 0 ] && [ "${decls:-0}" -ne 1 ]; then
				echo "  VIOLATION  $rel declares RULEFLOOR_VERSION ${decls:-0} time(s) with ${uses} derived install(s) — exactly ONE workflow-level declaration required"
				bad=$((bad + 1))
			fi
		done
	done
	[ "$files" -gt 0 ] || { echo "CANNOT-EVALUATE: no workflow files found"; return 2; }
	echo "rulefloor-install-gate: $files workflow file(s) scanned"
	echo "rulefloor-install-gate violations: $bad"
	[ "$bad" -eq 0 ]
}

if [ "${1:-}" = "--selftest" ]; then
	fails=0
	tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
	mkdir -p "$tmp/wf"
	wf() { printf '%s\n' "$@" > "$tmp/wf/ci.yml"; }
	expect() { # LABEL WANT_RC
		local out got
		out="$(check_dirs "$tmp/wf" 2>&1)"; got=$?
		if [ "$got" -eq "$2" ]; then
			printf '  ok    %s (exit %s)\n' "$1" "$got"
		else
			printf '  FAIL  %s (want %s, got %s)\n' "$1" "$2" "$got"
			printf '%s\n' "$out" | sed 's/^/          | /'
			fails=$((fails + 1))
		fi
	}
	echo "rulefloor-install-gate selftest"
	wf 'env:' '  RULEFLOOR_VERSION: v0.7.0' 'x: curl "https://github.com/ozgurcd/rulefloor/archive/refs/tags/${RULEFLOOR_VERSION}.tar.gz"' 'y: go build -ldflags "-X main.version=${RULEFLOOR_VERSION}" -o rulefloor .'
	expect "the declared derived route (URL + stamp) PASSES" 0
	wf '    # x: go install github.com/ozgurcd/rulefloor@v0.6.0'
	expect "a commented go-install mention PASSES" 0
	wf '    # x: brew install ozgurcd/tap/rulefloor'
	expect "a commented brew-install mention PASSES" 0
	wf '    # x: curl "https://github.com/ozgurcd/rulefloor/archive/refs/tags/v0.8.0.tar.gz"'
	expect "a commented hardcoded-tag mention PASSES" 0
	wf 'x: go install github.com/ozgurcd/rulefloor@v0.6.0'
	expect "a live go-install route FIRES" 1
	wf 'env:' '  RULEFLOOR_VERSION: v0.7.0' 'x: curl "https://github.com/ozgurcd/rulefloor/archive/refs/tags/v0.8.0.tar.gz"'
	expect "a hardcoded tag FIRES" 1
	wf 'env:' '  RULEFLOOR_VERSION: v0.7.0' 'jobenv:' '  RULEFLOOR_VERSION: v0.8.0' 'x: curl "https://github.com/ozgurcd/rulefloor/archive/refs/tags/${RULEFLOOR_VERSION}.tar.gz"'
	expect "a second declaration FIRES (one per workflow)" 1
	wf 'x: brew install ozgurcd/tap/rulefloor'
	expect "the tap-HEAD route FIRES" 1
	wf 'env:' '  RULEFLOOR_VERSION: v0.7.0' 'x: curl "https://github.com/ozgurcd/rulefloor/archive/refs/tags/${RULEFLOOR_VERSION}.tar.gz"' 'y: go build -ldflags "-X main.version=v0.7.0" -o rulefloor .'
	expect "a LITERAL ldflags stamp FIRES even with the URL derived (the circular assert)" 1
	wf '    # y: go build -ldflags "-X main.version=v0.7.0" (documented example)'
	expect "a commented literal-stamp mention PASSES" 0
	if [ "$fails" -eq 0 ]; then
		echo "SELFTEST OK — 10 case(s), fire and pass both proven"
		exit 0
	fi
	echo "SELFTEST FAIL — $fails case(s)"
	exit 1
fi

if [ "$#" -gt 0 ]; then
	check_dirs "$@"
else
	check_dirs "$WIKI_DIR/../identuum-idp-oss/.github/workflows" "$WIKI_DIR/../identuum-ui/.github/workflows"
fi
exit $?
