# identuum-idp-oss — developer Makefile
# Requires: Go 1.26+, Docker with Compose plugin, staticcheck.
#
# Quick start:
#   make fast-up          # start local Postgres on 127.0.0.1:5513
#   make integration-test # run the DB-backed integration + teeth suites against the local DB
#   make fast-down        # stop and remove containers (volume preserved)
#
# Routine validation — THE LOCAL CLOSE RITUAL:
#   make verify-parallel  # both witness legs at once: measured 130s, not 229s
#
# THE-UNCOLLECTED-84 (2026-09-04): verify-parallel existed and saved a measured
# 84s of 214s, and was referenced nowhere but its own block below — so the
# saving only happened when a human remembered to type it. This line is where
# the local ritual collects it. It runs the SAME two legs, unaltered, and
# `make verify` / `make verify-integration` still work exactly as before for
# anyone who wants one leg alone (or has no database).
#
# CI IS DELIBERATELY NOT SWITCHED: .github/workflows/ci.yml keeps running
# ci-verify and ci-integration-test serially, on separate jobs, where a shared
# runner and a per-job database make concurrency neither free nor safe.
#
# Optional live integration chain:
#   make validate
#
# Port allocation:
#   5532  identuum-ag monolith Postgres (avoid)
#   5533  identuum-ag-oss Postgres      (avoid)
#   5534  reserved
#   5513  identuum-idp-oss Postgres     <-- THIS MODULE
#
# Safety:
#   DB URLs are never echoed to stdout. seed-style tools are gated by
#   the operator and are explicitly NOT inside `make verify`.

# THE RUNNER-SHELL RULE (THE-CI-SHAPE follow-up, 2026-08-07). Every recipe in
# this file runs under bash on EVERY platform, declared once. Without this,
# make hands recipes to /bin/sh — which is bash on the Mac this repo is
# developed on and DASH on the Ubuntu runner, and the difference is exactly
# the class of failure CI run #56 hit:
#
#   /bin/sh: 1: set: Illegal option -o pipefail
#   make[1]: *** [Makefile:373: doccomment-check] Error 2
#
# Fixing the RECIPE would be the wrong shape: it cures one line while every
# future recipe re-rolls the same dice, and a dialect bug only surfaces on the
# platform the author is not typing on. Both platforms ship /bin/bash;
# declaring it kills the whole axis for every present and future recipe.
SHELL := /bin/bash

## DEV_PG_HOST_PORT: the published port fast-up probes for readiness.
## A variable rather than a literal so the POSTGRES-NOT-READY branch can be
## red-proven against a port that BLOCKS, without editing the recipe.
## RESTORED 2026-08-02 (BOUND-LABEL): a block rewrite in this same slice deleted
## it, and fast-up then probed `-p ''` and waited the FULL bound on every run —
## caught only because the failure message printed "no answer on 127.0.0.1: "
## with the port missing. Reading the output is what found it; the exit code was
## the one I expected.
DEV_PG_HOST_PORT ?= 5513
## THE-SHARED-VOLUME (2026-09-04): EXPORTED, or the override is decoration.
## The compose file now publishes ${DEV_PG_HOST_PORT:-5513}, and compose reads
## it from the ENVIRONMENT — a make variable that is never exported reaches the
## readiness probe below and not the container, so a second checkout would move
## its probe and still collide on the bind. Same for the project name, whose
## default lives in the compose file; exporting an unset variable is harmless
## and lets `IDENTUUM_IDP_COMPOSE_PROJECT=x make fast-up` work.
export DEV_PG_HOST_PORT
export IDENTUUM_IDP_COMPOSE_PROJECT
## THE BOUNDS fast-up WAITS UNDER. All overridable so every failure branch can be
## red-proven cheaply instead of by waiting out the real values.
##
## PG_READY_TIMEOUT IS SECONDS OF WALL CLOCK, NOT ATTEMPTS (BOUND-LABEL,
## 2026-08-02). It used to count loop turns, each of which was a 2s-capped probe
## PLUS a 1s sleep — so the real ceiling was ~3x the number printed, and the
## recipe announced "within 3s" after 8 SECONDS. Worse, the red proof that
## "confirmed" the label used a CLOSED port, where pg_isready refuses instantly
## and elapsed happens to equal the label: THE ONE CONDITION UNDER WHICH THE
## LABEL CANNOT BE FALSIFIED. It is now a deadline computed once from `date +%s`,
## checked before each probe AND before each sleep, with the per-probe -t clamped
## to the time actually remaining, so the printed number is the ceiling.
## THE FAILURE MESSAGE PRINTS THE BOUND AND THE MEASURED WAIT SIDE BY SIDE, so
## the claim is checkable from the output instead of on trust. A label nobody
## can falsify from what it prints is how the last one survived.
ENGINE_PROBE_TIMEOUT ?= 15
COMPOSE_UP_TIMEOUT ?= 180
EVIDENCE_TIMEOUT ?= 15
PG_READY_TIMEOUT ?= 90
COMPOSE_FILE  ?= deployment/docker-compose.dev.yml
COMPOSE_CMD   ?= docker compose
DEV_APP_SERVICE ?= app
DEV_POSTGRES_SERVICE ?= postgres-idp-oss
## The dev compose names its project and app container
## ${IDENTUUM_IDP_COMPOSE_PROJECT:-identuum-idp-oss-dev} (D-024); this default
## read `identuum-idp-oss`, the owner's own app container, until
## TOOLS-MATRIX-CONTAINERS (2026-10-05), so dev-recreate-app's `docker rm -f`
## aimed at it.
DEV_COMPOSE_PROJECT = $(or $(IDENTUUM_IDP_COMPOSE_PROJECT),identuum-idp-oss-dev)
DEV_APP_CONTAINER ?= $(DEV_COMPOSE_PROJECT)
## PROTECTED (owner, TOOLS-MATRIX-CONTAINERS 2026-10-05): the owner's own
## containers and their compose project; no target or proof stops, removes,
## recreates or renames them (agent-rules.md §H-bis).
PROTECTED_CONTAINERS := identuum-idp-oss-postgres identuum-idp-oss
## The app's host port, container port, listen address and issuer in
## deployment/docker-compose.dev.yml (${DEV_APP_PORT:-7113}). EXPORTED like
## DEV_PG_HOST_PORT, so `DEV_APP_PORT=17113 make oss-up dev-smoke` moves the
## container and the probes together (owner ruling t, 2026-10-07: the e2e-full
## harness runs on 17113 beside a dev stack on 7113). dev-ports-selftest pins it.
DEV_APP_PORT ?= 7113
export DEV_APP_PORT
DEV_HEALTH_URL ?= http://127.0.0.1:$(DEV_APP_PORT)/health
DEV_COMPONENT_URL ?= http://127.0.0.1:$(DEV_APP_PORT)/api/v1/component
DEV_SYSTEM_INFO_URL ?= http://127.0.0.1:$(DEV_APP_PORT)/system/info

# DB URL for the DEV STACK / app — the human's live database. NOT used by the
# integration suites (TEST-DB-ISOLATION-1): those TRUNCATE and replay setup, so
# they must never point here. Override by exporting it before calling make.
OSS_DB_URL ?= postgres://idp_oss_user:dev-idp_oss_user-not-a-secret@127.0.0.1:5513/identuum_idp_oss?sslmode=disable

# DB URL for the INTEGRATION SUITES — a dedicated *_test database, separate from
# the dev DB (TEST-DB-ISOLATION-1). The harness refuses any DSN that is not a
# *_test database on 127.0.0.1:$(DEV_PG_HOST_PORT) (internal/testsupport.
# RequireTestDatabase, the policy of test-db-endpoint below; no environment
# escape since OSS-MINT-GUARD-3). Create it once with `make test-db`.
# Its port IS DEV_PG_HOST_PORT (OSS-MINT-ISOLATION, 2026-10-10), so a
# port-only override moves create, migrate, suites and rule teeth together;
# test-db-endpoint refuses an explicit URL on any other server.
OSS_TEST_DB_URL ?= postgres://idp_oss_user:dev-idp_oss_user-not-a-secret@127.0.0.1:$(DEV_PG_HOST_PORT)/identuum_idp_oss_test?sslmode=disable

# WIKI_TOOLS — the shared gate scripts live in the sibling wiki repo.
WIKI_TOOLS ?= $(CURDIR)/../wiki/tools

.PHONY: verify-integration clock-fuse-gate repo-green fast-up fast-down fast-clean build build-binary test staticcheck integration-test validate clean api-docgen api-docgen-dry-run api-docs oss-up oss-down oss-logs oss-build oss-bootstrap oss-recover-site-admin image-base-parity fmt-check vet vet-integration integration-staticcheck doccomment-check integration-inventory tagged-vet clock-fuse-report tool-versions
.PHONY: dev-up dev-rebuild dev-recreate-app dev-ps dev-logs dev-app-logs dev-pg-logs dev-down dev-smoke dev-health
.PHONY: ui-vendor ui-vendor-check
.PHONY: verify ci-verify tracked-binary-check credential-transparency workflow-yaml workflow-yaml-parity image-base-check api-surface clock-fuse grype-scan verify-oss-contract verify-no-panic verify-oss wiki-fresh rulefloor-check rulefloor-integration ci-integration-test test-db

## wiki-fresh: WIKI-1 gate — fail when this repo's wiki page is BEHIND. NOT in
## the verify plan since OSS-GATE-TIDY (2026-10-05, owner ruling P-066): the
## wiki stage's `make check` judges freshness at the close; this target is a
## manual look. The paragraphs below describe it as it ran inside verify.
## Runs `achta --wiki-dir $(WIKI_DIR) wiki check --only freshness` and uses
## achta's OWN exit code (THE-PYTHONLESS-GATE, 2026-09-05; the python3 parse
## of achta's JSON that stood here since THE-FRESHNESS-HANDOVER is gone —
## achta v0.4.1 shipped the freshness-only enforcing mode this comment used
## to ask for). Exit 0 = every pin fresh; 1 = drift (behind/unpinned);
## 2 = cannot evaluate (an unreadable page, a refused directory).
##
## THIS GATE NEEDS achta >= v0.4.1, AND SAYS SO BY NAME. achta is installed
## from a Homebrew cask and pinned nowhere — not in the seven ci.yml pins that
## toolchain-parity checks, because CI never runs achta at all: a fresh clone
## has no ../wiki and takes the SKIPPED branch below. A CI pin would assert a
## tool CI never exercises, and parity compares declared version strings, not
## what the binary accepts — a matching string is not proof the flag exists
## (the same reason the binary was proved by running the flag, not by reading
## `achta version`). So the refusal lives here, where the dependency is: an
## older achta answers `--only` with "flag provided but not defined: -only"
## (measured on v0.4.0) and exit 2; this recipe catches exactly that answer
## and names the requirement and the installed version instead of dying on a
## flag-parser message. A missing achta is named the same way. Neither branch
## can pass: both exit 2, and 2 is fatal to verify.
##
## THE WIKI IS NAMED, NOT DISCOVERED (THE-NAMED-WIKI, 2026-09-05). achta
## v0.4.0 has repo-owned wikis, and --wiki-dir selects one fail-closed: a
## directory that is not the direct wiki child of its workspace root is
## REFUSED (exit 2), and --wiki-dir with --workspace is refused too. Measured
## before this change, discovery from both this directory and the wiki's
## resolved to the same ten parent-wiki pages — so this is hardening, not a
## fix — but achta's JSON never names the directory it resolved, so a gate
## that checked the wrong wiki and PASSED would have been indistinguishable
## from this one. Naming it removes that possibility. The cd is gone with it:
## --wiki-dir accepts the relative $(WIKI_DIR) from this directory.
##
## WHY --only freshness AND NOT THE PLAIN COMMAND, measured the hard way.
## `achta wiki freshness` REPORTS drift and exits 0 — wiring it would have
## turned this hard gate into a report. Plain `achta wiki check` does fail,
## but it bundles freshness with derived blocks, and the derived block records
## `Working tree vs HEAD: clean` while `make verify` DIRTIES this tree writing
## GATE-RUN.txt, so its derive half fails for the whole duration of every
## verify — an earlier attempt wired it that way and broke verify outright.
## `--only freshness` evaluates and reports the freshness check alone under
## achta's unchanged exit contract; that is the whole reason the flag exists.
##
## PROVED FAILING, not only passing: an UNREADABLE wiki page makes this print
## "wiki check freshness: cannot_evaluate" and exit 2 — the case the deleted
## script counted and still exited 0 on. And it PASSES on a DIRTY tree with
## fresh pins, which is what verify needs and what the plain command cannot do.
##
## BE HONEST ABOUT WHAT THIS ENFORCES: at verify time HEAD is
## the LAST commit, so a green gate means "the PREVIOUS slice's wiki update was
## banked before new work is verified" — zero commits of allowed drift. It does
## NOT and cannot check the commit you are about to make; the §F-bis append for
## THIS slice is still on you, and the gate will catch its absence on the NEXT
## slice's verify. A missing wiki dir (fresh clone / CI / a Legattus
## materialized tree) prints one loud SKIPPED line and continues — visible,
## never silent — and a `wiki freshness: NOT JUDGED` line, which the recorder
## captures as evidence, so a record reads "not judged" there and never a bare
## exit=0 that looks like a judged green (owner ruling, OSS-TIDY-3,
## 2026-10-02). The old typo guard ("--repo
## matches no page exits 2") is gone with the --repo flag; what replaces it is
## --wiki-dir's own refusal of any directory that is not a workspace's direct
## wiki child, so a mistyped WIKI_DIR fails here rather than checking nothing.
WIKI_DIR ?= ../wiki

wiki-fresh:
	@if [ ! -d "$(WIKI_DIR)" ]; then \
		echo "WIKI FRESHNESS SKIPPED: no wiki at $(WIKI_DIR)"; \
		echo "wiki freshness: NOT JUDGED — no wiki at $(WIKI_DIR); exit 0 here is not a freshness verdict"; \
	else \
		command -v achta >/dev/null 2>&1 || { echo "wiki-fresh: achta is not installed — this gate needs achta >= v0.4.1 (wiki check --only freshness)" >&2; exit 2; }; \
		out=$$(achta --wiki-dir "$(WIKI_DIR)" wiki check --only freshness 2>&1); rc=$$?; \
		printf '%s\n' "$$out"; \
		case "$$out" in *"flag provided but not defined: -only"*) echo "wiki-fresh: achta >= v0.4.1 required (wiki check --only freshness); installed: $$(achta version)" >&2; exit 2;; esac; \
		exit $$rc; \
	fi

## rulefloor-check: RULE-FLOOR.md ledger gate — the sibling rulefloor CLI
## verifies every armed rule (tag present and unique, no .skip/.only/t.Skip,
## body hash pinned, Go rows re-run standalone, row count >= FLOOR, no orphan
## tags). Sibling-coupled like wiki-fresh, so it is NOT in ci-verify (one-repo
## rule) — enumerated in the ci.yml header. UNLIKE wiki-fresh there is NO skip
## branch: a missing sibling checkout or a failed build of the tool is
## CANNOT-EVALUATE, and CANNOT-EVALUATE is FATAL — a gate that could not
## measure must never be mistaken for one that measured and approved.
## No flag here may lower the tool's strictness.
RULEFLOOR_DIR ?= ../rulefloor

# Resolve the rulefloor binary for the ledger gates: $RULEFLOOR_BIN if
# set (explicit operator choice — an unsuitable one is FATAL), else
# `rulefloor` on PATH, else build-and-run the sibling checkout as LAST
# resort. Suitability is probed through the machine interface
# `version --json` (rulefloor.version.v1, v0.3.0+): older binaries have
# no machine interfaces and are refused — this floor rose from v0.2.0
# to v0.3.0 the day the probe moved off human-readable `--version`
# output (THE-TOOLING-UPGRADE). A PATH binary that fails the probe
# FALLS THROUGH to the sibling instead of failing outright, so a stale
# brew binary cannot mask a good sibling checkout; a sibling binary
# that fails the probe is rebuilt once. "dev" builds (sibling or
# go-install) pass by answering the probe. Resolution failure is
# CANNOT-EVALUATE (exit 2), never a skip. Sets $$RF for the invocation
# that follows.
define RULEFLOOR_RESOLVE
	RF=""; \
	if [ -n "$$RULEFLOOR_BIN" ]; then RF="$$RULEFLOOR_BIN"; \
	else \
		if command -v rulefloor >/dev/null 2>&1; then \
			CAND="$$(command -v rulefloor)"; \
			CV="$$("$$CAND" version --json 2>/dev/null | sed -n 's/.*"version":"\([^"]*\)".*/\1/p')"; \
			case "$$CV" in \
				dev) RF="$$CAND" ;; \
				v*) if [ "$$(printf 'v0.3.0\n%s\n' "$$CV" | sort -V | head -1)" = "v0.3.0" ]; then RF="$$CAND"; \
					else echo "$@: rulefloor $$CV on PATH predates v0.3.0 machine interfaces; trying the sibling"; fi ;; \
				*) echo "$@: rulefloor on PATH does not answer 'version --json'; trying the sibling" ;; \
			esac; \
		fi; \
		if [ -z "$$RF" ]; then \
			if [ ! -d "$(RULEFLOOR_DIR)" ]; then \
				echo "$@: CANNOT-EVALUATE — no rulefloor v0.3.0+ (set RULEFLOOR_BIN, 'brew install ozgurcd/tap/rulefloor' or 'brew upgrade rulefloor', or clone $(RULEFLOOR_DIR))" >&2; \
				exit 2; \
			fi; \
			if [ -x "$(RULEFLOOR_DIR)/rulefloor" ] && "$(RULEFLOOR_DIR)/rulefloor" version --json >/dev/null 2>&1; then :; else \
				echo "$@: building $(RULEFLOOR_DIR)/rulefloor (sibling fallback)"; \
				(cd "$(RULEFLOOR_DIR)" && go build -o rulefloor .) || { \
					echo "$@: CANNOT-EVALUATE — go build of the rulefloor tool failed" >&2; \
					exit 2; \
				}; \
			fi; \
			RF="$(RULEFLOOR_DIR)/rulefloor"; \
		fi; \
	fi; \
	RFV="$$("$$RF" version --json 2>/dev/null | sed -n 's/.*"version":"\([^"]*\)".*/\1/p')"; \
	case "$$RFV" in \
		dev) ;; \
		v*) if [ "$$(printf 'v0.3.0\n%s\n' "$$RFV" | sort -V | head -1)" != "v0.3.0" ]; then \
			echo "$@: CANNOT-EVALUATE — rulefloor $$RFV predates v0.3.0 machine interfaces (rulefloor.version.v1); upgrade it" >&2; \
			exit 2; \
		fi ;; \
		*) echo "$@: CANNOT-EVALUATE — $$RF does not answer 'version --json' (needs rulefloor v0.3.0+)" >&2; exit 2 ;; \
	esac; \
	echo "$@: rulefloor $$RFV at $$RF"
endef

rulefloor-check:
	@$(RULEFLOOR_RESOLVE); \
	"$$RF" check --repo .

## ledger-diff-gate (THE-LEDGER-DIFF-GATE, 2026-09-02): a ledger sentence
## never changes silently again. Runs `rulefloor ledger-diff --base <previous
## accepted witness> --json` (rulefloor.ledger-diff.v1; the base is measured
## from git: the newest `Witness: make verify green at` commit before HEAD)
## and reconciles it BOTH ways against the committed, single-use, SHA-scoped
## manifest ledger-amendments.json (ledger-amendments.v1): an undeclared
## change, a declaration the diff does not show, a sentence digest mismatch,
## a wrong base_commit, rulefloor exit 2 / cannot_evaluate / bad JSON /
## truncated — every one FAILS. The pass line carries the base SHA and the
## sha256 of the ledger-diff document into GATE-RUN.txt (EVIDENCE_RE
## `^check OK:`). Sits right after rulefloor-check: same cheapness, same
## reason to fail the aggregate early. Rule LEDGER-DIFF-RECONCILED-1.
ledger-diff-gate:
	@$(RULEFLOOR_RESOLVE); \
	go run ./tools/ledger-diff-gate --manifest ledger-amendments.json --repo . --rulefloor "$$RF"

## ledger-rebase (THE-MANIFEST-CADENCE, 2026-09-03): write base_commit from
## the measured previous accepted witness. NOT A GATE and deliberately NOT in
## the verify plan — verify judges this manifest, so a verify that rewrote it
## first would be checking its own homework.
##
## base_commit had to equal a value the gate already computes for itself
## (previousAcceptedWitness: the newest `Witness: make verify green at`
## commit strictly before HEAD). Hand-copying it cost four reds across two
## slices. Now the same binary writes it through the same function, so there
## is no second implementation to drift — and the value is still RE-MEASURED
## and CHECKED at verify time, which is what keeps deriving from becoming
## asserting: if a witness lands between the re-base and the verify, the gate
## refuses the manifest it just helped write.
##
## Run it when the manifest goes stale — which is exactly the first commit
## after any witness. Reasons for a moved rule stay hand-written; this writes
## ONLY base_commit. Rule LEDGER-REBASE-DERIVES-BASE-1.
ledger-rebase:
	@go run ./tools/ledger-diff-gate --rebase --manifest ledger-amendments.json --repo .

## repo-green: the commit floor — build + vet + test, as ONE named check.
##
## WIRED HERE ON PURPOSE (THE-GATE-THAT-CANNOT-RUN, 2026-08-04, owner ruling).
## The gate was first written as a Claude Code PreToolUse hook, which meant it
## did nothing until a human edited ~/.claude/settings.json by hand. A gate that
## depends on that is the decoration this workspace already refuses ("a
## decoration in a gate list is worse than an absence: it reads like coverage").
## So it is invoked by the gates people already run instead.
##
## IT DELIBERATELY OVERLAPS the build / vet / test steps in those aggregates.
## That is the cost of the floor existing where it is actually run, and it is
## paid knowingly: on a green tree the work happens twice. It runs FIRST, so a
## broken tree fails fast and the wasted repeat never happens.
##
## THREE OUTCOMES, and the third is why this is not just `go build && go test`:
##   0 GREEN   1 NOT-GREEN   2 CANNOT-EVALUATE (no toolchain / not a module)
## CANNOT-EVALUATE is FATAL here too — a gate that could not measure must never
## be mistaken for one that measured and approved.
##
## THE-GREEN-CONSUMERS (2026-09-21): the floor is `lictor green --repo
## $(CURDIR)` (gofmt, build, vet, test; stop at first red; GREEN-FLOOR-1), the
## installed, pinned port of wiki/tools/repo-green-gate.sh, which this recipe
## ran as `bash "$(WIKI_TOOLS)/repo-green-gate.sh" --check .` until then. No
## sibling checkout is consulted any more (`make repo-green
## WIKI_TOOLS=/nonexistent` is green); the lictor pin is asserted first, the
## way grype-scan asserts it. The evidence line is the judge's own
## (`GREEN: builds, vets and tests clean — subject <repo>; go version …`);
## the record keeps only `target: repo-green exit=N` for it, as before.
## STILL LOCAL-ONLY, BY CHOICE: it is not in ci-verify because its four
## floors run there as explicit steps already — not because it cannot run.
repo-green:
	@$(call LICTOR_ASSERT,repo-green); \
	"$(LICTOR)" green --repo "$(CURDIR)"

## ui-vendor (PLAN-E-1, vendored custody): refresh the identuum-ui static
## export the binary embeds (internal/uiexport/dist) and its manifest
## (internal/uiexport/manifest.json), from ONE pinned ui commit:
##   make ui-vendor UI_DIR=<ui checkout> UI_SHA=<commit>
## It refuses a ui checkout that is not AT that commit, or that is dirty (a
## tracked or untracked change), because the vendored bytes must be the
## commit's and nothing else. It builds in a clean clone of the commit under
## a gitignored ./.ui-vendor.* directory in this repo — a git checkout, as
## identuum-ui's publish-ui-export workflow builds in, because Tailwind's
## source detection honours .gitignore only inside a repository (a
## `git archive` copy scans node_modules and emits a different stylesheet;
## measured PLAN-F-1) — installs from the committed lockfile OFFLINE (the
## local pnpm store; no network at build time) and writes the files and a
## manifest carrying the ui commit, the lockfile's sha256, the node and pnpm
## versions, every file's sha256 and the tree digest (pkg/uiserve), the same
## digest the workflow's artifact carries. The clone is removed after.
UI_VENDOR_DIR := internal/uiexport
ui-vendor:
	@test -n "$(UI_DIR)" && test -n "$(UI_SHA)" || { echo "usage: make ui-vendor UI_DIR=<ui checkout> UI_SHA=<commit>"; exit 2; }
	@set -e; \
	full=$$(git -C "$(UI_DIR)" rev-parse --verify --quiet "$(UI_SHA)^{commit}") || { echo "ui-vendor: REFUSING — $(UI_SHA) is not a commit in $(UI_DIR)"; exit 1; }; \
	head=$$(git -C "$(UI_DIR)" rev-parse HEAD); \
	[ "$$head" = "$$full" ] || { echo "ui-vendor: REFUSING — $(UI_DIR) is at $$head, not $$full"; exit 1; }; \
	dirty=$$(git -C "$(UI_DIR)" status --porcelain --untracked-files=normal); \
	[ -z "$$dirty" ] || { echo "ui-vendor: REFUSING — $(UI_DIR) is dirty:"; echo "$$dirty"; exit 1; }; \
	tmp=$$(mktemp -d "$(CURDIR)/.ui-vendor.XXXXXX"); trap 'rm -rf "$$tmp"' EXIT; \
	git clone -q --no-checkout "$(UI_DIR)" "$$tmp"; git -C "$$tmp" checkout -q --detach "$$full"; \
	( cd "$$tmp" && pnpm install --frozen-lockfile --offline >"$$tmp.install.log" 2>&1 && pnpm build:export >"$$tmp.build.log" 2>&1 ) || { echo "ui-vendor: the export build failed:"; tail -20 "$$tmp.install.log" "$$tmp.build.log" 2>/dev/null; rm -f "$$tmp.install.log" "$$tmp.build.log"; exit 1; }; \
	rm -f "$$tmp.install.log" "$$tmp.build.log"; \
	rm -rf $(UI_VENDOR_DIR)/dist; mkdir -p $(UI_VENDOR_DIR)/dist; cp -R "$$tmp/out/." $(UI_VENDOR_DIR)/dist/; \
	go run ./tools/uivendor -dir $(UI_VENDOR_DIR)/dist -ui-commit "$$full" -lockfile "$$tmp/pnpm-lock.yaml" \
		-node "$$(cd "$$tmp" && node --version)" -pnpm "$$(cd "$$tmp" && pnpm --version)" > $(UI_VENDOR_DIR)/manifest.json; \
	echo "ui-vendor: vendored $$full — tree digest $$(sed -n 's/.*"tree_digest": "\([0-9a-f]*\)".*/\1/p' $(UI_VENDOR_DIR)/manifest.json)"

## ui-vendor-check: the vendored export the binary embeds is exactly the one
## its manifest records — every file's sha256 and the tree digest recomputed
## from the embedded bytes (internal/uiexport TestVendoredTreeMatchesManifest,
## pkg/uiserve.Check). In make verify.
ui-vendor-check:
	@go test ./internal/uiexport -run '^TestVendoredTreeMatchesManifest$$' -count=1
	@echo "check OK: ui-vendor-check the embedded export matches its manifest ($$(sed -n 's/.*"tree_digest": "\([0-9a-f]*\)".*/\1/p' $(UI_VENDOR_DIR)/manifest.json))"

## notices-check (OSS-NOTICES-TIDY): THIRD_PARTY_NOTICES records the inputs it
## was generated from — a digest of ./cmd/identuum-idp's build list and the
## vendored identuum-ui commit — and this refuses a tree where either moved
## without the file being regenerated (`make notices`). It then regenerates the
## Go licence texts from the module cache and refuses a file whose Go blocks
## differ (OSS-MINT-GUARD-2, review OSS-FIXES-3 F3: a compiled package's
## licence file can change inside a listed module without moving the digest).
## The COMPLETE file is judged (OSS-MINT-GUARD-3, review OSS-MINT-GUARD-2 G3):
## the header is regenerated and compared too, and the npm blocks must hash to
## the npm-body digest `make notices` recorded in the header when it
## regenerated them (regenerating them here would need an identuum-ui checkout
## at the vendored commit and a pnpm store). It needs only go list, the module
## cache and the manifest, so it runs in verify and in ci-verify.
.PHONY: notices notices-check
notices-check:
	@go run ./tools/notices -check

## notices: regenerate THIRD_PARTY_NOTICES (the module cache, pnpm, and an
## identuum-ui checkout at the vendored commit: UI_DIR, default ../identuum-ui).
notices:
	@go run ./tools/notices -write -ui "$(or $(UI_DIR),../identuum-ui)"

## tracked-binary-check: no compiled binary and no oversized blob may be
## TRACKED (THE-STRAY-BINARY, 2026-08-07). A 3.8 MB Mach-O named `notrun` —
## a stray `go build ./tools/notrun` artifact swept up by a broad `git add`
## in a6840be — rode every clone and the v0.3.0 source tag before anything
## noticed, and the thing that finally noticed was a local rebuild
## OVERWRITING it. Refused here: any tracked file whose first four bytes are
## ELF or Mach-O magic (either endianness, plus the universal-binary
## cafebabe), or whose size exceeds 1 MiB.
##
## NO ALLOWLIST, deliberately: if a legitimate oversized file ever lands,
## this prints it and FAILS for an owner ruling, rather than allowlisting it
## silently — an allowlist added in the same commit as the file it excuses is
## how gates go quiet. One-repo self-contained (the CI-shape rule): git
## ls-files + head + od, nothing outside the checkout.
tracked-binary-check:
	@bad=0; \
	while IFS= read -r -d '' f; do \
		[ -f "$$f" ] || continue; \
		magic=$$(head -c4 "$$f" 2>/dev/null | od -An -tx1 | tr -d ' \n'); \
		case "$$magic" in \
			7f454c46) echo "TRACKED BINARY (ELF): $$f"; bad=1;; \
			feedface|feedfacf|cffaedfe|cefaedfe) echo "TRACKED BINARY (Mach-O): $$f"; bad=1;; \
			cafebabe) echo "TRACKED BINARY (universal/cafebabe): $$f"; bad=1;; \
		esac; \
		size=$$(wc -c < "$$f" | tr -d ' '); \
		if [ "$$size" -gt 1048576 ]; then \
			echo "TRACKED FILE OVER 1 MiB: $$f ($$size bytes)"; bad=1; \
		fi; \
	done < <(git ls-files -z); \
	if [ "$$bad" -ne 0 ]; then \
		echo "A compiled binary or oversized blob is TRACKED. If it is a stray build,"; \
		echo "git rm it (and give it a /name .gitignore line). If it is legitimate,"; \
		echo "this gate has NO allowlist on purpose — take it to the owner for a"; \
		echo "ruling instead of teaching the gate to look away."; \
		exit 1; \
	fi; \
	echo "tracked-binary-check: no tracked ELF/Mach-O and nothing over 1 MiB"

## credential-transparency: every committed credential must be UNMISTAKABLY
## fake (THE-TRANSPARENT-CREDENTIALS, 2026-08-07). The audit found committed
## dev/CI DB passwords whose shape said nothing about whether they were real;
## a password that MIGHT be real forces every reader to treat it as real.
## Two rules, NO allowlist:
##   1. every tracked postgres://<user>:<pass>@ password is dev-<user>-not-a-secret
##      — self-describing AND tied to the username beside it;
##   2. ci.yml's data-encryption constant is the sequential byte string
##      00 01 02 … 1f, a value nobody would ever deploy.
##   3. the integration-test signing-key-encryption default (this Makefile) is
##      the declared repeated-cafebabe fake — gate-owned since THE-V030-CLOSEOUT.
## Anything else prints and FAILS for an owner ruling — an allowlist added in
## the same commit as the value it excuses is how gates go quiet. One-repo
## self-contained (the CI-shape rule).
credential-transparency:
	@bad=0; \
	while IFS=: read -r f ln m; do \
		user=$$(printf '%s' "$$m" | sed -E 's|postgres://([A-Za-z_][A-Za-z0-9_]*):.*|\1|'); \
		pass=$$(printf '%s' "$$m" | sed -E 's|postgres://[A-Za-z_][A-Za-z0-9_]*:(.*)@$$|\1|'); \
		if [ "$$pass" != "dev-$$user-not-a-secret" ]; then \
			echo "OPAQUE CREDENTIAL: $$f:$$ln — postgres user '$$user' has a password that is not dev-$$user-not-a-secret (value not printed)"; \
			bad=1; \
		fi; \
	done < <(git grep -noE "postgres://[A-Za-z_][A-Za-z0-9_]*:[^@\"'[:space:]]+@" -- .); \
	seq_key=$$(printf '%02x' $$(seq 0 31) | tr -d ' '); \
	key_line=$$(grep -E "^  IDENTUUM_IDP_DATA_ENCRYPTION_KEY:" .github/workflows/ci.yml || true); \
	case "$$key_line" in \
		*"$$seq_key"*) : ;; \
		*) echo "CI DATA-ENCRYPTION KEY is not the sequential fake-by-construction constant (ci.yml env block)"; bad=1;; \
	esac; \
	fake_sign=$$(printf 'cafebabe%.0s' 1 2 3 4 5 6 7 8); \
	if ! grep -qF "IDENTUUM_IDP_ENCRYPTION_KEY:-$$fake_sign" Makefile; then \
		echo "INTEGRATION-TEST SIGNING-KEY-ENCRYPTION DEFAULT is not the declared fake constant (Makefile integration-test env)"; bad=1; \
	fi; \
	if [ "$$bad" -ne 0 ]; then \
		echo "A committed credential does not declare itself fake. Placeholders are"; \
		echo "dev-<user>-not-a-secret, the sequential data key, and the repeated-"; \
		echo "cafebabe test signing default — anything else goes to the OWNER for a"; \
		echo "ruling; this gate has NO allowlist on purpose."; \
		exit 1; \
	fi; \
	echo "credential-transparency: every committed credential is fake by construction"

## workflow-yaml: every .github/workflows/*.yml must PARSE as YAML, or the
## workflow GitHub would run never starts and every gate it declares is a
## claim. Ported BYTE-IDENTICAL from identuum-ui (THE-UI-YAML-LINE-111) by
## THE-IDP-OSS-WORKFLOW-YAML (2026-09-06): identuum-ui's ci.yml was invalid
## YAML for a day — a colon-space inside a plain scalar — behind a green
## 16-target verify and a green two-repo mint; nothing parsed the workflows,
## the byte-scanning route gate passed it, GitHub would have refused it.
## This repo had the same blind spot across 28 targets, both its workflows
## happening to parse.
##
## THE PARSER, and why: yq (mikefarah, Go yaml.v3 — the same yaml.v3 family
## as go.mod's gopkg.in/yaml.v3 and the workspace's achta). A Go parser
## in-repo would mean a new tool under tools/, which this port may not add;
## the installed yq gives the same parser family with no new script, and
## measured on the ui defect it refuses exactly what GitHub refuses. The file
## is read whole (`yq eval '.'`), the scanner's own error is printed
## verbatim, an absent yq is exit 2 by name, no workflow files is exit 2.
## Sits after credential-transparency in verify AND in ci-verify
## (THE-CI-PARSES-ITS-OWN-WORKFLOWS, 2026-09-06): ci.yml installs yq from a
## sha256-pinned release binary at the workflow-env YQ_VERSION, and
## toolchain-parity holds that pin equal to the yq installed here — so CI
## refuses what local refuses. Before that step the parse ran only on
## developer machines, and a workflow could reach GitHub parsed by nothing
## but GitHub. What CI cannot do is save ci.yml from itself: a ci.yml
## GitHub cannot parse never starts the job; the local run is the one that
## catches THIS file, CI catches every other workflow.
##
## THE RECIPE BELOW IS ONE OF TWO IDENTICAL COPIES (identuum-idp-oss,
## identuum-ui), held byte-identical by `workflow-yaml-parity` below against
## WORKFLOW_YAML_MD5 — the image-base-check discipline. Edit one copy, read
## the new digest out of the parity failure, update the pin and the block in
## every copy. Comments above the target are outside the hashed block.
workflow-yaml:
	@command -v yq >/dev/null 2>&1 || { echo "workflow-yaml: yq is not installed — cannot parse .github/workflows/*.yml; refusing to pass silently" >&2; exit 2; }; \
	bad=0; n=0; \
	for f in .github/workflows/*.yml .github/workflows/*.yaml; do \
		[ -f "$$f" ] || continue; n=$$((n+1)); \
		if out=$$(yq eval '.' "$$f" 2>&1 >/dev/null); then \
			echo "  parses   $$f"; \
		else \
			echo "  INVALID  $$f"; printf '%s\n' "$$out" | sed 's/^/           /'; bad=1; \
		fi; \
	done; \
	[ "$$n" -gt 0 ] || { echo "workflow-yaml: no workflow files under .github/workflows — nothing to parse" >&2; exit 2; }; \
	if [ "$$bad" -ne 0 ]; then \
		echo "check FAILED: workflow-yaml — a workflow GitHub cannot parse never runs; fix the file, never the gate"; \
		exit 1; \
	fi; \
	echo "check OK: workflow-yaml $$n workflow file(s) parse (yq $$(yq --version 2>/dev/null | grep -oE 'v[0-9.]+' | head -1))"

## workflow-yaml-parity: this repo's workflow-yaml block must equal the copy
## shared with identuum-ui, byte for byte (the image-base-parity discipline:
## a copy that drifts to a laxer parser accepts what GitHub rejects, which is
## worse than no gate). The block is the target line through the `check OK`
## line, hashed as extracted; WORKFLOW_YAML_MD5 is the pin every copy carries.
## The ui side's parity target is a follow-up there (read-only to the port).
WORKFLOW_YAML_MD5 ?= d63f3fdb5cd211c38abe98a03ecb1544

workflow-yaml-parity:
	@blk="$$(awk '/^workflow-yaml:/{f=1} f{print} f&&/check OK: workflow-yaml/{exit}' Makefile)"; \
	got="$$(printf '%s\n' "$$blk" | { md5sum 2>/dev/null || md5; } | awk '{print $$1}')"; \
	if [ "$$got" != "$(WORKFLOW_YAML_MD5)" ]; then \
		echo "WORKFLOW-YAML COPY HAS DIVERGED:"; \
		echo "  wanted md5 $(WORKFLOW_YAML_MD5)"; \
		echo "  got    md5 $$got"; \
		echo "This repo's workflow-yaml no longer matches the copy shared with identuum-ui."; \
		echo "Either restore this copy, or update the block AND WORKFLOW_YAML_MD5 in every copy."; \
		exit 1; \
	fi; \
	echo "check OK: workflow-yaml-parity block md5 $$got matches the shared pin"

## verify: repo-local default validation; no Docker, DB, live services, or secrets.
# WHY wiki-freshness RUNS LAST (slice THE-SEALED-GATES, 2026-08-04)
# --------------------------------------------------------------------
# It used to run FIRST, and that ordering hid a real defect for a whole
# slice: identuum-idp-oss commit 032737c landed while internal/handlers
# and internal/api did not compile. `make verify` never reached `vet`,
# because it stopped at wiki-fresh — the repo's own wiki page was stale
# for the entirely expected reason that the slice had just added commits
# to the repo. So the aggregate that exists to catch a broken build
# reported failure for a DOCUMENTATION reason and never looked at the
# code, and only `make ci-verify` (which has no wiki gate) exposed it.
#
# Freshness is a staleness signal about prose. A compile break is a
# correctness fact about code. When both are red, the correctness fact
# must be the one that gets reported, so the gates now run in that order:
# every build/vet/test/lint gate first, wiki-fresh LAST. wiki-fresh is
# still fatal — nothing here is downgraded to a warning — it simply no
# longer masks what it is not about.
# OSS-GATE-TIDY (2026-10-05, owner ruling P-066): wiki-fresh LEFT this plan.
# Its subject is the pin in ../wiki, which an OSS-only slice cannot move, so
# an OSS slice could not reach green past its first commit (queue :5). The
# wiki stage's own `make check` judges freshness at the close and its witness;
# the target stays for a manual look. grype-scan is now the last entry.
# The two paragraphs above and below are history from when it was planned.
# THE-GATE-THAT-STOPS-TOO-EARLY (2026-09-14): freshness is the LAST
# plan entry, after grype-scan, with nothing below it. It remains fatal.
# A red target no longer stops this local run: verify-all drives every
# independent target through the shared recorder's init/step/finalize API,
# preserving each exit code and a RED final verdict if any target fails.
# Failed prerequisites are explicit NOT-RUN results (exit=125), with their
# reason in the record. Boundaries requires this run's gograph-build, so a
# failed rebuild cannot let it judge a stale graph. The plan and that edge
# live here; the shared, byte-pinned recorder is not forked or weakened.
# This recipe is the canonical repo-local close gate. docs/maintainers/README.md's Validation
# matrix mirrors its ordered coverage and omissions; the focused
# TestVerifyGateSetBoundaryContract pin makes removing the boundary step fail
# inside repo-green before a misleading green aggregate can be reported.
# tool-versions: print the gate set's five tools — version AND path.
# THE-UNWATCHED-FOUR: local staticcheck drifted a whole slice unseen,
# and two go-installed binaries in ~/go/bin shadowed brew while reports
# said "the local brew version". Print-only by design: local tracks
# brew-latest and CI asserts its own pins; this line makes skew and
# shadowing VISIBLE at every close instead of discovered by incident.
tool-versions:
	@printf 'go          %s  %s\n' "$$(go version | awk '{print $$3}')" "$$(command -v go)"
	@printf 'staticcheck %s  %s\n' "$$(staticcheck --version 2>/dev/null | awk '{print $$2, $$3}')" "$$(command -v staticcheck || echo MISSING)"
	@printf 'grype       %s  %s\n' "$$(grype --version 2>/dev/null | awk '{print $$2}')" "$$(command -v grype || echo MISSING)"
	@printf 'govulncheck %s  %s\n' "$$(govulncheck -version 2>/dev/null | awk '/Scanner/{print $$2}')" "$$(command -v govulncheck || echo MISSING)"
	@printf 'rulefloor   %s  %s\n' "$$(rulefloor version --json 2>/dev/null)" "$$(command -v rulefloor || echo MISSING)"
	@printf 'yq          %s  %s\n' "$$(yq --version 2>/dev/null | grep -oE 'v[0-9.]+' | head -1)" "$$(command -v yq || echo MISSING)"
	@printf 'gograph     %s  %s\n' "$$(gograph version 2>/dev/null | awk '{print $$3}')" "$$(command -v gograph || echo MISSING)"

## toolchain-parity (THE-UNCOMPARED-TOOLCHAIN, 2026-09-04): tool-versions
## above PRINTS what is installed here; the workflow env DECLARES what CI
## builds. Both were true and neither compared to the other, so the ledger
## was checked by rulefloor v0.8.1 here and v0.7.0 in CI for weeks and
## nothing failed. This target refuses that disagreement.
##
## It found two more the day it was written: local grype 0.118.0 against a
## CI pin of v0.117.0, and GATE_WITNESS_SHA256 still naming the
## PRE-instrumentation gate-witness.sh — which CI verifies with
## `sha256sum -c`, so CI would have failed outright, two slices after the
## change that caused it, with every local gate green.
##
## NOT wired into ci-verify. In CI the tools are installed FROM these pins
## moments earlier, so comparing them back is close to a self-check; the
## drift this catches is between the two machines, and it is here that it
## goes unseen. gograph is deliberately absent from the comparison: CI does
## not install it at all (ci-verify subtracts the gograph targets), so there
## is no pin to disagree with. Rule CI-LOCAL-PARITY-1.
toolchain-parity:
	@go run ./tools/toolchain-parity --repo .

## ci-witness (THE-UNRUN-CI, 2026-09-04): does anything here EVIDENCE a CI
## run? Three slices closed with pins CI has never executed, and a stale
## GATE_WITNESS_SHA256 proved CI can sit broken for two slices while every
## local gate is green. `make verify` witnesses a local run into a committed
## GATE-RUN.txt; CI writes the same kind of record and uploads it to an
## artifact nobody downloads, so no local gate has ever seen one.
##
## This target judges a CI record IF ONE IS COMMITTED HERE. It fetches
## nothing — a gate that reaches the network fails on a plane — and it
## cannot make CI run. Absent, or present but UNTRACKED, it reports NO CLAIM
## and passes: absence is honest. Committed, it must be green, complete,
## commit-tied, clean, on HEAD's ancestry, and carry the `ci-run:`
## provenance only the workflow writes.
##
## The untracked case is why the provenance line exists. A local
## `make ci-verify` writes GATE-RUN.ci.txt to the same gitignored path with
## the same gate label; one from 2026-08-28, green and commit-tied and 138
## commits stale, was in this working tree, and the FIRST version of this
## gate accepted it as CI evidence. Rule CI-RECORD-HONEST-1.
# The caller owns this gate identity, shared with its producer below. Read
# target names from the unexpanded plan: inspection must not execute its commands.
CI_VERIFY_GATE := identuum-idp-oss make ci-verify
# OSS-LICTOR-ADOPT-B: the Integration job's record, fetched by ci-fetch into
# CI-WITNESS.integration.txt, is judged the same way. Its gate label and plan
# are read from scripts/ci-integration-record.sh, the one place that declares
# them; absent, it is NO CLAIM, exactly as CI-WITNESS.txt is.
CI_INTEGRATION_RECORD := CI-WITNESS.integration.txt
ci-witness:
	@plan=$$(printf '%s\n' $(value CI_VERIFY_PLAN) | cut -d= -f1 | paste -sd ' ' -); \
	go run ./tools/ci-witness --repo . --expect-gate "$(CI_VERIFY_GATE)" --expect-plan "$$plan" || exit $$?; \
	gate=$$(sed -n "s/^		--label '\(.*\)' --tie commit .*/\1/p" scripts/ci-integration-record.sh); \
	plan=$$(sed -n "s/^	'\([a-z-]*\)=.*/\1/p" scripts/ci-integration-record.sh | paste -sd ' ' -); \
	[ -n "$$gate" ] && [ -n "$$plan" ] || { echo "check FAILED: ci-witness — scripts/ci-integration-record.sh declares no integration gate or plan"; exit 1; }; \
	go run ./tools/ci-witness --repo . --record $(CI_INTEGRATION_RECORD) --expect-gate "$$gate" --expect-plan "$$plan"

## ci-fetch (THE-GREEN-CI-BASELINE, 2026-09-04): the OPERATOR STEP that
## downloads a CI run's record so ci-witness has something to judge.
##
## A GATE MUST NOT REACH THE NETWORK — it would fail on a plane, and a gate
## whose verdict depends on GitHub being up is not a gate. So the fetch is
## deliberately NOT part of verify, NOT part of the mint, and NOT invoked by
## any check. A human or agent runs it, reviews what came back, and commits
## it; only then does ci-witness see a claim.
##
## THE RUN MUST BE NAMED. There is no "latest" here: `make ci-fetch` without
## RUN=<id> refuses, because a record fetched from whatever happened to be
## newest is a record nobody chose. Recipes in this file run /bin/bash
## (SHELL := /bin/bash, line 38), and the guard below was observed to fire.
##
##   make ci-fetch RUN=33875886668
##   git add CI-WITNESS.txt CI-WITNESS.integration.txt && git commit
ci-fetch:
	@if [ -z "$(RUN)" ]; then \
		echo "ci-fetch: name the run — make ci-fetch RUN=<id>"; \
		echo "ci-fetch: refusing to fetch 'whatever is newest'; a record nobody chose witnesses nothing."; \
		echo "ci-fetch: list them with: gh run list"; \
		exit 1; \
	fi
	@rm -rf .ci-fetch && mkdir -p .ci-fetch
	gh run download $(RUN) -n gate-run-ci-verify -D .ci-fetch
	gh run download $(RUN) -n gate-run-ci-integration -D .ci-fetch
	@cp .ci-fetch/GATE-RUN.ci.txt CI-WITNESS.txt && cp .ci-fetch/GATE-RUN.ci-integration.txt $(CI_INTEGRATION_RECORD) && rm -rf .ci-fetch
	@echo "ci-fetch: wrote CI-WITNESS.txt and $(CI_INTEGRATION_RECORD) from run $(RUN) — READ THEM, then commit them."
	@$(MAKE) --no-print-directory ci-witness || true

## mint-check (THE-UNMINTED-DIFF, 2026-09-04): does the diff since the last
## MINTED witness reach the running appliance? OWNER RULING: a slice whose
## diff cannot reach it does not pay the e2e mint — and that is COMPUTED,
## never judged.
##
## The TOOL's exit codes: 0 SKIPPABLE, 10 MINT REQUIRED, 1 undecidable — and
## test-full treats undecidable as REQUIRED, because a classifier that cannot
## decide is not a licence to skip. WHAT test-full ACTUALLY READS is narrower
## than that (THE-TWO-JUDGE-CONTRACTS, 2026-09-06): it runs the tool through
## `go run`, which collapses every non-zero child exit to 1 (MEASURED: the
## tool's 10 prints "exit status 10" and go run returns 1), so its branch is
## 0 versus non-zero — only an explicit 0 skips, 10 and 1 both mint. Fail
## closed, and correct; but the three-way code never crosses `go run`. The
## direction of the default is the whole design: a path is no-reach only when
## it matches a DECLARED entry, so go.mod, go.sum and any path nobody has
## declared all require the mint. Rule MINT-REACHABILITY-1.
mint-check:
	@go run ./tools/mint-reachability --repo . || true

## mint-decide: the same classifier, run so a CALLER can read the answer.
##
## THE-TWO-JUDGE-CONTRACTS (2026-09-06): this comment used to say "its exit
## code is the answer", and a dispatcher that tested `$?` for 10 never fired.
## Make cannot hand a recipe's exit code through: ANY non-zero recipe exit is
## make's own exit 2 (MEASURED with a one-line fixture: `exit 10` prints
## "Error 10", make exits 2), and `go run` had already collapsed the tool's 10
## to 1 before make saw it. So the contract, stated as what a caller sees:
## `make mint-decide` exits 0 for SKIPPABLE and 2 for anything else — REQUIRED
## or undecidable, fail closed — and its LAST LINE names the tool's own code
## (`mint-decide: tool exit 10 …`). A three-way caller reads that line, never
## the exit status. The tool is BUILT, not `go run`, so the code on that line
## is the tool's (the clock-fuse-report pattern). test-full does not use this
## target: it runs the classifier itself and branches on 0 versus non-zero.
## TestRuleMintReachability1 pins both the recipe shape and this wording.
mint-decide:
	@bin=$$(mktemp "$${TMPDIR:-/tmp}/mintreach.XXXXXX"); \
	if [ -z "$$bin" ]; then echo "mint-decide: mktemp produced no path — CANNOT-EVALUATE"; exit 2; fi; \
	if ! go build -o "$$bin" ./tools/mint-reachability; then rm -f "$$bin"; echo "mint-decide: the classifier does not build — CANNOT-EVALUATE"; exit 2; fi; \
	"$$bin" --repo .; rc=$$?; rm -f "$$bin"; \
	echo "mint-decide: tool exit $$rc (0 SKIPPABLE, 10 MINT REQUIRED, 1 undecidable); make itself exits 0 only for SKIPPABLE and 2 otherwise — read this line, not the exit status"; \
	exit $$rc

.PHONY: mint-decide mint-report witness-mint-test

## Verify records the classifier's verdict without treating mint debt as a
## code failure. Keep mint-decide's fail-closed caller contract unchanged.
mint-report:
	@out=$$($(MAKE) --no-print-directory mint-decide 2>&1); rc=$$?; \
	printf '%s\n' "$$out"; \
	echo "check OK: mint-decide report recorded (make exit $$rc); only SKIPPABLE permits a witness"

## witness-mint-test: the proof that mint debt is RECORDED without failing
## verify and REFUSES every witness attempt — scripts/witness-mint-test.sh,
## 14 assertions over two synthetic repositories built from the real
## classifier, recorder and witness recipe (nothing outside them is read).
## THE-THREE-SMALL-ONES-OSS (2026-09-19): until then nothing in the tree ran
## it (`git grep -l witness-mint-test` found only itself), so the proof held
## only when someone ran it by hand. It sits in the verify plan beside
## mint-decide, whose contract it proves; its `SELFTEST OK` line is the
## evidence. About 6 s. NOT in ci-verify: the machinery it proves —
## mint-decide, witness, witness-mint-check — is local-only and subtracted
## from that plan, and a proof of a local-only recipe runs where the recipe
## runs; adding it there would also widen the documented ci-verify set.
witness-mint-test:
	@bash scripts/witness-mint-test.sh

## script-tests (OSS-QUEUE-TRIAGE, 2026-10-02): the three script proofs no
## plan or CI job ran — verify-check-test.sh pinned VERIFY_PLAN at 34 against
## a 35-entry plan, red and unseen. Each builds its own throwaway repository.
## dev-ports-selftest (OSS-TEST-FULL-PORTS, owner ruling t, 2026-10-07): the
## dev compose app's host port, container port, issuer and listen address all
## come from ${DEV_APP_PORT:-7113}, no other line of the file names 7113, and
## the Makefile defaults DEV_APP_PORT to 7113, exports it and builds its probe
## URLs from it. The files are parameters so the check can be shown red on old
## copies.
DEV_PORTS_COMPOSE ?= deployment/docker-compose.dev.yml
DEV_PORTS_MAKEFILE ?= Makefile
.PHONY: dev-ports-selftest
dev-ports-selftest:
	@set -u; c="$(DEV_PORTS_COMPOSE)"; m="$(DEV_PORTS_MAKEFILE)"; n=0; fails=0; \
	pin() { n=$$((n+1)); if grep -qxF -- "$$2" "$$3"; then echo "  ok    $$1"; else echo "  FAIL  $$1: $$3 lacks the line: $$2"; fails=$$((fails+1)); fi; }; \
	pin "compose publishes the app on DEV_APP_PORT" '      - "127.0.0.1:$${DEV_APP_PORT:-7113}:$${DEV_APP_PORT:-7113}"' "$$c"; \
	pin "compose issuer follows DEV_APP_PORT" '      IDENTUUM_IDP_OSS_ISSUER: "http://localhost:$${DEV_APP_PORT:-7113}"' "$$c"; \
	pin "compose listen follows DEV_APP_PORT" '      IDENTUUM_IDP_OSS_LISTEN: "0.0.0.0:$${DEV_APP_PORT:-7113}"' "$$c"; \
	n=$$((n+1)); stray=$$(grep -nE '7113' "$$c" | grep -vE '^[0-9]+:[[:space:]]*#' | grep -vF ':-7113}' || true); \
	if [ -z "$$stray" ]; then echo "  ok    no other compose line names 7113"; else echo "  FAIL  compose names 7113 outside the DEV_APP_PORT default: $$stray"; fails=$$((fails+1)); fi; \
	pin "Makefile defaults DEV_APP_PORT to 7113" 'DEV_APP_PORT ?= 7113' "$$m"; \
	pin "Makefile exports DEV_APP_PORT to compose" 'export DEV_APP_PORT' "$$m"; \
	pin "dev-smoke health probe follows DEV_APP_PORT" 'DEV_HEALTH_URL ?= http://127.0.0.1:$$(DEV_APP_PORT)/health' "$$m"; \
	pin "dev-smoke component probe follows DEV_APP_PORT" 'DEV_COMPONENT_URL ?= http://127.0.0.1:$$(DEV_APP_PORT)/api/v1/component' "$$m"; \
	pin "dev-smoke build probe follows DEV_APP_PORT" 'DEV_SYSTEM_INFO_URL ?= http://127.0.0.1:$$(DEV_APP_PORT)/system/info' "$$m"; \
	[ $$fails -eq 0 ] && echo "check OK: dev-ports-selftest $$n case(s): the dev app's port, issuer and listen come from DEV_APP_PORT, default 7113" || { echo "check FAILED: dev-ports-selftest $$fails of $$n case(s)"; exit 1; }

.PHONY: script-tests
script-tests:
	@$(MAKE) --no-print-directory protected-guard-selftest
	@$(MAKE) --no-print-directory record-home-paths-selftest
	@$(MAKE) --no-print-directory test-full-dispatch-selftest
	@$(MAKE) --no-print-directory claim-guard-selftest
	@$(MAKE) --no-print-directory dev-ports-selftest
	@$(MAKE) --no-print-directory test-db-endpoint-selftest
	@$(MAKE) --no-print-directory compose-pin-selftest
	@bash scripts/verify-check-test.sh
	@bash scripts/ci-integration-record-test.sh
	@bin=$$(mktemp "$${TMPDIR:-/tmp}/ci-witness.XXXXXX"); \
	go build -o "$$bin" ./tools/ci-witness || { rm -f "$$bin"; exit 1; }; \
	bash scripts/ci-witness-expectation-test.sh "$$bin"; rc=$$?; rm -f "$$bin"; exit $$rc

## protected-guard / protected-check (TOOLS-MATRIX-CONTAINERS, 2026-10-05):
## nothing this repository runs may stop, remove, recreate or rename the
## owner's containers (PROTECTED_CONTAINERS; agent-rules.md §H-bis).
## protected-guard is the prerequisite of every container target: it refuses
## when the dev compose project, its -postgres container or DEV_APP_CONTAINER
## resolves to a protected name, or COMPOSE_FILE is the published compose
## (project identuum-idp-oss, containers identuum-idp-oss and -postgres).
## `make protected-check SCRIPT=<file>` refuses a proof script with a docker
## command that acts on a protected name, or a compose command on the
## published file without its own `-p`; run it before any proof script.
.PHONY: protected-guard protected-check protected-guard-selftest
protected-guard:
	@for n in "$(DEV_COMPOSE_PROJECT)" "$(DEV_COMPOSE_PROJECT)-postgres" "$(DEV_APP_CONTAINER)"; do \
		case " $(PROTECTED_CONTAINERS) " in *" $$n "*) echo "protected-guard: REFUSED — this target would act on $$n, the owner's protected container or project; ask the owner first (agent-rules.md §H-bis)" >&2; exit 2;; esac; \
	done; \
	case " $(COMPOSE_FILE) " in *deployment/docker-compose.yml*) echo "protected-guard: REFUSED — COMPOSE_FILE is deployment/docker-compose.yml, whose project and container names are the owner's; ask the owner first (agent-rules.md §H-bis)" >&2; exit 2;; esac

protected-check:
	@test -n "$(SCRIPT)" && test -f "$(SCRIPT)" || { echo "protected-check: usage: make protected-check SCRIPT=<file>" >&2; exit 2; }; \
	names=$$(printf '%s|' $(PROTECTED_CONTAINERS)); names=$${names%|}; \
	act='docker([[:space:]]+container)?[[:space:]]+(stop|rm|kill|rename|restart|update)[[:space:]]|docker[[:space:]]+compose[[:space:]].*[[:space:]](down|rm|stop|kill|restart|up|create)([[:space:]]|$$)'; \
	hits=$$(grep -nE "$$act" "$(SCRIPT)" | grep -E "(^|[[:space:]=:\"'])($$names)([[:space:]:\"']|$$)"); \
	pub=$$(grep -nE "$$act" "$(SCRIPT)" | grep -F 'deployment/docker-compose.yml' | grep -vE '[[:space:]]-p[[:space:]]'); \
	if [ -n "$$hits$$pub" ]; then \
		echo "protected-check: REFUSED — $(SCRIPT) would act on the owner's protected containers; ask the owner first (agent-rules.md §H-bis):" >&2; \
		printf '%s\n' "$$hits" "$$pub" | grep -v '^$$' >&2; exit 2; \
	fi; \
	echo "check OK: protected-check $(SCRIPT): no command acts on a protected container"

protected-guard-selftest:
	@d=$$(mktemp -d "$${TMPDIR:-/tmp}/protected.XXXXXX"); trap 'rm -rf "$$d"' EXIT; n=0; fails=0; \
	expect() { want=$$1; label=$$2; shift 2; n=$$((n + 1)); "$$@" > /dev/null 2>&1; rc=$$?; \
		if [ $$rc -eq $$want ]; then echo "  ok    exit $$rc  $$label"; else echo "  FAIL  want exit $$want, got $$rc  $$label"; fails=$$((fails + 1)); fi; }; \
	chk() { printf '%s\n' "$$2" > "$$d/s.sh"; expect $$1 "check: $$2" $(MAKE) --no-print-directory protected-check SCRIPT="$$d/s.sh"; }; \
	chk 2 'docker stop identuum-idp-oss-postgres'; \
	chk 2 'docker rm -f identuum-idp-oss'; \
	chk 2 'docker rename identuum-idp-oss-postgres old-pg'; \
	chk 2 'docker compose -p identuum-idp-oss -f deployment/docker-compose.dev.yml down'; \
	chk 2 'IDENTUUM_IDP_COMPOSE_PROJECT=identuum-idp-oss docker compose -f deployment/docker-compose.dev.yml up -d'; \
	chk 2 'docker compose -f deployment/docker-compose.yml up -d'; \
	chk 0 'docker stop identuum-idp-oss-dev-postgres'; \
	chk 0 'docker ps --filter name=identuum-idp-oss-postgres'; \
	chk 0 'docker compose -p v097rel -f deployment/docker-compose.yml -f override.yml up -d'; \
	chk 0 'cd /work/identuum-idp-oss && docker compose -f deployment/docker-compose.dev.yml up -d'; \
	expect 0 "guard: default dev project" $(MAKE) --no-print-directory protected-guard; \
	expect 0 "guard: the e2e harness project" $(MAKE) --no-print-directory protected-guard IDENTUUM_IDP_COMPOSE_PROJECT=scratch-e2e; \
	expect 2 "guard: project identuum-idp-oss" $(MAKE) --no-print-directory protected-guard IDENTUUM_IDP_COMPOSE_PROJECT=identuum-idp-oss; \
	expect 2 "guard: DEV_APP_CONTAINER=identuum-idp-oss" $(MAKE) --no-print-directory protected-guard DEV_APP_CONTAINER=identuum-idp-oss; \
	expect 2 "guard: the published compose" $(MAKE) --no-print-directory protected-guard COMPOSE_FILE=deployment/docker-compose.yml; \
	for f in conformance/run.sh scripts/*.sh; do expect 0 "this repository: $$f" $(MAKE) --no-print-directory protected-check SCRIPT="$$f"; done; \
	if [ $$fails -ne 0 ]; then echo "protected-guard-selftest: FAIL — $$fails of $$n case(s) wrong" >&2; exit 1; fi; \
	echo "check OK: protected-guard-selftest $$n case(s), refusals and passes proven"

## compose-pin-selftest (OSS-MINT-GUARD-2; review OSS-MINT-COVERAGE C1, judge
## ruling Q2(b)): this Makefile runs from a fixture directory where docker,
## curl, go and lsof are stubs that record each call and the compose variables
## it saw, so nothing reaches a daemon. oss-up's build and start carry
## -p <project> with COMPOSE_PROJECT_NAME and COMPOSE_REMOVE_ORPHANS cleared,
## even when the caller exports COMPOSE_PROJECT_NAME=identuum-idp-oss; a
## protected project or a DEV_APP_CONTAINER that is not the project's app
## container is refused before any docker call; devseed-live refuses leftovers
## of its project (identuum-devseed until OSS-CANDIDATE-LIFECYCLE-FIX,
## scratch-devseed since) without a compose command, and otherwise starts its
## project with -p scratch-devseed even under an outer command-line project.
## OSS-MINT-GUARD-3 (review OSS-MINT-GUARD-2 G2): devseed-live also refuses,
## before any start, a volume or network carrying one of the names it would
## create whatever its labels (the stub answers only an unfiltered listing
## with it, as a foreign or unlabelled one would), and a second invocation
## while the lock is held; and its teardown runs no down at all when a name it
## recorded exists without the project's label (a foreign volume appearing
## during the run). Every exit releases the lock it took (until
## OSS-CANDIDATE-LIFECYCLE-FIX: a refused teardown now keeps it, below).
## OSS-MINT-GUARD-5 (review OSS-MINT-GUARD-4 R1-R3): the volume and network
## names carry the invocation id and the one volume removal names that volume;
## a volume another writer re-creates under the project's SHARED name (the
## name its config resolves to, without the invocation id) right after the
## final identity inspection (E-RACE) survives and the run is red — while a
## writer that copies this run's EXACT invocation-unique name in that interval
## has its volume removed by that name, the accepted residual (judge ruling Q3
## (a), OSS-MINT-GUARD-6), modeled by its own case; a recorded volume without
## the id in its name is refused; a DOCKER_HOST or context endpoint that is
## not this host's unix socket (tcp, ssh, another context, an unresolvable
## one) is refused before any other docker call, and an accepted one is pinned
## on every later call; DEVSEED_LIVE_PG_PORT 5513, 5432 or 05513, selected on
## the command line, through `make -e` or by an `override`, is refused before
## any docker call. OSS-MINT-GUARD-6 (review OSS-MINT-GUARD-5 F1, F2): a
## COMPOSE_CMD carrying --host, -H, --context or -c, from the environment, the
## command line or `make -e`, is refused before any docker call, and so is a
## bound nested oss-up with such a command, another context, another engine id
## or another mutex; a command-line DEV_COMPOSE does not reach the nested
## start; two runs with separate locks (two /tmp) against one modeled daemon:
## the second is refused at the daemon mutex before any resource call; a held
## mutex is refused and left as it was; an engine whose ID changes mid-run
## stops every later removal and seed and keeps the mutex; an absent mutex
## image is refused. OSS-CANDIDATE-LIFECYCLE-FIX (SPEC K1-K6): the project is
## scratch-devseed and a bound nested oss-up of a non-scratch project is
## refused; the claim is the one shared harness claim (HARNESS_LOCK), and a
## held one names the other harnesses; the daemon mutex carries the project
## and ports; a resolved config that mounts a host path is refused before any
## start; the teardown is one WHOLE step — an unrecorded or replaced object,
## a foreign container attached to a recorded network or volume, a name
## without the invocation id or a failed record removes NOTHING — and a
## refused or failed teardown, a recorded object still present after its
## removal or a changed engine keeps the claim, the mutex and the record,
## whose manifest.json names the engine, project, invocation, ports, mutex and
## every recorded resource; fast-up of a scratch project reuses only the
## recorded scratch PostgreSQL its full ID names (checked on the engine) and
## refuses every other case without a Compose start, while the default dev
## project keeps its reuse. COMPOSE_PIN_MAKEFILE runs the same cases against
## another copy of this Makefile (a red baseline or a mutant).
COMPOSE_PIN_MAKEFILE ?= $(abspath Makefile)
.PHONY: compose-pin-selftest
compose-pin-selftest:
	@d=$$(mktemp -d "$${TMPDIR:-/tmp}/compose-pin.XXXXXX"); trap 'rm -rf "$$d"' EXIT; n=0; fails=0; \
	mkdir -p "$$d/bin" "$$d/w/deployment" "$$d/tmp" "$$d/tmp2" "$$d/fixed"; : > "$$d/w/deployment/docker-compose.dev.yml"; \
	sed "s#^override HARNESS_LOCK := /tmp/identuum-harness.lock\$$#override HARNESS_LOCK := $$d/fixed/identuum-harness.lock#" "$(COMPOSE_PIN_MAKEFILE)" > "$$d/w/Makefile"; \
	[ "$$(grep -c "^override HARNESS_LOCK := $$d/fixed/identuum-harness.lock\$$" "$$d/w/Makefile")" = 1 ] || { echo "check FAILED: compose-pin-selftest — the Makefile does not declare HARNESS_LOCK as the one fixed path /tmp/identuum-harness.lock"; exit 1; }; \
	printf '%s\n' '#!/bin/sh' \
		'echo "docker $$* | cpn=$${COMPOSE_PROJECT_NAME-unset} cro=$${COMPOSE_REMOVE_ORPHANS-unset} iicp=$${IDENTUUM_IDP_COMPOSE_PROJECT-unset} pg=$${DEV_PG_HOST_PORT-unset} dh=$${DOCKER_HOST-unset} dctx=$${DOCKER_CONTEXT-unset}" >> "$$STUB_D/calls"' \
		'engine="$${STUB_DAEMON:-$$STUB_D}"; S="$$engine/state"; mkdir -p "$$S/c" "$$S/n" "$$S/v"; V0=scratch-devseed_postgres-idp-oss-data-v18; N0=scratch-devseed_default' \
		'while [ "$${1:-}" = --host ] || [ "$${1:-}" = -H ] || [ "$${1:-}" = --context ] || [ "$${1:-}" = -c ]; do echo "guard6-selector $$1 $$2" >> "$$STUB_D/other"; shift 2; done' \
		'[ "$${1:-}" != container ] || shift' \
		'case "$$*" in *"json .NetworkSettings.Ports"*) [ -e "$$STUB_D/pg-inspect" ] || exit 1; cat "$$STUB_D/pg-inspect"; exit 0;; esac' \
		'if [ "$${1:-}" = info ] || [ "$${1:-} $${2:-}" = "system info" ]; then cat "$$engine/engine-id" 2>/dev/null || echo guard6-engine-a; exit 0; fi' \
		'if [ "$$1 $$2" = "image inspect" ]; then [ -e "$$STUB_D/no-mutex-image" ] && exit 1; echo null; exit 0; fi' \
		'if [ "$${1:-}" = create ]; then nm=; ow=; en=; prev=; for a in "$$@"; do [ "$$prev" != --name ] || nm="$$a"; case "$$a" in io.identuum.harness.mutex-owner=*) ow=$${a#*=};; io.identuum.harness.engine=*) en=$${a#*=};; esac; prev="$$a"; done; [ "$$nm" = identuum-harness-lock-engine ] || { echo "unmodeled mutex name" >&2; exit 97; }; mkdir "$$engine/mutex" 2>/dev/null || { echo "Conflict: mutex name is already in use" >&2; exit 1; }; printf "%s\n" "$$*" > "$$engine/mutex/labels"; echo "$$ow" > "$$engine/mutex/owner"; echo "$$en" > "$$engine/mutex/engine"; echo guard6-mutex-id; exit 0; fi' \
		'if [ "$${1:-}" = inspect ]; then for a in "$$@"; do case "$$a" in guard6-mutex-id|identuum-harness-lock-engine) [ -d "$$engine/mutex" ] || exit 1; case "$$*" in *mutex-owner*) echo "guard6-mutex-id $$(cat "$$engine/mutex/owner" 2>/dev/null) $$(cat "$$engine/mutex/engine" 2>/dev/null)";; *) echo guard6-mutex-id;; esac; exit 0;; esac; done; fi' \
		'if [ "$${1:-}" = rm ]; then for a in "$$@"; do [ "$$a" != guard6-mutex-id ] || { rm -rf "$$engine/mutex"; echo guard6-mutex-released >> "$$STUB_D/other"; exit 0; }; done; fi' \
		'if [ "$${1:-}" = ps ] && [ -e "$$STUB_D/pause" ] && [ ! -e "$$STUB_D/ready" ]; then : > "$$STUB_D/ready"; i=0; while [ ! -e "$$STUB_D/resume" ]; do i=$$((i+1)); [ $$i -lt 500 ] || exit 98; /bin/sleep 0.01; done; fi' \
		'if [ "$$1 $$2" = "context inspect" ]; then [ -n "$${DOCKER_HOST:-}" ] && { echo "$$DOCKER_HOST"; exit 0; }; [ -e "$$STUB_D/context-fail" ] && exit 1; cat "$$STUB_D/endpoint" 2>/dev/null || echo unix:///var/run/docker.sock; exit 0; fi' \
		'ovarg=; for a in "$$@"; do case "$$a" in *invocation.json) ovarg=$$a;; esac; done; ovany=$${ovarg:-$$(ls "$$TMPDIR"/devseed-live.*/invocation.json 2>/dev/null | head -1)}' \
		'inv=; [ -z "$$ovany" ] || inv=$$(sed -n "s/.*\"io.identuum.harness.invocation\":\"\([0-9a-f]*\)\".*/\1/p" "$$ovany" | head -1)' \
		'V=$$V0; N=$$N0; if [ -n "$$ovarg" ]; then x=$$(sed -n "s/.*\"postgres-idp-oss-data-v18\":{\"name\":\"\([^\"]*\)\".*/\1/p" "$$ovarg"); V=$${x:-$$V0}; x=$$(sed -n "s/.*\"default\":{\"name\":\"\([^\"]*\)\".*/\1/p" "$$ovarg"); N=$${x:-$$N0}; fi' \
		'case " $$* " in' \
		'*" config --volumes "*) echo postgres-idp-oss-data-v18; exit 0;;' \
		'*" config --networks "*) echo default; exit 0;;' \
		'*" config --services "*) printf "postgres-idp-oss\napp\n"; exit 0;;' \
		'*" config --format json "*) bm=; [ -e "$$STUB_D/bind-mount" ] && bm=",\"volumes\":[{\"type\":\"bind\",\"source\":\"/tmp\",\"target\":\"/x\"}]"' \
		'  key=$$(cat "$$STUB_D/config-key" 2>/dev/null); if [ -z "$$key" ]; then bm="$$bm,\"command\":null,\"entrypoint\":null"; else bm="$$bm,\"$$key\":[\"container:identuum-idp-oss-postgres:ro\"]"; fi' \
		'  echo "{\"name\":\"scratch-devseed\",\"services\":{\"postgres-idp-oss\":{\"command\":null,\"entrypoint\":null,\"container_name\":\"scratch-devseed-postgres\",\"image\":\"postgres:18-alpine\",\"ports\":[{\"host_ip\":\"127.0.0.1\",\"published\":\"$${DEV_PG_HOST_PORT}\",\"target\":5432}]},\"app\":{\"container_name\":\"scratch-devseed\",\"image\":\"scratch-devseed:local\",\"ports\":[{\"host_ip\":\"127.0.0.1\",\"published\":\"$${DEV_APP_PORT}\",\"target\":7113}]$$bm}},\"volumes\":{\"postgres-idp-oss-data-v18\":{\"name\":\"$$V\"}},\"networks\":{\"default\":{\"name\":\"$$N\"}}}"; exit 0;;' \
		'*" compose "*" up "*) [ -e "$$STUB_D/up-fails" ] && exit 1; [ -e "$$STUB_D/ignore-names" ] && { V=$$V0; N=$$N0; }' \
		'  if [ -e "$$STUB_D/late" ]; then echo "2026-10-10T00:00:09Z - -" > "$$S/v/$$V"; else echo "2026-10-10T00:00:01Z scratch-devseed $${inv:--}" > "$$S/v/$$V"; fi' \
		'  echo "$$N scratch-devseed $${inv:--}" > "$$S/n/n1"; echo "scratch-devseed-postgres scratch-devseed $${inv:--}" > "$$S/c/c1"; echo "scratch-devseed scratch-devseed $${inv:--}" > "$$S/c/c2"' \
		'  [ ! -e "$$STUB_D/foreign-member" ] || echo "scratch-intruder someone-else - attached" > "$$S/c/fm"; [ ! -e "$$STUB_D/up-fails-partial" ] || exit 1; exit 0;;' \
		'*" compose "*) exit 0;;' \
		'esac' \
		'q=; fmt=; filt=; prev=; last=; for a in "$$@"; do case "$$prev" in --filter) filt="$$filt $$a";; --format) fmt="$$a";; esac; case "$$a" in -q|-aq) q=1;; esac; prev="$$a"; last="$$a"; done' \
		'match() { for g in $$filt; do case "$$g" in label=com.docker.compose.project=*) [ "$$2" = "$${g#*project=}" ] || return 1;; label=io.identuum.harness.invocation=*) [ "$$3" = "$${g#*invocation=}" ] || return 1;; name=*) m="$${g#name=^/\?}"; [ "$$1" = "$${m%?}" ] || return 1;; network=*|volume=*) [ "$$2" = scratch-devseed ] || [ "$${4:-}" = attached ] || return 1;; *) return 1;; esac; done; return 0; }' \
		'proj=; case "$$filt" in *project=*) proj=1;; esac' \
		'case "$$1 $$2" in' \
		'"ps "*) case "$$filt" in *invocation=*) [ ! -e "$$STUB_D/list-fails" ] || exit 1;; esac; for f in "$$S"/c/*; do [ -e "$$f" ] || continue; read -r nm pj iv at < "$$f"; match "$$nm" "$$pj" "$$iv" "$$at" || continue; if [ -n "$$q" ]; then echo "$${f##*/}"; else echo "$${f##*/} $$nm"; fi; done; [ -n "$$proj" ] && [ -e "$$STUB_D/leftover" ] && echo deadbeef; exit 0;;' \
		'"network ls") for f in "$$S"/n/*; do [ -e "$$f" ] || continue; read -r nm pj iv < "$$f"; match "$$nm" "$$pj" "$$iv" || continue; if [ -n "$$q" ]; then echo "$${f##*/}"; else case "$$fmt" in *.ID*) echo "$${f##*/} $$nm";; *) echo "$$nm";; esac; fi; done; [ -n "$$proj" ] && [ -e "$$STUB_D/leftover" ] && echo deadbeef; [ -z "$$filt" ] && [ -e "$$STUB_D/foreign-network" ] && echo "$${N0}_$$inv"; exit 0;;' \
		'"volume ls") for f in "$$S"/v/*; do [ -e "$$f" ] || continue; read -r ct pj iv < "$$f"; match "$${f##*/}" "$$pj" "$$iv" || continue; echo "$${f##*/}"; done; [ -n "$$proj" ] && [ -e "$$STUB_D/leftover" ] && echo deadbeef; [ -z "$$filt" ] && [ -e "$$STUB_D/foreign-volume" ] && echo "$${V0}_$$inv"; exit 0;;' \
		'"network inspect") [ -e "$$S/n/$$last" ] || exit 1; read -r nm pj iv < "$$S/n/$$last"; case "$$fmt" in *index*) echo "$$last $$iv";; *) echo "$$nm";; esac; exit 0;;' \
		'"volume inspect") [ -e "$$S/v/$$last" ] || exit 1; read -r ct pj iv < "$$S/v/$$last"; case "$$fmt" in *index*) echo "$$ct $$iv"' \
		'  k=$$(cat "$$STUB_D/vinspect" 2>/dev/null || echo 0); k=$$((k+1)); echo $$k > "$$STUB_D/vinspect"; [ $$k -eq 2 ] || exit 0' \
		'  if [ -e "$$STUB_D/replace-after-inspect" ]; then rm -f "$$S/v/$$last"; echo "2026-10-10T00:00:07Z $$pj $$iv" > "$$S/v/$$V0"; echo replaced-after-inspect >> "$$STUB_D/other"; fi; if [ -e "$$STUB_D/replace-exact-after-inspect" ]; then echo "2026-10-10T00:00:07Z $$pj $$iv" > "$$S/v/$$last"; echo replaced-exact-after-inspect >> "$$STUB_D/other"; fi;;' \
		'  *) echo "$$ct";; esac; exit 0;;' \
		'"network rm") rm -f "$$S/n/$$last"; exit 0;;' \
		'"volume rm") [ -e "$$S/v/$$last" ] || { echo "Error response from daemon: get $$last: no such volume" >&2; exit 1; }; rm -f "$$S/v/$$last"; exit 0;;' \
		'"inspect "*) [ -e "$$S/c/$$last" ] || exit 1; read -r nm pj iv < "$$S/c/$$last"; case "$$fmt" in *Mounts*) for v in "$$S"/v/*; do [ -e "$$v" ] && echo "$${v##*/}"; done;; *compose.project*) echo "$$last $$iv $$pj /$$nm";; *) echo "$$last $$iv";; esac; exit 0;;' \
		'"rm "*) case " $$* " in *" -v "*) rm -f "$$S/v/ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"; echo implicit-anonymous-removal >> "$$STUB_D/other";; esac; [ -e "$$STUB_D/rm-fails" ] && [ "$$last" = c2 ] && { echo "Error response from daemon: cannot remove c2" >&2; exit 1; }; [ -e "$$STUB_D/rm-noop" ] || rm -f "$$S/c/$$last"; exit 0;;' \
		'esac' \
		'exit 0' > "$$d/bin/docker"; \
	printf '%s\n' '#!/bin/sh' 'echo "curl $$*" >> "$$STUB_D/other"' 'engine="$${STUB_DAEMON:-$$STUB_D}"; S="$$engine/state"' \
		'if [ -e "$$STUB_D/change-engine" ]; then echo guard6-engine-b > "$$engine/engine-id"; echo guard6-engine-changed >> "$$STUB_D/calls"; fi' \
		'for V in "$$S"/v/scratch-devseed_postgres-idp-oss-data-v18*; do if [ -e "$$STUB_D/replace-volume" ] && [ -e "$$V" ]; then read -r ct pj iv < "$$V"; echo "2026-10-10T00:00:05Z $$pj $$iv" > "$$V"; fi; done' \
		'if [ -e "$$STUB_D/record-damage" ]; then read -r nm pj iv < "$$S/c/c1"; echo "foreign-preserve foreign-project $$iv" > "$$S/c/spoof"; fi' \
		'for r in "$$TMPDIR"/devseed-live.*/created; do case "$$(cat "$$STUB_D/record-damage" 2>/dev/null)" in missing) rm -f "$$r";; incomplete) echo "incomplete" >> "$$r";; manifest) rm -f "$$STUB_D/fixed/identuum-harness.lock/manifest.json";; esac; done' \
		'if [ -e "$$STUB_D/anonymous" ]; then pj=$$(cat "$$STUB_D/anonymous"); echo "2030-01-01T00:00:00Z $$pj -" > "$$S/v/ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"; fi' \
		'if [ -e "$$STUB_D/foreign-container" ]; then echo "scratch-devseed-intruder-1 scratch-devseed someone-else" > "$$S/c/f1"; fi' \
		'exit 0' > "$$d/bin/curl"; \
	printf '#!/bin/sh\necho "go $$*" >> "%s/other"\nexit 0\n' "$$d" > "$$d/bin/go"; \
	printf '#!/bin/sh\nexit 1\n' > "$$d/bin/lsof"; chmod +x "$$d/bin/docker" "$$d/bin/curl" "$$d/bin/go" "$$d/bin/lsof"; \
	printf '%s\n' '#!/bin/sh' 'if [ "$$#" = 0 ]; then exec /usr/bin/mktemp "$$STUB_D/tmp/probe.XXXXXX"; fi' 'exec /usr/bin/mktemp "$$@"' > "$$d/bin/mktemp"; chmod +x "$$d/bin/mktemp"; \
	printf '#!/bin/sh\nexec "%s" "$$@"\n' "$$(command -v node)" > "$$d/bin/node"; chmod +x "$$d/bin/node"; \
	for t in pg_isready psql; do printf '#!/bin/sh\necho "%s $$*" >> "%s/other"\n[ -e "%s/pg-ready" ]\n' "$$t" "$$d" "$$d" > "$$d/bin/$$t"; chmod +x "$$d/bin/$$t"; done; \
	run() { rm -rf "$$d/calls" "$$d/state" "$$d/other" "$$d/vinspect" "$$d"/tmp/devseed-live.*; (cd "$$d/w" && env -u MAKEFLAGS -u MAKEOVERRIDES -u MFLAGS -u MAKELEVEL -u COMPOSE_PROJECT_NAME -u COMPOSE_REMOVE_ORPHANS -u IDENTUUM_IDP_COMPOSE_PROJECT -u DEV_APP_CONTAINER -u DOCKER_HOST -u DOCKER_CONTEXT -u DEVSEED_LIVE_PG_PORT STUB_D="$$d" TMPDIR="$$d/tmp" PATH="$$d/bin:$$PATH" "$$@") > "$$d/out" 2>&1; }; \
	verdict() { n=$$((n + 1)); if [ -z "$$2" ]; then echo "  ok    $$1"; else echo "  FAIL  $$1:$$2"; fails=$$((fails + 1)); fi; }; \
	pinned() { want=$$1; miss=; c=$$(grep -c ' compose ' "$$d/calls" 2>/dev/null); [ "$${c:-0}" -ge "$$2" ] || miss="$$miss only-$${c:-0}-compose-calls"; \
		grep ' compose ' "$$d/calls" 2>/dev/null | grep -vF -- " -p $$want " >/dev/null && miss="$$miss unpinned"; \
		grep ' compose ' "$$d/calls" 2>/dev/null | grep -vF -- "cpn=unset cro=unset iicp=$$want" >/dev/null && miss="$$miss inherited-env"; echo "$$miss"; }; \
	startfirst() { case "$$1" in *' up -d'*|*' build '*) ;; *) echo " first-compose-call-not-build-or-up";; esac; }; \
	nodown() { grep -qE ' compose .* down( |$$)' "$$d/calls" && echo " compose-down-called"; }; \
	removed() { grep -qE "^docker $$1( |$$)" "$$d/calls" || echo " $$2-not-removed"; }; \
	kept() { grep -qE "^docker $$1( |$$)" "$$d/calls" && echo " $$2-removed"; }; \
	none_removed() { grep -qE '^docker (rm -f|network rm|volume rm) ' "$$d/calls" && echo " something-removed"; }; \
	advice() { grep -qE 'docker ((container )?rm |(volume|network) rm |.*prune|compose .*down .* (-v|--volumes))' "$$d/out" && echo " deleting-advice"; grep -qF 'Removal is a manual owner decision.' "$$d/out" || echo " no-owner-decision"; }; \
	retained() { [ -d "$$lock" ] || echo " claim-released"; [ -d "$$d/mutex" ] || echo " mutex-released"; grep -q '"state":"refused"' "$$lock/manifest.json" 2>/dev/null || echo " no-refused-record"; grep -q 'is KEPT with' "$$d/out" || echo " kept-not-named"; advice; }; \
	reset() { rm -rf "$$lock" "$$d/mutex"; }; \
	run env COMPOSE_PROJECT_NAME=identuum-idp-oss COMPOSE_REMOVE_ORPHANS=true IDENTUUM_IDP_COMPOSE_PROJECT=identuum-e2e $(MAKE) --no-print-directory oss-up; rc=$$?; \
	verdict "oss-up under an inherited COMPOSE_PROJECT_NAME=identuum-idp-oss builds and starts -p identuum-e2e" "$$( [ $$rc -eq 0 ] || echo " exit $$rc")$$(pinned identuum-e2e 2)"; \
	run env IDENTUUM_IDP_COMPOSE_PROJECT=identuum-e2e $(MAKE) --no-print-directory oss-up DEV_COMPOSE_PROJECT=scratch-pin; rc=$$?; \
	verdict "a command-line DEV_COMPOSE_PROJECT moves -p and the file's names together" "$$( [ $$rc -eq 0 ] || echo " exit $$rc")$$(pinned scratch-pin 2)"; \
	run env IDENTUUM_IDP_COMPOSE_PROJECT=identuum-idp-oss $(MAKE) --no-print-directory oss-up; rc=$$?; \
	verdict "oss-up of the protected project is refused before any docker call" "$$( [ $$rc -ne 0 ] || echo " exit 0")$$( [ ! -s "$$d/calls" ] || echo " docker-called")"; \
	run env IDENTUUM_IDP_COMPOSE_PROJECT=identuum-e2e $(MAKE) --no-print-directory oss-up DEV_APP_CONTAINER=identuum-idp-oss-dev; rc=$$?; \
	verdict "oss-up with a DEV_APP_CONTAINER that is not the project's is refused before any docker call" "$$( [ $$rc -eq 2 ] || echo " exit $$rc")$$( [ ! -s "$$d/calls" ] || echo " docker-called")"; \
	: > "$$d/leftover"; run $(MAKE) --no-print-directory devseed-live; rc=$$?; rm -f "$$d/leftover"; \
	verdict "devseed-live refuses scratch-devseed leftovers and offers inspection only" "$$( [ $$rc -ne 0 ] || echo " exit 0")$$( grep -q ' compose ' "$$d/calls" && echo " compose-called")$$( grep -q 'resources this run did not create' "$$d/out" || echo " no-refusal-line")$$(advice)$$(for c in 'docker inspect ' 'docker volume inspect ' 'docker network inspect '; do grep -qF "$$c" "$$d/out" || echo " missing-inspection"; done)$$(grep -q deadbeef "$$d/out" || echo " missing-id")"; \
	run $(MAKE) --no-print-directory devseed-live IDENTUUM_IDP_COMPOSE_PROJECT=identuum-e2e; \
	first=$$(grep ' compose ' "$$d/calls" | grep -v ' config ' | head -1); \
	verdict "devseed-live under an outer command-line project starts only -p scratch-devseed, and removes nothing before its own start" "$$(pinned scratch-devseed 3)$$(startfirst "$$first")"; \
	lock="$$d/fixed/identuum-harness.lock"; \
	verdict "devseed-live labels what it starts with its invocation id, records it by ID, removes exactly that by ID (two containers, the network, the volume), runs no compose down, and releases its lock" "$$(grep -q -- '-f [^ ]*invocation.json' "$$d/calls" || echo " no-overlay")$$(grep -q 'check OK: record — this run created 4 resource' "$$d/out" || echo " not-recorded")$$(removed 'rm -f c1' container-c1)$$(removed 'rm -f c2' container-c2)$$(removed 'network rm n1' network)$$(removed 'volume rm scratch-devseed_postgres-idp-oss-data-v18_[0-9a-f]{32}' volume)$$(nodown)$$( [ -z "$$(ls "$$d/state/c" "$$d/state/n" "$$d/state/v" 2>/dev/null | grep -v '^$$' | grep -v ':$$')" ] || echo " residue")$$( [ ! -e "$$lock" ] || echo " lock-left")"; \
	for kind in volume network; do \
		: > "$$d/foreign-$$kind"; run $(MAKE) --no-print-directory devseed-live; rc=$$?; rm -f "$$d/foreign-$$kind"; \
		verdict "devseed-live refuses a $$kind with a name it would create whatever its labels (seen only unfiltered), before any start or removal" "$$( [ $$rc -ne 0 ] || echo " exit 0")$$(grep -E ' compose .* (up|down|build) ' "$$d/calls" >/dev/null && echo " compose-acted")$$(grep -qE '^docker (rm|network rm|volume rm) ' "$$d/calls" && echo " removed")$$(grep -q 'already exist' "$$d/out" || echo " no-refusal-line")$$( [ ! -e "$$lock" ] || echo " lock-left")"; \
	done; \
	mkdir "$$lock"; echo held > "$$lock/pid"; run $(MAKE) --no-print-directory devseed-live; rc=$$?; \
	verdict "SPEC-K2: the harness claim is shared — held by any harness run (openid-conformance, e2e-full or devseed-live), devseed-live is refused before any docker call and leaves it" "$$( [ $$rc -ne 0 ] || echo " exit 0")$$( [ ! -s "$$d/calls" ] || echo " docker-called")$$(grep -q held "$$lock/pid" 2>/dev/null || echo " lock-taken")$$(grep -q 'openid-conformance or identuum-ui e2e-full' "$$d/out" || echo " other-harnesses-not-named")"; \
	verdict "holder fallback" "$$(grep -qF 'holder: no holder file' "$$d/out" || echo " no-fallback")"; \
	printf 'final-conformance scratch-test <>;\t%090d\nSECOND-LINE\n' 0 > "$$lock/holder"; \
	run $(MAKE) --no-print-directory devseed-live; rc=$$?; want=$$(head -1 "$$lock/holder" | LC_ALL=C tr -cd 'A-Za-z0-9._ -' | cut -c1-80); \
	verdict "holder first line filtered and bounded, all workspace holder kinds named" "$$(grep -qxF "devseed-live: holder: $$want" "$$d/out" || echo " bad-holder")$$(grep -q SECOND-LINE "$$d/out" && echo " second-line")$$(for k in final-conformance testbook-fixtures human-acceptance; do grep -qF "$$k" "$$d/out" || echo " missing-kind"; done)$$( [ ! -s "$$d/calls" ] || echo " docker-called")"; \
	run env TMPDIR="$$d/tmp2" $(MAKE) --no-print-directory devseed-live; rc=$$?; \
	verdict "REVIEW-H1: a caller with another TMPDIR takes the same lock, so it is refused before any docker call and leaves the lock" "$$( [ $$rc -ne 0 ] || echo " exit 0")$$( [ ! -s "$$d/calls" ] || echo " docker-called")$$(grep -q held "$$lock/pid" 2>/dev/null || echo " lock-taken")$$(grep -qF "$$lock" "$$d/out" || echo " lock-not-named")$$( [ ! -e "$$d/tmp2/identuum-harness.lock" ] || echo " lock-under-TMPDIR")"; \
	rm -rf "$$lock"; \
	: > "$$d/late"; run $(MAKE) --no-print-directory devseed-live; rc=$$?; rm -f "$$d/late"; \
	verdict "SPEC-K5: a volume with a recorded name that appears during the run without this run's invocation label refuses the WHOLE teardown before the first removal (nothing removed); the run is red and keeps its claim, mutex and record" "$$( [ $$rc -ne 0 ] || echo " exit 0")$$(none_removed)$$(nodown)$$(grep -q 'teardown — refused' "$$d/out" || echo " no-refusal-line")$$(retained)"; reset; \
	: > "$$d/replace-volume"; run $(MAKE) --no-print-directory devseed-live; rc=$$?; rm -f "$$d/replace-volume"; \
	verdict "REVIEW-H2 + SPEC-K5: a same-name, same-label replacement of the recorded volume (its creation time changed) refuses the WHOLE teardown: neither it nor this run's own containers and network are removed; the run is red and keeps its claim, mutex and record" "$$( [ $$rc -ne 0 ] || echo " exit 0")$$(none_removed)$$(nodown)$$(grep -q 'replaced since it was recorded' "$$d/out" || echo " no-refusal-line")$$( [ -n "$$(ls "$$d/state/v" 2>/dev/null)" ] || echo " replacement-gone")$$( [ -e "$$d/state/c/c1" ] || echo " own-container-gone")$$(retained)"; reset; \
	: > "$$d/foreign-container"; run $(MAKE) --no-print-directory devseed-live; rc=$$?; rm -f "$$d/foreign-container"; \
	verdict "REVIEW-H2 + SPEC-K5: a foreign container of the same project refuses the WHOLE teardown: neither it nor this run's own resources are removed; the run is red and keeps its claim, mutex and record" "$$( [ $$rc -ne 0 ] || echo " exit 0")$$(none_removed)$$(nodown)$$(grep -q 'teardown — refused for container:f1' "$$d/out" || echo " no-refusal-line")$$( [ -e "$$d/state/c/f1" ] || echo " foreign-gone")$$( [ -e "$$d/state/c/c2" ] || echo " own-container-gone")$$(retained)"; \
	m="$$lock/manifest.json"; \
	verdict "SPEC-K4/K6: the kept record's public manifest.json names the engine, the project, the invocation, the ports, the daemon mutex and every recorded resource (containers and network by ID, the volume by name and creation time)" "$$(grep -q '"schema":"identuum.harness.run.v1","kind":"devseed-live","state":"refused","project":"scratch-devseed","invocation":"[0-9a-f]\{32\}","daemon_id":"guard6-engine-a","endpoint":"unix:///var/run/docker.sock","mutex_id":"guard6-mutex-id","ports":\[25513,27113\]' "$$m" 2>/dev/null || echo " header")$$(grep -q '{"kind":"container","id":"c1"},{"kind":"container","id":"c2"},{"kind":"network","id":"n1"},{"kind":"volume","name":"scratch-devseed_postgres-idp-oss-data-v18_[0-9a-f]\{32\}","created_at":"2026-10-10T00:00:01Z"}' "$$m" 2>/dev/null || echo " resources")"; reset; \
	run $(MAKE) --no-print-directory devseed-live; rc=$$?; \
	verdict "REVIEW-R1: the volume and the network devseed-live creates carry its invocation id in their names, resolved with its overlay, and its one volume removal names that volume" "$$(grep -q 'check OK: teardown' "$$d/out" || echo " teardown-not-ok")$$(grep -E ' compose .*-f [^ ]*invocation.json .*config --format json' "$$d/calls" >/dev/null || echo " not-resolved-with-overlay")$$(cat "$$d"/tmp/devseed-live.*/invocation.json 2>/dev/null | grep -qE '"postgres-idp-oss-data-v18":[{]"name":"scratch-devseed_postgres-idp-oss-data-v18_[0-9a-f]{32}"' || echo " volume-name-without-id")$$(cat "$$d"/tmp/devseed-live.*/invocation.json 2>/dev/null | grep -qE '"default":[{]"name":"scratch-devseed_default_[0-9a-f]{32}"' || echo " network-name-without-id")$$( [ "$$(grep -cE '^docker volume rm scratch-devseed_postgres-idp-oss-data-v18_[0-9a-f]{32} ' "$$d/calls")" = 1 ] || echo " not-one-own-volume-rm")$$( [ "$$(grep -cE '^docker volume rm ' "$$d/calls")" = 1 ] || echo " other-volume-rm")"; \
	: > "$$d/replace-after-inspect"; run $(MAKE) --no-print-directory devseed-live; rc=$$?; rm -f "$$d/replace-after-inspect"; \
	verdict "REVIEW-R1 shared-name control (E-RACE under the configured name): another writer replaces the volume, under the name the project's config resolves to, after the final identity inspection and before the removal; the replacement survives, the removal names only this run's volume, the run is red" "$$( [ $$rc -ne 0 ] || echo " exit 0")$$(grep -q replaced-after-inspect "$$d/other" 2>/dev/null || echo " no-replacement")$$(grep -qE '^docker volume rm scratch-devseed_postgres-idp-oss-data-v18 ' "$$d/calls" && echo " replacement-name-removed")$$( [ -e "$$d/state/v/scratch-devseed_postgres-idp-oss-data-v18" ] || echo " replacement-gone")$$(grep -q 'check FAILED: teardown' "$$d/out" || echo " no-failed-teardown")$$(retained)"; reset; \
	: > "$$d/replace-exact-after-inspect"; run $(MAKE) --no-print-directory devseed-live; rc=$$?; rm -f "$$d/replace-exact-after-inspect"; \
	verdict "REVIEW-R1 accepted residual (judge ruling Q3 (a)): a writer that copies this run's exact volume name after the final identity inspection has its volume removed by that name, and the teardown is not refused" "$$(grep -q replaced-exact-after-inspect "$$d/other" 2>/dev/null || echo ' no-replacement')$$( [ -z "$$(ls "$$d/state/v" 2>/dev/null)" ] || echo ' replacement-kept')$$(grep -q 'check OK: teardown' "$$d/out" || echo ' teardown-refused')$$( [ ! -e "$$lock" ] || echo ' lock-left')"; \
	: > "$$d/ignore-names"; run $(MAKE) --no-print-directory devseed-live; rc=$$?; rm -f "$$d/ignore-names"; \
	verdict "a recorded volume whose name does not carry the invocation id refuses the WHOLE teardown (nothing removed by name or ID); the run is red and keeps its claim, mutex and record" "$$( [ $$rc -ne 0 ] || echo " exit 0")$$(none_removed)$$( [ -e "$$d/state/v/scratch-devseed_postgres-idp-oss-data-v18" ] || echo " volume-gone")$$(grep -q 'teardown — refused' "$$d/out" || echo " no-refusal-line")$$(retained)"; reset; \
	: 'OSS-CANDIDATE-LIFECYCLE-FIX (SPEC K4, K5): attachments, failed removals, failed records.'; \
	: > "$$d/foreign-member"; run $(MAKE) --no-print-directory devseed-live; rc=$$?; rm -f "$$d/foreign-member"; \
	verdict "SPEC-K5: a container this run did not create, attached to its recorded network or using its recorded volume (outside the project), refuses the WHOLE teardown; nothing is removed; claim, mutex and record kept" "$$( [ $$rc -ne 0 ] || echo " exit 0")$$(none_removed)$$(grep -q 'container fm, not recorded, is attached' "$$d/out" || echo " no-attachment-line")$$( [ -e "$$d/state/c/fm" ] || echo " member-gone")$$(retained)"; reset; \
	: > "$$d/rm-fails"; run $(MAKE) --no-print-directory devseed-live; rc=$$?; rm -f "$$d/rm-fails"; \
	verdict "SPEC-K5: a removal that fails is red, and the claim, the daemon mutex and the record (naming the container left) stay" "$$( [ $$rc -ne 0 ] || echo " exit 0")$$(grep -q "removing this run's container c2 failed" "$$d/out" || echo " no-failure-line")$$( [ -e "$$d/state/c/c2" ] || echo " c2-gone")$$(grep -q '"id":"c2"' "$$lock/manifest.json" 2>/dev/null || echo " c2-not-in-record")$$(retained)"; reset; \
	: > "$$d/rm-noop"; run $(MAKE) --no-print-directory devseed-live; rc=$$?; rm -f "$$d/rm-noop"; \
	verdict "SPEC-K5: a recorded container still present after its removal is red (every recorded object is proved gone before the claim is released); claim, mutex and record kept" "$$( [ $$rc -ne 0 ] || echo " exit 0")$$(grep -q 'still present after its removal: container:c1' "$$d/out" || echo " not-proved-gone")$$(retained)"; reset; \
	: > "$$d/list-fails"; run $(MAKE) --no-print-directory devseed-live; rc=$$?; rm -f "$$d/list-fails"; \
	verdict "SPEC-K4: when what the run created cannot be listed (no record), nothing is removed; the run is red and keeps its claim, mutex and reservation record" "$$( [ $$rc -ne 0 ] || echo " exit 0")$$(none_removed)$$(grep -q 'docker could not list what this run created' "$$d/out" || echo " no-record-failure-line")$$(retained)"; reset; \
	for damage in missing incomplete manifest; do echo "$$damage" > "$$d/record-damage"; run $(MAKE) --no-print-directory devseed-live; rc=$$?; rm -f "$$d/record-damage"; \
		verdict "R-ADV B1 $$damage creation record refuses without label reconstruction" "$$( [ $$rc -ne 0 ] || echo ' exit 0')$$(none_removed)$$(retained)"; reset; done; \
	for label in scratch-devseed unlabelled; do echo "$$label" > "$$d/anonymous"; run $(MAKE) --no-print-directory devseed-live; rc=$$?; rm -f "$$d/anonymous"; \
	verdict "R-ADV B3 $$label anonymous mount refuses with no implicit removal" "$$( [ $$rc -ne 0 ] || echo ' exit 0')$$(none_removed)$$(retained)"; reset; done; \
	: 'OSS-ALLOWLIST-NULL-FIX: the stub config carries command and entrypoint as null, as Compose 5.6.0 writes them, so every green case proves null is accepted; a non-null command or entrypoint is refused below.'; \
	for key in volumes_from external_links links pid ipc uts use_api_socket devices configs secrets provider cap_add security_opt userns_mode volume_driver privileged deploy env_file logging tmpfs command entrypoint; do echo "$$key" > "$$d/config-key"; run $(MAKE) --no-print-directory devseed-live; rc=$$?; rm -f "$$d/config-key"; \
		verdict "R-ADV B2 $$key refuses before startup" "$$( [ $$rc -ne 0 ] || echo ' exit 0')$$(grep -qE ' compose .* (up|build) ' "$$d/calls" && echo ' started')"; done; \
	: 'N3 (OSS-TEARDOWN-MESSAGES): a run that fails before it created anything releases the claim and the mutex; one that created something first keeps them.'; \
	: > "$$d/up-fails"; run $(MAKE) --no-print-directory devseed-live; rc=$$?; rm -f "$$d/up-fails"; \
	verdict "N3: an oss-up that fails before creating anything tears down nothing, proves the project empty and releases the claim and the daemon mutex" "$$( [ $$rc -ne 0 ] || echo ' exit 0')$$(none_removed)$$(grep -q 'check OK: teardown' "$$d/out" || echo ' teardown-not-ok')$$( [ ! -e "$$lock" ] || echo ' lock-left')$$( [ ! -d "$$d/mutex" ] || echo ' mutex-left')"; reset; \
	: > "$$d/up-fails-partial"; run $(MAKE) --no-print-directory devseed-live; rc=$$?; rm -f "$$d/up-fails-partial"; \
	verdict "N3: an oss-up that fails after creating part of the project refuses the whole teardown; nothing removed; claim, mutex and record kept with inspection-only advice" "$$( [ $$rc -ne 0 ] || echo ' exit 0')$$(none_removed)$$(grep -q 'teardown — refused' "$$d/out" || echo ' no-refusal-line')$$(retained)$$(grep -qF 'docker inspect ' "$$d/out" || echo ' no-inspection')"; reset; \
	: > "$$d/bind-mount"; run $(MAKE) --no-print-directory devseed-live; rc=$$?; rm -f "$$d/bind-mount"; \
	verdict "SPEC-K1: a resolved config that mounts a host path is refused before any start, and the claim and mutex are released (nothing was created)" "$$( [ $$rc -ne 0 ] || echo " exit 0")$$(grep -qE ' compose .* (up|build) ' "$$d/calls" && echo " started")$$(grep -q 'a host mount' "$$d/out" || echo " no-refusal-line")$$( [ ! -e "$$lock" ] || echo " lock-left")$$( [ ! -d "$$d/mutex" ] || echo " mutex-left")"; \
	for form in tcp ssh context current unresolved; do \
		rm -f "$$d/endpoint" "$$d/context-fail"; envs=; want="docker context inspect"; \
		case $$form in \
			tcp) envs=DOCKER_HOST=tcp://192.0.2.10:2376; want=;; \
			ssh) envs=DOCKER_HOST=ssh://ci@192.0.2.10; want=;; \
			context) envs=DOCKER_CONTEXT=remote-builder; echo ssh://ci@192.0.2.10 > "$$d/endpoint";; \
			current) echo tcp://192.0.2.10:2375 > "$$d/endpoint";; \
			unresolved) envs=DOCKER_CONTEXT=missing; : > "$$d/context-fail";; \
		esac; \
		run env $$envs $(MAKE) --no-print-directory devseed-live; rc=$$?; \
		got=$$(sed 's/ --format.*//' "$$d/calls" 2>/dev/null | tr '\n' ';' | sed 's/;$$//'); \
		verdict "REVIEW-R2: a $$form endpoint that is not this host's own engine is refused before any other docker call or start, the lock released" "$$( [ $$rc -ne 0 ] || echo " exit 0")$$( [ "$$got" = "$$want" ] || echo " docker-calls:$$got")$$(grep -q "this host's own Docker engine" "$$d/out" || echo " no-topology-line")$$(grep -q '192[.]0[.]2[.]10' "$$d/out" && echo " endpoint-printed")$$( [ ! -e "$$lock" ] || echo " lock-left")"; \
	done; rm -f "$$d/endpoint" "$$d/context-fail"; \
	echo unix:///home/op/.colima/default/docker.sock > "$$d/endpoint"; run env DOCKER_CONTEXT=colima $(MAKE) --no-print-directory devseed-live; rc=$$?; rm -f "$$d/endpoint"; \
	verdict "a local unix-socket context is accepted, and every later docker call, the nested oss-up's included, runs pinned to it with no DOCKER_CONTEXT" "$$(grep -q 'check OK: teardown' "$$d/out" || echo " teardown-not-ok")$$(head -1 "$$d/calls" | grep -q '^docker context inspect ' || echo " endpoint-not-resolved-first")$$(sed 1d "$$d/calls" | grep -v ' dh=unix:///home/op/.colima/default/docker.sock dctx=unset$$' | grep -q . && echo " unpinned-call")$$(grep -qE ' compose .* up ' "$$d/calls" || echo " never-started")"; \
	printf 'override DEVSEED_LIVE_PG_PORT := 5432\n' > "$$d/w/override.mk"; \
	for form in cmd-5513 cmd-5432 cmd-05513 env-e-5513 override-5432; do \
		case $$form in \
			cmd-5513) run $(MAKE) --no-print-directory devseed-live DEVSEED_LIVE_PG_PORT=5513;; \
			cmd-5432) run $(MAKE) --no-print-directory devseed-live DEVSEED_LIVE_PG_PORT=5432;; \
			cmd-05513) run $(MAKE) --no-print-directory devseed-live DEVSEED_LIVE_PG_PORT=05513;; \
			env-e-5513) run env DEVSEED_LIVE_PG_PORT=5513 $(MAKE) -e --no-print-directory devseed-live;; \
			override-5432) run $(MAKE) --no-print-directory -f Makefile -f override.mk devseed-live;; \
		esac; rc=$$?; \
		verdict "REVIEW-R3: a reserved devseed PostgreSQL port ($$form) is refused before any docker call, lock or start" "$$( [ $$rc -ne 0 ] || echo " exit 0")$$( [ ! -s "$$d/calls" ] || echo " docker-called")$$(grep -q 'DEVSEED_LIVE_PG_PORT' "$$d/out" || echo " no-refusal-line")$$( [ ! -e "$$lock" ] || echo " lock-taken")"; \
	done; rm -f "$$d/w/override.mk"; \
	run $(MAKE) --no-print-directory devseed-live DEVSEED_LIVE_PG_PORT=35599; rc=$$?; \
	verdict "a free scratch devseed PostgreSQL port (35599) is carried to every compose call of the run" "$$(grep -q 'check OK: preflight — ports 35599 and 27113 free' "$$d/out" || echo " port-not-checked")$$(grep -qE ' compose .* up ' "$$d/calls" || echo " never-started")$$(grep ' compose ' "$$d/calls" | grep -v ' pg=35599 ' | grep -q . && echo " port-not-carried")"; \
	: 'GUARD-6 F1 (review OSS-MINT-GUARD-5): the exact supported command; every refusal precedes any docker call.'; \
	for selector in --host -H --context -c; do \
		case $$selector in --host|-H) value=tcp://model.invalid:2375;; *) value=remote-model;; esac; \
		command="docker $$selector $$value compose"; \
		for form in env command env-e nested; do \
			case $$form in \
				env) run env COMPOSE_CMD="$$command" $(MAKE) --no-print-directory devseed-live;; \
				command) run $(MAKE) --no-print-directory devseed-live COMPOSE_CMD="$$command";; \
				env-e) run env COMPOSE_CMD="$$command" $(MAKE) -e --no-print-directory devseed-live;; \
				nested) run $(MAKE) --no-print-directory devseed-live COMPOSE_CMD="$$command" IDENTUUM_IDP_COMPOSE_PROJECT=identuum-e2e;; \
			esac; rc=$$?; \
			verdict "GUARD6-F1/$$form/$$selector: refuses COMPOSE_CMD before ANY Docker or nested startup" "$$( [ $$rc -ne 0 ] || echo ' exit-0')$$( [ ! -s "$$d/calls" ] || echo ' docker-called')$$(grep -qE 'REFUS|refus' "$$d/out" || echo ' no-refusal')$$(grep -qE ' compose .* (build|up) ' "$$d/calls" 2>/dev/null && echo ' nested-start-selected-unchecked-engine')"; \
		done; \
	done; \
	: 'GUARD-6 F2: two lock namespaces (two /tmp), one daemon.'; \
	mkdir -p "$$d/ns2/w/deployment" "$$d/ns2/tmp" "$$d/ns2/fixed" "$$d/daemon"; \
	cp "$$d/w/deployment/docker-compose.dev.yml" "$$d/ns2/w/deployment/docker-compose.dev.yml"; \
	sed "s#$$d/fixed/identuum-harness.lock#$$d/ns2/fixed/identuum-harness.lock#" "$$d/w/Makefile" > "$$d/ns2/w/Makefile"; \
	rm -rf "$$d/state" "$$d/calls" "$$d/other"; : > "$$d/pause"; \
	(cd "$$d/w" && env -u MAKEFLAGS -u MAKEOVERRIDES -u MFLAGS -u MAKELEVEL -u COMPOSE_CMD -u DOCKER_HOST -u DOCKER_CONTEXT STUB_D="$$d" STUB_DAEMON="$$d/daemon" TMPDIR="$$d/tmp" PATH="$$d/bin:/usr/bin:/bin" $(MAKE) --no-print-directory devseed-live) > "$$d/first.out" 2>&1 & first=$$!; \
	i=0; while [ ! -e "$$d/ready" ] && kill -0 $$first 2>/dev/null; do i=$$((i+1)); [ $$i -lt 500 ] || break; /bin/sleep 0.01; done; \
	control=; [ -e "$$d/ready" ] && [ -d "$$d/fixed/identuum-harness.lock" ] && kill -0 $$first 2>/dev/null || control=' first-not-holding-local-lock'; \
	(cd "$$d/ns2/w" && env -u MAKEFLAGS -u MAKEOVERRIDES -u MFLAGS -u MAKELEVEL -u COMPOSE_CMD -u DOCKER_HOST -u DOCKER_CONTEXT STUB_D="$$d/ns2" STUB_DAEMON="$$d/daemon" TMPDIR="$$d/ns2/tmp" PATH="$$d/bin:/usr/bin:/bin" $(MAKE) --no-print-directory devseed-live) > "$$d/second.out" 2>&1; rc=$$?; \
	: > "$$d/resume"; wait $$first; rm -f "$$d/pause" "$$d/ready" "$$d/resume"; \
	verdict "GUARD6-F2/separate-namespaces: second refuses while first holds the SAME daemon" "$$control$$( [ $$rc -ne 0 ] || echo ' second-exit-0')$$(grep -qE ' compose |^docker (ps|volume|network|rm) ' "$$d/ns2/calls" 2>/dev/null && echo ' second-resource-call')$$(grep -qE 'mutex|identuum-harness-lock-engine' "$$d/second.out" || echo ' no-mutex-refusal')$$(grep -q 'check OK: teardown' "$$d/first.out" || echo ' first-cleanup-not-run')$$( [ ! -d "$$d/daemon/mutex" ] || echo ' first-mutex-left')"; \
	: 'A stale mutex with no owner process is never broken automatically.'; \
	rm -rf "$$d/mutex"; mkdir "$$d/mutex"; echo stale-owner > "$$d/mutex/labels"; \
	run $(MAKE) --no-print-directory devseed-live; rc=$$?; \
	verdict "GUARD6-F2/stale: refuses without breaking daemon mutex" "$$( [ $$rc -ne 0 ] || echo ' exit-0')$$(grep -q stale-owner "$$d/mutex/labels" 2>/dev/null || echo ' stale-mutex-changed')$$(grep -qE ' compose |^docker (ps|volume|network|rm) ' "$$d/calls" 2>/dev/null && echo ' resource-call')$$(grep -q identuum-harness-lock-engine "$$d/out" || echo ' mutex-not-named')"; \
	rm -rf "$$d/mutex"; \
	: 'The modeled engine changes after the start and the record, before the seed and the teardown.'; \
	: > "$$d/change-engine"; run $(MAKE) --no-print-directory devseed-live; rc=$$?; rm -f "$$d/change-engine"; \
	verdict "GUARD6-F2/engine-change: refuses before any later operation on changed engine" "$$(grep -q guard6-engine-changed "$$d/calls" || echo ' change-not-injected')$$( [ $$rc -ne 0 ] || echo ' exit-0')$$(sed -n '/guard6-engine-changed/,$$p' "$$d/calls" | grep -qE '^docker (rm|volume rm|network rm|.* compose )' && echo ' cleanup-on-changed-engine')$$(grep -qiE 'daemon.*(chang|ident)|engine.*(chang|ident)' "$$d/out" || echo ' no-identity-refusal')$$( [ -d "$$d/mutex" ] || echo ' mutex-released-on-changed-engine')$$(grep -q '^go ' "$$d/other" && echo ' seeded-on-changed-engine')$$( [ -d "$$lock" ] || echo ' claim-released-on-changed-engine')"; \
	rm -f "$$d/engine-id"; reset; \
	run $(MAKE) --no-print-directory devseed-live; rc=$$?; \
	cr=$$(grep -n '^docker container create ' "$$d/calls" | head -1 | cut -d: -f1); fr=$$(grep -nE '^docker (ps|volume|network) | compose ' "$$d/calls" | head -1 | cut -d: -f1); \
	rl=$$(grep -n '^docker container rm guard6-mutex-id' "$$d/calls" | tail -1 | cut -d: -f1); lr=$$(grep -nE '^docker (rm -f|network rm|volume rm) ' "$$d/calls" | tail -1 | cut -d: -f1); \
	verdict "GUARD6-F2/green: the daemon mutex identuum-harness-lock-engine is created (never started, no network, this run's owner and engine labels) after the topology check and the engine id, before any resource call, and removed by its ID after the teardown" "$$(grep -q 'check OK: up' "$$d/out" || echo ' not-started')$$( [ -n "$$cr" ] && [ -n "$$fr" ] && [ "$$cr" -lt "$$fr" ] || echo ' mutex-not-before-resources')$$(head -2 "$$d/calls" | sed -n 2p | grep -q '^docker info ' || echo ' engine-id-not-second')$$( [ -n "$$rl" ] && [ -n "$$lr" ] && [ "$$rl" -gt "$$lr" ] || echo ' mutex-not-released-after-teardown')$$(grep '^docker container create ' "$$d/calls" | grep -- '--name identuum-harness-lock-engine ' | grep -- '--network=none' | grep -q -- 'io.identuum.harness.mutex-owner=[0-9a-f]\{32\} ' || echo ' mutex-args')$$(grep '^docker container create ' "$$d/calls" | grep -- 'io.identuum.harness.project=scratch-devseed ' | grep -q -- 'io.identuum.harness.ports=25513,27113 ' || echo ' mutex-not-labelled-with-project-and-ports')$$(grep -qE '^docker (container )?start ' "$$d/calls" && echo ' mutex-started')$$( [ ! -d "$$d/mutex" ] || echo ' mutex-left')$$(grep -q 'check OK: mutex — released' "$$d/out" || echo ' no-release-line')"; \
	: > "$$d/no-mutex-image"; run $(MAKE) --no-print-directory devseed-live; rc=$$?; rm -f "$$d/no-mutex-image"; \
	verdict "GUARD6-F2/no-image: without the pinned mutex image on the engine, the run is refused before any resource call and pulls nothing" "$$( [ $$rc -ne 0 ] || echo ' exit-0')$$(grep -qE ' compose |^docker (ps|volume|network|rm|pull|container create) ' "$$d/calls" && echo ' acted')$$(grep -q 'docker pull gcr.io/distroless/static-debian12@sha256:' "$$d/out" || echo ' no-pull-advice')$$( [ ! -d "$$d/mutex" ] || echo ' mutex-created')$$( [ ! -e "$$lock" ] || echo ' lock-left')"; \
	: 'GUARD-6 F1, nested: an oss-up under the harness binding re-checks the command, the endpoint, the engine and the mutex itself.'; \
	bind="IDENTUUM_HARNESS_ENGINE_ID=guard6-engine-a IDENTUUM_HARNESS_MUTEX_ID=guard6-mutex-id DOCKER_HOST=unix:///var/run/docker.sock IDENTUUM_IDP_COMPOSE_PROJECT=scratch-e2e"; \
	mkdir "$$d/mutex"; \
	for selector in --host -H --context -c; do \
		case $$selector in --host|-H) value=tcp://model.invalid:2375;; *) value=remote-model;; esac; \
		run env $$bind $(MAKE) --no-print-directory oss-up COMPOSE_CMD="docker $$selector $$value compose"; rc=$$?; \
		verdict "GUARD6-F1/nested-oss-up/$$selector: a bound oss-up refuses a COMPOSE_CMD that is not docker compose before any docker call" "$$( [ $$rc -ne 0 ] || echo ' exit-0')$$( [ ! -s "$$d/calls" ] || echo ' docker-called')$$(grep -q 'REFUSED under the harness binding' "$$d/out" || echo ' no-refusal')"; \
	done; \
	for form in context engine mutex project; do \
		case $$form in \
			context) run env $$bind DOCKER_CONTEXT=remote-model $(MAKE) --no-print-directory oss-up;; \
			project) run env $$bind $(MAKE) --no-print-directory oss-up IDENTUUM_IDP_COMPOSE_PROJECT=identuum-e2e;; \
			engine) run env $$bind IDENTUUM_HARNESS_ENGINE_ID=guard6-engine-z $(MAKE) --no-print-directory oss-up;; \
			mutex) run env $$bind IDENTUUM_HARNESS_MUTEX_ID=another-mutex $(MAKE) --no-print-directory oss-up;; \
		esac; rc=$$?; \
		verdict "GUARD6-F1/nested-oss-up/$$form: a bound oss-up whose $$form is not the harness's is refused before any build or start" "$$( [ $$rc -ne 0 ] || echo ' exit-0')$$(grep -q ' compose ' "$$d/calls" 2>/dev/null && echo ' compose-called')$$(grep -q 'REFUSED under the harness binding' "$$d/out" || echo ' no-refusal')"; \
	done; \
	run env $$bind $(MAKE) --no-print-directory oss-up; rc=$$?; \
	verdict "GUARD6-F1/nested-oss-up/bound: a bound oss-up whose command, endpoint, engine and mutex are the harness's builds and starts" "$$( [ $$rc -eq 0 ] || echo " exit $$rc")$$(grep -qE ' compose .* build ' "$$d/calls" || echo ' not-built')$$(grep -qE ' compose .* up ' "$$d/calls" || echo ' not-started')"; \
	rm -rf "$$d/mutex"; \
	run $(MAKE) --no-print-directory devseed-live 'DEV_COMPOSE=docker --host tcp://model.invalid:2375 compose -p scratch-devseed -f deployment/docker-compose.dev.yml'; rc=$$?; \
	verdict "GUARD6-F1/dev-compose: a command-line DEV_COMPOSE does not reach the nested oss-up, which starts with the fixed command" "$$(grep -q 'check OK: up' "$$d/out" || echo ' up-failed')$$(grep -q 'guard6-selector' "$$d/other" 2>/dev/null && echo ' selector-reached-docker')$$(grep -qE ' compose .* up ' "$$d/calls" || echo ' never-started')"; \
	: 'OSS-CANDIDATE-LIFECYCLE-FIX (SPEC K3): fast-up of a scratch project reuses only a recorded scratch PostgreSQL, never a Compose start.'; \
	cid=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef; good="$$cid|/scratch-mint-pg|true|{\"5432/tcp\":[{\"HostIp\":\"127.0.0.1\",\"HostPort\":\"36599\"}]}|[]"; \
	for form in no-id short-id absent named-other wide-port bind-mount not-ready reuse default-dev; do \
		rm -f "$$d/pg-inspect" "$$d/pg-ready"; id=$$cid; pg=36599; proj=scratch-mint; \
		case $$form in \
			no-id) id=;; short-id) id=0123456789ab;; absent) ;; \
			named-other) echo "$$good" | sed 's#/scratch-mint-pg#/identuum-idp-oss-dev-postgres#' > "$$d/pg-inspect"; : > "$$d/pg-ready";; \
			wide-port) echo "$$good" | sed 's#127.0.0.1#0.0.0.0#' > "$$d/pg-inspect"; : > "$$d/pg-ready";; \
			bind-mount) echo "$$good" | sed 's#|\[\]$$#|[{"Type":"bind","Source":"/tmp"}]#' > "$$d/pg-inspect"; : > "$$d/pg-ready";; \
			not-ready) echo "$$good" > "$$d/pg-inspect";; \
			reuse) echo "$$good" > "$$d/pg-inspect"; : > "$$d/pg-ready";; \
			default-dev) proj=; : > "$$d/pg-ready";; \
		esac; \
		run env IDENTUUM_IDP_COMPOSE_PROJECT=$$proj FAST_UP_PG_CONTAINER=$$id $(MAKE) --no-print-directory fast-up DEV_PG_HOST_PORT=$$pg; rc=$$?; \
		case $$form in \
			reuse) verdict "SPEC-K3/fast-up/reuse: a scratch project reuses the recorded scratch PostgreSQL only after its full ID, name, state, single loopback port and mounts are checked on the engine; no Compose call" "$$( [ $$rc -eq 0 ] || echo " exit $$rc")$$(grep -q ' compose ' "$$d/calls" && echo ' compose-called')$$(grep -q 'REUSING the recorded scratch PostgreSQL' "$$d/out" || echo ' no-reuse-line')$$(grep -q "^docker container inspect .* $$cid" "$$d/calls" || echo ' identity-not-inspected')";; \
			default-dev) verdict "SPEC-K3/fast-up/default-dev: the default dev project keeps its compatible-server reuse (it is not a candidate path)" "$$( [ $$rc -eq 0 ] || echo " exit $$rc")$$(grep -q 'compatible PostgreSQL already answers' "$$d/out" || echo ' no-reuse-line')$$(grep -q ' compose ' "$$d/calls" && echo ' compose-called')";; \
			*) case $$form in no-id) why='is not a full container ID';; short-id) why='is not a full 64-character container ID';; absent) why='is not on this engine';; named-other) why='is not named scratch-';; \
				wide-port) why='does not publish exactly 5432/tcp on 127.0.0.1:36599';; bind-mount) why='mounts a host path';; *) why='does not answer on 127.0.0.1:36599';; esac; \
				verdict "SPEC-K3/fast-up/$$form: a scratch project is refused ($$why) with no Compose start and nothing stopped" "$$( [ $$rc -ne 0 ] || echo ' exit-0')$$(grep -q ' compose ' "$$d/calls" && echo ' compose-called')$$(grep -q "fast-up: REFUSED — .*$$why" "$$d/out" || echo ' no-refusal')";; \
		esac; \
	done; rm -f "$$d/pg-inspect" "$$d/pg-ready"; \
	run env DEV_PG_HOST_PORT=36599 $(MAKE) --no-print-directory test-full-mint; rc=$$?; \
	verdict "SPEC-K3/test-full-mint: a mint on the default dev project is refused before anything runs" "$$( [ $$rc -ne 0 ] || echo ' exit-0')$$( [ ! -s "$$d/calls" ] || echo ' docker-called')$$(grep -q 'test-full-mint: REFUSED — the mint runs only against a recorded scratch PostgreSQL' "$$d/out" || echo ' no-refusal')"; \
	: > "$$d/pg-ready"; run env DEV_PG_HOST_PORT=36599 IDENTUUM_IDP_COMPOSE_PROJECT=scratch-mint $(MAKE) --no-print-directory test-full-mint; rc=$$?; rm -f "$$d/pg-ready"; \
	verdict "SPEC-K3/test-full-mint: a scratch mint without its recorded PostgreSQL is refused at fast-up, with no Compose start, though a server answers the port" "$$( [ $$rc -ne 0 ] || echo ' exit-0')$$(grep -q ' compose ' "$$d/calls" && echo ' compose-called')$$(grep -q 'FAST_UP_PG_CONTAINER is not a full container ID' "$$d/out" || echo ' no-refusal')$$(grep -q 'devseed-live' "$$d/out" && echo ' went-on')"; \
	if [ $$fails -ne 0 ]; then echo "check FAILED: compose-pin-selftest $$fails of $$n case(s)"; exit 1; fi; \
	echo "check OK: compose-pin-selftest $$n case(s): oss-up and devseed-live pin their compose project, clear inherited compose settings and never act on resources they did not create"

## record-home-paths (OSS-GATE-TIDY, 2026-10-05): a TRACKED gate record
## (git ls-files GATE-RUN*.txt) never carries a machine's user directory — a
## /Users/<name>/ or /home/<name>/ path, or $HOME/ when the caller has one —
## because a witness commits that record for every reader. Untracked records
## (GATE-RUN.ci.txt, the integration record) are not judged; no tracked record
## at all cannot pass. Planned in verify and ci-verify; lictor's environment
## allowlist may leave $HOME unset there, so the two literal shapes carry it.
.PHONY: record-home-paths record-home-paths-selftest
RECORD_REPO ?= $(CURDIR)
record-home-paths:
	@repo="$(RECORD_REPO)"; files="$$(git -C "$$repo" ls-files 'GATE-RUN*.txt')"; \
	[ -n "$$files" ] || { echo "check FAILED: record-home-paths — no tracked GATE-RUN*.txt in $$repo; nothing to judge is not a pass"; exit 2; }; \
	pat='/Users/[^/[:space:]]+/|/home/[^/[:space:]]+/'; \
	case "$${HOME:-/}" in /) ;; *) pat="$$pat|$$(printf '%s' "$${HOME%/}" | sed 's/[][\.*^$$+?(){}|]/\\&/g')/" ;; esac; \
	hits="$$(cd "$$repo" && grep -nHE -- "$$pat" $$files)"; \
	if [ -n "$$hits" ]; then echo "check FAILED: record-home-paths — a tracked gate record carries a home path; a committed record must not name a machine's user directory:"; printf '%s\n' "$$hits" | cut -c1-200; exit 1; fi; \
	echo "check OK: record-home-paths — $$(printf '%s\n' $$files | grep -c .) tracked record(s), none names a user home directory (the Users or home shapes, or HOME); this line spells no path, because a witness commits it into the record it judges"

## record-home-paths-selftest (OSS-GATE-TIDY, 2026-10-05): fixture repositories
## (git init, records staged, nothing committed) run through record-home-paths:
## a clean record passes; /Users/<name>/, /home/<name>/ and $HOME/ each fail;
## an untracked record is not judged; no tracked record cannot pass.
record-home-paths-selftest:
	@d=$$(mktemp -d "$${TMPDIR:-/tmp}/home-paths.XXXXXX"); trap 'rm -rf "$$d"' EXIT; n=0; fails=0; \
	expect() { want=$$1; label=$$2; shift 2; n=$$((n + 1)); out=$$("$$@" 2>&1); rc=$$?; line=OK; [ $$want -eq 0 ] || line=FAILED; \
		if [ $$rc -eq $$want ] && printf '%s\n' "$$out" | grep -q "^check $$line: record-home-paths"; then echo "  ok    exit $$rc  $$label"; else echo "  FAIL  want exit $$want and a 'check $$line' line, got exit $$rc  $$label"; fails=$$((fails + 1)); fi; }; \
	rec() { mkdir -p "$$d/$$1"; git -C "$$d/$$1" init -q; printf 'schema: gate-run.v1\n%s\n' "$$3" > "$$d/$$1/$$2"; git -C "$$d/$$1" add "$$2"; }; \
	rec clean GATE-RUN.txt 'target: vet exit=0'; \
	rec users GATE-RUN.txt 'evidence: /Users/alice/go/bin/staticcheck'; \
	rec home GATE-RUN.integration.txt 'evidence: /home/runner/work/identuum-idp-oss'; \
	rec envhome GATE-RUN.txt 'evidence: /opt/agent/cache/go-build'; \
	rec untracked GATE-RUN.txt 'target: vet exit=0'; printf '/Users/alice/x\n' > "$$d/untracked/GATE-RUN.scratch.txt"; \
	mkdir -p "$$d/none"; git -C "$$d/none" init -q; \
	expect 0 "a record with no home path" $(MAKE) --no-print-directory record-home-paths RECORD_REPO="$$d/clean"; \
	expect 2 "/Users/<name>/ in GATE-RUN.txt" $(MAKE) --no-print-directory record-home-paths RECORD_REPO="$$d/users"; \
	expect 2 "/home/<name>/ in GATE-RUN.integration.txt" $(MAKE) --no-print-directory record-home-paths RECORD_REPO="$$d/home"; \
	expect 2 "\$$HOME/ (HOME=/opt/agent)" env HOME=/opt/agent $(MAKE) --no-print-directory record-home-paths RECORD_REPO="$$d/envhome"; \
	expect 0 "an untracked record is not judged" $(MAKE) --no-print-directory record-home-paths RECORD_REPO="$$d/untracked"; \
	okline=$$($(MAKE) --no-print-directory record-home-paths RECORD_REPO="$$d/clean" 2>&1 | grep '^check OK: record-home-paths'); \
	rec ownline GATE-RUN.txt "evidence: [record-home-paths] $$okline"; \
	expect 0 "its own OK line, committed into the record by a witness" $(MAKE) --no-print-directory record-home-paths RECORD_REPO="$$d/ownline"; \
	expect 2 "no tracked record cannot pass" $(MAKE) --no-print-directory record-home-paths RECORD_REPO="$$d/none"; \
	expect 0 "this repository" $(MAKE) --no-print-directory record-home-paths; \
	if [ $$fails -ne 0 ]; then echo "record-home-paths-selftest: FAIL — $$fails of $$n case(s) wrong" >&2; exit 1; fi; \
	echo "check OK: record-home-paths-selftest $$n case(s), refusals and passes proven"

## test-full-dispatch-selftest (OSS-GATE-TIDY, 2026-10-05; queue :8): test-full's
## tier branch, proven without a stack or a container. It runs the UNCHANGED
## test-full recipe of $(DISPATCH_MAKEFILE) from a fixture directory whose
## ../identuum-ui is an empty directory, with a stub `go` first on PATH that
## prints a fixture classifier line and exit code, and MAKE= a stub that only
## prints the dispatch it was handed. Cases: "e2e-quick owed" dispatches
## test-full-mint E2E_TIER=quick; an e2e-full line, an unknown line and exit 3
## dispatch E2E_TIER=full; exit 0 dispatches nothing. What it cannot prove:
## that a real quick-class change makes the classifier print that line, and
## that identuum-ui's e2e-quick then runs green (queue :8).
.PHONY: test-full-dispatch-selftest
DISPATCH_MAKEFILE ?= $(CURDIR)/Makefile
test-full-dispatch-selftest:
	@d=$$(mktemp -d "$${TMPDIR:-/tmp}/dispatch.XXXXXX"); trap 'rm -rf "$$d"' EXIT; n=0; fails=0; \
	mkdir -p "$$d/bin" "$$d/oss" "$$d/identuum-ui"; \
	printf '#!/bin/sh\nprintf "%%s\\n" "$$FIXTURE_LINE"\nexit "$$FIXTURE_RC"\n' > "$$d/bin/go"; \
	printf '#!/bin/sh\necho "dispatch: $$*"\n' > "$$d/bin/probe"; chmod +x "$$d/bin/go" "$$d/bin/probe"; \
	case_() { n=$$((n + 1)); out=$$(cd "$$d/oss" && env PATH="$$d/bin:$$PATH" FIXTURE_LINE="$$2" FIXTURE_RC="$$3" $(MAKE) --no-print-directory -f "$(DISPATCH_MAKEFILE)" test-full MAKE="$$d/bin/probe" 2>&1); \
		if printf '%s\n' "$$out" | grep -qF -- "$$4" && { [ -z "$$5" ] || ! printf '%s\n' "$$out" | grep -qF -- "$$5"; }; then echo "  ok    $$1"; \
		else fails=$$((fails + 1)); echo "  FAIL  $$1: wanted \"$$4\"$${5:+ and no \"$$5\"}"; printf '%s\n' "$$out" | sed 's/^/        /'; fi; }; \
	case_ "e2e-quick owed -> E2E_TIER=quick" "check OK: mint-reachability MINT REQUIRED — 1 reaching path; e2e-quick owed: src/x.ts" 1 "dispatch: --no-print-directory test-full-mint E2E_TIER=quick" ""; \
	case_ "e2e-full owed -> E2E_TIER=full" "check OK: mint-reachability MINT REQUIRED — 1 reaching path; e2e-full owed: Makefile" 1 "dispatch: --no-print-directory test-full-mint E2E_TIER=full" "E2E_TIER=quick"; \
	case_ "unknown line, exit 3 -> E2E_TIER=full" "mint-reachability: cannot evaluate" 3 "dispatch: --no-print-directory test-full-mint E2E_TIER=full" "E2E_TIER=quick"; \
	case_ "exit 0 -> no dispatch" "check OK: mint-reachability SKIPPABLE — tier none" 0 "test-full: MINT SATISFIED" "dispatch:"; \
	n=$$((n + 1)); order=$$(awk '$$0=="test-full-mint:"{r=1;next} r&&/^[^\t#]/{r=0} r&&/\$$\(MAKE\).*devseed-live/&&!d{d=NR} r&&/\$$\(MAKE\).*e2e-\$$\(E2E_TIER\)/&&!e{e=NR} END{print (d && e && d<e) ? "before" : "not-before"}' "$(DISPATCH_MAKEFILE)"); \
	if [ "$$order" = before ]; then echo "  ok    test-full-mint runs devseed-live before the e2e half (owner ruling v)"; \
	else fails=$$((fails + 1)); echo "  FAIL  test-full-mint does not run devseed-live before the e2e half (owner ruling v): a red devseed-live after a green e2e record leaves that record as the mint"; fi; \
	if [ $$fails -ne 0 ]; then echo "test-full-dispatch-selftest: FAIL — $$fails of $$n case(s) wrong" >&2; exit 1; fi; \
	echo "check OK: test-full-dispatch-selftest $$n case(s): quick only when e2e-quick is owed, full otherwise, nothing on 0 (no stack, no container)"

.PHONY: witness witness-parity

## witness-check (THE-UNEARNED-WITNESS, 2026-09-04): has this tree earned a
## witness cycle? Run it BEFORE cutting one. A witness says "make verify was
## green on THIS tree" and costs a full verify, so it is worth spending only
## when the tree changed in a way a verify can judge.
##
## MEASURED from this repository: 50 witness commits, NINE record-only commits
## (eight manifest re-bases, one mint marker), and one cycle whose entire diff
## was records. Records are evidence; evidence does not earn a cycle.
##
## Exit 0 earned, 11 refused, 1 undecidable — and undecidable means GO AHEAD:
## this check exists to save a cycle, never to block one it cannot reason
## about. Rule WITNESS-EARNS-ITS-CYCLE-1.
witness-check:
	@go run ./tools/witness-earns --repo .

verify:
	# OSS-LICTOR-VERIFY (2026-10-02): driven by `lictor witness run --all`
	# (lictor v0.4.4), byte-equal to the scripts/verify-all.sh it replaces on
	# records, exits and dirty-tree streams; on a clean tree its console differs
	# only as lictor declares (routing to stderr, a repository line, a summary).
	# THE-UNWITNESSED-GREEN: the declared targets are recorded so a committed-head run leaves a record
	# (GATE-RUN.txt): per-target exit codes, the five tool versions with
	# paths, the tools' own count lines, and a digest of the tree the run
	# saw (minus the record itself). An interrupted run reads
	# INCOMPLETE, never green.
	#
	# rulefloor-check sits EARLY on purpose: it is cheap (hash pins + four
	# standalone go test -run rows), so a tampered proof is reported early;
	# remaining targets still run to give the complete verdict. Sibling-coupled,
	# so ci-verify subtracts it — see the ci.yml header enumeration.
	#
	# fmt-check / vet / go build / go test are NOT missing: `repo-green`
	# runs all four as ONE named floor (order F, THE-FLIPPED-CELLS). tagged-vet
	# stays because repo-green runs UNTAGGED and cannot see //go:build files.
	#
	# P3-9: the boundary policy EXISTS and is ENFORCED. boundaries.json
	# (committed at the repo root — .gograph/ is gitignored) is checked after
	# the precise build, because the CLI reads the persisted graph: a stale
	# graph reports stale imports. Red-proved: internal/crypto importing
	# internal/api fails with [boundary_violation]. Local-only like the other
	# gograph lines; ci-verify documents the omission.
	+@$(call LICTOR_ASSERT,verify); \
	$(GATE_RECORD_DRIVER) "$(LICTOR)" witness run --all --repo "$(CURDIR)" \
		--record GATE-RUN.txt --label "identuum-idp-oss make verify" \
		--requires gograph-boundaries:gograph-build -- \
		$(VERIFY_PLAN)

# One authoritative argument vector; drivers enter through the target above.
define VERIFY_PLAN
		'tool-versions=$(MAKE) --no-print-directory tool-versions' \
		'toolchain-parity=$(MAKE) --no-print-directory toolchain-parity' \
		'ci-witness=$(MAKE) --no-print-directory ci-witness' \
		'mint-decide=$(MAKE) --no-print-directory mint-report' \
		'witness-mint-test=$(MAKE) --no-print-directory witness-mint-test' \
		'script-tests=$(MAKE) --no-print-directory script-tests' \
		'openapi-check=$(MAKE) --no-print-directory openapi-check' \
		'repo-green=$(MAKE) --no-print-directory repo-green' \
		'tracked-binary-check=$(MAKE) --no-print-directory tracked-binary-check' \
		'record-home-paths=$(MAKE) --no-print-directory record-home-paths' \
		'ui-vendor-check=$(MAKE) --no-print-directory ui-vendor-check' \
		'notices-check=$(MAKE) --no-print-directory notices-check' \
		'credential-transparency=$(MAKE) --no-print-directory credential-transparency' \
		'workflow-yaml=$(MAKE) --no-print-directory workflow-yaml' \
		'workflow-yaml-parity=$(MAKE) --no-print-directory workflow-yaml-parity' \
		'rulefloor-check=$(MAKE) --no-print-directory rulefloor-check' \
		'ledger-diff-gate=$(MAKE) --no-print-directory ledger-diff-gate' \
		'image-base-check=$(MAKE) --no-print-directory image-base-check' \
		'api-surface=$(MAKE) --no-print-directory api-surface' \
		'vet-integration=$(MAKE) --no-print-directory vet-integration' \
		'doccomment-check=$(MAKE) --no-print-directory doccomment-check' \
		'r-suite=$(MAKE) --no-print-directory r-suite' \
		'image-base-parity=$(MAKE) --no-print-directory image-base-parity' \
		'witness-parity=$(MAKE) --no-print-directory witness-parity' \
		'image-policy-restate-check=$(MAKE) --no-print-directory image-policy-restate-check' \
		'distroless-exec-check=$(MAKE) --no-print-directory distroless-exec-check' \
		'clock-fuse-report=$(MAKE) --no-print-directory clock-fuse-report' \
		'clock-fuse-gate=$(MAKE) --no-print-directory clock-fuse-gate' \
		'tagged-vet=$(MAKE) --no-print-directory tagged-vet' \
		'integration-inventory=$(MAKE) --no-print-directory integration-inventory' \
		'gograph-capabilities=gograph capabilities --intention "repo-local make verify"' \
		'gograph-build=gograph build . --precise' \
		'gograph-boundaries=gograph boundaries --config boundaries.json' \
		'go-mod-tidy-diff=go mod tidy -diff' \
		'staticcheck=staticcheck ./...' \
		'govulncheck=govulncheck ./...' \
		'grype-scan=$(MAKE) grype-scan'
endef

## ci-verify: CI mirror of `make verify` MINUS CI_VERIFY_SUBTRACTS and PLUS
## CI_VERIFY_ADDS, both declared once below CI_VERIFY_PLAN and held to the two
## plans by script-tests. This lead sentence enumerated them twice and was
## wrong both times: "Both omissions" against a third (2026-08-04), then "THREE
## omissions" against fourteen subtracted and four added (re-measured
## OSS-QUEUE-TRIAGE, 2026-10-02). The reasons follow; a name declared there is
## never silent drift.
##
## ledger-diff-gate: its base is the previous ACCEPTED witness commit, measured
## from the local witness chain that CI's single-commit checkout does not carry
## (see the gate-witness tie-note); the same reconciliation runs in every local
## `make verify` and its evidence line is in the committed GATE-RUN.txt.
##
## gograph stays a LOCAL-ONLY developer tool by decision (owner-distributed
## via the brew cask; CI does not install it), so its `capabilities` +
## `build` steps do not run here.
## The recorded mint-decide report is also local-only: it reads the sibling's
## e2e record and both checkout histories, which this single-repository CI
## job does not have. The local witness prerequisite owns that decision.
## witness-mint-test (THE-THREE-SMALL-ONES-OSS, 2026-09-19) is local-only for
## the same reason one step further: it proves that local-only machinery —
## mint-decide, witness, witness-mint-check — and a proof of a recipe runs
## where the recipe runs.
##
## govulncheck is omitted for a different reason: CI runs it as its own JOB.
## A vulnerability database moves under a tree that has not moved, so a red scan
## in a dedicated job leaves the build/test signal intact and "the code broke"
## stays distinguishable from "the world changed". Running it here as well would
## give one command two consumers in the same pipeline. `verify` still runs it,
## so the local full chain is unaffected.
##
## THIRD OMISSION: wiki-fresh, removed from this target 2026-08-01
## (FRESH-CI-ONE). The sentence that used to sit here was ACCURATE and that was
## the problem — it read "wiki-fresh (self-skips when ../wiki is absent, as in a
## CI checkout)", which is a plain statement that the call can never fail where
## this target actually runs. Proven, not assumed: `make ci-verify
## WIKI_DIR=/nonexistent-wiki` prints one SKIPPED line and exits 0. A step that
## cannot fail in the only environment that runs it is decoration, and a
## decoration in a gate list is worse than an absence: it reads like coverage.
## (OSS-GATE-TIDY, 2026-10-05: `verify` no longer runs it either, P-066.)
## `verify` still runs it, so the local chain is unchanged, and the four other
## repos in the fleet already kept it out of their CI target — this makes all
## five agree.
##
## THE ALTERNATIVE, KILLED IN WRITING so it is not re-proposed: "check the wiki
## out in CI so the gate can fire". It fails on three counts. (1) NOT MET, AND
## THE DRIFT IS NOW MEASURED — updated 2026-08-04 (THE-SEALED-GATES). This leg
## has now been wrong twice in opposite directions, which is the point. It first
## read "the published wiki is 30 commits behind local". The 2026-08-02 push
## killed that, and it was rewritten to "published and local are both fb27ec9
## today" — a FIXED POINT, and fixed points go stale. That sentence is false as
## of 2026-08-04: origin/main is still fb27ec9, local is be96ea2, and the wiki
## is FIFTY-FIVE commits ahead. Two days, no push, 55 commits of drift.
##
## So do not re-state this leg as a number or a SHA; state the mechanism. The
## precondition was never "the wiki is level once", it was LOCKSTEP — pins never
## behind the code they describe, held there by something. A one-time push is a
## coincidence of timing, not a mechanism: the next slice that commits code and
## wiki together puts them out of step again, and nothing pushes the wiki
## automatically. This paragraph predicted exactly that in writing on 2026-08-02
## and the 55 commits above are that prediction coming true on schedule. So a CI
## gate reading the published wiki would be green today and red on the next
## ordinary day, which is worse than reliably red — an intermittent gate teaches
## people that its failures are noise.
##
## To re-measure rather than trust this comment (the whole lesson of the leg):
##   git -C wiki rev-list --count origin/main..HEAD
##
## THE CONDITIONAL, replacing a claim that was true in general and false here
## (LOCKSTEP-DECIDE, 2026-08-02). This leg used to end "this leg is the one that
## could actually be fixed". That is TRUE FOR A TEAM THAT PUSHES CONTINUOUSLY —
## where committing and publishing are one act, a lockstep check is cheap and the
## leg really does fall. It is FALSE HERE, and the reason is the PUSH POLICY, not
## the mechanism: this workspace commits locally and pushes only when the owner
## says so. A lockstep gate under that policy goes RED at the first wiki commit
## of every slice and STAYS red until a push that may be days away. That is this
## paragraph's own objection — a gate that is red by default is turned off within
## a week — turned around and aimed at us. The mechanism exists and works
## (wiki/tools/wiki-unpushed-check.sh, opt-in, wired into nothing); what does not
## exist is a push cadence that would make gating on it anything other than
## self-defeating. **So leg (1) is not wishful and not fixable-here: it is
## CONDITIONAL ON A POLICY THIS WORKSPACE HAS DELIBERATELY CHOSEN NOT TO HAVE.**
## Change the push policy and this leg falls on its own; leave it and no mechanism
## rescues it. (2) The wiki is
## private, so CI would need a credential it does not currently have; this
## workflow has zero secrets today and that is worth more than this gate. (3) It
## inverts the authoring order: a slice updates code and wiki together, so a gate
## reading the PUBLISHED wiki demands the wiki land BEFORE the code PR merges — a
## cross-repo ordering constraint nothing else in this workspace imposes. It
## becomes the right answer when all three are MET — not momentarily true:
## something KEEPS the wiki in lockstep (not "the wiki happened to be pushed"),
## CI can read it without a new long-lived secret, and someone has decided the
## wiki-before-code merge order is acceptable. Until then the gate belongs in
## `verify`, where the sibling checkout is real.
##
## THE ONE-REPO RULE (THE-CI-SHAPE, 2026-08-07). Every target in this recipe
## must be runnable from a checkout of THIS repository alone. CI checks out one
## repo; the sibling wiki does not exist there, and the first push that carried
## a $(WIKI_TOOLS) dependency proved it the hard way:
##
##   bash: .../identuum-idp-oss/../wiki/tools/repo-green-gate.sh:
##     No such file or directory
##   make[1]: *** [Makefile:112: repo-green] Error 127
##
## So the wiki-coupled gates live in `verify` (where the sibling checkout is
## real) and are EXCLUDED here, enumerated: clock-fuse-gate (and wiki-fresh
## until OSS-GATE-TIDY moved it out of verify altogether, P-066) —
## and repo-green, which since THE-GREEN-CONSUMERS (2026-09-21) runs the
## installed lictor and COULD run here, but stays out BY CHOICE: nothing it
## measures is lost in CI — its four floors (fmt, build, test, vet) are
## already explicit steps of this recipe, and a floor run twice on one
## runner proves nothing the once did not.
## clock-fuse-gate's snapshot comparison IS lost in CI (recorded residue,
## ledger row REL-CI-WIKI-COUPLING); clock-fuse-report — self-contained, and
## hard-failing on tool error and the deadline arm — stays.
##
## Everything else is byte-identical to `verify`: image-base-check, go mod tidy
## -diff, go build, go test with the 120s timeout, staticcheck, and grype-scan.
## Keeping CI on this target instead of hand-rolled steps is what stops CI from
## drifting away from `verify`.
ci-verify:
	# THE-UNWITNESSED-MIRROR: ci-verify was the last gate entry point that
	# left no record. Same targets in the same order, driven through the
	# witness; CI uploads GATE-RUN.ci.txt (gitignored — a local run must not
	# read as an edit to the committed verify record's tree) as a workflow
	# artifact, tied to the checkout COMMIT via GATE_WITNESS_TIE=commit set
	# in ci.yml. This recipe is the ONE declared CI target set the record
	# cites: a name absent from this plan is a documented subtraction from
	# `verify` (see the header comments above), a planned name with no
	# recorded run reads INCOMPLETE.
	#
	# THE-TOOLING-UPGRADE: CI runs the REAL rulefloor check. The homegrown
	# tools/rulefloorlite subset is DELETED — it reimplemented extraction
	# with pre-v0.3.0 string-marker semantics and measurably diverged from
	# the real extractor (a marker inside a Go string literal satisfied
	# lite and failed rulefloor v0.3.0), and it never verified hashes.
	# CI builds the binary from the pinned, checksum-verified release tarball
	# declared in ci.yml; locally RULEFLOOR_RESOLVE falls back to PATH/sibling.
	#
	# P2-17 (owner ruling): -race runs HERE, in CI's aggregate. It ran NOWHERE —
	# not verify, not ci-verify, zero occurrences in this Makefile — so "CI is
	# weaker than verify" was wrong twice: nothing had the race detector at all.
	# The timeout rises 120s -> 300s FOR go-test-race ONLY because an
	# instrumented run is 2-10x slower. The plain 120s run lives in `verify`
	# (via repo-green, local-only by choice since THE-CI-SHAPE and run by the
	# installed lictor since THE-GREEN-CONSUMERS); in CI this instrumented
	# superset is the test floor.
	+@$(call LICTOR_ASSERT,ci-verify); \
	$(GATE_RECORD_DRIVER) "$(LICTOR)" witness run --repo "$(CURDIR)" \
		--record GATE-RUN.ci.txt --label "$(CI_VERIFY_GATE)" \
		--env IDENTUUM_IDP_TEST_DATABASE_URL --env IDENTUUM_IDP_REQUIRE_DB_TESTS \
		--env IDENTUUM_IDP_ALLOW_MULTI_REPLICA --env DEV_PG_HOST_PORT \
		--cites 'the ci-verify target in Makefile is the single declared CI gate set; its subtraction from verify is documented in the ci-verify header comments' -- \
		$(CI_VERIFY_PLAN)

# One authoritative argument vector; drivers enter through the target above.
define CI_VERIFY_PLAN
		'script-tests=$(MAKE) --no-print-directory script-tests' \
		'tracked-binary-check=$(MAKE) --no-print-directory tracked-binary-check' \
		'record-home-paths=$(MAKE) --no-print-directory record-home-paths' \
		'credential-transparency=$(MAKE) --no-print-directory credential-transparency' \
		'workflow-yaml=$(MAKE) --no-print-directory workflow-yaml' \
		'workflow-yaml-parity=$(MAKE) --no-print-directory workflow-yaml-parity' \
		'openapi-check=$(MAKE) --no-print-directory openapi-check' \
		'rulefloor-check=$(MAKE) --no-print-directory rulefloor-check' \
		'image-base-check=$(MAKE) --no-print-directory image-base-check' \
		'api-surface=$(MAKE) --no-print-directory api-surface' \
		'fmt-check=$(MAKE) --no-print-directory fmt-check' \
		'vet=$(MAKE) --no-print-directory vet' \
		'vet-integration=$(MAKE) --no-print-directory vet-integration' \
		'doccomment-check=$(MAKE) --no-print-directory doccomment-check' \
		'r-suite=$(MAKE) --no-print-directory r-suite' \
		'image-base-parity=$(MAKE) --no-print-directory image-base-parity' \
		'witness-parity=$(MAKE) --no-print-directory witness-parity' \
		'image-policy-restate-check=$(MAKE) --no-print-directory image-policy-restate-check' \
		'distroless-exec-check=$(MAKE) --no-print-directory distroless-exec-check' \
		'clock-fuse-report=$(MAKE) --no-print-directory clock-fuse-report' \
		'tagged-vet=$(MAKE) --no-print-directory tagged-vet' \
		'integration-inventory=$(MAKE) --no-print-directory integration-inventory' \
		'notices-check=$(MAKE) --no-print-directory notices-check' \
		'go-mod-tidy-diff=go mod tidy -diff' \
		'go-build=go build ./...' \
		'go-test-race=$(MAKE) --no-print-directory go-test-race' \
		'staticcheck=staticcheck ./...' \
		'grype-scan=$(MAKE) grype-scan'
endef

## go-test-race (OSS-CI-ENV, 2026-10-03): ci-verify's test floor. lictor runs
## each plan entry with its environment allowlist; since LICTOR-ADOPT-0.4.5
## (2026-10-06) ci-verify declares the CI job's DB settings
## (IDENTUUM_IDP_TEST_DATABASE_URL, IDENTUUM_IDP_REQUIRE_DB_TESTS,
## IDENTUUM_IDP_ALLOW_MULTI_REPLICA) with `--env NAME`, so they reach this
## recipe by name and the record states each one present or absent, never its
## value. A declared name that is absent is refused here (exit 2), before any
## test runs: through lictor 17 DB-backed tests once skipped under a green
## record (measured, OSS-CI-ENV). unit-db-endpoint judges the test URL first
## (OSS-MINT-GUARD-3, review OSS-MINT-GUARD-2 G1): the CI job's service is
## 127.0.0.1:45432/identuum_ci_test (OSS-MINT-GUARD-4: 45432, neither 5513 nor
## 5432), so ci-verify also declares DEV_PG_HOST_PORT and the job sets it to
## 45432; without it the port defaults to 5513 and the URL is refused.
.PHONY: go-test-race
go-test-race: unit-db-endpoint
	@for name in IDENTUUM_IDP_TEST_DATABASE_URL IDENTUUM_IDP_REQUIRE_DB_TESTS IDENTUUM_IDP_ALLOW_MULTI_REPLICA; do \
		printenv "$$name" >/dev/null || { echo "go-test-race: REFUSED — $$name is not set; ci-verify declares it with --env and the CI job sets it" >&2; exit 2; }; \
	done
	@go test ./... -count=1 -race -timeout=300s

# What ci-verify subtracts from verify and adds to it, declared ONCE
# (OSS-TIDY-3, 2026-10-02). script-tests (scripts/verify-check-test.sh) fails
# when the two plans above differ by anything else, so no comment here or in
# .github/workflows/ci.yml enumerates them; the reasons are in the ci-verify
# header.
CI_VERIFY_SUBTRACTS := ci-witness clock-fuse-gate gograph-boundaries gograph-build gograph-capabilities govulncheck ledger-diff-gate mint-decide repo-green tool-versions toolchain-parity ui-vendor-check witness-mint-test
CI_VERIFY_ADDS := fmt-check vet go-build go-test-race

## fmt-check: HARD gofmt gate (CE-GATES-3). Fails on drifted files AND on a
## non-zero gofmt exit status — gofmt walks files `go build` never compiles
## (testdata/*.go), and a file gofmt cannot PARSE prints nothing on stdout
## while exiting non-zero, so testing stdout alone silently passed it.
##
## Ported BYTE-IDENTICAL from identuum-idp-ce 2026-08-02 (FMT-VET-GAP), which
## was the only repo of the four that had it. The exit-status half is the part
## that gets dropped when this is re-typed rather than copied, so it is copied.
fmt-check:
	@fmt_out=$$(gofmt -l . 2>&1); fmt_status=$$?; \
	if [ $$fmt_status -ne 0 ] || [ -n "$$fmt_out" ]; then \
		echo "gofmt gate failed (gofmt exit $$fmt_status) — offenders/errors:"; \
		echo "$$fmt_out"; exit 1; \
	fi

## vet: the FULL go vet analyzer set.
##
## NOT REDUNDANT WITH `go test`, and the difference was enumerated before this
## was wired rather than assumed. `go test` runs a HIGH-CONFIDENCE SUBSET of
## vet on each package and its test files — per `go help test`, exactly:
##   atomic, bool, buildtags, directive, errorsas, ifaceassert, nilfunc,
##   printf, stringintconv, tests            (10 analyzers)
## `go tool vet help` registers 35. Wiring full vet therefore adds these 25,
## none of which any existing gate in this repo ran:
##   appends, asmdecl, assign, cgocall, composites, copylocks, defers,
##   framepointer, hostport, httpresponse, loopclosure, lostcancel, shift,
##   sigchanyzer, slog, stdmethods, stdversion, structtag, testinggoroutine,
##   timeformat, unmarshal, unreachable, unsafeptr, unusedresult, waitgroup
## Note the naming drift, which is why the two lists cannot be diffed naively:
## `go help test` writes `bool`/`buildtags`; vet registers them as
## `bools`/`buildtag`. Measured with go1.26.5 — re-enumerate on a toolchain
## bump rather than trusting this comment.
vet:
	go vet ./...

vet-integration:
	go vet -tags integration ./...

integration-staticcheck:
	@command -v staticcheck > /dev/null 2>&1 || { \
		echo "staticcheck not found on PATH. Install with:"; \
		echo "  go install honnef.co/go/tools/cmd/staticcheck@latest"; \
		exit 1; \
	}
	staticcheck -tags integration ./...

## openapi-check (THE-UNGUARDED-SPEC, 2026-09-06): the CHECKED-IN openapi.yaml
## — the public machine-readable API surface for OSS consumers — must be
## byte-for-byte what the generator emits from the source tree now. Until this
## target, nothing in verify compared the two: the docgen golden pins the
## generator against its own fixture, and a whole endpoint (GET
## /api/v1/agent-communication-authorizations) was absent from the checked-in
## spec while every gate stayed green; a hand-renamed path left `make verify`
## green at 6d1cc92 (27 targets, exit 0). Proved RED on that same mutation.
##
## It runs the tool's own test, which regenerates IN MEMORY (--dry-run emits
## the identical bytes --output writes; measured sha256-equal, and the
## generator is byte-deterministic across runs) and compares with
## ./openapi.yaml. It NEVER rewrites the file it judges — a gate that repairs
## its own subject proves nothing; the failure names the paths that differ,
## the first differing line, and the fixing command: `make api-docs`.
## Rule OPENAPI-CHECKED-IN-CURRENT-1. In verify and ci-verify alike (Go only).
.PHONY: openapi-check
openapi-check:
	go test ./tools/api-docgen -run '^TestOpenAPI_CheckedInSpecIsCurrent$$' -count=1

## doccomment-check: catch a SQL/code literal that gofmt TYPESET.
##
## THE DEFECT THIS EXISTS FOR, found 2026-08-02 after it shipped: gofmt does
## not only touch whitespace. Since Go 1.19 it REFORMATS DOC COMMENTS, and its
## typesetter turns a pair of apostrophes into a right double quote. A comment
## documenting the SQL `family_id = ''` became `family_id = ”` — the code in
## the comment stopped being the code. It passed `gofmt -l` cleanly, because
## the typeset form IS gofmt's preferred output.
##
## THE DISCRIMINATOR, chosen so it cannot fire on prose: typesetting `''`
## produces a LONE closing quote — a `”` with no `“` opening it on that line.
## Genuine prose quotation comes in pairs. So this flags lines where the count
## of `”` EXCEEDS the count of `“`, and says nothing about correctly-paired
## quotes, which stay legal. Measured at introduction: zero lone-closing lines
## across all four Go repos.
##
## TWO NAMED LIMITS, recorded rather than left for someone to discover:
##
## LIMIT 1 — it catches `''` -> `”` and NOT ``` `` ``` -> `“`. gofmt typesets a
## pair of BACKTICKS into a left double quote, which is the same class of damage
## and is invisible to a rule keyed on unbalanced CLOSING quotes: a lone `“`
## makes opens EXCEED closes, the opposite of what is flagged. Not fixed here,
## because the symmetric rule (flag lone `“` too) collides with LIMIT 2 far more
## often — an opening quote on one line and its close on the next is ordinary
## prose. Fixing it properly needs a comment-block parser, not a line rule.
##
## THIRD LEG, closed 2026-08-02: an EMPTY FILE LIST. `git ls-files` matching
## nothing feeds xargs nothing; BSD xargs then runs awk ZERO times and exits 0,
## so the capture is empty and a check keyed on emptiness reports CLEAN over a
## set it never examined. A file-count FLOOR now refuses to answer at all when
## the list is empty — a scan that examined nothing must say so, not pass.
##
## LIMIT 2 — the rule is PER LINE, so prose that opens a quotation on one line
## and closes it on the next trips it: the closing line has a `”` and no `“`.
## Measured at introduction: zero such lines across all four Go repos, so this
## costs nothing today. When it first fires on real prose, that is the signal to
## replace the line rule with a block-aware one — not to delete the check.
## THE FIX when it fires: put the code in an indented doc-comment block —
## a line beginning `//<TAB>` is preformatted and gofmt leaves it verbatim.
doccomment-check:
	@set -o pipefail; \
	files=$$(git ls-files '*.go'); n=$$(printf '%s\n' "$$files" | grep -c '\.go$$' || true); \
	if [ "$$n" -lt 1 ]; then \
		echo "DOC-COMMENT SCAN FOUND NO GO FILES ($$n) — refusing to report CLEAN over an empty set."; \
		exit 1; \
	fi; \
	bad=$$(printf '%s\n' "$$files" | xargs awk '{ o=gsub(/“/,"“"); c=gsub(/”/,"”"); if (c>o) printf "%s:%d: %s\n", FILENAME, FNR, $$0 }'); scan_status=$$?; \
	if [ $$scan_status -ne 0 ]; then \
		echo "DOC-COMMENT SCAN FAILED (exit $$scan_status) — the check could not run, so it reports NOTHING, not CLEAN."; \
		exit 1; \
	fi; \
	if [ -n "$$bad" ]; then \
		echo "DOC-COMMENT TYPESETTING FOUND (LINT-TAGS): a lone closing quote, which is what gofmt makes of two apostrophes:"; \
		echo "$$bad"; \
		echo "Code quoted in a doc comment must be an indented block (//<TAB>code), or gofmt will typeset it."; \
		exit 1; \
	fi

## clock-fuse: report test literals that omit the `now func() time.Time` seam.
##
## THE SIGNATURE (identuum-idp-ce@433bc6c): a test builds a fixture from a
## FROZEN clock, then hands it to code reading the WALL clock, because the
## construction site omitted the `now` field its struct already offers. That one
## was green for 45 days and red for 3 hours, with no file changed — invisible
## to mtime, git log and review alike.
##
## REPORTING TARGET, NOT A GATE, and deliberately so: omitting `now` is the
## PRECONDITION, not the defect. Only a fixture derived from a frozen clock is a
## fuse. identuum-idp-ce carries 27 omissions of which ZERO are fuses (license
## tests offset from time.Now, so fixture and judge move together;
## NilNowFuncDefaultsToWallClock omits the seam ON PURPOSE — that IS its
## subject). Wiring this into `verify` would fail on 27 correct tests and teach
## people to skip it. Gate it only behind an allowlist, or behind a narrower
## frozen-fixture rule — both are their own decision.
##
## THE EXIT CONTRACT, MEASURED BEFORE IT WAS WRITTEN DOWN (WIRE-THE-GATE-THEN-TRIAGE,
## 2026-08-02). The tool exits:
##   0  only when there is NO omission, NO mixed-clock test and NO optless
##      construction — it prints "CLEAN" and returns.
##   1  on ANY finding of those three kinds. The never-injected census does NOT
##      affect the exit; it is reported, not gated.
##   2  on a TOOL ERROR — a WALK failure (a root that cannot be read). A PARSE
##      failure is NOT one: clockfuse deliberately skips a file it cannot parse
##      ("unparseable file is not this tool's business"), so a malformed file is
##      silently excluded rather than reported. That is a real blind spot, stated
##      here rather than implied away, and it is why the wording below says WALK.
##
## MEASURED TODAY: every repo has findings (identuum-idp-oss 41 omissions,
## identuum-idp-ce 119, identuum-ag-ce 11, identuum-ag-oss 1 optless), so all four
## exit 1. WIRING THIS AS A HARD GATE WOULD BREAK ALL FOUR VERIFIES IMMEDIATELY.
##
## SO IT IS WIRED REPORT-ONLY, AND THAT IS SAID OUT LOUD RATHER THAN HIDDEN. The
## AG pair used to write `@go run ./tools/clockfuse . || true`, which is the same
## decision taken silently: the `@` hid the command and the `|| true` discarded the
## verdict, so the target could not fail and nothing said why. Both are gone. The
## target below now exits with the tool's own status; `clock-fuse-report` is what
## verify calls, and it prints the finding count AND the fact that it is not
## gating. NO ALLOWLIST was added to make anything pass — the findings are real and
## await the triage recorded in the wiki queue.
##
## A TOOL ERROR STILL FAILS. Exit 2 is not a finding; a detector that could not
## finish must not be reported as a detector that found nothing.
clock-fuse:
	go run ./tools/clockfuse .

## clock-fuse-gate: the findings arm finally GATES (owner ruling, 2026-08-05,
## closing CLOCK-FUSE + CENSUS-GATES-NOTHING). The DEADLINE arm always hard-
## failed; the findings arm was report-only, and the census drifted 223 -> 170
## with nothing noticing. This fails ONLY on a finding-class NEW against
## .clockfuse-snapshot (count|file|type|field — line numbers deliberately
## absent, so edits above a finding do not turn it "new"). Removals pass
## silently: DEFECT-30b proved the raw count REWARDS deleting seams, so the raw
## count is exactly what this does not gate. Snapshot regeneration is a
## deliberate act: `lictor clockfuse --repo . -snapshot` — never by hand, and
## never by this target, which writes nothing.
##
## THE-JUDGE-OWNS-ITS-PIN (2026-09-21): the judge is the INSTALLED, PINNED
## lictor (`lictor clockfuse --repo "$(CURDIR)"`, lictor migration row 3,
## v0.3.0 onward), in place of `bash "$(WIKI_TOOLS)/clockfuse-gate.sh"
## --check .` — the last sibling-script read in this repository's verify plan
## but one, so a materialized commit tree no longer fails here for a path it
## does not own. The evidence line is unchanged, byte for byte. `clock-fuse`
## (the analyzer itself) and `clock-fuse-report` are untouched.
clock-fuse-gate:
	@$(call LICTOR_ASSERT,clock-fuse-gate); \
	"$(LICTOR)" clockfuse --repo "$(CURDIR)"

## clock-fuse-report: what `verify` and the CI aggregate call. REPORT-ONLY for
## findings, HARD FAIL for a tool error AND for the DEADLINE gate (exit 3).
## See the exit contract on clock-fuse.
##
## IT BUILDS THE BINARY INSTEAD OF `go run`, and that is not a style choice.
## MEASURED: `go run` COLLAPSES EVERY NON-ZERO EXIT TO 1 — it prints "exit status
## 2" on stderr and itself returns 1. So the exit-2 branch below could never fire
## through `go run`, and a tool error would have been reported as findings. A
## contract whose distinguishing case is unreachable is not a contract; building
## the binary preserves the real status. Proven: `go run ... /nonexistent-root`
## exits 1, the built binary exits 2.
clock-fuse-report:
	@bin=$$(mktemp "$${TMPDIR:-/tmp}/clockfuse.XXXXXX"); \
	if [ -z "$$bin" ]; then \
		echo "CLOCK-FUSE TOOL ERROR: mktemp produced no path, so the detector cannot run."; \
		echo "A report over a detector that never executed is the vacuity this repo hunts."; \
		echo "This DOES fail the build. (GNU mktemp rejects the BSD '-t prefix' form —"; \
		echo "found by the runner-shape container proof, THE-RUNNER-SHELL.)"; \
		exit 1; \
	fi; \
	if ! go build -o "$$bin" ./tools/clockfuse; then \
		rm -f "$$bin"; \
		echo "CLOCK-FUSE TOOL ERROR: the detector does not build. This DOES fail the build."; \
		exit 1; \
	fi; \
	out=$$("$$bin" . 2>&1); rc=$$?; rm -f "$$bin"; \
	if [ $$rc -eq 127 ] || [ $$rc -eq 126 ]; then \
		echo "$$out"; \
		echo "CLOCK-FUSE TOOL ERROR (exit $$rc): the detector BINARY did not execute — that is"; \
		echo "not a findings report, and treating it as one let a never-run detector print"; \
		echo "REPORT-ONLY on the runner. This DOES fail the build."; \
		exit 1; \
	fi; \
	echo "$$out"; \
	if [ $$rc -eq 2 ]; then \
		echo "CLOCK-FUSE TOOL ERROR (exit 2): the detector could not finish, so it found nothing"; \
		echo "for reasons that have nothing to do with the code. This DOES fail the build."; \
		exit 1; \
	fi; \
	if [ $$rc -eq 3 ]; then \
		echo "CLOCK-FUSE GATE (exit 3): a DEADLINE seam has never been injected. This DOES fail the build."; \
		echo "The seam compares a clock read against a stored instant, so no test can stand on"; \
		echo "its boundary until something freezes it. Inject it from a test, or delete the seam."; \
		exit 1; \
	fi; \
	if [ $$rc -ne 0 ]; then \
		echo "CLOCK-FUSE: findings above (tool exit $$rc). REPORT-ONLY — this does NOT fail the build."; \
		echo "Each needs triage as FUSE or BENIGN; gating before that triage would fail every repo today."; \
	fi

## api-surface: the public API of this module is EXACTLY these ten pkg/
## packages — extension, features, licenseprovider, migrations, oidc, pkce,
## runtime, totp, uiserve, webauthn — and nothing else under pkg/ (P-061,
## wiki/platform/decisions.md: "that table IS the public-API decision";
## executed by THE-THREE-DIRS, d1b9830, which moved migrations, runtime and
## server under internal/pkg/; uiserve added by the owner decision of
## 2026-09-24, PLAN-F-1; migrations and runtime return as narrow facades by
## owner ruling w, 2026-10-08, OSS-SEAM-1 — server stays internal; extension
## added by OSS-SEAM-4, owner rulings z and aa, 2026-10-08). What each
## exports is pinned by internal/apigolden; docs/PUBLIC-API.md says the promise.
##
## WHY A GATE AND NOT A COMMENT: a directory under pkg/ is a contract for
## free — the moment it exists, a downstream module can import it, and
## moving it back under internal/ later is a breaking change while the
## reverse is not. So the set is enumerated HERE, in the recipe, and the
## gate is red on either drift: a directory MISSING (a public seam deleted
## or moved without this list changing) or a directory EXTRA (a new seam
## published without a decision). Each offender is named. Listing the seven
## twice — in P-061 and here — is deliberate: the wiki says why, this recipe
## makes the tree agree, and a change to one without the other is the red.
##
## No sibling checkout, no network, no tool but find/sort: runs in ci-verify
## as well as verify (THE ONE-REPO RULE above ci-verify). Untracked
## directories count — the tree is the API, not the index — which is also
## how it is red-proved (an untracked pkg/decoy/ names `decoy`).
API_SURFACE := extension features licenseprovider migrations oidc pkce runtime totp uiserve webauthn
api-surface:
	@want="$$(printf '%s\n' $(API_SURFACE) | sort | tr '\n' ' ' | sed 's/ $$//')"; \
	have="$$(find pkg -mindepth 1 -maxdepth 1 -type d | sed 's#^pkg/##' | sort | tr '\n' ' ' | sed 's/ $$//')"; \
	if [ "$$have" != "$$want" ]; then \
		echo "check FAILED: api-surface — pkg/ must hold EXACTLY {$$want} (P-061); it holds {$$have}"; \
		for d in $$have; do case " $$want " in *" $$d "*) ;; *) echo "  EXTRA   pkg/$$d — a public seam nobody decided; move it under internal/ or amend P-061 AND this list";; esac; done; \
		for d in $$want; do case " $$have " in *" $$d "*) ;; *) echo "  MISSING pkg/$$d — a public seam CE imports is gone; restore it or amend P-061 AND this list";; esac; done; \
		exit 1; \
	fi; \
	echo "check OK: api-surface — pkg/ holds exactly {$$want} (P-061)"

## image-base-check: fail if any Dockerfile builds FROM an Alpine base.
##
## IMG-NONALPINE (owner decision 2026-07-31): every image WE build must be
## musl-free. The Postgres SERVICE image is EXEMPT — it lives in compose, never
## in a Dockerfile, so this scan never sees it and must not be widened until it
## does. (THE-CONFORMANCE-HARNESS keeps its third-party suite clone OUTSIDE
## this repo tree — ../.conformance-suite-cache — precisely so this shared,
## md5-paritied block never has to learn about it.)
##
## THREE RULES, because a literal `^FROM.*alpine` check has a hole (IMG-GATE-2):
##   1. a FROM line that resolves to an Alpine base;
##   2. an ARG whose DEFAULT is an Alpine base — `ARG DEBIAN_VARIANT=alpine`
##      plus `FROM golang:$${GO_VERSION}-$${DEBIAN_VARIANT}` is an Alpine image
##      with no literal `alpine` on any FROM line at all;
##   3. a FROM carrying a variable this file's own ARG defaults cannot resolve.
##      UNRESOLVABLE FAILS LOUD rather than passing quietly — a gate that cannot
##      tell must not answer 'fine'.
##
## Anchored to ^FROM / ^ARG, never the bare word. A bare-word `alpine` check
## would fail on this repo's own documentation: the Dockerfiles carry prose
## matches for the rule's own name, the tags they moved off, and the Alpine-isms
## they document. Measured, not hypothetical.
##
## `find -exec ... +` rather than xargs, so zero matching files skips awk
## instead of leaving it reading stdin. The awk prints file:line for every
## finding; a non-empty result is the failure signal.
##
## This recipe is byte-identical in FOUR repos — identuum-idp-oss,
## identuum-idp-ce, identuum-ag-ce and identuum-ui (ported 2026-08-02,
## IMG-GATE-4). Diverging copies of a policy gate are how a policy stops being
## one, so this is no longer a request: `image-base-parity` below pins the
## md5 of these 9 lines and FAILS this repo if its copy is edited by one
## character. Both targets are prerequisites of `verify`, so the enforcement
## runs wherever the gate runs. identuum-ag-oss is deliberately absent from the
## list: it ships NO Dockerfile, so it has nothing to gate and the missing
## target there is correct, not an oversight.
image-base-check:
	@out="$$(find . -name 'Dockerfile*' -not -path './.git/*' -not -path './vendor/*' -exec awk 'FNR==1{delete A} /^ARG[ \t]+[A-Za-z_][A-Za-z0-9_]*=/{s=$$0;sub(/^ARG[ \t]+/,"",s);p=index(s,"=");n=substr(s,1,p-1);v=substr(s,p+1);sub(/[ \t].*$$/,"",v);gsub(/^"|"$$/,"",v);A[n]=v;if(v~/alpine/){printf "%s:%d: ARG default is an Alpine base: %s\n",FILENAME,FNR,$$0}} /^FROM[ \t]/{r=$$0;for(i=0;i<10;i++){ch=0;for(n in A)if(index(r,"$${" n "}")>0){gsub("[$$][{]" n "[}]",A[n],r);ch=1}if(!ch)break}if(r~/alpine/){printf "%s:%d: FROM resolves to an Alpine base: %s\n",FILENAME,FNR,$$0}else if(r~/[$$]/){printf "%s:%d: FROM has an UNRESOLVED variable, no ARG default in this file - failing loud: %s\n",FILENAME,FNR,$$0}}' {} + 2>/dev/null || true)"; \
	if [ -n "$$out" ]; then \
		echo "ALPINE BASE IMAGE FOUND (IMG-NONALPINE):"; \
		echo "$$out"; \
		echo "Every image we build must be musl-free. The Postgres SERVICE image is exempt and belongs in compose, not in a Dockerfile."; \
		exit 1; \
	fi

## image-base-parity: the copies check THEMSELVES.
##
## `image-base-check` above is maintained byte-identical in FOUR repos —
## identuum-idp-oss, identuum-idp-ce, identuum-ag-ce and identuum-ui. Until
## 2026-08-02 that was a claim in a comment and nothing verified it, which is
## the same shape as every CLEAN-that-measured-nothing this workspace has
## found: a policy stated in prose, enforced by hope.
##
## HOW IT IS ENFORCED WITHOUT SIBLING CHECKOUTS. A cross-repo diff cannot run
## in CI — each job checks out ONE repo. So the four do not compare themselves
## to each other; they each compare their own copy to an AGREED DIGEST, pinned
## below. Editing any copy by one character changes that copy's digest and
## turns THAT repo red, in CI and locally, with no sibling required. Four
## repos agreeing with one constant is equivalent to four repos agreeing with
## each other, and it is checkable from a single checkout.
##
## THE UNIT IS EXACT: from `image-base-check:` through its closing `fi`, plus
## the blank line that terminates the recipe — 9 lines. The blank line is IN
## the hash deliberately, because a recipe that swallows the following line is
## a real defect and would otherwise hash the same. Note the `printf '%s\n\n'`
## below: command substitution strips ALL trailing newlines, so the 9th line has
## to be put back or this target hashes 8 lines and is red forever. It was, on
## first run, in all four repos at once.
##
## CHANGING THE GATE ON PURPOSE: edit one copy, run `make image-base-parity`
## to read the new digest out of the failure message, update IMAGE_BASE_MD5 in
## all four, and copy the block to all four. The target tells you the value it
## wanted and the value it got, so the update is mechanical.
IMAGE_BASE_MD5 ?= 771f2aed39cca106ecdaf4f283ec1007

image-base-parity:
	@blk="$$(awk '/^image-base-check:/{f=1} f{print; if(f&&/^\tfi$$/){getline; print; exit}}' Makefile)"; \
	got="$$(printf '%s\n\n' "$$blk" | { md5sum 2>/dev/null || md5; } | awk '{print $$1}')"; \
	if [ "$$got" != "$(IMAGE_BASE_MD5)" ]; then \
		echo "IMAGE-BASE-CHECK COPY HAS DIVERGED (IMG-GATE-4):"; \
		echo "  wanted md5 $(IMAGE_BASE_MD5)"; \
		echo "  got    md5 $$got"; \
		echo "This repo's image-base-check no longer matches the copy shared with identuum-idp-oss, identuum-idp-ce, identuum-ag-ce and identuum-ui."; \
		echo "Either restore this copy, or update the block AND IMAGE_BASE_MD5 in all four."; \
		exit 1; \
	fi

## witness — THE ONLY WAY A WITNESS COMMIT IS MADE (THE-WITNESS-THAT-CANNOT-LIE,
## 2026-09-07). A witness made any other way is a defect.
##
## MEASURED, idp-oss reflog, 2026-09-07: `commit: Witness: make verify green at
## 64a71cb` then `reset: moving to HEAD~1`. A hand-typed chain committed a
## witness over a RED record because one `;` ended its `&&` guard; a read of
## the output caught it, not a gate. The witness is the one claim this
## workspace trusts, so it is made HERE, by a recipe that REFUSES unless every
## one of these holds, in this order:
##   1. GATE-RUN.txt exists and says `result: green`;
##   2. its `repo-head:` is a prefix of `git rev-parse HEAD` — a green record
##      for another head witnesses that head, not this one;
##   3. `scripts/gate-witness.sh check` accepts it: complete, no non-zero
##      exit, and its `tree:` digest equals the tree NOW (the record excluded);
##   4. nothing but GATE-RUN.txt is modified — a witness is record-only.
## Only then: `git add GATE-RUN.txt` and ONE commit with the canonical subject
## `Witness: make verify green at <short HEAD>`. Nothing else is staged, ever;
## the message is written by this recipe, never typed.
## The recipe exits 1 for a refusal the record explains and 2 when it cannot
## evaluate (no record). Until 2026-09-18 a step ran FIRST: the wiki's parts
## commit gate, with an IDENTUUM_PARTS_BYPASS escape quoted in the body; wiki
## 46d6bf3 (THE-ONE-BOOK) retired that gate and its file, and the step went
## with it (THE-WITNESS-THAT-WAITED-FOR-A-RETIRED-GATE, 2026-09-19) — no
## bypass exists. This block is byte-identical in identuum-idp-oss and
## identuum-ui and pinned by `witness-parity` below.
witness:
	@set -u; rec=GATE-RUN.txt; \
	test -f "$$rec" || { echo "witness: REFUSED — $$rec is absent; run make verify first"; exit 2; }; \
	res=$$(sed -n 's/^result: //p' "$$rec" | head -1); \
	[ "$$res" = green ] || { echo "witness: REFUSED — $$rec says result: $${res:-<absent>}, not green"; exit 1; }; \
	full=$$(git rev-parse HEAD); rhead=$$(sed -n 's/^repo-head: //p' "$$rec" | head -1); \
	[ -n "$$rhead" ] || { echo "witness: REFUSED — $$rec carries no repo-head: line"; exit 1; }; \
	case "$$full" in "$$rhead"*) ;; *) echo "witness: REFUSED — $$rec was written at repo-head $$rhead, HEAD is $$(git rev-parse --short HEAD)"; exit 1;; esac; \
	bash scripts/gate-witness.sh check . "$$rec" || { echo "witness: REFUSED — $$rec does not witness this tree (gate-witness check, above)"; exit 1; }; \
	other=$$(git status --porcelain | grep -v " $$rec$$" || true); \
	[ -z "$$other" ] || { echo "witness: REFUSED — a witness is record-only, and the tree carries more than $$rec:"; printf '%s\n' "$$other"; exit 1; }; \
	subject="Witness: make verify green at $$(git rev-parse --short HEAD)"; \
	n=$$(grep -c '^target: .* exit=0$$' "$$rec" || true); msg=$$(mktemp "$${TMPDIR:-/tmp}/witness.XXXXXX"); \
	{ printf '%s\n\n' "$$subject"; printf 'Record-only commit made by make witness: %s as make verify wrote it at the clean HEAD %s, %s planned target(s) at exit=0, tree digest verified by gate-witness check. A witness made any other way is a defect.\n' "$$rec" "$$full" "$$n"; } > "$$msg"; \
	if git add "$$rec" && git commit -q -F "$$msg"; then rm -f "$$msg"; echo "witness: $$subject -> $$(git rev-parse --short HEAD)"; \
	else rm -f "$$msg"; echo "witness: REFUSED — git commit did not land"; exit 1; \
	fi

## witness-parity: the two copies of `witness` check THEMSELVES — the
## image-base-parity discipline: from `witness:` through its closing `fi`, plus
## the blank line that terminates the recipe, hashed and compared with a pin
## shared by identuum-idp-oss and identuum-ui. A copy edited by one character
## turns its repo red with no sibling checkout required. CHANGING IT ON
## PURPOSE: edit one copy, run `make witness-parity`, read the digest from the
## failure, update WITNESS_MD5 in both and copy the block to both.
WITNESS_MD5 ?= 2e107f86a44d0fff59fc01659f1f2535

witness-parity:
	@blk="$$(awk '/^witness:/{f=1} f{print; if(f&&/^\tfi$$/){getline; print; exit}}' Makefile)"; \
	got="$$(printf '%s\n\n' "$$blk" | { md5sum 2>/dev/null || md5; } | awk '{print $$1}')"; \
	if [ "$$got" != "$(WITNESS_MD5)" ]; then \
		echo "check FAILED: witness-parity — the witness recipe has diverged from the copy shared with identuum-idp-oss and identuum-ui: wanted md5 $(WITNESS_MD5), got $$got; restore this copy, or update the block AND WITNESS_MD5 in both"; \
		exit 1; \
	fi; \
	echo "check OK: witness-parity witness block md5 $$got matches the shared pin"

## claim-guard (WIKI-CLAIM-BOOK, owner ruling i, 2026-10-06): the witness
## refuses while another slice holds this checkout's `achta claim`. The caller
## names its own slice in ACHTA_SLICE (make witness ACHTA_SLICE=<GOAL NAME>).
## No claim at all is a warning, not a refusal; a missing achta or a status
## that is not achta.claim.v1 is CANNOT EVALUATE (exit 2). A prerequisite of
## witness, outside the witness recipe itself.
ACHTA ?= achta
.PHONY: claim-guard
witness: claim-guard
claim-guard:
	@command -v "$(ACHTA)" >/dev/null 2>&1 || { echo "claim-guard: CANNOT EVALUATE — achta is not installed"; exit 2; }; \
	json=$$("$(ACHTA)" claim status --repo "$(CURDIR)" --json) || { echo "claim-guard: CANNOT EVALUATE — achta claim status failed"; exit 2; }; \
	case "$$json" in *'"schema_version":"achta.claim.v1"'*) ;; *) echo "claim-guard: CANNOT EVALUATE — the answer is not an achta.claim.v1 status"; exit 2;; esac; \
	case "$$json" in *'"claim":null'*) echo "claim-guard: WARNING — no slice holds this checkout's claim; take one before writing: achta claim take --repo $(CURDIR) --slice <GOAL NAME>"; exit 0;; esac; \
	holder=$$(printf '%s' "$$json" | sed -n 's/.*"claim":{"slice":"\([^"]*\)".*/\1/p'); \
	[ -n "$$holder" ] || { echo "claim-guard: CANNOT EVALUATE — the status names no holder"; exit 2; }; \
	[ "$$holder" = "$${ACHTA_SLICE:-}" ] || { echo "claim-guard: REFUSED — slice $$holder holds this checkout's claim, and this witness runs as '$${ACHTA_SLICE:-<unset>}'; only the holder witnesses here (owner ruling i)"; exit 1; }; \
	echo "claim-guard: OK — $$holder holds the claim"

## claim-guard-selftest: drives claim-guard with a stub achta whose `claim
## status --json` prints a fixture: a claim held by another slice (refused,
## naming it), by the caller (pass), by someone while ACHTA_SLICE is unset
## (refused), no claim (warning, pass), and output that is not a claim status
## (cannot evaluate). It also asserts that `witness` lists claim-guard as a
## prerequisite. The same text in the wiki, identuum-idp-oss and identuum-ui.
.PHONY: claim-guard-selftest
claim-guard-selftest:
	@set -u; t=$$(mktemp -d "$${TMPDIR:-/tmp}/claim-guard.XXXXXX"); trap 'rm -rf "$$t"' EXIT; \
	printf '#!/bin/sh\ncat "%s"\n' "$$t/status.json" > "$$t/achta"; chmod +x "$$t/achta"; \
	held() { printf '{"schema_version":"achta.claim.v1","operation":"status","status":"pass","claim":{"slice":"%s","time":"2026-10-06T00:00:00Z","note":""},"releases":[]}' "$$1" > "$$t/status.json"; }; \
	n=0; fails=0; \
	case_() { n=$$((n+1)); out=$$($(MAKE) --no-print-directory claim-guard ACHTA="$$t/achta" $$2 2>&1); rc=$$?; \
		if { [ "$$3" = pass ] && [ "$$rc" -eq 0 ]; } || { [ "$$3" = fail ] && [ "$$rc" -ne 0 ]; }; then ok=1; else ok=0; fi; \
		if [ $$ok = 1 ] && printf '%s' "$$out" | grep -q -- "$$4"; then echo "  ok    $$1"; else echo "  FAIL  $$1: exit $$rc, wanted $$3 and '$$4'; got: $$out"; fails=$$((fails+1)); fi; }; \
	held OTHER-SLICE; case_ "a claim held by another slice is refused, naming it" "ACHTA_SLICE=MINE" fail "REFUSED — slice OTHER-SLICE holds"; \
	held MINE; case_ "the holder passes" "ACHTA_SLICE=MINE" pass "OK — MINE holds"; \
	held OTHER-SLICE; case_ "a held claim with ACHTA_SLICE unset is refused" "ACHTA_SLICE=" fail "REFUSED — slice OTHER-SLICE holds"; \
	printf '{"schema_version":"achta.claim.v1","operation":"status","status":"pass","claim":null,"releases":[]}' > "$$t/status.json"; \
	case_ "no claim is a warning, not a refusal" "ACHTA_SLICE=MINE" pass "WARNING — no slice holds"; \
	printf 'not json' > "$$t/status.json"; case_ "an unreadable status cannot be evaluated" "ACHTA_SLICE=MINE" fail "CANNOT EVALUATE"; \
	n=$$((n+1)); if $(MAKE) --no-print-directory -pnrR 2>/dev/null | grep -Eq '^witness:.* claim-guard( |$$)'; then echo "  ok    witness lists claim-guard as a prerequisite"; else echo "  FAIL  witness does not list claim-guard as a prerequisite"; fails=$$((fails+1)); fi; \
	if [ $$fails -ne 0 ]; then echo "claim-guard-selftest: FAIL — $$fails of $$n case(s) wrong" >&2; exit 1; fi; \
	echo "check OK: claim-guard-selftest $$n case(s)"

## OSS-only prerequisite, outside the shared witness recipe and its pin.
## Phony: every attempt re-reads both trees and the mint record, even after
## a previous refusal. No stored approval or bypass controls this decision.
.PHONY: witness-mint-check
witness: witness-mint-check
witness-mint-check:
	@if $(MAKE) --no-print-directory mint-decide; then \
		echo "witness: mint prerequisite satisfied; proceeding with the shared witness recipe"; \
	else \
		echo "witness: REFUSED — the e2e mint is owed or cannot be established as satisfied; mint-decide's reason is above. Re-running witness cannot pay this debt."; \
		exit 1; \
	fi

## ledger-census (OSS-GATE-TIDY, 2026-10-05; queue :6): the wiki's retirement
## ledger pins every tools/ directory here by its .go line count, and until now
## only the wiki ran that census — a slice later, in a repository the breaking
## slice may not write. This runs the wiki's own command (the
## retirement-ledger-census entry of the wiki's `make check`) from here, as an
## OSS-only prerequisite of `witness`, so a tools/ change is red at THIS close,
## naming the row to edit ("line N size — row R states <dir> has X lines; on
## disk it has Y"). Sibling-coupled (it reads the wiki), so it is in neither
## verify nor ci-verify. A missing wiki or achta is CANNOT EVALUATE (exit 2)
## and refuses the witness like a red.
.PHONY: ledger-census
witness: ledger-census
ledger-census:
	@wiki="$(abspath $(WIKI_DIR))"; \
	[ -f "$$wiki/contracts/retirement-ledger.md" ] || { echo "ledger-census: CANNOT EVALUATE — $$wiki/contracts/retirement-ledger.md is absent; the wiki sibling is required at the close"; exit 2; }; \
	command -v achta >/dev/null 2>&1 || { echo "ledger-census: CANNOT EVALUATE — achta is not installed"; exit 2; }; \
	achta --wiki-dir "$$wiki" ledger census --file "$$wiki/contracts/retirement-ledger.md" --dir "$$wiki/tools" --tree "GO=$(CURDIR)/tools" --ext .go || { echo "ledger-census: REFUSED — a tools/ line count no longer matches its retirement-ledger row (named above); edit that row in the wiki's contracts/retirement-ledger.md before the witness"; exit 1; }

## image-policy-restate-check: IMG-NONALPINE is stated in ONE place — the
## canonical text beside image-base-check above. THE-IMAGE-POLICY-TRUTH
## (2026-08-22): ci.yml carried a WIDER restatement — "the image-base
## policy is no Alpine anywhere except the Go builder" — false under the
## owner decision (the Postgres SERVICE image is exempt), contradicted by
## the postgres:18-alpine pin in the SAME file, and naming a Go-builder
## carve-out that stopped existing when the builder moved to
## golang:1.27.0-bookworm. Prose drifts; references do not: every site
## other than the canonical block cites IMG-NONALPINE by name.
##
## The phrase list is the MEASURED restatement shapes, not a bare-word
## `alpine` scan — the image-base-check header above and the appliance
## image test both record why bare-word matching fails on this repo's
## own documentation. FOUR shapes shipped, and the list covers all four
## (THE-RESTATE-COVERAGE, 2026-08-22 — the first cut carried only the
## ci.yml shape, so reintroducing the Dockerfile's or the test's
## "Alpine-free" restatement passed green; measured against 7517de8):
## the ci.yml defining sentence, the canonical text's own "musl-free",
## and the "Alpine-free" wording both Dockerfile.local and the appliance
## image test used to carry.
##
## THE QUOTATION DECISION, on the record: adding "Alpine-free" turned
## this gate red on the appliance test's truthful description of the OLD
## header. The comment was reworded to stop carrying the phrase — NO
## path is excluded from this scan; a named exclusion is a standing hole
## in the gate, a rewording is not. HONEST LIMIT, stated plainly: a scan
## cannot tell a quotation from a restatement, nor catch a paraphrase
## that avoids these phrases; it catches the shapes that actually
## shipped.
image-policy-restate-check:
	@out="$$(git grep -n -I -E 'no [Aa]lpine anywhere|image-base policy|musl-free|[Aa]lpine-free' -- ':!Makefile' 2>/dev/null || true)"; \
	if [ -n "$$out" ]; then \
		echo "IMAGE POLICY RESTATED OUTSIDE ITS CANONICAL SITE (IMG-NONALPINE):"; \
		echo "$$out"; \
		echo "The policy text lives beside image-base-check in the Makefile. Cite IMG-NONALPINE by name; never restate the rule."; \
		exit 1; \
	fi

## distroless-exec-check: the runtime image ships NO SHELL, so any make rule that
## wraps a container exec in `sh -c` / `bash -c` is dead on arrival (exec: "sh":
## executable file not found, exit 127).
##
## THE-MANUAL-TARGETS (2026-08-31): this exact defect was fixed once in
## oss-recover-site-admin and left standing in oss-bootstrap, where it made the
## documented bootstrap path unusable — the harness worked around it and the
## operator lost an hour to it. Nothing failed, because nothing checked. This
## gate is the teeth: exec the binary directly, always.
distroless-exec-check:
	@# Match the container-exec ARGV line itself (`app sh -c …`), not the
	@# `compose … exec` line: these rules span backslash continuations, so the
	@# shell wrapper and the word `exec` are on DIFFERENT lines. A pattern
	@# requiring both on one line matched nothing — including the original
	@# defect (caught by this gate's own red-proof before it was trusted).
	@# Comment lines are EXCLUDED deliberately: the rules above and this gate's
	@# own prose quote the broken form to explain it. Recipe lines are what
	@# execute, so only they are scanned (a doc line must never fail a build).
	@out="$$(grep -nE '(^|[[:space:]])app[[:space:]]+(sh|bash)[[:space:]]+-c' Makefile \
		| grep -vE '^[0-9]+:[[:space:]]*@?#' || true)"; \
	if [ -n "$$out" ]; then \
		echo "SHELL-WRAPPED CONTAINER EXEC (the runtime image is distroless — no shell):"; \
		echo "$$out"; \
		echo "Exec the binary DIRECTLY: '... exec app /app/identuum-idp <subcommand>'."; \
		echo "Subcommands taking [database-url] read IDENTUUM_IDP_DATABASE_URL /"; \
		echo "IDENTUUM_IDP_OSS_DB from the container env, so no shell expansion is needed."; \
		exit 1; \
	fi

## grype-scan: Anchore Grype filesystem scan, judged by lictor (`lictor grype
## --repo $(CURDIR)`), the INSTALLED, PINNED judge — the byte-faithful port of
## this repository's tools/grype-gate at 1cbe9f6 (github.com/ozgurcd/lictor,
## `brew install ozgurcd/tap/lictor`). THE-LAST-BORROWER (2026-09-21): CE
## (128dc78) and ui (fe07c3b) had switched to lictor; this repository, the
## judge's home, was the last consumer, so the switch RETIRES tools/grype-gate
## (seven files, 1659 lines; its 77 assertions are lictor's now) and the
## `bin/grype-gate` build target with it. The rule it enforced,
## GRYPE-FIXABLE-FAILS-1, and GRYPE-SUBJECT-1 live in lictor's floor; the
## evidence line is unchanged. The pin: ci.yml env LICTOR_VERSION and
## LICTOR_SHA256, read here the way GRYPE_VERSION is read and asserted against
## `lictor version --json` before the judge runs (missing lictor: exit 2 by
## name with the brew line; another version: refused by name, recipe exit 1);
## tools/toolchain-parity holds the same pin. Requires grype to be installed
## (https://github.com/anchore/grype) — lictor runs it.
## Runs both locally (via `verify`) AND in CI (via `ci-verify`) — CI installs a
## tag-pinned grype AND the sha256-pinned lictor release archive in
## .github/workflows/ci.yml before invoking this target.
##
## WHY IT IS NO LONGER `grype dir:. --fail-on high` (THE-STALE-DEPENDENCY,
## owner ruling P-042): that flag exits 0 on a finding whose severity the
## database does not rate, and it did — golang.org/x/crypto v0.55.0 carried
## GO-2026-6354 and GO-2026-6355, BOTH with a published fix in v0.56.0, BOTH
## reported as severity "Unknown". The gate passed and the finding rode in
## three consecutive slice reports with nothing failing.
##
## The gate now fails on a finding that HAS AN AVAILABLE FIX — not because it
## is severe, but because somebody published the remedy and this repository
## has not taken it. A finding with NO fix cannot be actioned by a bump, so it
## is reported, not failed. The High/Critical floor is kept exactly as it was,
## so this is strictly stronger than the flag it replaces. The only way past a
## fixable finding is a named entry in grype-allowlist.json carrying a reason
## AND a ruling; an entry missing either fails the gate rather than excusing
## anything. Rule GRYPE-FIXABLE-FAILS-1 (lictor's floor since THE-LAST-BORROWER).
## (THE-JUDGE-AND-ITS-SUBJECT, 2026-09-12, had `bin/grype-gate` rebuilt
## whenever a judge source was newer than it, so a verify never ran a stale
## judge; a pinned, installed lictor makes that prerequisite moot — the judge
## a verify runs is the declared version, asserted below.)
## LICTOR names the judge binary; overridable so the refusals can be
## exercised (`make grype-scan LICTOR=/nonexistent/lictor` → exit 2 by name).
LICTOR ?= lictor
## LICTOR_ASSERT is the ONE thing a recipe can say that lictor cannot: that
## lictor is ABSENT. $(1) is the target's name for the message.
##
## THE-JUDGE-OWNS-ITS-PIN (2026-09-21): the version half is DELETED. Since
## lictor v0.3.0 the judge reads the consumer's pin ITSELF — every `--repo`
## command parses this repository's .github/workflows/ci.yml for
## `LICTOR_VERSION`, refuses a mismatch or an absent declaration with exit 2
## and one stderr line naming both versions, and `--unpinned` permits only an
## absent declaration, never a mismatch. A recipe that re-read the pin and
## re-judged it would be a second implementation of the judge's own
## judgement, drifting the moment lictor's rule changes — the shared-by-copy
## class lictor exists to end. So the assertion that remains is the one lictor
## cannot make from inside a binary that is not there.
define LICTOR_ASSERT
command -v "$(LICTOR)" >/dev/null 2>&1 || { \
		echo "$(1): lictor is not installed ($(LICTOR)) — refusing to pass silently. Install it:" >&2; \
		echo "  brew install ozgurcd/tap/lictor" >&2; \
		exit 2; \
	}
endef
grype-scan:
	@$(call LICTOR_ASSERT,grype-scan); \
	"$(LICTOR)" grype --repo "$(CURDIR)"

## fast-up: start the local development Postgres container.
## fast-up: start local dev Postgres with EVERY external call under a bound.
##
## THE FAULT THIS EXISTS FOR (ORB-RECUR, observed three times on 2026-08-02):
## the Docker engine wedges. `/_ping` stops answering, `docker ps` hangs
## forever, and the published port forwards KEEP ACCEPTING TCP, so every
## reachability check still says yes. A wait with no bound CANNOT FAIL, and
## something that cannot fail cannot tell you what went wrong.
##
## EVERY CALL THAT LEAVES THIS PROCESS IS BOUNDED, not just the first
## (BOUND-LABEL, 2026-08-02). The previous version probed the engine and then
## ran `compose up -d`, `compose ps` and `compose logs` unbounded — CHECK THEN
## ACT, against a fault that arrives between the check and the act, and it
## arrived three times in a single session. The evidence-gathering calls
## mattered most: THE BRANCH THAT EXISTS TO REPORT A HANG COULD ITSELF HANG.
## `run_bounded` wraps all four and reports rc 124 on expiry.
##
## TWO FAILURES THAT LOOK IDENTICAL FROM INSIDE AN UNBOUNDED LOOP:
##   ENGINE UNREACHABLE — the daemon is not answering. Nothing in this repo
##     has run yet, so it cannot be a code fault.
##   POSTGRES NOT READY — the engine answered and the container was created,
##     but the database did not come up inside the bound. That IS about this
##     repo, so the failure prints `ps` and the container tail.
##
## IT RESTARTS NOTHING. Clearing a wedged engine destroys every container on
## the machine, including ones this repo knows nothing about. A build target
## that quietly reaches for that is one that eats other people's work.
##
## A SCRATCH PROJECT IS REUSE-ONLY (OSS-CANDIDATE-LIFECYCLE-FIX, SPEC K3). With
## IDENTUUM_IDP_COMPOSE_PROJECT=scratch-* (a candidate run, such as a mint's
## test-full), a PostgreSQL that merely answers the port is no ownership
## evidence. fast-up then reuses only the scratch PostgreSQL the caller names
## by the full container ID its create printed, FAST_UP_PG_CONTAINER, after
## checking on this unix-socket engine that the ID answers, is named
## scratch-*, is running, publishes exactly 5432/tcp on
## 127.0.0.1:DEV_PG_HOST_PORT and mounts no host path, and that the dev user
## connects. Anything else is refused, and a scratch project never falls back
## to a Compose start (that start recorded nothing). Reuse grants no removal.
## The default dev project is unchanged and is never a candidate path.
##
## IT STOPS NOTHING EITHER (TOOLS-MATRIX-CONTAINERS, 2026-10-05). When a
## PostgreSQL already answers DEV_PG_HOST_PORT and the dev user connects (the
## dev stack, or the owner's own stack from this same compose file), fast-up
## reuses it: the integration suites only need a server with their own
## identuum_idp_oss_test database (test-db). An incompatible server on the
## port is refused by name. Agents used to stop the owner's container to free
## 5513 for a second, identical server.
fast-up: protected-guard
	@run_bounded() { \
		_secs=$$1; shift; \
		_out=$$(mktemp); \
		"$$@" > "$$_out" 2>&1 & _pid=$$!; \
		_i=0; \
		while kill -0 $$_pid 2>/dev/null && [ $$_i -lt $$_secs ]; do sleep 1; _i=$$((_i+1)); done; \
		if kill -0 $$_pid 2>/dev/null; then \
			kill -9 $$_pid 2>/dev/null; wait $$_pid 2>/dev/null; \
			RB_OUT=$$(cat "$$_out"); rm -f "$$_out"; RB_RC=124; return 124; \
		fi; \
		wait $$_pid; _rc=$$?; \
		RB_OUT=$$(cat "$$_out"); rm -f "$$_out"; RB_RC=$$_rc; return $$_rc; \
	}; \
	if ! command -v docker > /dev/null 2>&1; then \
		echo "DOCKER CLI NOT FOUND: TOOL ABSENT — 'docker' is not on PATH."; \
		echo "This is not a wedged engine and not a code fault: the client itself is missing,"; \
		echo "so nothing was asked of any daemon. Install Docker, or point COMPOSE_CMD at a"; \
		echo "client that exists. fast-up FAILS here rather than reporting, because unlike the"; \
		echo "inventory it is an ACTION target: it cannot do its job without the tool."; \
		exit 1; \
	fi; \
	printf 'Probing the Docker engine (bound %ss)...\n' '$(ENGINE_PROBE_TIMEOUT)'; \
	run_bounded $(ENGINE_PROBE_TIMEOUT) docker version --format '{{.Server.Version}}'; \
	if [ $$RB_RC -eq 124 ]; then \
		echo "DOCKER ENGINE UNREACHABLE: no answer in $(ENGINE_PROBE_TIMEOUT)s."; \
		echo "'docker version' could not reach the server. NOTHING IN THIS REPO HAS RUN YET,"; \
		echo "so this is not a code fault: the daemon is wedged or stopped. Note that the"; \
		echo "published ports keep ACCEPTING TCP while this is true, so an open port and a"; \
		echo "listed container are NOT evidence the database is alive."; \
		echo "Clearing it is an operator decision (it kills every container on the machine),"; \
		echo "so this target will not do it for you."; \
		exit 1; \
	elif [ $$RB_RC -eq 127 ]; then \
		echo "DOCKER CLI NOT FOUND: TOOL ABSENT — the engine probe returned 127 (command not found)."; \
		echo "Nothing answered because nothing was run. This is NOT a wedged engine."; \
		exit 1; \
	elif [ $$RB_RC -ne 0 ]; then \
		echo "DOCKER ENGINE ERROR: 'docker version' answered but failed (exit $$RB_RC)."; \
		echo "This is DIFFERENT from a wedged engine — it replied, so read what it said:"; \
		echo "$$RB_OUT"; \
		exit 1; \
	fi; \
	echo "Docker engine OK (server $$RB_OUT)."; \
	case "$(DEV_COMPOSE_PROJECT)" in scratch-*) \
		cid="$${FAST_UP_PG_CONTAINER:-}"; \
		refuse() { echo "fast-up: REFUSED — $$1. Project $(DEV_COMPOSE_PROJECT) is a scratch (candidate) project: fast-up only REUSES a scratch PostgreSQL whose creation the caller recorded, by the full container ID its create printed (FAST_UP_PG_CONTAINER; docs/TESTING-OPERATORS.md), and it never starts one with Compose for a scratch project (nothing was started or stopped)"; exit 2; }; \
		case "$$cid" in ''|*[!0-9a-f]*) refuse "FAST_UP_PG_CONTAINER is not a full container ID";; esac; \
		[ $${#cid} -eq 64 ] || refuse "FAST_UP_PG_CONTAINER is not a full 64-character container ID"; \
		case "$${DOCKER_HOST:-unix:///}" in unix:///*) ;; *) refuse "DOCKER_HOST is not this host's own Docker engine (not a unix socket)";; esac; \
		run_bounded $(ENGINE_PROBE_TIMEOUT) docker container inspect --format '{{.Id}}|{{.Name}}|{{.State.Running}}|{{json .NetworkSettings.Ports}}|{{json .Mounts}}' "$$cid"; \
		[ $$RB_RC -eq 0 ] || refuse "container $$cid is not on this engine (docker container inspect exit $$RB_RC)"; \
		gid=$${RB_OUT%%|*}; r=$${RB_OUT#*|}; gname=$${r%%|*}; r=$${r#*|}; grun=$${r%%|*}; r=$${r#*|}; gports=$${r%%|*}; gmounts=$${r#*|}; \
		[ "$$gid" = "$$cid" ] || refuse "the container answering is not $$cid"; \
		case "$$gname" in /scratch-*) ;; *) refuse "container $$cid is not named scratch-*";; esac; \
		[ "$$grun" = true ] || refuse "container $$cid is not running"; \
		[ "$$gports" = '{"5432/tcp":[{"HostIp":"127.0.0.1","HostPort":"$(DEV_PG_HOST_PORT)"}]}' ] || refuse "container $$cid does not publish exactly 5432/tcp on 127.0.0.1:$(DEV_PG_HOST_PORT)"; \
		case "$$gmounts" in *'"Type":"bind"'*) refuse "container $$cid mounts a host path";; esac; \
		if command -v pg_isready > /dev/null 2>&1 && pg_isready -h 127.0.0.1 -p $(DEV_PG_HOST_PORT) -t 2 > /dev/null 2>&1 && \
			command -v psql > /dev/null 2>&1 && PGPASSWORD=dev-idp_oss_user-not-a-secret psql -h 127.0.0.1 -p $(DEV_PG_HOST_PORT) -U idp_oss_user -d postgres -tAc 'select 1' > /dev/null 2>&1; then \
			echo "fast-up: REUSING the recorded scratch PostgreSQL $$cid ($${gname#/}) on 127.0.0.1:$(DEV_PG_HOST_PORT): its full ID, name, state, single published port and mounts were checked on this engine; nothing started, nothing stopped, and reuse grants no removal."; \
			exit 0; \
		fi; \
		refuse "the recorded scratch PostgreSQL $$cid does not answer on 127.0.0.1:$(DEV_PG_HOST_PORT) with the dev user (a reuse-only run never falls back to starting one)";; \
	esac; \
	if command -v pg_isready > /dev/null 2>&1 && pg_isready -h 127.0.0.1 -p $(DEV_PG_HOST_PORT) -t 2 > /dev/null 2>&1; then \
		if command -v psql > /dev/null 2>&1 && PGPASSWORD=dev-idp_oss_user-not-a-secret psql -h 127.0.0.1 -p $(DEV_PG_HOST_PORT) -U idp_oss_user -d postgres -tAc 'select 1' > /dev/null 2>&1; then \
			echo "fast-up: a compatible PostgreSQL already answers 127.0.0.1:$(DEV_PG_HOST_PORT) (the dev user connects) — REUSING it; nothing started, nothing stopped."; \
			exit 0; \
		fi; \
		echo "fast-up: 127.0.0.1:$(DEV_PG_HOST_PORT) answers, but the dev user cannot connect — another server holds the port. Nothing was stopped: free it yourself, or set DEV_PG_HOST_PORT."; \
		exit 1; \
	fi; \
	printf 'Starting the dev stack (bound %ss)...\n' '$(COMPOSE_UP_TIMEOUT)'; \
	run_bounded $(COMPOSE_UP_TIMEOUT) $(COMPOSE_CMD) -f $(COMPOSE_FILE) up -d; \
	up_rc=$$RB_RC; echo "$$RB_OUT"; \
	if [ $$up_rc -eq 124 ]; then \
		echo "COMPOSE UP TIMED OUT after $(COMPOSE_UP_TIMEOUT)s."; \
		echo "The engine ANSWERED the version probe moments ago, so this is check-then-act:"; \
		echo "it wedged in between, or an image pull is slower than the bound. Re-run to"; \
		echo "distinguish them — a wedged engine fails at the probe instead."; \
		exit 1; \
	elif [ $$up_rc -eq 127 ]; then \
		echo "COMPOSE NOT FOUND: TOOL ABSENT — '$(COMPOSE_CMD)' returned 127 (command not found)."; \
		echo "The docker CLI exists but this compose invocation does not. Nothing was started."; \
		exit 1; \
	elif [ $$up_rc -ne 0 ]; then \
		echo "COMPOSE UP FAILED (exit $$up_rc). Output above."; \
		exit 1; \
	fi; \
	printf 'Waiting for PostgreSQL to become ready (bound %ss of WALL CLOCK)...\n' '$(PG_READY_TIMEOUT)'; \
	wait_start=$$(date +%s); deadline=$$(( wait_start + $(PG_READY_TIMEOUT) )); expired=0; \
	while :; do \
		rem=$$(( deadline - $$(date +%s) )); \
		if [ $$rem -le 0 ]; then expired=1; break; fi; \
		probe_t=$$rem; [ $$probe_t -gt 2 ] && probe_t=2; \
		if command -v pg_isready > /dev/null 2>&1; then \
			pg_isready -h 127.0.0.1 -p $(DEV_PG_HOST_PORT) -t $$probe_t > /dev/null 2>&1 && break; \
		else \
			run_bounded $$probe_t $(COMPOSE_CMD) -f $(COMPOSE_FILE) exec -T postgres-idp-oss pg_isready -h 127.0.0.1; \
			[ $$RB_RC -eq 0 ] && break; \
		fi; \
		if [ $$(date +%s) -ge $$deadline ]; then expired=1; break; fi; \
		sleep 1; \
	done; \
	if [ $$expired -eq 1 ]; then \
		echo "POSTGRES NOT READY: no answer on 127.0.0.1:$(DEV_PG_HOST_PORT) within $(PG_READY_TIMEOUT)s (waited $$(( $$(date +%s) - wait_start ))s)."; \
		echo "THE ENGINE ANSWERED, so this is NOT the wedged-engine fault — the container"; \
		echo "was created and the database did not come up. Evidence follows (bound $(EVIDENCE_TIMEOUT)s each)."; \
		run_bounded $(EVIDENCE_TIMEOUT) $(COMPOSE_CMD) -f $(COMPOSE_FILE) ps; \
		if [ $$RB_RC -eq 124 ]; then echo "  (compose ps timed out — the engine wedged while reporting)"; \
		elif [ $$RB_RC -eq 127 ]; then echo "  (compose ps: TOOL ABSENT — command not found, no evidence gathered)"; \
		else echo "$$RB_OUT"; fi; \
		run_bounded $(EVIDENCE_TIMEOUT) $(COMPOSE_CMD) -f $(COMPOSE_FILE) logs --tail 20 postgres-idp-oss; \
		if [ $$RB_RC -eq 124 ]; then echo "  (compose logs timed out — the engine wedged while reporting)"; \
		elif [ $$RB_RC -eq 127 ]; then echo "  (compose logs: TOOL ABSENT — command not found, no evidence gathered)"; \
		else echo "$$RB_OUT"; fi; \
		exit 1; \
	fi; \
	echo "PostgreSQL is ready (127.0.0.1:$(DEV_PG_HOST_PORT))."

## fast-down: stop and remove the local development containers (volume preserved).
##
## `--profile app` is REQUIRED (THE-MANUAL-TARGETS): compose only stops
## containers whose profile is active, so a plain `down` left the profiled app
## container RUNNING — holding the network open and serving against a database
## that had just been removed. Measured on the operator's box.
fast-down: protected-guard
	$(COMPOSE_CMD) -f $(COMPOSE_FILE) --profile app down

## fast-clean: stop containers AND remove the named volume (full reset).
## Use this to start with a fresh empty database. validate uses this automatically.
## Same `--profile app` requirement as fast-down — without it the app container
## survives the volume removal and keeps serving on a destroyed database.
fast-clean: protected-guard
	$(COMPOSE_CMD) -f $(COMPOSE_FILE) --profile app down --volumes

## dev-up: start the local IDP OSS app + Postgres stack (volumes preserved).
dev-up: protected-guard
	$(COMPOSE_CMD) -f $(COMPOSE_FILE) --profile app up -d

## dev-rebuild: rebuild and force-recreate only the local IDP OSS app service.
dev-rebuild: protected-guard
	$(COMPOSE_CMD) -f $(COMPOSE_FILE) --profile app up -d --build --force-recreate $(DEV_APP_SERVICE)

## dev-recreate-app: recover stale app container/network state without deleting Postgres data.
dev-recreate-app: protected-guard
	-$(COMPOSE_CMD) -f $(COMPOSE_FILE) --profile app rm -f -s $(DEV_APP_SERVICE)
	@docker rm -f $(DEV_APP_CONTAINER) 2>/dev/null || true
	$(COMPOSE_CMD) -f $(COMPOSE_FILE) up -d $(DEV_POSTGRES_SERVICE)
	sleep 3
	$(COMPOSE_CMD) -f $(COMPOSE_FILE) --profile app up -d --build --force-recreate $(DEV_APP_SERVICE)

## dev-ps: show local IDP OSS compose status.
dev-ps:
	$(COMPOSE_CMD) -f $(COMPOSE_FILE) --profile app ps

## dev-logs: follow local IDP OSS app logs (Ctrl-C to detach).
dev-logs: dev-app-logs

## dev-app-logs: follow local IDP OSS app logs (Ctrl-C to detach).
dev-app-logs:
	$(COMPOSE_CMD) -f $(COMPOSE_FILE) --profile app logs -f $(DEV_APP_SERVICE)

## dev-pg-logs: follow local IDP OSS Postgres logs (Ctrl-C to detach).
dev-pg-logs:
	$(COMPOSE_CMD) -f $(COMPOSE_FILE) logs -f $(DEV_POSTGRES_SERVICE)

## dev-down: stop and remove the local IDP OSS stack (volumes preserved).
dev-down: protected-guard
	$(COMPOSE_CMD) -f $(COMPOSE_FILE) --profile app down

## dev-seed: seed the RUNNING dev stack with known TEST credentials and print
## them (organization + org_admin + org_user + a confidential OAuth client).
## Requires a stack that is already up and MIGRATED. The credentials are
## public and documented — they are only ever valid in a disposable dev
## database, which is why the tool demands an explicit confirmation flag.
dev-seed: protected-guard
	go run ./tools/devseed --issuer http://127.0.0.1:$(DEV_APP_PORT) \
		--container $(DEV_APP_CONTAINER) --i-know-this-is-a-dev-database

## devseed-live (OSS-DEVSEED-LIVE, owner ruling u, 2026-10-07): dev-seed proved
## end to end on a DISPOSABLE appliance of its own — project scratch-devseed
## (identuum-devseed until OSS-CANDIDATE-LIFECYCLE-FIX, SPEC K1)
## from deployment/docker-compose.dev.yml, Postgres on 25513, app on 27113 (the
## P-087 variables) — so the owner's dev stack and the e2e harness are never
## touched. Every step prints `check OK:` or `check FAILED:` and decides the exit:
##   lock           an exclusive invocation lock, /tmp/identuum-harness.lock
##                  (HARNESS_LOCK: one fixed path per machine, whatever
##                  TMPDIR says — OSS-MINT-GUARD-4, review
##                  OSS-MINT-GUARD-3-PREREVIEW H1, where two callers with
##                  different TMPDIR values took different locks; shared
##                  since OSS-CANDIDATE-LIFECYCLE-FIX, SPEC K2, with
##                  openid-conformance and identuum-ui's e2e-full, so no two
##                  harness runs share a host port whatever their project or
##                  engine), taken before the first docker command, held
##                  through the teardown and released once everything the run
##                  recorded is proved gone (a refused or failed teardown
##                  keeps it, below); a held lock refuses
##                  (OSS-MINT-GUARD-3, review OSS-MINT-GUARD-2 G2: two runs
##                  could otherwise both see an empty project and tear down
##                  each other's resources); with it a random invocation id is
##                  drawn, the label io.identuum.harness.invocation that binds
##                  what this run creates to this run;
##   command        the Compose command is fixed (OSS-MINT-GUARD-6, review
##                  OSS-MINT-GUARD-5 F1): COMPOSE_CMD, from the environment,
##                  the command line or `make -e`, must be exactly
##                  `docker compose` (COMPOSE_CMD_IS_DOCKER_COMPOSE), else
##                  refused before the lock and any docker command; the run
##                  calls `docker compose` itself, and the nested oss-up gets
##                  COMPOSE_CMD='docker compose' on its command line with
##                  MAKEFLAGS, MAKEOVERRIDES, MFLAGS and MAKEFILES cleared;
##   topology       exactly one supported topology (OSS-MINT-GUARD-5, review
##                  OSS-MINT-GUARD-4 R2, owner ruling Q-TOPOLOGY (b)): this
##                  host's own Docker engine through a unix socket on this
##                  host. A DOCKER_HOST that is not unix:///... is refused
##                  before any docker command; then the endpoint docker itself
##                  resolves (DOCKER_HOST, else DOCKER_CONTEXT, else the
##                  current context; `docker context inspect`, local config
##                  only) must be unix:///..., else refused; every later docker
##                  call, oss-up's included, is pinned to it (DOCKER_HOST set
##                  to it, DOCKER_CONTEXT unset);
##   engine         the daemon's ID (`docker info`) is recorded (OSS-MINT-GUARD-6,
##                  F2, judge ruling Q2 (a)); every later docker call of the
##                  recipe first checks that the same ID answers, and so do
##                  the nested oss-build and oss-up (HARNESS_BINDING_CHECK) and
##                  each devseed step; a changed or silent daemon stops every
##                  further docker command, the run is red and nothing more is
##                  removed. The check precedes each call: an engine switched
##                  inside one docker or Compose call is not seen;
##   mutex          then, before any resource call, the daemon mutex: the
##                  never-started container HARNESS_MUTEX
##                  (identuum-harness-lock-engine) created on the checked
##                  engine from HARNESS_MUTEX_IMAGE (--pull=never: an absent
##                  image is a refusal naming `docker pull`), labelled with
##                  this run's id, the engine's, this project and its two
##                  ports. The daemon refuses a second container of that
##                  name, so a second devseed-live, openid-conformance or
##                  e2e-full run against this engine is refused, from
##                  whatever filesystem namespace or /tmp it runs. Held
##                  through the teardown, then removed by its ID after its
##                  labels are re-read; a mutex that already exists (held, or
##                  left by a killed run) is never removed by the harness: the
##                  refusal names it with a read-only inspection command;
##                  removal is a manual owner decision. The /tmp lock
##                  above stays as well;
##   preflight      the project holds NO container, volume or network (by its
##                  compose label) and no container is named scratch-devseed
##                  or scratch-devseed-postgres, else refused naming them
##                  with read-only inspection commands (removal is a manual
##                  owner decision, OSS-TEARDOWN-MESSAGES) — leftovers are never
##                  deleted by assumption (judge ruling Q2(b), OSS-MINT-GUARD-2;
##                  until then a `down --volumes` ran first, on whatever the
##                  project held); then the names this run creates — each
##                  volume and network key as scratch-devseed_<key>_<invocation
##                  id> (OSS-MINT-GUARD-5, R1), given to Compose by the overlay
##                  and checked against `docker compose config` with it — are
##                  looked for in an UNFILTERED listing and refused if one
##                  exists, whatever its labels (G2); the names, all absent,
##                  are this run's inventory; the resolved config must hold
##                  exactly app and postgres-idp-oss, no privileged or
##                  host-namespace service, no host mount, no external network
##                  or volume and no volume backed by a host path, the two
##                  ports on 127.0.0.1 only and the app image named
##                  <project>:local (SPEC K1), else refused; then both host
##                  ports free, else refused naming the holder;
##   up             oss-up builds the tree and starts the project, its
##                  project, app container and ports passed on oss-up's
##                  command line so an outer command line cannot split them,
##                  with a generated compose overlay ($dir/invocation.json)
##                  that puts the invocation label on every service, volume
##                  and network the resolved config names, and gives each
##                  volume and network its invocation-unique name;
##   record         right after the start, the containers and networks
##                  carrying this run's invocation label, by full ID, and its
##                  volumes, by name and creation time, are written to
##                  $dir/created: what this run actually created; a public
##                  projection, manifest.json in the claim (engine, endpoint,
##                  project, invocation, ports, mutex, every recorded
##                  resource), is written whole after the reservation, after
##                  the record and after the teardown (SPEC K4, K6);
##   health         /health answers within 120s;
##   seed           devseed as dev-seed runs it (--container) plus --json;
##   credentials    TestDevseedLive (tools/devseed/live_test.go) signs in as
##                  site_admin and org_admin with password + a TOTP code from
##                  the printed secret, signs org_user in with its password
##                  alone (TOTP is asked of admins only here), and authenticates the client
##                  at the token endpoint: a bogus code with the right secret
##                  gets exactly 400 invalid_grant, a wrong secret 401
##                  invalid_client, and nothing else passes;
##   second run     a re-seed refuses as devseed documents (the org_admin
##                  already has TOTP, and devseed keeps no copy of the secret);
##   teardown       on every exit (EXIT, INT and TERM traps) it removes the
##                  recorded resources and nothing else, never a project-level
##                  `down` (OSS-MINT-GUARD-4, review OSS-MINT-GUARD-3-PREREVIEW
##                  H2: a project label and an expected name are shared by
##                  anything of the project, so they prove no ownership). Each
##                  recorded container and network is re-inspected and removed
##                  by its ID (`docker rm -f -v`, `docker network rm`) only when
##                  its ID and invocation label still match; a recorded volume
##                  only when its name carries this run's invocation id and
##                  its creation time and label still match (`docker volume
##                  rm`). Docker removes a volume by name with no identity
##                  precondition, so between the last inspection and the
##                  removal another writer could replace a volume under a
##                  shared name (review OSS-MINT-GUARD-4 R1, E-RACE); the
##                  random id in the name keeps an ordinary stack's volume out
##                  of reach, and a recorded volume without it is refused, not
##                  removed. The accepted residual (judge ruling Q3 (a),
##                  OSS-MINT-GUARD-6): a writer outside the harness that copies
##                  this run's exact name from the daemon inside that interval
##                  can have its volume removed without a red verdict; neither
##                  lock nor mutex binds such a writer. ONE WHOLE STEP
##                  (OSS-CANDIDATE-LIFECYCLE-FIX, SPEC K5): everything is
##                  checked before the first removal — a container, network or
##                  volume of the project, or one carrying a name this run
##                  would create, that is not in the record (a foreign
##                  same-project container, a same-name replacement, whatever
##                  its labels), a recorded object whose identity changed, a
##                  recorded volume name without the invocation id, and a
##                  container this run did not create attached to a recorded
##                  network or using a recorded volume — and one finding
##                  refuses the whole step: NOTHING is removed, check FAILED.
##                  After the removals every recorded object is proved gone,
##                  then 0 containers and 0 volumes of the project, counted by
##                  docker commands whose own failure fails the check. A failed
##                  listing removes nothing. A refused or failed teardown, a
##                  record that cannot be written or a changed engine keeps the
##                  claim, the daemon mutex and the record for an operator.
## OSS-PRE-RELEASE-FIXES: before ANY docker command the project must be
## scratch-devseed and not a PROTECTED_CONTAINERS name or the dev project, so
## a command-line DEVSEED_LIVE_PROJECT cannot aim the cleanup at the owner's
## stack. DEVSEED_LIVE_PG_PORT, however it is selected (command line,
## environment, an `override` elsewhere), must be a decimal port 1-65535 with
## no leading zero and neither 5513 (the owner's PostgreSQL) nor 5432, else
## refused before any docker command (OSS-MINT-GUARD-5, review
## OSS-MINT-GUARD-4 R3); the validated value is the one every step uses. The
## occupied-port refusal in preflight stays as an additional check. The
## --json output (passwords, TOTP secrets, the client secret) and
## every log go to mode-600 files (umask 077) in a fresh mktemp directory that
## is left for the owner; this recipe prints only check names. test-full-mint
## runs it BEFORE the e2e half (owner ruling v, 2026-10-08, amends P-089).
## OSS-MINT-GUARD-6 (review OSS-MINT-GUARD-5 F1): the harnesses' Compose
## command is fixed, not the caller's. COMPOSE_CMD_IS_DOCKER_COMPOSE is yes only
## when COMPOSE_CMD's own text, read with $(value) and never expanded (a
## caller's make function or shell text does not run), is exactly
## `docker compose`: a global option in it (--host, -H, --context, -c or any
## other) would select an engine the topology check never saw.
COMPOSE_CMD_IS_DOCKER_COMPOSE = $(if $(and $(findstring $(value COMPOSE_CMD),docker compose),$(findstring docker compose,$(value COMPOSE_CMD))),yes,no)
## OSS-MINT-GUARD-6 (F2, judge ruling Q2 (a)): the daemon mutex. One
## never-started container of this fixed name on the checked engine, shared by
## devseed-live and identuum-ui's e2e-full: the daemon refuses a second
## container of one name, so every caller of that engine is serialized,
## whatever its filesystem namespace or /tmp. Created from the distroless
## runtime image deployment/Dockerfile.local pins (no VOLUME, so creating it
## creates no volume), never pulled by the harness. A held one is never broken
## automatically. `override`, so no command line moves either.
override HARNESS_MUTEX := identuum-harness-lock-engine
override HARNESS_MUTEX_IMAGE := gcr.io/distroless/static-debian12@sha256:d75cdd72874d4790092fcb1b058493ecf6bb5bf2b2b897045b00ff01d91843f2
## HARNESS_BINDING_CHECK: the nested oss-build and oss-up of a harness run
## (devseed-live and e2e-full pass IDENTUUM_HARNESS_ENGINE_ID and
## IDENTUUM_HARNESS_MUTEX_ID) re-check before their own docker call that
## COMPOSE_CMD is exactly docker compose, DOCKER_CONTEXT is unset and
## DOCKER_HOST a unix socket, the daemon answering has the ID the harness
## recorded, and the daemon mutex is still the harness's own; and
## (OSS-CANDIDATE-LIFECYCLE-FIX, SPEC K1) that the nested project is a
## scratch- project. An ordinary oss-up, without the binding, is unchanged.
HARNESS_BINDING_CHECK = @if [ -n "$${IDENTUUM_HARNESS_ENGINE_ID:-}" ]; then \
	r="$@: REFUSED under the harness binding (nothing was built or started)"; \
	[ "$(COMPOSE_CMD_IS_DOCKER_COMPOSE)" = yes ] || { echo "$$r — COMPOSE_CMD is not exactly 'docker compose'" >&2; exit 2; }; \
	case "$(DEV_COMPOSE_PROJECT)" in scratch-*) ;; *) echo "$$r — project $(DEV_COMPOSE_PROJECT) is not a scratch- project; a harness starts scratch-prefixed projects only" >&2; exit 2;; esac; \
	case "$${DOCKER_CONTEXT:-}|$${DOCKER_HOST:-}" in "|unix:///"*) ;; *) echo "$$r — the Docker endpoint is not the harness's pinned unix socket" >&2; exit 2;; esac; \
	[ "$$(docker info --format '{{.ID}}' 2>/dev/null)" = "$$IDENTUUM_HARNESS_ENGINE_ID" ] || { echo "$$r — the Docker daemon answering is not the engine the harness checked (its ID changed, or it did not answer)" >&2; exit 2; }; \
	[ -n "$${IDENTUUM_HARNESS_MUTEX_ID:-}" ] && [ "$$(docker container inspect --format '{{.Id}}' $(HARNESS_MUTEX) 2>/dev/null)" = "$$IDENTUUM_HARNESS_MUTEX_ID" ] || { echo "$$r — the daemon mutex $(HARNESS_MUTEX) is not the harness's own" >&2; exit 2; }; \
	fi
## OSS-CANDIDATE-LIFECYCLE-FIX (SPEC K1): the project is scratch-prefixed, like
## every candidate-effective Compose project, so every name it derives
## (containers, image tag, volume, network) is a scratch name.
DEVSEED_LIVE_PROJECT := scratch-devseed
DEVSEED_LIVE_PG_PORT := 25513
DEVSEED_LIVE_APP_PORT := 27113
## The one harness claim on this machine (OSS-MINT-GUARD-4, review
## OSS-MINT-GUARD-3-PREREVIEW H1): a fixed path, never derived from TMPDIR or
## any other variable, and `override` so a command line cannot move it either.
## OSS-CANDIDATE-LIFECYCLE-FIX (SPEC K2): shared by every harness —
## devseed-live, conformance/run.sh (openid-conformance) and identuum-ui's
## e2e-full — so one host authority reserves every harness project and port
## together (devseed-live and openid-conformance both publish 27113). A claim
## kept by a refused teardown, with its manifest.json, is refused until an
## operator resolves it. compose-pin-selftest rewrites this one line in its
## private copy of the Makefile.
override HARNESS_LOCK := /tmp/identuum-harness.lock
.PHONY: devseed-live
devseed-live:
	@set -u; umask 077; p=$(DEVSEED_LIVE_PROJECT); app=$(DEVSEED_LIVE_APP_PORT); pg='$(DEVSEED_LIVE_PG_PORT)'; \
	if [ "$$p" != scratch-devseed ]; then echo "devseed-live: REFUSED — project '$$p' is not scratch-devseed; this target only ever tears down its own project (no docker command was run)"; exit 2; fi; \
	for n in $(PROTECTED_CONTAINERS) identuum-idp-oss-dev; do \
		if [ "$$p" = "$$n" ]; then echo "devseed-live: REFUSED — project '$$p' is protected or the dev project (no docker command was run)"; exit 2; fi; \
	done; \
	case "$$pg" in ''|0*|*[!0-9]*) echo "devseed-live: REFUSED — DEVSEED_LIVE_PG_PORT '$$pg' is not a port number (no docker command was run)"; exit 2;; esac; \
	if [ $${#pg} -gt 5 ] || [ "$$pg" -gt 65535 ] || [ "$$pg" = 5513 ] || [ "$$pg" = 5432 ]; then echo "devseed-live: REFUSED — DEVSEED_LIVE_PG_PORT $$pg is not a port devseed-live starts PostgreSQL on: 5513 (the owner's PostgreSQL) and 5432 are refused however they are selected, and a port must be 1-65535; choose a free scratch port (no docker command was run)"; exit 2; fi; \
	if [ "$(COMPOSE_CMD_IS_DOCKER_COMPOSE)" != yes ]; then echo "devseed-live: REFUSED — COMPOSE_CMD is not exactly 'docker compose'. This target fixes its Compose command: a global option in it (--host, -H, --context, -c or any other) would select an engine the topology check never saw. Unset COMPOSE_CMD (no docker command was run)"; exit 2; fi; \
	export IDENTUUM_IDP_COMPOSE_PROJECT="$$p" DEV_PG_HOST_PORT="$$pg" DEV_APP_PORT="$$app"; \
	dc() { ( unset COMPOSE_PROJECT_NAME COMPOSE_REMOVE_ORPHANS; docker compose -p "$$p" -f deployment/docker-compose.dev.yml --profile app "$$@" ); }; \
	dir=$$(mktemp -d "$${TMPDIR:-/tmp}/devseed-live.XXXXXX"); fails=0; cleaned=0; keep=0; \
	ok() { echo "devseed-live: check OK: $$1"; }; \
	bad() { echo "devseed-live: check FAILED: $$1"; fails=$$((fails+1)); }; \
	insp() { case "$$1" in container) ic='docker inspect'; ifm='{{.Id}} {{.Name}} {{index .Config.Labels "com.docker.compose.project"}} {{index .Config.Labels "io.identuum.harness.invocation"}}';; \
		network) ic='docker network inspect'; ifm='{{.Id}} {{.Name}} {{index .Labels "com.docker.compose.project"}} {{index .Labels "io.identuum.harness.invocation"}}';; \
		*) ic='docker volume inspect'; ifm='{{.Name}} {{.CreatedAt}} {{index .Labels "com.docker.compose.project"}} {{index .Labels "io.identuum.harness.invocation"}}';; esac; \
		printf "devseed-live:   found %s %s; inspect its ID, name and ownership labels:\n    %s --format '%s' '%s'\n" "$$1" "$$2" "$$ic" "$$ifm" "$$2"; }; \
	lock='$(HARNESS_LOCK)'; \
	if ! mkdir "$$lock" 2>/dev/null; then hl='no holder file'; \
		if [ -f "$$lock/holder" ]; then IFS= read -r hl < "$$lock/holder" || true; hl=$$(printf '%s' "$$hl" | LC_ALL=C tr -cd 'A-Za-z0-9._ -' | cut -c1-80); fi; \
		echo "devseed-live: check FAILED: preflight — could not take $$lock: another harness run on this machine holds it (devseed-live, final-conformance, testbook-fixtures, human-acceptance, openid-conformance or identuum-ui e2e-full/e2e-quick; every run takes this one claim, whatever its TMPDIR), or a killed run left it, or a refused teardown kept it with its record; read $$lock/manifest.json when present. Removal is a manual owner decision (refused; no docker command was run)"; \
		echo "devseed-live: holder: $$hl"; exit 1; fi; \
	echo $$$$ > "$$lock/pid"; printf 'devseed-live %s\n' "$$p" > "$$lock/holder"; trap 'rm -rf "$$lock"' EXIT; \
	topo="devseed-live supports exactly one topology: this host's own Docker engine, through a unix socket on this host (unix:///...); unset DOCKER_HOST and DOCKER_CONTEXT, or select the local context (docker context use <name>)"; \
	case "$${DOCKER_HOST:-unix:///}" in unix:///*) ;; *) echo "devseed-live: check FAILED: preflight — DOCKER_HOST selects an endpoint that is not this host's own Docker engine (not a unix socket). $$topo (refused; no docker command was run)"; exit 1;; esac; \
	if ! ep=$$(docker context inspect --format '{{.Endpoints.docker.Host}}' 2>>"$$dir/preflight.log"); then echo "devseed-live: check FAILED: preflight — the Docker context could not be resolved, so the engine this run would use is unknown. $$topo (refused; nothing was started)"; exit 1; fi; \
	case "$$ep" in unix:///*) ;; *) echo "devseed-live: check FAILED: preflight — the selected Docker context's endpoint is not this host's own Docker engine (not a unix socket). $$topo (refused; nothing was started)"; exit 1;; esac; \
	export DOCKER_HOST="$$ep"; unset DOCKER_CONTEXT; \
	ok "preflight — the Docker endpoint is this host's own engine (a unix socket); every docker call of this run is pinned to it"; \
	lab=io.identuum.harness.invocation; iid=$$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n'); \
	case "$$iid" in *[!0-9a-f]*|'') echo "devseed-live: check FAILED: preflight — no invocation id could be drawn from /dev/urandom (refused; no docker command was run)"; exit 1;; esac; \
	[ $${#iid} -eq 32 ] || { echo "devseed-live: check FAILED: preflight — no invocation id could be drawn from /dev/urandom (refused; no docker command was run)"; exit 1; }; \
	eflag="$$dir/engine-changed"; \
	if ! eng=$$(docker info --format '{{.ID}}' 2>>"$$dir/preflight.log") || [ -z "$$eng" ]; then echo "devseed-live: check FAILED: preflight — the Docker daemon did not report its ID, so this run cannot bind to the engine it checked (refused; nothing was started)"; exit 1; fi; \
	still() { [ ! -e "$$eflag" ] && [ "$$(command docker info --format '{{.ID}}' 2>/dev/null)" = "$$eng" ] && return 0; : > "$$eflag"; echo "devseed-live: REFUSED — the Docker daemon answering is not the engine checked at preflight (its ID changed, or it did not answer); no further docker command is run" >&2; return 1; }; \
	docker() { still || return 1; command docker "$$@"; }; \
	mx='$(HARNESS_MUTEX)'; mimg='$(HARNESS_MUTEX_IMAGE)'; mid=; \
	mfmt='{{.Id}} {{index .Config.Labels "io.identuum.harness.mutex-owner"}} {{index .Config.Labels "io.identuum.harness.engine"}}'; \
	release_mutex() { [ -n "$$mid" ] || return 0; m=$$mid; mid=; \
		if [ "$$keep" = 1 ]; then echo "devseed-live: the daemon mutex $$mx ($$m) is KEPT with the claim $$lock: this run's resources were not all proved gone"; return; fi; \
		if [ -e "$$eflag" ]; then keep=1; bad "engine — the Docker daemon answering is not the engine checked at preflight (its ID changed, or it did not answer): no further docker command was run, nothing more was removed, and the daemon mutex $$mx is left on the engine it was taken on. Removal is a manual owner decision. Inspect that engine read-only: docker container inspect $$mx"; return; fi; \
		if [ "$$(docker container inspect --format "$$mfmt" "$$m" 2>>"$$dir/down.log")" = "$$m $$iid $$eng" ] && docker container rm "$$m" >>"$$dir/down.log" 2>&1; then ok "mutex — released the daemon mutex $$mx, this run's, by its ID"; \
		else keep=1; bad "mutex — the daemon mutex $$mx is no longer this run's, or could not be removed; it was left in place. Removal is a manual owner decision. Inspect it read-only: docker container inspect $$mx (log: $$dir/down.log)"; fi; }; \
	wm() { { printf '{"schema":"identuum.harness.run.v1","kind":"devseed-live","state":"%s","project":"%s","invocation":"%s","daemon_id":"%s","endpoint":"%s","mutex_id":"%s","ports":[%s,%s],"resources":[' "$$1" "$$p" "$$iid" "$$eng" "$$ep" "$$mid" "$$pg" "$$app"; sep=; \
		if [ -e "$$dir/created" ]; then while read -r k i t; do [ -n "$$k" ] || continue; if [ "$$k" = volume ]; then printf '%s{"kind":"volume","name":"%s","created_at":"%s"}' "$$sep" "$$i" "$$t"; else printf '%s{"kind":"%s","id":"%s"}' "$$sep" "$$k" "$$i"; fi; sep=,; done < "$$dir/created"; fi; \
		printf ']}\n'; } > "$$lock/manifest.json.part" && mv "$$lock/manifest.json.part" "$$lock/manifest.json"; }; \
	if ! vols=$$(docker image inspect --format '{{json .Config.Volumes}}' "$$mimg" 2>>"$$dir/preflight.log"); then echo "devseed-live: check FAILED: preflight — the daemon mutex image $$mimg is not on this engine; pull it once (docker pull $$mimg) and re-run (refused; nothing was started)"; exit 1; fi; \
	[ "$$vols" = null ] || { echo "devseed-live: check FAILED: preflight — the daemon mutex image $$mimg declares a VOLUME, so creating the mutex would create a volume (refused; nothing was started)"; exit 1; }; \
	if ! mid=$$(docker container create --name "$$mx" --pull=never --network=none --restart=no --read-only --label io.identuum.harness.mutex=engine-v1 --label "io.identuum.harness.mutex-owner=$$iid" --label "io.identuum.harness.engine=$$eng" --label io.identuum.harness.kind=devseed-live --label "io.identuum.harness.project=$$p" --label "io.identuum.harness.ports=$$pg,$$app" "$$mimg" /identuum-harness-lock 2>>"$$dir/preflight.log") || [ -z "$$mid" ]; then mid=; \
		echo "devseed-live: check FAILED: preflight — could not take the daemon mutex: container $$mx could not be created on this engine. Another harness run (devseed-live, openid-conformance or e2e-full, from any filesystem namespace) holds it, or a killed run left it; it is never removed automatically. Removal is a manual owner decision. Inspect it read-only (docker container inspect $$mx; labels io.identuum.harness.*) (refused; nothing was started)"; exit 1; fi; \
	trap 'release_mutex; [ "$$keep" = 1 ] || rm -rf "$$lock"' EXIT; \
	if [ "$$(docker container inspect --format "$$mfmt" "$$mid" 2>>"$$dir/preflight.log")" != "$$mid $$iid $$eng" ]; then echo "devseed-live: check FAILED: preflight — the daemon mutex $$mx read back is not the one this run created (refused; nothing was started)"; exit 1; fi; \
	ok "preflight — took the daemon mutex $$mx on the engine checked; held through the teardown, and every later docker call first checks that the same engine answers"; \
	wm reserved || { echo "devseed-live: check FAILED: preflight — the run record $$lock/manifest.json could not be written (refused; nothing was started)"; exit 1; }; \
	record() { \
		if ! rc=$$(docker ps -aq --no-trunc --filter "label=$$lab=$$iid" 2>>"$$dir/down.log") || ! rn=$$(docker network ls -q --no-trunc --filter "label=$$lab=$$iid" 2>>"$$dir/down.log") || \
			! rv=$$(docker volume ls -q --filter "label=$$lab=$$iid" 2>>"$$dir/down.log"); then return 1; fi; \
		for c in $$rc; do got=$$(docker inspect --format "{{.Id}} {{index .Config.Labels \"$$lab\"}} {{index .Config.Labels \"com.docker.compose.project\"}} {{.Name}}" "$$c") || return 1; \
			read -r id marker project name <<<"$$got"; [ "$$id $$marker $$project" = "$$c $$iid $$p" ] || return 1; case "$$name" in /"$$p"|/"$$p-postgres") ;; *) return 1;; esac; \
			mounts=$$(docker inspect --format '{{range .Mounts}}{{if eq .Type "volume"}}{{println .Name}}{{end}}{{end}}' "$$c") || return 1; for v in $$mounts; do printf '%s\n' "$$rv" | grep -qxF "$$v" || return 1; done; done; \
		{ for c in $$rc; do echo "container $$c"; done; for n in $$rn; do name=$$(docker network inspect --format '{{.Name}}' "$$n") || return 1; grep -qxF "network:$$name" "$$dir/inventory" || return 1; echo "network $$n"; done; \
			for v in $$rv; do grep -qxF "volume:$$v" "$$dir/inventory" || return 1; t=$$(docker volume inspect --format '{{.CreatedAt}}' "$$v" 2>>"$$dir/down.log") && [ -n "$$t" ] || return 1; echo "volume $$v $$t"; done; } > "$$dir/created.part" || return 1; \
		seal; }; \
	seal() { mv "$$dir/created.part" "$$dir/created" && wm created && cksum "$$dir/created" "$$lock/manifest.json" > "$$dir/created.complete.part" && mv "$$dir/created.complete.part" "$$dir/created.complete"; }; \
	teardown() { \
		if [ ! -f "$$dir/created.complete" ] || [ ! -f "$$dir/created" ] || [ ! -f "$$lock/manifest.json" ] || [ "$$(cksum "$$dir/created" "$$lock/manifest.json")" != "$$(cat "$$dir/created.complete")" ]; then keep=1; bad "teardown — refused: creation record missing or incomplete; labels cannot reconstruct it; nothing was removed (log: $$dir/down.log)"; return; fi; \
		if ! allc=$$(docker ps -aq --no-trunc 2>>"$$dir/down.log") || ! projc=$$(docker ps -aq --no-trunc --filter "label=com.docker.compose.project=$$p" 2>>"$$dir/down.log") || \
			! namec=$$(docker ps -a --no-trunc --format '{{.ID}} {{.Names}}' 2>>"$$dir/down.log") || \
			! alln=$$(docker network ls --no-trunc --format '{{.ID}} {{.Name}}' 2>>"$$dir/down.log") || ! projn=$$(docker network ls -q --no-trunc --filter "label=com.docker.compose.project=$$p" 2>>"$$dir/down.log") || \
			! allv=$$(docker volume ls --format '{{.Name}}' 2>>"$$dir/down.log") || ! projv=$$(docker volume ls -q --filter "label=com.docker.compose.project=$$p" 2>>"$$dir/down.log"); then \
			keep=1; bad "teardown — refused: docker could not list containers, networks and volumes, so this run's ownership was not proved; nothing was removed"; return; fi; \
		rec() { grep -qxF "$$1 $$2" "$$dir/created" || grep -q "^$$1 $$2 " "$$dir/created"; }; strange=; removed=0; \
		for c in $$projc $$(printf '%s\n' "$$namec" | awk -v a="$$p" -v b="$$p-postgres" '$$2==a||$$2==b{print $$1}'); do rec container "$$c" || strange="$$strange container:$$c"; done; \
		for n in $$projn; do rec network "$$n" || strange="$$strange network:$$n"; done; \
		for v in $$projv; do rec volume "$$v" || strange="$$strange volume:$$v"; done; \
		for e in $$(cat "$$dir/inventory"); do nm=$${e#*:}; case "$$e" in \
			network:*) for n in $$(printf '%s\n' "$$alln" | awk -v n="$$nm" '$$2==n{print $$1}'); do rec network "$$n" || strange="$$strange network:$$nm"; done;; \
			*) if printf '%s\n' "$$allv" | grep -qxF "$$nm"; then rec volume "$$nm" || strange="$$strange volume:$$nm"; fi;; esac; done; \
		while read -r kind id t; do case "$$kind" in \
			container) printf '%s\n' "$$allc" | grep -qxF "$$id" || continue; \
				[ "$$(docker inspect --format "{{.Id}} {{index .Config.Labels \"$$lab\"}}" "$$id" 2>>"$$dir/down.log")" = "$$id $$iid" ] || strange="$$strange container:$$id(identity changed)"; \
				if ! mounts=$$(docker inspect --format '{{range .Mounts}}{{if eq .Type "volume"}}{{println .Name}}{{end}}{{end}}' "$$id" 2>>"$$dir/down.log"); then strange="$$strange container:$$id(mount inspection failed)"; else for v in $$mounts; do rec volume "$$v" || strange="$$strange container:$$id(unrecorded volume $$v)"; done; fi;; \
			network) printf '%s\n' "$$alln" | awk '{print $$1}' | grep -qxF "$$id" || continue; \
				[ "$$(docker network inspect --format "{{.Id}} {{index .Labels \"$$lab\"}}" "$$id" 2>>"$$dir/down.log")" = "$$id $$iid" ] || { strange="$$strange network:$$id(identity changed)"; continue; }; \
				if ! us=$$(docker ps -aq --no-trunc --filter "network=$$id" 2>>"$$dir/down.log"); then strange="$$strange network:$$id(its members could not be listed)"; continue; fi; \
				for c in $$us; do rec container "$$c" || strange="$$strange network:$$id(container $$c, not recorded, is attached)"; done;; \
			volume) printf '%s\n' "$$allv" | grep -qxF "$$id" || continue; \
				case "$$id" in *_"$$iid") ;; *) strange="$$strange volume:$$id(name lacks the invocation id of this run, so a removal by name could reach another writer's volume)"; continue;; esac; \
				[ "$$(docker volume inspect --format "{{.CreatedAt}} {{index .Labels \"$$lab\"}}" "$$id" 2>>"$$dir/down.log")" = "$$t $$iid" ] || { strange="$$strange volume:$$id(replaced since it was recorded)"; continue; }; \
				if ! us=$$(docker ps -aq --no-trunc --filter "volume=$$id" 2>>"$$dir/down.log"); then strange="$$strange volume:$$id(its users could not be listed)"; continue; fi; \
				for c in $$us; do rec container "$$c" || strange="$$strange volume:$$id(container $$c, not recorded, uses it)"; done;; esac; done < "$$dir/created"; \
		if [ -n "$$strange" ]; then keep=1; bad "teardown — refused for$$strange: this run did not record creating it (by ID, with its invocation label), its identity changed since, or something it did not create is attached to what it did; the whole step was refused before the first removal, so NOTHING was removed, this run's own resources included"; return; fi; \
		while read -r kind id t; do case "$$kind" in \
			container) printf '%s\n' "$$allc" | grep -qxF "$$id" || continue; \
				[ "$$(docker inspect --format "{{.Id}} {{index .Config.Labels \"$$lab\"}}" "$$id" 2>>"$$dir/down.log")" = "$$id $$iid" ] || { keep=1; bad "teardown — container $$id changed identity right before its removal; not removed"; continue; }; \
				if docker rm -f "$$id" >>"$$dir/down.log" 2>&1; then removed=$$((removed+1)); else keep=1; bad "teardown — removing this run's container $$id failed (log: $$dir/down.log)"; fi;; \
			network) printf '%s\n' "$$alln" | awk '{print $$1}' | grep -qxF "$$id" || continue; \
				[ "$$(docker network inspect --format "{{.Id}} {{index .Labels \"$$lab\"}}" "$$id" 2>>"$$dir/down.log")" = "$$id $$iid" ] || { keep=1; bad "teardown — network $$id changed identity right before its removal; not removed"; continue; }; \
				if docker network rm "$$id" >>"$$dir/down.log" 2>&1; then removed=$$((removed+1)); else keep=1; bad "teardown — removing this run's network $$id failed (log: $$dir/down.log)"; fi;; \
			volume) printf '%s\n' "$$allv" | grep -qxF "$$id" || continue; \
				[ "$$(docker volume inspect --format "{{.CreatedAt}} {{index .Labels \"$$lab\"}}" "$$id" 2>>"$$dir/down.log")" = "$$t $$iid" ] || { keep=1; bad "teardown — volume $$id was replaced right before its removal (its creation time or invocation label changed); not removed"; continue; }; \
				if docker volume rm "$$id" >>"$$dir/down.log" 2>&1; then removed=$$((removed+1)); else keep=1; bad "teardown — removing this run's volume $$id failed (log: $$dir/down.log)"; fi;; esac; done < "$$dir/created"; \
		if ! allc=$$(docker ps -aq --no-trunc 2>>"$$dir/down.log") || ! alln=$$(docker network ls -q --no-trunc 2>>"$$dir/down.log") || ! allv=$$(docker volume ls --format '{{.Name}}' 2>>"$$dir/down.log"); then \
			keep=1; bad "teardown — docker could not list containers, networks and volumes after the removals, so none was proved gone"; return; fi; \
		left=; while read -r kind id t; do case "$$kind" in container) all=$$allc;; network) all=$$alln;; volume) all=$$allv;; *) continue;; esac; \
			printf '%s\n' "$$all" | grep -qxF "$$id" && left="$$left $$kind:$$id"; done < "$$dir/created"; \
		if [ -n "$$left" ]; then keep=1; bad "teardown — still present after its removal:$$left"; return; fi; \
		if ! cs=$$(docker ps -aq --filter "label=com.docker.compose.project=$$p" 2>>"$$dir/down.log"); then keep=1; bad "teardown — docker ps failed, so the containers of $$p were not counted"; return; fi; \
		if ! vs=$$(docker volume ls -q --filter "label=com.docker.compose.project=$$p" 2>>"$$dir/down.log"); then keep=1; bad "teardown — docker volume ls failed, so the volumes of $$p were not counted"; return; fi; \
		c=$$(printf '%s' "$$cs" | grep -c .); v=$$(printf '%s' "$$vs" | grep -c .); \
		if [ "$$c" = 0 ] && [ "$$v" = 0 ]; then ok "teardown — removed the $$removed resource(s) this run recorded creating, each by ID after rechecking its identity, and proved each gone; 0 containers and 0 volumes of $$p left"; \
		else keep=1; bad "teardown — project $$p still has $$c container(s) and $$v volume(s)"; fi; }; \
	advise() { echo "devseed-live: Removal is a manual owner decision. Inspect on the original engine $$eng ($$ep); the commands below are read-only."; \
		echo "devseed-live: recorded project $$p, invocation label $$lab=$$iid (a record, not proof of current ownership). List the project's objects:"; \
		for q in 'ps -a' 'volume ls' 'network ls'; do echo "    docker $$q --filter label=com.docker.compose.project=$$p"; done; \
		if [ -f "$$dir/created" ]; then while read -r k i t; do [ -n "$$i" ] || continue; insp "$$k" "$$i"; [ "$$k" != volume ] || echo "    (recorded creation time $$t)"; done < "$$dir/created"; fi; \
		insp container "$$mx"; }; \
	cleanup() { [ "$$cleaned" = 1 ] && return 0; cleaned=1; teardown; if [ "$$keep" = 1 ]; then wm refused; else wm torn-down; fi; release_mutex; \
		if [ "$$keep" = 1 ]; then echo "devseed-live: the claim $$lock is KEPT with this run's record ($$lock/manifest.json, $$dir/created): what it created was not all proved gone. The claim and the daemon mutex stay until the owner decides."; advise; else rm -rf "$$lock"; fi; \
		echo "devseed-live: files left for the owner in $$dir (mode 600, never printed)"; }; \
	finish() { cleanup; trap - EXIT; \
		if [ "$$fails" -eq 0 ]; then echo "devseed-live: green"; exit 0; fi; echo "devseed-live: RED — $$fails check(s) failed"; exit 1; }; \
	left=; found=; for q in 'ps -aq' 'volume ls -q' 'network ls -q'; do \
		if ! out=$$(docker $$q --filter "label=com.docker.compose.project=$$p" 2>>"$$dir/preflight.log"); then echo "devseed-live: check FAILED: preflight — docker $$q failed, so leftovers of $$p were not counted (refused; nothing was started)"; exit 1; fi; \
		k=$${q%% *}; [ "$$k" != ps ] || k=container; for i in $$out; do found="$$found $$k:$$i"; done; \
		[ -z "$$out" ] || left="$$left $${q%% *}"; done; \
	for n in "$$p" "$$p-postgres"; do \
		if ! out=$$(docker ps -aq --filter "name=^/?$$n\$$" 2>>"$$dir/preflight.log"); then echo "devseed-live: check FAILED: preflight — docker ps failed, so container $$n was not looked for (refused; nothing was started)"; exit 1; fi; \
		for i in $$out; do found="$$found container:$$i"; done; \
		[ -z "$$out" ] || left="$$left container:$$n"; done; \
	if [ -n "$$left" ]; then echo "devseed-live: check FAILED: preflight — project $$p already has resources this run did not create ($$left ); the listing found them by the project label or a container name, which proves no creation authority, so they are never removed by assumption. Removal is a manual owner decision. The commands below are read-only (refused; nothing was started)"; \
		for e in $$found; do insp "$${e%%:*}" "$${e#*:}"; done; exit 1; fi; \
	ok "preflight — project $$p has no containers, volumes or networks, so everything it holds from here on is this run's"; \
	if ! vk=$$(dc config --volumes 2>>"$$dir/preflight.log") || ! nk=$$(dc config --networks 2>>"$$dir/preflight.log") || ! sk=$$(dc config --services 2>>"$$dir/preflight.log"); then \
		echo "devseed-live: check FAILED: preflight — docker compose config failed, so the names this run would create are unknown (refused; nothing was started)"; exit 1; fi; \
	inv=; for k in $$vk; do inv="$$inv volume:$${p}_$${k}_$$iid"; done; for k in $$nk; do inv="$$inv network:$${p}_$${k}_$$iid"; done; \
	case "$$inv" in *volume:*network:*) ;; *) echo "devseed-live: check FAILED: preflight — docker compose config names no volume or no network for $$p (refused; nothing was started)"; exit 1;; esac; \
	ov=; for k in $$sk; do ov="$$ov,\"$$k\":{\"labels\":{\"$$lab\":\"$$iid\"}}"; done; ov="{\"services\":{$${ov#,}},"; \
	o2=; for k in $$vk; do o2="$$o2,\"$$k\":{\"name\":\"$${p}_$${k}_$$iid\",\"labels\":{\"$$lab\":\"$$iid\"}}"; done; ov="$$ov\"volumes\":{$${o2#,}},"; \
	o2=; for k in $$nk; do o2="$$o2,\"$$k\":{\"name\":\"$${p}_$${k}_$$iid\",\"labels\":{\"$$lab\":\"$$iid\"}}"; done; ov="$$ov\"networks\":{$${o2#,}}}"; \
	printf '%s\n' "$$ov" > "$$dir/invocation.json"; \
	if ! cfg=$$(dc -f "$$dir/invocation.json" config --format json 2>>"$$dir/preflight.log"); then \
		echo "devseed-live: check FAILED: preflight — docker compose config with this run's overlay failed, so the names this run would create are unknown (refused; nothing was started)"; exit 1; fi; \
	flat=$$(printf '%s' "$$cfg" | tr -d ' \t\n'); \
	for e in $$inv; do printf '%s' "$$flat" | grep -qF "\"name\":\"$${e#*:}\"" || { echo "devseed-live: check FAILED: preflight — $$e is not the name docker compose resolves for it with this run's overlay (refused; nothing was started)"; exit 1; }; done; \
	kbad() { echo "devseed-live: check FAILED: preflight — the resolved config is not this harness's project alone: $$1 (refused; nothing was started)"; exit 1; }; \
	: 'N1/N2 (OSS-TEARDOWN-MESSAGES): one reviewed allowlist of service keys and values, the rule openid-conformance and e2e-full apply too; a key not on it (cap_add, privileged, userns_mode, volume_driver, devices, security_opt, deploy, env_file, a host namespace, ...) is refused; build takes context and dockerfile only, labels only the invocation label of this run, logging only json-file with size options; command and entrypoint only as null, which Compose 5.6.0 writes for every service that sets neither (OSS-ALLOWLIST-NULL-FIX).'; \
	if ! msg=$$(printf '%s' "$$cfg" | P="$$p" PG="$$pg" APP="$$app" LAB="$$lab" IID="$$iid" node -e 'const c=JSON.parse(require("fs").readFileSync(0,"utf8")),e=process.env,bad=[],prot=(n)=>typeof n==="string"&&n.startsWith("identuum-idp-oss"),KEYS=["build","container_name","depends_on","environment","healthcheck","image","labels","logging","networks","ports","profiles","restart","volumes"],NULL_ONLY=["command","entrypoint"],svcs=Object.keys(c.services||{}).sort(),pub=[];if(svcs.join(" ")!=="app postgres-idp-oss")bad.push("its services ("+svcs.join(" ")+") are not exactly app and postgres-idp-oss");for(const [s,d] of Object.entries(c.services||{})){if(!d)continue;for(const k of Object.keys(d))if(!KEYS.includes(k)&&!(NULL_ONLY.includes(k)&&d[k]===null))bad.push("service "+s+" sets unreviewed key "+k);if(d.container_name!==undefined&&d.container_name!==e.P&&d.container_name!==e.P+"-postgres")bad.push("a container is named "+d.container_name);for(const k of Object.keys(d.build||{}))if(k!=="context"&&k!=="dockerfile")bad.push("service "+s+" sets unreviewed build key "+k);for(const [k,v] of Object.entries(d.labels||{}))if(k!==e.LAB||v!==e.IID)bad.push("service "+s+" sets label "+k);const l=d.logging;if(l&&(l.driver!=="json-file"||Object.keys(l).some((k)=>k!=="driver"&&k!=="options")||Object.keys(l.options||{}).some((k)=>k!=="max-size"&&k!=="max-file")))bad.push("service "+s+" logs through an unreviewed driver or option");if(d.restart!==undefined&&!["no","always","on-failure","unless-stopped"].includes(d.restart))bad.push("service "+s+" restart "+d.restart);for(const [k,n] of Object.entries(d.networks||{})){if(!Object.hasOwn(c.networks||{},k))bad.push("service "+s+" has an unowned network");for(const nk of Object.keys(n||{}))if(nk!=="aliases")bad.push("service "+s+" sets unreviewed network key "+nk);for(const a of (n&&n.aliases)||[])if(prot(a))bad.push("a network alias takes a protected name");}for(const m of d.volumes||[]){if(!m||m.type!=="volume"&&m.type!=="tmpfs")bad.push("service "+s+" has a host mount ("+((m&&m.type)||"host")+")");else if(m.type==="volume"&&(!m.source||!Object.hasOwn(c.volumes||{},m.source)))bad.push("service "+s+" has an unowned volume source");}for(const q of d.ports||[]){pub.push(String(q&&q.published));if(!q||q.host_ip!=="127.0.0.1")bad.push("a port is published on an address other than 127.0.0.1");}if(d.build&&d.image!==e.P+":local")bad.push("service "+s+" builds image "+(d.image||"-"));}if(!Object.values(c.services||{}).some((d)=>d&&d.image===e.P+":local"))bad.push("the built app image is not "+e.P+":local");if([...new Set(pub)].sort().join(" ")!==[e.PG,e.APP].sort().join(" "))bad.push("its published ports are not exactly "+e.PG+" and "+e.APP);for(const [kind,want] of [["volumes","local"],["networks","bridge"]])for(const [k,d] of Object.entries(c[kind]||{})){if(d&&d.external)bad.push(kind+" "+k+" is external");if(d&&d.driver_opts)bad.push(kind+" "+k+" sets driver options");if(d&&d.driver&&d.driver!==want)bad.push(kind+" "+k+" uses an unreviewed driver");}if(bad.length){console.log(bad.join("; "));process.exit(1);}' 2>/dev/null); then kbad "$${msg:-the resolved config could not be read}"; fi; \
	ok "preflight — the resolved config holds only app and postgres-idp-oss of $$p: no privileged or host-namespace service, no host mount, no external network or volume, ports $$pg and $$app on 127.0.0.1 only"; \
	if ! allv=$$(docker volume ls --format '{{.Name}}' 2>>"$$dir/preflight.log") || ! alln=$$(docker network ls --format '{{.Name}}' 2>>"$$dir/preflight.log"); then \
		echo "devseed-live: check FAILED: preflight — docker volume ls or network ls failed, so the names this run would create were not looked for (refused; nothing was started)"; exit 1; fi; \
	taken=; for e in $$inv; do case "$$e" in volume:*) all=$$allv;; *) all=$$alln;; esac; printf '%s\n' "$$all" | grep -qxF "$${e#*:}" && taken="$$taken $$e"; done; \
	if [ -n "$$taken" ]; then echo "devseed-live: check FAILED: preflight —$$taken already exist(s), whatever its labels; a same-name volume or network is not this run's, and Compose would reuse it. Removal is a manual owner decision. The commands below are read-only (refused; nothing was started)"; \
		for e in $$taken; do insp "$${e%%:*}" "$${e#*:}"; done; exit 1; fi; \
	printf '%s\n' $$inv > "$$dir/inventory"; \
	ok "preflight — the names this run creates ($$(printf '%s\n' $$inv | tr '\n' ' '| sed 's/ $$//')) are absent, recorded in $$dir/inventory"; \
	for port in $$pg $$app; do \
		holder=$$(docker ps --filter "publish=$$port" --format '{{.Names}}' | tr '\n' ' '); \
		[ -n "$$holder" ] || holder=$$(lsof -nP -iTCP:"$$port" -sTCP:LISTEN 2>/dev/null | awk 'NR>1{print $$1" pid "$$2}' | sort -u | tr '\n' ' '); \
		if [ -n "$$holder" ]; then echo "devseed-live: check FAILED: preflight — host port $$port is taken by: $$holder(refused; nothing was started)"; exit 1; fi; \
	done; ok "preflight — ports $$pg and $$app free"; \
	: > "$$dir/created.part"; seal || { echo "devseed-live: check FAILED: preflight — the empty creation record could not be sealed (refused; nothing was started)"; exit 1; }; \
	trap 'cleanup' EXIT; trap 'bad "interrupted"; finish' INT TERM; \
	if env -u MAKEFLAGS -u MAKEOVERRIDES -u MFLAGS -u MAKEFILES $(MAKE) --no-print-directory oss-up COMPOSE_CMD='docker compose' IDENTUUM_HARNESS_ENGINE_ID="$$eng" IDENTUUM_HARNESS_MUTEX_ID="$$mid" IDENTUUM_IDP_COMPOSE_PROJECT="$$p" DEV_COMPOSE_PROJECT="$$p" DEV_APP_CONTAINER="$$p" DEV_PG_HOST_PORT="$$pg" DEV_APP_PORT="$$app" COMPOSE_FILE="deployment/docker-compose.dev.yml -f $$dir/invocation.json" >"$$dir/up.log" 2>&1; then ok "up — oss-up built the tree and started project $$p, every resource labelled with this run's invocation id"; else bad "up — oss-up failed (log: $$dir/up.log)"; finish; fi; \
	if record; then ok "record — this run created $$(grep -c . "$$dir/created") resource(s), recorded by ID in $$dir/created"; else bad "record — docker could not list what this run created"; finish; fi; \
	i=0; until curl -fsS --max-time 2 "http://127.0.0.1:$$app/health" >/dev/null 2>&1; do \
		i=$$((i+1)); if [ $$i -ge 60 ]; then bad "health — no answer on 127.0.0.1:$$app within 120s"; finish; fi; sleep 2; done; \
	ok "health — 127.0.0.1:$$app answers"; \
	still || finish; \
	if (umask 077; go run ./tools/devseed --issuer "http://127.0.0.1:$$app" --container "$$p" \
		--i-know-this-is-a-dev-database --json >"$$dir/seed.json" 2>"$$dir/seed.err"); then ok "seed — devseed --container --json exit 0"; \
	else bad "seed — devseed exit non-zero (stderr in $$dir/seed.err)"; finish; fi; \
	IDENTUUM_DEVSEED_LIVE_CREDS="$$dir/seed.json" go test ./tools/devseed -count=1 -run '^TestDevseedLive$$' -v >"$$dir/credentials.log" 2>&1; rc=$$?; \
	grep -E '^    --- (PASS|FAIL): TestDevseedLive/' "$$dir/credentials.log" | sed -E 's/^    --- PASS: TestDevseedLive\//devseed-live: check OK: credentials — /; s/^    --- FAIL: TestDevseedLive\//devseed-live: check FAILED: credentials — /; s/ \([0-9.]+s\)$$//; s/_/ /g'; \
	n=$$(grep -cE '^    --- PASS: TestDevseedLive/' "$$dir/credentials.log"); \
	if [ "$$rc" -eq 0 ] && [ "$$n" -eq 4 ]; then ok "credentials — 4 of 4 sign-in checks"; else bad "credentials — go test exit $$rc, $$n of 4 passed (log: $$dir/credentials.log)"; fi; \
	still || finish; \
	(umask 077; go run ./tools/devseed --issuer "http://127.0.0.1:$$app" --container "$$p" \
		--i-know-this-is-a-dev-database --json >"$$dir/seed2.json" 2>"$$dir/seed2.err"); rc=$$?; \
	answer=$$(grep -oE '[a-z_]+ login: [^ ]+ already has TOTP enrolled' "$$dir/seed2.err" | head -1); \
	if [ "$$rc" -ne 0 ] && [ -n "$$answer" ]; then ok "second run — refused as documented: $$answer"; \
	else bad "second run — exit $$rc without the documented refusal (stderr in $$dir/seed2.err)"; fi; \
	finish

## dev-reset: DESTRUCTIVE one-command path to a known-good, seeded stack:
## drop the database volume, start Postgres, RECREATE the app so its
## entrypoint re-applies migrations, wait for health, then seed.
##
## The app recreate is not optional: migrations run from the app entrypoint at
## container start, so `fast-clean && dev-up` alone leaves a fresh volume with
## NO SCHEMA and the next command fails with `relation "users" does not exist`.
dev-reset: protected-guard
	$(MAKE) --no-print-directory fast-clean
	$(MAKE) --no-print-directory dev-up
	$(MAKE) --no-print-directory dev-recreate-app
	@printf 'waiting for %s to become healthy' "$(DEV_HEALTH_URL)"; \
	for i in $$(seq 1 40); do \
		if curl -fsS --max-time 3 "$(DEV_HEALTH_URL)" >/dev/null 2>&1; then echo " — up."; break; fi; \
		printf '.'; sleep 5; \
	done
	$(MAKE) --no-print-directory dev-seed

## dev-smoke: check the local IDP OSS health and component discovery
## endpoints, and REFUSE a stale binary: the running process announces the
## commit it was built from (/system/info build_commit, stamped by
## oss-build); when that differs from the working tree — including
## "unknown" from an unstamped image, or a clean-built binary while the
## tree is dirty — the smoke fails naming both sides
## (THE-THREE-THAT-MUST-NOT-REPEAT item 1: a 13:43 image served an
## evening of clicks against a 15:33 fix, and nothing said so).
dev-smoke:
	curl -fsS --max-time 5 $(DEV_HEALTH_URL) >/dev/null
	curl -fsS --max-time 5 $(DEV_COMPONENT_URL) >/dev/null
	@running=$$(curl -fsS --max-time 5 $(DEV_SYSTEM_INFO_URL) | sed -n 's/.*"build_commit":"\([^"]*\)".*/\1/p'); \
	tree=$$(git rev-parse HEAD)$$(test -n "$$(git status --porcelain)" && echo "-dirty"); \
	if [ -z "$$running" ]; then \
		echo "dev-smoke: REFUSING — the running IdP does not announce build_commit (pre-provenance image); rebuild: make oss-build && make dev-recreate-app"; exit 1; \
	fi; \
	if [ "$$running" != "$$tree" ]; then \
		echo "dev-smoke: REFUSING — STALE BINARY: the running IdP was built from '$$running' but the working tree is '$$tree'; rebuild: make oss-build && make dev-recreate-app"; exit 1; \
	fi; \
	echo "dev-smoke: build_commit matches the working tree ($$running)"
	@echo "IDP OSS local smoke checks passed."

## dev-health: alias for dev-smoke.
dev-health: dev-smoke

## r-suite: THE MODEL AS A GATE. Every AdminPermissionsModel.md rule that can be
## asserted in-process, named by its matrix id, so a failure says WHICH rule
## broke. Runs in verify AND ci-verify: the model is "final and concrete", so no
## commit gets to skip it.
##
## REQUIRE MODE: -run pins the R prefix, and the count check below fails if the
## suite ever SHRINKS. A deleted rule test would otherwise pass silently, which
## is the one failure a green suite cannot show you.
## RG_SUITE_FLOOR — raised as each audit gap is closed. Never lowered.
RG_SUITE_FLOOR ?= 4

r-suite:
	@echo "R-SUITE — AdminPermissionsModel.md"
	@go test ./internal/domain/ ./internal/service/ ./internal/handlers/ \
		-run 'TestR[0-9]|TestModel_|TestSessionScopeTrio|TestSiteAdminTenantWrite' -count=1
	@n=$$(go test ./internal/domain/ -run 'TestR[0-9]' -count=1 -v 2>/dev/null | grep -c '^--- PASS: TestR'); \
		if [ "$$n" -lt 8 ]; then \
			echo "R-SUITE SHRANK: $$n rule test(s) ran, expected at least 8."; \
			echo "A rule test was deleted or renamed out of the R prefix. The model is"; \
			echo "final and concrete — its tests do not get quietly removed."; \
			exit 1; \
		fi; \
		echo "R-SUITE OK — $$n rule test(s) in internal/domain, plus the behavioural and DB-teeth suites"
	@# Rg-SUITE FLOOR — the gap-closure tests (RgN by compliance-audit gap id).
	@# They are DB-backed, so this Docker-free target cannot RUN them; what it
	@# can do is refuse if they have been deleted. A gap closed by a test that
	@# someone later removed is a gap, and it would reopen silently.
	@n=$$(grep -rho 'func TestRg[0-9]*_' --include='*_test.go' . 2>/dev/null | sort -u | wc -l | tr -d ' '); \
		if [ "$$n" -lt $(RG_SUITE_FLOOR) ]; then \
			echo "Rg-SUITE SHRANK: $$n gap test(s) present, expected at least $(RG_SUITE_FLOOR)."; \
			echo "Each RgN closes a numbered gap from the compliance audit. Deleting one does"; \
			echo "not close the gap — it stops measuring it."; \
			exit 1; \
		fi; \
		echo "Rg-SUITE OK — $$n gap test(s) present (floor $(RG_SUITE_FLOOR)); they RUN under make integration-test"

## build: compile the OSS binary and all packages.
build:
	go build ./...

## build-binary: build the release binary with the version stamped from the
## working tree (Order C). VERSION defaults to `git describe` with the leading
## v stripped; pass VERSION=x.y.z to override. An unstamped build reports
## "dev", which can never match a release tag — the publish workflow's
## canonical binary-vs-tag gate refuses any build where stamping broke.
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null | sed 's/^v//')
# COMMIT — the working tree's provenance, "-dirty" when uncommitted changes
# exist. Stamped into internal/buildinfo.Commit so the RUNNING process can
# announce what it was built from (/system/info), and dev-smoke can refuse
# a stale binary (THE-THREE-THAT-MUST-NOT-REPEAT item 1).
COMMIT ?= $(shell git rev-parse HEAD 2>/dev/null)$(shell test -n "$$(git status --porcelain 2>/dev/null)" && echo "-dirty")
build-binary:
	go build -trimpath -ldflags "-s -w -X main.buildVersion=$(VERSION) -X github.com/identuum/identuum-idp-oss/internal/buildinfo.Commit=$(COMMIT)" -o bin/identuum-idp ./cmd/identuum-idp
	./bin/identuum-idp --version

## test: run all unit tests (excludes build-tagged integration tests). A set
## IDENTUUM_IDP_TEST_DATABASE_URL is judged first (unit-db-endpoint).
test: unit-db-endpoint
	go test ./... -count=1

## staticcheck: run staticcheck on all packages including integration tests.
staticcheck:
	staticcheck ./...
	staticcheck -tags integration ./...

## tagged-vet: TYPE-CHECK the test files no other gate compiles, AND PROVE IT DID.
##
## THE HOLE THIS CLOSES (ASK-THE-TOOLCHAIN, 2026-08-02): identuum-idp-ce holds
## `//go:build conformance` files that NO gate compiled — `vet`, `staticcheck`,
## `integration-build` and `test` all omit the tag, and the standalone target is
## reached by neither aggregate. They could rot to a compile error with everything
## green.
##
## AND THE HOLE THE FIRST VERSION OPENED (VET-THE-TAGS-YOU-DERIVED, 2026-08-02),
## iteration FOUR of one mistake: it split the raw //go:build expression on commas
## and fed the fragments to `go vet -tags`. `//go:build slow && postgres` became
## `slow`, `&&`, `postgres`; three vets ran, all passed, and THE FILE WAS
## TYPE-CHECKED BY NOTHING. The coverage was ASSERTED by running some vets, never
## DERIVED. Its teeth tested a different question — names empty while files exist —
## and passed only because every constraint on disk was a single bare atom.
##
## THE PLAN AND THE COVERAGE BOTH COME FROM tools/notrun, which parses each
## constraint with go/build/constraint and then asks go/build.Context.MatchFile
## whether a candidate tag set really selects the file. Nothing here parses an
## expression, and nothing here assumes a vet reached anything.
##
## THREE FAILURE MODES, all loud:
##   - ANY FILE NO PLANNED VET SELECTS -> FAIL, with its path. This is the check
##     the previous version was missing entirely.
##   - files exist behind other tags but no plan and no uncovered list -> FAIL,
##     because that combination means the deriver is broken.
##   - a planned vet fails to type-check -> FAIL, which is the point of running it.
tagged-vet:
	@if ! command -v go > /dev/null 2>&1; then \
		echo "TAGGED-VET UNAVAILABLE: TOOL ABSENT — the go toolchain is not on PATH."; \
		exit 0; \
	fi; \
	if ! out=$$(go run ./tools/notrun 2>&1); then \
		echo "TAGGED-VET: could not derive the plan — tools/notrun failed:"; \
		echo "$$out"; \
		exit 1; \
	fi; \
	nof=$$(printf '%s\n' "$$out" | sed -n 's/^othertag_files=//p'); \
	npc=$$(printf '%s\n' "$$out" | sed -n 's/^vetplan_count=//p'); \
	nuc=$$(printf '%s\n' "$$out" | sed -n 's/^uncovered_count=//p'); \
	nrc=$$(printf '%s\n' "$$out" | sed -n 's/^refused_count=//p'); \
	nic=$$(printf '%s\n' "$$out" | sed -n 's/^invisible_count=//p'); \
	if [ -z "$$nof" ] || [ -z "$$npc" ] || [ -z "$$nuc" ] || [ -z "$$nrc" ] || [ -z "$$nic" ]; then \
		echo "TAGGED-VET: tools/notrun did not report every key it must."; \
		echo "$$out"; exit 1; \
	fi; \
	if [ "$$nic" -ne 0 ]; then \
		echo "tagged-vet: $$nic file(s) are UNREACHABLE BY ./... and are excluded from every count."; \
		echo "WHAT WAS DERIVED: no ./... listing reaches their directory — not with the default build,"; \
		echo "not with -tags integration, and not with the file's own constraint atoms. WHAT WAS NOT"; \
		echo "DERIVED: which of the two causes applies — the go tool skipping testdata/dot/underscore"; \
		echo "directories (normal, expected), or a directory that no pattern can list for another"; \
		echo "reason (worth a look). The distinction is not measured here, so it is not asserted:"; \
		printf '%s\n' "$$out" | sed -n 's/^invisible=/  /p'; \
		echo "  A NOTICE, not a failure. Printed because saying nothing about a file you decided not"; \
		echo "  to check is how the last six defects hid."; \
	fi; \
	if [ "$$nrc" -ne 0 ]; then \
		echo "TAGGED-VET REFUSED TO SEARCH $$nrc FILE(S) — their constraints have more atoms than the"; \
		echo "search bound, so NOBODY LOOKED. This is NOT 'no tag set can select them': that claim"; \
		echo "would require a search that was never run."; \
		printf '%s\n' "$$out" | sed -n 's/^refused=/  /p'; \
		echo "Raise the bound in tools/notrun or simplify the constraint — deliberately, either way."; \
		exit 1; \
	fi; \
	if [ "$$nuc" -ne 0 ]; then \
		echo "TAGGED-VET CANNOT COVER $$nuc FILE(S) — no tag set makes the toolchain select them,"; \
		echo "so nothing here can type-check them and this refuses to imply otherwise:"; \
		printf '%s\n' "$$out" | sed -n 's/^uncovered=/  /p'; \
		echo "A SEARCH WAS RUN AND FOUND NOTHING — that is different from refusing to search"; \
		echo "(reported separately above). A GOOS/GOARCH filename suffix or an unparsable"; \
		echo "//go:build line needs a deliberate decision, not a silent pass."; \
		exit 1; \
	fi; \
	if [ "$$nof" -ne 0 ] && [ "$$npc" -eq 0 ]; then \
		echo "TAGGED-VET BROKEN: $$nof file(s) are selected by neither the default nor the"; \
		echo "integration build, yet no vet plan was derived and none was reported uncovered."; \
		exit 1; \
	fi; \
	if [ "$$npc" -eq 0 ]; then \
		echo "tagged-vet: nothing outside default+integration on disk (othertag_files=$$nof) — nothing to type-check."; \
		exit 0; \
	fi; \
	ran=0; \
	for plan in $$(printf '%s\n' "$$out" | sed -n 's/^vetplan=//p'); do \
		pgoos=$$(printf '%s' "$$plan" | cut -d/ -f1); \
		pgoarch=$$(printf '%s' "$$plan" | cut -d/ -f2); \
		ptags=$$(printf '%s' "$$plan" | cut -d/ -f3); \
		echo "tagged-vet: GOOS=$${pgoos:-<host>} GOARCH=$${pgoarch:-<host>} go vet $${ptags:+-tags $$ptags} ./...   (derived, and verified to select the files it must)"; \
		env $${pgoos:+GOOS=$$pgoos} $${pgoarch:+GOARCH=$$pgoarch} \
			go vet $${ptags:+-tags "$$ptags"} ./... || exit 1; \
		ran=$$((ran+1)); \
	done; \
	if [ "$$ran" -ne "$$npc" ]; then \
		echo "TAGGED-VET BROKEN: derived $$npc plan(s) and ran $$ran."; \
		exit 1; \
	fi

## INTEGRATION_RUN_HINT: the command THIS repo actually runs its DB-backed
## tests with. It is a variable because the inventory used to print
## "make fast-up && make integration-test" in every repo, and identuum-ag-ce has
## NO integration-test target — a printed instruction that does not work is the
## same defect as a printed count that was never derived, in the friendliest
## possible disguise.
INTEGRATION_RUN_HINT ?= make fast-up && make integration-test

## integration-inventory: SAY WHAT THIS AGGREGATE DID NOT RUN.
##
## THE BLIND SPOT THIS CLOSES (RUN-SET, 2026-08-02): `verify` is Docker-free by
## design, and the CI aggregate is `verify` minus the Docker steps, so NEITHER
## runs the integration suite. SILENCE ABOUT WORK NOT DONE READS AS WORK DONE.
##
## THE COUNTING MOVED OUT OF THIS MAKEFILE (COUNT-THE-SKIPPER, 2026-08-02). It
## used to be an awk one-liner that tracked the last `func Test` it had seen and
## blamed any DSN skip on it. A SHARED HELPER gating three tests therefore counted
## as ONE, and a skip above the first test in a file was attributed to the last
## test of the PREVIOUS file. "Which test ends up skipping" is a CALL-GRAPH
## question and no line matcher can answer it, so `tools/notrun` reads the AST.
##
## FAILURE IS NO LONGER SPELLED ZERO. The awk was wrapped in `|| echo 0`, so one
## unreadable file made the count come back 0 at exit 0 — the
## empty-input-reports-CLEAN defect, for the FOURTH time in this workspace, in the
## half that by design cannot have a floor. `tools/notrun` exits non-zero on any
## read or parse error and prints nothing, so a broken run cannot look like a
## clean one; this target treats a non-zero exit or a missing key as a FAILURE.
## NO FLOOR WAS INVENTED FOR POPULATION B — identuum-idp-ce genuinely has zero of
## them, and a floor it cannot meet would be a lie about what is being checked.
##
## FOUR OUTCOMES, and the causes are kept apart on purpose:
##   1. A TOOL IS ABSENT (git or go not on PATH) -> CANNOT MEASURE. Names the
##      MISSING TOOL, claims nothing, and does NOT fail. This is a REPORT: a
##      developer who cannot run it must still be able to reach green.
##   2. NOT A GIT CHECKOUT -> cannot measure either, but for a DIFFERENT reason,
##      and says which. Also does not fail.
##   3. THE MEASUREMENT RAN AND FAILED, or a real checkout holds zero tagged
##      files -> FAILS. Something is wrong with the code or with the counter.
##   4. OTHERWISE -> prints EVERY population under a sentence true FOR IT.
##
## THREE POPULATIONS, NOT TWO (PROVED-ON-A-SHAPE-YOU-INVENTED, 2026-08-02). The
## previous version had one line for "no build tag" and swept everything that was
## not integration-tagged into it — including identuum-idp-ce's three //go:build
## conformance files, under a sentence saying this aggregate COMPILES AND RUNS
## them. It never compiles them. Each population now gets its own line:
##   A  not selected by the default build, selected by -tags integration
##   C  selected by NEITHER build — the constraint text is reported for the
##      reader, and `tagged-vet` type-checks these so they cannot rot unseen
##   B  SELECTED BY THE DEFAULT BUILD: compiled, selected, RUN here, and inert
##
## EVERY SELECTION CLAIM IS DERIVED FROM go/build.Context.MatchFile
## (ASK-THE-TOOLCHAIN, 2026-08-02). The line for C used to read "in N file(s) this
## aggregate never compiles" — ASSERTED, never derived, and FALSE for any file
## whose constraint the default build satisfies (`linux`, `cgo`, `!race`,
## `go1.26`). It was true only because `conformance` happened to be the only other
## tag on disk: the THIRD consecutive exact-by-current-shape number.
## The headline no longer says all of them "need Postgres": that is provable for
## B and for the DSN-reaching part of C, and not for A, so it is claimed only
## where it holds.
integration-inventory:
	@if ! command -v git > /dev/null 2>&1; then \
		echo "INTEGRATION-INVENTORY UNAVAILABLE: TOOL ABSENT — git is not on PATH."; \
		echo "This is not a repository problem and not a code problem: the tool that lists"; \
		echo "the files is missing. NOTHING is claimed about the integration suite."; \
		exit 0; \
	fi; \
	if ! git rev-parse --git-dir > /dev/null 2>&1; then \
		echo "INTEGRATION-INVENTORY UNAVAILABLE: git is present but this is not a checkout."; \
		echo "An ENVIRONMENT condition, not a code fault, so it does not fail the build."; \
		echo "NOTHING is claimed — do not read this as 'nothing to run'."; \
		exit 0; \
	fi; \
	if ! command -v go > /dev/null 2>&1; then \
		echo "INTEGRATION-INVENTORY UNAVAILABLE: TOOL ABSENT — the go toolchain is not on PATH."; \
		echo "The counter is a Go program (tools/notrun) and cannot be built. NOTHING is claimed."; \
		exit 0; \
	fi; \
	if ! out=$$(go run ./tools/notrun 2>&1); then \
		echo "INTEGRATION-INVENTORY MEASUREMENT FAILED — the counter ran and could not finish:"; \
		echo "$$out"; \
		echo "This is NOT the same as a count of zero, and it is deliberately not reported as one."; \
		exit 1; \
	fi; \
	nif=$$(printf '%s\n' "$$out" | sed -n 's/^integration_files=//p'); \
	nit=$$(printf '%s\n' "$$out" | sed -n 's/^integration_tests=//p'); \
	nof=$$(printf '%s\n' "$$out" | sed -n 's/^othertag_files=//p'); \
	not=$$(printf '%s\n' "$$out" | sed -n 's/^othertag_tests=//p'); \
	nod=$$(printf '%s\n' "$$out" | sed -n 's/^othertag_dsn_tests=//p'); \
	non=$$(printf '%s\n' "$$out" | sed -n 's/^othertag_names=//p'); \
	nb=$$(printf '%s\n' "$$out" | sed -n 's/^default_dsn_tests=//p'); \
	if [ -z "$$nif" ] || [ -z "$$nit" ] || [ -z "$$nof" ] || [ -z "$$not" ] || [ -z "$$nod" ] || [ -z "$$nb" ]; then \
		echo "INTEGRATION-INVENTORY MEASUREMENT FAILED: the counter exited 0 but did not report every key."; \
		echo "$$out"; \
		exit 1; \
	fi; \
	if [ "$$nif" -eq 0 ]; then \
		echo "INTEGRATION-INVENTORY BROKEN: this IS a git checkout and it holds zero integration-tagged test files."; \
		echo "Either every //go:build integration file was removed, or the counter no longer matches them."; \
		echo "Do not read this as 'nothing to run' — it means the count is not trustworthy."; \
		exit 1; \
	fi; \
	echo "NOT RUN HERE: $$((nit + not + nb)) test function(s). Selection derived from go/build, not guessed:"; \
	echo "  $$nit in $$nif file(s) the DEFAULT build does not select and -tags integration does."; \
	if [ "$$not" -gt 0 ]; then \
		echo "  $$not in $$nof file(s) selected by NEITHER build (constraints: $$non), type-checked by tagged-vet"; \
		echo "     — of which $$nod reach a skip on an unset DSN."; \
	fi; \
	echo "  $$nb selected BY THE DEFAULT BUILD: compiled here, selected here, RUN here, and they skip on an unset DSN"; \
	echo "     (attributed through helpers and package-level consts by AST — see tools/notrun)."; \
	echo "Those tests need Postgres and this aggregate is Docker-free by design. Run them with:"; \
	echo "  $(INTEGRATION_RUN_HINT)"

## integration-test: run the DB-backed suites against local dev Postgres — the
## e2e end-to-end tests PLUS the runtime, internal/pkg/runtime and internal/postgres
## teeth (issuer-confinement, metrics listener, P3-5 key-encryption-at-rest,
## setup-state repository). All share one Postgres; see the per-test isolation
## notes (e.g. IDENTUUM_IDP_ALLOW_MULTI_REPLICA, the setup-state row-lock tx).
## DB URL is read from IDENTUUM_IDP_TEST_DATABASE_URL env (if set) or the
## OSS_TEST_DB_URL default (the dedicated *_test database — NEVER the dev DB;
## TEST-DB-ISOLATION-1). The harness refuses a non-_test DSN.
## Encryption key is read from IDENTUUM_IDP_ENCRYPTION_KEY env (if set) or the TEST-ONLY
## default below (64-hex AES-256-GCM key — cafebabe×8; NEVER use in production).
## Neither the URL nor the key is echoed (@ prefix).
##
## THE RUN SET IS `./...`, AND THE PATHSPEC IT REPLACED IS THE POINT (RUN-SET,
## 2026-08-02). This target used to name four package trees explicitly:
##   ./internal/e2e/... ./internal/runtime/... ./pkg/runtime/... ./internal/postgres/...
##   (pkg/runtime is internal/pkg/runtime since P-061, 2026-09-07; the list is quoted as it was)
## All 32 integration-tagged files happened to live in two of them, so the list
## was TOTAL BY COINCIDENCE, not by construction. A new `//go:build integration`
## file under internal/service would have compiled under vet-integration, passed
## staticcheck -tags integration, and NEVER RUN — a skip by pathspec, invisible
## because nothing reports a test that was never selected.
##
## WHY `./...` RATHER THAN A GATE OVER THE PATHSPEC. A hand-maintained list is a
## second source of truth for "which packages hold integration tests"; a checker
## that compares the list against the tagged-file set is a third, and it can be
## wrong in ways that read as clean. `./...` DELETES the drifting thing instead
## of adding a watcher for it. It is also what identuum-idp-ce already does, so
## this removes a divergence rather than inventing a mechanism. Measured cost of
## the wider set on 2026-08-02: 21s, 45 packages, 0 failures.
## ci-integration-test: the pure DB-backed suite — exactly what CI's
## integration job runs in its one-repo checkout. The developer-facing
## integration-test target below CHAINS test-db (createdb + migrate
## bootstrap) and the rulefloor-integration teeth around it; CI runs
## the SAME teeth as their own step after this target (THE-CI-TEETH,
## with the pinned rulefloor install), and only test-db stays local —
## the CI service container provides the database. See the ci.yml
## header enumeration.
## test-db-endpoint-selftest (OSS-MINT-ISOLATION, 2026-10-10; review
## OSS-FIXES2-REVIEW-2026-10-10 R1): ONE selected integration endpoint. This
## Makefile runs from a fixture directory where psql, createdb, pg_isready, go,
## docker, lictor, rulefloor and curl are stubs that record each call, so
## nothing connects anywhere. Dry run (make -n): a port-only override prints the
## scratch port at the create, migrate, suite and rulefloor sites and 5513 at
## none. Real runs: verify-integration hands lictor the port and the test URL
## by name, because lictor passes no other variable to a plan entry (measured
## 2026-10-10: only GIT_OPTIONAL_LOCKS, GOENV, GOWORK, HOME, LC_ALL and PATH
## reach one); every DB-backed target refuses, exit 2, before any stub is
## called: nothing set (the 5513 default, judge ruling Q1(a)), a URL whose
## host:port disagrees with DEV_PG_HOST_PORT, a non-loopback host, a non-URL
## DSN, and (OSS-MINT-GUARD-2, review OSS-MINT-ISOLATION M1/M2) a _test URL
## whose options redirect the driver's port, host or database, a non-_test
## database, and PGHOSTADDR. 5513 has no exception (OSS-MINT-GUARD-4, judge
## ruling Q-HOSTED (a)): the full local Linux imitation of the former hosted
## Integration Tests job — every marker GitHub Actions sets for it, passed in
## the environment and on make's command line, with a uname stub answering
## Linux — is refused by every DB-backed target before any command, and the
## CI jobs' own port 45432 is accepted with the same markers. go-test-race and
## test (unit-db-endpoint) refuse the owner's 5513, an option redirect, the
## former escape beside a non-_test database and the full imitation on 5513
## before go runs, and run go once for a
## scratch URL or none; ci-verify declares DEV_PG_HOST_PORT to lictor. The full URL case table runs through this
## guard in tools/integration-witness/endpoint_test.go. dev.env.example
## assigns no test URL (review OSS-MINT-COVERAGE C3), counted by name only.
## The caller's own settings are unset first, so the CI job's URL cannot leak in.
TEST_DB_ENDPOINT_MAKEFILE ?= $(abspath Makefile)
.PHONY: test-db-endpoint-selftest
test-db-endpoint-selftest:
	@d=$$(mktemp -d "$${TMPDIR:-/tmp}/test-db-endpoint.XXXXXX"); trap 'rm -rf "$$d"' EXIT; n=0; fails=0; \
	mkdir -p "$$d/bin" "$$d/w"; ln -s "$(TEST_DB_ENDPOINT_MAKEFILE)" "$$d/w/Makefile"; \
	for c in psql createdb pg_isready go docker rulefloor curl; do \
		printf '#!/bin/sh\necho "%s $$*" >> "%s/calls"\n' "$$c" "$$d" > "$$d/bin/$$c"; chmod +x "$$d/bin/$$c"; done; \
	printf '#!/bin/sh\necho "uname $$*" >> "%s/calls"\necho Linux\n' "$$d" > "$$d/bin/uname"; chmod +x "$$d/bin/uname"; \
	printf '#!/bin/sh\necho "lictor $$*" >> "%s/calls"\necho "$$*" > "%s/lictor.args"\necho "port=$$DEV_PG_HOST_PORT" >> "%s/lictor.args"\ncase "$$IDENTUUM_IDP_TEST_DATABASE_URL" in *@127.0.0.1:"$$DEV_PG_HOST_PORT"/*) echo url=agrees;; *) echo url=disagrees;; esac >> "%s/lictor.args"\n' "$$d" "$$d" "$$d" "$$d" > "$$d/bin/lictor"; chmod +x "$$d/bin/lictor"; \
	run() { (cd "$$d/w" && env -u IDENTUUM_IDP_TEST_DATABASE_URL -u IDENTUUM_IDP_DATABASE_URL -u OSS_TEST_DB_URL -u DEV_PG_HOST_PORT -u LICTOR -u GATE_RECORD_DRIVER -u MAKEFLAGS -u MAKEOVERRIDES -u MFLAGS -u MAKELEVEL -u CI -u GITHUB_ACTIONS -u GITHUB_JOB -u RUNNER_OS -u PGHOSTADDR -u PGSERVICE -u IDENTUUM_IDP_ALLOW_NON_TEST_DB -u IDENTUUM_IDP_REQUIRE_DB_TESTS -u IDENTUUM_IDP_ALLOW_MULTI_REPLICA PATH="$$d/bin:$$PATH" "$$@"); }; \
	dry() { label=$$1; port=$$2; other=$$3; shift 3; n=$$((n + 1)); out=$$(run $(MAKE) --no-print-directory -n test-db ci-integration-test rulefloor-integration "$$@" 2>&1); miss=; \
		url="postgres://idp_oss_user:dev-idp_oss_user-not-a-secret@127.0.0.1:$$port/identuum_idp_oss_test?sslmode=disable"; \
		printf '%s\n' "$$out" | grep -qF -- "psql -h 127.0.0.1 -p $$port " || miss="$$miss psql"; \
		printf '%s\n' "$$out" | grep -qF -- "createdb -h 127.0.0.1 -p $$port " || miss="$$miss createdb"; \
		printf '%s\n' "$$out" | grep -qF -- "migrate \"\$${IDENTUUM_IDP_TEST_DATABASE_URL:-$$url}\"" || miss="$$miss migrate"; \
		[ "$$(printf '%s\n' "$$out" | grep -cF -- "IDENTUUM_IDP_TEST_DATABASE_URL=\"\$${IDENTUUM_IDP_TEST_DATABASE_URL:-$$url}\"")" = 2 ] || miss="$$miss suite+rulefloor"; \
		printf '%s\n' "$$out" | grep -qE -- "(127\.0\.0\.1:|localhost:|-p )$$other([^0-9]|$$)" && miss="$$miss names-$$other"; \
		if [ -z "$$miss" ]; then echo "  ok    $$label"; else echo "  FAIL  $$label: missing or wrong:$$miss"; fails=$$((fails + 1)); fi; }; \
	refuse() { label=$$1; shift; n=$$((n + 1)); rm -f "$$d/calls"; out=$$(run "$$@" 2>&1); rc=$$?; \
		if [ $$rc -ne 0 ] && [ ! -s "$$d/calls" ] && printf '%s\n' "$$out" | grep -q -- '-db-endpoint: REFUSED'; then echo "  ok    refused before any command: $$label"; \
		else echo "  FAIL  $$label: exit $$rc, refusal line $$(printf '%s\n' "$$out" | grep -c -- '-db-endpoint: REFUSED'), calls: $$(cut -d' ' -f1 "$$d/calls" 2>/dev/null | tr '\n' ' ')"; fails=$$((fails + 1)); fi; }; \
	runs() { label=$$1; shift; n=$$((n + 1)); rm -f "$$d/calls"; out=$$(run "$$@" 2>&1); rc=$$?; \
		if [ $$rc -eq 0 ] && grep -q '^go test ' "$$d/calls" 2>/dev/null; then echo "  ok    judged, then ran go test: $$label"; \
		else echo "  FAIL  $$label: exit $$rc, calls: $$(cut -d' ' -f1-2 "$$d/calls" 2>/dev/null | tr '\n' ' ')"; fails=$$((fails + 1)); fi; }; \
	accept() { label=$$1; shift; n=$$((n + 1)); rm -f "$$d/calls"; out=$$(run "$$@" 2>&1); rc=$$?; \
		if [ $$rc -eq 0 ] && [ ! -s "$$d/calls" ]; then echo "  ok    accepted: $$label"; else echo "  FAIL  $$label: exit $$rc"; fails=$$((fails + 1)); fi; }; \
	dry "DEV_PG_HOST_PORT=35514 only: every site uses 35514, none names 5513" 35514 5513 DEV_PG_HOST_PORT=35514; \
	u=postgres://u:dev-u-not-a-secret@127.0.0.1:35514/x_test; \
	for t in test-db ci-integration-test rulefloor-integration integration-test verify-integration test-full-mint; do \
		refuse "$$t: nothing set, so the 5513 default" $(MAKE) --no-print-directory $$t; \
		refuse "$$t: test URL on 5513 while DEV_PG_HOST_PORT=35514" env DEV_PG_HOST_PORT=35514 IDENTUUM_IDP_TEST_DATABASE_URL=postgres://u:dev-u-not-a-secret@127.0.0.1:5513/x_test $(MAKE) --no-print-directory $$t; \
		refuse "$$t: a _test URL on 35514 whose port option is 5513" env DEV_PG_HOST_PORT=35514 "IDENTUUM_IDP_TEST_DATABASE_URL=$$u?port=5513" $(MAKE) --no-print-directory $$t; \
		refuse "$$t: a _test URL whose percent-encoded host and port options name another server" env DEV_PG_HOST_PORT=35514 "IDENTUUM_IDP_TEST_DATABASE_URL=$$u?%68ost=db.example&%70ort=5513" $(MAKE) --no-print-directory $$t; \
		refuse "$$t: a _test URL whose dbname option is the live database" env DEV_PG_HOST_PORT=35514 "IDENTUUM_IDP_TEST_DATABASE_URL=$$u?dbname=identuum_idp_oss" $(MAKE) --no-print-directory $$t; \
		refuse "$$t: a non-_test database on the scratch port" env DEV_PG_HOST_PORT=35514 IDENTUUM_IDP_TEST_DATABASE_URL=postgres://u:dev-u-not-a-secret@127.0.0.1:35514/identuum_idp_oss $(MAKE) --no-print-directory $$t; \
	done; \
	for t in validate verify-oss; do refuse "$$t: nothing set, refused before its fast-clean" $(MAKE) --no-print-directory $$t; done; \
	refuse "PGHOSTADDR set beside a scratch port" env DEV_PG_HOST_PORT=35514 PGHOSTADDR=10.0.0.1 $(MAKE) --no-print-directory test-db; \
	refuse "the disposable-database escape does not admit a non-_test database" env DEV_PG_HOST_PORT=35514 IDENTUUM_IDP_ALLOW_NON_TEST_DB=1 IDENTUUM_IDP_TEST_DATABASE_URL=postgres://u:dev-u-not-a-secret@127.0.0.1:35514/identuum_idp_oss $(MAKE) --no-print-directory test-db; \
	jm='CI=true GITHUB_ACTIONS=true GITHUB_JOB=integration RUNNER_OS=Linux RUNNER_ENVIRONMENT=github-hosted'; \
	own=postgres://u:dev-u-not-a-secret@127.0.0.1:5513/identuum_idp_oss_test?sslmode=disable; \
	for t in test-db ci-integration-test rulefloor-integration integration-test verify-integration; do \
		refuse "$$t: the full local Linux imitation of the former hosted job, its database on 5513 (uname says Linux; review OSS-MINT-GUARD-3-PREREVIEW H3)" env $$jm DEV_PG_HOST_PORT=5513 IDENTUUM_IDP_TEST_DATABASE_URL=$$own $(MAKE) --no-print-directory $$t $$jm DEV_PG_HOST_PORT=5513; \
	done; \
	accept "the CI jobs' port 45432 with every job marker set" env $$jm DEV_PG_HOST_PORT=45432 IDENTUUM_IDP_TEST_DATABASE_URL=postgres://u:dev-u-not-a-secret@127.0.0.1:45432/identuum_idp_oss_test?sslmode=disable $(MAKE) --no-print-directory test-db-endpoint $$jm DEV_PG_HOST_PORT=45432; \
	rt='IDENTUUM_IDP_REQUIRE_DB_TESTS=1 IDENTUUM_IDP_ALLOW_MULTI_REPLICA=1'; \
	for t in go-test-race test; do \
		refuse "$$t: a _test URL on the owner's 5513" env $$rt IDENTUUM_IDP_TEST_DATABASE_URL=postgres://u:dev-u-not-a-secret@127.0.0.1:5513/identuum_idp_oss_test $(MAKE) --no-print-directory $$t; \
		refuse "$$t: a _test URL whose port option redirects to 5513" env DEV_PG_HOST_PORT=35514 $$rt "IDENTUUM_IDP_TEST_DATABASE_URL=$$u?port=5513" $(MAKE) --no-print-directory $$t; \
		refuse "$$t: the former escape beside a non-_test database" env DEV_PG_HOST_PORT=35514 $$rt IDENTUUM_IDP_ALLOW_NON_TEST_DB=1 IDENTUUM_IDP_TEST_DATABASE_URL=postgres://u:dev-u-not-a-secret@127.0.0.1:35514/identuum_idp_oss $(MAKE) --no-print-directory $$t; \
		refuse "$$t: the full local Linux imitation of the former hosted job on 5513" env $$jm $$rt DEV_PG_HOST_PORT=5513 IDENTUUM_IDP_TEST_DATABASE_URL=$$own $(MAKE) --no-print-directory $$t $$jm; \
		runs "$$t: a _test URL on the selected scratch port" env DEV_PG_HOST_PORT=35514 $$rt IDENTUUM_IDP_TEST_DATABASE_URL=$$u $(MAKE) --no-print-directory $$t; \
	done; \
	runs "test: no test URL set, so no database to judge" $(MAKE) --no-print-directory test; \
	n=$$((n + 1)); rm -f "$$d/lictor.args"; run env DEV_PG_HOST_PORT=45432 $(MAKE) --no-print-directory ci-verify > /dev/null 2>&1; \
	if grep -qF -- '--env DEV_PG_HOST_PORT' "$$d/lictor.args" 2>/dev/null; then echo "  ok    ci-verify hands lictor DEV_PG_HOST_PORT by --env, so go-test-race judges the CI URL against the job's port"; \
	else echo "  FAIL  ci-verify does not declare DEV_PG_HOST_PORT to lictor"; fails=$$((fails + 1)); fi; \
	n=$$((n + 1)); ex=$$(grep -cE '^[[:space:]]*(export[[:space:]]+)?IDENTUUM_IDP_TEST_DATABASE_URL=' "$(dir $(TEST_DB_ENDPOINT_MAKEFILE))dev.env.example"); \
	if [ "$$ex" = 0 ]; then echo "  ok    dev.env.example assigns no IDENTUUM_IDP_TEST_DATABASE_URL, so the guarded targets derive it"; \
	else echo "  FAIL  dev.env.example assigns IDENTUUM_IDP_TEST_DATABASE_URL $$ex time(s) (value not read)"; fails=$$((fails + 1)); fi; \
	refuse "OSS_TEST_DB_URL on 5513 while DEV_PG_HOST_PORT=35514" $(MAKE) --no-print-directory test-db DEV_PG_HOST_PORT=35514 OSS_TEST_DB_URL=postgres://u:dev-u-not-a-secret@127.0.0.1:5513/x_test; \
	refuse "test URL on 35514 with the port left at 5513" env IDENTUUM_IDP_TEST_DATABASE_URL=postgres://u:dev-u-not-a-secret@127.0.0.1:35514/x_test $(MAKE) --no-print-directory test-db; \
	refuse "test URL without a port (5432) with the port at 5513" env IDENTUUM_IDP_TEST_DATABASE_URL=postgres://u:dev-u-not-a-secret@127.0.0.1/x_test $(MAKE) --no-print-directory test-db; \
	refuse "test URL on a non-loopback host" env IDENTUUM_IDP_TEST_DATABASE_URL=postgres://u:dev-u-not-a-secret@db.example:5513/x_test $(MAKE) --no-print-directory test-db; \
	refuse "a keyword DSN the guard cannot read" env 'IDENTUUM_IDP_TEST_DATABASE_URL=host=127.0.0.1 port=5513 dbname=x_test' $(MAKE) --no-print-directory test-db; \
	accept "port and both URLs on 35514 (127.0.0.1 and localhost)" env DEV_PG_HOST_PORT=35514 IDENTUUM_IDP_TEST_DATABASE_URL=postgres://u:dev-u-not-a-secret@127.0.0.1:35514/x_test $(MAKE) --no-print-directory test-db-endpoint OSS_TEST_DB_URL=postgres://u:dev-u-not-a-secret@localhost:35514/x_test; \
	n=$$((n + 1)); rm -f "$$d/lictor.args"; run env DEV_PG_HOST_PORT=35514 $(MAKE) --no-print-directory verify-integration > /dev/null 2>&1; \
	if grep -qF -- '--env DEV_PG_HOST_PORT' "$$d/lictor.args" 2>/dev/null && grep -qF -- '--env IDENTUUM_IDP_TEST_DATABASE_URL' "$$d/lictor.args" && grep -qx 'port=35514' "$$d/lictor.args" && grep -qx 'url=agrees' "$$d/lictor.args"; then \
		echo "  ok    verify-integration hands lictor DEV_PG_HOST_PORT=35514 and a test URL on 127.0.0.1:35514 by --env"; \
	else echo "  FAIL  verify-integration does not hand lictor the scratch endpoint: $$(grep -v '^lictor\|witness' "$$d/lictor.args" 2>/dev/null | tr '\n' ' ')$$(grep -o -- '--env [A-Z_]*' "$$d/lictor.args" 2>/dev/null | tr '\n' ' ')"; fails=$$((fails + 1)); fi; \
	if [ $$fails -ne 0 ]; then echo "check FAILED: test-db-endpoint-selftest $$fails of $$n case(s)"; exit 1; fi; \
	echo "check OK: test-db-endpoint-selftest $$n case(s): one selected integration endpoint, the port moves every URL default, 5513 and a disagreeing or redirecting URL are refused before any command"

## test-db: create + migrate the dedicated integration database
## (identuum_idp_oss_test on whichever PostgreSQL answers
## 127.0.0.1:$(DEV_PG_HOST_PORT), with the dev user: a scratch server, never
## 5513, which test-db-endpoint refuses everywhere), separate from
## the human's dev DB (TEST-DB-ISOLATION-1). Idempotent: CREATE DATABASE is skipped if it
## already exists, then migrations are (re-)applied. Never touches OSS_DB_URL.
## It migrates the URL the suites use (IDENTUUM_IDP_TEST_DATABASE_URL, else
## OSS_TEST_DB_URL), and test-db-endpoint has already refused that URL unless
## it names 127.0.0.1:$(DEV_PG_HOST_PORT), the server the database is created on,
## and a _test database. The database created is the one that URL names
## (OSS-MINT-GUARD-2; identuum_idp_oss_test by default). Before anything
## connects, integration-witness -check-url judges the same URL with the Go
## form of the policy (review OSS-MINT-ISOLATION M2: the migration is a test
## target's step here, so the test-database check runs at it; an operator's
## own `identuum-idp migrate` of a live database is unchanged).
test-db: test-db-endpoint bin/integration-witness
	@u="$${IDENTUUM_IDP_TEST_DATABASE_URL:-$(OSS_TEST_DB_URL)}"; db=$${u%%\?*}; db=$${db##*/}; \
	IDENTUUM_IDP_TEST_DATABASE_URL="$$u" DEV_PG_HOST_PORT='$(DEV_PG_HOST_PORT)' ./bin/integration-witness -check-url || exit 2; \
	echo "test-db: ensuring $$db on 127.0.0.1:$(DEV_PG_HOST_PORT) exists + migrated"; \
	PGPASSWORD=dev-idp_oss_user-not-a-secret psql -h 127.0.0.1 -p $(DEV_PG_HOST_PORT) -U idp_oss_user -d postgres -tAc \
		"SELECT 1 FROM pg_database WHERE datname='$$db'" | grep -q 1 || \
		PGPASSWORD=dev-idp_oss_user-not-a-secret createdb -h 127.0.0.1 -p $(DEV_PG_HOST_PORT) -U idp_oss_user "$$db"
	@$(MAKE) --no-print-directory build-binary
	@./bin/identuum-idp migrate "$${IDENTUUM_IDP_TEST_DATABASE_URL:-$(OSS_TEST_DB_URL)}"

## test-db-endpoint (OSS-MINT-ISOLATION, 2026-10-10; review
## OSS-FIXES2-REVIEW-2026-10-10 R1): ONE selected integration endpoint. The
## prerequisite of every DB-backed target here. OSS_TEST_DB_URL's default
## follows DEV_PG_HOST_PORT; a URL the caller sets (OSS_TEST_DB_URL, or
## IDENTUUM_IDP_TEST_DATABASE_URL, which the suites prefer) is VALIDATED, never
## rewritten, or the target refuses here with exit 2 before any command runs.
## THE EFFECTIVE ENDPOINT (OSS-MINT-GUARD-2, review OSS-MINT-ISOLATION M1/M2):
## the driver reads host, hostaddr, port, dbname, database and service from the
## URL's options and they override its authority and path, so judging the
## authority alone let `?port=5513` or `?dbname=identuum_idp_oss` through. A
## URL is accepted only as postgres:// or postgresql://, optional userinfo, ONE
## literal 127.0.0.1 or localhost on DEV_PG_HOST_PORT, a database of letters,
## digits and underscores ending in _test, and no option but one sslmode;
## every other option, percent escape, host list, socket directory or fragment
## is refused rather than resolved. tools/testdburl is the same policy in Go
## (the integration witness and internal/testsupport.RequireTestDatabase, which
## every DB-backed suite calls, both judge with it), and
## tools/integration-witness/endpoint_test.go runs one case table through both
## (TEST-DB-ENDPOINT-1). PGHOSTADDR and PGSERVICE are refused too: either can
## send psql and createdb elsewhere despite their -h and -p.
## PORT 5513 (judge rulings Q1(a) and, OSS-MINT-GUARD-4, Q-HOSTED (a)): the
## owner's PostgreSQL. It is refused first, before any URL is read, on every
## host and in every job, including the 5513 default when nothing is set; no
## variable, CI marker or operating system admits it. The CI workflow's test
## PostgreSQL services publish 45432 instead (tools/testdburl.CIPort; neither
## 5513 nor 5432), and its jobs set DEV_PG_HOST_PORT=45432. Until
## OSS-MINT-GUARD-4 the hosted Integration Tests job's own database was
## excepted on a Linux host from four CI markers, which a local Linux shell
## could imitate (review OSS-MINT-GUARD-3-PREREVIEW H3); that exception is
## gone. IDENTUUM_IDP_ALLOW_NON_TEST_DB is consulted nowhere.
## Messages name the variable and the rule, never the URL.
## TEST_DB_JUDGE is the policy itself, shared with unit-db-endpoint below.
define TEST_DB_JUDGE
port='$(DEV_PG_HOST_PORT)'; \
	no() { echo "$@: REFUSED — $$*" >&2; exit 2; }; \
	case "$$port" in ''|0*|*[!0-9]*) no "DEV_PG_HOST_PORT is not a port number";; esac; \
	[ "$$port" -le 65535 ] || no "DEV_PG_HOST_PORT is not a port number"; \
	[ -z "$${PGHOSTADDR:-}$${PGSERVICE:-}" ] || no "PGHOSTADDR or PGSERVICE is set, and either can send psql and createdb to another server than 127.0.0.1:$$port; unset them"; \
	judge() { n=$$1; u=$$2; \
		[ "$$port" != 5513 ] || no "port 5513 is the owner's PostgreSQL; no test run uses it, in CI or anywhere else, so $$n is refused whatever it names. Set DEV_PG_HOST_PORT to a scratch server's port, for example DEV_PG_HOST_PORT=35599 make fast-up"; \
		case "$$u" in postgres://*) r=$${u#postgres://};; postgresql://*) r=$${u#postgresql://};; *) no "$$n is not a postgres:// URL, so its server cannot be checked; write it as a postgres:// URL on 127.0.0.1:$$port";; esac; \
		a=$${r%%[/?#]*}; p=$${r#"$$a"}; \
		case "$$p" in /*) p=$${p#/};; *) no "$$n has no /database path after its server";; esac; \
		case "$${a##*@}" in "127.0.0.1:$$port"|"localhost:$$port") ;; *) no "$$n does not name 127.0.0.1:$$port or localhost:$$port, the selected scratch server: test-db would create the database there and then migrate and test another server. Point both at the same scratch server, or set only DEV_PG_HOST_PORT and let the URL follow it";; esac; \
		db=$${p%%\?*}; q=$${p#"$$db"}; \
		case "$$db" in ''|*[!A-Za-z0-9_]*) no "$$n's database name is not plain letters, digits and underscores";; *_test) ;; *) no "$$n's database $$db does not end in _test";; esac; \
		case "$$q" in '') ;; '?sslmode='*) m=$${q#\?sslmode=}; case "$$m" in ''|*[!a-z-]*) no "$$n carries an sslmode that is not a plain mode name";; esac;; \
			*) no "$$n carries a connection option other than one sslmode; host, hostaddr, port, dbname, database and service options can send the driver to another server or database, so none is accepted";; esac; };
endef
.PHONY: test-db-endpoint
test-db-endpoint:
	@$(TEST_DB_JUDGE) \
	judge OSS_TEST_DB_URL '$(OSS_TEST_DB_URL)'; \
	if [ -n "$${IDENTUUM_IDP_TEST_DATABASE_URL:-}" ]; then judge IDENTUUM_IDP_TEST_DATABASE_URL "$$IDENTUUM_IDP_TEST_DATABASE_URL"; fi; \
	echo "test-db-endpoint: every test database URL names 127.0.0.1:$$port and a _test database"

## unit-db-endpoint (OSS-MINT-GUARD-3, review OSS-MINT-GUARD-2 G1): the
## prerequisite of the runners that hand the caller's environment to
## `go test ./...` — go-test-race (ci-verify's test floor) and test. Their
## DB-backed unit suites (internal/runtime, pkg/runtime, pkg/migrations,
## cmd/identuum-idp, internal/pkg/runtime) open IDENTUUM_IDP_TEST_DATABASE_URL
## when it is set, and pkg/migrations DROPs and CREATEs databases on its
## server. A set URL is judged by TEST_DB_JUDGE above, exactly as
## test-db-endpoint judges it, before any command runs; an unset one is no
## database (those suites skip, or fail under IDENTUUM_IDP_REQUIRE_DB_TESTS).
## RequireTestDatabase applies the same policy inside each suite, so a bare
## `go test` is refused too.
.PHONY: unit-db-endpoint
unit-db-endpoint:
	@$(TEST_DB_JUDGE) \
	if [ -n "$${IDENTUUM_IDP_TEST_DATABASE_URL:-}" ]; then judge IDENTUUM_IDP_TEST_DATABASE_URL "$$IDENTUUM_IDP_TEST_DATABASE_URL"; \
		echo "unit-db-endpoint: IDENTUUM_IDP_TEST_DATABASE_URL names 127.0.0.1:$$port and a _test database"; \
	else echo "unit-db-endpoint: IDENTUUM_IDP_TEST_DATABASE_URL is not set, so no suite opens a database"; fi

ci-integration-test: test-db-endpoint
	@# -p 1 serializes PACKAGES. The DB-backed integration packages
	@# (internal/e2e, internal/postgres, internal/runtime, …) all share the ONE
	@# $(OSS_TEST_DB_URL) database, and internal/e2e's setup-replay suite
	@# TRUNCATEs shared tables while internal/postgres seeds orgs/clients —
	@# under go test's default package parallelism they race: measured
	@# 2026-08-21, one run lost a just-seeded client row mid-test
	@# ("no rows in result set") and the next counted foreign orgs in the
	@# setup-flow assertion ("non-system org count = 3; want 1"), a different
	@# victim each run. Within-package ordering was never parallel; -p 1 makes
	@# the cross-package ordering match it.
	@IDENTUUM_IDP_TEST_DATABASE_URL="$${IDENTUUM_IDP_TEST_DATABASE_URL:-$(OSS_TEST_DB_URL)}" \
	IDENTUUM_IDP_ENCRYPTION_KEY="$${IDENTUUM_IDP_ENCRYPTION_KEY:-cafebabecafebabecafebabecafebabecafebabecafebabecafebabecafebabe}" \
		go test -tags integration -p 1 ./... -count=1 -v

integration-test:
	@$(MAKE) --no-print-directory test-db
	@$(MAKE) --no-print-directory ci-integration-test
	@$(MAKE) --no-print-directory rulefloor-integration

## rulefloor-integration: the DB-backed rule teeth. Runs every ledger row of
## the integration profile (RG1/RG2 — the AdminPermissionsModel UPDATE teeth)
## against the live database, using the same DSN default integration-test
## exports. Plain `make verify` stays DB-free: those rows are verified
## statically there, and their runtime truth is THIS target's job. Missing
## sibling or failed tool build is CANNOT-EVALUATE = exit 2, never a skip,
## and a runtime SKIP inside the profile run is CANNOT-EVALUATE too.
rulefloor-integration: test-db-endpoint
	@$(RULEFLOOR_RESOLVE); \
	IDENTUUM_IDP_TEST_DATABASE_URL="$${IDENTUUM_IDP_TEST_DATABASE_URL:-$(OSS_TEST_DB_URL)}" \
		"$$RF" check --run-profile integration --tags integration

## verify-integration (THE-UNRUN-SUITE, owner ruling P-041): the gate for the
## integration-tagged suites, with a witness record of its own.
##
## WHY IT IS SEPARATE. `make verify` type-checks these files (vet-integration)
## but RUNS nothing in them, and that gap let two defects reach a witness — a
## bundle fixture broken for a slice, and the advertised RS256 list wrong for
## two days with a test on the right side sitting red. `make verify` stays
## DATABASE-FREE on purpose: it must run on any machine with a Go toolchain and
## no Docker. So the profile gets this entry point instead, wired into the
## two-repo mint where a database already stands up.
##
## THE RECORD. GATE-RUN.integration.txt, written incrementally by
## scripts/gate-witness.sh and GITIGNORED for the same reason as the ui's
## GATE-RUN.e2e-full.txt: a second committed record would stale the committed
## verify record's tree digest. Re-check it any time with
## `bash scripts/gate-witness.sh check . GATE-RUN.integration.txt`.
##
## THE THREE STEPS. integration-preflight answers the one question that decides
## whether a verdict is possible at all (is there a database?) and exits 2 —
## CANNOT-EVALUATE, never a pass — when there is not. integration-profile runs
## the suites through tools/integration-witness, which refuses to call a run
## with ZERO executed tests green. rulefloor-integration runs the ledger's
## DB-backed rows. Measured on an M-series laptop, 2026-09-03: 3s + 65s + 275s.
## The witness is BUILT, not `go run`: MEASURED 2026-09-03, `go run` reports a
## child's exit 2 as its own exit 1 (printing "exit status 2" to stderr), which
## would collapse CANNOT-EVALUATE into an ordinary failure and lose exactly the
## distinction this gate promises.
## THE ENDPOINT (OSS-MINT-ISOLATION, 2026-10-10). lictor hands a plan entry
## only its allowlist and the --env names (measured: GIT_OPTIONAL_LOCKS,
## GOENV, GOWORK, HOME, LC_ALL, PATH). Before this, a scratch DEV_PG_HOST_PORT
## or test URL never reached test-db or integration-witness, and both fell back
## to 5513. The recipe exports the one test URL and declares it and the port.
verify-integration: test-db-endpoint bin/integration-witness
	+@$(call LICTOR_ASSERT,verify-integration); \
	export IDENTUUM_IDP_TEST_DATABASE_URL="$${IDENTUUM_IDP_TEST_DATABASE_URL:-$(OSS_TEST_DB_URL)}"; \
	$(GATE_RECORD_DRIVER) "$(LICTOR)" witness run --repo "$(CURDIR)" \
		--record GATE-RUN.integration.txt \
		--label "identuum-idp-oss make verify-integration" \
		--env DEV_PG_HOST_PORT --env IDENTUUM_IDP_TEST_DATABASE_URL -- \
		$(VERIFY_INTEGRATION_PLAN)

# One authoritative argument vector; drivers enter through the target above.
define VERIFY_INTEGRATION_PLAN
		'integration-preflight=./bin/integration-witness -preflight' \
		'integration-db=$(MAKE) --no-print-directory test-db' \
		'integration-profile=./bin/integration-witness' \
		'rulefloor-integration=$(MAKE) --no-print-directory rulefloor-integration'
endef

.PHONY: verify-check ci-verify-check verify-integration-check
# Re-enter the SAME recipes, changing only where their record is written.
# No target vector, ordering, dependency or failure mode is repeated here.
verify-check ci-verify-check verify-integration-check:
	+@$(MAKE) --no-print-directory $(patsubst %-check,%,$@) GATE_RECORD_DRIVER='bash scripts/verify-check.sh'

.PHONY: verify-parallel
## verify-parallel: the two idp-oss witness legs CONCURRENTLY (THE-PARALLEL-RITUAL).
##
## MEASURED, not assumed (2026-09-04, this machine, dev DB already up):
##   serial      verify 102s + verify-integration 112s = 214s
##   concurrent  verify 110s | verify-integration 130s = 130s   saving 84s (39%)
## Both legs went green in BOTH arrangements. The legs DO contend for CPU —
## each is slower here than alone (+8%, +16%) — which is why the concurrent
## number is measured rather than taken as the longest leg.
##
## WHY THIS PAIR IS SAFE TO OVERLAP, enumerated rather than hoped:
##   - different records: GATE-RUN.txt vs GATE-RUN.integration.txt, and
##     gate-witness.sh now takes a per-record lock keyed on the record's
##     ABSOLUTE path, so even a same-record collision refuses instead of
##     interleaving (selftest case 10);
##   - no shared database: `verify` is database-free; only the integration leg
##     touches Postgres on $(DEV_PG_HOST_PORT) and identuum_idp_oss_test;
##   - no shared port and no shared compose project between the two.
##
## The wiki check is deliberately NOT here. It is not an independent leg: it
## READS both code repos' records (`check ../identuum-idp-oss GATE-RUN.txt`
## and friends), so overlapping it with the runs that WRITE those records is
## reading a file mid-write. It can only ever follow.
##
## Each recipe line is its own shell and this file declares bash, so the whole
## thing is ONE line: pipefail is set before the subshells (they inherit it, so
## a failing leg is not masked by its sed), and BOTH waits are collected before
## exiting. Propagation was proved for all four leg outcomes
## (true/true -> 0, false/true -> 1, true/false -> 1, false/false -> 1) and
## then observed firing on the real target.
verify-parallel:
	@set -o pipefail; ( $(MAKE) --no-print-directory verify 2>&1 | sed 's/^/[verify]      /' ) & p1=$$!; ( $(MAKE) --no-print-directory verify-integration 2>&1 | sed 's/^/[integration] /' ) & p2=$$!; rc=0; wait $$p1 || rc=1; wait $$p2 || rc=1; if [ "$$rc" -ne 0 ]; then echo "verify-parallel: at least one leg FAILED — read GATE-RUN.txt and GATE-RUN.integration.txt for the per-target exit codes" >&2; fi; exit $$rc

## PHONY (OSS-MINT-GUARD-2): a file target with no prerequisites never rebuilt
## an existing bin/integration-witness, so a changed witness could be judged by
## a stale binary. go build is incremental, so rebuilding every time is cheap.
.PHONY: bin/integration-witness
bin/integration-witness:
	go build -o bin/integration-witness ./tools/integration-witness

## validate: build + unit tests + staticcheck + integration build/test.
## Starts from a clean database (fast-clean removes stale volume data before run).
## The integration endpoint is judged FIRST, before fast-clean, not at
## integration-test after it (OSS-MINT-GUARD-2): a refused port must not cost
## the volume first.
validate: test-db-endpoint build test staticcheck
	go build -tags integration ./...
	$(MAKE) fast-clean
	$(MAKE) fast-up
	$(MAKE) integration-test
	$(MAKE) fast-down

## api-docgen: build + run the IDP OSS API docs-as-data generator (P1).
## Writes ./output/api/endpoints.yaml (gitignored). Deterministic + zero
## external services. NOT wired into `make validate` — opt-in only.
api-docgen:
	go build -o bin/api-docgen ./tools/api-docgen
	./bin/api-docgen

## api-docgen-dry-run: build + run the IDP OSS API generator in dry-run mode
## (writes YAML to stdout instead of disk). Useful for quick previews.
api-docgen-dry-run:
	go build -o bin/api-docgen ./tools/api-docgen
	./bin/api-docgen --dry-run

## api-docs: build the docs-as-data generator and emit an OpenAPI 3.0.3
## spec to the REPO ROOT as ./openapi.yaml (checked in, unlike the
## gitignored ./output/api/endpoints.yaml — this is the public,
## machine-readable API surface for OSS consumers). Deterministic; safe
## to re-run any time a route annotation changes.
api-docs:
	go build -o bin/api-docgen ./tools/api-docgen
	./bin/api-docgen --format=openapi --output .

## clean: remove build artifacts.
clean:
	rm -rf bin/
	rm -rf output/
	rm -f identuum-idp

## oss-build: build the local-demo OSS app image (Postgres + app profile).
##   Image: ${IDENTUUM_IDP_COMPOSE_PROJECT:-identuum-idp-oss-dev}:local (identuum-idp-oss-dev:local by default, D-024).
##   Source: deployment/Dockerfile.local (multi-stage golang:1.26.5-bookworm builder + debian:bookworm-slim runtime).
##   DB URLs are never echoed (compose env handles the URL inside the container).
##
## DEV_COMPOSE (OSS-MINT-GUARD-2, review OSS-MINT-COVERAGE C1): the e2e
## harness starts its appliance through oss-up, and compose lets an inherited
## COMPOSE_PROJECT_NAME outrank the file's own `name:`, so a caller's shell
## could aim the start at another project — the owner's identuum-idp-oss among
## them — while protected-guard checked identuum-e2e. oss-build and oss-up
## therefore run with the project pinned by -p to DEV_COMPOSE_PROJECT, the name
## protected-guard checks, with IDENTUUM_IDP_COMPOSE_PROJECT set to the same
## name for the file's container, image and volume names, and with
## COMPOSE_PROJECT_NAME and COMPOSE_REMOVE_ORPHANS cleared. oss-up refuses a
## DEV_APP_CONTAINER that is not that project's app container.
## compose-pin-selftest proves it with a docker stub. Started by a harness
## (devseed-live, e2e-full), each first runs HARNESS_BINDING_CHECK
## (OSS-MINT-GUARD-6; it also requires a scratch- project since
## OSS-CANDIDATE-LIFECYCLE-FIX).
DEV_COMPOSE = env -u COMPOSE_PROJECT_NAME -u COMPOSE_REMOVE_ORPHANS IDENTUUM_IDP_COMPOSE_PROJECT=$(DEV_COMPOSE_PROJECT) $(COMPOSE_CMD) -p $(DEV_COMPOSE_PROJECT) -f $(COMPOSE_FILE)
oss-build:
	$(HARNESS_BINDING_CHECK)
	$(DEV_COMPOSE) --profile app build --build-arg COMMIT=$(COMMIT) app

## oss-up: bring up Postgres + the OSS app container together.
##   The app container runs `identuum-idp migrate <url>` first (one-shot),
##   then serves the full OSS IdP via the no-arg default action (config
##   from IDENTUUM_IDP_DATABASE_URL / _ISSUER / _LISTEN). Listens on
##   127.0.0.1:7113.
##
##   PORT CONFLICT: if the old monolith container `identuum-idp-app` is
##   holding 7113, this target's `up -d` will fail. Operator must run:
##     docker stop identuum-idp-app
##   first (non-destructive; revert with `docker start identuum-idp-app`).
oss-up: protected-guard oss-app-container-check oss-build
	$(HARNESS_BINDING_CHECK)
	$(DEV_COMPOSE) --profile app up -d
	@# THE-LYING-READY: `up -d` returns as soon as the container is CREATED, and
	@# the entrypoint still has to migrate before it serves — so this target
	@# cannot claim 7113 is answering, and does not. The probes below are
	@# commands to run ONCE it is serving, not a statement that they work now.
	@echo "OSS app container STARTING on 127.0.0.1:$(DEV_APP_PORT) (Postgres on 127.0.0.1:$(DEV_PG_HOST_PORT))."
	@echo "It is not serving yet — the entrypoint migrates first. Wait for health:"
	@echo "  until curl -fsS --max-time 2 http://127.0.0.1:$(DEV_APP_PORT)/health >/dev/null; do sleep 2; done"
	@echo "Then smoke it:"
	@echo "  curl -s http://127.0.0.1:$(DEV_APP_PORT)/system/info"
	@echo "  curl -i http://127.0.0.1:$(DEV_APP_PORT)/api/v1/organizations"
	@echo "  curl -i http://127.0.0.1:$(DEV_APP_PORT)/api/v1/organizations/00000000-0000-7000-0000-000000000000/protocol-settings"

.PHONY: oss-app-container-check
oss-app-container-check:
	@[ "$(DEV_APP_CONTAINER)" = "$(DEV_COMPOSE_PROJECT)" ] || { echo "oss-up: REFUSED — DEV_APP_CONTAINER is $(DEV_APP_CONTAINER) but the compose project $(DEV_COMPOSE_PROJECT) names its app container $(DEV_COMPOSE_PROJECT); later targets would act on another container than the one started (nothing was built or started)" >&2; exit 2; }

## oss-down: stop the OSS app container (Postgres preserved so the
## next `oss-up` is fast).
oss-down: protected-guard
	$(COMPOSE_CMD) -f $(COMPOSE_FILE) --profile app stop app
	$(COMPOSE_CMD) -f $(COMPOSE_FILE) --profile app rm -f app

## oss-logs: follow the OSS app container logs (Ctrl-C to detach).
oss-logs:
	$(COMPOSE_CMD) -f $(COMPOSE_FILE) --profile app logs -f app

## oss-bootstrap: idempotent local-demo bootstrap against the running OSS app
##   container. Ensures one active signing key exists and creates the
##   site_admin row pinned to domain.SiteAdminID. Safe to re-run.
##
##   Requires IDENTUUM_IDP_BOOTSTRAP_PASSWORD to be exported in the caller's
##   environment. Optional: IDENTUUM_IDP_BOOTSTRAP_EMAIL (default
##   site_admin@system.local) and IDENTUUM_IDP_BOOTSTRAP_ALGORITHM
##   (EdDSA|ES256, default EdDSA).
##
##   The password is forwarded into the running container via `-e` so it
##   stays on the operator's host shell and the container's env block —
##   it is NEVER printed by the make rule or by the bootstrap binary.
##   The DB URL stays inside the container (read from $$IDENTUUM_IDP_OSS_DB
##   in the compose env). Neither shows up in `make` stdout.
##
##   Usage:
##     IDENTUUM_IDP_BOOTSTRAP_PASSWORD='<choose-a-strong-local-demo-password>' \
##       make oss-bootstrap
##
##   The bootstrap binary runs identuum-idp bootstrap inside the existing
##   identuum-idp-oss container. The container keeps serving HTTP — this is a
##   side-channel one-shot.
oss-bootstrap:
	@if [ -z "$$IDENTUUM_IDP_BOOTSTRAP_PASSWORD" ]; then \
		echo "ERROR: IDENTUUM_IDP_BOOTSTRAP_PASSWORD is not set in the caller's environment."; \
		echo "       Set it before running make oss-bootstrap (it is never echoed)."; \
		exit 2; \
	fi
	@# Exec the binary DIRECTLY — no `sh -c`. The runtime image is distroless
	@# (no shell), so `app sh -c '…'` died with exec: "sh": executable file not
	@# found and this target could never have worked (THE-MANUAL-TARGETS; the
	@# same defect RECOVERY-BINARY-PATH-1 already fixed in oss-recover-site-admin
	@# below). bootstrap with no positional URL reads the container's own
	@# IDENTUUM_IDP_DATABASE_URL / IDENTUUM_IDP_OSS_DB (requirePositionalURL) —
	@# no DSN assembly, no shell, and the URL never crosses the host boundary.
	@$(COMPOSE_CMD) -f $(COMPOSE_FILE) --profile app exec \
		-e IDENTUUM_IDP_BOOTSTRAP_PASSWORD \
		-e IDENTUUM_IDP_BOOTSTRAP_EMAIL \
		-e IDENTUUM_IDP_BOOTSTRAP_ALGORITHM \
		app /app/identuum-idp bootstrap

## oss-setup-code: print the first-run setup code for the RUNNING OSS app
##   container, for the browser wizard at http://localhost:7104/setup.
##
##   NO COMPOSE CHANGE WAS NEEDED, and none was made (THE-MANUAL-TARGETS,
##   measured 2026-08-31): /app/data is created by the appliance entrypoint
##   (appliance.PrepareDataDir → MkdirAll 0700) inside the container's own
##   writable layer, and the boot banner writes the token there. The command
##   was verified live against a container with ZERO mounts. Mounting a
##   /app/data volume was considered and REJECTED as unnecessary; the
##   SIGNING-KEY-SEAL-1 note in docker-compose.dev.yml is unaffected either
##   way, because ResolveEncryptionKey returns KeyFromOperator the moment
##   IDENTUUM_IDP_ENCRYPTION_KEY is set (which dev compose always sets) and
##   never consults the data dir for the key.
##
##   The code is only valid while the DB reports setup_required; once setup
##   completes the command says so and exits 2. The token is per-container:
##   recreating the app container regenerates it (the new one is printed on
##   the boot banner), so read it AFTER the container you intend to set up.
##
##   Prints the code to the operator's terminal — treat that terminal like
##   the boot log: it is a credential for the wizard.
oss-setup-code:
	@$(COMPOSE_CMD) -f $(COMPOSE_FILE) --profile app exec \
		app /app/identuum-idp show-setup-code /app/data

## openid-conformance: MANUAL OpenID Foundation conformance run
##   (THE-CONFORMANCE-HARNESS). Stands up the pinned conformance suite AND a
##   fresh disposable appliance with a conformance org on an ISOLATED compose
##   project (scratch-conformance; host ports 127.0.0.1:28443/28444/27113 —
##   never the dev stack or its data), runs the config-certification plan and
##   the basic plan headless, reports the suite's verdicts VERBATIM against
##   the committed expected-failure floor, and tears BOTH stacks down on
##   success, failure or interrupt. OSS-CANDIDATE-LIFECYCLE-FIX (SPEC K1-K5,
##   K8): it takes the shared harness claim HARNESS_LOCK and the daemon
##   mutex first, refuses existing project objects instead of a pre-run
##   down, records what it creates by ID and removes only that, as one whole
##   step, with no down; a refused teardown keeps the claim, the mutex and the
##   record. Only the cached suite clone (.conformance-suite-cache/, pinned by
##   conformance/PIN) and the images survive.
##   NOT part of verify or test-full. Fixes nothing; findings are reported.
##   See docs/TESTING-OPERATORS.md ("The OpenID conformance harness").
.PHONY: openid-conformance
## openid-conformance: the whole harness (both plans). THE-JAR-REQUEST-OBJECT
## adds the single-module runner: `make openid-conformance MODULE=<name>`
## runs ONLY that basic-plan module (index resolved from the committed
## conformance/plan-basic.modules.txt, which every FULL run regenerates),
## skipping the config plan — an iteration tool; the floor verdict still
## comes from the full run.
openid-conformance:
	@CONFORMANCE_MODULE="$(MODULE)" bash conformance/run.sh

## oss-fresh: DESTROY the local OSS stack and stand a bootstrapped one up.
##
##   *** THIS DESTROYS DATA. *** It removes the app + Postgres containers AND
##   the named Postgres volume — every organization, user, client, key and
##   audit row in the local dev database is gone. It refuses to run without
##   an explicit opt-in, which is deliberately not a default:
##
##     IDENTUUM_IDP_BOOTSTRAP_PASSWORD='<strong-local-demo-password>' \
##       make oss-fresh I_UNDERSTAND_THIS_DESTROYS_ALL_DATA=1
##
##   Sequence: fast-clean (profile-aware, so nothing survives) → oss-up →
##   wait for /health → oss-bootstrap → print where to sign in. Bootstrap
##   and the browser wizard are MUTUALLY EXCLUSIVE paths; this target takes
##   the bootstrap path, so /setup will report setup already complete.
oss-fresh:
	@if [ "$(I_UNDERSTAND_THIS_DESTROYS_ALL_DATA)" != "1" ]; then \
		echo "REFUSING: oss-fresh DESTROYS ALL LOCAL DEV DATA."; \
		echo "  It removes: the identuum-idp-oss-dev app container, the postgres-idp-oss"; \
		echo "  container, and the named Postgres volume (every org, user, client,"; \
		echo "  signing key and audit row in the local dev database)."; \
		echo "  Re-run with an explicit opt-in if that is what you want:"; \
		echo "    IDENTUUM_IDP_BOOTSTRAP_PASSWORD='<password>' make oss-fresh I_UNDERSTAND_THIS_DESTROYS_ALL_DATA=1"; \
		exit 2; \
	fi
	@if [ -z "$$IDENTUUM_IDP_BOOTSTRAP_PASSWORD" ]; then \
		echo "ERROR: IDENTUUM_IDP_BOOTSTRAP_PASSWORD is not set in the caller's environment."; \
		echo "       Set it before running make oss-fresh (it is never echoed)."; \
		exit 2; \
	fi
	@echo "oss-fresh: destroying the local OSS stack (containers + Postgres volume)..."
	@$(MAKE) --no-print-directory fast-clean
	@echo "oss-fresh: building + starting the appliance..."
	@$(MAKE) --no-print-directory oss-up
	@echo "oss-fresh: waiting for the appliance to serve..."
	@i=0; until curl -fsS --max-time 2 http://127.0.0.1:7113/health >/dev/null 2>&1; do \
		i=$$((i+1)); \
		if [ $$i -ge 60 ]; then echo "oss-fresh: appliance never became healthy (120s)"; exit 1; fi; \
		sleep 2; \
	done
	@echo "oss-fresh: bootstrapping site_admin..."
	@$(MAKE) --no-print-directory oss-bootstrap
	@echo ""
	@# THE-LYING-READY: never name a destination we have not probed. The UI is a
	@# SEPARATE process this target neither starts nor depends on, so its absence
	@# is the NORMAL outcome here and must never fail the run — the probe is
	@# hard-bounded (1s connect, 2s total) and its failure is an expected branch,
	@# not an error.
	@echo ""
	@if curl -fsS --connect-timeout 1 --max-time 2 -o /dev/null http://127.0.0.1:7104/ 2>/dev/null; then \
		echo "oss-fresh: BACKEND READY — and the UI answered on 7104 (probed just now)."; \
		echo "  IdP: http://localhost:7113   (health, OIDC discovery, API)"; \
		echo "  UI:  http://localhost:7104   (already running)"; \
		echo "  Sign in: http://localhost:7104/login as site_admin@system.local,"; \
		echo "  with the password you exported (this run never echoed it)."; \
	else \
		echo "oss-fresh: BACKEND READY — the IdP appliance is up and bootstrapped."; \
		echo "  IdP: http://localhost:7113   (health, OIDC discovery, API)"; \
		echo ""; \
		echo "  THE UI IS NOT RUNNING. It is a separate process; this target does"; \
		echo "  not start it, and nothing is listening on 7104 right now (probed)."; \
		echo "  There is no sign-in page to open until you start it:"; \
		echo ""; \
		echo "      cd ../identuum-ui && pnpm dev"; \
		echo ""; \
		echo "  Then sign in at http://localhost:7104/login as site_admin@system.local,"; \
		echo "  with the password you exported (this run never echoed it)."; \
	fi
	@echo "  Setup is ALREADY COMPLETE (bootstrap path) — do not run the /setup"
	@echo "  wizard; it will refuse."

## oss-recover-site-admin: explicit operator-run recovery for site_admin@system.local.
##   Use when the bootstrap row exists but the original password is lost.
##   This rewrites the password hash and resets MFA enrollment
##   (mfa_enabled=false, mfa_secret='', mfa_recovery_codes=[],
##   requires_password_change=false). Bootstrap is deliberately NOT changed
##   to update the password — that would let a re-bootstrap silently
##   overwrite an operator-set password.
##
##   Requires IDENTUUM_IDP_RECOVER_SITE_ADMIN_PASSWORD to be exported in
##   the caller's environment. The password is forwarded into the running
##   container via `-e` so it stays on the operator's host shell and the
##   container's env block — it is NEVER printed by the make rule or by
##   the recovery binary. The resulting argon2id hash is produced inside
##   the repository layer and never crosses the recovery boundary.
##
##   Usage:
##     IDENTUUM_IDP_RECOVER_SITE_ADMIN_PASSWORD='<choose-new-local-demo-password>' \
##       make oss-recover-site-admin
##
##   The recovery binary refuses to operate on a row whose ID/role/org
##   does not match the SiteAdminID / RoleSiteAdmin / SystemOrgID
##   sentinels — it cannot accidentally retarget a tenant user.
oss-recover-site-admin:
	@if [ -z "$$IDENTUUM_IDP_RECOVER_SITE_ADMIN_PASSWORD" ]; then \
		echo "ERROR: IDENTUUM_IDP_RECOVER_SITE_ADMIN_PASSWORD is not set in the caller's environment."; \
		echo "       Set it before running make oss-recover-site-admin (it is never echoed)."; \
		exit 2; \
	fi
	@# Exec the binary DIRECTLY — no `sh -c`. The runtime image is distroless
	@# (no shell), so `app sh -c '…'` failed with exec: "sh": executable file
	@# not found — "Error 127" in make's message; make's own exit is 2, as for
	@# every failed recipe (RECOVERY-BINARY-PATH-1). recover-site-admin
	@# with no positional URL reads the container's own IDENTUUM_IDP_DATABASE_URL
	@# / IDENTUUM_IDP_OSS_DB (requirePositionalURL) — no DSN assembly, no shell.
	@$(COMPOSE_CMD) -f $(COMPOSE_FILE) --profile app exec \
		-e IDENTUUM_IDP_RECOVER_SITE_ADMIN_PASSWORD \
		app /app/identuum-idp recover-site-admin

## verify-no-panic: P-018 completion gate — fails if any non-exempt panic/log.Fatal/os.Exit exists
## in production Go source (internal/ pkg/ cmd/, excluding _test.go and comment lines).
## Exempt per wiki/platform/server-model.md §7: cmd/identuum-idp/main.go (post-serve os.Exit),
##   internal/tlscert/generation.go (one-shot cert tooling), internal/mw/auth.go InjectPrincipalForTest.
## NOT wired into CI yet (no CI exists); run manually as a pre-release gate or after any serving-path edit.
verify-no-panic:
	@HITS=$$(grep -rnE --include="*.go" '\bpanic\(|log\.Fatal|os\.Exit' internal/ pkg/ cmd/ \
		| grep -v '_test\.go' \
		| grep -Ev ':[0-9]+:[[:space:]]*//' \
		| grep -v 'cmd/identuum-idp/main\.go' \
		| grep -v 'internal/tlscert/generation\.go' \
		| grep -v 'InjectPrincipalForTest'); \
	if [ -n "$$HITS" ]; then \
		echo "FAIL: non-exempt panic/log.Fatal/os.Exit found (violates P-018):"; \
		echo "$$HITS"; \
		exit 1; \
	fi
	@echo "verify-no-panic: OK — no non-exempt panic/log.Fatal/os.Exit in production Go source."

## verify-oss: end-to-end release gate (Docker required for phases 5-6).
##   Runs all phases in order, failing fast on any error:
##   (1) go build ./...         — compiler check
##   (2) staticcheck            — static analysis (matches validate)
##   (3) go test ./...          — unit tests
##   (4) verify-no-panic        — P-018 serving-path gate
##   (5) integration + teeth    — fast-clean → fast-up (Postgres:5513) →
##                                integration-test (e2e + runtime/pkg-runtime +
##                                internal/postgres teeth) → fast-down
##   (6) container contract e2e — oss-up (Postgres:5513 + app:7113) →
##                                health-wait → verify-oss-contract → oss-down
##   Phase 5 tears down the integration Postgres (fast-down) before phase 6
##   starts the compose stack (oss-up) — port 5513 is never double-bound.
##   Ends with "verify-oss: all checks passed" on full success.
verify-oss:
	$(MAKE) build
	$(MAKE) staticcheck
	$(MAKE) test
	$(MAKE) verify-no-panic
	go build -tags integration ./...
	$(MAKE) fast-clean
	$(MAKE) fast-up
	$(MAKE) integration-test
	$(MAKE) fast-down
	$(MAKE) oss-up
	@echo "verify-oss: waiting for OSS IdP to become healthy on 127.0.0.1:7113 ..."
	@WAIT=0; until curl -fsS --max-time 2 http://127.0.0.1:7113/health >/dev/null 2>&1; do \
		sleep 2; WAIT=$$((WAIT+2)); \
		if [ $$WAIT -ge 60 ]; then \
			echo "verify-oss: FAIL — OSS IdP did not become healthy within 60s"; exit 1; \
		fi; \
	done
	@echo "verify-oss: OSS IdP healthy."
	$(MAKE) verify-oss-contract
	$(MAKE) oss-down
	@echo "verify-oss: all checks passed"
# Judged before fast-clean, as for validate (OSS-MINT-GUARD-2).
verify-oss: test-db-endpoint

## verify-oss-contract: assert the OSS IdP wire contract against a
## running OSS runtime (the full IdP — the default serve action). Pins:
##   - /health 200 with status:"healthy"
##   - /.well-known/openid-configuration 200
##   - /.well-known/jwks.json 200
##   - /api/v1/component 200 (full-IdP-only route — proves this is the
##       real IdP, not the removed minimal scaffold)
##   - /authorize NOT 200 (mounted, but 4xx/redirect without valid params)
##   - /token NOT 200 (mounted, but 4xx without a valid request)
##
## Override IDP_BASE_URL to point at a non-default IDP host.
##
## This target is the OSS-side companion to the UI Playwright spec
## at identuum-ui/e2e/oss-contract.spec.ts; the two assert the same
## wire contract from opposite sides (host curl vs browser fetch). The
## /authorize and /token endpoints exist on the full IdP and return 4xx
## without valid input, so the NOT-200 pins still hold.
verify-oss-contract:
	@IDP_BASE_URL="$${IDP_BASE_URL:-http://localhost:7113}"; \
		echo "  Probing $$IDP_BASE_URL/health …"; \
		BODY=$$(curl -fsS --max-time 5 "$$IDP_BASE_URL/health") \
			|| { echo "  FAIL: /health unreachable"; exit 1; }; \
		echo "$$BODY" | grep -q '"status":"healthy"' \
			|| { echo "  FAIL: /health response missing 'status:healthy'"; exit 1; }; \
		echo "  /health OK"; \
		echo "  Probing $$IDP_BASE_URL/.well-known/openid-configuration …"; \
		curl -fsS --max-time 5 "$$IDP_BASE_URL/.well-known/openid-configuration" >/dev/null \
			|| { echo "  FAIL: /.well-known/openid-configuration unreachable"; exit 1; }; \
		echo "  /.well-known/openid-configuration OK"; \
		echo "  Probing $$IDP_BASE_URL/.well-known/jwks.json …"; \
		curl -fsS --max-time 5 "$$IDP_BASE_URL/.well-known/jwks.json" >/dev/null \
			|| { echo "  FAIL: /.well-known/jwks.json unreachable"; exit 1; }; \
		echo "  /.well-known/jwks.json OK"; \
		echo "  Probing $$IDP_BASE_URL/api/v1/component (full-IdP-only; must be 200) …"; \
		curl -fsS --max-time 5 "$$IDP_BASE_URL/api/v1/component" >/dev/null \
			|| { echo "  FAIL: /api/v1/component not 200 — this is not the full OSS IdP"; exit 1; }; \
		echo "  /api/v1/component OK (full IdP confirmed)"; \
		echo "  Probing $$IDP_BASE_URL/authorize (must NOT be 200) …"; \
		STATUS=$$(curl -s --max-time 5 -o /dev/null -w '%{http_code}' "$$IDP_BASE_URL/authorize"); \
		test "$$STATUS" != "200" \
			|| { echo "  FAIL: /authorize returned 200 — must be 4xx/redirect without valid params"; exit 1; }; \
		echo "  /authorize NOT 200 (got $$STATUS) ✓"; \
		echo "  Probing $$IDP_BASE_URL/token (must NOT be 200) …"; \
		STATUS=$$(curl -s --max-time 5 -X POST -o /dev/null -w '%{http_code}' "$$IDP_BASE_URL/token"); \
		test "$$STATUS" != "200" \
			|| { echo "  FAIL: /token returned 200 — must be 4xx without a valid request"; exit 1; }; \
		echo "  /token NOT 200 (got $$STATUS) ✓"
	@echo "OSS IdP runtime contract passed."

## test-full: the TEST-spec anchor — one command in THIS repo runs the full
## disposable-appliance behavior suite (T2 of the plan in
## docs/maintainers/TEST-spec-status.md).
##
## The ORCHESTRATOR BODY deliberately stays in the sibling checkout
## (identuum-ui/e2e-full/scripts/full-run.sh) — measured 2026-08-30: four ui
## source-invariant tests (static-rows, ui-provisioner, skip-ceiling,
## coverage-floor) pin that script's CONTENT and run in ui's single-checkout
## CI, so physically relocating it breaks four CI invariants. This target is
## the anchored ENTRY POINT: it requires the sibling checkout, delegates to
## the canonical runner (which stands the appliance FROM THIS REPO's working
## tree via oss-up), and then INDEPENDENTLY verifies the witnessed record —
## a delegated run that lies about its result still fails here.
.PHONY: test-full
test-full:
	@test -d ../identuum-ui || { echo "test-full: sibling checkout ../identuum-ui is required (the UI-driving phases and playwright specs live there)"; exit 1; }
	@# THE-UNMINTED-DIFF: ask FIRST whether this diff can reach the appliance,
	@# then DISPATCH. A dispatcher, not an early `exit 0`, because every make
	@# recipe LINE runs in its own shell — the first version exited that one
	@# line and the mint ran anyway. Caught by running it.
	@#
	@# The classifier's exit code IS the branch: 0 SKIPPABLE takes the skip,
	@# and REQUIRED (10) or undecidable (anything else) both fall through to
	@# the real mint. Fail closed: only an explicit 0 skips.
	@# THE-ONE-MINT-RECORD (2026-09-12): the classifier reads the mint's own
	@# record — ../identuum-ui/GATE-RUN.e2e-full.txt, both heads and the
	@# sibling's tree digest — and nothing else. MINT-STATE.json, the marker
	@# only this target wrote, is retired: three mints paid from the sibling
	@# had moved the record and never the marker.
	@# OSS-TIDY-3: the tier is the classifier's own line. `go run` collapses
	@# exit 10 to 1, so the line, not the code, says "e2e-quick owed"; any
	@# other non-zero answer — the full tier, undecidable, an unknown line —
	@# pays e2e-full. Fail closed: quick only when quick is named.
	@out=$$(go run ./tools/mint-reachability --repo . 2>&1); rc=$$?; \
	printf '%s\n' "$$out"; \
	if [ $$rc -eq 0 ]; then \
		echo "test-full: MINT SATISFIED by the e2e record in ../identuum-ui; every path since its heads is declared no-reach."; \
		echo "test-full: every mint floor stands; the next mint that runs still holds them."; \
	else \
		tier=full; \
		case "$$out" in *"e2e-quick owed"*) tier=quick;; esac; \
		echo "test-full: MINT REQUIRED — tier $$tier (e2e-$$tier)"; \
		$(MAKE) --no-print-directory test-full-mint E2E_TIER=$$tier; \
	fi

## test-full-mint: the mint itself. Never invoke directly to dodge the
## reachability check — test-full is the entry point, and this target exists
## only so the skip can be a branch instead of an early exit.
.PHONY: test-full-mint
## E2E_TIER: full (default) or quick — test-full passes the classifier's tier;
## the tier the sibling runs is the record this target checks.
E2E_TIER ?= full
test-full-mint:
	@case "$(E2E_TIER)" in full|quick) ;; *) echo "test-full-mint: E2E_TIER must be full or quick, got '$(E2E_TIER)'"; exit 2;; esac
	@# OSS-CANDIDATE-LIFECYCLE-FIX (SPEC K3): a mint is a candidate run, so its
	@# database phase reuses only a RECORDED scratch PostgreSQL — fast-up's
	@# scratch mode, IDENTUUM_IDP_COMPOSE_PROJECT=scratch-<name> with
	@# FAST_UP_PG_CONTAINER its full container ID. The default dev project, whose
	@# fast-up would reuse any server on the port or start the dev stack's own
	@# PostgreSQL by Compose, is never a mint path. Refused before anything runs.
	@case "$(DEV_COMPOSE_PROJECT)" in scratch-*) ;; *) echo "test-full-mint: REFUSED — the mint runs only against a recorded scratch PostgreSQL: set IDENTUUM_IDP_COMPOSE_PROJECT=scratch-<name> and FAST_UP_PG_CONTAINER=<the full ID its docker run printed> beside DEV_PG_HOST_PORT (docs/TESTING-OPERATORS.md, \"Running a mint against a scratch server\"); project $(DEV_COMPOSE_PROJECT) is not a scratch project (nothing was started)"; exit 2;; esac
	@# THE-UNRUN-SUITE (P-041): the integration profile runs HERE, before the
	@# appliance phases, because the mint is the one place a database is a
	@# given. fast-up is bounded and idempotent; the e2e harness tears the
	@# stack down at the end, so the test database is recreated next mint.
	$(MAKE) --no-print-directory fast-up
	@# OSS-DEVSEED-LIVE (owner ruling u, P-089): the owner's `make dev-seed`
	@# path proved live on its own disposable project. BEFORE the e2e half
	@# (owner ruling v, 2026-10-08): the e2e record is what the next test-full
	@# reads as the mint, so a red devseed-live must stop the mint before that
	@# record is written, or a re-run would answer MINT SATISFIED over it.
	@# E2E-SPEED-1 (owner ruling ee, 2026-10-08): verify-integration runs
	@# in the background while devseed-live runs in front. They share no
	@# project and no port: the integration profile uses the test database
	@# on 127.0.0.1:$(DEV_PG_HOST_PORT), devseed-live its own project scratch-devseed on
	@# 25513 and 27113. Each keeps its own exit code; the integration log is
	@# printed whole after both end, and the e2e half starts only when both
	@# are green, so neither can be red under a written e2e record.
	@log=$$(mktemp "$${TMPDIR:-/tmp}/verify-integration.XXXXXX"); \
	$(MAKE) --no-print-directory verify-integration >"$$log" 2>&1 & ipid=$$!; \
	$(MAKE) --no-print-directory devseed-live; drc=$$?; \
	wait $$ipid; irc=$$?; cat "$$log"; rm -f "$$log"; \
	echo "test-full-mint: verify-integration exit $$irc, devseed-live exit $$drc"; \
	[ $$irc -eq 0 ] && [ $$drc -eq 0 ]
	@bash scripts/gate-witness.sh check . GATE-RUN.integration.txt
	$(MAKE) -C ../identuum-ui e2e-$(E2E_TIER)
	@bash scripts/gate-witness.sh check ../identuum-ui GATE-RUN.e2e-$(E2E_TIER).txt
	@# The mint ran and both halves checked out. The record it wrote IS the
	@# marker: the next decision reads its heads (THE-ONE-MINT-RECORD).
	@echo "test-full: MINT PAID — ../identuum-ui/GATE-RUN.e2e-$(E2E_TIER).txt is the record of record for this pair."
# The endpoint guard on its own line, after the recipe: the recipe's tests
# find it by its header line (OSS-MINT-ISOLATION).
test-full-mint: test-db-endpoint
