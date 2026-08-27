# identuum-idp-oss — developer Makefile
# Requires: Go 1.26+, Docker with Compose plugin, staticcheck.
#
# Quick start:
#   make fast-up          # start local Postgres on 127.0.0.1:5513
#   make integration-test # run the DB-backed integration + teeth suites against the local DB
#   make fast-down        # stop and remove containers (volume preserved)
#
# Routine validation:
#   make verify
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
DEV_APP_CONTAINER ?= identuum-idp-oss
DEV_APP_PORT ?= 7113
DEV_HEALTH_URL ?= http://127.0.0.1:$(DEV_APP_PORT)/health
DEV_COMPONENT_URL ?= http://127.0.0.1:7113/api/v1/component
DEV_SYSTEM_INFO_URL ?= http://127.0.0.1:$(DEV_APP_PORT)/system/info

# DB URL for the DEV STACK / app — the human's live database. NOT used by the
# integration suites (TEST-DB-ISOLATION-1): those TRUNCATE and replay setup, so
# they must never point here. Override by exporting it before calling make.
OSS_DB_URL ?= postgres://idp_oss_user:dev-idp_oss_user-not-a-secret@127.0.0.1:5513/identuum_idp_oss?sslmode=disable

# DB URL for the INTEGRATION SUITES — a dedicated *_test database, separate from
# the dev DB (TEST-DB-ISOLATION-1). The harness refuses any DSN whose database
# name does not end in "_test" (internal/testsupport.RequireTestDatabase),
# absent IDENTUUM_IDP_ALLOW_NON_TEST_DB. Create it once with `make test-db`.
OSS_TEST_DB_URL ?= postgres://idp_oss_user:dev-idp_oss_user-not-a-secret@127.0.0.1:5513/identuum_idp_oss_test?sslmode=disable

# WIKI_TOOLS — the shared gate scripts live in the sibling wiki repo.
WIKI_TOOLS ?= $(CURDIR)/../wiki/tools

.PHONY: clock-fuse-gate repo-green fast-up fast-down fast-clean build build-binary test staticcheck integration-test validate clean api-docgen api-docgen-dry-run api-docs oss-up oss-down oss-logs oss-build oss-bootstrap oss-recover-site-admin image-base-parity fmt-check vet vet-integration integration-staticcheck doccomment-check integration-inventory tagged-vet clock-fuse-report tool-versions
.PHONY: dev-up dev-rebuild dev-recreate-app dev-ps dev-logs dev-app-logs dev-pg-logs dev-down dev-smoke dev-health
.PHONY: verify ci-verify tracked-binary-check credential-transparency image-base-check clock-fuse grype-scan verify-oss-contract verify-no-panic verify-oss wiki-fresh rulefloor-check rulefloor-integration ci-integration-test test-db

## wiki-fresh: WIKI-1 gate — fail verify when this repo's wiki page is BEHIND.
## Runs wiki-freshness.sh --repo identuum-idp-oss --strict against the sibling
## wiki checkout. BE HONEST ABOUT WHAT THIS ENFORCES: at verify time HEAD is
## the LAST commit, so a green gate means "the PREVIOUS slice's wiki update was
## banked before new work is verified" — zero commits of allowed drift. It does
## NOT and cannot check the commit you are about to make; the §F-bis append for
## THIS slice is still on you, and the gate will catch its absence on the NEXT
## slice's verify. A missing wiki dir (fresh clone / CI) prints one loud SKIPPED
## line and continues — visible, never silent. A typo'd repo name FAILS (the
## checker exits 2 when --repo matches no page), so the gate cannot be
## accidentally disabled by a rename.
WIKI_DIR ?= ../wiki

wiki-fresh:
	@if [ ! -d "$(WIKI_DIR)" ]; then \
		echo "WIKI FRESHNESS SKIPPED: no wiki at $(WIKI_DIR)"; \
	else \
		bash "$(WIKI_DIR)/tools/wiki-freshness.sh" --repo identuum-idp-oss --strict; \
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
##   0 GREEN   1 NOT-GREEN   3 CANNOT-EVALUATE (no toolchain / not a module)
## CANNOT-EVALUATE is FATAL here too — a gate that could not measure must never
## be mistaken for one that measured and approved.
repo-green:
	@bash "$(WIKI_TOOLS)/repo-green-gate.sh" --check .

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
# This recipe is the canonical repo-local close gate. README.md's Validation
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

verify:
	@$(MAKE) --no-print-directory tool-versions
	@$(MAKE) --no-print-directory repo-green
	@$(MAKE) --no-print-directory tracked-binary-check
	@$(MAKE) --no-print-directory credential-transparency
	# rulefloor-check sits EARLY on purpose: it is cheap (hash pins + four
	# standalone go test -run rows) and a tampered rule proof should fail the
	# aggregate before the expensive gates spend their minutes. Sibling-coupled,
	# so ci-verify subtracts it — see the ci.yml header enumeration.
	@$(MAKE) --no-print-directory rulefloor-check
	# fmt-check / vet / go build / go test are NOT missing: `repo-green` above
	# runs all four as ONE named floor (order F, THE-FLIPPED-CELLS). tagged-vet
	# stays because repo-green runs UNTAGGED and cannot see //go:build files.
	@$(MAKE) --no-print-directory image-base-check
	@$(MAKE) --no-print-directory vet-integration
	@$(MAKE) --no-print-directory doccomment-check
	@$(MAKE) --no-print-directory r-suite
	@$(MAKE) --no-print-directory image-base-parity
	@$(MAKE) --no-print-directory image-policy-restate-check
	@$(MAKE) --no-print-directory clock-fuse-report
	@$(MAKE) --no-print-directory clock-fuse-gate
	@$(MAKE) --no-print-directory tagged-vet
	@$(MAKE) --no-print-directory integration-inventory
	gograph capabilities --intention "repo-local make verify"
	gograph build . --precise
	# P3-9: the boundary policy finally EXISTS and is ENFORCED. boundaries.json
	# (committed at the repo root — .gograph/ is gitignored) was generated from
	# the import graph and is checked here, after the precise build, because the
	# CLI reads the persisted graph: a stale graph reports stale imports.
	# Red-proved: internal/crypto importing internal/api fails with
	# [boundary_violation]. Local-only like the other gograph lines; ci-verify
	# documents the omission.
	gograph boundaries --config boundaries.json
	go mod tidy -diff
	staticcheck ./...
	govulncheck ./...
	@$(MAKE) --no-print-directory wiki-fresh
	$(MAKE) grype-scan

## ci-verify: CI mirror of `make verify` MINUS the two gograph lines, MINUS
## govulncheck, and MINUS wiki-fresh. THREE omissions, all deliberate and all
## documented below; none is silent drift. (This lead sentence said "the two
## gograph lines and govulncheck ... Both omissions" until 2026-08-04 while a
## THIRD was spelled out twenty lines down — a count that did not match its own
## enumeration, agent-rules.md SS G-bis:313, in the file that lists the gates.)
##
## gograph stays a LOCAL-ONLY developer tool by decision (owner-distributed
## via the brew cask; CI does not install it), so its `capabilities` +
## `build` steps do not run here.
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
## real) and are EXCLUDED here, enumerated: repo-green, clock-fuse-gate,
## wiki-fresh. Nothing repo-green measures is lost in CI — its four floors
## (fmt, build, test, vet) are already explicit steps of this recipe.
## clock-fuse-gate's snapshot comparison IS lost in CI (recorded residue,
## ledger row REL-CI-WIKI-COUPLING); clock-fuse-report — self-contained, and
## hard-failing on tool error and the deadline arm — stays.
##
## Everything else is byte-identical to `verify`: image-base-check, go mod tidy
## -diff, go build, go test with the 120s timeout, staticcheck, and grype-scan.
## Keeping CI on this target instead of hand-rolled steps is what stops CI from
## drifting away from `verify`.
ci-verify:
	@$(MAKE) --no-print-directory tracked-binary-check
	@$(MAKE) --no-print-directory credential-transparency
	# THE-TOOLING-UPGRADE: CI runs the REAL rulefloor check. The homegrown
	# tools/rulefloorlite subset is DELETED — it reimplemented extraction
	# with pre-v0.3.0 string-marker semantics and measurably diverged from
	# the real extractor (a marker inside a Go string literal satisfied
	# lite and failed rulefloor v0.3.0), and it never verified hashes.
	# CI builds the binary from the pinned, checksum-verified release tarball
	# declared in ci.yml; locally RULEFLOOR_RESOLVE falls back to PATH/sibling.
	@$(MAKE) --no-print-directory rulefloor-check
	@$(MAKE) --no-print-directory image-base-check
	@$(MAKE) --no-print-directory fmt-check
	@$(MAKE) --no-print-directory vet
	@$(MAKE) --no-print-directory vet-integration
	@$(MAKE) --no-print-directory doccomment-check
	@$(MAKE) --no-print-directory r-suite
	@$(MAKE) --no-print-directory image-base-parity
	@$(MAKE) --no-print-directory image-policy-restate-check
	@$(MAKE) --no-print-directory clock-fuse-report
	@$(MAKE) --no-print-directory tagged-vet
	@$(MAKE) --no-print-directory integration-inventory
	go mod tidy -diff
	go build ./...
	# P2-17 (owner ruling): -race runs HERE, in CI's aggregate. It ran NOWHERE —
	# not verify, not ci-verify, zero occurrences in this Makefile — so "CI is
	# weaker than verify" was wrong twice: nothing had the race detector at all.
	# The timeout rises 120s -> 300s FOR THIS LINE ONLY because an instrumented
	# run is 2-10x slower. The plain 120s run lives in `verify` (via repo-green,
	# local-only since THE-CI-SHAPE); in CI this instrumented superset is the
	# test floor.
	go test ./... -count=1 -race -timeout=300s
	staticcheck ./...
	$(MAKE) grype-scan

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
## deliberate act: wiki/tools/clockfuse-gate.sh --snapshot . — never by hand.
clock-fuse-gate:
	@bash "$(WIKI_TOOLS)/clockfuse-gate.sh" --check .

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

## image-base-check: fail if any Dockerfile builds FROM an Alpine base.
##
## IMG-NONALPINE (owner decision 2026-07-31): every image WE build must be
## musl-free. The Postgres SERVICE image is EXEMPT — it lives in compose, never
## in a Dockerfile, so this scan never sees it and must not be widened until it
## does.
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

## grype-scan: Anchore Grype filesystem scan; fails on any High or Critical finding.
## Requires grype to be installed (https://github.com/anchore/grype).
## Runs both locally (via `verify`) AND in CI (via `ci-verify`) — CI installs a
## tag-pinned grype in .github/workflows/ci.yml before invoking this target.
grype-scan:
	grype dir:. --fail-on high

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
fast-up:
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
			run_bounded $$probe_t $(COMPOSE_CMD) -f $(COMPOSE_FILE) exec -T postgres-idp-oss pg_isready; \
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
fast-down:
	$(COMPOSE_CMD) -f $(COMPOSE_FILE) down

## fast-clean: stop containers AND remove the named volume (full reset).
## Use this to start with a fresh empty database. validate uses this automatically.
fast-clean:
	$(COMPOSE_CMD) -f $(COMPOSE_FILE) down --volumes

## dev-up: start the local IDP OSS app + Postgres stack (volumes preserved).
dev-up:
	$(COMPOSE_CMD) -f $(COMPOSE_FILE) --profile app up -d

## dev-rebuild: rebuild and force-recreate only the local IDP OSS app service.
dev-rebuild:
	$(COMPOSE_CMD) -f $(COMPOSE_FILE) --profile app up -d --build --force-recreate $(DEV_APP_SERVICE)

## dev-recreate-app: recover stale app container/network state without deleting Postgres data.
dev-recreate-app:
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
dev-down:
	$(COMPOSE_CMD) -f $(COMPOSE_FILE) --profile app down

## dev-seed: seed the RUNNING dev stack with known TEST credentials and print
## them (organization + org_admin + org_user + a confidential OAuth client).
## Requires a stack that is already up and MIGRATED. The credentials are
## public and documented — they are only ever valid in a disposable dev
## database, which is why the tool demands an explicit confirmation flag.
dev-seed:
	go run ./tools/devseed --issuer http://127.0.0.1:$(DEV_APP_PORT) \
		--container $(DEV_APP_CONTAINER) --i-know-this-is-a-dev-database

## dev-reset: DESTRUCTIVE one-command path to a known-good, seeded stack:
## drop the database volume, start Postgres, RECREATE the app so its
## entrypoint re-applies migrations, wait for health, then seed.
##
## The app recreate is not optional: migrations run from the app entrypoint at
## container start, so `fast-clean && dev-up` alone leaves a fresh volume with
## NO SCHEMA and the next command fails with `relation "users" does not exist`.
dev-reset:
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

## test: run all unit tests (excludes build-tagged integration tests).
test:
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
## e2e end-to-end tests PLUS the runtime, pkg/runtime and internal/postgres
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
## test-db: create + migrate the dedicated integration database
## (identuum_idp_oss_test on the dev Postgres), separate from the human's dev
## DB (TEST-DB-ISOLATION-1). Idempotent: CREATE DATABASE is skipped if it
## already exists, then migrations are (re-)applied. Never touches OSS_DB_URL.
test-db:
	@echo "test-db: ensuring $(OSS_TEST_DB_URL) exists + migrated"
	@PGPASSWORD=dev-idp_oss_user-not-a-secret psql -h 127.0.0.1 -p 5513 -U idp_oss_user -d postgres -tAc \
		"SELECT 1 FROM pg_database WHERE datname='identuum_idp_oss_test'" | grep -q 1 || \
		PGPASSWORD=dev-idp_oss_user-not-a-secret createdb -h 127.0.0.1 -p 5513 -U idp_oss_user identuum_idp_oss_test
	@$(MAKE) --no-print-directory build-binary
	@./bin/identuum-idp migrate "$(OSS_TEST_DB_URL)"

ci-integration-test:
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
rulefloor-integration:
	@$(RULEFLOOR_RESOLVE); \
	IDENTUUM_IDP_TEST_DATABASE_URL="$${IDENTUUM_IDP_TEST_DATABASE_URL:-$(OSS_TEST_DB_URL)}" \
		"$$RF" check --run-profile integration --tags integration

## validate: build + unit tests + staticcheck + integration build/test.
## Starts from a clean database (fast-clean removes stale volume data before run).
validate: build test staticcheck
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
##   Image: identuum-idp-oss:local
##   Source: deployment/Dockerfile.local (multi-stage golang:1.26.5-bookworm builder + debian:bookworm-slim runtime).
##   DB URLs are never echoed (compose env handles the URL inside the container).
oss-build:
	$(COMPOSE_CMD) -f $(COMPOSE_FILE) --profile app build --build-arg COMMIT=$(COMMIT) app

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
oss-up: oss-build
	$(COMPOSE_CMD) -f $(COMPOSE_FILE) --profile app up -d
	@echo "OSS app container starting on 127.0.0.1:7113 (Postgres on 127.0.0.1:5513)"
	@echo "Smoke probes:"
	@echo "  curl -s http://127.0.0.1:7113/system/info"
	@echo "  curl -i http://127.0.0.1:7113/api/v1/organizations"
	@echo "  curl -i http://127.0.0.1:7113/api/v1/organizations/00000000-0000-7000-0000-000000000000/protocol-settings"

## oss-down: stop the OSS app container (Postgres preserved so the
## next `oss-up` is fast).
oss-down:
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
##   The bootstrap binary runs identuum-idp bootstrap "$$IDENTUUM_IDP_OSS_DB"
##   inside the existing identuum-idp-oss container. The container
##   keeps serving HTTP — this is a side-channel one-shot.
oss-bootstrap:
	@if [ -z "$$IDENTUUM_IDP_BOOTSTRAP_PASSWORD" ]; then \
		echo "ERROR: IDENTUUM_IDP_BOOTSTRAP_PASSWORD is not set in the caller's environment."; \
		echo "       Set it before running make oss-bootstrap (it is never echoed)."; \
		exit 2; \
	fi
	@$(COMPOSE_CMD) -f $(COMPOSE_FILE) --profile app exec \
		-e IDENTUUM_IDP_BOOTSTRAP_PASSWORD \
		-e IDENTUUM_IDP_BOOTSTRAP_EMAIL \
		-e IDENTUUM_IDP_BOOTSTRAP_ALGORITHM \
		app sh -c '/app/identuum-idp bootstrap "$$IDENTUUM_IDP_OSS_DB"'

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
	@# not found, make exit 127 (RECOVERY-BINARY-PATH-1). recover-site-admin
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
