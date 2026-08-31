# TEST-spec — compliance status

The owner's requirements spec for the testing infrastructure is
`TEST-spec.MD` at the repo root — the owner's draft, deliberately untracked
(gitignored); the owner writes it, nobody else. This file tracks how far the
infrastructure actually meets it, and records what is deliberately deferred so
no gap is silent. Pattern borrowed from AdminPermissionsModel.md vs its
compliance doc: requirements in the owner's file, measured state here.

**STATUS: DONE (owner ruling, 2026-08-31).** With backup/restore deferred by
the owner's explicit decision (the one named deferral below), the owner has
declared the TEST-spec testing infrastructure COMPLETE: per-role coverage at
100% of the ruled denominator (294/294 cells, floor-enforced), first-time
install / complete reset / admin-reset scenarios witnessed every run,
traceless-by-construction, two-tier documentation shipped, and every one of
the 22 remaining skips reviewed and classified necessary under a
fail-on-raise ceiling. The deferral row stays below so the gap remains
visible, never silent.

Measured baseline (2026-08-30, detail in
`wiki/platform/disposable-harness.md`): the disposable harness
(`identuum-ui: make e2e-full`) stands a fresh appliance, runs 8 witnessed
phases, and tears down — 133/133 API endpoints exercised, 51/53 UI routes
content-reached (the 2 dark are the CE pair), site_admin refused on all 45
tenant-resource verbs, 22 skips each a named environment gate under a
ceiling, floors enforced (coverage 51, static-rows 24, skip 22, rulefloor
173/61).

## Requirement status

| Spec requirement | Status |
|---|---|
| Per-role coverage of ALL functionality (site_admin / org_admin / org_user) | **COVERED under THE SMARTER COUNTER (owner ruling 2026-08-31): 294 of 294 cells — 100%.** Every role-class endpoint exercised as all three principals (88 × 3 = 264), every public/M2M endpoint exercised (30 "@ any" class cells), the 15 browser-cookie session endpoints EXCLUDED BY NAME (covered by the dev-loop suite + UI floor). Refusal batteries [ROW 200/201/202] pin both directions of the model; [ROW 203] closed the remainder with safe probes, pinning three measured contracts on the way (org_user mfa-disable refuses 401; empty org update is a PROVEN 200 no-op; anonymous claim answers the anti-enumeration 200). The floor at 294 means ANY lost coverage fails the harness; the denominator tracks the docgen golden, and a golden change reads DENOMINATOR DRIFT until the matrix is re-derived deliberately. Honest limit unchanged: a covered cell is EXERCISED-in-a-passing-run; assertion depth lives in the suites themselves. |
| First-time installation (complete reset) | COVERED — the fresh-appliance phase + single bootstrap path, every run. |
| Admin reset without customer data loss | **COVERED (T-R2a, 2026-08-30)** — a witnessed LAST harness phase runs `recover-site-admin` on the populated appliance: old password refused, new password through first-login enrolment to working site_admin authority, every seeded tenant resource proven to survive by id, tenant logins unaffected. One product finding measured and pinned: pre-reset site_admin SESSIONS survive the reset (nothing revokes them) — recorded as RECOVER-REVOKE in the wiki queue; the pin flips when the product starts revoking. |
| Backup / restore | **DEFERRED (owner, re-affirmed 2026-08-31)** — the one open TEST-spec item, by the owner's ruling, with the ground now fully measured: the upgrade wizard's backup automation ("Create backup writes a real file") is served by **idp-ce** (5 `/api/upgrade/*` routes; idp-oss serves none), so extending it directly is CE work the standing off-limits rule forbids; meanwhile idp-oss already ships the shared `OrgBackup` domain format (envelope/cipher/KDF, design-doc §8.1) with **zero OSS consumers** — an OSS-native driver (e.g. `backup`/`restore` CLI beside bootstrap/recover-site-admin, format-compatible with the CE upgrade path) is the ready option when the owner rules. Options on the table: OSS-native driver / named CE authorization / documented pg_dump ceremony. A test cannot precede the procedure it proves; the witnessed round-trip harness phase lands with whichever procedure is chosen. |
| Traceless, own environment | MET — dedicated compose project, volumes destroyed before and after. The witnessed run records (gitignored GATE-RUN artifacts) persist deliberately as evidence, not residue. |
| Two-tier documentation (technical + operator) | **COVERED (T-R4, 2026-08-30)** — technical tier: [`TESTING.md`](TESTING.md) (layers, phases, floors, evidence chain, honest limits); operator tier: [`TESTING-OPERATORS.md`](TESTING-OPERATORS.md) (one command, how to read green/red, what to do on red, what is not covered, the no-trace promise). Deep harness internals remain in the wiki. Docs grow with the infrastructure — "complete" tracks the phases that exist. |
| No skips unless absolutely necessary | **REVIEWED (2026-08-31)** — all 22 dev-loop skips enumerated from the run's own report and classified; every one keeps the "absolutely necessary" label under standing rules: **8 CE-gated** (license/CE-setup specs — necessary while idp-ce is off-limits, owner-ruled), **3 AG-profile** (platform-status AG rows — different product, out of scope), **7 setup-window** (fresh-appliance/wizard/first-enrolment specs that can only run on a pre-setup appliance; the harness deliberately has exactly ONE setup path, and these specs DO run — in the fresh-appliance phase and the e2e-run rulefloor profile — so the dev-loop skip is a phase-placement fact, not lost coverage), **4 upgrade-live** (the upgrade wizard + its backup automation need the upgrade appliance environment, not yet a harness phase — NOTE for the backup/restore ruling: the upgrade path already ships backup automation to build on). The ceiling (22) fails the harness if any new skip appears. |

## The approved plan (owner, 2026-08-30)

T2 harness-anchor → T3 role-census (the (functionality × role) matrix becomes
a machine-checked floor) → T4.. close the uncovered cells (org_user negatives
first) → T-R2a admin-reset scenario → T-R4 two-tier docs. Existing
bash/node/Go tooling alongside Playwright is grandfathered; any NEW tool
needs owner sign-off first, per the spec's own clause.

**T2 status — anchored entry point LANDED; physical relocation DEFERRED with
a measured reason.** `make test-full` in THIS repo now runs the whole suite
(sibling-checkout guard → the canonical runner → an independent
gate-witness verification of the minted record, so a delegated run that lies
about its result still fails). The orchestrator BODY stays in
`identuum-ui/e2e-full/scripts/full-run.sh`: four ui source-invariant tests
(static-rows, ui-provisioner, skip-ceiling, coverage-floor) pin that script's
content and run in ui's single-checkout CI — relocating the file breaks four
CI invariants, so the move waits until those pins migrate with it (its own
slice, if ever worth it).
