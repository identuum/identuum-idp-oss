# TEST-spec — compliance status

The owner's requirements spec for the testing infrastructure is
`TEST-spec.MD` at the repo root — the owner's draft, deliberately untracked
(gitignored); the owner writes it, nobody else. This file tracks how far the
infrastructure actually meets it, and records what is deliberately deferred so
no gap is silent. Pattern borrowed from AdminPermissionsModel.md vs its
compliance doc: requirements in the owner's file, measured state here.

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
| Per-role coverage of ALL functionality (site_admin / org_admin / org_user) | PARTIAL — **now MEASURED (T3, 2026-08-30): 144 of 399 (endpoint × role) cells covered** — site_admin 66, org_admin 68, org_user 10 — within the census window (the API-driving harness phases; the dev-loop suite and browser flows sit outside it, stated honestly). The matrix is committed and machine-enforced every run (identuum-ui `e2e-full/role-matrix.json`, ROLE-MATRIX-1, ui FLOOR 62): drift fails, the floor holds, growth is a deliberate commit. T4.. closes the uncovered cells, org_user negatives first. |
| First-time installation (complete reset) | COVERED — the fresh-appliance phase + single bootstrap path, every run. |
| Admin reset without customer data loss | PARTIAL — `recover-site-admin` exists and MFA/org_admin recovery are spec-covered; the populated-appliance end-to-end scenario (reset + tenant data proven intact) is planned (T-R2a). |
| Backup / restore | **DEFERRED (owner, 2026-08-30)** — no product backup/restore procedure exists to test (only the encryption-key-rotation ceremony embeds a backup step). Deferred until the owner rules the product story: documented pg_dump/volume ceremony vs `backup`/`restore` CLI subcommands. A test cannot precede the procedure it proves. |
| Traceless, own environment | MET — dedicated compose project, volumes destroyed before and after. The witnessed run records (gitignored GATE-RUN artifacts) persist deliberately as evidence, not residue. |
| Two-tier documentation (technical + operator) | PARTIAL — technical detail lives in the wiki; the operator-level guide is planned (T-R4). |
| No skips unless absolutely necessary | PARTIAL — 22 skips, every one a named environment gate under a fail-on-raise ceiling. **CE-gated skips are ruled NECESSARY (owner, 2026-08-30)** while identuum-idp-ce remains off-limits for testing; the non-CE skips get a one-by-one review inside the census. |

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
