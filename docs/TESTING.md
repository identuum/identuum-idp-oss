# Testing infrastructure — technical reference

The requirements this infrastructure answers to live in the owner's spec
(`TEST-spec.MD`, untracked at the repo root); measured compliance and the
recorded deferrals live in [`TEST-spec-status.md`](TEST-spec-status.md).
This file is the technical tier of the spec's two-tier documentation
requirement: what runs, where it lives, what every floor means, and how the
evidence chain works. The operator tier is
[`TESTING-OPERATORS.md`](TESTING-OPERATORS.md).

## The three layers

1. **`make verify` (this repo)** — the per-commit gate: build, unit tests,
   staticcheck, govulncheck, grype, rulefloor ledger check (FLOOR 173),
   image-base policy, docgen golden, and the rest of the witnessed target
   list. Writes `GATE-RUN.txt` (committed) via `scripts/gate-witness.sh`:
   per-target exits, tool versions, evidence lines, and a digest of the tree
   the run saw. `identuum-ui` has the same shape (`make verify`, FLOOR 62).
2. **`make integration-test` (this repo)** — build-tagged suites against a
   dedicated `*_test` database (`TEST-DB-ISOLATION-1` refuses any other DSN).
3. **`make test-full` (this repo)** — the full-behavior disposable harness,
   anchored here (T2): a sibling-checkout guard, delegation to the canonical
   runner (`identuum-ui/e2e-full/scripts/full-run.sh` — its body stays there
   because four ui source-invariant tests pin its content in ui's
   single-checkout CI), then an independent `gate-witness check` of the
   minted record, so a delegated run that lies about its result still fails.

## What one `make test-full` run does

Stands a FRESH appliance (`down --volumes`, rebuild from this working tree,
`INSECURE_DEV_MODE` = rate limits off, nothing else), bootstraps site_admin
with a run-local password (never printed), then runs 10 witnessed phases,
serially (`--workers=1`, TOTP physics):

| Phase | What it proves |
|---|---|
| fresh-appliance | first-run window: `/` and `/setup` in `setup_required` state |
| api-suite | the census suites (auth, consent, CRUD, organizations, tokens, delete-cascade) |
| provisioner | seeds the tenant fixture: org, org_admin, org_user, OAuth clients, api-resource |
| static-rows-sweep | 25 committed `[ROW n]` assertions incl. the two per-verb refusal batteries ([ROW 200] site_admin, [ROW 201] org_user — one shared 45-verb builder) |
| static-rows | enforcement: the passed row set must EQUAL the committed set (floor 25) |
| role-matrix | the (endpoint, role) census: every `api()` call's (method, path, role-from-bearer-claims, status) observation, collapsed against the docgen endpoint golden and enforced against the committed matrix (189 of 399 cells; drift/floor/denominator all fail) |
| devloop-provisioned | the browser suite (chromium) against the provisioned appliance |
| skip-ceiling | devloop skips must not exceed the committed ceiling (22, every one a named environment gate) |
| coverage | UI route coverage derived from the run's own traces (floor 51 of 53; the 2 dark are the CE pair) |
| admin-reset | LAST, destructive: `recover-site-admin` on the populated appliance — old password refused, new password through first-login enrolment to working authority, tenant data surviving by id (TEST-spec R2) |

Teardown destroys the appliance and its volume before AND after. The record
(`GATE-RUN.e2e-full.txt`, gitignored in identuum-ui) is minted as the LAST
act of a slice close, post-commit at clean HEAD; the wiki check's
`witness-ui-e2e` gate fails a present-but-stale record (absent = no claim).

## The floors (all fail-on-regression, all derived from the run's own output)

| Floor | Value | Enforced by |
|---|---|---|
| rulefloor (this repo) | 173 armed rules | `make verify` → `rulefloor check` |
| rulefloor (identuum-ui) | 62 armed rules, 59 red-proofs | ui `make verify` |
| static rows | 25 committed rows, set-equality | `static-rows-from-run.mjs` |
| (endpoint, role) matrix | 189 of 399 cells | `role-matrix-from-run.mjs` |
| UI route coverage | 51 of 53 | `coverage-from-run.mjs` |
| devloop skip ceiling | ≤ 22 | `skip-ceiling-from-run.mjs` |

Growing a floor is a deliberate commit (the census bootstraps from a run's
observations, never hand-marked); lowering one is the regression the gates
exist to catch.

## Roles, the census window, and honest limits

The matrix's denominator is the docgen endpoint golden (133 endpoints) ×
{site_admin, org_admin, org_user}. A covered cell means the pair was
EXERCISED inside a passing witnessed phase — assertion quality is not
mechanically knowable, and browser-cookie traffic doesn't pass through
`api()`; the census window is the API-driving phases (fresh-appliance
through static-rows). UI-side coverage has its own floor. Uncovered today:
210 cells, closed in tranches (see TEST-spec-status.md).

## Tooling

Playwright drives both API and browser suites; bash orchestrates; node
scripts derive-and-enforce the floors; Go tests cover the backend
(grandfathered set per the spec — any NEW tool needs owner sign-off first).
Findings the harness measures but does not fix are recorded in the wiki
repo page's Open items (currently AUTH-503, RECOVER-REVOKE) with pins that
flip red when the product changes.
