# Testing infrastructure — technical reference

The requirements this infrastructure answers to live in the owner's spec
(`TEST-spec.MD`, untracked at the repo root); measured compliance and the
recorded deferrals live in [`TEST-spec-status.md`](TEST-spec-status.md).
This file is the technical tier of the spec's two-tier documentation
requirement: what runs, where it lives, what every floor means, and how the
evidence chain works. The operator tier is
[`TESTING-OPERATORS.md`](TESTING-OPERATORS.md).

## The layers

1. **`make verify` (this repo)** — the per-commit gate: build, unit tests,
   staticcheck, govulncheck, grype, rulefloor ledger check (FLOOR 253 on
   2026-09-06 — the first line of RULE-FLOOR.md is the live number),
   the IMG-NONALPINE gate, docgen golden, and the rest of the witnessed
   target list. Writes `GATE-RUN.txt` (committed) via `scripts/gate-witness.sh`:
   per-target exits, tool versions, evidence lines, and a digest of the tree
   the run saw. `identuum-ui` has the same shape (`make verify`, FLOOR 66).
2. **`make integration-test` (this repo)** — build-tagged suites against a
   dedicated `*_test` database (`TEST-DB-ISOLATION-1` refuses any other DSN).
3. **The by-hand stack targets (this repo)** — not a gate, but the same
   machinery an operator drives manually, kept honest because the harness
   uses the same compose file and entrypoint: `oss-fresh` (destroy → up →
   bootstrap → print where to sign in; refuses without
   `I_UNDERSTAND_THIS_DESTROYS_ALL_DATA=1`), `oss-up` / `fast-down` /
   `fast-clean` (all `--profile app`, so the profiled app container never
   survives a teardown), `oss-bootstrap` and `oss-recover-site-admin` (exec
   the binary DIRECTLY — the runtime image is distroless, so `sh -c` cannot
   work), and `oss-setup-code` (prints the first-run code from the
   container's own `/app/data`; no volume mount is required or made). See
   [`TESTING-OPERATORS.md`](TESTING-OPERATORS.md) "Running it by hand".
4. **`make test-full` (this repo)** — the full-behavior disposable harness,
   anchored here (T2): a sibling-checkout guard, delegation to the canonical
   runner (`identuum-ui/e2e-full/scripts/full-run.sh` — its body stays there
   because four ui source-invariant tests pin its content in ui's
   single-checkout CI), then an independent `gate-witness check` of the
   minted record, so a delegated run that lies about its result still fails.

## What one `make test-full` run does

Stands a FRESH appliance (`down --volumes`, rebuild from this working tree,
`INSECURE_DEV_MODE` = rate limits off, nothing else), bootstraps site_admin
with a run-local password (never printed), then runs 14 witnessed phases,
serially — `--workers=1` everywhere. (Measured 2026-09-04 in identuum-ui:
what serial protects is shared fixture state; the earlier "TOTP physics"
rationale was false, both login paths do a plain RFC 6238 window match.)

| Phase | What it proves |
|---|---|
| fresh-appliance | first-run window: `/` and `/setup` in `setup_required` state |
| api-suite | the census suites (auth, consent, CRUD, organizations, tokens, delete-cascade) |
| provisioner | seeds the tenant fixture: org, org_admin, org_user, OAuth clients, api-resource |
| static-rows-sweep | 27 committed `[ROW n]` assertions incl. the two per-verb refusal batteries ([ROW 200] site_admin, [ROW 201] org_user — one shared 45-verb builder) |
| static-rows | enforcement: the passed row set must EQUAL the committed set (floor 27) |
| role-matrix | the (endpoint, role) census: every `api()` call's (method, path, role-from-bearer-claims, status) observation, collapsed against the docgen endpoint golden and enforced against the committed matrix (312 committed cells, floor 297; drift/floor/denominator all fail) |
| verify-record-ui | refuses to mint over a stale ui `make verify` record (gate-witness check against the ui tree) |
| verify-record-idp-oss | the same for this repo's `GATE-RUN.txt` |
| devloop-provisioned | the browser suite (chromium) against the provisioned appliance |
| skip-ceiling | devloop skips must not exceed the committed ceiling (22, every one a named environment gate) |
| coverage | UI route coverage derived from the run's own traces (floor 52 of 54; the 2 dark are the CE pair) |
| closure | outside-matrix closure: session and class endpoints accounted for |
| admin-reset | destructive: `recover-site-admin` on the populated appliance — old password refused, new password through first-login enrolment to working authority, tenant data surviving by id (TEST-spec R2) |
| auth503-scan | LAST: store errors the appliance logged and answered as 503 (AUTH-503) are scanned, never swallowed |

Teardown destroys the appliance and its volume before AND after. The record
(`GATE-RUN.e2e-full.txt`, gitignored in identuum-ui) is minted as the LAST
act of a slice close, post-commit at clean HEAD; the wiki check's
`witness-ui-e2e` gate fails a present-but-stale record (absent = no claim).

## The floors (all fail-on-regression, all derived from the run's own output)

| Floor | Value | Enforced by |
|---|---|---|
| rulefloor (this repo) | 253 armed rules, 253 red-proofs (2026-09-06) | `make verify` → `rulefloor check` |
| rulefloor (identuum-ui) | 66 armed rules, 63 red-proofs | ui `make verify` |
| static rows | 27 committed rows, set-equality | `static-rows-from-run.mjs` |
| (endpoint, role) matrix | 312 committed cells (94 role-endpoints × 3 + 30 class cells), floor 297, all 312 observed in the last mint | `role-matrix-from-run.mjs` |
| UI route coverage | 52 of 54 (the 2 dark are the CE pair) | `coverage-from-run.mjs` |
| devloop skip ceiling | ≤ 22 | `skip-ceiling-from-run.mjs` |

(Numbers re-measured 2026-09-06 from the last mint's `GATE-RUN.e2e-full.txt`
evidence lines and the two `RULE-FLOOR.md` headers; they move with the floors,
and the records are the source, not this table.)

Growing a floor is a deliberate commit (the census bootstraps from a run's
observations, never hand-marked); lowering one is the regression the gates
exist to catch.

## Roles, the census window, and honest limits

The matrix's denominator is the docgen endpoint golden (144 endpoints,
`CanonicalEndpointCount`) × {site_admin, org_admin, org_user}. A covered cell
means the pair was EXERCISED inside a passing witnessed phase — assertion
quality is not mechanically knowable, and browser-cookie traffic doesn't pass
through `api()`; the census window is the API-driving phases (fresh-appliance
through static-rows). UI-side coverage has its own floor. Uncovered today:
none of the 312 committed cells (all observed in the last mint, 2026-09-05);
the committed set grew in tranches (see TEST-spec-status.md).

## Tooling

Playwright drives both API and browser suites; bash orchestrates; node
scripts derive-and-enforce the floors; Go tests cover the backend
(grandfathered set per the spec — any NEW tool needs owner sign-off first).
Findings the harness measures but does not fix are recorded in the wiki
repo page's Open items (currently AUTH-503, RECOVER-REVOKE) with pins that
flip red when the product changes.
