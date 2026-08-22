# Rule-ledger conventions — identuum policy (both repos)

This is the CANONICAL conventions document for how the identuum
repositories use the `rulefloor` tool. It covers `identuum-idp-oss` and
`identuum-ui`; the UI repo carries a pointer here. The tool's own README
documents MECHANISM (ledger format, commands, exit codes, guarantees,
honest limits) and deliberately knows nothing about this project; what a
profile name means HERE, what a proof must say HERE, and how debt is
burned down HERE is THIS project's policy, recorded in this file.
Standing contract and history: `wiki/contracts/rule-floor-posture.md`
(operating contract) and `wiki/contracts/rule-census.md` (per-rule
disposition).

## (a) Profile vocabulary — what each name means in THIS project

A profile name is opaque to the tool. Which test kinds the tool can
statically validate or execute is the TOOL's fact, not this document's:
discover it with `rulefloor capabilities --json` (per-kind
`static_validation` / `execution` flags) instead of trusting any list
written here. Everything below is identuum's own vocabulary, measured
from the ledgers.

### identuum-idp-oss (go-test rows)

| Profile | Meaning HERE | Runs in |
|---|---|---|
| `unit` | Hermetic Go test — no DB, no network, no env precondition. | Executed on every plain check: `make verify` → `make rulefloor-check`. |
| `integration` | DB-backed teeth (the AdminPermissionsModel triggers RG1–RG4 and the client-auth-boundary trio) needing live Postgres; `t.Skip` guards allowed in the body, but a runtime skip under the profile run is CANNOT-EVALUATE. | Static in plain `verify`; EXECUTED by `make rulefloor-integration` (`check --run-profile integration --tags integration`), chained by `make integration-test`, reached on a fresh database by `make validate`. |

### identuum-ui (playwright + vitest rows)

All playwright rows are static-only under `pnpm rulefloor`; enforcement of
their runtime truth is the named run itself (conditional and
describe-level skips are invisible to the static check — see the tool's
honest limits).

| Profile | Meaning HERE | Runs in |
|---|---|---|
| `chromium` | Unconditional spec — needs only `next dev` (port 7104), no auth, no appliance. | Default Playwright project: `pnpm exec playwright test <spec> --project=chromium`. |
| `e2e-run` | Auth-gated spec (body-level env skips) against the standing e2e appliance (IdP :7113) plus the fixture envelope `e2e/.auth/e2e-org-admin-fixture.json`. NOTE, measured (PROOF-BURNDOWN-3): WIZARD-1 and PIN-CHIP-1 carry this profile but actually run on the dedicated fresh disposable stack `pnpm e2e:oss-wizard-ui` (there is NO `oss-wizard` profile in the ledger); and SA-ORG-COPY-1 carries this profile while its spec self-documents needing dynamic-seeded state — recorded label drift, disposition open. | Playwright against the standing stack; wizard rows via `pnpm e2e:oss-wizard-ui`. |
| `e2e-dynamic` | Needs per-run seeded fixtures: `IDENTUUM_E2E_USE_DYNAMIC_FIXTURE=true` brings up a fresh disposable appliance and spawns its own `next dev` on :7104 (the port must be free — Next.js 16 refuses a second dev server per repo dir). Its globalTeardown tears the appliance down and deletes the fixture envelope. | Playwright in dynamic-fixture mode. |
| `e2e-destructive` | Mutates appliance state (e.g. an MFA reset). Run ONLY against disposable state, never the standing appliance/fixture. | Named destructive run, last. |
| `oss-change-password-run` | Env-gated named run (`IDENTUUM_E2E_OSS_CHANGE_PASSWORD=1` plus a disposable mfa-disabled test user). | Its named run (no runner script exists on this box — measured CANNOT-RUN in PROOF-BURNDOWN-3). |
| `ce-smoke-run`, `ce-m1-run` | CE appliance stacks (:7123–:7126) via `pnpm e2e:ce-customer-smoke` / `pnpm e2e:ce-fresh-m1-setup`, gated on operator-marked readiness envs. | The CE named runs. |
| `vitest` | `*.test.ts` source-invariant row: pinned (tag + hash + no skip) but never executed by `check`; the vitest suite runs in the repo's own CI gate. | `pnpm test` / CI. |

## (b) Red-proof text format — what we actually write

Every proof cell records a genuinely WATCHED failure, in one line (the
tool refuses `|` and newlines in cells), shaped as:

    <ISO date> mutated <product file or migration>: <exact mutation>;
    <test/rule id> FAIL '<observed failing assertion or message>';
    restored byte-identical, green

Dated. Names the mutation (product, never the test). Names the observed
failure (quote the assertion line or error). States the byte-identical
restore. When defense-in-depth escalation was needed, the proof records
the layer count (e.g. "broke only when BOTH layers neutralized").

Two real cells, quoted verbatim from the ledgers:

> `SOFTDEL-RESOLVE-1` (identuum-idp-oss): *2026-08-18 mutated
> GetClientByClientID query: client tombstone predicate 'oc.deleted_at IS
> NULL' -> TRUE; TestSoftDeletedClientDoesNotResolve FAIL 'a soft-deleted
> client RESOLVED at auth time'; source restored byte-identical, green*

> `ROLE-ORGUSER-FENCE-1` (identuum-ui): *2026-08-19 mutated
> src/app/org-admin/layout.tsx: role!==org_admin redirect guard
> neutralized to if(false); ROLE-ORGUSER-FENCE-1 FAIL 'org_user must not
> remain on /org-admin, Received /org-admin'; restored byte-identical,
> green (independently re-watched)*

## (c) Burndown method, escalation, dispositions

**The method, per row, no exceptions:**

1. BASELINE: the row's test runs green unmutated (in its profile's run).
2. Mutate the PRODUCT until the rule sentence is false — guards
   neutralized (`false &&` / `true ||`), predicates flipped, constants or
   redirect targets changed, forbidden strings injected, confirm gates
   dropped. NEVER the test.
3. WATCH the tagged test FAIL; capture the failing assertion.
4. Restore byte-identical; prove it (`git diff --quiet` over the product
   paths); re-run green.
5. Record the dated proof via `rulefloor prove` in the same session
   (`unproved` is the debt list that catches a missed record).

**Defense-in-depth escalation:** if a single layer's mutation does not
falsify the sentence, neutralize EVERY enforcing layer at once and record
the layer count in the proof (measured examples: TRIO-USER-1 took three
layers; USER-PW-REQUIRED-1 and USER-ORG-1 two; ORG-LIFECYCLE-1 three).

**VACUOUS:** only if the test still passes with every enforcing layer
neutralized. That is a test defect: fix the test so it bites, re-prove,
and record the finding in the slice's wiki row (measured example:
SA-ORG-COPY-1, the miss that created the ratchet).

**CANNOT-RUN:** if a row's profile genuinely cannot run on the box, STOP
that row — leave it unproved (`-` stays `-`; a proof text is NEVER
backfilled), and record the MEASURED reason in the slice's wiki ledger
row. The 8 standing UI remainders and their reasons are recorded in the
PROOF-BURNDOWN-3 row of `wiki/contracts/to-do-queue.MD`.

## (d) Tool gaps: reported, never built here

rulefloor is a layer below this project (owner ruling, THE-TOOL-BOUNDARY
/ THE-PROJECT-CONVENTIONS). When work in these repos hits a tool
limitation, the gap is REPORTED — in the slice's final report and, when
standing, in the wiki posture page — and never fixed from here. Tool
changes happen only in the tool's own repo, under its own slice, with the
owner's ruling.
