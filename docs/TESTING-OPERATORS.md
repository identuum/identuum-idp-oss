# Running the test suite — operator guide

This guide is for operators who want to check that the software works,
without needing to know how the tests are built. The technical companion is
[`TESTING.md`](TESTING.md).

## What the suite is

One command builds the software from this checkout, starts a complete
throwaway installation (its own database, its own containers — nothing
shared with anything you run), and exercises it the way real users would:
first-time setup, logging in as every kind of user (site administrator,
organization administrator, regular user), creating and managing
organizations, users, applications and settings, checking that every kind
of user is REFUSED the things they must not do, and finally resetting the
site administrator's password to prove customer data survives an admin
recovery. When it finishes, the throwaway installation is destroyed —
nothing is left behind, and nothing you have is touched.

## What you need

- Docker (running)
- This repository checked out next to its sibling `identuum-ui`
  (the folder layout: `identuum/identuum-idp-oss` and `identuum/identuum-ui`)
- `pnpm` installed in `identuum-ui` (`pnpm install` once)

## Run it

```bash
cd identuum-idp-oss
make test-full
```

It takes about 10 minutes and prints its progress phase by phase. All
passwords the run needs are generated fresh for that run and never shown.

## Reading the result

- **Green** — the run ends with lines like `gate-witness OK: … green on the
  tree it claims` and the command exits successfully. Everything the suite
  covers passed, including the safety floors (if a test quietly disappeared
  or coverage dropped, the run would FAIL — silence cannot hide a
  regression).
- **Red** — the command exits with an error and names the failing phase
  (for example `check OK: api-suite … failed=1` followed by the failing
  test's name and details). What to do:
  1. Run it once more. One known class of rare, transient failures exists
     (a session rejected mid-run under heavy load); a genuine bug fails
     both runs the same way.
  2. If it fails twice, save the printed output (and the
     `identuum-ui/GATE-RUN.e2e-full.txt` file, which records exactly what
     ran and what it saw) and report it. That file plus the printed failure
     is everything a developer needs to start.

## Running it by hand

Sometimes you do not want the whole suite — you want a working local stack to
click around in. Every step below is a `make` target run from
`identuum-idp-oss`; none of it needs a hand-written `docker` command.

**The whole thing, one command** (destroys the local dev database, so it asks
you to say so explicitly):

```bash
IDENTUUM_IDP_BOOTSTRAP_PASSWORD='<choose-a-strong-local-password>' \
  make oss-fresh I_UNDERSTAND_THIS_DESTROYS_ALL_DATA=1
```

That destroys the old stack, builds and starts the appliance, waits for it to
answer, and creates the site administrator. Without the opt-in it refuses and
lists exactly what it would remove.

It starts the **backend only**. The UI is a separate process, so when the run
finishes it probes port 7104 and tells you which situation you are in: if the
UI is already running it prints the sign-in URL; if it is not — the normal
case — it says so and gives you the command to start it, instead of pointing
you at a page that would not load.

**Or step by step:**

```bash
make fast-clean        # destroy: containers AND the Postgres volume (all data)
make oss-up            # build + start the appliance on 127.0.0.1:7113
make oss-bootstrap     # create site_admin (needs IDENTUUM_IDP_BOOTSTRAP_PASSWORD)
make oss-logs          # follow the app log (Ctrl-C detaches)
make fast-down         # stop + remove containers, KEEP the database
```

`make oss-bootstrap` needs the password in your environment; it is never
printed:

```bash
IDENTUUM_IDP_BOOTSTRAP_PASSWORD='<password>' make oss-bootstrap
```

### The two ways to create the first administrator — pick ONE

They are **mutually exclusive**. Both create the site administrator; whichever
runs first wins, and the other then refuses.

| | Bootstrap (CLI) | Wizard (browser) |
|---|---|---|
| How | `make oss-bootstrap` | open `/setup`, paste the setup code |
| Code needed | no | yes — `make oss-setup-code` prints it |
| After it runs | `/setup` reports setup already complete | `make oss-bootstrap` reports the same |

If you want the wizard, start the stack (`make fast-clean && make oss-up`) and
do **not** bootstrap. Then:

```bash
make oss-setup-code    # prints the first-run setup code
```

Treat that code like a password: it authorises the wizard. It is also printed
in the boot log. It is regenerated whenever the app container is recreated, so
read it after starting the container you intend to set up. Once setup is
complete the command tells you so and stops — it never prints a stale code.

### The URLs — and two that look alike but are not

Two processes, two ports. **The make targets in this repo start the backend
only** — nothing here ever starts the UI, so every `7104` address below is
dark until you start that process yourself. If a 7104 link does not load,
that is the first thing to check.

- **`http://localhost:7113`** — the IdP itself (health, OIDC discovery, API).
  Started by `make oss-up` / `make oss-fresh`.
- **`http://localhost:7104`** — the UI. **Not 3000.** The dev server is pinned
  to 7104 (`next dev --port 7104`). Start it yourself, in its own terminal:
  `cd ../identuum-ui && pnpm dev`. The docker install path serves the UI on
  the same port.
- **`http://localhost:7104/setup`** — the IdP's first-run wizard: enter the
  setup code, create the first organization and site administrator.
- **`http://localhost:7104/setup-required`** — a *different* page with a
  similar name. It means the **UI's own runtime configuration file is
  missing** (the UI does not know where the IdP is), not that the IdP needs
  setting up. Its fix is the UI's one-shot config helper, not the wizard. If
  you land here, no amount of setup-code pasting will help.

## The pre-upgrade audit (`audit-preupgrade`)

Recent releases moved a set of validation rules from the database into the
service. New writes are guarded on every path; rows written by an OLDER
binary can still hold shapes the new guards refuse. For three entities the
guard validates the **whole document on update**, so one bad stored field
makes **any** update to that row fail — the operator discovers it when an
unrelated rename starts answering 400.

**When to run it:** against your production database, with the OLD binary
still serving, BEFORE deploying an upgrade. It is strictly read-only — every
statement it issues is a `SELECT`, pinned by rule `AUDIT-PREUPGRADE-1`.

```
identuum-idp audit-preupgrade <database-url>
```

**Exit codes:**

- `0` — clean. No stored row matches a shape the guards refuse. Upgrade.
- `1` — findings. The output lists each shape with a count and the rule ID
  that refuses it. Fix the rows first (below), then re-run until clean.
- `2` — the audit could not run (bad URL, unreachable database). This is
  **not** clean; do not treat it as a pass.

**What a hit means, per severity:**

- `CRITICAL` (clients, api-resources, scope-templates): any update to that
  row fails after the upgrade. Fix before upgrading: give the row a valid
  value through the current API (rename the client, set a real audience,
  replace the scope list), or delete rows that are debris. Each shape's rule
  ID names the guard; `RULE-FLOOR.md` holds the rule's full sentence.
- `advisory` (organizations, users, service accounts, org roles): the row
  only fails when that specific field is re-supplied. Fix at leisure, but
  before the next edit of that field.

**Which shapes can actually be out there:** the audit sweeps everything, but
the database always refused some shapes itself (user emails and roles,
whitespace org/service-account names, unlisted client auth methods and
signing algorithms, private_key_jwt key-source pairing). Hits on those
indicate schema drift, not history. The shapes with a real historical write
path are: organization domains that fail the DNS grammar or were stored
un-normalized (`ORG-DOMAIN-FORMAT-1` / `ORG-UPDATE-VALIDATION-1`), blank or
whitespace client names and empty redirect-URI lists
(`CLIENT-UPDATE-VALIDATION-1`), confidential clients on method `none`
(`CLIENT-UPDATE-DOCUMENT-1`), whitespace api-resource names/audiences and
scope-template names (`REQUIRED-NAME-NOT-WHITESPACE-1`), and pre-2026
reserved-prefix scopes on either (`API-RESOURCE-REFUSAL-STATUS-1`,
`SCOPE-TEMPLATE-UPDATE-BLANK-1`).

**One migration that needs a decision, not a fix:** a confidential client on
`token_endpoint_auth_method: "none"` can no longer be moved to `none` — and
cannot stay there coherently either. `none` means "does not authenticate",
which is only valid for a public client, and `is_public` is create-only by
design: flipping it changes the client's entire security model (secret
issuance, service-account bindings, consent semantics), so it is an identity
property, not a setting. The migration path is: create a new **public**
client (it gets `none` by default), move the redirect URIs over, update the
relying application's client_id, then delete the old row. The audit counts
these under `CLIENT-UPDATE-DOCUMENT-1`.

## The OpenID conformance harness (`make openid-conformance`)

A MANUAL target — never part of `make verify` or the disposable suite. It
runs the OpenID Foundation conformance suite (pinned in `conformance/PIN`)
against a fresh disposable appliance, and reports the suite's verdicts
verbatim against a committed expected-failure floor. It fixes nothing: a
finding stays a finding until a product slice addresses it and the floor is
re-recorded deliberately.

**Prerequisites:** Docker (compose v2), network access on the FIRST run only
(clones the suite into `../.conformance-suite-cache` — a sibling of this
repo, outside every repo's scanners — and pulls its pinned images), python3,
node, openssl. Roughly 4 GB of images.

**Runtime:** first run ~10–20 min (clone + pulls + appliance build);
afterwards ~5 min. Everything runs on an isolated compose project
(`identuum-conformance`) with host ports 127.0.0.1:28443/28444/27113 — your
dev stack, its ports and its data are untouched. Teardown (`down --volumes`
for both stacks) fires on success, failure or Ctrl-C; only the cached suite
clone (and its python venv) survives between runs.

**Reading the result:**

- `RESULT: GREEN against the committed expected-failure floor` — the OP
  behaves exactly as the committed baseline records, INCLUDING its known
  findings. This is the healthy steady state.
- Nonzero exit — one of, and the output says which:
  - an UNEXPECTED failure: new behavior; read the verbatim condition list
    the suite prints.
  - an EXPECTED failure that now PASSES (floor semantics, rule
    `CONFORMANCE-FLOOR-1`): something improved; update
    `conformance/expected-failures-*.json` / `expected-skips-*.json` /
    `expected-basic-incomplete.txt`
    deliberately, the same way a rulefloor floor is raised.
  - `could not run` (exit 2): infrastructure, not conformance.

**The committed baseline (re-measured 2026-09-01 after THE-PKCE-DECISION,
suite release-v5.2.4):**

- Plan `oidcc-config-certification-test-plan`: PASSES clean (34 conditions,
  zero findings). The former signing-alg finding is FIXED — discovery now
  advertises `[EdDSA, ES256, RS256]` (see "RS256 — testing only" above).
- Plan `oidcc-basic-certification-test-plan`: runs ALL 36 modules
  (per-client PKCE retired the old mandatory-PKCE abort). 1744 conditions
  pass. The recorded floor:
  - 2 module FAILURES + 2 INCOMPLETE modules, one finding: `prompt=login`
    and `max_age=1` require the OP to FORCE re-authentication; the OP
    re-issues on the live session, so `auth_time` does not advance and both
    modules stall (`conformance/expected-basic-incomplete.txt` +
    `expected-failures-basic.json`). Needs a forced-login ceremony (own
    slice).
  - 7 recorded WARNINGS across 5 modules
    (`conformance/expected-failures-basic.json`, comments name each):
    partial profile claims (only `name`), email-in-id_token + unscoped
    `name` at userinfo (the access token carries role-derived scopes, not
    the consented OAuth scope — own slice), the deliberate
    refuse-to-fake-`acr` posture, and access-token revocation after
    authorization-code replay (the `AuthCodeReuseRevoker` seam is unwired —
    own slice, security-relevant SHOULD).
  - 4 recorded SKIPS (`conformance/expected-skips-basic.json`):
    address/phone scopes are not modeled, and the request-object module
    skips because the OP compliantly rejects request objects as
    unsupported.
  - 2 modules end in REVIEW (unregistered redirect_uri, request-object
    redirect_uri): the OP correctly refuses without redirecting and the
    suite records the error-page screenshot for human review — REVIEW is an
    accepted terminal result, not a floor entry.
- Transport measurement: the suite RUNS against an http OP but fails seven
  endpoint conditions on scheme alone, so the harness fronts the OP with a
  per-run self-signed https sidecar inside the isolated network
  (`conformance/compose.tls.yml`).

The suite clone is a tool repo: run, never modified — `run.sh` refuses to
proceed if the clone has local changes or is not at the pinned sha.
Browser-automation for the OP's own login/consent pages is committed in
`conformance/plan-basic.json`; it exercises whenever the browser actually
reaches those pages.

## RS256 — testing only, NEVER the default

Owner ruling (THE-PKCE-DECISION, 2026-09-01, verbatim): **"Add RS256 into the
list BUT DO NOT USE except testing and put this into documentation
CLEARLY."**

What that means in this product:

- **RS256 is a real capability.** `POST /api/v1/keys/generate` with
  `{"algorithm":"RS256"}` mints a real RSA-2048 signing key; it publishes in
  `/.well-known/jwks.json`; and it signs ID tokens. Discovery advertises
  `id_token_signing_alg_values_supported: [EdDSA, ES256, RS256]` because the
  OP can genuinely do all three — the list advertises nothing the OP cannot
  do.
- **RS256 is NEVER the default.** The issuer default is EdDSA (ES256
  fallback). An RS256 key — even present, active, and signing-capable —
  signs an ID token ONLY for a client that explicitly registered
  `id_token_signed_response_alg: "RS256"` (admin API or Dynamic Client
  Registration). Initial key generation never produces RS256; the access-
  and logout-token signer never selects it; the auth KeyManager refuses to
  sign with it.
- **It exists for conformance and interoperability TESTING, not
  operation.** The OpenID conformance suite and some legacy relying parties
  require RS256. Do not register production clients with RS256; do not
  generate an RS256 key on a production installation unless you are running
  an interop test against it. EdDSA is the operational algorithm.

## PKCE — required for public clients, optional to send, never optional to honor

PKCE posture (same ruling): **per-client**. A PUBLIC client (no credential)
MUST send a `code_challenge` (S256 only) — the request is refused without
one. A CONFIDENTIAL client MAY omit PKCE entirely. But PKCE is only optional
to SEND, never to HONOR: any challenge that was supplied is validated and
its verifier is enforced at the token endpoint, and a code minted without a
challenge refuses a gratuitous verifier.

## What the suite does NOT cover (known, recorded — not forgotten)

- **Backup / restore** — there is no product backup procedure yet to test;
  deferred until one is decided (see `TEST-spec-status.md`).
- **Commercial-edition (CE) features** — out of scope for this repository's
  suite by rule; the affected tests are skipped by name and counted, and
  the count may not grow.

## The promise

The suite runs on its own throwaway installation, built fresh and destroyed
at the end, both on success and on failure. It never reads or writes your
development database, your volumes, or your credentials.
