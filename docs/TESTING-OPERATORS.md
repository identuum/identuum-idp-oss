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

**The committed baseline (re-measured 2026-09-02 after
THE-JAR-REQUEST-OBJECT, suite release-v5.2.4):**

- Plan `oidcc-config-certification-test-plan`: PASSES clean (34 conditions,
  zero findings). The former signing-alg finding is FIXED — discovery now
  advertises `[EdDSA, ES256, RS256]` (see "RS256 — testing only" above).
- Plan `oidcc-basic-certification-test-plan`: runs ALL 36 modules to
  completion (per-client PKCE retired the old mandatory-PKCE abort;
  THE-SECOND-LOGIN's forced re-authentication retired the two stalls). 1872
  conditions passed in the THE-ADDRESS-PHONE-CLAIMS measurement run (three
  more modules now RUN instead of skipping), ZERO condition failures and
  ZERO warnings (the success total is NOT a stable number — runs of
  identical code have counted 1691, 1720, 1722, 1749 and 1754;
  failures/warnings/skips are the measured floor, the success total is
  not). The recorded floor:
  - `conformance/expected-basic-incomplete.txt` is EMPTY: `oidcc-prompt-login`
    and `oidcc-max-age-1` now run to completion with 0 failing conditions
    (result REVIEW — these modules ask for a screenshot of the second login,
    which the browser automation uploads; REVIEW is the accepted terminal
    state of that module class, exactly like the unregistered-redirect_uri
    error-page module).
  - 0 recorded WARNINGS — `conformance/expected-failures-basic.json` is
    EMPTY (`[]`). THE-CONSENTED-SCOPE retired the four email-in-id_token /
    unscoped-`name` warnings; THE-CODE-REUSE-REVOKER retired
    `oidcc-codereuse-30seconds`; THE-CLAIMS-PARAMETER retired
    `oidcc-claims-essential`; THE-PROFILE-CLAIMS retired `oidcc-scope-profile`
    (the full OIDC §5.1 profile is modeled and the conformance provisioner
    sets every field on the test user, so the 14-claim check passes
    truthfully); THE-HONEST-ACR retired the LAST entry,
    `oidcc-ensure-request-with-acr-values-succeeds` — measured, not faked:
    the suite requests every value in `acr_values_supported` (it sends
    `urn:identuum:loa:password urn:identuum:loa:mfa`), the password login
    the browser automation performs honestly satisfies the first, and the
    id_token now carries that performed acr (see "Honest acr" below).
  - 0 recorded SKIPS (`conformance/expected-skips-basic.json` is `[]`).
    THE-JAR-REQUEST-OBJECT retired the LAST one — measured, not assumed:
    with `request_parameter_supported: true` and `none` advertised,
    `oidcc-unsigned-request-object-supported-correctly-or-rejected-as-unsupported`
    RAN and PASSED (49 successes, 0 failures, 0 warnings; see "Request
    objects" below). THE-ADDRESS-PHONE-CLAIMS had retired the other
    three — `oidcc-scope-address`, `oidcc-scope-phone` and, because every
    standard scope is now supported, `oidcc-scope-all` — measured, not
    assumed: the provisioner sets a real phone number and every address
    member on the test user, the modules ran instead of skipping, and all
    three PASSED (0 failures, 0 warnings; see "Address and phone claims"
    below). The suite's `VerifyScopesReturnedInUserInfoClaims` requires
    every claim of a requested scope — for `phone` that is BOTH
    `phone_number` and `phone_number_verified` — which is why the OP emits
    `phone_number_verified: false` rather than omitting it.
  - 3 modules end in REVIEW: the two second-login modules above, and the
    error-page module `oidcc-ensure-registered-redirect-uri`: the OP
    correctly refuses without redirecting and the suite records the
    error-page screenshot for human review — REVIEW is an accepted terminal
    result, not a floor entry. `oidcc-ensure-request-object-with-redirect-uri`
    left this list with THE-JAR-REQUEST-OBJECT: the module offers "error
    page OR callback", the OP now resolves the object's registered
    redirect_uri over the query's invalid one and the suite completes the
    code flow — PASSED (50 successes, 0 failures, 0 warnings).
- Transport measurement: the suite RUNS against an http OP but fails seven
  endpoint conditions on scheme alone, so the harness fronts the OP with a
  per-run self-signed https sidecar inside the isolated network
  (`conformance/compose.tls.yml`).

The suite clone is a tool repo: run, never modified — `run.sh` refuses to
proceed if the clone has local changes or is not at the pinned sha.
Browser-automation for the OP's own login/consent pages is committed in
`conformance/plan-basic.json`; it exercises whenever the browser actually
reaches those pages. Image placeholders are filled deliberately, never by
the generic Login task: the first page of EVERY flow is the login page, and
a Login task that fills "the pending placeholder" fills the wrong one for
modules whose placeholder means "error page OR callback" — the suite then
finishes the module before its callback arrives and the callback's
submission dies with `runInBackground called after
runFinalisationTaskInBackground()` (result INTERRUPTED; measured on
`oidcc-ensure-request-object-with-redirect-uri` in THE-JAR-REQUEST-OBJECT).
The second-login screenshot the `prompt=login` / `max_age=1` modules ask
for (their `waitForPlaceholders` runs AFTER the callback, so without it
they sit WAITING until the runner times out — measured: 162 log entries, 0
failures, result UNKNOWN) is taken by two scoped tasks. The OP strips
`prompt=login` from the resumed `return_to` (or login would be forced
forever) and carries it on the login URL itself —
`/api/v1/auth/browser-login?return_to=…&prompt=login` — so the first task
matches exactly that marker; the second matches a login URL whose
`return_to` carries `max_age`. The error-page screenshot is taken only at
an `/oauth/authorize` URL showing an error.

## Consented scope on the access token — consent restricts, roles authorize

THE-CONSENTED-SCOPE (2026-09-01). Owner ruling, verbatim: **"access-token
scope = consented OAuth scopes INTERSECTED with role-permitted scopes.
Consent NARROWS, never grants beyond the role. Roles authorize; consent
restricts."** Rule `TOKEN-SCOPE-INTERSECTION-1`.

- **One claim, one meaning.** The access token's `scope` claim is always the
  set the token may EXERCISE. There is no second, role-derived claim: no
  consumer needs one (the admin guards read `scope` as the effective set;
  introspection recomputes the live RBAC set from the database).
- **Authorization-code tokens** (`UserTokenService.IssueForConsentedClient`)
  carry `consented ∩ permitted(role)`, where `permitted(role)` is the OIDC
  identity scopes (`openid profile email offline_access`) plus
  `domain.SessionScopesForRole` (the 27 org_admin scopes for org_admin;
  nothing for org_user / site_admin). A consented scope outside that set is
  dropped silently and the token response's `scope` reports the narrowed
  set (RFC 6749 §5.1). These tokens also carry `client_id` (RFC 9068) naming
  the client they were issued to.
- **Refresh rotation preserves it**: the refresh-token row stores the
  effective scope and `IssueRefresh` mints from the row, so no rotation can
  widen a token.
- **Login-session tokens** (`/api/v1/auth/login`, the UI) are unchanged: no
  client, no consent, role-derived `scope`, no `client_id`.
- **Introspection never widens.** For a client-bound token the live RBAC set
  may still REVOKE a scope (a removed role disappears at once) but never
  adds one the user did not consent to hand that client
  (`domain.NarrowScopeToLive`). Login-session tokens keep the live-replace
  semantics.
- **userinfo releases claims under the carried scope** (OIDC Core §5.4):
  `email` + `email_verified` under `email`, `name` under `profile`, humans
  only. A token carrying neither gets `sub` and the org/role projection.
- **The id_token carries no email.** In the code flow scope-requested claims
  belong to userinfo; only a `claims` request parameter (unsupported) would
  put them in the id_token.

## Profile claims — the full OIDC §5.1 set, unset is never emitted

THE-PROFILE-CLAIMS (2026-09-02, owner ruled the full profile). Rule
`PROFILE-CLAIMS-TRUTHFUL-1`.

- **Modeled** on `user_profiles` (migration 0035; one optional row per
  user, cascades with the user): given_name, family_name, middle_name,
  nickname, preferred_username, profile, picture, website, gender,
  birthdate, zoneinfo, locale. `name` stays on `users.name`; `updated_at`
  is the later of the user row's and the profile row's update time.
- **Unset is NEVER emitted** — no null, no "", no placeholder
  (`domain.ProfileClaims`). A field the user never set is simply absent.
- **Exposed** on the users API — `GET/PUT /api/v1/profile` (self-service:
  the caller's own display name + the twelve fields; email/role/status are
  not writable there) and `GET/PUT /api/v1/users/:id` (admin, same actor
  authority as any user update) — and on the UI account page
  (`/account/settings?tab=profile`). Formats are validated: `profile`,
  `picture`, `website` must be absolute http(s) URLs; `birthdate` is
  `YYYY-MM-DD`, `YYYY`, or `0000-MM-DD`; `zoneinfo` must be an IANA zone
  (the binary embeds tzdata); `locale` must be a well-formed BCP47 tag
  (RFC 5646 syntax, checked in the stdlib-only domain layer — not a
  subtag-registry lookup); free-text fields are capped at 256 characters
  (gender 64). "" clears a field.
- **Released** under `scope=profile` (the whole family, set fields only)
  or claim-by-claim through the `claims` parameter — consent-gated and
  role-intersected exactly like every other claim; humans only. The
  id_token carries them only for a consented `claims.id_token` request.
- **Advertised** honestly: `claims_supported` lists the family;
  `EmittableIdentityClaims` accepts them in the `claims` parameter.
- **Conformance**: `conformance/provision.mjs` sets EVERY field on the test
  user, so `oidcc-scope-profile`'s all-14-claims check passes on real data.

## Request objects — OIDC Core §6 / RFC 9101, by value, verified or refused

Rule `REQUEST-OBJECT-VERIFIED-1` (THE-JAR-REQUEST-OBJECT, 2026-09-02; wiki
decision P-027; rule `AUTHZ-REQUEST-OBJECT-REFUSED-1` re-worded through the
ledger-diff gate). `/authorize` accepts `request=<JWT>`:

| object | verdict |
|---|---|
| signed with a key the client REGISTERED (`jwks` / `jwks_uri`, the same resolution private_key_jwt uses), alg in the asymmetric allow-list (`EdDSA ES256 ES384 RS256 RS384 RS512`) | verified; its members are MERGED over the query (they supersede) and feed the unchanged pipeline — scope clamping, PKCE, `claims`, `acr_values`, `max_age` — so a parameter inside an object behaves exactly like the same parameter in the query |
| unsigned (`alg` `none`, empty signature) | ACCEPTED and advertised. Decision: an unsigned object carries no authority a plain query string lacks — every merged value still passes the same client / redirect_uri / PKCE / scope / consent validation. Refusing it would only keep `oidcc-unsigned-request-object-…` skipping (it drives an alg=none object and treats `request_not_supported` as a skip) and `oidcc-ensure-request-object-with-redirect-uri` at REVIEW (it skips unless `none` is advertised). |
| tampered / foreign signature, unknown `kid`, symmetric (`HS*`) or unsupported alg, `iss` not the client_id, `aud` not this issuer, `exp` past, `nbf` future, not a compact JWS | `invalid_request_object`; redirected ONLY to the REGISTERED query `redirect_uri` (the object's own cannot be trusted before it verifies), otherwise a direct 400; no code, ever |
| `client_id` in the object ≠ the query's; `response_type` present in both and different; `request` / `request_uri` nested inside | `invalid_request_object` (§6.1 agreement rules; parameter smuggling) |
| `request_uri` | NOT supported — `request_uri_not_supported`; discovery says `request_uri_parameter_supported: false` and `require_request_uri_registration: false` explicitly (the omitted Discovery default is true). No half state. |

Merging rules: `client_id` MUST travel in the query (RFC 9101 §5) and, when
repeated in the object, MUST match; `response_type` in both must match;
the object's other members supersede the query; `iss`/`aud`/`exp`/`nbf`/
`iat`/`jti` are envelope claims, never authorize parameters; numbers
(`max_age`) and objects (`claims`) are re-serialized to the wire strings the
query path would carry. The login/consent `return_to` re-encodes the MERGED
parameters without `request` — the object is verified once.

Discovery: `request_parameter_supported: true`,
`request_object_signing_alg_values_supported: ["none", …asymmetric…]`
(`domain.RequestObjectSigningAlgValuesSupported` is the one source),
`request_uri_parameter_supported: false`.

Conformance: `oidcc-unsigned-request-object-supported-correctly-or-rejected-as-unsupported`
now runs and passes (the OP processes the unsigned object) and
`oidcc-ensure-request-object-with-redirect-uri` — a registered redirect_uri
inside the object beside an INVALID one in the query — resolves to the
object's (it supersedes) and passes instead of REVIEW; see the baseline.

Iterating on one module: `make openid-conformance MODULE=<module-name>`
runs only that basic-plan module (index from the committed
`conformance/plan-basic.modules.txt`, regenerated by every full run) and
skips the config plan. The floor verdict is always the FULL run's.

## Address and phone claims — real fields, unset never emitted, verified never true

Rule `ADDRESS-PHONE-TRUTHFUL-1` (THE-ADDRESS-PHONE-CLAIMS, 2026-09-02; wiki
decision P-025). The OIDC Core §5.1 `phone_number` and §5.1.1 structured
`address` claims are modeled the PROFILE-CLAIMS way: optional columns on
`user_profiles` (migration `0036_address_phone.sql`), `NULL` = unset = never
emitted, no placeholders.

| field (API name) | claim | validation on write |
|---|---|---|
| `phone_number` | `phone_number` (+ `phone_number_verified`) | E.164: `+`, non-zero first digit, 2–15 digits |
| `address_formatted`, `address_street_address`, `address_locality`, `address_region`, `address_postal_code`, `address_country` | `address` object members `formatted`, `street_address`, `locality`, `region`, `postal_code`, `country` | text, ≤ 256 characters each |

- `address` is emitted only when at least one member is set, and carries
  ONLY the set members — never an empty object, never a member with an
  empty value.
- **`phone_number_verified` is NEVER true.** identuum has no phone
  verification event (no SMS/voice challenge exists), so the OP cannot
  truthfully claim it. It is emitted as `false`, and only alongside an
  emitted `phone_number`. Why `false` rather than omitting it: OIDC Core
  §5.1 defines `false` as "the OP has not taken affirmative steps to ensure
  the number was controlled by the End-User" — exactly the fact — and a
  relying party asking for the phone scope expects the pair (the
  conformance suite's `VerifyScopesReturnedInUserInfoClaims` requires BOTH
  `phone_number` and `phone_number_verified`; missing one is a WARNING).
  Omitting it would also be honest but would say less; `false` states the
  fact. A lone `phone_number_verified` without a number is never emitted.
- Surfaces: self-service `PUT /api/v1/profile` and the account page's
  Profile tab; admin `PUT/GET /api/v1/users/:id` (the same flattened field
  names; `""` clears). Release: `scope=address` → `address`; `scope=phone`
  → the phone pair; or claim-by-claim through the `claims` parameter —
  consent-gated (the OP consent page lists the requested scopes by name —
  `address`, `phone`; `domain.ScopeDescriptions` carries the human labels
  "View your postal address" / "View your phone number" for UI surfaces),
  role-intersected (`domain.PermittedClaimsForRole`:
  human roles only; a service account never receives them), userinfo only
  under scope, id_token only through `claims.id_token`.
- Discovery: `scopes_supported` gains `address` and `phone`;
  `claims_supported` gains `address`, `phone_number`,
  `phone_number_verified`. A client must have the scopes REGISTERED to
  request them (`ClampScopeToRegistered`).
- Conformance: the provisioner sets a phone number and every address member
  on the test user, so `oidcc-scope-address`, `oidcc-scope-phone` and —
  because every standard scope is now supported — `oidcc-scope-all` run
  instead of skipping; see the baseline above for the measured result.

## The `claims` request parameter — consent-gated, role-intersected

THE-CLAIMS-PARAMETER (2026-09-02, owner ruled BUILD). OIDC Core §5.5 lets a
client ask for individual claims (`claims={"userinfo":{"name":{"essential":
true}},"id_token":{"email":null}}`). Rule `CLAIMS-PARAM-CONSENT-1`.

- **Parsed at /authorize** (`domain.ParseClaimsRequest`): only the
  `userinfo` and `id_token` members, only the claims this OP can emit
  (`name`, `email`, `email_verified`); every unknown member or claim is
  IGNORED — never an error (§5.5.1). `essential` and voluntary are parsed
  and treated identically (§5.5.1 lets the OP omit an essential claim it
  cannot supply). Only a value that is not a JSON object is refused,
  redirect-safe, as `invalid_request`.
- **Consent covers claims like scopes.** The OP consent page lists the
  requested claims ("name (shared with the application)", "email (included
  in the ID token)"); approval stores them on the consent row
  (`oauth_consents.claims`, tokens like `userinfo:name`). A returning client
  asking for a claim not yet consented is sent to consent again
  (`ConsentService.Lookup` covers scope AND claims). `SkipConsent` clients
  bypass, as for scopes.
- **Persisted on the code row** (`oauth_authorization_codes.requested_claims`,
  migration 0034) and honored at the exchange: the `userinfo` member rides on
  the access token as `userinfo_claims` (∩ what the role permits —
  `domain.IntersectConsentedClaims`), and the `id_token` member is minted
  into the id_token. Login-session tokens carry none.
- **Released only when truthful.** userinfo emits `name` when the profile
  scope OR a consented `name` claim is present and the user record has a
  name; `email`/`email_verified` likewise. The id_token emits a requested
  claim only when the user record can supply it (§5.3.2: never a null or
  empty placeholder).
- **Roles authorize.** Every human role permits its own identity claims to
  a consented client; a principal with no role gets none.
- **Discovery** advertises `claims_parameter_supported: true` and a
  `claims_supported` list of exactly the claims that emit somewhere (id_token
  or userinfo): sub iss aud exp iat jti auth_time nonce acr amr name email
  email_verified organization_id role.

## Authorization-code reuse revokes what the code minted

THE-CODE-REUSE-REVOKER (2026-09-02). RFC 6749 §4.1.2: on reuse of an
authorization code the server MUST deny the request and SHOULD revoke all
tokens previously issued based on that code. Rule `CODE-REUSE-REVOKES-1`.

- **Recorded at the exchange.** Right after minting, the token endpoint
  writes the access token's `jti` + expiry and, with `offline_access`, the
  OAuth refresh token's id onto the consumed code row (migration 0033:
  `issued_access_jti`, `issued_access_expires_at`,
  `issued_refresh_token_id`). The write is fail-closed: if it cannot be
  recorded, the exchange answers `server_error` and no token goes out —
  tokens that could never be revoked on reuse must not exist.
- **Revoked on replay through the EXISTING paths, no new mechanism.**
  `AuthorizationCodeService.Consume` already detected the replay (P0-1b);
  `service.AuthCodeReuseRevocation` now implements its seam: the access
  `jti` goes into `oauth_token_revocations` via `TokenRevocationService`
  (the RFC 7009 `/revoke` store, read fail-closed by the bearer middleware
  and by introspection/userinfo), and the refresh token's whole rotation
  family is revoked via `RefreshTokenService.RevokeLineageByID` (the same
  cascade a refresh-token replay triggers), which also revokes the access
  tokens linked to that family.
- **The replay is still refused exactly as before** (`invalid_grant`,
  400), and the client learns nothing about whether revocation happened.
- **Idempotent.** A code replayed N times revokes once. A code row with
  nothing recorded (pre-0033 rows, or an exchange that failed after
  consume) revokes nothing; an unknown code never revokes anything.
- **Accepted cost (ruled 2026-08-04, P0-1b):** a client that
  double-submits one code revokes its own user's tokens from that code.
- **Window.** Reuse is detectable while the code row exists — the
  10-minute code TTL plus the cleanup lag. After the row is pruned a replay
  is indistinguishable from an unknown code.

## Honest acr — the id_token says how the user actually authenticated

Rules `ACR-HONEST-1` (THE-HONEST-ACR, 2026-09-02; wiki decision P-023) and
`ACR-HONEST-2` (THE-PHISHING-RESISTANT-ACR, 2026-09-02; P-024). The OP
never fakes an authentication context. Three honest contexts exist, and
they are EXACTLY the values discovery advertises in `acr_values_supported`,
in ladder order:

| acr (rank) | performed when | amr |
|---|---|---|
| `urn:identuum:loa:password` (1) | password verified | `["pwd"]` |
| `urn:identuum:loa:mfa` (2) | password AND a TOTP code verified | `["pwd","otp"]` |
| `urn:identuum:loa:phishing-resistant` (3) | a WebAuthn assertion verified — passkey login, or the passkey step-up on an existing session | login amr unchanged (a WebAuthn login stamps no amr; an uplift keeps the login's amr) |

Every local session creation stamps the context it performed
(`auth.LoginContext`: the JSON login, the browser login, the pending-MFA
completion; the WebAuthn login-finish stamps the phishing-resistant rung).
The id_token and access token carry `acr` = the session's EFFECTIVE context
(`Session.EffectiveACR`: the stamped rung, or the rung a recorded step-up
uplifted it to) and `amr` from `Session.EffectiveAMR`. A session that
carries no context (created before these slices) emits NO `acr` claim — an
absent claim is honest, a guessed one is not.

**Ranking lives in ONE place** — the ladder in `auth/acr.go`
(`ACRMeetsFloor`): a higher performed rung satisfies a request for a lower
one (phishing-resistant covers mfa and password; mfa covers password), never
the reverse.

**Advertising the third value was MEASURED, not assumed** (DO-4 of
THE-PHISHING-RESISTANT-ACR): the conformance suite requests EVERY advertised
value in one `acr_values` and its browser automation can only type a
password. With three values advertised the run on 2026-09-02 was 36 modules,
0 failures, 0 warnings, `oidcc-ensure-request-with-acr-values-succeeds`
PASSED, `RESULT: GREEN against the committed expected-failure floor` (still
`[]`) — the password login honestly satisfies one requested value and the
id_token's acr is in the requested set. So the value is advertised.

`acr_values` (OIDC Core §3.1.2.1) is honored with any-of semantics over the
rungs the OP knows; unknown values are a voluntary request the OP ignores
(never an error). When the session's effective context meets none of the
known requested rungs, the CHEAPEST requested rung decides:

- password rung on a session with no stamped context → `login_required`
  (re-login stamps it); interactive browsers go through the login form.
- TOTP rung, user has TOTP enrolled → the OP's step-up ceremony:
  `GET /api/v1/auth/step-up` renders a code form for the live browser
  session, `POST /api/v1/auth/step-up` verifies the code and records the
  uplift on the SAME session (`SessionRepository.RecordACRUplift` writes
  `sessions.last_acr_uplift_at/_value` — its first production writer), then
  303s back to the original authorize URL, which now mints. A wrong code
  re-renders the form (`error=invalid_code`) and writes nothing.
  `prompt=none` never gets the step-up page: `login_required` to the client.
- phishing-resistant rung (or the mfa rung for a user WITHOUT TOTP), user
  holds a passkey → the OP's passkey step-up ceremony: `GET
  /api/v1/auth/step-up/passkey` mints WebAuthn assertion options for the
  session's own user and renders a page whose inline script runs
  `navigator.credentials.get`; `POST /api/v1/auth/step-up/passkey?session_id=…`
  verifies the assertion through the same `WebAuthnService.FinishLogin` the
  passkey login uses (same validator, RP-ID/origin checks, single-use
  ceremony session), REFUSES an assertion by any other user, and only then
  records the uplift to `urn:identuum:loa:phishing-resistant` on the SAME
  session and answers `{"return_to": …}` for the page to resume. A failed
  or foreign assertion is 401 `invalid_assertion` and writes nothing. The
  page must load on an allowed RP origin — the issuer's own origin always is
  (`WebAuthnServiceConfig.BaseURL`), plus the UI origin when it shares the
  RP ID host.
- the cheapest ceremony that reaches the requested rung is offered: TOTP
  for the mfa rung when enrolled; a passkey otherwise (it reaches the
  phishing-resistant rung, which covers mfa).
- a rung this user cannot perform (TOTP rung without TOTP and without a
  passkey; phishing-resistant rung without a passkey) →
  `error=unmet_authentication_requirements` (OpenID "Unmet Authentication
  Requirements 1.0") to the client; no code, no token.

Manual check on a running appliance (a user with TOTP enrolled):

```sh
# 1. Sign in with password only at /api/v1/auth/browser-login, then:
curl -si -b "$JAR" -c "$JAR" \
  "$IDP/api/v1/oauth/authorize?client_id=$CID&redirect_uri=$RU&response_type=code&scope=openid&state=s&code_challenge=$CC&code_challenge_method=S256&acr_values=urn:identuum:loa:mfa" \
  | grep -i '^location:'      # → /api/v1/auth/step-up?return_to=... (enrolled) or error=unmet_authentication_requirements (not enrolled)
# 2. Submit the code on the step-up form, follow return_to, exchange the code:
#    the id_token payload carries "acr":"urn:identuum:loa:mfa","amr":["pwd","otp"].
```

What the conformance suite measures: `oidcc-ensure-request-with-acr-values-succeeds`
sends `acr_values` = every advertised value; its browser automation signs
in with the password only; the OP honestly satisfies the password rung and
the id_token's `acr` is in the requested set. The module PASSES without the
suite ever typing a TOTP — which is exactly why the two-value vocabulary is
the honest one: an advertised value nobody can perform would be a promise
the OP cannot keep.

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

## Forced re-authentication — prompt=login and max_age

THE-SECOND-LOGIN (2026-09-01). The authorize endpoint honors OIDC Core
§3.1.2.1's two re-authentication controls on an ALREADY-authenticated
browser:

- `prompt=login` sends the user back through the OP login form even though a
  live session exists. The ceremony consumes the prompt: the resumed request
  in `return_to` no longer carries `prompt=login` (otherwise login would be
  forced forever); every other parameter — and any other prompt token —
  survives.
- `max_age=N` compares the session's `auth_time` (its creation, or its last
  ACR uplift) with now; older than N seconds forces the same login ceremony.
  `max_age` stays in the resumed request — a fresh session passes it. A
  non-integer or negative `max_age` is refused redirect-safe as
  `invalid_request`.
- A fresh login mints a NEW session (the first survives it, subject to the
  organization's per-user session cap), so `auth_time` advances monotonically
  with each forced ceremony; the id_token always carries `auth_time`.
- `prompt=none` is unchanged: no form, ever — a stale `max_age` under
  `prompt=none` is the OIDC-required `error=login_required` redirect to the
  client.

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
