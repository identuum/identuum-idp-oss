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
IDENTUUM_IDP_COMPOSE_PROJECT=scratch-mint FAST_UP_PG_CONTAINER="$id" DEV_PG_HOST_PORT=35599 make test-full
```

The three variables are required: they name the scratch PostgreSQL the
database-backed phase uses — its project, the full container ID its
`docker run` printed (`$id`), and its port (see "Running a mint against a
scratch server" below for the commands). Without them the run is refused
before anything connects or starts: the port defaults to 5513, and a mint on
the default dev project, or without the recorded container, is never run.

It takes about 16 minutes and prints its progress phase by phase. All
passwords the run needs are generated fresh for that run and never shown.

Its last step is `make devseed-live` (about 50 seconds): `make dev-seed` run
against a disposable project of its own (`scratch-devseed`, host ports 25513
and 27113), then every credential it prints is used to sign in, and the
project is removed again. It needs those two ports free and refuses, naming
the holder, when one is taken. It also refuses, without removing anything,
when `scratch-devseed` still has containers, volumes or networks from an
earlier run; the refusal names each one with a read-only `docker inspect`
command and leaves removal to you. It
refuses too when a volume or network already has one of the names it would
create, whoever made it, when the resolved Compose configuration holds
anything but its two services, mounts a host path, runs privileged or in
the host's network, or publishes a port other than its two on 127.0.0.1,
and when another harness run is active (see "The harness claim and its
record" below). Each name it creates ends with a random id of that run
(`scratch-devseed_postgres-idp-oss-data-v18_<id>`,
`scratch-devseed_default_<id>`), so an ordinary stack or another run does
not create the same name by accident. At the end it removes only what it
recorded creating, each after checking it again, and a volume only under a
name that carries its own id. Everything is checked before the first
removal: when anything it did not create is found — a container, volume or
network of the project or under one of its names, a recorded one that was
replaced, or a container of someone else attached to its network or using
its volume — it removes nothing at all, not even its own resources, and the
run fails. After the removals it checks that every recorded resource is
gone. One case is not caught: Docker removes a volume by name, with no
identity check, so if another Docker user copies the run's exact volume
name and puts a volume of their own under it after the last check and
before the removal, that volume is removed and the run does not fail. The
claim and the mutex below do not stop a Docker user outside these targets.

`devseed-live` supports exactly one setup: the Docker engine of this
computer, reached through a unix socket on this computer. It refuses,
before any other Docker command, a `DOCKER_HOST` that is not a
`unix:///` socket, and a Docker context (`DOCKER_CONTEXT` or the current
one) whose endpoint is not one, such as `tcp://` or `ssh://`. It also
refuses a `COMPOSE_CMD` that is not exactly `docker compose` (from the
environment, the command line or `make -e`): an option such as `--host`,
`-H`, `--context` or `-c` in it would start the stack on another engine.
Every Docker command of the run, the nested `make oss-up` included, uses
the checked endpoint.

The `/tmp` claim keeps out a second run that sees the same `/tmp`. A run
with another `/tmp` (a container sharing the Docker socket, another mount
namespace) is kept out by the daemon mutex: before it lists or starts
anything, the run creates a stopped container named
`identuum-harness-lock-engine` on the checked engine, labelled with its
project and ports, and Docker refuses a second container of that name.
identuum-ui's `make e2e-full` and `make openid-conformance` take the same
mutex, so no two of them run against one engine at the same time. The
container is made from the distroless image that
`deployment/Dockerfile.local` pins
(`gcr.io/distroless/static-debian12@sha256:d75cdd72...`); it is never
pulled by the run, and when it is missing the run refuses and prints the
`docker pull` command. It is never started, and it is removed by its ID
at the end. When a run is killed, the container stays and the next run
refuses, naming it: check that no `devseed-live`, `e2e-full` or
`openid-conformance` run is active, inspect it (`docker container inspect identuum-harness-lock-engine`,
labels `io.identuum.harness.*`). Removing it is a manual owner decision. The run also
records the engine's ID (`docker info`) and checks it before every later
Docker command; if another engine answers, the run stops all Docker
commands, fails, and leaves the mutex in place. These checks do not prove
where a unix socket leads: a socket forwarded from another computer can
answer with a stable ID, and an engine switched inside one Docker command
is not seen.

`DEVSEED_LIVE_PG_PORT` (default 25513) may be set to another free port.
It is refused, before any Docker command, when it is 5513 or 5432, has a
leading zero, or is not a port number, however it is set (command line,
environment with `make -e`, or an `override`). The seeded credentials are
written to a mode-600 file in a new temporary directory, which is left for
you and never printed. Run it alone with `make devseed-live`.

The first phase is the DATABASE-BACKED suite (`make verify-integration`,
about 5m40s of that total, measured 2026-09-03): the tests that need a real
PostgreSQL rather than an in-memory stand-in. It runs here because the mint
is the one place a database is a given — `make verify` deliberately needs no
database, so it can run on any machine. That phase leaves its own record,
`GATE-RUN.integration.txt`, alongside the others.

If you have a scratch PostgreSQL up already, you can run just that phase:

```bash
DEV_PG_HOST_PORT=35599 make verify-integration
```

It answers one of three ways, and only the first is a pass: **green** (the
tests ran and passed, with the counts in the record), **red** (something
failed — or the suite executed no tests at all, which is treated as a
failure, because a suite that stops running must never look like one that
passed), and **cannot evaluate**, exit code 2, when there is no database to
talk to. That last one is not a pass and not a bug report: start PostgreSQL
and run it again.

### Running a mint against a scratch server

Every database-backed test entry (`make test-db`, `ci-integration-test`,
`integration-test`, `rulefloor-integration`, `verify-integration`,
`validate`, `verify-oss` and `test-full`) refuses port 5513, the PostgreSQL a
development stack publishes by default. Give the run its own server and move
only the port:

```bash
id=$(docker run -d --rm --name scratch-mint-pg --tmpfs /var/lib/postgresql \
  -p 127.0.0.1:35514:5432 \
  -e POSTGRES_USER=idp_oss_user -e POSTGRES_PASSWORD=dev-idp_oss_user-not-a-secret \
  postgres:18-alpine@sha256:9a8afca54e7861fd90fab5fdf4c42477a6b1cb7d293595148e674e0a3181de15)
IDENTUUM_IDP_COMPOSE_PROJECT=scratch-mint FAST_UP_PG_CONTAINER="$id" DEV_PG_HOST_PORT=35514 make test-full
docker stop "$id"                        # --rm removes the container; tmpfs keeps no volume
```

For `make verify-integration` alone, `DEV_PG_HOST_PORT=35514` is enough:
every test database URL follows it. A mint (`make test-full`) is a candidate
run, so its `make fast-up` step is stricter. With a `scratch-` project it
never starts a database and never trusts a server just because it answers
the port: it reuses only the container whose full ID you pass in
`FAST_UP_PG_CONTAINER` (the ID `docker run` printed), after checking on this
computer's Docker engine that the container is named `scratch-…`, is
running, publishes exactly 5432 on `127.0.0.1:DEV_PG_HOST_PORT` and mounts
no folder of this computer, and that the development user can connect.
Anything else is refused, and nothing is started or stopped. Reusing it
gives no right to remove it: you stop it yourself. `make fast-up` on the
default development project keeps its old behaviour (reuse a compatible
server on the port, or start the development PostgreSQL); a mint refuses
that project. The 5513 refusal has
no exception: no environment variable, CI setting or operating system admits
5513. The CI workflow's test PostgreSQL services use port 45432 (neither 5513
nor PostgreSQL's own 5432), and its jobs set `DEV_PG_HOST_PORT=45432`.

If you also set `IDENTUUM_IDP_TEST_DATABASE_URL` or `OSS_TEST_DB_URL`,
`DEV_PG_HOST_PORT` does not rewrite it: the URL is checked, and accepted only
in this form:

- the scheme `postgres://` or `postgresql://`;
- optional `user:password@`;
- exactly one server, `127.0.0.1` or `localhost`, on the `DEV_PG_HOST_PORT`
  port;
- a database name of letters, digits and underscores that ends in `_test`;
- no option except a single `sslmode=` (for example `?sslmode=disable`).

Everything else stops every database-backed target with
`test-db-endpoint: REFUSED` before it connects to anything: another port or
server, a host list, a socket directory, a percent-encoded name, a fragment,
and any other option. The driver lets `host`, `hostaddr`, `port`, `dbname`,
`database` and `service` options replace the server or the database the URL
appears to name, so none of them is accepted. `PGHOSTADDR` and `PGSERVICE`
in your environment are refused too. `make test-db` creates the database the
URL names (`identuum_idp_oss_test` when you set none).

The same rules apply to `make test`, to `go-test-race` (the CI test step) and
inside every database-backed Go test, so `go test ./...` run by hand is
refused in the same way. A database-backed test needs `DEV_PG_HOST_PORT` set
to the scratch server's port next to `IDENTUUM_IDP_TEST_DATABASE_URL`. There
is no escape variable: `IDENTUUM_IDP_ALLOW_NON_TEST_DB` no longer has any
effect.

`tools/integration-witness` (the runner behind `verify-integration`) applies
the same rules, and has no default: run on its own, it refuses unless
`IDENTUUM_IDP_TEST_DATABASE_URL` and `DEV_PG_HOST_PORT` are set and agree.
`scripts/ci-integration-record.sh` runs only in the CI Integration Tests job,
and hands each target that job's `DEV_PG_HOST_PORT`.

The appliance phases of `make test-full` use their own PostgreSQL (port
15513, project `scratch-e2e`), and `devseed-live` its own (port 25513,
project `scratch-devseed`): each phase has its own disposable server, so a
mint does not use one server throughout.

### The harness claim and its record

`devseed-live`, identuum-ui's `make e2e-full` / `make e2e-quick` and
`make openid-conformance` share one claim, the directory
`/tmp/identuum-harness.lock` (one fixed path, whatever `TMPDIR` says), and
the daemon mutex above. While one of them runs, the others are refused
before any Docker command: they never share a host port, whatever their
project or Docker engine (`devseed-live` and the conformance harness both
publish 27113). A busy claim is refused at once; nothing waits for it.

Inside the claim, each run keeps its record: `manifest.json` names the run
(its kind, project, random invocation id, the Docker engine's ID and
endpoint, its ports and the mutex's ID) and every resource it created —
containers and networks by full ID, volumes by name and creation time. It
is rewritten whole after the reservation, after the start and after the
teardown. A green run removes the claim, the record and the mutex when every
resource it recorded is gone.

When the teardown is refused or fails — something it did not create was
found, an identity changed, a removal failed, a resource is still there, or
the Docker engine changed — the run fails and KEEPS the claim, the mutex
and the record (its `manifest.json` then says `"state":"refused"`). Every
later harness run is refused until you resolve it:

1. Read `/tmp/identuum-harness.lock/manifest.json`.
2. Run the read-only inspection commands the refusal printed for each
   resource it names (`docker inspect <id>`, `docker network inspect <id>`,
   `docker volume inspect <name>`, and `docker container inspect` for the
   mutex). The harness never prints a removal command: a label or a name
   proves no ownership, and what it found may be protected.
3. Removal is a manual owner decision. Only the owner decides whether any
   resource, the mutex or the directory `/tmp/identuum-harness.lock` is
   removed, after confirming that no harness run is active.

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
  2. If it fails twice, save the printed output (and the record files —
     `identuum-ui/GATE-RUN.e2e-full.txt` for the appliance phases,
     `identuum-idp-oss/GATE-RUN.integration.txt` for the database-backed
     one — which record exactly what ran and what it saw) and report it.
     Those files plus the printed failure are everything a developer needs
     to start.

## Running it by hand

Sometimes you do not want the whole suite — you want a working local stack to
click around in. Every step below is a `make` target run from
`identuum-idp-oss`; none of it needs a hand-written `docker` command.

**The whole thing, one command** (destroys the local dev database, so it asks
you to say so explicitly):

First export `IDENTUUM_IDP_BOOTSTRAP_PASSWORD` using the hidden Bash prompt
in OPERATOR-GUIDE.md → "Create the first admin + signing key (bootstrap)".
Then invoke the existing `oss-fresh` target with its explicit destruction
confirmation only on a disposable stack you are authorized to destroy.
Never use the owner's protected development stack.

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

`make oss-bootstrap` needs `IDENTUUM_IDP_BOOTSTRAP_PASSWORD` exported in
your environment. Use the hidden Bash prompt in OPERATOR-GUIDE.md →
"Create the first admin + signing key (bootstrap)" to set it. Do not type
the password into a shell command, or enable shell tracing. Invoke the
target only against an explicitly authorized development stack.

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
- `CRITICAL: migration 0056 refuses the upgrade` (users, from v0.9.14): one
  address, in any case, belongs to more than one live account
  (`EMAIL-GLOBAL-UNIQUE-MIGRATION-1`). Each such address is printed as one
  line of user ids and organization ids, never the address. Fix before
  upgrading; see the operator guide, "Before upgrading to v0.9.14".

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

A MANUAL target — never part of `make verify`, CI or the disposable suite. It
is a RELEASE STEP: before an OSS release is tagged, it runs at the release
commit (both plans, no preload) and must end `RESULT: GREEN`; the release
notes record that run. No gate runs it, because it needs Docker, about 4 GB of
pinned images and a network clone on its first run. Until v0.9.6 nothing ran
it, and it had stopped at provisioning since v0.9.5 (FUNC-M10). It
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
(`scratch-conformance`) with host ports 127.0.0.1:28443/28444/27113 — your
dev stack, its ports and its data are untouched. It takes the harness claim
and the daemon mutex first (see "The harness claim and its record"), refuses
— rather than removes — anything the project already holds, and records
every container, network and volume it creates. The teardown fires on
success, failure or Ctrl-C and removes exactly those, each by its recorded
ID, as one step (no `down`); a refused teardown keeps the claim, the mutex
and the record. Only the cached suite clone (and its python venv) and the
images survive between runs. The per-run TLS certificate and key live in a
private temporary folder, never in the repository, and reach the TLS
sidecar with `docker cp`; no folder of this computer is mounted into a
container.

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

**The committed baseline (re-measured 2026-09-07 at `39be0f0` by the
owner, suite release-v5.2.4; the config-plan line below CORRECTS a claim
that stood from 2026-09-03 to 2026-09-07):**

- Plan `oidcc-config-certification-test-plan`: RED — module
  `oidcc-discovery-endpoint-verification` 36 conditions passed, 1 failed:
  `OIDCCCheckDiscEndpointIdTokenSigningAlgValuesSupported` — "RS256 support
  is required, but the server does not list it in
  `id_token_signing_alg_values_supported`" (OpenID Connect Discovery 1.0 §3:
  RS256 MUST be included). Discovery advertises `[EdDSA, ES256]`
  (`domain.IDTokenAdvertisedSigningAlgorithms`); RS256 is registrable per
  client and mintable on explicit operator request, never advertised, never
  the default, and the default keyset holds no RSA key
  (`auth.AutoGenerateInitialKey` mints EdDSA or ES256 only; see "RS256 —
  testing only" below). HOW THE FALSE CLAIM AROSE: the 2026-09-02 measurement
  passed this plan with `[EdDSA, ES256, RS256]` advertised; `d9ab771`
  (2026-09-03) de-advertised RS256 and rewrote this paragraph to say the plan
  "PASSES clean (34 conditions, zero findings)" without re-running it —
  `git log --since=2026-09-03 -- conformance/` was empty at that measurement.
  This is a historical result, not a result for the current tree.
  **Current policy (owner revision 2026-10-10):** the default still advertises
  `[EdDSA, ES256]`. `IDENTUUM_IDP_ADVERTISE_RS256=true` adds RS256 and ensures
  an active RSA signing key at startup. The conformance appliance enables it;
  `conformance/expected-failures-config.json` is now empty. Removing that
  expected failure tightens the config plan: the RS256 condition must pass.
  No new conformance run is claimed here; certification still requires a
  successful run with the option enabled. EdDSA remains the default signer.
- Plan `oidcc-basic-certification-test-plan`: runs ALL 36 modules to
  completion (per-client PKCE retired the old mandatory-PKCE abort;
  forced sign-in's forced re-authentication retired the two stalls). 1872
  conditions passed in the address and phone claims measurement run (three
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
    EMPTY (`[]`). consent scope enforcement retired the four email-in-id_token /
    unscoped-`name` warnings; code-reuse revocation retired
    `oidcc-codereuse-30seconds`; claims-parameter support retired
    `oidcc-claims-essential`; profile claims retired `oidcc-scope-profile`
    (the full OIDC §5.1 profile is modeled and the conformance provisioner
    sets every field on the test user, so the 14-claim check passes
    truthfully); honest authentication context retired the LAST entry,
    `oidcc-ensure-request-with-acr-values-succeeds` — measured, not faked:
    the suite requests every value in `acr_values_supported` (it sends
    `urn:identuum:loa:password urn:identuum:loa:mfa`), the password login
    the browser automation performs honestly satisfies the first, and the
    id_token now carries that performed acr (see "Honest acr" below).
  - 0 recorded SKIPS (`conformance/expected-skips-basic.json` is `[]`).
    request-object verification retired the LAST one — measured, not assumed:
    with `request_parameter_supported: true` and `none` advertised,
    `oidcc-unsigned-request-object-supported-correctly-or-rejected-as-unsupported`
    RAN and PASSED (49 successes, 0 failures, 0 warnings; see "Request
    objects" below). address and phone claims had retired the other
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
    left this list with request-object verification: the module offers "error
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
`oidcc-ensure-request-object-with-redirect-uri` in request-object verification).
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

consent scope enforcement (2026-09-01). **"access-token
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
  `email_verified` is true only for a proven mailbox (a verification email
  or the sign-in provider; rows verified before v0.9.12 count), never for an
  account an administrator activated or created (OSS-0912-C2).
- **The id_token carries no email.** In the code flow scope-requested claims
  belong to userinfo; only a `claims` request parameter (unsupported) would
  put them in the id_token.

## Profile claims — the full OIDC §5.1 set, unset is never emitted

profile claims (2026-09-02, the full profile was implemented). Rule
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

Rule `REQUEST-OBJECT-VERIFIED-1`. `/authorize` accepts `request=<JWT>`:

| object | verdict |
|---|---|
| signed with a key the client REGISTERED (`jwks` / `jwks_uri`, the same resolution private_key_jwt uses), alg in the asymmetric allow-list (`EdDSA ES256 ES384 RS256 RS384 RS512`). NOTE: this OP registers keys ONLY for `private_key_jwt` clients (`Client.Validate`, jwks-absent-for-non-pkj — a `client_secret_basic` DCR carrying a `jwks` is an honest 400, measured by the e2e), so a signed request object is a private_key_jwt-client feature; every other client sends unsigned objects | verified; its members are MERGED over the query (they supersede) and feed the unchanged pipeline — scope clamping, PKCE, `claims`, `acr_values`, `max_age` — so a parameter inside an object behaves exactly like the same parameter in the query |
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

Rule `ADDRESS-PHONE-TRUTHFUL-1`. The OIDC Core §5.1 `phone_number` and §5.1.1 structured
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

claims-parameter support (2026-09-02, implemented). OIDC Core §5.5 lets a
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
  bypass for an identity-only request (`openid`, `profile`, `email`),
  as for scopes.
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

code-reuse revocation (2026-09-02). RFC 6749 §4.1.2: on reuse of an
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

Rules `ACR-HONEST-1` and
`ACR-HONEST-2`. The OP
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
phishing-resistant authentication context): the conformance suite requests EVERY advertised
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

## RS256 — optional discovery advertisement, NEVER the default

`IDENTUUM_IDP_ADVERTISE_RS256` is a boolean setting, default `false`.
Unset or false preserves discovery's `[EdDSA, ES256]` list and the existing
keyset; it never automatically creates an RSA key. Invalid non-empty values
refuse startup without echoing the value. Go boolean spellings are accepted
(for example `true`, `false`, `1`, `0`), with surrounding whitespace trimmed.

Set it to `true` for conformance and certification: OpenID Connect Discovery
1.0 §3 requires RS256 in `id_token_signing_alg_values_supported`. Both discovery
builders then advertise `[EdDSA, ES256, RS256]` from one domain policy. Startup
reuses an active RSA signing key or generates one through KeyService. It
also ensures the normal EdDSA/ES256 signer exists on a fresh installation.
The decision that a key is missing and the insert run as one step under a
database lock, so processes starting together against one database create
one active RSA key and one default key, not one each; a rotating-only RSA
key still gets a new active one.
JWKS publishes the RSA public key. A startup line reports that RS256 is
advertised. A key read or creation failure enters NOT-SERVING with a named
health fault. Existing RSA keys are not removed when the option is disabled.

The repository's conformance appliance turns the option on. The config plan's
expected-failure file is empty; the former RS256 expected failure is removed.
The default-off posture does not meet this Discovery §3 MUST. Certification
needs the option on and a successful suite run; enabling it alone is no
certification claim.

What that means in this product:

- **RS256 is a real capability, advertised only with the option on.**
  `POST /api/v1/keys/generate` with `{"algorithm":"RS256"}` mints a real
  RSA-2048 signing key; it publishes in `/.well-known/jwks.json`; and it
  signs ID tokens for a client that registered it. This explicit key API
  remains available when the advertisement option is off. The advertised list
  and the registration allow-list have one source of truth each
  (`domain.IDTokenAdvertisedSigningAlgorithms` and
  `domain.IDTokenSigningAlgorithms`), and the rule `DISCOVERY-ALG-POLICY-1`
  keeps the advertised set a subset of the registrable set in both modes
  (a strict subset in the default mode).
- **RS256 is NEVER the default.** The issuer default is EdDSA (ES256
  fallback). An RS256 key — even present, active, and signing-capable —
  signs an ID token ONLY for a client that explicitly registered
  `id_token_signed_response_alg: "RS256"` (admin API or Dynamic Client
  Registration). Default initial key generation never produces RS256; the access-
  and logout-token signer never selects it; the auth KeyManager refuses to
  sign with it.
- **The option exists for conformance and interoperability.** EdDSA is the
  operational default. Advertising RS256 does not change the algorithm of
  any client that did not register RS256.

## PKCE — required for public clients (per-client setting, on by default), optional to send, never optional to honor

PKCE posture (same ruling): **per-client**. A PUBLIC client (no credential)
MUST send a `code_challenge` (S256 only) — the request is refused without
one. A CONFIDENTIAL client MAY omit PKCE entirely. But PKCE is only optional
to SEND, never to HONOR: any challenge that was supplied is validated and
its verifier is enforced at the token endpoint, and a code minted without a
challenge refuses a gratuitous verifier. A public client redeems its code
with `client_id` and `code_verifier` and no credential (discovery lists
`none` for the token endpoint only); it receives no refresh token.

**Per-client opt-out for testing (OSS-PUBLIC-CLIENT-PKCE-OPTION, owner
decision 2026-10-10).** "PKCE required" is a per-client setting,
`pkce_required`, true for every client by default; there is no server-wide
switch. The OpenID conformance public-client plan (`oidcc-test-plan` with
`client_auth_type=none`) sends no PKCE, so the conformance provisioning
(`conformance/provision.mjs`) creates its public test client with
`"pkce_required": false` through `POST /api/v1/clients` and checks that the
response echoes `client.pkce_required` false. Only an org_admin can turn it
off, only for a public client, and never through dynamic registration. With
it off the client may omit the challenge and redeem its code with
`client_id` alone; a challenge it sends is still S256-only and verified, and
`plain` is still refused. Production behaviour does not change unless an
admin opts a specific client out. Rule `PKCE-REQUIRED-DEFAULT-1`.

## Forced re-authentication — prompt=login and max_age

forced sign-in (2026-09-01). The authorize endpoint honors OIDC Core
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

## Auth verdicts — 401 is a verdict, 503 is a store error (AUTH-503)

authentication store-error handling (2026-09-02). **"a store/infra
error on the auth path answers 503 with an ERROR log and a correlation id;
401 is reserved for genuine verdicts. This changes STATUS and LOG, never the
refusal."**

**What was wrong (measured).** Every consumer on the authentication path
collapsed `err != nil` into the same unlogged `{"error":"unauthorized"}` a
bad token gets — `mw.BearerPrincipal` (verifier error, revocation-store
error, liveness-store error), `HandleValidateSession` (session and user
lookups), userinfo, introspection (`active:false`), the token endpoint
(`invalid_grant` / `invalid_client`), the browser cookie-session resolver
(a store error read as "anonymous" → bounced to login). The repositories
had always separated the two — a missing row is `domain.ErrSessionNotFound`
/ `ErrUserNotFound` / `ErrClientNotFound`, anything else is infrastructure —
so a transient database stall under load presented as "your session is
dead". Two harness hits: 2026-08-30 (three specs, one symptom) and
2026-09-02 (site-admin-admin-recovery bounced to `/login` while the SAME
cookie jar validated 200 one call later).

**What holds now.**

| answer | when | body | log |
|---|---|---|---|
| `401` | a VERDICT about the credential: absent, invalid, expired, revoked, mismatched, session/user/org not live | `{"error":"unauthorized","reason":"<verdict>"}` — reasons: `no_credential`, `missing_credential`, `token_invalid`, `token_revoked`, `session_not_live`, `token_not_session`, `session_not_found`, `session_not_usable`, `user_not_found`, `user_not_active`; ceremony pages answer `login_required` | none (a verdict is not an incident) |
| `503` | a STORE / INFRASTRUCTURE failure prevented the verdict (signing-key store, session, user, organization, revocation, refresh-token, client lookups) | `{"error":"temporarily_unavailable","reason":"auth_store_error","correlation_id":"<id>"}` + `X-Request-ID: <id>` + `Retry-After: 1`; browser ceremony pages get an HTML 503 with the same id | exactly one ERROR line `AUTH-503: auth-path store error — refused with 503, NOT an authentication verdict` with `where` (the lookup) and the same `correlation_id` |

Nothing is admitted either way. `domain.ErrAuthStoreUnavailable` names the
class (`domain.AuthStoreUnavailable(where, err)` wraps at the store sites);
`mw.RespondAuthStoreUnavailable` / `mw.RecordAuthStoreError` answer and log;
`mw.CorrelationIDMiddleware` (mounted globally, first after the security
headers) binds one id per request — the incoming `X-Request-ID` when it is
1–64 chars of `[A-Za-z0-9._-]`, else a fresh uuid — into the request context
so every `logger.*Context` line on that request carries `request_id`.
Introspection and userinfo use the `*Verdict` variants of the
IntrospectionService (the old methods keep their signatures). The token
endpoint maps the class in `emitTokenError` (503, never `invalid_grant` /
`server_error`). Refresh rotation and the authorization-code grant classify
their session / user / organization lookups the same way (typed not-found =
verdict; anything else = 503).

**Measured live (2026-09-02, dev appliance built from this tree).** With
postgres up, `GET /api/v1/validate` with `Authorization: Bearer garbage` →
`401 {"error":"unauthorized","reason":"token_invalid"}`, `X-Request-Id`
echoed. With the postgres container STOPPED, the same request →
`503`, `Retry-After: 1`, `X-Request-Id: demo-auth503-1`, body
`{"correlation_id":"demo-auth503-1","error":"temporarily_unavailable",
"reason":"auth_store_error",…}`, and the appliance logged exactly one
`{"level":"ERROR",…,"message":"AUTH-503: auth-path store error — refused
with 503, NOT an authentication verdict","where":"bearer.verify",
"correlation_id":"demo-auth503-1","error":"auth store unavailable:
signing-keys: failed to query signing keys: failed to connect to … no such
host","request_id":"demo-auth503-1"}`. Postgres restarted → `401
token_invalid` again. Before this slice that middle request was the same
unlogged `401 {"error":"unauthorized"}` as the first and the last.

**Hunting a transient.** Search the appliance log for `AUTH-503`; the line's
`where` names the lookup and `zap.Error` carries the driver text (never a
token). The id on the client's 503 body / `X-Request-ID` header is the join
key. The two-repo mint (`make test-full`) now records an `auth503-scan`
phase: after the whole run it prints every `AUTH-503` line the appliance
logged (count + lines) into the record — a fired transient is evidence,
never a red phase, because the UI retries 503s and the assertion that
matters is that no bare 401 was ever answered.

**Logout when the store cannot answer (logout store-error handling,
2026-09-02).** The last collapse sites were the two logout handlers:
`HandleEndSession` (`GET /api/v1/oidc/logout`) and
`HandleFrontchannelLogout` read a cookie-session store error as "no
session", cleared the cookie and silently skipped the revocation — the
session survived on the server while the browser believed it was gone. Now
(the ui's own logout pattern): on a store error while resolving OR revoking
(cookie session, browser token, hint session, bearer session) the cookie is
STILL cleared — the user asked to leave this device — but never silently:
one `AUTH-503` ERROR line (`where=logout.<lookup>`, the request's
correlation id), the audit event `user_session.logout.revocation_unconfirmed`
(`flow`, `where`, `reason=auth_store_error`, `correlation_id`; never a token
or cookie value) and the response header `X-Identuum-Logout:
revocation_unconfirmed` beside `X-Request-ID`. A session the store no longer
finds is not a store error: it is already ended, and the sign-out completes
as a success — for the hint session since OSS-CONFORMANCE-FIXES, for the
bearer session of `POST /api/v1/auth/logout` since OSS-HARDENING-2 (before,
a second sign-out of the same session answered `503 revocation_unconfirmed`),
and for every other revocation (the end-session cookie and bearer sessions,
the front-channel logout, the refresh-token logout and the self-service
session routes) since OSS-HARDENING-3.
RP-initiated end-session
still completes its redirect with `state` (the redirected audit carries
`revocation_unconfirmed: true`); if the CLIENT store did not answer the
`post_logout_redirect_uri` cannot be validated, so the browser gets the 503
page with the correlation id instead of a silent 204 (never an unvalidated
redirect). Front-channel (an invisible iframe): the same log + audit +
header, and the passive page adds "Signed out on this device. The
server-side sign-out could not be confirmed right now (reference <id>)";
beyond that there is nothing an iframe answer can honestly do — a 5xx would
only make RPs treat a fire-and-forget iframe as failed. A successful
revocation path is unchanged. Rule `LOGOUT-UNCONFIRMED-1` (red-proved by
mutation) pins the triple on both endpoints and that a healthy logout emits
neither the log line nor the event.

**Rules.** `AUTH-VERDICT-HONEST-1` (red-proved by mutation): a store error
never answers 401; a genuine verdict never answers 503 and always names its
reason; every 503 makes exactly one log-sink call carrying its correlation
id — pinned on the bearer middleware, `/api/v1/validate` and RFC 7662
introspection. `P0-JTI-1`'s sentence now says the store-error rejection is
the 503, not the 401. The ui's e2e asserts every auth 401 it meets carries a
reason and every 503 its correlation id (`expectHonestAuthBody`); the former
SESSION-REJECTION second-probe diagnostics are gone.

## What the suite does NOT cover (known, recorded — not forgotten)

- **Backup / restore** — the [operator procedure](OPERATOR-GUIDE.md#upgrading-and-rolling-back)
  is documented, but this suite does not exercise restoration.
- **Commercial-edition (CE) features** — out of scope for this repository's
  suite by rule; the affected tests are skipped by name and counted, and
  the count may not grow.

## The promise

The suite runs on its own throwaway installation, built fresh and destroyed
at the end, both on success and on failure. It never reads or writes your
development database, your volumes, or your credentials.
