# identuum-idp-oss

Copyright © 2026 Ozgur Demir. All rights reserved.

## Project Status

This repository is currently published for public inspection and
evaluation only.

- Not currently open source
- External contributions are not accepted
- No permission is granted to use, modify, redistribute, sublicense, or
  create derivative works, except as necessarily required by GitHub's
  Terms of Service and applicable law
- Current repository license: `LicenseRef-AllRightsReserved` (see
  [`LICENSE`](LICENSE))
- Licensing terms may change in a future release

---

Starter-tier core of the [Identuum](https://identuum.ai) identity
provider. `identuum-idp-oss` ships the Starter-tier OAuth 2.1 /
OpenID Connect surface as a self-contained Go module that you can run
on your own infrastructure.

> **Status:** first public release, `v0.3.3` — see Project Status above for
> the current license. The binary's version is STAMPED at build time from
> the release tag (`-ldflags -X main.buildVersion=…`; un-stamped builds
> report `dev` and can never pass the publish gate). Latest release notes:
> `docs/releases/v0.3.3.md`; the tag is cut by the owner, not by CI. The
> codebase passes the full validation matrix described below.

---

## What this is

- An OAuth 2.1 + OIDC Authorization Server that you self-host.
- Local credential auth, TOTP MFA, WebAuthn / passkeys, sessions,
  service accounts, OAuth clients, API resources, scope templates,
  org / user management, key management, OIDC discovery + JWKS,
  RFC 7662 introspection, RFC 7009 revocation, RFC 7591 Dynamic
  Client Registration (foundation), and Front-Channel /
  Back-Channel Logout 1.0 metadata + back-channel delivery.
- A single Go binary plus PostgreSQL 18+. No external services
  required for the OSS surface.

## What this isn't

- It is not the CE edition (`identuum-idp-ce`), which is licensed
  separately (see this repository's own [`LICENSE`](LICENSE) for the
  OSS core's current terms). PAR, managed/multi-IdP OIDC federation, audit log,
  reports, webhooks, MCP server, advanced DCR, LDAP, SCIM 2.0, SPIFFE,
  dynamic vault, and SIEM export live in CE. (Basic single-provider
  upstream OIDC login — OSS as relying-party to one generic OIDC
  provider — is OSS-core and SHIPPED end-to-end: configure one OIDC
  provider per org, then sign in through it; per-org managed /
  multi-IdP federation and LDAP/AD remain CE.)
- It is not OpenID-Foundation certified. Offline structural OIDC
  validation has passed; formal certification requires running the
  OpenID Foundation conformance suite against a hosted TLS
  deployment.
- It is not a turnkey production drop-in by itself. You are
  responsible for TLS termination, secret management, key custody,
  database backups, and operational monitoring.
- It is not horizontally scalable. OSS runs as a **single replica by
  design** — rate limiting, WebAuthn ceremony state, and the browser
  CSRF secret are per-process. A DB-backed instance lease enforces
  this: a second instance refuses to serve (503) rather than serving
  with silently-broken per-process security. Horizontal scaling / HA is
  a Professional+ commercial capability. See
  [Single-replica by design](#single-replica-by-design).

## Self-hosted install (single-node)

The single-node self-hosted install is a real product install path,
not an evaluation stub. It runs `identuum-idp` plus the
[`identuum-ui`](https://github.com/identuum/identuum-ui) operator UI
plus a dedicated PostgreSQL instance on one host, behind one Compose
project.

```bash
curl -fsSLO https://downloads.identuum.com/idp-oss/docker-compose.yml
docker compose up -d
open http://localhost:7104
```

The Compose stack starts three services:

| Service | Port (host) | Purpose |
|---------|-------------|---------|
| `identuum-ui` | `7104` | Browser entry point and first-run setup wizard |
| `identuum-idp` | `7113` | OAuth 2.1 / OIDC Authorization Server |
| `postgres` | _internal only_ | PostgreSQL 18 on the Compose network |

Open `http://localhost:7104` in a browser — the UI detects the
first-run state, redirects to `/setup`, and runs the wizard. The
wizard prompts for the setup code, then for the initial organization
and site-administrator credentials. The setup code is printed to the
IDP boot log on every restart while the system is in `setup_required`
state, alongside the wizard URL and the local support command for
re-displaying it later:

```bash
docker compose exec identuum-idp \
    identuum-idp show-setup-code /app/data
```

The setup code authorises the wizard only. It is not the
administrator password — that you create during the wizard. After
the wizard completes, the setup APIs respond `410 Gone` and the
code is invalidated.

The Compose file under
[`deployment/docker-compose.yml`](deployment/docker-compose.yml) is
the canonical source. It is image-only: `docker compose up -d` pulls
`ghcr.io/identuum/identuum-idp-oss` and `ghcr.io/identuum/identuum-ui`
from the official registry, and the customer never compiles anything
locally. The customer command flow above becomes literal once those
two tags are published — see
[`deployment/README.md`](deployment/README.md) for the manual
maintainer publish workflow.

Maintainers who need to rebuild from a local sibling-tree checkout use
the developer overlay at
[`deployment/docker-compose.build.yml`](deployment/docker-compose.build.yml);
see [`deployment/README.md`](deployment/README.md) for the exact
invocation. The overlay is maintainer-only and is not part of the
customer install path.

> **Scope of this slice.** Production hardening (HA Postgres, external
> KMS, reverse proxy with TLS, generated-on-first-boot DB credentials,
> backup automation, OSS-to-CE upgrade overlay) is intentionally out
> of scope; each is queued in the maintainers' planning wiki
> (private) as its own future slice.

### Single-replica by design

identuum-idp-oss is engineered to run as **exactly one replica**.
Several security mechanisms hold state **in-process** — they are correct
for one replica and silently broken across replicas:

- **Rate limiting** is a per-process token-bucket map, so N replicas
  grant N× every mounted limit.
- **WebAuthn ceremonies** keep challenge state in an in-process map, so
  a ceremony begun on one replica cannot finish on another.
- **The browser CSRF secret** is generated fresh per process, so
  replicas cannot validate each other's tokens.

Rather than *assume* a single replica, OSS **enforces** it. On startup
each instance acquires a **DB-backed singleton lease** and heartbeats
it. An instance that cannot acquire a live lease **refuses to serve**:
it stays alive but returns `503` on normal routes, reports the fault on
`GET /health`, keeps `/livez` up, and logs a loud `ERROR` naming the
incumbent — it never serves with broken per-process security (this is
the P-018 NOT-SERVING-JUST-ALERTING posture; it never panics or exits).

**Rolling deploys still work.** On graceful shutdown the outgoing
instance releases the lease and the incoming instance acquires it
immediately; if the outgoing instance dies ungracefully, its lease
lapses after the TTL (≈45 s) and the incoming instance — which retries
for a bounded window (≈60 s) — takes over. A rollout is not an outage.

**Horizontal scaling / high availability is a Professional+ commercial
capability.** To *knowingly* run multiple replicas of the OSS build,
set `IDENTUUM_IDP_ALLOW_MULTI_REPLICA=true`. This disables the lease and
prints a loud startup **WARNING** listing exactly what degrades — it is
never a silent bypass.

## Prerequisites

| Requirement | Notes |
|-------------|-------|
| Go | 1.26 or newer (the repo's `go.mod` is the source of truth); only needed for building from source |
| PostgreSQL | **18 or newer** — migration 0001 uses the built-in `uuidv7()` introduced in PG 18 |
| Docker + Compose plugin | Used by the customer-facing single-node install AND the developer `dev-*` / `fast-*` Make targets |
| `staticcheck` | `go install honnef.co/go/tools/cmd/staticcheck@latest` |
| `govulncheck` | `go install golang.org/x/vuln/cmd/govulncheck@latest` |
| `grype` | Anchore Grype — install with `brew install grype` or the upstream installer at https://github.com/anchore/grype#installation. `make verify` runs `grype dir:. --fail-on high`. |
| `rulefloor` | Only for `make verify` / `make rulefloor-check`. Resolved as `$RULEFLOOR_BIN`, then `rulefloor` on PATH, then a sibling `../rulefloor` checkout — see "Rule ledger" below. |
| `gograph` | Only for `make verify`, which runs `gograph capabilities`, `gograph build . --precise` and `gograph boundaries`. Not needed for `make fast-up`, `make integration-test`, or running the service. |

Both rows above were missing until 2026-09-04: `make verify` has invoked
`rulefloor` and `gograph` for months while this table listed neither, so a
newcomer reading only the Prerequisites could not have assembled the toolchain
that section asks for. `make verify` also needs the private maintainers' wiki as
a sibling — see the note under "Developer quickstart".

## Developer quickstart

The `make verify`, `make fast-*`, `make dev-*`, and
`deployment/docker-compose.dev.yml` targets are maintainer-facing
convenience only. They are not the customer install path; see the
"Self-hosted install" section above for that.

> **`make verify` does NOT run from a fresh clone, and that is by design.**
> Measured 2026-09-04 by cloning this repository into an empty directory and
> following this section verbatim: it fails at the `repo-green` target with
> `bash: ../wiki/tools/repo-green-gate.sh: No such file or directory`, because
> several of its gates live in the maintainers' wiki repository, which is
> private and is not a sibling of your clone. `make verify` is the MAINTAINER
> gate set, not a newcomer's first command. Everything else in this section
> works from a clean clone — that was measured in the same run.
>
> From a fresh clone, start with `make fast-up` and `make integration-test`
> below, or with the "Running locally" section further down, which was measured
> end to end from the same clone: build, `migrate`, serve, and `/health` 200.

```bash
git clone https://github.com/identuum/identuum-idp-oss.git
cd identuum-idp-oss

# Build + unit tests + staticcheck + govulncheck.
# MAINTAINERS ONLY — needs the private ../wiki sibling; see the note above.
make verify

# Start a throwaway local Postgres on 127.0.0.1:5513.
make fast-up

# Run the build-tagged integration suite. It runs against a DEDICATED
# `identuum_idp_oss_test` database (created + migrated by `make test-db`,
# which `integration-test` invokes first), NEVER the dev database: these
# suites TRUNCATE and replay setup, and the harness REFUSES any DSN whose
# database name does not end in `_test` (TEST-DB-ISOLATION-1). Point it
# elsewhere with IDENTUUM_IDP_TEST_DATABASE_URL, or set
# IDENTUUM_IDP_ALLOW_NON_TEST_DB=1 for a genuinely disposable database.
make integration-test

# Tear it down.
make fast-down
```

The full one-shot validation chain (clean DB → up → integration tests
→ down) is `make validate`.

### Rule ledger (RULE-FLOOR.md)

`make verify` includes `make rulefloor-check`, which verifies the
machine-checked rule ledger at the repo root with the rulefloor CLI,
resolved in order: `$RULEFLOOR_BIN` if set, `rulefloor` on PATH, then
building the sibling `../rulefloor` checkout as last resort. Candidates
are probed through the machine interface `version --json`
(rulefloor.version.v1) — v0.3.0 or newer only; a stale PATH binary
falls through to the sibling. No resolvable binary is CANNOT-EVALUATE
and fails `verify` — there is no skip. CI's `ci-verify` runs the SAME
target: the verify job installs the pinned tool
(`go install github.com/ozgurcd/rulefloor@v0.3.0`; see ci.yml).
Integration-profile rows are verified statically by
plain `verify` and EXECUTED by `make rulefloor-integration`, which
`make integration-test` chains after the suite. The tool's feature set
is discovered, never assumed: `rulefloor capabilities --json`.

How the ledger works — the format, commands, exit codes, guarantees —
is the tool's documentation (`../rulefloor/README.md`). What this
project's profile names mean, the red-proof text format we write, and
the burndown method are project POLICY:
[docs/RULE-FLOOR-CONVENTIONS.md](docs/RULE-FLOOR-CONVENTIONS.md).

## Configuration

Copy the example env file and edit local values:

```bash
cp dev.env.example dev.env.local
```

Important environment variables:

| Variable | Purpose |
|----------|---------|
| `IDENTUUM_IDP_DATABASE_URL` | Postgres DSN used at runtime |
| `IDENTUUM_IDP_TEST_DATABASE_URL` | Postgres DSN used by the integration harness |
| `IDENTUUM_IDP_ENCRYPTION_KEY` | At-rest AES key (32 bytes / 64 hex); encrypts MFA seeds at rest. **Optional** — auto-generated + persisted on first boot if unset. Production **should** supply a real externally-managed key (see below) |
| `IDENTUUM_IDP_ISSUER` | Public issuer URL (e.g. `https://idp.example.com`) |
| `IDENTUUM_IDP_LISTEN` | Serve/listen address (default `0.0.0.0:7113`; `--listen` flag overrides) |

The values in `dev.env.example` are **throwaway local-development**
constants only. Do not use them in any environment that holds real
data.

### At-rest encryption key

`IDENTUUM_IDP_ENCRYPTION_KEY` (32 bytes / 64 hex) encrypts MFA TOTP seeds at
rest. The runtime fails closed if it is missing or malformed: an absent or
invalid key records a startup-fatal and the IdP comes up **NOT-SERVING**
(refusing traffic with `503`), so the deployment surface must always provide
one.

- **Zero-config (default):** the container entrypoint (the binary's `appliance`
  subcommand — there is no shell in the image) auto-generates a key with
  `crypto/rand` and persists it 0600 to the data volume on first boot, then
  reuses it on every reboot. A fresh
  `docker compose up` therefore comes up serving with no manual step.
- **Production:** supply your own externally-managed key via the environment
  (`IDENTUUM_IDP_ENCRYPTION_KEY=$(openssl rand -hex 32)`) rather than relying on
  the volume-persisted key. The persisted file lives inside the data volume —
  convenience, not strong key separation — and an operator-supplied env key
  always wins (it is used as-is; the file is never written or overwritten).
- **Key loss:** if the key is lost or changed, previously-encrypted MFA secrets
  become unrecoverable and affected users must re-enroll. Back up the key (or
  manage it externally) alongside the database.

## Running locally

The Makefile exposes two ways to run the service against the local
Postgres:

- `make oss-up` — builds the local Docker image and runs the app
  container on `127.0.0.1:7113`.
- Direct binary execution:

  ```bash
  go build -o identuum-idp ./cmd/identuum-idp

  # Apply embedded migrations (one-shot subcommand; URL is a positional arg).
  ./identuum-idp migrate \
    "postgres://idp_oss_user:dev-idp_oss_user-not-a-secret@127.0.0.1:5513/identuum_idp_oss?sslmode=disable"

  # Serve (default action, no subcommand). Serving REQUIRES the at-rest key —
  # 0000…0001 is a PUBLIC dev key, local-only. Flags default from the env
  # (IDENTUUM_IDP_DATABASE_URL / _ISSUER / _LISTEN); run `identuum-idp help`.
  IDENTUUM_IDP_ENCRYPTION_KEY=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f \
    ./identuum-idp \
      --database-url "postgres://idp_oss_user:dev-idp_oss_user-not-a-secret@127.0.0.1:5513/identuum_idp_oss?sslmode=disable" \
      --issuer "http://localhost:7113" \
      --listen 127.0.0.1:7113
  ```

A fresh deployment has zero signing keys. Before tokens can be
issued, an operator must complete site-admin bootstrap and then
generate the first signing key:

```http
POST /api/v1/keys/generate
Authorization: Bearer <site_admin_access_token>
Content-Type: application/json

{"algorithm":"EdDSA"}
```

`algorithm` may be `EdDSA` (preferred) or `ES256`. **`RS256` is
rejected by the OSS issuance path** — `id_token_signing_alg_values_supported`
excludes RS256 by design. (Inbound `private_key_jwt` client assertions
may still use RS256; the two settings are separate.)

## First-run setup (under development)

The appliance-style first-run setup foundation is in place but the full
customer-facing `docker compose up -d` → browser-wizard flow is still
under construction. What ships today:

- A single-row `system_setup_state` migration (0019) tracking
  `setup_required` → `setup_complete`.
- An IDP-generated setup code persisted as plaintext in
  `$IDENTUUM_IDP_DATA_DIR/setup-token.txt` (mode 0600) and as a
  SHA-256 hash in the database. While setup is incomplete, the
  serve boot log prints the wizard URL, the plaintext code,
  and the local `show-setup-code` command. Once setup completes the
  file is deleted, the hash is cleared, and the setup APIs respond
  `410 Gone`.
- Three public endpoints under `/api/setup/`:
  - `GET  /api/setup/status` — no-secrets snapshot of setup state
  - `POST /api/setup/verify-token` — checks a candidate setup code
  - `POST /api/setup/complete` — creates the first organization,
    site administrator, and EdDSA signing key, then flips state
- A zero-credential local support command:
  ```bash
  identuum-idp show-setup-code <data-dir>
  ```
  Reads the on-disk token file and prints it. Exits non-zero with a
  diagnostic when setup is already complete (no file) or the data
  directory is missing.
- A first-pass setup wizard lives in `identuum-ui` and drives this
  surface; see that repo for the UI side.

The `bootstrap` and `recover-site-admin` operator subcommands remain the
supported headless recovery path. The wizard does not replace them.

Owner decisions binding all of the above are recorded in the
maintainers' planning wiki (private; decision ids D-IDP-INSTALL-09
through D-IDP-INSTALL-25).

## Validation matrix

The repo-local close gate is `make verify`. Its recipe in `Makefile` is the
source of truth; in order, it runs:

1. `repo-green` (gofmt, build, vet, and the untagged Go test suite).
2. The tracked-binary and credential-transparency checks.
3. `rulefloor-check` (unit rows execute; integration-profile rows are checked
   statically here), then `ledger-diff-gate`: `rulefloor ledger-diff` against
   the previous accepted witness commit, reconciled both ways with the
   committed single-use manifest `ledger-amendments.json` — a ledger
   sentence never changes silently (see `docs/RULE-FLOOR-CONVENTIONS.md` §e).
4. Image-base policy, integration vet, doc-comment, R-suite, image-parity, and
   image-policy-restatement checks.
5. Clock-fuse reporting plus its snapshot gate, tagged-file vet, and the
   integration inventory that names tests this Docker-free aggregate did not
   execute.
6. A precise gograph rebuild followed by
   `gograph boundaries --config boundaries.json`. This is part of the full
   local gate, not an optional review command.
7. `go mod tidy -diff`, `staticcheck ./...`, `govulncheck ./...`, wiki
   freshness, and `grype dir:. --fail-on high`.

```bash
make verify
```

The short command list previously printed here as "equivalent" was not
equivalent: it omitted the architecture boundary check and most repo-specific
gates. Do not substitute it for `make verify`.

What this close gate does not cover is equally explicit:

- It does not execute DB-backed integration tests or integration-profile
  Rulefloor rows; use `make integration-test` (or the `make validate` live
  chain). `integration-inventory` reports the current skipped population.
- It does not run `staticcheck -tags integration`; that belongs to
  `make integration-staticcheck`.
- It does not run the race detector locally; `ci-verify` runs the untagged
  suite with `-race`.
- It does not boot Docker Compose, exercise a live appliance or rotation,
  execute browser/UI tests, contact external services, or consume operator
  secrets. Those are separate integration, smoke, or sibling-repository gates.
- CI's `ci-verify` does not execute gograph or the boundary policy because CI
  does not install gograph. It pins that the local full gate still contains the
  boundary command, but new boundary violations are evaluated only by the
  repo-local `make verify` invocation.

Integration tests (require a running Postgres 18+):

```bash
go build -tags integration ./...
staticcheck -tags integration ./...
go test -tags integration ./internal/e2e/... -count=1 -v
```

The integration harness reads its DB URL from
`IDENTUUM_IDP_TEST_DATABASE_URL` (preferred) or
`IDENTUUM_IDP_DATABASE_URL`. It skips cleanly when neither is set, so
it will never block CI on a missing DB.

## Port allocation

| Port | Module |
|------|--------|
| 5432 | monolith Postgres (avoid) |
| 5532 | identuum-ag monolith Postgres (avoid) |
| 5533 | identuum-ag-oss Postgres (avoid) |
| 5534 | reserved |
| **5513** | **identuum-idp-oss Postgres** |
| 7113 | `cmd/identuum-idp` serve address |

## Module hygiene

- No `go.work` at any level.
- No `replace` directives in `go.mod`.
- `identuum-idp-oss` MUST NOT import `identuum-idp-ce`,
  `identuum-idp/internal`, `identuum-ag*`, `identuum-ui`,
  `auth-service`, or `internal-tools`. Verify with:

  ```bash
  go list -deps ./... | grep -E \
    'identuum-idp-ce|identuum-idp/internal|identuum-ag|identuum-ui|auth-service|internal-tools'
  # must return zero lines
  ```

## Security

**Do not open a public issue for security vulnerabilities.** Follow
the private disclosure process in [`SECURITY.md`](SECURITY.md). The
canonical contact is **`contact@identuum.ai`**.

## License

See [`LICENSE`](LICENSE). `identuum-idp-oss` is currently published for
viewing and evaluation only — no license to use, copy, modify,
distribute, or create derivative works is granted. See [`NOTICE`](NOTICE)
for attribution. External contributions are not being accepted at this
time.

## Further reading

- [`CHANGELOG.md`](CHANGELOG.md) — per-release changes
- [`SECURITY.md`](SECURITY.md) — vulnerability disclosure
- [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md) — community standards
- [`docs/GETTING_STARTED.md`](docs/GETTING_STARTED.md) — extended
  walk-through
- [`docs/PUBLICATION_CHECKLIST.md`](docs/PUBLICATION_CHECKLIST.md) —
  release / publication workflow (maintainer-facing)
- [`docs/ARCHIVE.md`](docs/ARCHIVE.md) — historical phase-by-phase
  development log (non-authoritative reference only)
