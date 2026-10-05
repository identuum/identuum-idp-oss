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

> **Status:** this README describes `main`. Published releases are on the
> [Releases](https://github.com/identuum/identuum-idp-oss/releases) page,
> with each release's changes in [`CHANGELOG.md`](CHANGELOG.md) and its
> notes in [`docs/releases/`](docs/releases/). See Project Status above for
> the current license. The binary's version and commit are STAMPED at build
> time (`identuum-idp version` prints both; un-stamped builds report `dev` and
> `commit unknown`). The tag is cut by the owner, not by CI.

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
not an evaluation stub. It runs `identuum-idp`, which also serves the
[`identuum-ui`](https://github.com/identuum/identuum-ui) operator UI
(embedded in the binary since `v0.6.0`), plus a dedicated PostgreSQL
instance on one host, behind one Compose project.

```bash
curl -fsSLO https://github.com/identuum/identuum-idp-oss/releases/latest/download/docker-compose.yml
docker compose up -d
open http://localhost:7113
```

The compose file is an asset of the latest GitHub Release; it pins that
release's image by tag and digest. Its checksum is the release's
`docker-compose.yml.sha256` asset.

The Compose stack starts two services:

| Service | Port (host) | Purpose |
|---------|-------------|---------|
| `identuum-idp` | `7113` | OAuth 2.1 / OIDC Authorization Server, the operator UI and the first-run setup wizard, on one origin |
| `postgres` | _internal only_ | PostgreSQL 18 on the Compose network |

The published port binds the host address named by
`IDENTUUM_IDP_BIND_ADDRESS`, defaulting to `0.0.0.0` (IPv4, every
interface). For a loopback-only install:

```bash
IDENTUUM_IDP_BIND_ADDRESS=127.0.0.1 docker compose up -d
```

IPv4 is the default everywhere; IPv6 is supported and opt-in. Publish on
IPv6 with an IPv6 host address (`IDENTUUM_IDP_BIND_ADDRESS='[::]'`, or
`'[::1]'` for IPv6 loopback). One variable publishes one family; to publish
both, add a second mapping in an override file — the compose file's header
shows it. The bare binary follows the same rule: `--listen 0.0.0.0:7113`
(the default) is IPv4 only, `--listen '[::]:7113'` listens on IPv6 (and IPv4
where the OS gives a dual-stack socket).

Upgrading from `v0.5.x`, where the UI was a second container on `:7104`:
see [`docs/releases/v0.6.0.md`](docs/releases/v0.6.0.md), "Upgrading".

Do not run `docker compose down -v` against a live install: the compose
file pins its container and volume names, so `-v` deletes the install's
database and data under any project name.

Open `http://localhost:7113` in a browser — the UI detects the
first-run state, redirects to `/setup`, and runs the wizard. The
wizard prompts for the setup code, then for the initial organization
and site-administrator credentials. The setup code is printed to the
IDP boot log on every restart while the system is in `setup_required`
state, alongside the wizard URL and the local support command for
re-displaying it later:

```bash
docker compose exec identuum-idp /app/identuum-idp show-setup-code /app/data
```

(The image is distroless: the binary is `/app/identuum-idp` and is not on
the `PATH`.) The setup code authorises the wizard only. It is not the
administrator password — that you create during the wizard. After
the wizard completes, the setup APIs respond `410 Gone` and the
code is invalidated.

### First sign-in, organizations and users

1. **Sign in as the site administrator** at `http://localhost:7113/login`.
   The login is always `site_admin@system.local` (the wizard shows it); the
   password is the one you chose in the wizard. At this first sign-in you
   enrol an authenticator app (TOTP) and are shown one-time recovery codes;
   every later sign-in asks for a code, and a recovery code works there once
   in place of the authenticator's.
2. **Create an organization** in the console (**Organizations → New**) with
   the email of its administrator. The organization is inactive until that
   administrator activates it, so it is listed under **Deactivated**, not
   under the default list. The console shows a one-time **activation link**:
   hand it to the administrator. Without SMTP — the default — nothing is
   mailed; with SMTP the link is also mailed.
3. **The organization administrator opens the link**, sets a password,
   enrols an authenticator app and signs in at `/login` with that address.
4. **The organization administrator invites users** (**Users → Invite
   user**) and hands each one-time invite link over; the user sets a
   password at `/invite` and signs in. MFA follows the organization's
   policy. (Over the API an administrator may instead create a user with a
   password; that user is active and verified at once and, by default, must
   choose their own password at first sign-in — then MFA if the policy asks.
   See the operator guide, "Creating a user with a password instead".)
5. **The organization administrator registers an application**
   (**Applications → New**; the client secret is shown once) and points it at
   `/.well-known/openid-configuration`: authorization code with PKCE,
   refresh with `offline_access`, sign-out at the discovery document's
   `end_session_endpoint`.

The full operator detail — the two mail modes, re-issuing links, the API
equivalents — is in [`docs/OPERATOR-GUIDE.md`](docs/OPERATOR-GUIDE.md).

### Health and where data lives

- `docker ps` shows the container's health from `identuum-idp healthcheck`,
  which requires both `GET /healthz` (liveness: the process serves) and
  `GET /readyz` (the database answers). With the database down the container
  turns **unhealthy** while `/healthz` stays 200.
- Everything durable is in PostgreSQL (the `identuum-idp-oss-postgres-data`
  volume) plus the data volume `identuum-idp-oss-data` at `/app/data`, which
  holds the generated at-rest encryption key and, until setup completes, the
  setup code. Back both up; sessions survive a restart because they live in
  the database.

The Compose file under
[`deployment/docker-compose.yml`](deployment/docker-compose.yml) is
the canonical source. It is image-only: `docker compose up -d` pulls
`ghcr.io/identuum/identuum-idp-oss` from the official registry, and the
customer never compiles anything locally. See
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
| Go | 1.27.1 or newer — `go.mod`'s `go 1.27.1` line is authoritative; only needed for building from source |
| PostgreSQL | **18 or newer** — migration 0001 uses the built-in `uuidv7()` introduced in PG 18 |
| Docker + Compose plugin | Used by the customer-facing single-node install AND the developer `dev-*` / `fast-*` Make targets |
| `staticcheck` | `go install honnef.co/go/tools/cmd/staticcheck@latest` |
| `govulncheck` | `go install golang.org/x/vuln/cmd/govulncheck@latest` |
| `grype` | Anchore Grype — install with `brew install grype` or the upstream installer at https://github.com/anchore/grype#installation. `make verify` runs `grype dir:. --fail-on high`. |
| `rulefloor` | Only for `make verify` / `make rulefloor-check`. Resolved as `$RULEFLOOR_BIN`, then `rulefloor` on PATH, then a sibling `../rulefloor` checkout — see "Rule ledger" below. |
| `gograph` | Only for `make verify`, which runs `gograph capabilities`, `gograph build . --precise` and `gograph boundaries`. Not needed for `make fast-up`, `make integration-test`, or running the service. |

## Build and test from source

You need Go (as `go.mod` names it), Docker for a disposable PostgreSQL 18, and
the PostgreSQL client tools (`psql`, `createdb`):

```bash
git clone https://github.com/identuum/identuum-idp-oss.git
cd identuum-idp-oss

go build -o identuum-idp ./cmd/identuum-idp   # the binary, UI embedded
go test ./...                                  # unit tests; no database

# Integration tests against a disposable PostgreSQL 18 on 127.0.0.1:5513.
make fast-up               # start it
make test-db               # create and migrate the dedicated *_test database
make ci-integration-test   # the integration suite (-tags integration)
make fast-down             # remove it
```

The integration suite refuses any database whose name does not end in
`_test`: it truncates tables and replays setup.

Maintainers' gates (`make verify` and the release records) are described in
[docs/maintainers/README.md](docs/maintainers/README.md).

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
| `IDENTUUM_IDP_ENCRYPTION_KEY` | At-rest AES key (32 bytes / 64 hex); encrypts MFA seeds at rest. **Optional in the image** — its entrypoint auto-generates + persists one on first boot; **required for the bare binary**. Production **should** supply a real externally-managed key (see below) |
| `IDENTUUM_IDP_DATA_DIR` | Where the setup code is written while setup is incomplete (`/app/data` in the image; unset: `<user config dir>/identuum-idp`) |
| `IDENTUUM_IDP_UI_PUBLIC_BASE_URL` | The UI's browser-facing base URL, used to build activation and invite links (the binary's own origin, e.g. `http://localhost:7113`); unset, the IdP answers `*_url_unavailable` instead of a link |
| `IDENTUUM_IDP_ISSUER` | Public issuer URL (e.g. `https://idp.example.com`) |
| `IDENTUUM_IDP_LISTEN` | Serve/listen address (default `0.0.0.0:7113`, IPv4 only; `[::]:7113` adds IPv6, an IPv6 literal binds that address; `--listen` flag overrides) |
| `IDENTUUM_IDP_TRUSTED_PROXIES` | Comma-separated reverse-proxy addresses or CIDRs, IPv4 or IPv6 (e.g. `10.0.0.0/8,2001:db8:1::/48`), whose `X-Forwarded-For` is honoured; unset trusts none |

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

## Running the bare binary (no Docker, no Makefile)

The binary alone runs the whole product, UI included; it needs only a
PostgreSQL 18+ database. From `v0.7.0` each release ships it for
`linux/amd64` and `linux/arm64`, with a `SHA256SUMS` file and a
build-provenance attestation per binary. Download, check and install it
(`ARCH=arm64` on an ARM host):

```bash
# The latest release (set VERSION yourself to install another one).
VERSION=$(curl -fsSLI -o /dev/null -w '%{url_effective}' https://github.com/identuum/identuum-idp-oss/releases/latest | sed 's#.*/tag/v##')
ARCH=amd64
BASE=https://github.com/identuum/identuum-idp-oss/releases/download/v${VERSION}
curl -fsSLO "${BASE}/identuum-idp-oss_${VERSION}_linux_${ARCH}"
curl -fsSLO "${BASE}/SHA256SUMS"
sha256sum --ignore-missing -c SHA256SUMS
# Optional, with the GitHub CLI: proves the binary was built by this
# repository's release workflow.
gh attestation verify "identuum-idp-oss_${VERSION}_linux_${ARCH}" -R identuum/identuum-idp-oss
install -m 0755 "identuum-idp-oss_${VERSION}_linux_${ARCH}" ./identuum-idp
./identuum-idp version
```

Or build it from this repository (Go, as `go.mod` names it; the UI is
embedded from the vendored tree): `go build -o identuum-idp ./cmd/identuum-idp`.

Then configure it through the environment, **migrate, and serve**. Unlike
the image's entrypoint, the bare binary does not migrate on start: on an
unmigrated database it stops at once with "the database is not migrated —
run `identuum-idp migrate <database-url>` before serving".

```bash
# Your database; this example is the compose file's local-only dev account.
export IDENTUUM_IDP_DATABASE_URL='postgres://identuum_idp:dev-identuum_idp-not-a-secret@127.0.0.1:5432/identuum_idp?sslmode=disable'
# Required: seals MFA secrets and signing keys at rest. Generate it once and
# keep it — losing it makes existing MFA enrolments and keys unreadable.
export IDENTUUM_IDP_ENCRYPTION_KEY="$(openssl rand -hex 32)"
export IDENTUUM_IDP_ISSUER=http://localhost:7113
export IDENTUUM_IDP_LISTEN=127.0.0.1:7113
# Where the setup code is written (default: <user config dir>/identuum-idp,
# for example ~/.config/identuum-idp — never the working directory).
export IDENTUUM_IDP_DATA_DIR=/var/lib/identuum-idp

./identuum-idp migrate "$IDENTUUM_IDP_DATABASE_URL"
./identuum-idp
```

The boot log prints the wizard URL and the setup code; re-display it with
`./identuum-idp show-setup-code "$IDENTUUM_IDP_DATA_DIR"`. Check health with
`./identuum-idp healthcheck http://127.0.0.1:7113`. `./identuum-idp help`
lists every subcommand. (Developers: `make oss-up` builds the local image
and runs it on `127.0.0.1:7113`.)

The setup wizard creates the first EdDSA signing key (the headless
`bootstrap` subcommand does too). Further keys can be generated by the
site administrator:

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

## First-run setup (how it works)

The `docker compose up -d` → browser-wizard flow ships end to end (the
wizard is part of the embedded UI). Its parts:

- A single-row `system_setup_state` migration (0019) tracking
  `setup_required` → `setup_complete`.
- An IDP-generated setup code persisted as plaintext in
  `$IDENTUUM_IDP_DATA_DIR/setup-token.txt` (mode 0600; `/app/data` in the
  image; unset, the per-user config directory's `identuum-idp`, never the
  working directory) and as a
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
    (audited as `setup.completed` and `user_created`)
- A zero-credential local support command (in the image:
  `/app/identuum-idp show-setup-code /app/data`):
  ```bash
  identuum-idp show-setup-code <data-dir>
  ```
  Reads the on-disk token file and prints it. Exits non-zero with a
  diagnostic when setup is already complete (no file) or the data
  directory is missing.
- The wizard at `/setup` (embedded identuum-ui) drives this surface. The
  site administrator's authenticator is enrolled at the first sign-in,
  not in the wizard.

The `bootstrap` and `recover-site-admin` operator subcommands remain the
supported headless recovery path. The wizard does not replace them.

## Port allocation

| Port | Use |
|------|-----|
| **5513** | the local PostgreSQL of `make fast-up` and the integration tests |
| **7113** | `cmd/identuum-idp` serve address |

## Module hygiene

- No `go.work` at any level.
- No `replace` directives in `go.mod`.
- No import outside this module and the dependencies `go.mod` declares:
  `go list -deps ./...` names only the standard library, this module's
  packages and modules listed in `go.mod`.

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
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — bug reports, feature requests and pull requests
- [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md) — community standards
- [`THIRD_PARTY_NOTICES`](THIRD_PARTY_NOTICES) — third-party licences
- [`docs/GETTING_STARTED.md`](docs/GETTING_STARTED.md) — extended
  walk-through
- [`docs/OPERATOR-GUIDE.md`](docs/OPERATOR-GUIDE.md) — operating an install
- [`deployment/README.md`](deployment/README.md) — the compose install and
  the release artefacts
- [`docs/releases/`](docs/releases/) — release notes
- [`docs/maintainers/`](docs/maintainers/README.md) — maintainer gates,
  records and test plans
