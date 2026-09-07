# Changelog — identuum-idp-oss

All notable changes to `identuum-idp-oss` are recorded here, starting from
the first public release. Format roughly follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning
follows [Semantic Versioning](https://semver.org/).

## Unreleased

## `v0.4.0`

The public API is frozen: `pkg/` holds exactly the six packages the
commercial edition imports — `features`, `licenseprovider`, `oidc`, `pkce`,
`totp`, `webauthn` — and a gate keeps it so. The three `pkg/` directories
nobody outside this repository imported (`migrations`, `runtime`, `server`)
moved under `internal/pkg/` (decision P-061). That is a change to the
module's import surface, hence `0.4.0` and not `0.3.8`. Measured delta
`v0.3.7..v0.4.0`: 12 commits (4 witness records, 4 manifest re-bases, 1 CI
record, 3 others), 19 files changed, +258/−93. No migration added, no
dependency moved, Go
1.27.1 unchanged; no endpoint changed.

### Changed

- **`pkg/migrations`, `pkg/runtime`, `pkg/server` → `internal/pkg/…`**
  (`d1b9830`). Measured first at `d461bd7`: inside this repository each was
  imported only by its own test, `pkg/runtime` also by
  `cmd/identuum-idp/main.go`; identuum-idp-ce's dependency closure named
  none of them; identuum-ui and the AG repositories import no OSS package.
  Package names, identifiers and behaviour are unchanged — only the import
  path moved. The destination is `internal/pkg/<name>` rather than
  `internal/<name>` because `internal/runtime` and `internal/server` already
  exist as the authorities the two shims alias. An importer of the old
  paths (there was none) would fail to compile; that is the SemVer minor.
  The `boundaries.json` rules follow the packages.

### Verification machinery (repository-visible, not in the binary)

- **`api-surface`** (`958a7d7`) — a Makefile gate in both `verify` and
  `ci-verify`: red unless the directories directly under `pkg/` are
  exactly the six above, each extra or missing directory named; red-proved
  with an untracked `pkg/decoy/` and with `pkg/totp` moved aside. `verify`
  runs 32 targets (was 31), `ci-verify` 25. The CI matrix comment and two
  workflow comments that still said `pkg/runtime` were corrected.
- CI run 34149894245 at `eb54e7f` (the gate commit's witness) green on all
  four jobs; its `ci-verify` record — 25 targets, `api-surface` among them —
  is committed as `CI-WITNESS.txt` (`fe82a71`).

## `v0.3.7`

Intermediate release on the v0.3 train, cut so identuum-idp-ce can pin a tag
instead of a pseudo-version (a pseudo-version's base-tag validation
unshallows the module-cache clone, and GitHub's runners on git 2.55.0 die
there with `fatal: shallow file has changed since we read it`). Measured
delta `v0.3.6..v0.3.7`: 305 commits (81 witness records, 11 manifest
re-bases, 4 CI records, 209 others), 445 files changed, +45336/−2588.
Eight migrations added (`0032`–`0039`); Go 1.27.1; eleven dependency bumps.
The Go source is identical to `f8a1e6a`, which identuum-idp-ce compiled and
vetted against clean and which CI run 34115127258 proved green.

### Added

- **Forced re-authentication** — `prompt=login` and `max_age` at the
  authorize endpoint; the login page is marked when re-authentication is
  forced (`a45c186`, `41add7b`).
- **The `claims` request parameter** — honored, consent-gated and
  role-intersected (`afffe86`); the **full OIDC profile** modelled (unset is
  never emitted; consent echoes `max_age`) (`0cabdc3`); **`address` and
  `phone` claims** as real profile fields with scope/claims release
  (`1a5fda9`); locale validated as RFC 5646 syntax (`d43044c`).
  Migrations `0034_claims_parameter`, `0035_user_profiles`,
  `0036_address_phone`.
- **Request objects by value** — verified against registered keys or
  unsigned; `request_uri` refused (`8dbcb01`).
- **Per-client PKCE, testing-only RS256** and the conformance findings they
  exposed (`ae6f837`); RS256 is a per-client registration again and discovery
  advertises what the issuer signs with (`d9ab771`). Migration
  `0032_client_id_token_alg`.
- **Scope stamping and replay revocation** — consented ∩ role-permitted scope
  is stamped on authorization-code access tokens (`37f3af7`); a replayed
  authorization code revokes what it minted (`58cc5a8`). Migration
  `0033_authcode_issued_tokens`.
- **Agent communication (AYGHU)** — the AgentCommunicationAuthorization
  aggregate with invariants and a canonical policy digest (`3d7dbc3`); the
  org_admin own-org admin API create/list/get/revoke with no existence oracle
  (`82bf8d6`); DPoP-bound participant tokens by client credentials
  (`32717fd`); observable revocation of issued participant `jti`s
  (`d4ab9cf`); introspection judged against the authorization (`ec2d785`);
  the creating org_admin owns the service account (`ea5e283`), owners can be
  set later (`c3cda23`). Migrations `0037_agent_communication_authorizations`,
  `0038_dpop_proof_replays`, `0039_agent_communication_tokens`.
- **Operators** — `rotate-encryption-key`, offline at-rest key rotation,
  atomic and resumable, refusing unknown schemas, with a doctor census and
  runbook (`47fb156`, `4b1abac`, `a916eba`); `audit-preupgrade`, the
  read-only sweep for rows the guards refuse (`19cb94b`); provenance
  announce and stale-binary refusal (`55eb706`); `create-organization` with
  absent `active` meaning ACTIVE and `admin_email` honored atomically
  (`f42c87b`); organization lifecycle filter on the list and deactivated
  organizations reachable on detail (`67a62f6`); activation returns the
  link that consumes the token or says why there is none (`6450c9b`);
  `INSECURE_DEV_MODE`, the named test-only rate-limit escape hatch
  (`da653e6`); a manual OpenID conformance harness, `make
  openid-conformance` (`1541270`).

### Changed

- **Auth path truthfulness (AUTH-503)** — a store error on the auth path
  answers `503` with an ERROR log line and a correlation id, never `401`;
  every `401` names its reason (`73070bd`); a logout that cannot revoke
  still clears the cookie but never passes silently (`9674215`).
- **Cookies** — the session cookie and the browser-login CSRF cookie take
  `Secure` from the request transport, decoupled from `gin.Mode`
  (`b71ff9f`, `ad02bc0`, `0a9cdb2`).
- **`site_admin` on tenant surfaces** — refused on the tenant OAuth-client
  surface, domains, protocol-settings, rbac-roles, service-accounts and
  api-resources (`1dcd479`, `15e235f`, `a813b4d`); scope templates invert to
  org_admin with the reserved-prefix validation wired (`ca42ea8`).
- **Refusal shapes tell the truth** — `weak_password` is `400`; sentinel
  `404`s only for misses, `409` for duplicates, `500` for faults across five
  write families and the update fallback (`75fba98`, `a6893b0`, `734e63c`);
  bulk rows name their class. A client that matched the old statuses will
  notice.
- **Update paths validated** — organization, user and client update paths
  distinguish "not supplied" from "supplied blank"; the client document
  validator runs at create and on the updated document (`92d3384`,
  `615d6fc`, `2bc4f1c`, `a4e718c`, `976432e`, `17f06a3`, `9bec8d4`);
  organization fields validated — "lexus" is no longer a domain
  (`92d3384`); org wire binds the five repository-supported fields and
  refuses slug and tier loudly (`c14b753`); users `active` wire contract
  fixed (`d952d06`).
- **Federated login, `acr`** — the performed context is stamped and
  `acr_values` is honored by step-up or refusal (`f0caeed`); a
  phishing-resistant rung with passkey step-up and downward-only ranking is
  the third advertised value (`f715b86`); the EFFECTIVE `amr` is copied onto
  the derived session (`27c044c`); an assumed ACR rung is no longer stamped
  on a federated session (`9127c53`); an upstream `acr` the ladder does not
  recognise is ASSUMED — stamped on no session, emitted in no id_token
  (`a42997d`, rule ACR-UNKNOWN-IS-ASSUMED-1). A relying party that requests
  `acr_values` from such a login gets step-up or
  `unmet_authentication_requirements` instead of a false assurance.
- **Soft-deleted users** — restore recovers them; approve/reset-mfa answer
  `404` not `500`; org_admin may delete same-org users; restore fails loud
  (`da226c7`, `78eb077`).
- **Discovery** advertises the issuer's signing algorithms (`d9ab771`); the
  unused second DPoP verifier is deleted (`c4c0af5`); the instance-lease
  uuid component is UUIDv7 (`ed56dca`).

### Toolchain and dependencies

- Go `1.27.0` → `1.27.1`; gin `1.11.0` → `1.12.0`; pgx/v5 `5.9.2` →
  `5.10.0`; goose/v3 `3.26.0` → `3.28.0`; prometheus/client_golang `1.23.2`
  → `1.24.1`; testify `1.11.1` → `1.12.1`; zap `1.27.0` → `1.28.0`;
  go-redis/v9 `9.17.2` → `9.22.0`; miniredis/v2 `2.35.0` → `2.39.0`;
  go-webauthn `0.15.0` → `0.18.0` (the one bump that needed code); jwt/v5
  `5.3.0` → `5.3.1`; x/crypto `0.53.0` → `0.56.0` (GO-2026-6303).

### Verification machinery (repository-visible, not in the binary)

- The rule ledger grew from 88 to **254 armed rules** (FLOOR 254); the
  `covers` map qualified on every rule; the ledger-diff gate reconciles a
  single-use amendment manifest at every verify (`bb650b8`).
- Every `make verify` and every CI run leaves a committed gate-run record
  (`5c0e107`, `e294d7c`); the first CI record this repository held
  (`91a8a7e`); records tie to the clean HEAD (`98ad34e`); the record is
  locked and two verify legs run concurrently (`7165378`, `7d7f56a`).
- **`make witness`** is the only way a witness commit is made, byte-identical
  with identuum-ui and pinned by `witness-parity` (`a6edb7f`).
- The e2e mint is COMPUTED by a reachability classifier, never judged
  (`dd4a171`, `bb1355e`); it applies under the ui's namespace and judges a
  stale e2e record by its two heads (`ad6a56b`).
- `openapi-check` compares the checked-in `openapi.yaml` byte for byte with
  its generator (`21a8b7e`); `workflow-yaml` parses every workflow with a
  pinned yq, held byte-identical with identuum-ui (`ac68b79`, `f98208c`);
  CI pins every gate tool and proves the versions it runs (`44990cf`,
  `9260c9c`); architecture boundaries declared and pinned (`5e304ed`).

## `v0.3.6`

Feature release: self-service password change, end to end. Measured delta
`v0.3.5..v0.3.6`: 5 commits, 21 files changed, +832/−62 (the release-prep
commit itself carries the Go 1.27.0 toolchain move); no migrations, no
dependency changes.

### Added

- **`POST /api/v1/auth/change-password`** — authenticated self-service
  password change. The target is always the caller's own account (no user
  id on the wire); the CURRENT password must verify; the new password is
  validated against the per-org password policy. Responses: `204` on
  success; `400 weak_password` with a safe displayable `message` on a
  policy violation; `403 invalid_current_password` — deliberately OPAQUE
  across wrong-password, federated (non-local) account, and
  no-local-hash; `401` for stale principals. Audit row `password_changed`
  with identifier-shaped metadata. This makes the UI's account-settings
  rotation (which always called this route) work against OSS.
- **Session revocation on password change (R2)** — a successful change
  revokes every OTHER session (revocation reason `password_changed`) and
  ALL OAuth refresh tokens; the session that made the change stays valid.
  The audit row records `other_sessions_revoked`,
  `session_revocation_clean`, `current_session_preserved`, and
  `refresh_tokens_revoked_count`.

### Changed

- **Toolchain: Go 1.27.0** (owner-directed) — `go.mod` and the image
  builder move together to `golang:1.27.0-bookworm` (digest-pinned;
  TOOLCHAIN-PARITY-1 enforces the pair). No dependency changes
  (`go mod tidy -diff` empty). Two v0.3.3-era test files were reflowed by
  go1.27's gofmt (formatting only; neither is ledger-pinned). The two EC
  JWK→key sites (DPoP proofs, private_key_jwt assertions) now construct
  keys via `ecdsa.ParseUncompressedPublicKey` — same on-curve validation
  and behavior, replacing the `ecdsa.PublicKey.X/.Y` construction Go 1.26
  deprecated; one dead assignment removed (both flagged by the go1.27-era
  staticcheck).
- **Customer compose pins refreshed** — the appliance file now pulls
  `identuum-idp-oss:v0.3.5` and `identuum-ui:v0.2.0`, each pinned by its
  published digest so tags cannot be silently retargeted.
- **Test infrastructure** (no runtime surface): the integration gate now
  serializes test packages (`go test -p 1`) — the DB-backed packages share
  one `*_test` database and raced under default package parallelism.

## `v0.3.5`

Security release. **`v0.3.4` was tagged but never published**: its image was
built by a `golang:1.26.5` builder while the host toolchain (and every
host-side scan) was already 1.26.6, so the image alone carried the 1.26.5
standard library — and the publish workflow's Trivy gate stopped it with 8
HIGH `gobinary` findings before GHCR login ever ran (run 32392773901; nothing
was pushed). The `v0.3.4` tag is public and stays (public tags are never
rewritten); the shipped release is `v0.3.5`, which is `v0.3.4`'s content plus
the fixed toolchain. All functional changes listed under `v0.3.4` below ship
first in `v0.3.5`.

### Security

- **Builder toolchain bumped to Go 1.26.6** (`deployment/Dockerfile.local`
  builder now `golang:1.26.6-bookworm`, digest-pinned; `go.mod` `go 1.26.6`;
  no dependency changes — `go mod tidy -diff` empty). This closes the 8 HIGH
  stdlib CVEs the v0.3.4 image carried, all fixed in Go 1.26.6:
  - CVE-2026-33818 — `encoding/asn1`: DoS via excessive recursion
  - CVE-2026-39821 — `net/http` / `golang.org/x/net/idna` (via stdlib): privilege escalation
  - CVE-2026-46600 — `golang.org/x/net/dns/dnsmessage` (via stdlib): DoS
  - CVE-2026-56853 — `net/http`: unencrypted HTTP/2 (h2c) DoS
  - CVE-2026-56858 — `html/template`: XSS via pathological input
  - CVE-2026-56859 — `encoding/xml`: DoS via decoding recursion depth
  - CVE-2026-56860 — `net/url`: DoS from quadratic complexity
  - CVE-2026-56862 — `crypto/tls`: DoS via indefinite KeyUpdate
  Verified locally with the publish gate's own scanner shape
  (`trivy image --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1`):
  exit 0, `gobinary` 0 findings on the rebuilt image (the v0.3.4-toolchain
  image reproduces 8 HIGH under the same scan).
- **TOOLCHAIN-PARITY-1** — a unit test now parses the Dockerfile builder's Go
  version and `go.mod`'s `go` directive and fails on any skew (digest pin
  required), so a host/image toolchain divergence can never again pass every
  host-side gate while shipping a stale stdlib in the image.

## `v0.3.4`

Operator-experience release: one-command appliance lifecycle operations,
health-visible failure states, and a setup wizard that can no longer lose
the operator's credentials. Measured delta `v0.3.3..HEAD` at preparation:
33 commits, 89 files changed, +3475/−90, one new migration (0031) — plus
this release-prep commit itself (34 commits to the tag).

### Added

- **`doctor` subcommand** — read-only appliance diagnosis printing named
  states (`version`, `db`, `at-rest-key` source, `setup`,
  `signing-key-seal`); exit `0` healthy, non-zero with a `FAILING:` line
  naming each failing state. DSNs and key material are never printed.
- **`factory-reset` subcommand** — returns the database to factory state
  (schema wipe + re-applied migrations → empty, migrated,
  `setup_required`). Refused, with no database contact, unless the exact
  `--i-understand-this-destroys-all-data` flag is passed.
- **`GET /api/v1/health/details`** (site_admin) — OSS runtime health:
  `status` + `version` always; `database` / `audit_system` when wired;
  Redis and audit queue-depth fields absent rather than zero-faked.
  Registered in the canonical endpoint surface (api-docgen).
- **Admin state on the organizations read surface** — `is_claimed` /
  `can_assign_admin` are projected from live org_admin counts on
  `GET /api/v1/organizations` and `GET /api/v1/organizations/:id`; a
  wiring gap yields ABSENT fields (never `false`) plus a health fault.
- **Migration 0031** — the database refuses to mark setup complete unless
  a live site_admin exists, so setup-state and site_admin existence can
  no longer disagree.
- **`docs/OPERATOR-GUIDE.md`** — every appliance lifecycle operation as
  one copy-paste `docker exec` command for image-only installs (no shell
  in the container, no DSN assembly).
- **Machine-checked rule ledger** (`RULE-FLOOR.md`) — 85 armed rules, all
  red-proved, verified by `make verify` and CI; internal quality
  infrastructure with no runtime surface.

### Changed

- **Setup wizard adopt-and-reset** — completing setup against a database
  that already has a site_admin now ADOPTS that account and resets its
  credentials; the completion screen reports the pinned
  `site_admin@system.local` login (never the operator-typed contact
  address), and `bootstrap` marks setup complete so a bootstrapped
  database can no longer present the wizard with a credential-eating
  split-brain.
- **Signing-key seal is health-visible** — active signing keys that no
  longer decrypt under the current at-rest key put the process into
  NOT-SERVING: `/health` answers `503` with a named `signing-key-seal`
  fault instead of a silent every-login-fails brick.
- **One-shot subcommands know their own database** — `migrate`,
  `bootstrap`, `recover-site-admin`, `show-setup-code`, `doctor`, and
  `factory-reset` all fall back to `IDENTUUM_IDP_DATABASE_URL`, then
  `IDENTUUM_IDP_OSS_DB`, when no URL argument is given; an explicit
  argument wins and the URL is never printed.
- **`recover-site-admin` works on the distroless image** — the make
  wrapper execs the binary directly (no `sh`), and the subcommand reads
  the at-rest key from the appliance data volume when the environment
  does not carry it.
- **Test infrastructure** (no runtime surface): integration suites run
  against a dedicated `*_test` database with a harness guard that refuses
  non-test DSNs; the session-rotation replay test measures its grace
  window on a single clock so host-vs-VM drift cannot flake it.

## `v0.3.3`

First public release.

### Added

- `LICENSE`: All Rights Reserved (view/evaluation only) —
  `SPDX-License-Identifier: LicenseRef-AllRightsReserved`. `NOTICE` keeps
  the third-party-attribution paragraph, which covers this module's own
  Go dependencies (declared in `go.mod`/`go.sum`) and is unaffected by
  this repository's own license.
- `README.md` Project Status section: published for viewing and
  evaluation only, not currently open source, external contributions
  not accepted.

No code or protocol behavior changes in this release; the binary
version is not bumped (no `ldflags` stamp, no version-string commit).

Full notes in `docs/releases/v0.3.3.md`.
