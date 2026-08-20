# Changelog — identuum-idp-oss

All notable changes to `identuum-idp-oss` are recorded here, starting from
the first public release. Format roughly follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning
follows [Semantic Versioning](https://semver.org/).

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
