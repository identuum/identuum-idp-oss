# Changelog — identuum-idp-oss

All notable changes to `identuum-idp-oss` are recorded here, starting from
the first public release. Format roughly follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning
follows [Semantic Versioning](https://semver.org/).

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
