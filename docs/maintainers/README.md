# identuum-idp-oss — maintainers

Maintainer-only material: the repository's gates and records, and the
documents behind them. A user building or running identuum-idp-oss needs
none of it; start at the [README](../../README.md).

- [RULE-FLOOR-CONVENTIONS.md](RULE-FLOOR-CONVENTIONS.md) — the rule ledger's
  project policy
- [DEPENDENCY-CURRENCY.md](DEPENDENCY-CURRENCY.md) — the dependency currency
  rule and its recorded exceptions
- [TEST-spec-status.md](TEST-spec-status.md) — the test specification's
  measured status
- [OSS_MANUAL_TEST_MATRIX.md](OSS_MANUAL_TEST_MATRIX.md) and
  [MANUAL-TEST.md](MANUAL-TEST.md) — manual test plans
- `make notices` / `make notices-check` — regenerate and check
  [THIRD_PARTY_NOTICES](../../THIRD_PARTY_NOTICES) (`go run ./tools/notices`;
  regeneration needs an identuum-ui checkout at the vendored commit)

## Maintainer gates

The `make verify`, `make fast-*`, `make dev-*`, and
`deployment/docker-compose.dev.yml` targets are maintainer-facing
convenience only. They are not the customer install path; see the
"Self-hosted install" section of the [README](../../README.md) for that.

> **`make verify` does NOT run from a fresh clone, and that is by design.**
> Measured 2026-09-04 by cloning this repository into an empty directory and
> following this section verbatim: it failed at the `repo-green` target with
> `bash: ../wiki/tools/repo-green-gate.sh: No such file or directory`, because
> several of its gates live in the maintainers' wiki repository, which is
> private and is not a sibling of your clone. (Since THE-GREEN-CONSUMERS,
> 2026-09-21, `repo-green` runs the installed `lictor` instead of that script
> and needs no sibling; the next wiki-coupled gate in the plan,
> `clock-fuse-gate`, still does — not re-measured from a fresh clone.)
> `make verify` is the MAINTAINER gate set, not a newcomer's first command.
> Everything else in this section works from a clean clone — that was
> measured in the same run.
>
> From a fresh clone, start with `make fast-up` and `make integration-test`
> below, or with the README's "Running the bare binary" section, which was measured
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
[RULE-FLOOR-CONVENTIONS.md](RULE-FLOOR-CONVENTIONS.md).

## Validation matrix

The repo-local close gate is `make verify`. Its `VERIFY_PLAN` definition in
`Makefile` is the source of truth for the exact order; its checks include:

1. `repo-green` (gofmt, build, vet, and the untagged Go test suite).
2. The tracked-binary, credential-transparency and workflow-yaml checks (every
   `.github/workflows/*.yml` must parse; the workflow-yaml block is held
   byte-identical to identuum-ui by `workflow-yaml-parity`; both also run in
   `ci-verify`, where ci.yml installs yq from a sha256-pinned release binary
   and `toolchain-parity` holds that pin equal to the local yq).
3. `rulefloor-check` (unit rows execute; integration-profile rows are checked
   statically here), then `ledger-diff-gate`: `rulefloor ledger-diff` against
   the previous accepted witness commit, reconciled both ways with the
   committed single-use manifest `ledger-amendments.json` — a ledger
   sentence never changes silently (see [RULE-FLOOR-CONVENTIONS.md](RULE-FLOOR-CONVENTIONS.md) §e).
4. Image-base policy, integration vet, doc-comment, R-suite, image-parity, and
   image-policy-restatement checks.
5. Clock-fuse reporting plus its snapshot gate, tagged-file vet, and the
   integration inventory that names tests this Docker-free aggregate did not
   execute.
6. A precise gograph rebuild followed by
   `gograph boundaries --config boundaries.json`. This is part of the full
   local gate, not an optional review command.
7. `go mod tidy -diff`, `staticcheck ./...`, `govulncheck ./...`,
   `grype-scan`, then wiki freshness as the final entry.

The local driver attempts every independent planned target after a failure;
any failure keeps the final verdict red. A target blocked by a failed declared
prerequisite is recorded as NOT-RUN with its reason and exit 125. In particular,
boundary evaluation requires that run's successful graph rebuild. Freshness
remains fatal, but cannot mask the security checks. The shared record writer
is unchanged; dirty work is evaluated without replacing the gate record.

```bash
make verify
```

The three authoritative argument vectors are `VERIFY_PLAN`, `CI_VERIFY_PLAN`
and `VERIFY_INTEGRATION_PLAN`, each defined once in `Makefile`. Their existing
recipes select the recorder, label, record path and failure behavior. `verify`
attempts all independent targets; `ci-verify` and `verify-integration` retain
the recorder's fail-fast behavior. Their records remain `GATE-RUN.txt`,
`GATE-RUN.ci.txt` and `GATE-RUN.integration.txt`, respectively; the latter two
are gitignored.

For a non-minting check, use `make verify-check`, `make ci-verify-check`, or
`make verify-integration-check`. These run the existing plans in this checkout
with the same recorder and verdict rules, writing the diagnostic record to a
temporary path outside the working tree. Tracked files must remain byte-identical;
ignored build caches may change just as under the minting driver. A check does
not replace a required minting run. Integration still needs its live services.

The external output is diagnostic, not a witness: the shared recorder's Git
exclusions cannot bind an outside record path to the tree. Its target verdict
still applies; do not use that output's tree-binding metadata as evidence.
The driver copies no checkout or credentials and needs no sandbox. Linked
worktrees use the same Git-based path discovery as ordinary checkouts.

Run the standalone transport proofs with `bash scripts/verify-check-test.sh`.

A foreign consumer can invoke `make -C /path/to/identuum-idp-oss verify-check`.
No consumer wiring is part of this change.

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

