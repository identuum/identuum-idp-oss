# Dependency currency — what is current, what lags, and why

The standing rule (owner, 2026-08-26, the fourth standing rule): **dependencies
track latest stable; a version below latest stable is DRIFT unless a reason is
RECORDED IN THE REPO.** This file is that record for this module's DIRECT
requirements. It is not a changelog — it says what is deliberately behind and
why, so nobody has to re-derive the decision from a report.

Measured 2026-09-03 (`go list -m -u`, `govulncheck ./...`, `grype dir:`).

## Taken

| Module | From | To | Why |
| --- | --- | --- | --- |
| `golang.org/x/crypto` | v0.55.0 | **v0.56.0** | Security. GO-2026-6354 and GO-2026-6355, both fixed in 0.56.0. Build, vet and the whole suite unchanged. |
| `github.com/golang-jwt/jwt/v5` | v5.3.0 | **v5.3.1** | Patch release, no API change. |
| `github.com/stretchr/testify` | v1.11.1 | **v1.12.1** | Minor, test-only. Judged by the unit suite: green, no code change. Carried `stretchr/objx` v0.5.2 → v0.5.3 with it. |
| `github.com/alicebob/miniredis/v2` | v2.35.0 | **v2.39.0** | Four minors, test-only (the Redis fake). Judged by the unit suite: green, no code change. |

## Deliberately behind, with the reason

Every row below is a MINOR upgrade, not a patch. The rule allows lag that has
been decided; what it forbids is lag nobody looked at. Each was measured
against latest stable on 2026-09-03, carries **no advisory** in either
scanner, and is held for the same reason: a minor bump can add or change API,
so each needs its own build-and-test pass and its own slice, and taking nine
of them in one commit would make a single red impossible to attribute.

| Module | Current | Latest | Note |
| --- | --- | --- | --- |
| `github.com/gin-gonic/gin` | v1.11.0 | v1.12.0 | The HTTP framework. A minor bump touches routing and middleware behaviour; the route census and the role matrix are the things to re-run. |
| `github.com/go-webauthn/webauthn` | v0.15.0 | v0.18.0 | Three minors on a **v0 module**, where the semver compatibility promise does not apply. Needs the WebAuthn ceremony suites re-run, not just a compile. |
| `github.com/jackc/pgx/v5` | v5.9.2 | v5.10.0 | The database driver. The integration profile (`make verify-integration`) is the gate that would judge it. |
| `github.com/redis/go-redis/v9` | v9.17.2 | v9.22.0 | Five minors. Session and cache paths. |
| `github.com/pressly/goose/v3` | v3.26.0 | v3.28.0 | The migration engine — a bump is a migration-path change, judged by a fresh-appliance mint. |
| `github.com/prometheus/client_golang` | v1.23.2 | v1.24.1 | Metrics surface. |
| `go.uber.org/zap` | v1.27.0 | v1.28.0 | Logging. |

Current at latest stable and needing no note: `github.com/google/uuid` v1.6.0,
`gopkg.in/yaml.v3` v3.0.1.

## The advisory with no fix

`govulncheck` reports **GO-2026-5932** against `golang.org/x/crypto` with
`Fixed in: N/A`. There is no version to move to, and this module's own code
does not call the vulnerable symbol (govulncheck's symbol analysis reports
zero affecting vulnerabilities). It is therefore reported, not actioned, and
the scan gate is built to match: a finding with an available fix FAILS, a
finding with none does not (see `tools/grype-gate` and rule
`GRYPE-FIXABLE-FAILS-1`). If a fix is published, the gate turns red on the
next run — which is the point.

## The npm side

`identuum-ui` was measured on the same day and is READ-ONLY in the slice that
wrote this file: `pnpm audit` reports **zero advisories at every severity**,
and six packages lag latest (biome 2.5.10→2.5.11, next 16.3.3→16.3.4,
lucide-react 1.34.0→1.39.0, react-hook-form 7.86.0→7.87.0, zod 4.4.3→4.5.4,
@types/node 22.19.19→26.4.1 — the last one is a standing deliberate hold,
recorded in that repository: types track the `engines` floor, not the newest
local runtime). Acting on those belongs to a slice that may write there.
