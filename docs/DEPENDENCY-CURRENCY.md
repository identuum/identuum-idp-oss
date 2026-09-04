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
| `go.uber.org/zap` | v1.27.0 | **v1.28.0** | Minor, logging. Judged by the unit suite: green, no code change. |
| `github.com/prometheus/client_golang` | v1.23.2 | **v1.24.1** | Minor, metrics. Judged by the unit suite: green, no code change. Carried `prometheus/procfs` 0.16.1 → 0.21.1, `protobuf` 1.36.9 → 1.36.11 and `go.yaml.in/yaml/v2` 2.4.2 → 2.4.4 with it. |
| `github.com/pressly/goose/v3` | v3.26.0 | **v3.28.0** | Minor, the migration engine. Judged by `make verify-integration` (49 packages, 3804 tests, green — the migration-applying suites run there against a live database). Carried `sethvargo/go-retry` 0.3.0 → 0.4.0, `x/net` 0.57.0 → 0.58.0 and `protobuf` 1.36.11 → 1.36.12. |
| `github.com/jackc/pgx/v5` | v5.9.2 | **v5.10.0** | Minor, the database driver — every repository, pool and transaction path. Judged by `make verify-integration` (49 packages, 3804 tests, green) and the unit suite: no code change. |
| `github.com/redis/go-redis/v9` | v9.17.2 | **v9.22.0** | Five minors, the session and cache client. The currency file named no single judge for it, so it was given both: the unit suite (which drives it through the miniredis fake) and `make verify-integration`, both green, no code change. Added `go.uber.org/atomic` v1.11.0 and `zeebo/xxh3` as indirects. |
| `github.com/gin-gonic/gin` | v1.11.0 | **v1.12.0** | Minor, the HTTP framework — routing and middleware. Judged by the two-repo mint (the route census, the role matrix and the coverage floor all held at 144 / 312 / 52) plus the unit suite and the docgen ratchet. No code change. Carried `goccy/go-yaml` 1.18.0 → 1.19.2, `ugorji/go/codec` 1.3.0 → 1.3.1, `x/arch` 0.20.0 → 0.22.0, and added `mongo-driver/v2` as an indirect of gin's binding layer. |
| `github.com/go-webauthn/webauthn` | v0.15.0 | **v0.18.0** | Three minors on a **v0 module**, and the ONLY one of the nine that needed a code change: `RegistrationOption` and `LoginOption` now return an `error`, so the service's two option closures gained a `return nil`. That is a signature migration, not a behaviour change — neither closure can fail, each only sets fields on a struct the library owns. Judged by the WebAuthn ceremony suites inside the two-repo mint, plus the unit suite. Carried `go-webauthn/x` 0.1.26 → 0.3.0, `go-tpm` 0.9.6 → 0.9.8, `go-viper/mapstructure` 2.4.0 → 2.5.0, and added `tinylib/msgp` and `philhofer/fwd` as indirects. |

## Deliberately behind, with the reason

**Nothing is held today.** The nine minors this section listed were all taken
on 2026-09-03 (THE-NINE-MINORS), one commit each, in risk order, each judged
by the gate named beside it above. The section stays because the rule needs a
place for the next held row: a version below latest stable belongs here with
its reason, or it is drift.

| Module | Current | Latest | Note |
| --- | --- | --- | --- |
| — | — | — | nothing held |

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

## The toolchain: who is authoritative, per tool

Added 2026-09-04 (THE-UNCOMPARED-TOOLCHAIN). `make tool-versions` prints what
is installed here; the CI workflow env declares what CI builds. Both were
true and nothing compared them, so the ledger was checked by rulefloor v0.8.1
here and v0.7.0 in CI for weeks, silently. `make toolchain-parity` now refuses
that disagreement (rule `CI-LOCAL-PARITY-1`). This table says what to do when
it fires — which side moves.

| Tool | Declared in | Authority when they differ |
| --- | --- | --- |
| `rulefloor` | workflow env `RULEFLOOR_VERSION` (+ `RULEFLOOR_SHA256`) | **Latest stable**, per the fourth standing rule. Neither side wins by being CI or local: the pin is the RECORD, and the fix is to bump the pin to latest stable and install that here. A version below latest stable belongs in the held table above with its reason. |
| `staticcheck` | workflow env `STATICCHECK_VERSION` | Latest stable, as above. |
| `grype` | workflow env `GRYPE_VERSION` | Latest stable, as above. |
| `govulncheck` | workflow env `GOVULNCHECK_VERSION` | Latest stable, as above. |
| `go` | **`go.mod`'s `go` directive** — not re-declared in the workflow | go.mod is authoritative for BOTH sides. CI's `setup-go` derives from it; this machine must match it. Changing the toolchain means changing go.mod, never the pin. |
| `gograph` | nothing — **deliberately absent** | Local-only. CI does not install it (`ci-verify` subtracts the gograph targets), so there is no pin to disagree with. Recorded here so the absence is a decision, not an oversight: if gograph ever enters CI, it must gain an env pin and a row in the parity gate the same day. |
| `scripts/gate-witness.sh` | workflow env `GATE_WITNESS_SHA256` | The **wiki master** is authoritative. CI verifies the vendored copy with `sha256sum -c`, so the pin must follow the master the moment the script changes — this is exactly the drift that was sitting here when the gate was written. |
| `scripts/rulefloor-install-gate.sh` | workflow env `RULEFLOOR_GATE_SHA256` | The wiki master, as above. |

**What the parity gate does NOT prove.** It compares declarations against THIS
machine. It cannot prove that CI, when it next runs, actually builds and
installs what the env declares — nothing here can run CI. Those two are
different claims, and only the first is gated.

## A note on the mint

Added 2026-09-04 (THE-UNMINTED-DIFF). A dependency bump changes `go.mod` and
`go.sum`, and those REACH the running appliance: `make test-full` classifies
them as requiring the e2e mint, and no bump recorded in the table above may
skip it. Editing this file alone does not — prose cannot reach the appliance,
which is why `docs/**` is a declared no-reach entry and this very paragraph
is the worked example.
