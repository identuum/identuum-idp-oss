# Public Go API of identuum-idp-oss

identuum-idp-oss is a binary first. A small set of packages under `pkg/` is
also a Go API that a trusted downstream module (identuum-idp-ce) imports and
links statically into its own binary. Everything else — `internal/` and the
binary's commands — is not an API and may change in any release.

## The packages

The set is exactly these ten directories under `pkg/`, enforced by
`make api-surface`:

- `pkg/extension` — deny-only restrictions a linked module adds to OSS
  decisions (owner rulings z and aa, 2026-10-08). OSS builds an immutable
  `Decision` (actor, tenant, operation, target, required scopes) after its
  own authentication, tenant authority and base checks, and before any
  write; a downstream module cannot build one. Each `Restriction` in
  `runtime.Options.Restrictions` may refuse it. A `*Denial` answers 403 with
  `restricted` or `license_required`, or 409 with `quota_exceeded`; any other
  error, and a panic, is 403 `restricted`. A restriction never turns an OSS
  refusal into an allow. Covered operations: API resource create, update and
  delete. With no restrictions OSS behaves as before.

- `pkg/runtime` — builds and runs the OSS IdP in the caller's process:
  `New(Options)`, then `Start` and `Shutdown`; `Done`, `ServeErr`,
  `Serving`, `Addr`, `MetricsAddr`. `Options` maps one to one onto the
  runtime's configuration. The caller owns the process, its signals and the
  migration order; `Start` does not migrate. The HTTP engine, the database
  pool, repositories, services and keys are not exposed.
  `NewWithListener(Options, net.Listener)` serves a listener the caller
  bound: the runtime owns it only when the constructor succeeds, and then
  `Shutdown` closes it exactly once; on a constructor error the caller still
  owns it, open. `Health()` returns a read-only snapshot — whether the
  runtime serves normal traffic, and its faults (component and reason, with
  no URL or secret). After a fatal startup fault the runtime is NOT-SERVING:
  normal routes answer 503 and `/health` keeps answering.
- `pkg/migrations` — `Apply(ctx, db)` brings a database to `Current()` with
  the OSS migrations embedded in this module, the same files, version table
  (`goose_db_version`) and lock as `identuum-idp migrate`.
  `RequireCurrent(ctx, db)` writes nothing and returns nil when the database
  is at `Current()`, or a `*VersionError` (`Found`, `Wanted`) when it is
  older or newer. `pkg/runtime` makes the same check at `Start`: a schema at
  another version is NOT-SERVING with one fatal fault, "schema at <found>,
  this server needs <wanted>: run identuum-idp migrate" (owner ruling y,
  2026-10-08).
- `pkg/features`, `pkg/licenseprovider`, `pkg/oidc`, `pkg/pkce`, `pkg/totp`,
  `pkg/uiserve`, `pkg/webauthn` — as before.

Typical composition:

```go
db, _ := sql.Open("pgx", dsn)
if _, err := migrations.Apply(ctx, db); err != nil { /* stop */ }
rt, err := runtime.New(runtime.Options{Addr: ":7113", Issuer: issuer, DatabaseURL: dsn})
if err != nil { /* stop */ }
if err := rt.Start(ctx); err != nil { /* stop */ }
// ... wait for a signal or rt.Done() ...
_ = rt.Shutdown(drainCtx)
```

## The compatibility promise

Owner ruling w (2026-10-08):

- A patch release keeps source compatibility and established behaviour of
  these packages.
- An addition to their API comes with the API golden updated and a regression
  test.
- While the module is `v0`, a breaking change ships only in an announced
  minor release, after one full minor line in which the old form is marked
  `// Deprecated:` with its replacement and a migration note.
- After `v1`, a breaking change needs a new module major version.
- A security fix may tighten unsafe behaviour; its release notes say what a
  caller must change.

The exported API of every package above is recorded in
`internal/apigolden/testdata/pkg.api`, and `go test ./internal/apigolden`
fails on any difference, naming what was added or removed. Changing the API
means changing that file, deliberately, in the same commit.

Import the module at a released version; no `replace` directive and no
`go.work`.
