// Package runtime is the public OSS seam for the identuum-idp-oss
// in-process IDP runtime lifecycle (open DB, wire services, mount the
// Gin route surface, run a graceful HTTP server, drain).
//
// It is the canonical import path for downstream callers — including
// the identuum-idp-ce overlay — that need to start the OSS runtime
// in-process without crossing the internal/ boundary.
//
// Implementation note: this file is a thin shim over the existing
// internal/runtime package. Config and Runtime are Go type aliases of
// internal/runtime.Config and internal/runtime.Runtime so a value
// constructed at either path is the same value at every Go compile
// site. New is a pass-through wrapper around internal/runtime.New.
// The internal package remains the single source of truth for
// behaviour; this public package is the stable import surface CE
// pins against.
//
// CE composition contract (R1 boundary — see wiki/repos/identuum-idp-oss.md
// §"pkg/runtime"):
//
//	rt, err := runtime.New(runtime.Config{
//	    Addr:      ":7113",
//	    Issuer:    "https://idp.example.com",
//	    JWKSDBURL: jwksDBURL, // operator-supplied; NEVER logged
//	    Version:   buildVersion,
//	    Stdout:    os.Stdout,
//	    Stderr:    os.Stderr,
//	})
//	if err := rt.Start(ctx); err != nil { ... }
//	// caller waits on rt.Done() or its own signal channel
//	if err := rt.Shutdown(drainCtx); err != nil { ... }
//
// R1 boundary — what this seam does NOT expose:
//
//   - *pgxpool.Pool is intentionally NOT reachable through any
//     accessor. CE must compose its own pool when it needs one and
//     thread CE-specific repositories through CE-owned code.
//   - repository.* interfaces and internal/service.* concrete types
//     are likewise not surfaced. CE composes with OSS through the
//     internal/api engine (pkg/router was DELETED 2026-08-05, P3-8 — zero importers)
//     and through the pkg/migrations seam (for OSS schema
//     application), not by reaching into runtime internals.
//   - Migrations are NOT run by Start. Operators run migrations
//     separately (see pkg/migrations.Apply). The runtime expects the
//     schema to be at the OSS embedded version before Start.
//
// SECURITY contract:
//
//   - The operator-supplied JWKSDBURL is never printed to Config.Stdout
//     or Config.Stderr. Errors that may embed the URL are scrubbed at
//     the internal layer before being returned or logged.
//   - This package carries no license envelope, no signing key, no
//     DB handle, no secret material, and no network surface of its
//     own beyond what the internal runtime owns.
//   - The OSS module must never import identuum-idp-ce.
package runtime

import (
	"context"

	internalruntime "github.com/identuum/identuum-idp-oss/internal/runtime"
)

// Config drives the OSS runtime. Aliased from
// internal/runtime.Config so a literal such as
// `runtime.Config{Addr: ":7113"}` constructed at either path is the
// same value.
//
// Field-level documentation lives on internal/runtime.Config and is
// intentionally not duplicated here — duplicated docs would drift.
type Config = internalruntime.Config

// Runtime is the OSS in-process IDP lifecycle handle. Aliased from
// internal/runtime.Runtime so callers obtain the same behavioural
// surface (Start, Shutdown, Done, ServeErr, Addr, Engine) via either
// import path.
type Runtime = internalruntime.Runtime

// New validates cfg and returns a Runtime. Pass-through wrapper
// around internal/runtime.New. New does not open the DB, bind the
// listener, or construct services — those happen in Runtime.Start.
func New(cfg Config) (*Runtime, error) {
	return internalruntime.New(cfg)
}

// Compile-time pin: the runtime context parameter on Start matches
// the stdlib context.Context. The unused reference exists so this
// file owns at least one stdlib import the doc claims it relies on,
// keeping `goimports` from re-shaping the import block on cosmetic
// edits.
var _ = context.Background
