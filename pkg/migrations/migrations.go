// Package migrations is the public OSS seam for the embedded OSS
// migration filesystem and a minimal Apply helper.
//
// It is the canonical import path for downstream callers — including
// the identuum-idp-ce overlay — that need to embed and run the OSS
// baseline migrations without crossing an internal/ boundary.
//
// Implementation note: this file is a thin shim that re-exports the
// embed.FS from the existing top-level migrations package
// (github.com/identuum/identuum-idp-oss/migrations) and adds a small
// goose-backed Apply helper. The top-level package remains the single
// source of truth for the SQL file set and the //go:embed directive;
// the public package is the stable import surface CE will pin against.
//
// Why a separate pkg/migrations seam:
//   - It matches the pkg/features and pkg/licenseprovider naming
//     convention established by the prior T1 seam slice, so CE has a
//     single, predictable import root (github.com/identuum/identuum-idp-oss/pkg/*).
//   - It carries no dependency on internal/ subtrees, so a CE binary
//     that only wants to apply OSS migrations does not transitively
//     pull in internal/postgres, internal/service, or any other OSS
//     runtime package.
//
// Version table posture:
//   - The OSS Apply helper applies migrations using goose's default
//     `goose_db_version` table. This matches both the existing
//     internal/postgres.RunMigrations behaviour and the ratified
//     single-binary dual-license OSS/CE overlay model (see wiki/platform/dual-license-boundary.md
//     §"IDP CE canonical model"): OSS migrations apply first under
//     `goose_db_version`, and CE additive migrations apply later under
//     `goose_db_version_ce` via CE-owned code.
//   - The public seam does NOT support a custom version-table override.
//     A future CE runtime will call Apply here to drive OSS migrations
//     against the default table, then run its own CE-side Apply that
//     uses `goose_db_version_ce`. Keeping the OSS seam scoped to the
//     OSS default table avoids exposing knobs that could let a caller
//     point OSS at a non-default table and silently lose history.
//
// SECURITY contract:
//   - The package depends only on the OSS top-level migrations
//     package, goose, and the standard library. It carries no DB URL,
//     no credentials, no secrets, no envelope material, and no network
//     surface.
//   - The OSS module must never import identuum-idp-ce.
package migrations

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"

	goosev3 "github.com/pressly/goose/v3"
	"github.com/pressly/goose/v3/lock"

	coremigrations "github.com/identuum/identuum-idp-oss/migrations"
)

// DirName is the directory inside EmbedFS that contains the OSS
// migration SQL files. The OSS embed history is intentionally flat
// at the root of the embedded FS, so this is ".".
const DirName = "."

// DefaultDialect is the SQL dialect that the OSS migration history is
// authored against. Mirrors goose's DialectPostgres value.
const DefaultDialect = "postgres"

// DefaultVersionTable is the goose version table the OSS Apply helper
// uses. This is the goose default name; the OSS seam does not expose a
// custom-table override (see package doc, "Version table posture").
const DefaultVersionTable = "goose_db_version"

// LockPeriodSeconds is the advisory-lock retry interval used by Apply.
// Matches the value internal/postgres.RunMigrations uses today so a
// caller switching from the internal helper to this public seam sees
// no behavioural change.
const LockPeriodSeconds uint64 = 5

// LockMaxRetries caps the advisory-lock retry attempts used by Apply.
// Total wait budget = LockPeriodSeconds × LockMaxRetries seconds.
// Matches internal/postgres.RunMigrations.
const LockMaxRetries uint64 = 24

// EmbedFS is the embedded OSS migration filesystem. It is a var alias
// of the same embed.FS declared in the top-level migrations package,
// so an integrity probe such as fs.ReadFile is satisfied by reading
// either path identically.
//
// The value is a defensive var (not a const, which would not compile
// for embed.FS) — callers must treat it as immutable. The underlying
// //go:embed directive lives in the core package.
var EmbedFS = coremigrations.EmbedFS

// Result is the per-source outcome of a single migration step. The
// shape mirrors the internal/postgres.MigrationResult type but lives
// in this public package so the seam has no internal/* dependency.
type Result struct {
	// Source is the migration file path inside EmbedFS (e.g.
	// "0001_identity_credentials.sql").
	Source string
	// Applied is true when the migration was newly applied during
	// this Up pass; false when goose reports the migration was
	// already at the target version (empty step).
	Applied bool
}

// Current returns the highest migration version number embedded in
// the OSS history, zero-padded to four digits (e.g. "0018"). Returns
// "0000" if no migrations are embedded (which should never happen —
// the core migrations_test.go guarantees at least one).
func Current() string {
	return coremigrations.Current()
}

// Apply runs every pending migration in EmbedFS against db using
// goose's Postgres dialect and the OSS default version table.
//
// A PostgreSQL session-level advisory lock is taken via
// goose's WithSessionLocker so concurrent processes racing the same
// startup path do not race the schema; only one holds the lock at a
// time and the others wait up to LockPeriodSeconds × LockMaxRetries
// seconds before failing.
//
// The caller owns the *sql.DB handle — Apply neither opens nor closes
// it. pgxpool.Pool is NOT a *sql.DB; callers that already hold a
// pgxpool should open a separate database/sql handle via the stdlib
// pgx driver (github.com/jackc/pgx/v5/stdlib) for migrations only and
// close it before serving traffic.
//
// Returns the per-source result list so callers can log which files
// were applied this run.
func Apply(ctx context.Context, db *sql.DB) ([]Result, error) {
	return ApplyFS(ctx, db, EmbedFS)
}

// ApplyFS is the lower-level variant of Apply that takes an explicit
// fs.FS. It is exposed for tests that want to verify Apply's behaviour
// against a minimal in-memory filesystem (avoiding a live database is
// still the caller's responsibility — ApplyFS requires a real *sql.DB).
//
// CE runtimes should always prefer Apply, which uses the canonical
// OSS EmbedFS; ApplyFS exists so the seam's behavioural contract can
// be pinned in tests without re-embedding the SQL files.
func ApplyFS(ctx context.Context, db *sql.DB, fsys fs.FS) ([]Result, error) {
	if db == nil {
		return nil, errors.New("migrations: nil *sql.DB passed to Apply")
	}
	if fsys == nil {
		return nil, errors.New("migrations: nil fs.FS passed to ApplyFS")
	}

	locker, err := lock.NewPostgresSessionLocker(
		lock.WithLockTimeout(LockPeriodSeconds, LockMaxRetries),
	)
	if err != nil {
		return nil, fmt.Errorf("migrations: lock setup failed: %w", err)
	}

	provider, err := goosev3.NewProvider(
		goosev3.DialectPostgres,
		db,
		fsys,
		goosev3.WithSessionLocker(locker),
	)
	if err != nil {
		return nil, fmt.Errorf("migrations: provider setup failed: %w", err)
	}

	results, err := provider.Up(ctx)
	if err != nil {
		return nil, fmt.Errorf("migrations: apply failed: %w", err)
	}

	out := make([]Result, 0, len(results))
	for _, r := range results {
		if r == nil || r.Source == nil {
			continue
		}
		out = append(out, Result{
			Source:  r.Source.Path,
			Applied: !r.Empty,
		})
	}
	return out, nil
}
