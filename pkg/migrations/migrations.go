// Package migrations applies the identuum-idp-oss database schema. It is the
// public seam a caller composing pkg/runtime uses to bring the schema to
// Current() before Start (OSS-SEAM-1, owner ruling w, 2026-10-08).
//
// It is a narrow facade: Apply runs the OSS SQL migrations embedded in this
// module, exactly as `identuum-idp migrate` does — the same files, the same
// goose version table (goose_db_version) and the same session lock — and
// returns one Result per migration file. It takes no filesystem of its own;
// a downstream module's additive migrations are not part of this package.
// Compatibility: docs/PUBLIC-API.md.
package migrations

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	internalmigrations "github.com/identuum/identuum-idp-oss/internal/pkg/migrations"
	"github.com/identuum/identuum-idp-oss/internal/postgres"
)

// Result is one migration file's outcome.
type Result struct {
	// Source is the migration file's path in the embedded set.
	Source string
	// Applied is true when this call applied the file, false when the
	// database already had it.
	Applied bool
}

// Apply brings db to Current(). It is safe to call on a current database:
// every Result then has Applied false.
func Apply(ctx context.Context, db *sql.DB) ([]Result, error) {
	in, err := internalmigrations.Apply(ctx, db)
	if err != nil {
		return nil, err
	}
	out := make([]Result, 0, len(in))
	for _, r := range in {
		out = append(out, Result{Source: r.Source, Applied: r.Applied})
	}
	return out, nil
}

// Current is the newest schema version the embedded migrations define.
func Current() string { return internalmigrations.Current() }

// VersionError says the database schema is at another version than Current:
// Found is the newest applied version (0 when the database has no migrations
// table), Wanted the embedded one.
type VersionError struct {
	Found, Wanted int64
}

func (e *VersionError) Error() string {
	return (&postgres.SchemaVersionError{Found: e.Found, Wanted: e.Wanted}).Error()
}

// RequireCurrent returns nil when db is at Current(), a *VersionError when
// it is older or newer, and another error when the version cannot be read.
// It is the check pkg/runtime makes before serving (owner ruling y,
// 2026-10-08); it writes nothing.
func RequireCurrent(ctx context.Context, db *sql.DB) error {
	if db == nil {
		return errors.New("migrations: nil *sql.DB passed to RequireCurrent")
	}
	var present bool
	if err := db.QueryRowContext(ctx, `SELECT to_regclass('goose_db_version') IS NOT NULL`).Scan(&present); err != nil {
		return fmt.Errorf("migrations: could not check the database schema: %w", err)
	}
	var found int64
	if present {
		if err := db.QueryRowContext(ctx, postgres.AppliedSchemaVersionSQL).Scan(&found); err != nil {
			return fmt.Errorf("migrations: could not read the database schema version: %w", err)
		}
	}
	var mismatch *postgres.SchemaVersionError
	if err := postgres.CheckSchemaVersion(found); errors.As(err, &mismatch) {
		return &VersionError{Found: mismatch.Found, Wanted: mismatch.Wanted}
	}
	return nil
}
