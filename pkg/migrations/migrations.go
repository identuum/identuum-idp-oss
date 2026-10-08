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

	internalmigrations "github.com/identuum/identuum-idp-oss/internal/pkg/migrations"
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
