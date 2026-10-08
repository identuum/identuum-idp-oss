package runtime

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/identuum/identuum-idp-oss/internal/postgres"
)

// migrationsTable is goose's version table, as internal/pkg/migrations names
// it (DefaultVersionTable). A literal because internal/runtime may not import
// that package (boundaries.json).
const migrationsTable = "goose_db_version"

// schemaQuerier is the one pool method the schema check needs.
type schemaQuerier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// errNotMigrated says what to do. OSS-RC: on an unmigrated database the bare
// binary logged `relation "signing_keys" does not exist`, retried the instance
// lease as a "transient error" for a minute, blamed "another live instance"
// and exited. The image's entrypoint migrates on start; the bare binary does
// not.
var errNotMigrated = errors.New("runtime: the database is not migrated — run `identuum-idp migrate <database-url>` before serving (the image's entrypoint migrates on start; the bare binary does not)")

// requireMigratedSchema fails when the migrations table is absent, before
// anything else touches the schema.
func requireMigratedSchema(ctx context.Context, q schemaQuerier) error {
	var present bool
	if err := q.QueryRow(ctx, `SELECT to_regclass($1) IS NOT NULL`, migrationsTable).Scan(&present); err != nil {
		return fmt.Errorf("runtime: could not check the database schema: %w", err)
	}
	if !present {
		return errNotMigrated
	}
	return nil
}

// schemaVersionFault names the NOT-SERVING fault of a schema at another
// version than this binary embeds.
const schemaVersionFault = "schema-version"

// requireCurrentSchema compares the newest applied migration with the newest
// embedded one (owner ruling y, 2026-10-08): a *postgres.SchemaVersionError
// on a mismatch, another error when the version cannot be read.
func requireCurrentSchema(ctx context.Context, q schemaQuerier) error {
	var found int64
	if err := q.QueryRow(ctx, postgres.AppliedSchemaVersionSQL).Scan(&found); err != nil {
		return fmt.Errorf("runtime: could not read the database schema version: %w", err)
	}
	return postgres.CheckSchemaVersion(found)
}
