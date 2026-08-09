package postgres

import (
	"database/sql"
	"errors"
	"fmt"

	// Side-effect import: registers the "pgx" driver with database/sql so
	// callers can sql.Open("pgx", url) without touching pgxpool. We import
	// pgx/v5/stdlib here so a single OSS package owns the driver
	// registration — callers do not have to add it themselves.
	_ "github.com/jackc/pgx/v5/stdlib"
)

// OpenStdlibDB opens a *sql.DB against databaseURL using the pgx stdlib
// driver. Suitable for tooling that needs a database/sql handle (notably
// goose migrations via RunMigrations); long-lived runtime traffic should
// use NewPool instead, which gives back a pgxpool.Pool.
//
// The caller owns Close. Errors never include the URL.
func OpenStdlibDB(databaseURL string) (*sql.DB, error) {
	if databaseURL == "" {
		return nil, errors.New("postgres: database URL is empty")
	}
	db, err := sql.Open("pgx", databaseURL)
	if err != nil {
		return nil, fmt.Errorf("postgres: open stdlib db failed: %w", err)
	}
	return db, nil
}
