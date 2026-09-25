package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	goosev3 "github.com/pressly/goose/v3"
	"github.com/pressly/goose/v3/lock"

	"github.com/identuum/identuum-idp-oss/migrations"
)

// MigrationLockPeriodSeconds is the advisory-lock retry interval.
const MigrationLockPeriodSeconds uint64 = 5

// MigrationLockMaxRetries caps the advisory-lock retry attempts. Total
// wait budget = MigrationLockPeriodSeconds × MigrationLockMaxRetries
// seconds (default = 120 s).
const MigrationLockMaxRetries uint64 = 24

// MigrationResult is the per-source outcome of a single migration step.
type MigrationResult struct {
	Source  string
	Applied bool
}

// RunMigrations applies every pending migration embedded in
// identuum-idp-oss/migrations.EmbedFS under a PostgreSQL session-level
// advisory lock. Multiple processes may race the startup path safely;
// only one holds the lock at a time and the others wait up to
// MigrationLockPeriodSeconds × MigrationLockMaxRetries seconds before
// failing. The caller owns the *sql.DB handle — this function neither
// opens nor closes it.
//
// pgxpool.Pool is NOT a *sql.DB; callers that already hold a pgxpool
// should open a separate database/sql handle via the stdlib pgx
// driver (github.com/jackc/pgx/v5/stdlib) for migrations only and
// close it before serving traffic. Keeping the pool and the migration
// handle independent prevents goose's internal state from leaking
// into the long-lived runtime pool.
//
// Returns the per-source result list so callers can log which files
// were applied this run.
func RunMigrations(ctx context.Context, db *sql.DB) ([]MigrationResult, error) {
	report, err := RunMigrationsReport(ctx, db)
	if err != nil {
		return nil, err
	}
	return report.Results, nil
}

// MigrationReport is what one migration run did: the migrations it applied
// (goose's Up returns only those), how many the binary embeds, and the
// database's version afterwards.
type MigrationReport struct {
	Results  []MigrationResult
	Embedded int
	Version  int64
}

// Applied counts the results that applied a migration.
func (r MigrationReport) Applied() int {
	n := 0
	for _, res := range r.Results {
		if res.Applied {
			n++
		}
	}
	return n
}

// RunMigrationsReport is RunMigrations with its report: Embedded is the
// provider's own source list (every migration the binary carries, applied
// or not), Version the database's version after Up.
func RunMigrationsReport(ctx context.Context, db *sql.DB) (MigrationReport, error) {
	if db == nil {
		return MigrationReport{}, errors.New("postgres: nil *sql.DB passed to RunMigrations")
	}

	locker, err := lock.NewPostgresSessionLocker(
		lock.WithLockTimeout(MigrationLockPeriodSeconds, MigrationLockMaxRetries),
	)
	if err != nil {
		return MigrationReport{}, fmt.Errorf("postgres: migration lock setup failed: %w", err)
	}

	provider, err := goosev3.NewProvider(
		goosev3.DialectPostgres,
		db,
		migrations.EmbedFS,
		goosev3.WithSessionLocker(locker),
	)
	if err != nil {
		return MigrationReport{}, fmt.Errorf("postgres: migration provider setup failed: %w", err)
	}

	results, err := provider.Up(ctx)
	if err != nil {
		return MigrationReport{}, fmt.Errorf("postgres: migrations failed: %w", err)
	}

	out := make([]MigrationResult, 0, len(results))
	for _, r := range results {
		if r == nil || r.Source == nil {
			continue
		}
		out = append(out, MigrationResult{
			Source:  r.Source.Path,
			Applied: !r.Empty,
		})
	}
	version, err := provider.GetDBVersion(ctx)
	if err != nil {
		return MigrationReport{}, fmt.Errorf("postgres: read migrated version failed: %w", err)
	}
	return MigrationReport{Results: out, Embedded: len(provider.ListSources()), Version: version}, nil
}
