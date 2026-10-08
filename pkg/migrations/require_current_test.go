package migrations_test

import (
	"context"
	"database/sql"
	"errors"
	"net/url"
	"os"
	"testing"

	goosev3 "github.com/pressly/goose/v3"

	coremigrations "github.com/identuum/identuum-idp-oss/migrations"
	"github.com/identuum/identuum-idp-oss/pkg/migrations"

	"github.com/identuum/identuum-idp-oss/internal/postgres"
	"github.com/identuum/identuum-idp-oss/internal/testsupport"
)

// OSS-SEAM-3 proof 6: RequireCurrent is nil on a current database and a
// *VersionError holding found and wanted on an older, a newer or an
// unmigrated one.
func TestRequireCurrent(t *testing.T) {
	if err := migrations.RequireCurrent(context.Background(), nil); err == nil {
		t.Fatal("a nil database must be refused")
	}
	dsn := os.Getenv("IDENTUUM_IDP_TEST_DATABASE_URL")
	if dsn == "" {
		if os.Getenv("IDENTUUM_IDP_REQUIRE_DB_TESTS") != "" {
			t.Fatal("IDENTUUM_IDP_REQUIRE_DB_TESTS is set but IDENTUUM_IDP_TEST_DATABASE_URL is not")
		}
		t.Skip("IDENTUUM_IDP_TEST_DATABASE_URL not set; skipping the DB-backed RequireCurrent proof")
	}
	if err := testsupport.RequireTestDatabase(dsn); err != nil {
		t.Fatal(err)
	}
	admin, err := postgres.OpenStdlibDB(dsn)
	if err != nil {
		t.Fatalf("open the test database: %v", err)
	}
	t.Cleanup(func() { _ = admin.Close() })
	ctx := context.Background()
	want := postgres.EmbeddedSchemaVersion()
	upTo := func(t *testing.T, db *sql.DB, v int64) {
		p, err := goosev3.NewProvider(goosev3.DialectPostgres, db, coremigrations.EmbedFS)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := p.UpTo(ctx, v); err != nil {
			t.Fatalf("migrate to %d: %v", v, err)
		}
	}
	cases := []struct {
		name  string
		setup func(t *testing.T, db *sql.DB)
		found int64 // -1: current, no error
	}{
		{"current", func(t *testing.T, db *sql.DB) { upTo(t, db, want) }, -1},
		{"older", func(t *testing.T, db *sql.DB) { upTo(t, db, want-1) }, want - 1},
		{"newer", func(t *testing.T, db *sql.DB) {
			upTo(t, db, want)
			if _, err := db.ExecContext(ctx, `INSERT INTO goose_db_version (version_id, is_applied) VALUES ($1, true)`, want+1); err != nil {
				t.Fatal(err)
			}
		}, want + 1},
		{"unmigrated", func(*testing.T, *sql.DB) {}, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			name := "identuum_idp_oss_test_seam3_rc_" + tc.name
			if _, err := admin.ExecContext(ctx, `DROP DATABASE IF EXISTS `+name+` WITH (FORCE)`); err != nil {
				t.Fatal(err)
			}
			if _, err := admin.ExecContext(ctx, `CREATE DATABASE `+name); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if _, err := admin.ExecContext(ctx, `DROP DATABASE IF EXISTS `+name+` WITH (FORCE)`); err != nil {
					t.Errorf("drop the scratch database %s: %v", name, err)
				}
			})
			u, err := url.Parse(dsn)
			if err != nil {
				t.Fatal("the test DSN is not a URL")
			}
			u.Path = "/" + name
			db, err := postgres.OpenStdlibDB(u.String())
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = db.Close() })
			tc.setup(t, db)

			err = migrations.RequireCurrent(ctx, db)
			if tc.found < 0 {
				if err != nil {
					t.Fatalf("a current database: %v; want nil", err)
				}
				return
			}
			var ve *migrations.VersionError
			if !errors.As(err, &ve) || ve.Found != tc.found || ve.Wanted != want {
				t.Fatalf("RequireCurrent = %v; want a *VersionError with Found %d and Wanted %d", err, tc.found, want)
			}
		})
	}
}
