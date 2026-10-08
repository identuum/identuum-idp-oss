package migrations_test

import (
	"context"
	"database/sql"
	"net/url"
	"os"
	"reflect"
	"testing"

	coremigrations "github.com/identuum/identuum-idp-oss/migrations"
	"github.com/identuum/identuum-idp-oss/pkg/migrations"

	internalmigrations "github.com/identuum/identuum-idp-oss/internal/pkg/migrations"
	"github.com/identuum/identuum-idp-oss/internal/postgres"
	"github.com/identuum/identuum-idp-oss/internal/testsupport"
)

// OSS-SEAM-1 proof 4: the public Apply and Current answer as the existing
// paths do — the shim's and the migrate command's (internal/postgres) — and
// write the same history, in the same default version table.
func TestMigrations_AnswerAsTheExistingPaths(t *testing.T) {
	if got, want := migrations.Current(), internalmigrations.Current(); got != want || got != coremigrations.Current() {
		t.Fatalf("Current() = %q; the shim says %q and the embedded set %q", got, want, coremigrations.Current())
	}
	_, perr := migrations.Apply(context.Background(), nil)
	_, ierr := internalmigrations.Apply(context.Background(), nil)
	if perr == nil || ierr == nil || perr.Error() != ierr.Error() {
		t.Fatalf("a nil database: public %v, internal %v; want the same refusal", perr, ierr)
	}
}

func TestMigrations_ResultAndHistoryEqualTheMigrateCommand(t *testing.T) {
	dsn := os.Getenv("IDENTUUM_IDP_TEST_DATABASE_URL")
	if dsn == "" {
		if os.Getenv("IDENTUUM_IDP_REQUIRE_DB_TESTS") != "" {
			t.Fatal("IDENTUUM_IDP_REQUIRE_DB_TESTS is set but IDENTUUM_IDP_TEST_DATABASE_URL is not")
		}
		t.Skip("IDENTUUM_IDP_TEST_DATABASE_URL not set; skipping the DB-backed migration equivalence")
	}
	if err := testsupport.RequireTestDatabase(dsn); err != nil {
		t.Fatal(err)
	}
	admin, err := postgres.OpenStdlibDB(dsn)
	if err != nil {
		t.Fatalf("open the test database: %v", err)
	}
	// Closed by the FIRST cleanup registered, so it runs LAST: the scratch
	// databases' DROPs below need it open (a defer would close it first).
	t.Cleanup(func() { _ = admin.Close() })
	ctx := context.Background()

	// Two fresh scratch databases: one migrated by the public Apply, one by
	// the migrate command's path. Both are dropped at the end.
	fresh := func(name string) *sql.DB {
		if _, err := admin.ExecContext(ctx, `DROP DATABASE IF EXISTS `+name); err != nil {
			t.Fatalf("drop %s: %v", name, err)
		}
		if _, err := admin.ExecContext(ctx, `CREATE DATABASE `+name); err != nil {
			t.Fatalf("create %s: %v", name, err)
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
			t.Fatalf("open %s: %v", name, err)
		}
		t.Cleanup(func() { _ = db.Close() })
		return db
	}
	history := func(db *sql.DB) [][2]any {
		rows, err := db.QueryContext(ctx, `SELECT version_id, is_applied FROM goose_db_version ORDER BY id`)
		if err != nil {
			t.Fatalf("read goose_db_version: %v", err)
		}
		defer func() { _ = rows.Close() }()
		var out [][2]any
		for rows.Next() {
			var v int64
			var applied bool
			if err := rows.Scan(&v, &applied); err != nil {
				t.Fatal(err)
			}
			out = append(out, [2]any{v, applied})
		}
		return out
	}
	pubDB, cliDB := fresh("identuum_idp_oss_test_seam1_pub"), fresh("identuum_idp_oss_test_seam1_cli")

	got, err := migrations.Apply(ctx, pubDB)
	if err != nil {
		t.Fatalf("public Apply: %v", err)
	}
	cli, err := postgres.RunMigrations(ctx, cliDB)
	if err != nil {
		t.Fatalf("migrate command path: %v", err)
	}
	if len(got) != len(cli) || len(got) == 0 {
		t.Fatalf("on a fresh database the public Apply gave %d results, the migrate command %d", len(got), len(cli))
	}
	for i := range got {
		if got[i].Source != cli[i].Source || got[i].Applied != cli[i].Applied {
			t.Fatalf("result %d: public %q applied=%v, migrate command %q applied=%v",
				i, got[i].Source, got[i].Applied, cli[i].Source, cli[i].Applied)
		}
	}
	if hp, hc := history(pubDB), history(cliDB); !reflect.DeepEqual(hp, hc) {
		t.Fatalf("goose_db_version differs: public %d rows, migrate command %d rows", len(hp), len(hc))
	}
	// A second public Apply on the now-current database applies nothing and
	// writes no history.
	before := history(pubDB)
	again, err := migrations.Apply(ctx, pubDB)
	if err != nil {
		t.Fatalf("second public Apply: %v", err)
	}
	for _, r := range again {
		if r.Applied {
			t.Fatalf("a current database re-applied %s", r.Source)
		}
	}
	if after := history(pubDB); !reflect.DeepEqual(before, after) {
		t.Fatalf("a second Apply changed goose_db_version: %d rows before, %d after", len(before), len(after))
	}
	t.Logf("fresh database: %d migration(s) applied by both paths, %d history rows each", len(got), len(before))
}
