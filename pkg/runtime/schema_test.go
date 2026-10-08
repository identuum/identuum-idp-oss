package runtime_test

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	goosev3 "github.com/pressly/goose/v3"

	"github.com/identuum/identuum-idp-oss/internal/postgres"
	"github.com/identuum/identuum-idp-oss/internal/testsupport"
	coremigrations "github.com/identuum/identuum-idp-oss/migrations"
	"github.com/identuum/identuum-idp-oss/pkg/runtime"
)

// scratchDatabase creates an empty database next to the test database and
// drops it when the test ends; it returns the new database's URL and handle.
func scratchDatabase(t *testing.T, name string) (string, *sql.DB) {
	t.Helper()
	dsn := os.Getenv("IDENTUUM_IDP_TEST_DATABASE_URL")
	if dsn == "" {
		if os.Getenv("IDENTUUM_IDP_REQUIRE_DB_TESTS") != "" {
			t.Fatal("IDENTUUM_IDP_REQUIRE_DB_TESTS is set but IDENTUUM_IDP_TEST_DATABASE_URL is not")
		}
		t.Skip("IDENTUUM_IDP_TEST_DATABASE_URL not set; skipping a DB-backed schema test")
	}
	if err := testsupport.RequireTestDatabase(dsn); err != nil {
		t.Fatal(err)
	}
	admin, err := postgres.OpenStdlibDB(dsn)
	if err != nil {
		t.Fatalf("open the test database: %v", err)
	}
	// Registered first, so it closes last: the DROP below needs it.
	t.Cleanup(func() { _ = admin.Close() })
	ctx := context.Background()
	if _, err := admin.ExecContext(ctx, `DROP DATABASE IF EXISTS `+name+` WITH (FORCE)`); err != nil {
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
	return u.String(), db
}

// migrateTo applies the embedded migrations up to and including version.
func migrateTo(t *testing.T, db *sql.DB, version int64) {
	t.Helper()
	p, err := goosev3.NewProvider(goosev3.DialectPostgres, db, coremigrations.EmbedFS)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.UpTo(context.Background(), version); err != nil {
		t.Fatalf("migrate to %d: %v", version, err)
	}
}

// rowCounts gives every table in the public schema as its row count and a
// digest of its rows, so an update shows as well as an insert.
func rowCounts(t *testing.T, db *sql.DB) map[string]string {
	t.Helper()
	ctx := context.Background()
	rows, err := db.QueryContext(ctx, `SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' AND table_type = 'BASE TABLE'`)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			t.Fatal(err)
		}
		names = append(names, n)
	}
	_ = rows.Close()
	out := map[string]string{}
	for _, n := range names {
		var c int64
		var digest sql.NullString
		q := fmt.Sprintf(`SELECT count(*), md5(string_agg(t::text, ',' ORDER BY t::text)) FROM %q t`, n)
		if err := db.QueryRowContext(ctx, q).Scan(&c, &digest); err != nil {
			t.Fatal(err)
		}
		out[n] = fmt.Sprintf("%d rows %s", c, digest.String)
	}
	return out
}

// startOn builds a runtime on dsn with the single-replica lease ON (no
// override), starts it on its own listener and returns it with the address.
func startOn(t *testing.T, dsn, dataDir string) (*runtime.Runtime, string, error) {
	t.Helper()
	ln := listen(t)
	getenv := func(k string) string {
		if k == "IDENTUUM_IDP_ALLOW_MULTI_REPLICA" {
			return ""
		}
		return os.Getenv(k)
	}
	rt, err := runtime.NewWithListener(runtime.Options{Issuer: "http://localhost:7113", DatabaseURL: dsn,
		DataDir: dataDir, Stdout: io.Discard, Stderr: io.Discard, Getenv: getenv}, ln)
	if err != nil {
		t.Fatal(err)
	}
	return rt, ln.Addr().String(), rt.Start(context.Background())
}

func body(t *testing.T, addr, path string) (int, string) {
	t.Helper()
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Get("http://" + addr + path)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// OSS-SEAM-3 proofs 1-3 (owner ruling y): a schema one version behind, or
// one version ahead, is NOT-SERVING — a normal route answers 503, /health and
// Health show one fatal fault naming both versions and no URL — and the
// runtime writes no row and no setup token while it holds that state.
func TestSchemaVersionMismatch_IsNotServingAndWritesNothing(t *testing.T) {
	want := postgres.EmbeddedSchemaVersion()
	cases := []struct {
		name  string
		found int64
		setup func(t *testing.T, db *sql.DB)
	}{
		{"older", want - 1, func(t *testing.T, db *sql.DB) { migrateTo(t, db, want-1) }},
		{"newer", want + 1, func(t *testing.T, db *sql.DB) {
			migrateTo(t, db, want)
			if _, err := db.Exec(`INSERT INTO goose_db_version (version_id, is_applied) VALUES ($1, true)`, want+1); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dsn, db := scratchDatabase(t, "identuum_idp_oss_test_seam3_"+tc.name)
			tc.setup(t, db)
			before := rowCounts(t, db)
			dataDir := t.TempDir()
			rt, addr, err := startOn(t, dsn, dataDir)
			if err != nil {
				t.Fatalf("a schema at another version is NOT-SERVING, not a Start error: %v", err)
			}
			reason := fmt.Sprintf("schema at %d, this server needs %d: run identuum-idp migrate", tc.found, want)
			if code, _ := body(t, addr, "/api/v1/component"); code != http.StatusServiceUnavailable {
				t.Errorf("a normal route answered %d; want 503", code)
			}
			code, health := body(t, addr, "/health")
			if code == 0 || !strings.Contains(health, reason) {
				t.Errorf("/health answered %d without the fault %q", code, reason)
			}
			h := rt.Health()
			var fatal []runtime.Fault
			for _, f := range h.Faults {
				if f.Fatal {
					fatal = append(fatal, f)
				}
			}
			if h.Serving || len(fatal) != 1 || fatal[0].Reason != reason {
				t.Errorf("Health: serving %v, fatal faults %v; want NOT-SERVING with one fault %q", h.Serving, fatal, reason)
			}
			for _, text := range []string{health, fmt.Sprint(h.Faults)} {
				if strings.Contains(text, dsn) || strings.Contains(text, "postgres://") {
					t.Error("the fault text carries the database URL")
				}
			}
			if err := shutdown(t, rt); err != nil {
				t.Fatal(err)
			}
			if after := rowCounts(t, db); !reflect.DeepEqual(before, after) {
				for n := range after {
					if before[n] != after[n] {
						t.Errorf("table %s changed while NOT-SERVING", n)
					}
				}
			}
			if entries, _ := os.ReadDir(dataDir); len(entries) != 0 {
				t.Errorf("the data directory gained %s; want nothing written", filepath.Join(dataDir, entries[0].Name()))
			}
		})
	}
}

// OSS-SEAM-3 proof 5: a database without the migrations table keeps today's
// answer, a Start error that says to migrate.
func TestSchemaVersion_MissingTableKeepsTodaysError(t *testing.T) {
	dsn, _ := scratchDatabase(t, "identuum_idp_oss_test_seam3_empty")
	rt, _, err := startOn(t, dsn, t.TempDir())
	if err == nil {
		_ = shutdown(t, rt)
		t.Fatal("Start on a database without migrations succeeded")
	}
	const today = "runtime: the database is not migrated — run `identuum-idp migrate <database-url>` before serving (the image's entrypoint migrates on start; the bare binary does not)"
	if err.Error() != today {
		t.Fatalf("Start answered %q; want today's %q", err, today)
	}
}
