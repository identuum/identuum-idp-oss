package main

import (
	"bytes"
	"context"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/identuum/identuum-idp-oss/internal/postgres"
	"github.com/identuum/identuum-idp-oss/internal/testsupport"
)

// OSS-MIGRATE-COUNT: `migrate` (and factory-reset's re-migration) says what
// it did — how many migrations it applied, how many the binary embeds, and
// the database's resulting version. It used to print len(goose Up's
// results) as the embedded count, and Up returns only what it applied, so an
// up-to-date database read "applied 0 migration(s) of 0 embedded". DB-gated
// like the runtime tests: skips without IDENTUUM_IDP_TEST_DATABASE_URL, fails
// under IDENTUUM_IDP_REQUIRE_DB_TESTS.

// embeddedMigrations counts the .sql files in migrations/ (the directory the
// binary embeds whole, migrations/embed.go) and their highest version, read
// from disk so the expectation does not come from the code under test (and
// this layer may not import the migrations package, boundaries.json).
func embeddedMigrations(t *testing.T) (int, int64) {
	t.Helper()
	names, err := fs.Glob(os.DirFS("../../migrations"), "*.sql")
	if err != nil || len(names) == 0 {
		t.Fatalf("embedded migrations: %d (%v)", len(names), err)
	}
	var top int64
	for _, n := range names {
		digits := n[:strings.IndexFunc(n, func(r rune) bool { return r < '0' || r > '9' })]
		v, err := strconv.ParseInt(digits, 10, 64)
		if err != nil {
			t.Fatalf("migration %s has no numeric version", n)
		}
		top = max(top, v)
	}
	return len(names), top
}

// freshMigrateDatabase creates an empty, guarded (*_test) database beside the
// test database and returns its DSN; it is dropped when the test ends.
func freshMigrateDatabase(t *testing.T) string {
	t.Helper()
	base := os.Getenv("IDENTUUM_IDP_TEST_DATABASE_URL")
	if base == "" {
		if os.Getenv("IDENTUUM_IDP_REQUIRE_DB_TESTS") != "" {
			t.Fatal("IDENTUUM_IDP_REQUIRE_DB_TESTS is set but IDENTUUM_IDP_TEST_DATABASE_URL is not")
		}
		t.Skip("IDENTUUM_IDP_TEST_DATABASE_URL not set; skipping DB-backed migrate report test")
	}
	if err := testsupport.RequireTestDatabase(base); err != nil {
		t.Fatal(err)
	}
	name := fmt.Sprintf("migrate_report_%d_test", os.Getpid())
	admin, err := postgres.OpenStdlibDB(base)
	if err != nil {
		t.Fatal("open test database")
	}
	defer admin.Close()
	ctx := context.Background()
	_, _ = admin.ExecContext(ctx, "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)")
	if _, err := admin.ExecContext(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatalf("create %s: %v", name, err)
	}
	t.Cleanup(func() {
		if db, err := postgres.OpenStdlibDB(base); err == nil {
			_, _ = db.ExecContext(context.Background(), "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)")
			_ = db.Close()
		}
	})
	u, err := url.Parse(base)
	if err != nil {
		t.Fatal("parse test database URL")
	}
	u.Path = "/" + name
	return u.String()
}

func TestMigrate_ReportsAppliedEmbeddedAndTheDatabaseVersion(t *testing.T) {
	dsn := freshMigrateDatabase(t)
	m, v := embeddedMigrations(t)
	ctx := context.Background()
	run := func(what string, fn func(context.Context, string, *bytes.Buffer, *bytes.Buffer) int) string {
		var stdout, stderr bytes.Buffer
		if rc := fn(ctx, dsn, &stdout, &stderr); rc != 0 {
			t.Fatalf("%s exit = %d; stderr %q", what, rc, stderr.String())
		}
		if strings.Contains(stdout.String()+stderr.String(), "postgres://") {
			t.Fatalf("%s printed a database URL", what)
		}
		return stdout.String()
	}
	migrate := func(ctx context.Context, dsn string, o, e *bytes.Buffer) int { return runMigrate(ctx, dsn, o, e) }
	reset := func(ctx context.Context, dsn string, o, e *bytes.Buffer) int { return runFactoryReset(ctx, dsn, o, e) }

	for _, tc := range []struct {
		what, want string
		fn         func(context.Context, string, *bytes.Buffer, *bytes.Buffer) int
	}{
		{"migrate on a fresh database", fmt.Sprintf("identuum-idp: migrate: applied %d migration(s) of %d embedded; database at version %d\n", m, m, v), migrate},
		{"migrate on the up-to-date database", fmt.Sprintf("identuum-idp: migrate: applied 0 migration(s) of %d embedded; database at version %d\n", m, v), migrate},
		{"factory-reset's re-migration", fmt.Sprintf("identuum-idp: factory-reset: re-applied %d migration(s) of %d embedded; database at version %d\n", m, m, v), reset},
	} {
		out := run(tc.what, tc.fn)
		if !strings.Contains(out, tc.want) {
			t.Errorf("%s printed:\n%s\nwant the line %q", tc.what, out, strings.TrimSpace(tc.want))
		}
	}
}
