//go:build integration

package postgres_test

import (
	"context"
	"strings"
	"testing"

	"github.com/identuum/identuum-idp-oss/migrations"
)

// TestMigration0053_BackfillCheckAndDown runs 0053's own Up and Down text
// (OSS-0912-C2) against a session-local `users` table that shadows the real
// one (a temporary table is found first on the search path), inside a
// transaction that is rolled back, so the shared test database is never
// altered: verified rows become 'legacy', unverified rows stay NULL (owner Q2
// (b)), the CHECK refuses an unnamed value, a pending row may hold a proof,
// and Down removes the column.
func TestMigration0053_BackfillCheckAndDown(t *testing.T) {
	data, err := migrations.EmbedFS.ReadFile("0053_users_email_verified_via.sql")
	if err != nil {
		t.Fatalf("failed to read 0053: %v", err)
	}
	up, down, ok := strings.Cut(string(data), "-- +goose Down")
	if !ok {
		t.Fatalf("0053 has no Down section")
	}
	ctx := context.Background()
	tx, err := modelTeethPool(t).Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	exec := func(what, sql string) {
		t.Helper()
		for _, stmt := range strings.Split(stripSQLLineComments(sql), ";") {
			if strings.TrimSpace(stmt) == "" {
				continue
			}
			if _, err := tx.Exec(ctx, stmt); err != nil {
				t.Fatalf("%s: %v", what, err)
			}
		}
	}
	exec("shadow table", `CREATE TEMP TABLE users (id INT PRIMARY KEY, email_verified BOOLEAN NOT NULL) ON COMMIT DROP;
		INSERT INTO users VALUES (1, true), (2, false)`)
	exec("0053 Up", up)

	rows, err := tx.Query(ctx, `SELECT id, email_verified_via FROM pg_temp.users ORDER BY id`)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	got := map[int]*string{}
	for rows.Next() {
		var id int
		var via *string
		if err := rows.Scan(&id, &via); err != nil {
			t.Fatalf("scan: %v", err)
		}
		got[id] = via
	}
	rows.Close()
	if got[1] == nil || *got[1] != "legacy" {
		t.Errorf("a verified row's via = %v; want 'legacy'", got[1])
	}
	if got[2] != nil {
		t.Errorf("an unverified row's via = %q; want NULL (never proven)", *got[2])
	}

	exec("savepoint", `SAVEPOINT bad_value`)
	if _, err := tx.Exec(ctx, `UPDATE pg_temp.users SET email_verified_via = 'trusted' WHERE id = 2`); err == nil {
		t.Errorf("the CHECK accepted an unnamed value")
	}
	exec("rollback to savepoint", `ROLLBACK TO SAVEPOINT bad_value`)
	if _, err := tx.Exec(ctx, `UPDATE pg_temp.users SET email_verified_via = 'email_link' WHERE id = 2`); err != nil {
		t.Errorf("an unverified row cannot record a proof: %v", err)
	}

	exec("0053 Down", down)
	var n int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM pg_attribute WHERE attrelid = 'pg_temp.users'::regclass AND attname = 'email_verified_via' AND NOT attisdropped`).Scan(&n); err != nil || n != 0 {
		t.Errorf("after Down the column count = %d (err %v); want 0", n, err)
	}
}

// stripSQLLineComments drops "--" line comments (the goose annotations and
// the header, which may hold a semicolon) before the text is split.
func stripSQLLineComments(s string) string {
	var b strings.Builder
	for _, line := range strings.Split(s, "\n") {
		if i := strings.Index(line, "--"); i >= 0 {
			line = line[:i]
		}
		b.WriteString(line)
		b.WriteString("\n")
	}
	return b.String()
}
