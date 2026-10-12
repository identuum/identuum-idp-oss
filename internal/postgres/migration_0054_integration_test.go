//go:build integration

package postgres_test

import (
	"context"
	"strings"
	"testing"

	"github.com/identuum/identuum-idp-oss/migrations"
)

// TestMigration0054_SpendsAddresslessRowsAndDown runs 0054's own Up and Down
// text (OSS-0912-C2-FIX, review R1) against a session-local
// `email_verifications` table that shadows the real one, inside a transaction
// that is rolled back: an unused row from before the upgrade (no address) is
// spent, a used row keeps its time, a row written after the upgrade with an
// address stays open, and Down removes the column.
func TestMigration0054_SpendsAddresslessRowsAndDown(t *testing.T) {
	data, err := migrations.EmbedFS.ReadFile("0054_email_verifications_address.sql")
	if err != nil {
		t.Fatalf("failed to read 0054: %v", err)
	}
	up, down, ok := strings.Cut(string(data), "-- +goose Down")
	if !ok {
		t.Fatalf("0054 has no Down section")
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
	exec("shadow table", `CREATE TEMP TABLE email_verifications (token_hash TEXT PRIMARY KEY, used_at TIMESTAMPTZ) ON COMMIT DROP;
		INSERT INTO email_verifications VALUES ('open', NULL), ('used', '2026-01-01T00:00:00Z')`)
	exec("0054 Up", up)
	exec("a row after the upgrade", `INSERT INTO pg_temp.email_verifications (token_hash, email_hash) VALUES ('new', repeat('a', 64))`)

	spent := map[string]bool{}
	rows, err := tx.Query(ctx, `SELECT token_hash, used_at IS NOT NULL, used_at = '2026-01-01T00:00:00Z' FROM pg_temp.email_verifications`)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	keptTime := false
	for rows.Next() {
		var h string
		var used bool
		var same *bool
		if err := rows.Scan(&h, &used, &same); err != nil {
			t.Fatalf("scan: %v", err)
		}
		spent[h] = used
		if h == "used" && same != nil && *same {
			keptTime = true
		}
	}
	rows.Close()
	if !spent["open"] {
		t.Errorf("an unused row without an address stays open; want it spent")
	}
	if !spent["used"] || !keptTime {
		t.Errorf("a used row lost its used_at")
	}
	if spent["new"] {
		t.Errorf("a row with an address is spent; want it open")
	}

	exec("0054 Down", down)
	var n int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM pg_attribute WHERE attrelid = 'pg_temp.email_verifications'::regclass AND attname = 'email_hash' AND NOT attisdropped`).Scan(&n); err != nil || n != 0 {
		t.Errorf("after Down the column count = %d (err %v); want 0", n, err)
	}
}
