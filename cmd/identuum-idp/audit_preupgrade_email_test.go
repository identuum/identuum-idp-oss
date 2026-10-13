package main

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/identuum/identuum-idp-oss/internal/postgres"
)

// OSS-0914-STAGE-3 item 3 (follow-up of owner decision EMAIL-SCOPE (a)):
// migration 0056 refuses the upgrade while one address belongs to more than
// one live account. audit-preupgrade reports those groups before the upgrade:
// how many addresses, and per group the user ids and organization ids, never
// the address; and it exits non-zero. A soft-deleted account does not count,
// as in 0056.
//
// RULE: AUDIT-PREUPGRADE-EMAIL-DUP-1
func TestAuditPreupgrade_ReportsAddressesThatBlock0056(t *testing.T) {
	dsn := freshMigrateDatabase(t)
	ctx := context.Background()
	var stdout, stderr bytes.Buffer
	if rc := runMigrate(ctx, dsn, &stdout, &stderr); rc != 0 {
		t.Fatalf("migrate exit = %d", rc)
	}
	stdout.Reset()
	if rc := runAuditPreupgrade(ctx, dsn, &stdout, &stderr); rc != 0 {
		t.Fatalf("control: audit of a clean database exit = %d; want 0 (%s)", rc, stdout.String())
	}

	db, err := postgres.OpenStdlibDB(dsn)
	if err != nil {
		t.Fatal("open the scratch database")
	}
	defer db.Close()
	for _, q := range []string{
		`DROP INDEX users_email_lower_key_undeleted`,
		`DELETE FROM goose_db_version WHERE version_id = 56`,
		`INSERT INTO organizations (name, domain, org_slug, active) VALUES ('eg-a', 'eg-a.example.invalid', 'eg-a', true), ('eg-b', 'eg-b.example.invalid', 'eg-b', true)`,
		`INSERT INTO users (email, password_hash, organization_id, role) SELECT 'dup@example.invalid', 'x', id, 'org_user' FROM organizations WHERE org_slug = 'eg-a'`,
		`INSERT INTO users (email, password_hash, organization_id, role) SELECT 'DUP@Example.Invalid', 'x', id, 'org_user' FROM organizations WHERE org_slug = 'eg-b'`,
		`INSERT INTO users (email, password_hash, organization_id, role, deleted_at) SELECT 'gone@example.invalid', 'x', id, 'org_user', now() FROM organizations WHERE org_slug = 'eg-a'`,
		`INSERT INTO users (email, password_hash, organization_id, role) SELECT 'gone@example.invalid', 'x', id, 'org_user' FROM organizations WHERE org_slug = 'eg-b'`,
	} {
		if _, err := db.ExecContext(ctx, q); err != nil {
			t.Fatalf("put the database before 0056: %v", err)
		}
	}
	want := []string{}
	rows, err := db.QueryContext(ctx, `SELECT id::text, organization_id::text FROM users WHERE lower(email) = 'dup@example.invalid'`)
	if err != nil {
		t.Fatalf("read the duplicate group: %v", err)
	}
	for rows.Next() {
		var id, org string
		if err := rows.Scan(&id, &org); err != nil {
			t.Fatalf("scan: %v", err)
		}
		want = append(want, id, org)
	}
	_ = rows.Close()

	stdout.Reset()
	stderr.Reset()
	rc := runAuditPreupgrade(ctx, dsn, &stdout, &stderr)
	out := stdout.String() + stderr.String()
	if rc != 1 {
		t.Errorf("audit exit = %d; want 1 (findings)", rc)
	}
	if !strings.Contains(out, "count=1 ") || !strings.Contains(out, "EMAIL-GLOBAL-UNIQUE-MIGRATION-1") {
		t.Errorf("audit printed %q; want one address under EMAIL-GLOBAL-UNIQUE-MIGRATION-1", out)
	}
	for _, id := range want {
		if !strings.Contains(out, id) {
			t.Errorf("audit output lacks the group's id %s", id)
		}
	}
	if low := strings.ToLower(out); strings.Contains(low, "dup@") || strings.Contains(low, "gone@") || strings.Contains(out, "postgres://") {
		t.Errorf("audit printed an address or the database URL: %q", out)
	}
}
