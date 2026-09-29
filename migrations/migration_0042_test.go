package migrations_test

import (
	"strings"
	"testing"

	"github.com/identuum/identuum-idp-oss/migrations"
)

// TestMigration0042AuditEventsOrganization is a content-level guard over the
// OSS-FIN-3 column: Up adds organization_id with its index and backfills only
// from a metadata organization_id that names an existing organization (text
// comparison, no cast); Down drops both and nothing else.
func TestMigration0042AuditEventsOrganization(t *testing.T) {
	data, err := migrations.EmbedFS.ReadFile("0042_audit_events_organization.sql")
	if err != nil {
		t.Fatalf("failed to read 0042: %v", err)
	}
	up, down, ok := strings.Cut(string(data), "-- +goose Down")
	if !ok {
		t.Fatalf("0042 has no Down section")
	}
	for _, want := range []string{
		"ADD COLUMN organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE",
		"ON audit_events (organization_id, created_at DESC)",
		"a.metadata ? 'organization_id'",
		"o.id::text = lower(a.metadata->>'organization_id')",
		"a.organization_id IS NULL",
	} {
		if !strings.Contains(up, want) {
			t.Errorf("0042 Up lacks %q", want)
		}
	}
	if strings.Contains(up, "::uuid") {
		t.Errorf("0042 Up casts metadata to uuid; a malformed value would fail the migration")
	}
	if !strings.Contains(down, "DROP INDEX IF EXISTS idx_audit_events_organization_created_at") ||
		!strings.Contains(down, "DROP COLUMN IF EXISTS organization_id") {
		t.Errorf("0042 Down does not drop the index and the column")
	}
}
