package migrations_test

import (
	"strings"
	"testing"

	"github.com/identuum/identuum-idp-oss/migrations"
)

// TestMigration0005CreatesOrganizationDomains is a content-level guard
// over the final OSS migration: the organization_domains table must be
// created with the citext extension, the four-index hot-path support
// (organization_id, domain, verified-partial, primary-partial), the
// shared updated_at trigger reused from migration 0001, and the
// backfill from organizations.domain. Renames or drops here are
// breaking — flag them loudly.
func TestMigration0005CreatesOrganizationDomains(t *testing.T) {
	data, err := migrations.EmbedFS.ReadFile("0005_organization_domains.sql")
	if err != nil {
		t.Fatalf("failed to read 0005: %v", err)
	}
	body := string(data)

	mustContain := []string{
		`CREATE EXTENSION IF NOT EXISTS citext`,
		`CREATE TABLE organization_domains`,
		`uq_org_domains_org_domain`,
		`uq_org_domains_verified_domain`,
		`uq_org_domains_one_primary_per_org`,
		`idx_org_domains_organization_id`,
		`idx_org_domains_domain`,
		`idx_org_domains_verification_expires`,
		`trg_organization_domains_updated_at`,
		`set_organizations_updated_at`,
		`INSERT INTO organization_domains`,
		`FROM organizations o`,
	}
	for _, needle := range mustContain {
		if !strings.Contains(body, needle) {
			t.Errorf("0005_organization_domains.sql missing required substring %q", needle)
		}
	}
}
