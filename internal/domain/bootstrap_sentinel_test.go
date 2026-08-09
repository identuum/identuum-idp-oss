package domain_test

import (
	"testing"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// TestBootstrapSentinelIDs pins the expected reserved UUIDv7-zero sentinel
// values. These constants are wire-format — they are embedded in migrations
// and in DB rows. Any change requires a coordinated migration across all
// installed instances; this test makes accidental drift a compile-time + test
// failure rather than a silent runtime inconsistency.
func TestBootstrapSentinelIDs(t *testing.T) {
	t.Run("domain.SystemOrgID_is_UUIDv7_zero", func(t *testing.T) {
		const want = "00000000-0000-7000-0000-000000000000"
		if domain.SystemOrgID != want {
			t.Errorf("domain.domain.SystemOrgID = %q, want %q (reserved UUIDv7-zero sentinel)", domain.SystemOrgID, want)
		}
		parsed, err := uuid.Parse(domain.SystemOrgID)
		if err != nil {
			t.Fatalf("domain.domain.SystemOrgID is not a valid UUID: %v", err)
		}
		if parsed.Version() != 7 {
			t.Errorf("domain.domain.SystemOrgID version = %d, want 7 (UUIDv7)", parsed.Version())
		}
	})

	t.Run("domain.SiteAdminID_is_UUIDv7_zero_plus_one", func(t *testing.T) {
		const want = "00000000-0000-7000-0000-000000000001"
		if domain.SiteAdminID != want {
			t.Errorf("domain.domain.SiteAdminID = %q, want %q (reserved UUIDv7-zero+1 sentinel)", domain.SiteAdminID, want)
		}
		parsed, err := uuid.Parse(domain.SiteAdminID)
		if err != nil {
			t.Fatalf("domain.domain.SiteAdminID is not a valid UUID: %v", err)
		}
		if parsed.Version() != 7 {
			t.Errorf("domain.domain.SiteAdminID version = %d, want 7 (UUIDv7)", parsed.Version())
		}
	})

	t.Run("domain.SystemOrgID_and_domain.SiteAdminID_are_distinct", func(t *testing.T) {
		if domain.SystemOrgID == domain.SiteAdminID {
			t.Error("domain.domain.SystemOrgID and domain.domain.SiteAdminID must be distinct UUIDs")
		}
	})

	t.Run("sentinel_IDs_are_not_uuid_nil", func(t *testing.T) {
		nilUUID := uuid.Nil.String()
		if domain.SystemOrgID == nilUUID {
			t.Errorf("domain.domain.SystemOrgID must not be uuid.Nil (%s)", nilUUID)
		}
		if domain.SiteAdminID == nilUUID {
			t.Errorf("domain.domain.SiteAdminID must not be uuid.Nil (%s)", nilUUID)
		}
	})

	t.Run("domain.SiteAdminEmail_is_canonical", func(t *testing.T) {
		const want = "site_admin@system.local"
		if domain.SiteAdminEmail != want {
			t.Errorf("domain.domain.SiteAdminEmail = %q, want %q", domain.SiteAdminEmail, want)
		}
	})

	t.Run("domain.SystemOrgDomain_is_canonical", func(t *testing.T) {
		const want = "system.local"
		if domain.SystemOrgDomain != want {
			t.Errorf("domain.domain.SystemOrgDomain = %q, want %q", domain.SystemOrgDomain, want)
		}
	})

	// LegacySystemOrgID: must be the old non-UUIDv7 sentinel value, distinct from the
	// current SystemOrgID, and explicitly NOT a UUIDv7 (version bit = 0, not 7).
	t.Run("LegacySystemOrgID_is_expected_value", func(t *testing.T) {
		const want = "00000000-0000-0000-0000-000000000001"
		if domain.LegacySystemOrgID != want {
			t.Errorf("domain.LegacySystemOrgID = %q, want %q", domain.LegacySystemOrgID, want)
		}
	})

	t.Run("LegacySystemOrgID_is_distinct_from_SystemOrgID", func(t *testing.T) {
		if domain.LegacySystemOrgID == domain.SystemOrgID {
			t.Errorf("LegacySystemOrgID must not equal SystemOrgID: both are %q", domain.LegacySystemOrgID)
		}
	})

	t.Run("LegacySystemOrgID_is_not_UUIDv7", func(t *testing.T) {
		parsed, err := uuid.Parse(domain.LegacySystemOrgID)
		if err != nil {
			t.Fatalf("LegacySystemOrgID is not a valid UUID: %v", err)
		}
		if parsed.Version() == 7 {
			t.Errorf("LegacySystemOrgID must not be a UUIDv7 (it is the old non-v7 sentinel); got version %d", parsed.Version())
		}
	})
}
