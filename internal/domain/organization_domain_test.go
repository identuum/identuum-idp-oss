package domain

import (
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func newPendingOrgDomain() *OrganizationDomain {
	return &OrganizationDomain{
		ID:             uuid.New(),
		OrganizationID: uuid.New(),
		Domain:         "example.com",
		IsPrimary:      false,
		CreatedAt:      time.Now().UTC(),
		UpdatedAt:      time.Now().UTC(),
	}
}

func newVerifiedOrgDomain() *OrganizationDomain {
	now := time.Now().UTC()
	d := newPendingOrgDomain()
	d.VerifiedAt = &now
	return d
}

func TestOrganizationDomain_Validate_Pending_NoToken_OK(t *testing.T) {
	d := newPendingOrgDomain()
	if err := d.Validate(); err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
}

func TestOrganizationDomain_Validate_Pending_WithCoherentToken_OK(t *testing.T) {
	d := newPendingOrgDomain()
	hash := "sha256-hash"
	exp := time.Now().UTC().Add(1 * time.Hour)
	d.VerificationTokenHash = &hash
	d.VerificationTokenExpiresAt = &exp

	if err := d.Validate(); err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
}

func TestOrganizationDomain_Validate_Verified_OK(t *testing.T) {
	d := newVerifiedOrgDomain()
	if err := d.Validate(); err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
}

func TestOrganizationDomain_Validate_MissingOrganizationID_Rejected(t *testing.T) {
	d := newPendingOrgDomain()
	d.OrganizationID = uuid.Nil
	if err := d.Validate(); err == nil {
		t.Fatal("expected error for nil organization id, got nil")
	}
}

func TestOrganizationDomain_Validate_EmptyDomain_Rejected(t *testing.T) {
	d := newPendingOrgDomain()
	d.Domain = "   "
	if err := d.Validate(); err == nil {
		t.Fatal("expected error for empty domain, got nil")
	}
}

func TestOrganizationDomain_Validate_NegativeAttempts_Rejected(t *testing.T) {
	d := newPendingOrgDomain()
	d.VerificationAttempts = -1
	if err := d.Validate(); err == nil {
		t.Fatal("expected error for negative verification attempts, got nil")
	}
}

func TestOrganizationDomain_Validate_Verified_WithTokenHash_Rejected(t *testing.T) {
	d := newVerifiedOrgDomain()
	hash := "sha256-hash"
	d.VerificationTokenHash = &hash
	if err := d.Validate(); err == nil {
		t.Fatal("expected error for verified domain carrying token hash, got nil")
	}
}

func TestOrganizationDomain_Validate_Verified_WithTokenExpiry_Rejected(t *testing.T) {
	d := newVerifiedOrgDomain()
	exp := time.Now().UTC().Add(1 * time.Hour)
	d.VerificationTokenExpiresAt = &exp
	if err := d.Validate(); err == nil {
		t.Fatal("expected error for verified domain carrying token expiry, got nil")
	}
}

func TestOrganizationDomain_Validate_Pending_TokenHashWithoutExpiry_Rejected(t *testing.T) {
	d := newPendingOrgDomain()
	hash := "sha256-hash"
	d.VerificationTokenHash = &hash
	if err := d.Validate(); err == nil {
		t.Fatal("expected error for token hash without expiry, got nil")
	}
}

func TestOrganizationDomain_Validate_Pending_TokenExpiryWithoutHash_Rejected(t *testing.T) {
	d := newPendingOrgDomain()
	exp := time.Now().UTC().Add(1 * time.Hour)
	d.VerificationTokenExpiresAt = &exp
	if err := d.Validate(); err == nil {
		t.Fatal("expected error for token expiry without hash, got nil")
	}
}

func TestOrganizationDomain_IsVerified_TrueWhenVerifiedAtSet(t *testing.T) {
	d := newVerifiedOrgDomain()
	if !d.IsVerified() {
		t.Fatal("expected IsVerified true when VerifiedAt is set")
	}
}

func TestOrganizationDomain_IsVerified_FalseWhenPending(t *testing.T) {
	d := newPendingOrgDomain()
	if d.IsVerified() {
		t.Fatal("expected IsVerified false when VerifiedAt is nil")
	}
}

func TestOrganizationDomain_HasPendingVerificationToken_TrueWhenHashSet(t *testing.T) {
	d := newPendingOrgDomain()
	hash := "sha256-hash"
	exp := time.Now().UTC().Add(1 * time.Hour)
	d.VerificationTokenHash = &hash
	d.VerificationTokenExpiresAt = &exp
	if !d.HasPendingVerificationToken() {
		t.Fatal("expected HasPendingVerificationToken true")
	}
}

func TestOrganizationDomain_HasPendingVerificationToken_FalseWhenWhitespace(t *testing.T) {
	d := newPendingOrgDomain()
	hash := "   "
	d.VerificationTokenHash = &hash
	if d.HasPendingVerificationToken() {
		t.Fatal("expected HasPendingVerificationToken false for whitespace-only hash")
	}
}

func TestNormalizeDomain_LowercaseAndTrim(t *testing.T) {
	got := NormalizeDomain("  Example.COM  ")
	if got != "example.com" {
		t.Fatalf("expected example.com, got %q", got)
	}
}

func TestNormalizeDomain_EmptyStringStaysEmpty(t *testing.T) {
	if got := NormalizeDomain("   "); got != "" {
		t.Fatalf("expected empty string, got %q", got)
	}
}

// TestOrganizationDomain_ErrorSentinelsAreDistinct pins the sentinel
// error identity so a future refactor cannot accidentally collapse two
// of them into the same value (which would defeat errors.Is on call
// sites that branch on the specific lifecycle failure).
func TestOrganizationDomain_ErrorSentinelsAreDistinct(t *testing.T) {
	sentinels := []error{
		ErrOrganizationDomainNotFound,
		ErrOrganizationDomainAlreadyExists,
		ErrOrganizationDomainVerifiedByOther,
		ErrOrganizationDomainInvalid,
	}
	for i := range sentinels {
		for j := i + 1; j < len(sentinels); j++ {
			if sentinels[i] == sentinels[j] {
				t.Fatalf("sentinel %d and %d collide on identity", i, j)
			}
			if strings.TrimSpace(sentinels[i].Error()) == strings.TrimSpace(sentinels[j].Error()) {
				t.Fatalf("sentinel %d and %d collide on message", i, j)
			}
		}
	}
}
