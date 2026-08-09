package domain

import (
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
)

// OrganizationDomain is one verified-or-pending domain owned by an
// organization. Slice 1 of the org-admin Domains feature introduces the
// type and its backing table; no HTTP surface mutates this type yet.
//
// Lifecycle:
//
//   - A row with VerifiedAt == nil is a pending claim. While pending it
//     may carry a VerificationTokenHash + VerificationTokenExpiresAt so a
//     future slice can complete out-of-band proof-of-control (e.g. DNS
//     TXT challenge).
//   - A row with VerifiedAt != nil is the canonical verified claim for
//     the (organization, domain) pair. Verified rows MUST NOT carry
//     verification token state — the token is single-use and is cleared
//     when verification succeeds.
//   - IsPrimary marks the org's public discovery domain. At most one row
//     per organization may carry IsPrimary == true (enforced by the
//     partial unique index uq_org_domains_one_primary_per_org).
//
// Authority: every read and write on this type is organization-scoped.
// No call site should accept an organization id from client input — the
// caller's session-derived actor.OrganizationID is authoritative. (Slice
// 1 ships no callers; this constraint binds the future handler slice.)
type OrganizationDomain struct {
	ID                         uuid.UUID
	OrganizationID             uuid.UUID
	Domain                     string
	IsPrimary                  bool
	VerifiedAt                 *time.Time
	VerificationTokenHash      *string
	VerificationTokenExpiresAt *time.Time
	VerificationAttempts       int
	CreatedAt                  time.Time
	UpdatedAt                  time.Time
}

// Sentinel errors for OrganizationDomain. They mirror the existing
// ErrOrganization* style in errors.go so callers can errors.Is() them.
var (
	ErrOrganizationDomainNotFound        = errors.New("organization domain not found")
	ErrOrganizationDomainAlreadyExists   = errors.New("organization domain already exists")
	ErrOrganizationDomainVerifiedByOther = errors.New("organization domain already verified by another organization")
	ErrOrganizationDomainInvalid         = errors.New("organization domain is invalid")
)

// IsVerified reports whether this row represents a completed proof-of-
// control claim. Pending rows return false.
func (d *OrganizationDomain) IsVerified() bool {
	return d.VerifiedAt != nil
}

// HasPendingVerificationToken reports whether this row currently carries
// outstanding verification token state. A row may have IsVerified() ==
// false and HasPendingVerificationToken() == false simultaneously (a
// freshly created claim before the token is minted, or a row whose
// previous token has been cleared by a callable cleanup job).
func (d *OrganizationDomain) HasPendingVerificationToken() bool {
	return d.VerificationTokenHash != nil && strings.TrimSpace(*d.VerificationTokenHash) != ""
}

// Validate enforces the model invariants used as a guard at the
// repository boundary. The same invariants are pinned at the database
// layer (CHECK constraints + partial unique indexes); Validate is the
// fail-fast guard for callers that have not yet hit the DB.
//
// Token state semantics:
//
//   - Verified rows MUST NOT carry token hash or token-expires-at.
//   - A row with a token hash MUST also carry a token-expires-at, and
//     vice versa — the pair is meaningful only together.
func (d *OrganizationDomain) Validate() error {
	if d.OrganizationID == uuid.Nil {
		return errors.New("organization_id is required")
	}

	trimmed := strings.TrimSpace(d.Domain)
	if trimmed == "" {
		return errors.New("domain is required")
	}

	if d.VerificationAttempts < 0 {
		return errors.New("verification_attempts must be non-negative")
	}

	if d.IsVerified() {
		if d.VerificationTokenHash != nil {
			return errors.New("verified domain must not carry a verification token hash")
		}
		if d.VerificationTokenExpiresAt != nil {
			return errors.New("verified domain must not carry a verification token expiry")
		}
		return nil
	}

	// Pending row. Token state, if present, must be coherent.
	hasHash := d.VerificationTokenHash != nil && strings.TrimSpace(*d.VerificationTokenHash) != ""
	hasExpiry := d.VerificationTokenExpiresAt != nil
	if hasHash != hasExpiry {
		return errors.New("verification token hash and expiry must be set together")
	}

	return nil
}

// NormalizeDomain returns the wire-canonical form of a domain string for
// storage and lookup. Mirrors the lowercase-trim used by the existing
// HandleUpdateOrganization path so the new table sees the same shape the
// legacy organizations.domain column already sees.
func NormalizeDomain(d string) string {
	return strings.ToLower(strings.TrimSpace(d))
}
