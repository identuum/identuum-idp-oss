package domain

import (
	"errors"
	"fmt"
	"net/mail"
	"strings"
	"time"
	"unicode"

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

	// THE-UNVALIDATED-DOMAIN: the same grammar the organizations table is
	// held to — one definition, both call sites.
	if err := ValidateDomainFormat(d.Domain); err != nil {
		return err
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
//
// A single trailing dot (the FQDN root form, "example.com.") is stripped so
// that "example.com" and "example.com." are one key, matching what
// normalizeDNSDomainName already does on the verification side.
func NormalizeDomain(d string) string {
	n := strings.ToLower(strings.TrimSpace(d))
	return strings.TrimSuffix(n, ".")
}

// organizationNameMaxLength / organizationSlugMaxLength mirror the live
// column widths (organizations.name, organizations.org_slug are VARCHAR(255)),
// so an over-long value is refused cleanly instead of failing in the driver.
const (
	organizationNameMaxLength = 255
	organizationSlugMaxLength = 255
)

// THE-UNVALIDATED-UPDATE (2026-08-31): these per-field validators exist so the
// CREATE path (Organization.Validate, via buildOrganization) and the UPDATE
// path (OrganizationService.Update, which validates each supplied option) run
// THE SAME rule — one definition per field, never a second grammar. The
// previous slice's rule claimed update coverage it did not have: Update()
// went straight to repo.Update, so PUT {"domain":"lexus"} persisted.
//
// Each takes the field's own type and returns the same error the create path
// has always returned, so behaviour on create is unchanged.

// ValidateOrganizationName refuses a blank/whitespace-only name and anything
// wider than the name column.
func ValidateOrganizationName(name string) error {
	if strings.TrimSpace(name) == "" {
		return errors.New("name is required")
	}
	if len(name) > organizationNameMaxLength {
		return fmt.Errorf("name must be %d characters or fewer", organizationNameMaxLength)
	}
	return nil
}

// ValidateOrganizationSlug accepts an EMPTY slug (it is optional) but holds a
// present one to lowercase letters, digits and hyphens, never hyphen-edged.
func ValidateOrganizationSlug(slug string) error {
	s := strings.TrimSpace(slug)
	if s == "" {
		return nil
	}
	if len(s) > organizationSlugMaxLength {
		return fmt.Errorf("org_slug must be %d characters or fewer", organizationSlugMaxLength)
	}
	if s[0] == '-' || s[len(s)-1] == '-' {
		return errors.New("org_slug must not start or end with a hyphen")
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z') && !(c >= '0' && c <= '9') && c != '-' {
			return errors.New("org_slug may contain only lowercase letters, digits and hyphens")
		}
	}
	return nil
}

// ValidateOrganizationTier refuses a value outside the enum, which would
// otherwise render as TierBase via Tier.String() — a silent downgrade.
func ValidateOrganizationTier(t Tier) error {
	if t != TierBase && t != TierPro && t != TierEnterprise {
		return errors.New("tier must be one of TierBase, TierPro or TierEnterprise")
	}
	return nil
}

// ValidateMaxSessionsPerUser bounds the per-user session cap.
func ValidateMaxSessionsPerUser(n int) error {
	if n < 1 {
		return errors.New("max_sessions_per_user must be at least 1")
	}
	if n > 100 {
		return errors.New("max_sessions_per_user cannot exceed 100")
	}
	return nil
}

// ValidateMFAPolicy accepts only the two policy words the column stores.
func ValidateMFAPolicy(p string) error {
	if p != "optional" && p != "required" {
		return errors.New("mfa_policy must be 'optional' or 'required'")
	}
	return nil
}

// ValidateServiceAccountExpiryDays bounds the SA expiry window (0 = perpetual).
func ValidateServiceAccountExpiryDays(d int) error {
	if d < 0 || d > 3650 {
		return errors.New("service_account_expiry_days must be between 0 (perpetual) and 3650")
	}
	return nil
}

// ValidateM2MAnomalyLimit / ValidateM2MAnomalyWindowSeconds refuse negative
// counts and windows. Zero remains valid — it is the "disabled" value live
// rows carry.
func ValidateM2MAnomalyLimit(n int) error {
	if n < 0 {
		return errors.New("m2m_anomaly_limit must not be negative")
	}
	return nil
}

func ValidateM2MAnomalyWindowSeconds(n int) error {
	if n < 0 {
		return errors.New("m2m_anomaly_window_seconds must not be negative")
	}
	return nil
}

// ValidateAuthPolicyValue / ValidateAPIAuthorizationPolicyValue mirror the
// policy checks Organization.Validate performs, for the update path.
func ValidateAuthPolicyValue(p string) error {
	if p != AuthPolicyPermissive && p != AuthPolicyLocalOnly && p != AuthPolicyIDPOnly && p != AuthPolicyMixed {
		return errors.New("auth_policy must be one of 'local_only', 'idp_only', 'mixed', or '' (permissive default)")
	}
	return nil
}

func ValidateAPIAuthorizationPolicyValue(p string) error {
	if p != "" && p != APIAuthPolicyStrict && p != APIAuthPolicyImplicit {
		return errors.New("api_authorization_policy must be 'STRICT' or 'IMPLICIT'")
	}
	return nil
}

// ValidateComplianceContactEmail accepts an empty value (the field is
// optional, and clearing it is legitimate) and otherwise requires a parseable
// address — the same mail.ParseAddress convention User.Validate uses.
func ValidateComplianceContactEmail(email string) error {
	e := strings.TrimSpace(email)
	if e == "" {
		return nil
	}
	if _, err := mail.ParseAddress(e); err != nil {
		return errors.New("compliance_contact_email must be a valid email address")
	}
	return nil
}

// domainMaxLength is the DNS limit on a fully-qualified name in presentation
// form (RFC 1035 §2.3.4, 255 octets of wire format ≙ 253 characters here).
const domainMaxLength = 253

// domainLabelMaxLength is the DNS limit on a single label (RFC 1035 §2.3.4).
const domainLabelMaxLength = 63

// ValidateDomainFormat is THE domain-format grammar for this codebase — one
// definition, used by both Organization.Validate and
// OrganizationDomain.Validate. It is deliberately the only place the shape is
// decided; adding a second grammar elsewhere is how the two drift apart.
//
// THE-UNVALIDATED-DOMAIN (2026-08-31): before this, the entire check on an
// organization's domain was `== ""`, so `lexus` — no dot, no TLD — was
// accepted and persisted. OrganizationDomain.Validate had no format check
// either, so wiring it in would not have caught it.
//
// THE GRAMMAR, on the NORMALIZED value (lowercase, trimmed, one optional
// trailing dot removed):
//
//	total length            1..253 characters
//	at least TWO labels     a dot is REQUIRED — this is what rejects "lexus"
//	label length            1..63 characters each; no empty label, so no
//	                        leading/trailing dot and no ".." run
//	label alphabet          a-z, 0-9 and '-' (ASCII LDH); a label may not
//	                        start or end with '-'
//	final label (the TLD)   at least 2 characters, and either all-alphabetic
//	                        or an A-label ("xn--" prefix). This rejects
//	                        numeric TLDs, which is also what rejects a bare
//	                        IPv4 address like 192.168.1.1
//	case                    input is lowercased before checking, so
//	                        "Example.COM" is accepted and stored lowercase
//	IDN                     ASCII/punycode ONLY. A name containing non-ASCII
//	                        is refused with a message telling the operator to
//	                        submit the punycode (xn--) form. Converting it
//	                        here would mean shipping an IDNA table and a
//	                        normalization policy this slice did not measure.
//
// DELIBERATELY STILL ACCEPTED: any syntactically valid TLD, including .test,
// .local, .internal and unregistered ones. There is no IANA list check —
// the system organization itself is "system.local", the harness uses ".test"
// throughout, and a bundled list would go stale silently. This validator
// answers "is this a well-formed domain name", not "is this a registered
// public domain"; the latter is what the DNS verification flow is for.
func ValidateDomainFormat(d string) error {
	n := NormalizeDomain(d)
	if n == "" {
		return errors.New("domain is required")
	}
	if len(n) > domainMaxLength {
		return fmt.Errorf("%w: longer than %d characters", ErrOrganizationDomainInvalid, domainMaxLength)
	}
	for _, r := range n {
		if r > unicode.MaxASCII {
			return fmt.Errorf("%w: %q contains non-ASCII characters — submit the punycode (xn--) form",
				ErrOrganizationDomainInvalid, d)
		}
	}

	labels := strings.Split(n, ".")
	if len(labels) < 2 {
		return fmt.Errorf("%w: %q has no dot — a domain needs at least a name and a top-level domain (for example %q)",
			ErrOrganizationDomainInvalid, d, n+".com")
	}

	for _, label := range labels {
		if label == "" {
			return fmt.Errorf("%w: %q has an empty label (a leading dot, a trailing dot, or \"..\")",
				ErrOrganizationDomainInvalid, d)
		}
		if len(label) > domainLabelMaxLength {
			return fmt.Errorf("%w: label %q is longer than %d characters",
				ErrOrganizationDomainInvalid, label, domainLabelMaxLength)
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return fmt.Errorf("%w: label %q starts or ends with a hyphen",
				ErrOrganizationDomainInvalid, label)
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			isLower := c >= 'a' && c <= 'z'
			isDigit := c >= '0' && c <= '9'
			if !isLower && !isDigit && c != '-' {
				return fmt.Errorf("%w: label %q contains %q — only letters, digits and hyphens are allowed",
					ErrOrganizationDomainInvalid, label, string(rune(c)))
			}
		}
	}

	tld := labels[len(labels)-1]
	if len(tld) < 2 {
		return fmt.Errorf("%w: top-level domain %q is shorter than 2 characters",
			ErrOrganizationDomainInvalid, tld)
	}
	if !strings.HasPrefix(tld, "xn--") {
		for i := 0; i < len(tld); i++ {
			if tld[i] < 'a' || tld[i] > 'z' {
				return fmt.Errorf("%w: top-level domain %q must be alphabetic (or a punycode \"xn--\" label)",
					ErrOrganizationDomainInvalid, tld)
			}
		}
	}
	return nil
}
