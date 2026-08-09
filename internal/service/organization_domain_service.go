package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/lifecycle"
	"github.com/identuum/identuum-idp-oss/internal/repository"
	"github.com/identuum/identuum-idp-oss/internal/utils/uuidgen"
)

// DomainProofVerifier abstracts the proof-of-control check the
// organization-domain service runs at /verify. The OSS DNS verifier
// (DNSDomainProofVerifier) implements this; tests inject a fake.
type DomainProofVerifier interface {
	Verify(ctx context.Context, domainName string, expectedHashHex string) error
}

// OrganizationDomainService is the OSS-narrow domain admin surface.
// It takes the OrganizationDomainRepository plus a DomainProofVerifier
// (the production wiring is the OSS DNS verifier). When no verifier
// is wired, Verify returns ErrDomainVerifierUnavailable so the route
// fails closed rather than silently approving.
type OrganizationDomainService struct {
	repo     repository.OrganizationDomainRepository
	verifier DomainProofVerifier
	now      func() time.Time
}

// ErrDomainVerifierUnavailable is returned when Verify is called but
// no DomainProofVerifier was wired. Mirrors the slice-2 fail-closed
// default used elsewhere in OSS.
var ErrDomainVerifierUnavailable = errors.New("organization domain: verifier not configured")

// ErrDomainTokenAlreadyConsumed is returned when Verify hits a row
// that no longer carries a pending verification token (already
// verified, or token was cleared by a previous attempt).
var ErrDomainTokenAlreadyConsumed = errors.New("organization domain: no pending verification token")

// ErrDomainTokenExpired is returned when the row's
// VerificationTokenExpiresAt has passed.
var ErrDomainTokenExpired = errors.New("organization domain: verification token expired")

var errOrganizationDomainNotFound = errors.New("service: organization domain not found")

// ErrOrganizationDomainNotFound exposes the OSS not-found sentinel.
func ErrOrganizationDomainNotFound() error { return errOrganizationDomainNotFound }

// NewOrganizationDomainService constructs the service. repo must be
// non-nil; verifier may be nil (Verify fails closed in that case).
func NewOrganizationDomainService(report *lifecycle.StartupReport, repo repository.OrganizationDomainRepository, verifier DomainProofVerifier) *OrganizationDomainService {
	if repo == nil {
		report.Fatal("NewOrganizationDomainService", "service: NewOrganizationDomainService requires a non-nil OrganizationDomainRepository")
	}
	return &OrganizationDomainService{repo: repo, verifier: verifier, now: time.Now}
}

// AddOrganizationDomain inserts a new pending domain claim for
// orgID. The raw verification token is returned EXACTLY ONCE so the
// caller can publish it as the DNS TXT challenge body; only the
// SHA-256 hex of the token is persisted.
func (s *OrganizationDomainService) AddOrganizationDomain(ctx context.Context, orgID uuid.UUID, rawDomain string) (*domain.OrganizationDomain, string, error) {
	if orgID == uuid.Nil {
		return nil, "", fmt.Errorf("organization id is required")
	}
	normalized := domain.NormalizeDomain(rawDomain)
	if normalized == "" {
		return nil, "", fmt.Errorf("domain is required")
	}
	id, err := uuidgen.NewV7()
	if err != nil {
		return nil, "", fmt.Errorf("organization domain uuid generation failed: %w", err)
	}
	rawToken, hashHex, err := newDomainVerificationToken()
	if err != nil {
		return nil, "", fmt.Errorf("organization domain token generation failed")
	}
	now := s.now().UTC()
	expires := now.Add(72 * time.Hour)
	d := &domain.OrganizationDomain{
		ID:                         id,
		OrganizationID:             orgID,
		Domain:                     normalized,
		IsPrimary:                  false,
		VerificationTokenHash:      &hashHex,
		VerificationTokenExpiresAt: &expires,
		CreatedAt:                  now,
		UpdatedAt:                  now,
	}
	if err := d.Validate(); err != nil {
		return nil, "", err
	}
	created, err := s.repo.CreateOrganizationDomain(ctx, d)
	if err != nil {
		return nil, "", err
	}
	return created, rawToken, nil
}

// ListByOrganization returns every domain row for orgID.
func (s *OrganizationDomainService) ListByOrganization(ctx context.Context, orgID uuid.UUID) ([]*domain.OrganizationDomain, error) {
	if orgID == uuid.Nil {
		return nil, fmt.Errorf("organization id is required")
	}
	return s.repo.ListOrganizationDomainsByOrganization(ctx, orgID)
}

// GetByID returns a single domain row by id.
func (s *OrganizationDomainService) GetByID(ctx context.Context, id uuid.UUID) (*domain.OrganizationDomain, error) {
	d, err := s.repo.GetOrganizationDomainByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if d == nil {
		return nil, errOrganizationDomainNotFound
	}
	return d, nil
}

// Delete removes a row scoped to orgID.
func (s *OrganizationDomainService) Delete(ctx context.Context, id, orgID uuid.UUID) error {
	if orgID == uuid.Nil {
		return fmt.Errorf("organization id is required")
	}
	return s.repo.DeleteOrganizationDomain(ctx, id, orgID)
}

// SetPrimary promotes the row to primary; the prior primary, if any,
// is demoted in the same repository transaction.
func (s *OrganizationDomainService) SetPrimary(ctx context.Context, id, orgID uuid.UUID) error {
	if orgID == uuid.Nil {
		return fmt.Errorf("organization id is required")
	}
	return s.repo.SetPrimaryOrganizationDomain(ctx, id, orgID)
}

// Verify runs proof-of-control against the configured verifier. On
// success the row flips to verified at s.now(). The repo's
// verification_attempts counter is incremented on every call
// regardless of outcome so a future rate-limit hook can observe it.
//
// Returns: nil on success; ErrDomainVerifierUnavailable when no
// verifier was wired; ErrDomainTokenAlreadyConsumed if the row has
// no pending token; ErrDomainTokenExpired if the token TTL has
// elapsed; or one of the DNS verifier sentinels.
func (s *OrganizationDomainService) Verify(ctx context.Context, id, orgID uuid.UUID) error {
	if orgID == uuid.Nil {
		return fmt.Errorf("organization id is required")
	}
	if s.verifier == nil {
		return ErrDomainVerifierUnavailable
	}
	row, err := s.repo.GetOrganizationDomainByID(ctx, id)
	if err != nil {
		return err
	}
	if row == nil || row.OrganizationID != orgID {
		return errOrganizationDomainNotFound
	}
	if row.IsVerified() {
		return nil
	}
	if !row.HasPendingVerificationToken() {
		return ErrDomainTokenAlreadyConsumed
	}
	if row.VerificationTokenExpiresAt != nil && row.VerificationTokenExpiresAt.Before(s.now()) {
		return ErrDomainTokenExpired
	}
	// Best-effort attempt bump. Ignored on failure so a transient
	// counter error never blocks a valid verification.
	_ = s.repo.IncrementOrganizationDomainVerificationAttempts(ctx, id, orgID)
	expected := strings.ToLower(strings.TrimSpace(*row.VerificationTokenHash))
	if err := s.verifier.Verify(ctx, row.Domain, expected); err != nil {
		return err
	}
	return s.repo.SetOrganizationDomainVerified(ctx, id, s.now().UTC())
}

// newDomainVerificationToken returns a 32-byte hex-encoded raw token
// + its SHA-256 hex digest. Only the digest is persisted.
func newDomainVerificationToken() (string, string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", err
	}
	raw := hex.EncodeToString(b)
	sum := sha256.Sum256([]byte(raw))
	return raw, hex.EncodeToString(sum[:]), nil
}
