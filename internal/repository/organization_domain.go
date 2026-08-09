package repository

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// OrganizationDomainRepository is the persistence surface for the
// per-organization domains table introduced in migration 0019. The
// methods exposed here are scoped to slice 1 of the org-admin Domains
// feature: enough to support a future handler slice (list / add /
// verify / remove / set-primary) without committing to a wire shape.
//
// Tenancy: every method that can mutate or remove a row requires an
// organization_id. The pgx implementation MUST include organization_id
// in the SQL WHERE clause for those methods so a malformed caller can
// never reach across organizations even if a request-scoped id were
// trusted by mistake at a higher layer.
type OrganizationDomainRepository interface {
	// CreateOrganizationDomain inserts a new row. The caller is expected
	// to have validated the domain string with domain.Validate() and
	// normalized it via domain.NormalizeDomain(). The repository surfaces
	// duplicate-row errors as domain.ErrOrganizationDomainAlreadyExists
	// (collision with the (organization_id, domain) UNIQUE) or
	// domain.ErrOrganizationDomainVerifiedByOther (collision with the
	// global verified-domain partial unique index — only reachable when
	// the row being inserted is already verified, which is the case for
	// the migration backfill but not for normal pending claims).
	CreateOrganizationDomain(ctx context.Context, d *domain.OrganizationDomain) (*domain.OrganizationDomain, error)

	// GetOrganizationDomainByID retrieves a single row by id. Returns
	// domain.ErrOrganizationDomainNotFound when no row matches.
	GetOrganizationDomainByID(ctx context.Context, id uuid.UUID) (*domain.OrganizationDomain, error)

	// ListOrganizationDomainsByOrganization returns every row for the
	// given organization, primary first then newest-first. Returns an
	// empty slice (never nil) when the org has no rows.
	ListOrganizationDomainsByOrganization(ctx context.Context, organizationID uuid.UUID) ([]*domain.OrganizationDomain, error)

	// GetVerifiedOrganizationDomainByDomain looks up the single verified
	// row globally by domain string. Returns
	// domain.ErrOrganizationDomainNotFound when no verified row exists.
	// This is the path the future public-lookup switch (slice 3) will
	// use; nothing calls it yet.
	GetVerifiedOrganizationDomainByDomain(ctx context.Context, domainName string) (*domain.OrganizationDomain, error)

	// SetOrganizationDomainVerified flips a pending row to verified at
	// the supplied timestamp and clears its verification token state.
	// The caller is expected to have validated the proof-of-control
	// out-of-band; this method does not inspect the token hash.
	SetOrganizationDomainVerified(ctx context.Context, id uuid.UUID, verifiedAt time.Time) error

	// IncrementOrganizationDomainVerificationAttempts bumps the
	// verification_attempts counter by 1 on the given row. Both id AND
	// organization_id are bound into the WHERE clause so a caller cannot
	// mutate counters across tenants. Surfaces
	// domain.ErrOrganizationDomainNotFound when no row matched (id
	// wrong OR org mismatch). The counter is intentionally observable
	// from outside the failure path so a future rate-limit or anti-abuse
	// hook can inspect it directly from the row.
	IncrementOrganizationDomainVerificationAttempts(ctx context.Context, id uuid.UUID, organizationID uuid.UUID) error

	// DeleteOrganizationDomain removes a row. Both id and organization_id
	// are required in the SQL WHERE so a misrouted call cannot delete
	// across tenants. Surfaces domain.ErrOrganizationDomainNotFound when
	// no row matched (id wrong OR org mismatch — the two are
	// indistinguishable on purpose so the call cannot probe for the
	// existence of a row outside the caller's org).
	DeleteOrganizationDomain(ctx context.Context, id uuid.UUID, organizationID uuid.UUID) error

	// SetPrimaryOrganizationDomain atomically demotes the org's current
	// primary (if any) and promotes the supplied row. The supplied id
	// MUST belong to the supplied organization — the implementation
	// enforces this in the same transaction. Surfaces
	// domain.ErrOrganizationDomainNotFound when the target row does not
	// exist or belongs to a different org.
	SetPrimaryOrganizationDomain(ctx context.Context, id uuid.UUID, organizationID uuid.UUID) error
}
