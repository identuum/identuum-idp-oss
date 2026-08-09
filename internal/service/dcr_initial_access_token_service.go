package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/crypto"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/lifecycle"
	"github.com/identuum/identuum-idp-oss/internal/repository"
	"github.com/identuum/identuum-idp-oss/internal/utils/uuidgen"
)

// DCRInitialAccessTokenService is the OSS service layer for the
// DCR initial access token (IAT) lifecycle: issue, list, revoke,
// consume.
//
// Issue / List / Revoke are admin-facing operations enforced at
// the HTTP layer with mw.RequireSiteAdmin. Consume is the
// load-bearing path the DCR handler calls when an incoming
// /api/v1/oauth/register request presents an Authorization:
// Bearer <iat> header — it atomically validates + increments the
// uses_count so two concurrent registrations cannot both pass
// the gate on a single-use token.
type DCRInitialAccessTokenService struct {
	repo  repository.DynamicRegistrationTokenRepository
	clock func() time.Time
}

// NewDCRInitialAccessTokenService builds the service bound to repo.
// repo MUST be non-nil; passing nil is a bootstrap bug and panics.
func NewDCRInitialAccessTokenService(report *lifecycle.StartupReport, repo repository.DynamicRegistrationTokenRepository) *DCRInitialAccessTokenService {
	if repo == nil {
		report.Fatal("NewDCRInitialAccessTokenService", "service: NewDCRInitialAccessTokenService requires a non-nil repository")
	}
	return &DCRInitialAccessTokenService{repo: repo, clock: time.Now}
}

// WithClock overrides the clock seam for deterministic tests.
// Production code should never call this.
func (s *DCRInitialAccessTokenService) WithClock(clock func() time.Time) *DCRInitialAccessTokenService {
	if clock == nil {
		clock = time.Now
	}
	s.clock = clock
	return s
}

// dcrIATMinTTL is the lower bound on the requested TTL. Tokens
// shorter than this are clamped up so an operator cannot
// accidentally issue a token that expires before the operator
// can hand it off.
const dcrIATMinTTL = 1 * time.Minute

// dcrIATMaxTTL is the upper bound on the requested TTL. Tokens
// longer than this are clamped down so the IAT cannot
// indefinitely outlive its issuance audit trail.
const dcrIATMaxTTL = 30 * 24 * time.Hour

// dcrIATDefaultTTL is the TTL applied when the caller does not
// supply one.
const dcrIATDefaultTTL = 24 * time.Hour

// dcrIATDefaultMaxUses is the MaxUses applied when the caller
// does not supply one. Single-use IATs are the safer default —
// the operator can explicitly raise the ceiling per call site.
const dcrIATDefaultMaxUses = 1

// IssueOptions is the input shape for issuing a new IAT.
type IssueOptions struct {
	// OrganizationID, when non-nil, binds the IAT to a tenant —
	// the DCR caller's registered client.OrganizationID MUST
	// equal this value.
	OrganizationID *uuid.UUID
	// AllowedGrantTypes is the closed allow-list this IAT
	// imposes on top of the DCR handler's allow-list. Empty
	// means no IAT-imposed constraint (the handler allow-list
	// still applies).
	AllowedGrantTypes []string
	// AllowedTokenEndpointAuthMethods is the closed allow-list
	// this IAT imposes on top of the DCR handler's allow-list.
	// Empty means no IAT-imposed constraint.
	AllowedTokenEndpointAuthMethods []string
	// TTL is the requested duration before expires_at. Clamped
	// to [dcrIATMinTTL, dcrIATMaxTTL]. Zero means
	// dcrIATDefaultTTL.
	TTL time.Duration
	// MaxUses is the consumption ceiling. 0 means
	// dcrIATDefaultMaxUses (1). Use a sentinel negative value
	// (-1) to request explicitly unlimited; the service maps
	// that to 0 in storage (DB-level unlimited).
	MaxUses int
	// CreatedByUserID is the site_admin actor that issued the
	// IAT. Captured for audit correlation; not used at
	// consume-time.
	CreatedByUserID *uuid.UUID
	// Description is a short operator-supplied label (e.g.
	// "partner onboarding 2026-Q3"). Stored verbatim. Never
	// returned to the registering client.
	Description string
}

// IssueResult carries the persisted IAT row and the one-shot
// raw token. The raw token is returned EXACTLY ONCE — neither
// the service nor the repository stores or logs it.
type IssueResult struct {
	Token   *domain.DynamicRegistrationToken
	RawIAT  string
	TokenID uuid.UUID
}

// Issue mints a new IAT, hashes it, persists the hash, and
// returns the one-shot raw token. The caller MUST display the
// raw token to the operator exactly once and then drop it.
func (s *DCRInitialAccessTokenService) Issue(ctx context.Context, opts IssueOptions) (*IssueResult, error) {
	ttl := opts.TTL
	if ttl == 0 {
		ttl = dcrIATDefaultTTL
	}
	if ttl < dcrIATMinTTL {
		ttl = dcrIATMinTTL
	}
	if ttl > dcrIATMaxTTL {
		ttl = dcrIATMaxTTL
	}
	maxUses := opts.MaxUses
	switch {
	case maxUses == 0:
		maxUses = dcrIATDefaultMaxUses
	case maxUses < 0:
		// Caller-requested unlimited.
		maxUses = 0
	}

	// 256-bit opaque random IAT. 32 bytes → 64 hex chars.
	raw, err := crypto.GenerateRandomString(32)
	if err != nil {
		return nil, fmt.Errorf("service: IAT generation failed: %w", err)
	}
	hash := crypto.HashSecret(raw)

	id, err := uuidgen.NewV7()
	if err != nil {
		return nil, fmt.Errorf("service: IAT id generation failed: %w", err)
	}

	now := s.clock().UTC()
	row := &domain.DynamicRegistrationToken{
		ID:                              id,
		TokenHash:                       hash,
		OrganizationID:                  opts.OrganizationID,
		AllowedGrantTypes:               normalizeStringSet(opts.AllowedGrantTypes),
		AllowedTokenEndpointAuthMethods: normalizeStringSet(opts.AllowedTokenEndpointAuthMethods),
		ExpiresAt:                       now.Add(ttl),
		MaxUses:                         maxUses,
		UsesCount:                       0,
		CreatedByUserID:                 opts.CreatedByUserID,
		Description:                     opts.Description,
	}
	saved, err := s.repo.Insert(ctx, row)
	if err != nil {
		return nil, err
	}
	// Scrub the hash from the saved row before returning so the
	// caller cannot accidentally re-emit it. The raw token is
	// returned via the IssueResult struct ONLY.
	saved.TokenHash = ""
	return &IssueResult{Token: saved, RawIAT: raw, TokenID: saved.ID}, nil
}

// List returns the IAT rows in newest-first order. The
// repository scrubs token_hash on the way out — this method
// MUST NOT re-populate it.
func (s *DCRInitialAccessTokenService) List(ctx context.Context) ([]*domain.DynamicRegistrationToken, error) {
	return s.repo.List(ctx)
}

// Get returns a single IAT row by id. The repository scrubs
// token_hash on the way out.
func (s *DCRInitialAccessTokenService) Get(ctx context.Context, id uuid.UUID) (*domain.DynamicRegistrationToken, error) {
	return s.repo.GetByID(ctx, id)
}

// Revoke sets revoked_at = now on the row identified by id.
// Idempotent: re-revoking a revoked row returns nil.
func (s *DCRInitialAccessTokenService) Revoke(ctx context.Context, id uuid.UUID) error {
	return s.repo.Revoke(ctx, id, s.clock().UTC())
}

// ErrIATInvalid is the opaque sentinel returned by Consume for
// any failure mode the service does not want to disambiguate on
// the wire (missing hash / revoked / expired / max-uses
// exhausted). DCR handlers MUST map this to a single generic
// 401 error envelope so a probing caller cannot infer IAT
// state.
var ErrIATInvalid = errors.New("service: dcr initial access token invalid")

// ConsumePolicy carries the IAT-derived constraints the DCR
// handler must enforce against the request after Consume
// succeeds. The DCR handler uses this to reject a request that
// passed bearer auth but violates the IAT's allowlist (e.g.
// asks for grant_types=client_credentials when the IAT is
// scoped to authorization_code).
type ConsumePolicy struct {
	OrganizationID                  *uuid.UUID
	AllowedGrantTypes               []string
	AllowedTokenEndpointAuthMethods []string
	TokenID                         uuid.UUID
}

// Consume verifies + atomically increments uses_count for the
// IAT identified by rawToken. Returns ConsumePolicy on success;
// returns ErrIATInvalid for every failure mode.
//
// rawToken MUST be the raw IAT presented by the caller — the
// service hashes it before lookup. The raw token is NEVER
// logged or persisted.
func (s *DCRInitialAccessTokenService) Consume(ctx context.Context, rawToken string) (*ConsumePolicy, error) {
	if strings.TrimSpace(rawToken) == "" {
		return nil, ErrIATInvalid
	}
	hash := crypto.HashSecret(rawToken)
	t, err := s.repo.ConsumeByHash(ctx, hash, s.clock().UTC())
	if err != nil {
		if errors.Is(err, repository.ErrDynamicRegistrationTokenNotFound) ||
			errors.Is(err, repository.ErrDynamicRegistrationTokenInactive) {
			return nil, ErrIATInvalid
		}
		return nil, err
	}
	return &ConsumePolicy{
		OrganizationID:                  t.OrganizationID,
		AllowedGrantTypes:               append([]string(nil), t.AllowedGrantTypes...),
		AllowedTokenEndpointAuthMethods: append([]string(nil), t.AllowedTokenEndpointAuthMethods...),
		TokenID:                         t.ID,
	}, nil
}

// normalizeStringSet trims whitespace, drops empties, and
// de-duplicates entries. Returns an empty (non-nil) slice when
// the input is empty so the repository writes a zero-length
// TEXT[] (NOT NULL by table schema).
func normalizeStringSet(in []string) []string {
	if len(in) == 0 {
		return []string{}
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}
