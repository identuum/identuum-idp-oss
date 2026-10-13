// Package service — ConsentService is the OSS-narrow consent helper.
// It owns the lookup/grant/revoke primitives the /authorize flow
// consults when client.SkipConsent is false. The service is
// intentionally minimal: it stores the granted scope string, the
// (user, client, audience) tuple it is keyed by, and the lifecycle
// timestamps. There is no extra metadata column, no per-scope
// description, no scope-level revoke — match the monolith's
// observed pattern (replace-on-regrant; single row per tuple).
//
// Scope subset semantics:
//
//   - Scopes are normalised by splitting on whitespace, lowercasing
//     never (OIDC scopes are case-sensitive by RFC 6749 §3.3), and
//     skipping empty tokens. The stored row preserves the wire
//     ordering supplied at grant time.
//   - The Lookup(user, client, audience, requested) call returns
//     Covered=true iff EVERY requested token already appears in
//     the granted set. That is the same semantics monolith uses
//     in shouldSkipConsent → isScopeCovered.
package service

import (
	"context"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/lifecycle"
	"github.com/identuum/identuum-idp-oss/internal/repository"
	"github.com/identuum/identuum-idp-oss/internal/utils/uuidgen"
)

// ConsentService is the façade in front of the oauth_consents table.
type ConsentService struct {
	repo repository.OAuthConsentRepository
	now  func() time.Time
}

// NewConsentService constructs the service. repo MUST be non-nil.
func NewConsentService(report *lifecycle.StartupReport, repo repository.OAuthConsentRepository) *ConsentService {
	if repo == nil {
		report.Fatal("NewConsentService", "service: NewConsentService requires a non-nil OAuthConsentRepository")
	}
	return &ConsentService{repo: repo, now: time.Now}
}

// GrantConsentInput drives Grant.
type GrantConsentInput struct {
	UserID         uuid.UUID
	OrganizationID *uuid.UUID
	ClientID       string
	Audience       string
	Scope          string
	// Claims are the consented OIDC §5.5 claim tokens ("userinfo:name",
	// "id_token:email") — domain.ClaimsRequest.Tokens() of the approved
	// request (THE-CLAIMS-PARAMETER).
	Claims []string
}

// ConsentDecision is what Lookup returns.
type ConsentDecision struct {
	// Found is true when a row exists for the (user, client,
	// audience) tuple AND is active.
	Found bool

	// GrantedScope is the verbatim stored scope string.
	GrantedScope string

	// GrantedClaims is the verbatim stored claim-token string.
	GrantedClaims string

	// Covered is true iff Found AND every token in the requested scope
	// appears in the granted-scope set AND every requested claim token
	// appears in the granted-claims set.
	Covered bool
}

// Sentinel errors.
var (
	ErrConsentInvalidInput = errors.New("service: consent requires user_id + client_id")
)

// Lookup returns the active consent decision for the supplied
// tuple + requested scope. Returns a zero ConsentDecision (Found=
// false, Covered=false) when no active row exists.
func (s *ConsentService) Lookup(ctx context.Context, userID uuid.UUID, clientID, audience, requestedScope string, requestedClaims ...string) (*ConsentDecision, error) {
	if userID == uuid.Nil || strings.TrimSpace(clientID) == "" {
		return &ConsentDecision{}, ErrConsentInvalidInput
	}
	row, err := s.repo.GetActive(ctx, userID, clientID, audience)
	if err != nil {
		return &ConsentDecision{}, err
	}
	if row == nil || !row.IsActive() {
		return &ConsentDecision{}, nil
	}
	return &ConsentDecision{
		Found:         true,
		GrantedScope:  row.Scope,
		GrantedClaims: row.Claims,
		// THE-CLAIMS-PARAMETER: a §5.5 claim the user has not consented to
		// for this client is exactly as uncovered as an unconsented scope.
		Covered: scopeCovers(row.Scope, requestedScope) && domain.ClaimsCover(row.Claims, requestedClaims),
	}, nil
}

// Grant persists a new consent row OR — on (user, client,
// audience) conflict — flips the existing row's scope and clears
// revoked_at. Returns the persisted row's ID for audit.
func (s *ConsentService) Grant(ctx context.Context, in GrantConsentInput) (uuid.UUID, error) {
	if in.UserID == uuid.Nil || strings.TrimSpace(in.ClientID) == "" {
		return uuid.Nil, ErrConsentInvalidInput
	}
	id, err := uuidgen.NewV7()
	if err != nil {
		return uuid.Nil, err
	}
	row := &domain.OAuthConsent{
		ID:             id,
		UserID:         in.UserID,
		OrganizationID: in.OrganizationID,
		ClientID:       in.ClientID,
		Audience:       in.Audience,
		Scope:          normaliseScope(in.Scope),
		Claims:         domain.JoinClaimTokens(in.Claims),
		GrantedAt:      s.now().UTC(),
	}
	persisted, err := s.repo.Upsert(ctx, row)
	if err != nil {
		return uuid.Nil, err
	}
	return persisted.ID, nil
}

// Revoke marks the (user, client, audience) row revoked.
func (s *ConsentService) Revoke(ctx context.Context, userID uuid.UUID, clientID, audience string) error {
	if userID == uuid.Nil || strings.TrimSpace(clientID) == "" {
		return ErrConsentInvalidInput
	}
	return s.repo.Revoke(ctx, userID, clientID, audience, s.now().UTC())
}

// ClientConsent is one client's ACTIVE consent for a user, its audience rows
// grouped (D3): the union of their scopes in first-seen order, and the
// earliest and latest grant.
type ClientConsent struct {
	ClientID       string
	Scopes         []string
	FirstGrantedAt time.Time
	LastGrantedAt  time.Time
}

// ErrConsentNotFound: the user holds no active consent for the client.
var ErrConsentNotFound = errors.New("service: no active consent for this client")

// ListForUser returns userID's active consents, one entry per client_id
// across audiences, ordered by client_id (D3, GET /api/v1/me/consents).
func (s *ConsentService) ListForUser(ctx context.Context, userID uuid.UUID) ([]ClientConsent, error) {
	if userID == uuid.Nil {
		return nil, ErrConsentInvalidInput
	}
	rows, err := s.repo.ListActiveByUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	byClient := map[string]*ClientConsent{}
	seen := map[string]map[string]struct{}{}
	var order []string
	for _, row := range rows {
		if row == nil || !row.IsActive() || row.UserID != userID {
			continue
		}
		c, ok := byClient[row.ClientID]
		if !ok {
			c = &ClientConsent{ClientID: row.ClientID, FirstGrantedAt: row.GrantedAt, LastGrantedAt: row.GrantedAt}
			byClient[row.ClientID] = c
			seen[row.ClientID] = map[string]struct{}{}
			order = append(order, row.ClientID)
		}
		if row.GrantedAt.Before(c.FirstGrantedAt) {
			c.FirstGrantedAt = row.GrantedAt
		}
		if row.GrantedAt.After(c.LastGrantedAt) {
			c.LastGrantedAt = row.GrantedAt
		}
		for _, tok := range splitScope(row.Scope) {
			if _, dup := seen[row.ClientID][tok]; !dup {
				seen[row.ClientID][tok] = struct{}{}
				c.Scopes = append(c.Scopes, tok)
			}
		}
	}
	sort.Strings(order)
	out := make([]ClientConsent, 0, len(order))
	for _, id := range order {
		out = append(out, *byClient[id])
	}
	return out, nil
}

// HasActiveForClient reports whether userID holds an active consent for
// clientID on any audience.
func (s *ConsentService) HasActiveForClient(ctx context.Context, userID uuid.UUID, clientID string) (bool, error) {
	if userID == uuid.Nil || strings.TrimSpace(clientID) == "" {
		return false, ErrConsentInvalidInput
	}
	rows, err := s.repo.ListActiveByUser(ctx, userID)
	if err != nil {
		return false, err
	}
	for _, row := range rows {
		if row != nil && row.ClientID == clientID && row.IsActive() {
			return true, nil
		}
	}
	return false, nil
}

// RevokeClient revokes every active audience row of (userID, clientID) and
// returns how many it revoked; none is ErrConsentNotFound (D3).
func (s *ConsentService) RevokeClient(ctx context.Context, userID uuid.UUID, clientID string) (int64, error) {
	if userID == uuid.Nil || strings.TrimSpace(clientID) == "" {
		return 0, ErrConsentInvalidInput
	}
	n, err := s.repo.RevokeAllForClient(ctx, userID, clientID, s.now().UTC())
	if err != nil {
		return 0, err
	}
	if n == 0 {
		return 0, ErrConsentNotFound
	}
	return n, nil
}

// scopeCovers reports whether every token in `requested` already
// appears in `granted`. Both inputs are space-separated. An empty
// requested set is trivially covered (there is nothing to ask for).
func scopeCovers(granted, requested string) bool {
	req := splitScope(requested)
	if len(req) == 0 {
		return true
	}
	have := map[string]struct{}{}
	for _, g := range splitScope(granted) {
		have[g] = struct{}{}
	}
	for _, r := range req {
		if _, ok := have[r]; !ok {
			return false
		}
	}
	return true
}

// normaliseScope splits on whitespace, drops empty tokens, and
// re-joins on a single space. Order is preserved.
func normaliseScope(scope string) string {
	toks := splitScope(scope)
	if len(toks) == 0 {
		return ""
	}
	return strings.Join(toks, " ")
}
