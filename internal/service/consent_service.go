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
}

// ConsentDecision is what Lookup returns.
type ConsentDecision struct {
	// Found is true when a row exists for the (user, client,
	// audience) tuple AND is active.
	Found bool

	// GrantedScope is the verbatim stored scope string.
	GrantedScope string

	// Covered is true iff Found AND every token in the
	// requested-scope argument appears in the granted-scope set.
	Covered bool
}

// Sentinel errors.
var (
	ErrConsentInvalidInput = errors.New("service: consent requires user_id + client_id")
)

// Lookup returns the active consent decision for the supplied
// tuple + requested scope. Returns a zero ConsentDecision (Found=
// false, Covered=false) when no active row exists.
func (s *ConsentService) Lookup(ctx context.Context, userID uuid.UUID, clientID, audience, requestedScope string) (*ConsentDecision, error) {
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
		Found:        true,
		GrantedScope: row.Scope,
		Covered:      scopeCovers(row.Scope, requestedScope),
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
