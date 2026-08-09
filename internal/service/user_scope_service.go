package service

import (
	"context"
	"errors"
	"sort"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/lifecycle"
	"github.com/identuum/identuum-idp-oss/internal/repository"
)

// UserScopeService is the OSS-narrow service for the user-scope
// lookup hot path. It wraps `OrgRoleRepository.GetScopesForUser`
// with input validation, deduplication, and stable lexical
// ordering so callers (future /token, introspection, and
// authorization paths) do not have to repeat that work.
//
// The service deliberately exposes NO HTTP route — the monolith
// has no /users/:id/scopes endpoint and OSS preserves that
// surface. Composed CE wiring can layer routes on top of this
// service surface; OSS gives them a clean entry point.
//
// What this service does NOT do (out of scope for this slice):
//
//   - cache scope results
//   - issue tokens or refresh tokens
//   - perform any session lookup
//   - validate that the caller is authorized to read the target's
//     scopes (that decision lives at the layer that calls into
//     this service, e.g. OrgRoleService.GetScopesForUserForActor
//     or a future /introspection handler)
type UserScopeService struct {
	roles repository.OrgRoleRepository
}

// NewUserScopeService constructs a UserScopeService. repo must be
// non-nil.
func NewUserScopeService(report *lifecycle.StartupReport, repo repository.OrgRoleRepository) *UserScopeService {
	if repo == nil {
		report.Fatal("NewUserScopeService", "service: NewUserScopeService requires a non-nil OrgRoleRepository")
	}
	return &UserScopeService{roles: repo}
}

// ErrInvalidUserID is returned when a caller passes uuid.Nil for
// a user id. Exposed via the sentinel pattern so handlers can
// `errors.Is(err, service.ErrInvalidUserID())` without depending
// on the unexported variable.
var errInvalidUserID = errors.New("service: invalid user id")

// ErrInvalidUserID exposes the OSS sentinel.
func ErrInvalidUserID() error { return errInvalidUserID }

// ErrNilPrincipal is returned by GetScopesForPrincipal when the
// supplied principal is nil. Treated as ErrUnauthorized-shaped
// at the handler layer; the helper distinguishes them so a
// caller can decide whether to log the "nil principal reached
// the service" case more loudly than the unauthorized case.
var errNilPrincipal = errors.New("service: nil principal")

// ErrNilPrincipal exposes the OSS sentinel.
func ErrNilPrincipal() error { return errNilPrincipal }

// GetScopesForUser returns the deduplicated, lexically sorted
// union of scope strings bound to userID's roles. When
// resourceID is non-nil, the repository filters to scopes linked
// to that api-resource (audience filtering).
//
// Behavior:
//
//   - userID == uuid.Nil → ErrInvalidUserID
//   - repo error → propagated unchanged
//   - no roles bound → empty []string{} (never nil)
//   - duplicates collapsed and result sorted in place
func (s *UserScopeService) GetScopesForUser(ctx context.Context, userID uuid.UUID, resourceID *uuid.UUID) ([]string, error) {
	if userID == uuid.Nil {
		return nil, errInvalidUserID
	}
	raw, err := s.roles.GetScopesForUser(ctx, userID, resourceID)
	if err != nil {
		return nil, err
	}
	return dedupeAndSortScopes(raw), nil
}

// GetScopesForPrincipal is a thin self-lookup convenience for
// future introspection/token paths: it derives the userID from
// p.UserID and forwards to GetScopesForUser. Returns
// ErrNilPrincipal when p is nil; ErrInvalidUserID when
// p.UserID == uuid.Nil.
func (s *UserScopeService) GetScopesForPrincipal(ctx context.Context, p *domain.Principal, resourceID *uuid.UUID) ([]string, error) {
	if p == nil {
		return nil, errNilPrincipal
	}
	if p.UserID == uuid.Nil {
		return nil, errInvalidUserID
	}
	return s.GetScopesForUser(ctx, p.UserID, resourceID)
}

// dedupeAndSortScopes returns a copy of in with duplicates
// removed and lexical order applied. The empty input case
// returns []string{} (never nil) so callers can use
// `len(scopes) == 0` consistently without nil-checking.
func dedupeAndSortScopes(in []string) []string {
	if len(in) == 0 {
		return []string{}
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}
