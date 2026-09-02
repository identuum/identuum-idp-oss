// Package service — CookieSessionService is the OSS browser-cookie
// session helper. It owns:
//
//   - the canonical cookie name (`identuum_session`)
//   - the secure cookie-flag profile (HttpOnly + SameSite=Lax + Secure
//     by default, with an explicit operator opt-out for local dev)
//   - issuing a Set-Cookie header from a freshly-rotated user-session
//     refresh token
//   - clearing the cookie on logout
//   - extracting the cookie value from an incoming request
//   - resolving the cookie value back to a (*domain.User, *domain.Session)
//     pair via the existing UserSessionService selector lookup
//
// The cookie value itself is the user-session refresh token in its
// existing `<selector>.<base64url(validator)>` wire shape — there is
// no separate browser-token store. Pros: zero new storage, zero new
// indexes, the existing rotation/reuse-detection path on
// /api/v1/auth/session/refresh continues to work. Cons: the browser
// cookie and the refresh-token wire shape share a hash family, so a
// successful XSS exfiltration of the cookie is equivalent to
// exfiltrating the refresh token. The HttpOnly + Secure + SameSite=Lax
// posture defends against the common XSS + CSRF vectors; operators
// running an SPA MUST front the IDP with HTTPS.
//
// What this package will NOT do:
//
//   - mint a separate browser-session token. The
//     user-session refresh token is the source of truth.
//   - persist anything new. The existing `sessions` table backs the
//     lookup.
//   - parse JWTs. The bearer path still owns the JWT-driven principal
//     resolution.
package service

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/lifecycle"
)

// Canonical cookie name. Kept package-level so handlers + tests
// agree on a single source of truth.
const browserSessionCookieName = "identuum_session"

// CookieSessionLookupResult is the safe projection returned by
// Resolve. Both fields are populated on success; both are nil on a
// (resolved) absence (no cookie / unknown selector / revoked
// session).
type CookieSessionLookupResult struct {
	Session *domain.Session
	User    *domain.User
}

// CookieSessionUserLookup is the seam CookieSessionService consults
// to resolve a session's user_id → *domain.User. Mirrors the
// handlers.UserByIDLookup interface but lives in the service package
// so the service does not import handlers.
type CookieSessionUserLookup interface {
	GetByID(ctx context.Context, id uuid.UUID) (*domain.User, error)
}

// CookieSessionServiceOptions parameterises the helper. AllowPlainHTTP
// turns OFF the Secure cookie flag; intended for local-dev runs only.
// Operators running TLS termination at a reverse proxy SHOULD leave
// it false (the default).
type CookieSessionServiceOptions struct {
	AllowPlainHTTP bool
}

// CookieSessionService is the cookie helper.
type CookieSessionService struct {
	sessions       *UserSessionService
	users          CookieSessionUserLookup
	orgs           OrgLiveLookup
	browserTokens  *BrowserSessionTokenService
	allowPlainHTTP bool
}

// WithBrowserTokenService wires the cookie-indirection seam. When
// present, Resolve consults the browser_session_tokens table
// instead of treating the cookie value as the refresh-token wire
// shape. Without it wired, Resolve falls back to the legacy
// behavior (operator opt-out during migration).
func (s *CookieSessionService) WithBrowserTokenService(b *BrowserSessionTokenService) *CookieSessionService {
	s.browserTokens = b
	return s
}

// WithOrganizationLookup wires the tenant-liveness seam. When present,
// Resolve rejects a cookie whose user's organization is no longer
// operational (P0-5) — this catches org DEACTIVATION, which (unlike
// deletion) does not cascade deleted_at onto the user row.
func (s *CookieSessionService) WithOrganizationLookup(o OrgLiveLookup) *CookieSessionService {
	s.orgs = o
	return s
}

// orgOperational reports whether the resolved user's organization is still
// operational (domain.Organization.IsOperational). A nil org lookup (unwired)
// or a site_admin's nil org is treated as operational — there is no tenant to
// gate. Any lookup failure or non-operational org rejects the cookie.
func (s *CookieSessionService) orgOperational(ctx context.Context, user *domain.User) (bool, error) {
	if s.orgs == nil || user.OrganizationID == uuid.Nil {
		return true, nil
	}
	org, err := s.orgs.GetByID(ctx, user.OrganizationID)
	if err != nil {
		// AUTH-503: a missing organization is a verdict (not operational);
		// any other repository error is the store class.
		if errors.Is(err, domain.ErrOrganizationNotFound) {
			return false, nil
		}
		return false, domain.AuthStoreUnavailable("organization", err)
	}
	return org != nil && org.IsOperational(), nil
}

// NewCookieSessionService constructs the helper. sessions is
// required; users is optional (callers that only need Issue / Clear
// can pass nil).
func NewCookieSessionService(report *lifecycle.StartupReport, sessions *UserSessionService, users CookieSessionUserLookup, opts CookieSessionServiceOptions) *CookieSessionService {
	if sessions == nil {
		report.Fatal("NewCookieSessionService", "service: NewCookieSessionService requires a non-nil UserSessionService")
	}
	return &CookieSessionService{
		sessions:       sessions,
		users:          users,
		allowPlainHTTP: opts.AllowPlainHTTP,
	}
}

// CookieName returns the canonical cookie name. Exposed so tests +
// the logout handler can clear the cookie without depending on the
// package-level constant.
func (s *CookieSessionService) CookieName() string {
	return browserSessionCookieName
}

// Issue returns the http.Cookie that should be planted on the
// response writer after a successful local login. The cookie value
// is the supplied refresh token. The cookie expires at the supplied
// session expiry; MaxAge is computed in seconds-from-now.
//
// Cookie posture:
//
//   - Name      = identuum_session
//   - Value     = the refresh-token wire string
//   - Path      = /
//   - HttpOnly  = true
//   - SameSite  = Lax  (defends against cross-site POSTs while
//     permitting top-level navigation from a
//     client's redirect_uri)
//   - Secure    = !AllowPlainHTTP  (TLS-only by default)
//
// Domain is NOT set — the cookie is host-only, the most restrictive
// scope.
func (s *CookieSessionService) Issue(refreshToken string, expiresAt time.Time) *http.Cookie {
	maxAge := max(int(time.Until(expiresAt).Seconds()), 0)
	return &http.Cookie{
		Name:     browserSessionCookieName,
		Value:    refreshToken,
		Path:     "/",
		Expires:  expiresAt,
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   !s.allowPlainHTTP,
		SameSite: http.SameSiteLaxMode,
	}
}

// Clear returns the cookie that should be planted on the logout
// response. Empty value + MaxAge=-1 instructs the user-agent to
// delete the cookie. Same flag posture as Issue so the user-agent's
// "is this the same cookie?" matching succeeds.
func (s *CookieSessionService) Clear() *http.Cookie {
	return &http.Cookie{
		Name:     browserSessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   !s.allowPlainHTTP,
		SameSite: http.SameSiteLaxMode,
	}
}

// Read returns the cookie value when present. An empty string +
// false is returned when the cookie is missing or empty.
func (s *CookieSessionService) Read(r *http.Request) (string, bool) {
	if r == nil {
		return "", false
	}
	c, err := r.Cookie(browserSessionCookieName)
	if err != nil || c == nil {
		return "", false
	}
	v := strings.TrimSpace(c.Value)
	if v == "" {
		return "", false
	}
	return v, true
}

// Resolve takes a cookie value (the refresh-token wire string),
// looks up the session by selector, validates the validator hash,
// and on success returns a CookieSessionLookupResult with the
// loaded session + user.
//
// Resolve does NOT rotate the refresh token — read-only verification
// only. The /authorize and consent handlers call this on every
// request; rotation belongs to the existing
// /api/v1/auth/session/refresh path. (Rotating on every browser
// request would defeat the rotation-detection signal.)
//
// Returns (nil, nil) when the cookie is unknown / revoked / expired
// / the validator does not match. A non-nil error is reserved for
// repository-layer failures.
func (s *CookieSessionService) Resolve(ctx context.Context, cookieValue string) (*CookieSessionLookupResult, error) {
	if cookieValue == "" {
		return nil, nil
	}
	// Preferred path: cookie indirection via browser_session_tokens.
	if s.browserTokens != nil {
		resolved, err := s.browserTokens.Resolve(ctx, cookieValue)
		if err != nil {
			return nil, err
		}
		if resolved == nil {
			return nil, nil
		}
		session, err := s.sessions.repo.GetByID(ctx, resolved.SessionID)
		if err != nil {
			return nil, err
		}
		if session == nil {
			return nil, nil
		}
		now := s.sessions.now().UTC()
		if canUse, _ := session.CanBeUsed(now); !canUse {
			return nil, nil
		}
		if s.users == nil {
			return &CookieSessionLookupResult{Session: session}, nil
		}
		return s.resolveUser(ctx, session)
	}
	// Legacy fallback: cookie value is the user-session refresh
	// token wire shape. Retained ONLY for operators mid-migration
	// who have not yet wired the indirection.
	secure, parseErr := domain.ParseSecureRefreshToken(cookieValue)
	if parseErr != nil {
		return nil, nil
	}
	session, err := s.sessions.repo.GetByTokenSelector(ctx, secure.Selector)
	if err != nil {
		return nil, err
	}
	if session == nil {
		return nil, nil
	}
	now := s.sessions.now().UTC()
	if canUse, _ := session.CanBeUsed(now); !canUse {
		return nil, nil
	}
	if !constantTimeHashEqualSession(session.TokenValidatorHash, hashSessionValidator(secure.Validator)) {
		return nil, nil
	}
	if s.users == nil {
		return &CookieSessionLookupResult{Session: session}, nil
	}
	return s.resolveUser(ctx, session)
}

// resolveUser loads the session's user and checks its organization.
// AUTH-503: "no such user" (banned / deleted rows are filtered by the
// query and arrive as ErrUserNotFound) and a non-operational organization
// are VERDICTS → (nil, nil) = anonymous; any other store error is returned
// so the browser page answers 503 instead of bouncing a live session to
// login.
func (s *CookieSessionService) resolveUser(ctx context.Context, session *domain.Session) (*CookieSessionLookupResult, error) {
	user, err := s.users.GetByID(ctx, session.UserID)
	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			return nil, nil
		}
		return nil, domain.AuthStoreUnavailable("user", err)
	}
	if user == nil {
		return nil, nil
	}
	operational, oerr := s.orgOperational(ctx, user)
	if oerr != nil {
		return nil, oerr
	}
	if !operational {
		return nil, nil
	}
	return &CookieSessionLookupResult{Session: session, User: user}, nil
}
