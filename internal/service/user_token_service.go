// Package service — UserTokenService issues short-lived JWT
// access tokens for human-user sessions. It mirrors the M2M
// TokenService's signing posture (EdDSA preferred, ES256 fallback,
// RS256 unconditionally banned) but is purpose-built for the
// /api/v1/auth/login + /api/v1/auth/session/refresh flow:
//
//   - sub = user UUID.
//   - actor_type = "user" — the load-bearing marker that lets
//     /oidc/userinfo and downstream consumers distinguish a
//     human-user token from an SA-bound client_credentials
//     token.
//   - org_id + email + role from the user row.
//   - session_id from the session, so /oauth/revoke can map a
//     revoked jti back to its session for audit / cascade.
//   - auth_time + acr + amr surfaced from the session's
//     effective-ACR / effective-auth-time helpers (matches the
//     monolith's step-up-aware behavior).
//
// The service NEVER mints a refresh token — refresh-token life-
// cycle lives in UserSessionService. Callers that want a paired
// (access, refresh) shape compose the two services explicitly.
package service

import (
	"context"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/lifecycle"
	"github.com/identuum/identuum-idp-oss/internal/utils/uuidgen"
	"github.com/identuum/identuum-idp-oss/pkg/oidc"
)

// UserTokenService produces signed access tokens for human-user
// sessions. The underlying signing key is selected via the same
// SigningKeyProvider seam the M2M TokenService consumes — keep
// the OSS signing-key administration centralised on one repo.
type UserTokenService struct {
	keys           SigningKeyProvider
	issuer         string
	audience       string
	accessTokenTTL time.Duration
	now            func() time.Time
	// minter is the format seam (A-4 Phase 1). Production wiring is the
	// JWT minter, so the on-the-wire token is unchanged; tests inject a
	// stub to prove the seam is load-bearing.
	minter oidc.AccessTokenMinter
	// newJTI generates the token identifier. Injectable so the
	// equivalence test can pin a fixed jti; defaults to a UUIDv7 source.
	newJTI func() (string, error)
}

// UserTokenServiceOptions parameterises the service. Issuer is
// required; AccessTokenTTL defaults to 1h; Audience defaults to
// the issuer when empty (the access token's `aud` claim falls
// back to the issuer URL — matches the monolith's BaseURL fallback).
type UserTokenServiceOptions struct {
	Issuer         string
	Audience       string
	AccessTokenTTL time.Duration
	// Minter overrides the access-token format seam. Nil (the normal
	// case) wires the JWT minter over `keys`, so production output is
	// unchanged. A-4 Phase 1.
	Minter oidc.AccessTokenMinter
}

// NewUserTokenService constructs the service. keys is required;
// nil panics so a misconfigured deployment cannot silently mint
// unsigned tokens. opts.Issuer must be non-empty.
func NewUserTokenService(report *lifecycle.StartupReport, keys SigningKeyProvider, opts UserTokenServiceOptions) *UserTokenService {
	if keys == nil {
		report.Fatal("NewUserTokenService", "service: NewUserTokenService requires a non-nil SigningKeyProvider")
	}
	if opts.Issuer == "" {
		report.Fatal("NewUserTokenService", "service: NewUserTokenService requires a non-empty Issuer")
	}
	ttl := opts.AccessTokenTTL
	if ttl <= 0 {
		ttl = time.Hour
	}
	aud := opts.Audience
	if aud == "" {
		aud = opts.Issuer
	}
	minter := opts.Minter
	if minter == nil {
		// Default wiring: the JWT minter over the same signing keys —
		// production tokens are byte-identical to the pre-A-4 inline path.
		minter = newJWTAccessTokenMinter(keys)
	}
	return &UserTokenService{
		keys:           keys,
		issuer:         opts.Issuer,
		audience:       aud,
		accessTokenTTL: ttl,
		now:            time.Now,
		minter:         minter,
		newJTI:         uuidgen.NewV7String,
	}
}

// UserAccessTokenResponse is the projection callers receive on a
// successful issuance. RefreshToken is deliberately NOT a field —
// the user-session refresh lifecycle is owned by
// UserSessionService.
type UserAccessTokenResponse struct {
	AccessToken string
	TokenType   string
	ExpiresIn   int64
	JTI         string
	ExpiresAt   time.Time
	// Scope is the space-separated `scope` claim the token carries — the
	// effective set it may exercise. Empty when the token carries none.
	Scope string
	// UserInfoClaims is the `userinfo_claims` claim the token carries — the
	// OIDC §5.5 claim names consented for userinfo ∩ role-permitted
	// (THE-CLAIMS-PARAMETER). Nil when none.
	UserInfoClaims []string
}

// IssueForSession mints a JWT access token for the supplied
// user + session. Returns ErrTokenServiceNoSigningKey when no
// EdDSA/ES256 active key is available, ErrTokenServiceSigningFailed
// when the signing path fails. The raw token is NEVER logged or
// retained by the service.
//
// The token carries:
//
//   - iss   = service.Issuer
//   - sub   = user.ID.String()
//   - aud   = service.Audience (single string)
//   - iat   = now
//   - exp   = now + AccessTokenTTL
//   - jti   = UUIDv7
//   - actor_type   = "user"
//   - org_id       = user.OrganizationID (when non-Nil)
//   - email        = user.Email
//   - role         = string(user.Role)
//   - session_id   = session.ID.String()
//   - auth_time    = session.EffectiveAuthTime().Unix()
//   - acr          = session.EffectiveACR()
//   - amr          = session.Amr (when non-empty)
//
// The header carries `alg` + `kid` matching the selected signing
// key. RS256 is unconditionally banned.
func (s *UserTokenService) IssueForSession(ctx context.Context, user *domain.User, session *domain.Session) (*UserAccessTokenResponse, error) {
	if user == nil {
		return nil, ErrTokenServiceInvalidRequest
	}
	// ORG-ADMIN-SCOPES: session tokens carry role-derived scopes. The admin
	// guards read the scope claim (mw.principalHasAnyScope), and a session
	// token that carried none made every org_admin 403 on its own org. The
	// grant is org-bound at the point of use, not in the string — see
	// domain.OrgAdminSessionScopes.
	return s.issue(ctx, user, session, domain.SessionScopesForRole(user.Role), "", nil)
}

// IssueForConsentedClient mints the access token the authorization_code
// grant hands to an OAuth client. TOKEN-SCOPE-INTERSECTION-1 (owner
// ruling, THE-CONSENTED-SCOPE): the token's `scope` claim is the CONSENTED
// scope INTERSECTED with what the user's ROLE permits — roles authorize,
// consent restricts, consent never grants beyond the role. A consented but
// role-forbidden scope never lands; a role-permitted but unconsented scope
// never lands. The service owns the intersection so no caller can stamp a
// wider set; the effective scope is returned in Response.Scope for the
// token response, the refresh-token row, and the id_token.
//
// The token additionally carries `client_id` (RFC 9068 §2.2) naming the
// client it was issued to, which is what lets introspection tell a
// client-bound token from a login-session token. Everything else matches
// IssueForSession.
//
// THE-CLAIMS-PARAMETER: consentedUserInfoClaims are the OIDC §5.5
// userinfo-member claim names the user consented for this client; the token
// carries them as `userinfo_claims` INTERSECTED with what the role permits
// (domain.IntersectConsentedClaims) — the same rule as scope, applied to
// individual claims. Nil/empty stamps no such claim.
func (s *UserTokenService) IssueForConsentedClient(ctx context.Context, user *domain.User, session *domain.Session, clientID, consentedScope string, consentedUserInfoClaims []string) (*UserAccessTokenResponse, error) {
	if user == nil || clientID == "" {
		return nil, ErrTokenServiceInvalidRequest
	}
	return s.issue(ctx, user, session,
		domain.IntersectConsentedScope(consentedScope, user.Role), clientID,
		domain.IntersectConsentedClaims(consentedUserInfoClaims, user.Role))
}

func (s *UserTokenService) issue(ctx context.Context, user *domain.User, session *domain.Session, scope, clientID string, userinfoClaims []string) (*UserAccessTokenResponse, error) {
	if user == nil {
		return nil, ErrTokenServiceInvalidRequest
	}
	if session == nil {
		return nil, ErrTokenServiceInvalidRequest
	}
	now := s.now().UTC()
	exp := now.Add(s.accessTokenTTL)
	jti, err := s.newJTI()
	if err != nil {
		return nil, ErrTokenServiceSigningFailed
	}
	// Extra carries exactly the claims the pre-A-4 inline path added
	// beyond the typed core: session_id + auth_time always, the rest
	// only when non-empty. The minter copies these verbatim, so the
	// on-the-wire claim set is unchanged.
	extra := map[string]any{
		"session_id": session.ID.String(),
		"auth_time":  session.EffectiveAuthTime().Unix(),
	}
	if user.OrganizationID != (domain.User{}).OrganizationID {
		extra["org_id"] = user.OrganizationID.String()
	}
	if user.Email != "" {
		extra["email"] = user.Email
	}
	if user.Role != "" {
		extra["role"] = string(user.Role)
	}
	if scope != "" {
		extra["scope"] = scope
	}
	if len(userinfoClaims) > 0 {
		extra["userinfo_claims"] = userinfoClaims
	}
	if acr := session.EffectiveACR(); acr != "" {
		extra["acr"] = acr
	}
	if amr := session.EffectiveAMR(); len(amr) > 0 {
		extra["amr"] = amr
	}
	wireToken, storeKey, err := s.minter.Mint(ctx, oidc.TokenClaims{
		Issuer:    s.issuer,
		Subject:   user.ID.String(),
		Audience:  s.audience,
		IssuedAt:  now,
		ExpiresAt: exp,
		JTI:       jti,
		ActorType: ActorTypeUser,
		ClientID:  clientID,
		Extra:     extra,
	})
	if err != nil {
		return nil, err
	}
	return &UserAccessTokenResponse{
		AccessToken:    wireToken,
		TokenType:      "Bearer",
		ExpiresIn:      int64(s.accessTokenTTL.Seconds()),
		JTI:            storeKey,
		ExpiresAt:      exp,
		Scope:          scope,
		UserInfoClaims: userinfoClaims,
	}, nil
}

// ActorTypeUser is the canonical actor_type value for tokens
// minted by UserTokenService. Distinct from
// ActorTypeServiceAccount so userinfo / introspection consumers
// can branch on the human-user vs SA-bound classification.
const ActorTypeUser = "user"

// selectUserSigningKey mirrors the M2M TokenService's selectSigningKey
// behavior: prefer EdDSA, fall back to ES256, ban RS256.
// Pulled out as a package-level function so both services share
// the policy.
func selectUserSigningKey(ctx context.Context, keys SigningKeyProvider) (*domain.SigningKey, jwt.SigningMethod, error) {
	if keys == nil {
		return nil, nil, ErrTokenServiceNoSigningKey
	}
	out, err := keys.ListActive(ctx)
	if err != nil {
		return nil, nil, ErrTokenServiceNoSigningKey
	}
	for i := range out {
		k := &out[i]
		if k.Algorithm == domain.KeyAlgorithmEdDSA && k.PrivateKey != "" {
			return k, jwt.SigningMethodEdDSA, nil
		}
	}
	for i := range out {
		k := &out[i]
		if k.Algorithm == domain.KeyAlgorithmES256 && k.PrivateKey != "" {
			return k, jwt.SigningMethodES256, nil
		}
	}
	return nil, nil, ErrTokenServiceNoSigningKey
}

// errors package keep-alive.
var _ = errors.New
