// Package service — IDTokenService mints OIDC ID tokens for the
// authorization_code grant when the consented scope set contains
// "openid". Same signing posture as the M2M TokenService and the
// UserTokenService: EdDSA preferred, ES256 fallback, RS256
// unconditionally banned at issuance.
//
// The ID token is distinct from the access token both in lifetime
// and in claim shape. OIDC Core §2 defines the ID token as a
// signed JWT that carries:
//
//   - iss, sub, aud, exp, iat, jti  (the standard signed-claims set)
//   - nonce         (when the auth request supplied one)
//   - auth_time     (when "max_age" or "auth_time" was requested;
//     OSS always emits it because /authorize binds it
//     in the auth code row)
//   - acr / amr     (when the session carries them)
//   - email / email_verified  (when openid+email scope is granted)
//
// The OSS IDTokenService is purpose-built — it does NOT use the
// M2M TokenService. The reason: M2M tokens carry actor_type +
// client_id + scope; ID tokens carry nonce + auth_time + acr/amr +
// email_verified. Sharing a code path between the two would force a
// matrix of "is this a user or a client?" branches; keeping them
// separate keeps each service's claim contract auditable.
package service

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/lifecycle"
	"github.com/identuum/identuum-idp-oss/internal/utils/uuidgen"
	"github.com/identuum/identuum-idp-oss/pkg/oidc"
)

// IDTokenService issues OIDC ID tokens for user sessions.
type IDTokenService struct {
	keys   SigningKeyProvider
	issuer string
	ttl    time.Duration
	now    func() time.Time
	// idIssuer is the A-4 format seam. Production wiring is the JWT
	// issuer, so the on-the-wire id_token is unchanged; tests inject a
	// stub to prove the seam is load-bearing.
	idIssuer oidc.IDTokenIssuer
	// newJTI generates the token identifier. Injectable so the
	// equivalence test can pin a fixed jti; defaults to a UUIDv7 source.
	newJTI func() (string, error)
}

// IDTokenServiceOptions parameterises the service. Issuer is
// required; TTL defaults to 1 hour (same as the access-token TTL —
// shorter TTLs are achievable by callers via a tighter
// AccessTokenTTL but this slice keeps them aligned).
type IDTokenServiceOptions struct {
	Issuer string
	TTL    time.Duration
	// IDTokenIssuer overrides the id-token format seam. Nil (the normal
	// case) wires the JWT issuer over `keys`, so production output is
	// unchanged. A-4 Phase 4.
	IDTokenIssuer oidc.IDTokenIssuer
}

// NewIDTokenService constructs the service. keys must be non-nil
// and opts.Issuer must be non-empty. Both panic on misuse so a
// boot-time misconfiguration cannot silently mint unsigned tokens.
func NewIDTokenService(report *lifecycle.StartupReport, keys SigningKeyProvider, opts IDTokenServiceOptions) *IDTokenService {
	if keys == nil {
		report.Fatal("NewIDTokenService", "service: NewIDTokenService requires a non-nil SigningKeyProvider")
	}
	if opts.Issuer == "" {
		report.Fatal("NewIDTokenService", "service: NewIDTokenService requires a non-empty Issuer")
	}
	ttl := opts.TTL
	if ttl <= 0 {
		ttl = time.Hour
	}
	idIssuer := opts.IDTokenIssuer
	if idIssuer == nil {
		// Default wiring: the JWT issuer over the same signing keys —
		// production id_tokens are byte-identical to the pre-A-4 path.
		idIssuer = newJWTIDTokenIssuer(keys)
	}
	return &IDTokenService{
		keys:     keys,
		issuer:   opts.Issuer,
		ttl:      ttl,
		now:      time.Now,
		idIssuer: idIssuer,
		newJTI:   uuidgen.NewV7String,
	}
}

// IDTokenInput is the projection the caller (the authorization_code
// grant handler) supplies to mint an ID token.
type IDTokenInput struct {
	// User is required.
	User *domain.User

	// Session is required. The service stamps auth_time, acr, and
	// amr from the session's effective helpers.
	Session *domain.Session

	// Audience is the requesting client_id. OIDC Core §2: the `aud`
	// claim MUST contain the client_id. Required.
	Audience string

	// Nonce is echoed verbatim when non-empty. Optional.
	Nonce string

	// Scope is the consented scope string. Retained on the input; in the
	// code flow no scope value puts identity claims in the id_token
	// (THE-CONSENTED-SCOPE, OIDC Core §5.4).
	Scope string

	// Claims are the OIDC §5.5 id_token-member claim names the client was
	// consented (and the role permitted) to receive IN the id_token
	// (THE-CLAIMS-PARAMETER): name, email, email_verified. Each is emitted
	// only when the user record can truthfully supply it.
	Claims []string

	// SigningAlg is the client's explicitly registered
	// id_token_signed_response_alg, or empty for the issuer default
	// (EdDSA-preferred / ES256-fallback, never RS256). RS256 here is
	// honored only because the client explicitly asked — testing-only
	// per THE-PKCE-DECISION.
	SigningAlg string
}

// IDTokenResponse carries the signed ID token and its lifecycle
// metadata. ExpiresIn is the standard "seconds until expiry"
// integer the wire layer surfaces.
type IDTokenResponse struct {
	IDToken   string
	JTI       string
	ExpiresAt time.Time
	ExpiresIn int64
}

// Sentinel errors. The wire-side handler maps everything to
// `server_error` per OIDC Core §3.1.3.6 — ID-token-minting errors
// are operator misconfiguration, not protocol errors. The granular
// sentinels exist for tests and operator dashboards.
var (
	ErrIDTokenInvalidRequest = errors.New("service: id_token invalid_request")
	ErrIDTokenNoSigningKey   = errors.New("service: id_token no signing key")
	ErrIDTokenSigningFailed  = errors.New("service: id_token signing failed")
)

// Issue mints an ID token for the supplied user + session + audience
// + nonce + scope. The JWT carries:
//
//	iss            = service.Issuer
//	sub            = user.ID.String()
//	aud            = input.Audience (single client_id string)
//	iat            = now
//	exp            = now + TTL
//	jti            = UUIDv7
//	auth_time      = session.EffectiveAuthTime().Unix()
//	nonce          = input.Nonce (when non-empty)
//	acr            = session.EffectiveACR() (when non-empty)
//	amr            = session.Amr (when non-empty)
//	email          = user.Email (when scope contains "email")
//	email_verified = user.EmailVerified (when scope contains "email")
//
// `name`, `picture`, and other OIDC profile claims are NOT emitted
// in this slice — the OSS user domain model already exposes Email
// but does not yet store profile-level metadata.
//
// Signing posture: EdDSA preferred, ES256 fallback, RS256 banned.
// The header carries `alg` + `kid` matching the selected key.
func (s *IDTokenService) Issue(ctx context.Context, in IDTokenInput) (*IDTokenResponse, error) {
	if in.User == nil || in.Session == nil {
		return nil, ErrIDTokenInvalidRequest
	}
	if in.User.ID == uuid.Nil {
		return nil, ErrIDTokenInvalidRequest
	}
	if in.Audience == "" {
		return nil, ErrIDTokenInvalidRequest
	}

	now := s.now().UTC()
	exp := now.Add(s.ttl)
	jti, err := s.newJTI()
	if err != nil {
		return nil, ErrIDTokenSigningFailed
	}

	// Extra carries exactly the claims the pre-A-4 inline path added
	// beyond the typed core: auth_time always; acr/amr when the session
	// carries them; email/email_verified under the same scope gating.
	// The issuer copies Extra verbatim, so the wire claim set is
	// unchanged.
	extra := map[string]any{
		"auth_time": in.Session.EffectiveAuthTime().Unix(),
	}
	if acr := in.Session.EffectiveACR(); acr != "" {
		extra["acr"] = acr
	}
	if len(in.Session.Amr) > 0 {
		extra["amr"] = in.Session.Amr
	}
	// Email scope gating. The OSS service does not enable
	// implicit-all-claims emission; `email` only lands when the
	// consented scope explicitly contains "email".
	// THE-CONSENTED-SCOPE: in the authorization-code flow an access token is
	// issued, so the claims the `email` scope requests belong to the userinfo
	// response, NOT the id_token (OIDC Core §5.4: scope-requested claims are
	// returned from UserInfo whenever an access token is issued; only a
	// `claims` request parameter puts them in the id_token, which this OP
	// does not support). Conformance-measured
	// (EnsureIdTokenDoesNotContainEmailForScopeEmail): the id_token carried
	// email under scope=email, exposing user data to any party the RP shows
	// the id_token to. in.Scope stays on the input for a future `claims`
	// parameter; today no scope value puts email in the id_token.
	_ = scopeContains
	// THE-CLAIMS-PARAMETER: a §5.5 `claims.id_token` request the user
	// consented to (and the role permits) puts the named identity claims
	// in the id_token — only when the user record can truthfully supply
	// them (§5.3.2: never null/empty placeholders).
	for _, name := range in.Claims {
		switch name {
		case "name":
			if in.User.Name != nil && *in.User.Name != "" {
				extra["name"] = *in.User.Name
			}
		case "email":
			if in.User.Email != "" {
				extra["email"] = in.User.Email
				extra["email_verified"] = in.User.EmailVerified
			}
		case "email_verified":
			if in.User.Email != "" {
				extra["email"] = in.User.Email
				extra["email_verified"] = in.User.EmailVerified
			}
		}
	}

	idToken, err := s.idIssuer.IssueIDToken(ctx, oidc.IDTokenClaims{
		Issuer:     s.issuer,
		Subject:    in.User.ID.String(),
		Audience:   in.Audience,
		Nonce:      in.Nonce,
		IssuedAt:   now,
		ExpiresAt:  exp,
		JTI:        jti,
		Extra:      extra,
		SigningAlg: in.SigningAlg,
	})
	if err != nil {
		return nil, err
	}
	return &IDTokenResponse{
		IDToken:   idToken,
		JTI:       jti,
		ExpiresAt: exp,
		ExpiresIn: int64(s.ttl.Seconds()),
	}, nil
}

// scopeContains reports whether the space-separated scope string
// contains the named scope as a whole token.
func scopeContains(scope, name string) bool {
	if scope == "" || name == "" {
		return false
	}
	return slices.Contains(splitScope(scope), name)
}

func splitScope(scope string) []string {
	out := make([]string, 0)
	start := -1
	for i := 0; i < len(scope); i++ {
		if scope[i] == ' ' || scope[i] == '\t' {
			if start >= 0 {
				out = append(out, scope[start:i])
				start = -1
			}
			continue
		}
		if start < 0 {
			start = i
		}
	}
	if start >= 0 {
		out = append(out, scope[start:])
	}
	return out
}
