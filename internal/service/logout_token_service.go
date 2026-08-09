// Package service — LogoutTokenService mints OIDC Back-Channel
// Logout 1.0 §2.4 `logout_token` JWTs. Same signing posture as
// IDTokenService: EdDSA preferred, ES256 fallback, RS256 banned at
// issuance.
//
// HTTP delivery to the client's `backchannel_logout_uri` is NOT
// implemented in this slice — `oauth_clients` does not yet carry
// the `backchannel_logout_uri` column, so there is no destination
// to POST to. The token issuer is the precondition for the future
// delivery slice; this slice exercises the token's claim shape +
// signing posture under tests.
//
// Because no delivery is wired, discovery does NOT advertise
// `backchannel_logout_supported`. The four frontchannel/backchannel
// `*_logout_supported` flags continue to be advertised as the
// literal `false` until full delivery (and per-client URI metadata)
// lands.
package service

import (
	"context"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/lifecycle"
	"github.com/identuum/identuum-idp-oss/internal/utils/uuidgen"
)

// LogoutTokenService mints logout_token JWTs.
type LogoutTokenService struct {
	keys   SigningKeyProvider
	issuer string
	ttl    time.Duration
	now    func() time.Time
}

// LogoutTokenServiceOptions parameterises the service. Issuer is
// required; TTL defaults to 2 minutes (Back-Channel Logout 1.0 §2.6
// recommends a short window).
type LogoutTokenServiceOptions struct {
	Issuer string
	TTL    time.Duration
}

// NewLogoutTokenService constructs the service. keys + issuer
// required.
func NewLogoutTokenService(report *lifecycle.StartupReport, keys SigningKeyProvider, opts LogoutTokenServiceOptions) *LogoutTokenService {
	if keys == nil {
		report.Fatal("NewLogoutTokenService", "service: NewLogoutTokenService requires a non-nil SigningKeyProvider")
	}
	if opts.Issuer == "" {
		report.Fatal("NewLogoutTokenService", "service: NewLogoutTokenService requires a non-empty Issuer")
	}
	ttl := opts.TTL
	if ttl <= 0 {
		ttl = 2 * time.Minute
	}
	return &LogoutTokenService{keys: keys, issuer: opts.Issuer, ttl: ttl, now: time.Now}
}

// LogoutTokenInput drives Issue. At least one of Subject or
// SessionID MUST be set (Back-Channel Logout 1.0 §2.4 — the
// logout_token MUST identify the user or the session).
type LogoutTokenInput struct {
	Audience  string    // client_id; required.
	Subject   uuid.UUID // user UUID; optional if SessionID is set.
	SessionID uuid.UUID // sid claim; optional if Subject is set.
}

// LogoutTokenResponse carries the signed logout_token + metadata.
type LogoutTokenResponse struct {
	LogoutToken string
	JTI         string
	ExpiresAt   time.Time
}

// Sentinel errors.
var (
	ErrLogoutTokenInvalidInput  = errors.New("service: logout_token invalid_request")
	ErrLogoutTokenNoSigningKey  = errors.New("service: logout_token no signing key")
	ErrLogoutTokenSigningFailed = errors.New("service: logout_token signing failed")
)

// Issue mints a logout_token with:
//
//	iss     = service.Issuer
//	sub     = input.Subject (when non-Nil)
//	aud     = input.Audience (single string)
//	iat     = now
//	exp     = now + TTL
//	jti     = UUIDv7
//	sid     = input.SessionID (when non-Nil)
//	events  = {"http://schemas.openid.net/event/backchannel-logout":{}}
//
// nonce is NEVER emitted (Back-Channel Logout 1.0 §2.4 forbids it).
// Signing posture: EdDSA preferred, ES256 fallback, RS256 banned.
func (s *LogoutTokenService) Issue(ctx context.Context, in LogoutTokenInput) (*LogoutTokenResponse, error) {
	if in.Audience == "" {
		return nil, ErrLogoutTokenInvalidInput
	}
	if in.Subject == uuid.Nil && in.SessionID == uuid.Nil {
		return nil, ErrLogoutTokenInvalidInput
	}
	signingKey, method, err := selectUserSigningKey(ctx, s.keys)
	if err != nil {
		return nil, ErrLogoutTokenNoSigningKey
	}
	priv, err := parsePrivateKeyPEM(signingKey.PrivateKey, signingKey.Algorithm)
	if err != nil {
		return nil, ErrLogoutTokenSigningFailed
	}
	now := s.now().UTC()
	exp := now.Add(s.ttl)
	jtiID, err := uuidgen.NewV7()
	if err != nil {
		return nil, ErrLogoutTokenSigningFailed
	}
	claims := jwt.MapClaims{
		"iss": s.issuer,
		"aud": in.Audience,
		"iat": now.Unix(),
		"exp": exp.Unix(),
		"jti": jtiID.String(),
		"events": map[string]any{
			"http://schemas.openid.net/event/backchannel-logout": map[string]any{},
		},
	}
	if in.Subject != uuid.Nil {
		claims["sub"] = in.Subject.String()
	}
	if in.SessionID != uuid.Nil {
		claims["sid"] = in.SessionID.String()
	}
	token := jwt.NewWithClaims(method, claims)
	token.Header["kid"] = signingKey.KID
	signed, err := token.SignedString(priv)
	if err != nil {
		return nil, ErrLogoutTokenSigningFailed
	}
	return &LogoutTokenResponse{
		LogoutToken: signed,
		JTI:         jtiID.String(),
		ExpiresAt:   exp,
	}, nil
}
