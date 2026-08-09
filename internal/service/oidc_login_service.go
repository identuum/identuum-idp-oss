package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/lifecycle"
	"github.com/identuum/identuum-idp-oss/internal/repository"
)

// OIDCLoginService orchestrates the RP login INITIATION for OSS basic
// single-provider upstream OIDC login — Slice 4 of
// docs/design/oss-basic-oidc-login.md. Given a configured provider id it
// resolves the provider, fetches its discovery metadata (Slice 3), generates
// crypto-random state + nonce + PKCE, persists an OIDCState row (with the PKCE
// verifier encrypted at rest via the same CryptoService that protects MFA
// secrets), and returns the upstream authorize URL for a 302 redirect.
//
// It manages the ONE provider addressed by id — it never enumerates or routes
// a list (multi-IdP is CE). It does NOT do the callback, token exchange,
// ID-token validation, JIT, or session mint (Slices 5-7).
type OIDCLoginService struct {
	providers repository.IdentityProviderRepository
	discovery *OIDCDiscoveryService
	states    repository.OIDCStateRepository
	cipher    SecretCipher

	stateTTL time.Duration
	now      func() time.Time
}

// OIDCLoginServiceDeps are the required collaborators.
type OIDCLoginServiceDeps struct {
	Providers repository.IdentityProviderRepository
	Discovery *OIDCDiscoveryService
	States    repository.OIDCStateRepository
	Cipher    SecretCipher
}

// OIDCLoginServiceOptions parameterises the service.
type OIDCLoginServiceOptions struct {
	// StateTTL bounds the lifetime of a persisted OIDCState row. Defaults to
	// 10 minutes — long enough for a user to authenticate upstream, short
	// enough to bound replay of an intercepted state.
	StateTTL time.Duration
}

const (
	defaultOIDCLoginStateTTL = 10 * time.Minute
	// oidcLoginRandomBytes is the entropy for each of state / nonce / PKCE
	// verifier (32 bytes → 43-char base64url, within the PKCE 43-128 range).
	oidcLoginRandomBytes = 32
	defaultReturnURL     = "/"
	pkceMethodS256       = "S256"
)

// ErrLoginProviderNotFound is returned when the provider id is unknown, not
// oidc, inactive, or not usable for login (no redirect_uri configured).
// A handler maps it to 404 — nothing about the provider is leaked.
var ErrLoginProviderNotFound = errors.New("service: OIDC login provider not found")

// ErrLoginDiscoveryFailed is returned when the upstream discovery fetch or
// validation fails. A handler maps it to a 502-class error with NO redirect.
var ErrLoginDiscoveryFailed = errors.New("service: OIDC login discovery failed")

// ErrLoginStatePersist is returned when state/nonce/PKCE generation,
// encryption, or the OIDCState persist fails. A handler maps it to 500. No
// state row is left behind.
var ErrLoginStatePersist = errors.New("service: OIDC login state persistence failed")

// NewOIDCLoginService constructs the service. All collaborators are REQUIRED;
// a nil dependency records a fatal startup fault (P-018, NOT-SERVING) rather
// than panicking.
func NewOIDCLoginService(report *lifecycle.StartupReport, deps OIDCLoginServiceDeps, opts OIDCLoginServiceOptions) *OIDCLoginService {
	if deps.Providers == nil {
		report.Fatal("NewOIDCLoginService", "service: NewOIDCLoginService requires a non-nil IdentityProviderRepository")
	}
	if deps.Discovery == nil {
		report.Fatal("NewOIDCLoginService", "service: NewOIDCLoginService requires a non-nil OIDCDiscoveryService")
	}
	if deps.States == nil {
		report.Fatal("NewOIDCLoginService", "service: NewOIDCLoginService requires a non-nil OIDCStateRepository")
	}
	if deps.Cipher == nil {
		report.Fatal("NewOIDCLoginService", "service: NewOIDCLoginService requires a non-nil SecretCipher (PKCE verifier must never be stored in plaintext)")
	}
	ttl := opts.StateTTL
	if ttl <= 0 {
		ttl = defaultOIDCLoginStateTTL
	}
	return &OIDCLoginService{
		providers: deps.Providers,
		discovery: deps.Discovery,
		states:    deps.States,
		cipher:    deps.Cipher,
		stateTTL:  ttl,
		now:       time.Now,
	}
}

// InitiateLogin resolves the provider, discovers its metadata, mints + persists
// the OIDCState (encrypted PKCE verifier, sanitized return URL), and returns
// the upstream authorize URL. On any failure it returns a typed sentinel and
// leaves no state row behind.
func (s *OIDCLoginService) InitiateLogin(ctx context.Context, providerID uuid.UUID, returnURL string) (string, error) {
	// 1. Resolve the ONE provider by id; require oidc + active. Any lookup
	// error (incl. not-found) collapses to not-found — no internal leak.
	provider, err := s.providers.GetByID(ctx, providerID)
	if err != nil || provider == nil || provider.Type != domain.IDPTypeOIDC || !provider.Active {
		return "", ErrLoginProviderNotFound
	}
	redirectURI := firstNonEmpty(provider.Config.RedirectURIs)
	if redirectURI == "" {
		return "", ErrLoginProviderNotFound // not usable for login
	}

	// 2. Discover the upstream metadata (Slice 3 — https-only, SSRF-guarded).
	doc, err := s.discovery.Discover(ctx, provider.Config.IssuerURL)
	if err != nil {
		return "", ErrLoginDiscoveryFailed
	}

	// 3. Crypto-random state, nonce, PKCE verifier (distinct per request).
	state, serr := randomURLToken(oidcLoginRandomBytes)
	nonce, nerr := randomURLToken(oidcLoginRandomBytes)
	verifier, verr := randomURLToken(oidcLoginRandomBytes)
	if serr != nil || nerr != nil || verr != nil {
		return "", ErrLoginStatePersist
	}
	challenge := pkceS256Challenge(verifier)

	// 4. Encrypt the PKCE verifier at rest — it is NEVER persisted in plaintext.
	encVerifier, cerr := s.cipher.Encrypt(verifier)
	if cerr != nil {
		return "", ErrLoginStatePersist
	}

	// 5. Persist the OIDCState. Sanitize the return URL (open-redirect defense).
	st := &domain.OIDCState{
		State:                 state,
		Nonce:                 nonce,
		PKCEVerifierEncrypted: encVerifier,
		ProviderID:            provider.ID,
		OrganizationID:        provider.OrganizationID,
		RedirectURI:           redirectURI,
		ReturnURL:             sanitizeReturnURL(returnURL),
		CodeChallengeMethod:   pkceMethodS256,
		ExpiresAt:             s.now().Add(s.stateTTL),
	}
	if err := s.states.Create(ctx, st); err != nil {
		return "", ErrLoginStatePersist
	}

	// 6. Build the upstream authorize URL from the discovered endpoint.
	return buildAuthorizeURL(doc.AuthorizationEndpoint, provider.Config.ClientID, redirectURI, state, nonce, challenge, provider.Config.Scopes), nil
}

// randomURLToken returns n crypto-random bytes as a base64url (no-pad) string.
func randomURLToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// pkceS256Challenge computes BASE64URL(SHA256(ASCII(verifier))) per RFC 7636.
func pkceS256Challenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// firstNonEmpty returns the first non-blank string, or "".
func firstNonEmpty(vals []string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// sanitizeReturnURL enforces the open-redirect defense: only a same-site,
// relative path is honored. Anything absolute, protocol-relative (//host),
// scheme/host-bearing, or backslash-carrying collapses to the safe default.
func sanitizeReturnURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" || !strings.HasPrefix(raw, "/") || strings.HasPrefix(raw, "//") || strings.Contains(raw, "\\") {
		return defaultReturnURL
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "" || u.Host != "" {
		return defaultReturnURL
	}
	return raw
}

// buildAuthorizeURL assembles the upstream authorization request. It guarantees
// the openid scope is present and always sends S256 PKCE + state + nonce.
func buildAuthorizeURL(authEndpoint, clientID, redirectURI, state, nonce, challenge string, scopes []string) string {
	scope := ensureOpenIDScope(scopes)
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", clientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("scope", scope)
	q.Set("state", state)
	q.Set("nonce", nonce)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", pkceMethodS256)
	sep := "?"
	if strings.Contains(authEndpoint, "?") {
		sep = "&"
	}
	return authEndpoint + sep + q.Encode()
}

// ensureOpenIDScope returns the space-joined scopes with "openid" guaranteed
// present (prepended when missing).
func ensureOpenIDScope(scopes []string) string {
	hasOpenID := false
	cleaned := make([]string, 0, len(scopes)+1)
	for _, sc := range scopes {
		sc = strings.TrimSpace(sc)
		if sc == "" {
			continue
		}
		if sc == "openid" {
			hasOpenID = true
		}
		cleaned = append(cleaned, sc)
	}
	if !hasOpenID {
		cleaned = append([]string{"openid"}, cleaned...)
	}
	return strings.Join(cleaned, " ")
}
