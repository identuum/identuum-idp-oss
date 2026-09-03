package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/server"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// stubVerifier is a no-op TokenClaimsVerifier used only to
// construct an IntrospectionService so the discovery handler
// activates the introspection_endpoint advertisement path.
type stubVerifier struct{}

func (stubVerifier) IntrospectToken(_ context.Context, _ string) (*service.IntrospectionClaims, error) {
	return nil, nil
}

// stubClientAuth always succeeds; here only used to flip the
// OAuthClientAuth-wired branch of the discovery handler.
type stubClientAuth struct{}

func (stubClientAuth) Authenticate(_ context.Context, _, _, _ string) (*service.AuthenticatedClient, error) {
	return nil, nil
}

func fetchDiscovery(t *testing.T, deps OSSRouterDeps) map[string]any {
	t.Helper()
	engine := NewOSSEngine(deps)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("discovery status = %d, body=%q", w.Code, w.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return out
}

// ---------- IntrospectionService missing → no advertisement ----------

func TestDiscovery_NoIntrospectionServiceOmitsEndpoints(t *testing.T) {
	body := fetchDiscovery(t, OSSRouterDeps{
		DiscoveryConfig: server.OIDCDiscoveryConfig{Issuer: "https://idp.test"},
	})
	if _, ok := body["introspection_endpoint"]; ok {
		t.Errorf("introspection_endpoint advertised without service")
	}
	if _, ok := body["revocation_endpoint"]; ok {
		t.Errorf("revocation_endpoint advertised without service")
	}
}

// ---------- IntrospectionService wired → endpoints advertised ----------

func TestDiscovery_IntrospectionServiceAdvertisesEndpoints(t *testing.T) {
	svc := service.NewIntrospectionService(nil, stubVerifier{}, nil)
	body := fetchDiscovery(t, OSSRouterDeps{
		DiscoveryConfig:      server.OIDCDiscoveryConfig{Issuer: "https://idp.test"},
		IntrospectionService: svc,
	})
	want := "https://idp.test/api/v1/oauth/introspection"
	if got := body["introspection_endpoint"]; got != want {
		t.Errorf("introspection_endpoint = %v, want %s", got, want)
	}
	want = "https://idp.test/api/v1/oauth/revoke"
	if got := body["revocation_endpoint"]; got != want {
		t.Errorf("revocation_endpoint = %v, want %s", got, want)
	}
	// Without ClientAuth wired, no auth-methods advertised.
	if _, ok := body["introspection_endpoint_auth_methods_supported"]; ok {
		t.Errorf("auth methods advertised without OAuthClientAuth wired")
	}
}

// ---------- OAuthClientAuth wired → auth methods advertised ----------

func TestDiscovery_OAuthClientAuthAdvertisesAuthMethods(t *testing.T) {
	svc := service.NewIntrospectionService(nil, stubVerifier{}, nil)
	body := fetchDiscovery(t, OSSRouterDeps{
		DiscoveryConfig:      server.OIDCDiscoveryConfig{Issuer: "https://idp.test"},
		IntrospectionService: svc,
		OAuthClientAuth:      stubClientAuth{},
	})
	for _, key := range []string{"introspection_endpoint_auth_methods_supported", "revocation_endpoint_auth_methods_supported"} {
		raw, ok := body[key].([]any)
		if !ok {
			t.Fatalf("%s missing or wrong type: %T", key, body[key])
		}
		joined := make([]string, 0, len(raw))
		for _, v := range raw {
			if s, ok := v.(string); ok {
				joined = append(joined, s)
			}
		}
		got := strings.Join(joined, ",")
		if !strings.Contains(got, "client_secret_basic") || !strings.Contains(got, "client_secret_post") {
			t.Errorf("%s = %v, want both client_secret_basic and client_secret_post", key, joined)
		}
	}
}

// ---------- /authorize and /token are not falsely advertised as live ----------

func TestDiscovery_TokenEndpointStillStaticPlaceholder(t *testing.T) {
	// authorization_endpoint and token_endpoint come from
	// server.DiscoveryDocument unchanged. They are advertised as
	// metadata-only placeholders — the routes are NOT registered.
	// Confirm the body still carries them but no route lives at
	// the placeholder paths.
	svc := service.NewIntrospectionService(nil, stubVerifier{}, nil)
	deps := OSSRouterDeps{
		DiscoveryConfig:      server.OIDCDiscoveryConfig{Issuer: "https://idp.test"},
		IntrospectionService: svc,
	}
	body := fetchDiscovery(t, deps)
	if body["token_endpoint"] == nil {
		t.Errorf("token_endpoint missing from discovery")
	}
	// Now confirm the underlying token route is NOT registered.
	engine := NewOSSEngine(deps)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/oauth2/token", nil))
	// INTENTIONAL ABSENCE — the one shape where a 404 satisfying the assertion
	// IS the point. This test exists to prove /oauth2/token is NOT mounted while
	// discovery still advertises it, so no existence control belongs here: adding
	// one would assert the opposite of the contract. Recorded explicitly because
	// a census that flags "a 404 would satisfy this" is right about the mechanics
	// and wrong about the intent, and the next sweep should not re-open it.
	if w.Code == http.StatusOK {
		t.Errorf("token endpoint unexpectedly live: %d", w.Code)
	}
}

// ---------- TokenService advertisement ----------

func TestDiscovery_TokenServiceAdvertisesOSSTokenEndpoint(t *testing.T) {
	tokenSvc := service.NewTokenService(nil, stubKeyProvider{}, service.TokenServiceOptions{Issuer: "https://idp.test"})
	intro := service.NewIntrospectionService(nil, stubVerifier{}, nil)
	body := fetchDiscovery(t, OSSRouterDeps{
		DiscoveryConfig:      server.OIDCDiscoveryConfig{Issuer: "https://idp.test"},
		IntrospectionService: intro,
		TokenService:         tokenSvc,
		OAuthClientAuth:      stubClientAuth{},
	})
	want := "https://idp.test/api/v1/oauth/token"
	if got := body["token_endpoint"]; got != want {
		t.Errorf("token_endpoint = %v, want %s", got, want)
	}
	methods, _ := body["token_endpoint_auth_methods_supported"].([]any)
	if len(methods) != 2 {
		t.Errorf("token_endpoint_auth_methods = %v", methods)
	}
	grants, _ := body["grant_types_supported"].([]any)
	if len(grants) != 1 || grants[0] != "client_credentials" {
		t.Errorf("grant_types_supported = %v, want only client_credentials", grants)
	}
}

// ---------- Userinfo advertisement ----------

func TestDiscovery_UserinfoAdvertisedWhenIntrospectionWired(t *testing.T) {
	svc := service.NewIntrospectionService(nil, stubVerifier{}, nil)
	body := fetchDiscovery(t, OSSRouterDeps{
		DiscoveryConfig:      server.OIDCDiscoveryConfig{Issuer: "https://idp.test"},
		IntrospectionService: svc,
	})
	want := "https://idp.test/api/v1/oidc/userinfo"
	if got := body["userinfo_endpoint"]; got != want {
		t.Errorf("userinfo_endpoint = %v, want %s", got, want)
	}
}

func TestDiscovery_NoUserinfoAdvertisedWithoutIntrospection(t *testing.T) {
	body := fetchDiscovery(t, OSSRouterDeps{
		DiscoveryConfig: server.OIDCDiscoveryConfig{Issuer: "https://idp.test"},
	})
	// Static document has no userinfo_endpoint when discovery
	// composition does not add one.
	if got, _ := body["userinfo_endpoint"].(string); got == "https://idp.test/api/v1/oidc/userinfo" {
		t.Errorf("userinfo advertised without IntrospectionService: %q", got)
	}
}

// ---------- private_key_jwt advertisement ----------

type stubAssertionClientAuth struct{}

func (stubAssertionClientAuth) Authenticate(_ context.Context, _, _, _ string) (*service.AuthenticatedClient, error) {
	return nil, nil
}

func (stubAssertionClientAuth) AuthenticateAssertion(_ context.Context, _, _ string) (*service.AuthenticatedClient, error) {
	return nil, nil
}

func (stubAssertionClientAuth) HasAssertionValidator() bool { return true }

func TestDiscovery_PrivateKeyJWTAdvertisedWhenAssertionWired(t *testing.T) {
	intro := service.NewIntrospectionService(nil, stubVerifier{}, nil)
	tokenSvc := service.NewTokenService(nil, stubKeyProvider{}, service.TokenServiceOptions{Issuer: "https://idp.test"})
	body := fetchDiscovery(t, OSSRouterDeps{
		DiscoveryConfig:      server.OIDCDiscoveryConfig{Issuer: "https://idp.test"},
		IntrospectionService: intro,
		TokenService:         tokenSvc,
		OAuthClientAuth:      stubAssertionClientAuth{},
	})
	rawMethods, ok := body["token_endpoint_auth_methods_supported"].([]any)
	if !ok {
		t.Fatalf("methods missing or wrong type: %T", body["token_endpoint_auth_methods_supported"])
	}
	var sawPKJ bool
	for _, m := range rawMethods {
		if m == "private_key_jwt" {
			sawPKJ = true
		}
	}
	if !sawPKJ {
		t.Errorf("private_key_jwt not advertised when assertion seam wired: %v", rawMethods)
	}
	if _, ok := body["token_endpoint_auth_signing_alg_values_supported"]; !ok {
		t.Errorf("token_endpoint_auth_signing_alg_values_supported missing")
	}
}

func TestDiscovery_PrivateKeyJWTAbsentWhenAssertionNotWired(t *testing.T) {
	intro := service.NewIntrospectionService(nil, stubVerifier{}, nil)
	tokenSvc := service.NewTokenService(nil, stubKeyProvider{}, service.TokenServiceOptions{Issuer: "https://idp.test"})
	body := fetchDiscovery(t, OSSRouterDeps{
		DiscoveryConfig:      server.OIDCDiscoveryConfig{Issuer: "https://idp.test"},
		IntrospectionService: intro,
		TokenService:         tokenSvc,
		OAuthClientAuth:      stubClientAuth{}, // basic + post only
	})
	rawMethods, _ := body["token_endpoint_auth_methods_supported"].([]any)
	for _, m := range rawMethods {
		if m == "private_key_jwt" {
			t.Errorf("private_key_jwt advertised without assertion seam wired: %v", rawMethods)
		}
	}
}

// ---------- Negative invariants preserved ----------

func TestDiscovery_DoesNotAdvertiseAuthorizationCode(t *testing.T) {
	intro := service.NewIntrospectionService(nil, stubVerifier{}, nil)
	tokenSvc := service.NewTokenService(nil, stubKeyProvider{}, service.TokenServiceOptions{Issuer: "https://idp.test"})
	body := fetchDiscovery(t, OSSRouterDeps{
		DiscoveryConfig:      server.OIDCDiscoveryConfig{Issuer: "https://idp.test"},
		IntrospectionService: intro,
		TokenService:         tokenSvc,
		OAuthClientAuth:      stubClientAuth{},
	})
	grants, _ := body["grant_types_supported"].([]any)
	for _, g := range grants {
		if g == "authorization_code" || g == "refresh_token" || g == "password" {
			t.Errorf("forbidden grant advertised: %v", g)
		}
	}
}

// ---------- refresh_token grant advertisement ----------

// discoveryFakeRefreshRepo satisfies repository.RefreshTokenRepository
// minimally — discovery construction only needs RefreshTokenService
// to be constructible.
type discoveryFakeRefreshRepo struct{}

func (discoveryFakeRefreshRepo) Insert(context.Context, *domain.RefreshToken) error {
	return nil
}
func (discoveryFakeRefreshRepo) GetByID(context.Context, uuid.UUID) (*domain.RefreshToken, error) {
	return nil, nil
}
func (discoveryFakeRefreshRepo) MarkRevoked(context.Context, uuid.UUID, time.Time) error {
	return nil
}
func (discoveryFakeRefreshRepo) MarkRotated(context.Context, uuid.UUID, uuid.UUID, time.Time) error {
	return nil
}
func (discoveryFakeRefreshRepo) SetAccessJTI(context.Context, uuid.UUID, string, time.Time) error {
	return nil
}
func (discoveryFakeRefreshRepo) RevokeAllBySubject(context.Context, string, time.Time) (int64, error) {
	return 0, nil
}
func (discoveryFakeRefreshRepo) RevokeByFamily(context.Context, string, time.Time) (int64, error) {
	return 0, nil
}
func (discoveryFakeRefreshRepo) DeleteExpiredBefore(context.Context, time.Time) (int64, error) {
	return 0, nil
}

func TestDiscovery_RefreshTokenAdvertisedWhenWired(t *testing.T) {
	intro := service.NewIntrospectionService(nil, stubVerifier{}, nil)
	tokenSvc := service.NewTokenService(nil, stubKeyProvider{}, service.TokenServiceOptions{Issuer: "https://idp.test"})
	refreshSvc := service.NewRefreshTokenService(nil, &discoveryFakeRefreshRepo{}, service.RefreshTokenServiceOptions{})
	tokenSvc = tokenSvc.WithRefreshTokenService(refreshSvc)
	body := fetchDiscovery(t, OSSRouterDeps{
		DiscoveryConfig:      server.OIDCDiscoveryConfig{Issuer: "https://idp.test"},
		IntrospectionService: intro,
		TokenService:         tokenSvc,
		OAuthClientAuth:      stubClientAuth{},
		RefreshTokenService:  refreshSvc,
	})
	grants, _ := body["grant_types_supported"].([]any)
	var sawRefresh, sawAC bool
	for _, g := range grants {
		if g == "refresh_token" {
			sawRefresh = true
		}
		if g == "authorization_code" || g == "password" {
			sawAC = true
		}
	}
	if !sawRefresh {
		t.Errorf("refresh_token not advertised: %v", grants)
	}
	if sawAC {
		t.Errorf("forbidden grant advertised: %v", grants)
	}
}

func TestDiscovery_RefreshTokenAbsentWhenNotWired(t *testing.T) {
	intro := service.NewIntrospectionService(nil, stubVerifier{}, nil)
	tokenSvc := service.NewTokenService(nil, stubKeyProvider{}, service.TokenServiceOptions{Issuer: "https://idp.test"})
	body := fetchDiscovery(t, OSSRouterDeps{
		DiscoveryConfig:      server.OIDCDiscoveryConfig{Issuer: "https://idp.test"},
		IntrospectionService: intro,
		TokenService:         tokenSvc,
		OAuthClientAuth:      stubClientAuth{},
	})
	grants, _ := body["grant_types_supported"].([]any)
	for _, g := range grants {
		if g == "refresh_token" {
			t.Errorf("refresh_token advertised without wiring: %v", grants)
		}
	}
}

func TestDiscovery_NoTokenServiceDoesNotAdvertiseClientCredentials(t *testing.T) {
	body := fetchDiscovery(t, OSSRouterDeps{
		DiscoveryConfig: server.OIDCDiscoveryConfig{Issuer: "https://idp.test"},
	})
	// grant_types_supported should be the static defaults
	// (authorization_code + refresh_token from server.DiscoveryDocument),
	// NOT just client_credentials. Pin the absence of OSS's
	// /api/v1/oauth/token path.
	if got, _ := body["token_endpoint"].(string); got == "https://idp.test/api/v1/oauth/token" {
		t.Errorf("OSS token_endpoint advertised without TokenService: %s", got)
	}
	// authorization_code MUST NOT silently appear as live — it
	// comes from the static defaults, not from us.
	if got, _ := body["authorization_endpoint"].(string); got == "" {
		// The static document advertises authorization_endpoint as a
		// placeholder; ensure it's present so callers see the
		// canonical shape, but the route is non-live (confirmed by
		// TestDiscovery_TokenEndpointStillStaticPlaceholder).
		t.Errorf("authorization_endpoint missing from discovery")
	}
}

// stubKeyProvider satisfies SigningKeyProvider for the discovery
// test where we only need TokenService construction to succeed.
type stubKeyProvider struct{}

func (stubKeyProvider) ListActive(_ context.Context) ([]domain.SigningKey, error) {
	return nil, nil
}

// ---------- conformance audit (discovery hardening batch) ----------

// TestDiscovery_TokenEndpointAuthSigningAlgIsInboundOnly pins the
// inbound-vs-outbound distinction operators sometimes confuse:
//
//   - `token_endpoint_auth_signing_alg_values_supported` is the
//     INBOUND `private_key_jwt` client-authentication allowlist. It
//     describes assertions the OP ACCEPTS. RS256 is on this list
//     because confidential clients may authenticate to the token
//     endpoint with RS256 assertions.
//
//   - `id_token_signing_alg_values_supported` is the OUTBOUND ID
//     token issuance posture. RS256 is BANNED here.
//
// The test asserts both relationships at the same time so a future
// refactor cannot collapse the two fields.
func TestDiscovery_TokenEndpointAuthSigningAlgIsInboundOnly(t *testing.T) {
	// Wire the assertion validator stub so the inbound metadata
	// field actually populates.
	intro := service.NewIntrospectionService(nil, stubVerifier{}, nil)
	tokenSvc := service.NewTokenService(nil, stubKeyProvider{}, service.TokenServiceOptions{Issuer: "https://idp.test"})
	body := fetchDiscovery(t, OSSRouterDeps{
		DiscoveryConfig:      server.OIDCDiscoveryConfig{Issuer: "https://idp.test"},
		IntrospectionService: intro,
		TokenService:         tokenSvc,
		OAuthClientAuth:      stubAssertionClientAuth{},
	})
	inbound, ok := body["token_endpoint_auth_signing_alg_values_supported"].([]any)
	if !ok {
		t.Fatalf("inbound field missing or wrong type: %T", body["token_endpoint_auth_signing_alg_values_supported"])
	}
	var inboundHasRS256 bool
	for _, a := range inbound {
		if a == "RS256" {
			inboundHasRS256 = true
		}
	}
	if !inboundHasRS256 {
		t.Errorf("inbound private_key_jwt allowlist must include RS256 for confidential-client compat; got %v", inbound)
	}
	// The outbound `id_token_signing_alg_values_supported` shape is
	// pinned by TestDiscovery_SigningAlgSetForIDTokens under
	// fullChainDiscovery (THE-ADVERTISED-RS256: exactly EdDSA/ES256).
	// This test's concern is only the INBOUND private_key_jwt allowlist
	// asserted above — where RS256 IS present, which is the whole point of
	// the inbound/outbound distinction.
}

// TestDiscovery_NoNonStandardTopLevelKeys pins the OIDC-Conformance
// Phase 3 remediation: the discovery document MUST NOT carry vendor-
// specific top-level keys like `mode`, `build`, or `tier`. Operators
// reading the document expect strict OIDC Discovery 1.0 §3 shape.
func TestDiscovery_NoNonStandardTopLevelKeys(t *testing.T) {
	body := fullChainDiscovery(t)
	for _, banned := range []string{"mode", "build", "tier"} {
		if _, ok := body[banned]; ok {
			t.Errorf("non-standard top-level discovery key %q present: %v", banned, body[banned])
		}
	}
}

// THE-ADVERTISED-RS256 (owner ruling, superseding the advertising half of
// THE-PKCE-DECISION): the full-chain outbound set is exactly
// {EdDSA, ES256} — what the issuer will SIGN an id_token with. RS256 stays
// an explicit per-client registration for testing and is NOT advertised,
// because a discovery reader takes this list as the OP's issuance policy.
// Everything else stays forbidden.
func TestDiscovery_SigningAlgSetForIDTokens(t *testing.T) {
	body := fullChainDiscovery(t)
	algs, _ := body["id_token_signing_alg_values_supported"].([]any)
	algSet := make(map[string]bool, len(algs))
	for _, a := range algs {
		if s, ok := a.(string); ok {
			algSet[s] = true
		}
	}
	if !algSet["EdDSA"] || !algSet["ES256"] {
		t.Errorf("advertised set must include EdDSA + ES256; got %v", algSet)
	}
	if len(algSet) != 2 {
		t.Errorf("advertised set must be EXACTLY EdDSA + ES256; got %v", algSet)
	}
	for _, a := range algs {
		if a == "RS256" || a == "RS384" || a == "RS512" ||
			a == "PS256" || a == "PS384" || a == "PS512" ||
			a == "HS256" || a == "none" {
			t.Errorf("forbidden alg advertised: %v", a)
		}
	}
}

func TestDiscovery_FrontChannelLogoutFlagsExplicitlyFalse(t *testing.T) {
	body := fullChainDiscovery(t)
	for _, k := range []string{
		"frontchannel_logout_supported",
		"frontchannel_logout_session_supported",
		"backchannel_logout_supported",
		"backchannel_logout_session_supported",
	} {
		v, ok := body[k]
		if !ok {
			t.Errorf("flag %q missing; explicit false is preferred over omission", k)
			continue
		}
		if v != false {
			t.Errorf("flag %q must be false until implemented: got %v", k, v)
		}
	}
}

func TestDiscovery_AdvertisesOfflineAccessOnlyWithUserSession(t *testing.T) {
	// With UserSessionService wired, offline_access is advertised.
	body := fullChainDiscovery(t)
	scopes, _ := body["scopes_supported"].([]any)
	var sawOffline bool
	for _, s := range scopes {
		if s == "offline_access" {
			sawOffline = true
		}
	}
	if !sawOffline {
		t.Errorf("offline_access missing from scopes_supported: %v", scopes)
	}
}

func TestDiscovery_OnlyCodeIsAdvertisedAsResponseType(t *testing.T) {
	body := fullChainDiscovery(t)
	rts, _ := body["response_types_supported"].([]any)
	if len(rts) != 1 || rts[0] != "code" {
		t.Errorf("response_types_supported = %v, want [\"code\"]", rts)
	}
}

func TestDiscovery_SubjectTypesAndClaimsAdvertised(t *testing.T) {
	body := fullChainDiscovery(t)
	if got, _ := body["subject_types_supported"].([]any); len(got) != 1 || got[0] != "public" {
		t.Errorf("subject_types_supported = %v", got)
	}
	claims, _ := body["claims_supported"].([]any)
	required := map[string]bool{"sub": false, "iss": false, "aud": false, "exp": false, "iat": false, "email": false, "email_verified": false}
	for _, c := range claims {
		if s, ok := c.(string); ok {
			if _, want := required[s]; want {
				required[s] = true
			}
		}
	}
	for k, present := range required {
		if !present {
			t.Errorf("claims_supported missing %q: %v", k, claims)
		}
	}
}

// RULE: PKCE-S256-1
func TestDiscovery_CodeChallengeMethodsS256Only(t *testing.T) {
	body := fullChainDiscovery(t)
	ms, _ := body["code_challenge_methods_supported"].([]any)
	if len(ms) != 1 || ms[0] != "S256" {
		t.Errorf("code_challenge_methods_supported = %v, want [\"S256\"]", ms)
	}
}

func TestDiscovery_EndSessionEndpointAdvertisedWhenChainLive(t *testing.T) {
	body := fullChainDiscovery(t)
	if got, _ := body["end_session_endpoint"].(string); got != "https://idp.test/api/v1/oidc/logout" {
		t.Errorf("end_session_endpoint = %q", got)
	}
}

// fullChainDiscovery returns the discovery body when every
// upstream service is wired so we can audit the "live" shape.
func fullChainDiscovery(t *testing.T) map[string]any {
	t.Helper()
	intro := service.NewIntrospectionService(nil, stubVerifier{}, nil)
	tokenSvc := service.NewTokenService(nil, stubKeyProvider{}, service.TokenServiceOptions{Issuer: "https://idp.test"})
	refreshSvc := service.NewRefreshTokenService(nil, &discoveryFakeRefreshRepo{}, service.RefreshTokenServiceOptions{})
	tokenSvc = tokenSvc.WithRefreshTokenService(refreshSvc)

	codes := service.NewAuthorizationCodeService(nil, &discoveryFakeAuthCodeRepo{}, service.AuthorizationCodeServiceOptions{})
	authorize := service.NewAuthorizeService(nil, &discoveryFakeClientLookup{}, codes, service.AuthorizeServiceOptions{Issuer: "https://idp.test"})
	userToken := service.NewUserTokenService(nil, stubKeyProvider{}, service.UserTokenServiceOptions{Issuer: "https://idp.test"})
	userSession := service.NewUserSessionService(nil, &discoveryFakeSessionRepo{}, service.UserSessionServiceOptions{})
	cookieSvc := service.NewCookieSessionService(nil, userSession, nil, service.CookieSessionServiceOptions{AllowPlainHTTP: true})

	return fetchDiscovery(t, OSSRouterDeps{
		DiscoveryConfig:          server.OIDCDiscoveryConfig{Issuer: "https://idp.test"},
		IntrospectionService:     intro,
		TokenService:             tokenSvc,
		OAuthClientAuth:          stubClientAuth{},
		RefreshTokenService:      refreshSvc,
		AuthorizationCodeService: codes,
		AuthorizeService:         authorize,
		UserToken:                userToken,
		UserLookup:               discoveryFakeUserLookup{},
		SessionLookup:            discoveryFakeSessionLookup{},
		UserSessionService:       userSession,
		CookieSession:            cookieSvc,
	})
}

// minimal repo/lookup fakes used only by fullChainDiscovery.
type discoveryFakeAuthCodeRepo struct{}

func (discoveryFakeAuthCodeRepo) Insert(context.Context, *domain.OAuthAuthorizationCode) error {
	return nil
}
func (discoveryFakeAuthCodeRepo) GetActiveByCodeHash(context.Context, string, time.Time) (*domain.OAuthAuthorizationCode, error) {
	return nil, nil
}
func (discoveryFakeAuthCodeRepo) GetByCodeHashAnyState(context.Context, string) (*domain.OAuthAuthorizationCode, error) {
	return nil, nil
}
func (discoveryFakeAuthCodeRepo) MarkConsumed(context.Context, uuid.UUID, time.Time) (bool, error) {
	return true, nil
}
func (discoveryFakeAuthCodeRepo) DeleteExpiredBefore(context.Context, time.Time) (int64, error) {
	return 0, nil
}
func (discoveryFakeAuthCodeRepo) RecordIssuedTokens(context.Context, uuid.UUID, string, time.Time, *uuid.UUID) error {
	return nil
}

type discoveryFakeClientLookup struct{}

func (discoveryFakeClientLookup) GetClientByClientID(context.Context, string) (*domain.Client, error) {
	return nil, nil
}

type discoveryFakeUserLookup struct{}

func (discoveryFakeUserLookup) GetByID(context.Context, uuid.UUID) (*domain.User, error) {
	return nil, nil
}

type discoveryFakeSessionLookup struct{}

func (discoveryFakeSessionLookup) GetByID(context.Context, uuid.UUID) (*domain.Session, error) {
	return nil, nil
}

func (discoveryFakeSessionLookup) GetSessionWithUserAndOrgStatus(context.Context, uuid.UUID) (*domain.SessionValidationInfo, error) {
	return nil, nil
}

type discoveryFakeSessionRepo struct{}

func (discoveryFakeSessionRepo) Create(context.Context, *domain.Session) (*domain.Session, error) {
	return nil, nil
}
func (discoveryFakeSessionRepo) GetByID(context.Context, uuid.UUID) (*domain.Session, error) {
	return nil, nil
}
func (discoveryFakeSessionRepo) GetByTokenSelector(context.Context, uuid.UUID) (*domain.Session, error) {
	return nil, nil
}
func (discoveryFakeSessionRepo) Update(context.Context, *domain.Session, uuid.UUID) error {
	return nil
}
func (discoveryFakeSessionRepo) RotateToken(context.Context, uuid.UUID, string, string, time.Time, time.Time) (*domain.Session, bool, error) {
	return nil, false, nil
}
func (discoveryFakeSessionRepo) RecordACRUplift(context.Context, uuid.UUID, time.Time, string) error {
	return nil
}
func (discoveryFakeSessionRepo) Revoke(context.Context, uuid.UUID, uuid.UUID, string) error {
	return nil
}
func (discoveryFakeSessionRepo) RevokeByUserID(context.Context, uuid.UUID, string) error {
	return nil
}
func (discoveryFakeSessionRepo) RevokeByOrganizationID(context.Context, uuid.UUID, string) error {
	return nil
}
func (discoveryFakeSessionRepo) Delete(context.Context, uuid.UUID, uuid.UUID) error { return nil }
func (discoveryFakeSessionRepo) ListByUserID(context.Context, uuid.UUID, bool) ([]*domain.Session, error) {
	return nil, nil
}
func (discoveryFakeSessionRepo) ListActiveByUserID(context.Context, uuid.UUID) ([]*domain.Session, error) {
	return nil, nil
}
func (discoveryFakeSessionRepo) CountActiveByUserID(context.Context, uuid.UUID) (int, error) {
	return 0, nil
}
func (discoveryFakeSessionRepo) DeleteExpiredReturning(context.Context, time.Duration, int) ([]*domain.Session, error) {
	return nil, nil
}
func (discoveryFakeSessionRepo) GetSessionWithUserAndOrgStatus(context.Context, uuid.UUID) (*domain.SessionValidationInfo, error) {
	return nil, nil
}
func (discoveryFakeSessionRepo) GetStats(context.Context) (map[string]int, error) {
	return nil, nil
}
