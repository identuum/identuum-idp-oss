package handlers

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// In-memory SigningKeyProvider local to the handlers test package.
type keyProvider struct {
	keys []domain.SigningKey
}

func (p *keyProvider) ListActive(_ context.Context) ([]domain.SigningKey, error) {
	return p.keys, nil
}

func genEdDSA(t *testing.T, kid string) domain.SigningKey {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	pkPEM := pemMarshalPK(t, priv)
	pubPEM := pemMarshalPub(t, pub)
	return domain.SigningKey{
		KID: kid, Algorithm: domain.KeyAlgorithmEdDSA,
		PrivateKey: pkPEM, PublicKey: pubPEM, State: domain.KeyStateActive,
	}
}

func genRS256(t *testing.T, kid string) domain.SigningKey {
	t.Helper()
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	return domain.SigningKey{
		KID: kid, Algorithm: domain.KeyAlgorithmRS256,
		PrivateKey: pemMarshalPK(t, priv), PublicKey: pemMarshalPub(t, &priv.PublicKey),
		State: domain.KeyStateActive,
	}
}

func pemMarshalPK(t *testing.T, k any) string {
	t.Helper()
	b, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: b}))
}

func pemMarshalPub(t *testing.T, k any) string {
	t.Helper()
	b, err := x509.MarshalPKIXPublicKey(k)
	if err != nil {
		t.Fatalf("marshal pub: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: b}))
}

// stub OAuth client authenticator that always succeeds with a
// fixed AuthenticatedClient — keeps these tests focused on the
// /token handler shape, not the client-auth chain.
type tokenStubAllow struct {
	kind service.AuthenticatedClientKind
}

func (s tokenStubAllow) Authenticate(_ context.Context, id, _, _ string) (*service.AuthenticatedClient, error) {
	out := &service.AuthenticatedClient{
		Kind: s.kind, ClientID: id, AuthRecordID: uuid.New(),
	}
	if s.kind == service.AuthenticatedClientKindAPIResource {
		out.AllowedScopes = []string{"billing:read"}
	}
	return out, nil
}

type tokenStubReject struct{}

func (tokenStubReject) Authenticate(_ context.Context, _, _, _ string) (*service.AuthenticatedClient, error) {
	return nil, errors.New("denied")
}

func newTokenEngine(t *testing.T, keys *keyProvider, ca service.TokenClaimsVerifier, stub interface {
	Authenticate(context.Context, string, string, string) (*service.AuthenticatedClient, error)
}, audSvc audit.Service) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	tokenSvc := service.NewTokenService(nil, keys, service.TokenServiceOptions{Issuer: "https://idp.test"})
	RegisterTokenRoutes(r, TokenHandlerDeps{
		TokenService: tokenSvc,
		ClientAuth:   stub,
		Audit:        audSvc,
	})
	_ = ca
	return r
}

// ---------- Route presence ----------

func TestToken_RouteAbsentWithoutTokenService(t *testing.T) {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	RegisterTokenRoutes(r, TokenHandlerDeps{ClientAuth: tokenStubAllow{kind: service.AuthenticatedClientKindOAuth}})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/v1/oauth/token", nil))
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestToken_RouteAbsentWithoutClientAuth(t *testing.T) {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	tokenSvc := service.NewTokenService(nil, &keyProvider{keys: []domain.SigningKey{genEdDSA(t, "k")}}, service.TokenServiceOptions{Issuer: "https://idp.test"})
	RegisterTokenRoutes(r, TokenHandlerDeps{TokenService: tokenSvc})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/v1/oauth/token", nil))
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

// ---------- Client auth ----------

func TestToken_MissingClientAuth401(t *testing.T) {
	r := newTokenEngine(t, &keyProvider{keys: []domain.SigningKey{genEdDSA(t, "k")}}, nil, tokenStubReject{}, &audit.Recorder{})
	body := strings.NewReader("grant_type=client_credentials&client_id=cli-1&client_secret=WRONG-SECRET-MUST-NOT-LEAK")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/oauth/token", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
	if strings.Contains(w.Body.String(), "WRONG-SECRET-MUST-NOT-LEAK") {
		t.Errorf("response leaked secret sentinel: %q", w.Body.String())
	}
}

// ---------- Unsupported grants ----------

func TestToken_UnsupportedGrantReturns400(t *testing.T) {
	r := newTokenEngine(t, &keyProvider{keys: []domain.SigningKey{genEdDSA(t, "k")}}, nil, tokenStubAllow{kind: service.AuthenticatedClientKindOAuth}, &audit.Recorder{})
	body := strings.NewReader("grant_type=authorization_code&client_id=cli-1&client_secret=S")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/oauth/token", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
	if !strings.Contains(w.Body.String(), `"error":"unsupported_grant_type"`) {
		t.Errorf("body = %q", w.Body.String())
	}
}

func TestToken_RefreshTokenGrantUnsupported(t *testing.T) {
	r := newTokenEngine(t, &keyProvider{keys: []domain.SigningKey{genEdDSA(t, "k")}}, nil, tokenStubAllow{kind: service.AuthenticatedClientKindOAuth}, &audit.Recorder{})
	body := strings.NewReader("grant_type=refresh_token&client_id=cli-1&client_secret=S")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/oauth/token", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
	if !strings.Contains(w.Body.String(), `"error":"unsupported_grant_type"`) {
		t.Errorf("body = %q", w.Body.String())
	}
}

func TestToken_MissingGrantType400(t *testing.T) {
	r := newTokenEngine(t, &keyProvider{keys: []domain.SigningKey{genEdDSA(t, "k")}}, nil, tokenStubAllow{kind: service.AuthenticatedClientKindOAuth}, &audit.Recorder{})
	body := strings.NewReader("client_id=cli-1&client_secret=S")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/oauth/token", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
	if !strings.Contains(w.Body.String(), `"error":"invalid_request"`) {
		t.Errorf("body = %q", w.Body.String())
	}
}

// ---------- Success ----------

func TestToken_SuccessResponseShape(t *testing.T) {
	rec := &audit.Recorder{}
	r := newTokenEngine(t, &keyProvider{keys: []domain.SigningKey{genEdDSA(t, "k")}}, nil, tokenStubAllow{kind: service.AuthenticatedClientKindOAuth}, rec)
	body := strings.NewReader("grant_type=client_credentials&client_id=cli-1&client_secret=S")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/oauth/token", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%q", w.Code, w.Body.String())
	}
	// RFC 6749 §5.1 no-cache headers.
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("Cache-Control = %q", w.Header().Get("Cache-Control"))
	}
	if w.Header().Get("Pragma") != "no-cache" {
		t.Errorf("Pragma = %q", w.Header().Get("Pragma"))
	}
	// Body fields.
	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, ok := resp["access_token"].(string); !ok {
		t.Errorf("access_token missing or not string")
	}
	if resp["token_type"] != "Bearer" {
		t.Errorf("token_type = %v", resp["token_type"])
	}
	if _, ok := resp["expires_in"].(float64); !ok {
		t.Errorf("expires_in missing or not number")
	}
	if _, present := resp["refresh_token"]; present {
		t.Errorf("refresh_token must NOT be present in response: %v", resp)
	}
	// Audit fired.
	var sawAudit bool
	for _, e := range rec.Events() {
		if e.Action == "oauth_token.issued" {
			sawAudit = true
			if e.Metadata["client_id"] != "cli-1" {
				t.Errorf("audit client_id = %v", e.Metadata["client_id"])
			}
			if e.Metadata["grant_type"] != "client_credentials" {
				t.Errorf("audit grant_type = %v", e.Metadata["grant_type"])
			}
			// Sensitive-field absence.
			if _, ok := e.Metadata["access_token"]; ok {
				t.Errorf("audit leaked access_token")
			}
			if _, ok := e.Metadata["client_secret"]; ok {
				t.Errorf("audit leaked client_secret")
			}
		}
	}
	if !sawAudit {
		t.Errorf("missing oauth_token.issued audit")
	}
}

func TestToken_InvalidScopeReturns400(t *testing.T) {
	r := newTokenEngine(t, &keyProvider{keys: []domain.SigningKey{genEdDSA(t, "k")}}, nil, tokenStubAllow{kind: service.AuthenticatedClientKindOAuth}, &audit.Recorder{})
	body := strings.NewReader("grant_type=client_credentials&scope=billing:read&client_id=cli-1&client_secret=S")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/oauth/token", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
	if !strings.Contains(w.Body.String(), `"error":"invalid_scope"`) {
		t.Errorf("body = %q", w.Body.String())
	}
}

func TestToken_APIResourceScopeGranted(t *testing.T) {
	r := newTokenEngine(t, &keyProvider{keys: []domain.SigningKey{genEdDSA(t, "k")}}, nil, tokenStubAllow{kind: service.AuthenticatedClientKindAPIResource}, &audit.Recorder{})
	body := strings.NewReader("grant_type=client_credentials&scope=billing:read&client_id=https://api.example.com&client_secret=S")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/oauth/token", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%q", w.Code, w.Body.String())
	}
	var resp map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["scope"] != "billing:read" {
		t.Errorf("scope = %v", resp["scope"])
	}
}

// ---------- Audience policy (RFC 8707) ----------

// audienceLookupStub satisfies service.AudienceLookup for handler
// tests so we can exercise the invalid_target wire mapping
// without standing up the api-resource repository.
type audienceLookupStub struct {
	byAud map[string]*domain.APIResource
}

func (a audienceLookupStub) LookupAudience(_ context.Context, aud string) (*domain.APIResource, error) {
	return a.byAud[aud], nil
}

func newTokenEngineWithAudience(t *testing.T, keys *keyProvider, stub interface {
	Authenticate(context.Context, string, string, string) (*service.AuthenticatedClient, error)
}, lookup service.AudienceLookup) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	tokenSvc := service.NewTokenService(nil, keys, service.TokenServiceOptions{Issuer: "https://idp.test"}).
		WithAudienceLookup(lookup)
	RegisterTokenRoutes(r, TokenHandlerDeps{
		TokenService: tokenSvc,
		ClientAuth:   stub,
		Audit:        &audit.Recorder{},
	})
	return r
}

func TestToken_UnknownAudienceReturnsInvalidTarget(t *testing.T) {
	r := newTokenEngineWithAudience(t,
		&keyProvider{keys: []domain.SigningKey{genEdDSA(t, "k")}},
		tokenStubAllow{kind: service.AuthenticatedClientKindOAuth},
		audienceLookupStub{byAud: map[string]*domain.APIResource{}},
	)
	body := strings.NewReader("grant_type=client_credentials&audience=https://missing.example.com&client_id=cli-1&client_secret=S")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/oauth/token", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
	if !strings.Contains(w.Body.String(), `"error":"invalid_target"`) {
		t.Errorf("body = %q", w.Body.String())
	}
}

func TestToken_InactiveAudienceReturnsInvalidTarget(t *testing.T) {
	res := &domain.APIResource{
		ID:       uuid.New(),
		Audience: "https://billing.example.com",
		Active:   false,
	}
	r := newTokenEngineWithAudience(t,
		&keyProvider{keys: []domain.SigningKey{genEdDSA(t, "k")}},
		tokenStubAllow{kind: service.AuthenticatedClientKindOAuth},
		audienceLookupStub{byAud: map[string]*domain.APIResource{res.Audience: res}},
	)
	body := strings.NewReader("grant_type=client_credentials&audience=https://billing.example.com&client_id=cli-1&client_secret=S")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/oauth/token", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
	if !strings.Contains(w.Body.String(), `"error":"invalid_target"`) {
		t.Errorf("body = %q", w.Body.String())
	}
}

func TestToken_ScopeOutsideAudienceReturnsInvalidScope(t *testing.T) {
	res := &domain.APIResource{
		ID:       uuid.New(),
		Audience: "https://billing.example.com",
		Active:   true,
		Scopes:   []domain.APIScope{{Name: "billing:read"}},
	}
	r := newTokenEngineWithAudience(t,
		&keyProvider{keys: []domain.SigningKey{genEdDSA(t, "k")}},
		tokenStubAllow{kind: service.AuthenticatedClientKindOAuth},
		audienceLookupStub{byAud: map[string]*domain.APIResource{res.Audience: res}},
	)
	// admin:write is not in the audience's set.
	body := strings.NewReader("grant_type=client_credentials&audience=https://billing.example.com&scope=admin:write&client_id=cli-1&client_secret=S")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/oauth/token", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
	if !strings.Contains(w.Body.String(), `"error":"invalid_scope"`) {
		t.Errorf("body = %q, want invalid_scope", w.Body.String())
	}
}

// ---------- refresh_token grant ----------

// refreshHandlerRepo is the smallest possible repository used
// just to drive Issue + IssueRefresh in the handler-test process.
type refreshHandlerRepo struct {
	byID map[uuid.UUID]*domain.RefreshToken
}

func newRefreshHandlerRepo() *refreshHandlerRepo {
	return &refreshHandlerRepo{byID: map[uuid.UUID]*domain.RefreshToken{}}
}

func (r *refreshHandlerRepo) Insert(_ context.Context, rt *domain.RefreshToken) error {
	cp := *rt
	r.byID[rt.ID] = &cp
	return nil
}

func (r *refreshHandlerRepo) GetByID(_ context.Context, id uuid.UUID) (*domain.RefreshToken, error) {
	row, ok := r.byID[id]
	if !ok {
		return nil, nil
	}
	cp := *row
	return &cp, nil
}

func (r *refreshHandlerRepo) MarkRevoked(_ context.Context, id uuid.UUID, at time.Time) error {
	if row, ok := r.byID[id]; ok {
		row.RevokedAt = &at
	}
	return nil
}

func (r *refreshHandlerRepo) MarkRotated(_ context.Context, oldID, newID uuid.UUID, at time.Time) error {
	if row, ok := r.byID[oldID]; ok {
		row.RevokedAt = &at
		row.ReplacedBy = &newID
	}
	return nil
}

func (r *refreshHandlerRepo) SetAccessJTI(_ context.Context, id uuid.UUID, jti string, at time.Time) error {
	if row, ok := r.byID[id]; ok {
		row.AccessJTI = jti
		row.LastUsedAt = &at
	}
	return nil
}

func (r *refreshHandlerRepo) RevokeAllBySubject(_ context.Context, subject string, at time.Time) (int64, error) {
	if subject == "" {
		return 0, nil
	}
	var n int64
	for _, row := range r.byID {
		if row.Subject != subject || row.RevokedAt != nil {
			continue
		}
		stamp := at
		row.RevokedAt = &stamp
		n++
	}
	return n, nil
}

func (r *refreshHandlerRepo) RevokeByFamily(_ context.Context, familyID string, at time.Time) (int64, error) {
	if familyID == "" {
		return 0, nil
	}
	var n int64
	for _, row := range r.byID {
		if row.FamilyID != familyID || row.RevokedAt != nil {
			continue
		}
		if !row.ExpiresAt.After(at) {
			continue
		}
		stamp := at
		row.RevokedAt = &stamp
		n++
	}
	return n, nil
}

func (r *refreshHandlerRepo) DeleteExpiredBefore(_ context.Context, _ time.Time) (int64, error) {
	return 0, nil
}

func newTokenEngineWithRefresh(t *testing.T, stub interface {
	Authenticate(context.Context, string, string, string) (*service.AuthenticatedClient, error)
}) (*gin.Engine, *service.RefreshTokenService) {
	t.Helper()
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	keys := &keyProvider{keys: []domain.SigningKey{genEdDSA(t, "k")}}
	refreshSvc := service.NewRefreshTokenService(nil, newRefreshHandlerRepo(), service.RefreshTokenServiceOptions{TTL: time.Hour})
	tokenSvc := service.NewTokenService(nil, keys, service.TokenServiceOptions{Issuer: "https://idp.test"}).
		WithRefreshTokenService(refreshSvc)
	RegisterTokenRoutes(r, TokenHandlerDeps{
		TokenService: tokenSvc,
		ClientAuth:   stub,
		Audit:        &audit.Recorder{},
	})
	return r, refreshSvc
}

func TestToken_RefreshGrantSuccessShapeIncludesRefreshToken(t *testing.T) {
	r, svc := newTokenEngineWithRefresh(t, tokenStubAllow{kind: service.AuthenticatedClientKindOAuth})
	// Seed a refresh token bound to client_id = "stub-client" (the
	// stub Authenticate uses whichever id the form supplies).
	issued, err := svc.Issue(context.Background(), service.IssueRefreshTokenInput{
		ClientID: "stub-client", Subject: "stub-client", Scope: "read",
	})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	body := strings.NewReader("grant_type=refresh_token&refresh_token=" + issued.Token + "&client_id=stub-client&client_secret=S")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/oauth/token", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%q", w.Code, w.Body.String())
	}
	var resp map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["access_token"] == "" {
		t.Errorf("access_token missing")
	}
	if resp["refresh_token"] == nil || resp["refresh_token"] == "" {
		t.Errorf("refresh_token missing from refresh-grant response")
	}
	if resp["refresh_token"] == issued.Token {
		t.Errorf("refresh_token not rotated")
	}
	if !strings.Contains(w.Header().Get("Cache-Control"), "no-store") {
		t.Errorf("Cache-Control no-store missing")
	}
}

// RULE: TOKEN-SPLIT-1
func TestToken_RefreshGrantUnknownIsInvalidGrant(t *testing.T) {
	r, _ := newTokenEngineWithRefresh(t, tokenStubAllow{kind: service.AuthenticatedClientKindOAuth})
	body := strings.NewReader("grant_type=refresh_token&refresh_token=" + uuid.NewString() + ".AAAA&client_id=cli&client_secret=S")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/oauth/token", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
	if !strings.Contains(w.Body.String(), `"error":"invalid_grant"`) {
		t.Errorf("body = %q", w.Body.String())
	}
}

func TestToken_RefreshGrantDisabledIsUnsupportedGrant(t *testing.T) {
	// TokenService WITHOUT WithRefreshTokenService.
	r := newTokenEngine(t,
		&keyProvider{keys: []domain.SigningKey{genEdDSA(t, "k")}},
		nil,
		tokenStubAllow{kind: service.AuthenticatedClientKindOAuth},
		&audit.Recorder{},
	)
	body := strings.NewReader("grant_type=refresh_token&refresh_token=ANY&client_id=cli&client_secret=S")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/oauth/token", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
	if !strings.Contains(w.Body.String(), `"error":"unsupported_grant_type"`) {
		t.Errorf("body = %q", w.Body.String())
	}
}

func TestToken_ClientCredentialsResponseHasNoRefreshToken(t *testing.T) {
	r, _ := newTokenEngineWithRefresh(t, tokenStubAllow{kind: service.AuthenticatedClientKindOAuth})
	body := strings.NewReader("grant_type=client_credentials&client_id=cli&client_secret=S")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/oauth/token", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	var resp map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if _, ok := resp["refresh_token"]; ok {
		t.Errorf("client_credentials response leaked refresh_token: %+v", resp)
	}
}

// ---------- RS256 ban end-to-end ----------

func TestToken_RS256OnlyKeyReturnsServerError(t *testing.T) {
	r := newTokenEngine(t, &keyProvider{keys: []domain.SigningKey{genRS256(t, "kid-rs")}}, nil, tokenStubAllow{kind: service.AuthenticatedClientKindOAuth}, &audit.Recorder{})
	body := strings.NewReader("grant_type=client_credentials&client_id=cli-1&client_secret=S")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/oauth/token", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500 (RS256 issuance banned)", w.Code)
	}
}

// ---------- Roundtrip: issued token verifies AND introspects active:true ----------

func TestToken_RoundTripIntrospectsActiveTrue(t *testing.T) {
	ed := genEdDSA(t, "kid-eddsa")
	r := newTokenEngine(t, &keyProvider{keys: []domain.SigningKey{ed}}, nil, tokenStubAllow{kind: service.AuthenticatedClientKindOAuth}, &audit.Recorder{})
	body := strings.NewReader("grant_type=client_credentials&client_id=cli-1&client_secret=S")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/oauth/token", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("issue status = %d, body=%q", w.Code, w.Body.String())
	}
	var resp map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	access := resp["access_token"].(string)

	// Build a verifier-compatible introspector inline: parse claims
	// using the issued key. IntrospectionService.Introspect treats
	// any error as active:false, so a successful parse here means
	// the wire path is correct.
	pubBlock, _ := pem.Decode([]byte(ed.PublicKey))
	pub, err := x509.ParsePKIXPublicKey(pubBlock.Bytes)
	if err != nil {
		t.Fatalf("public parse: %v", err)
	}
	parser := jwt.NewParser(jwt.WithValidMethods([]string{"EdDSA"}))
	tok, err := parser.Parse(access, func(_ *jwt.Token) (any, error) { return pub, nil })
	if err != nil || !tok.Valid {
		t.Fatalf("verify roundtrip failed: %v valid=%v", err, tok != nil && tok.Valid)
	}
}

// ---------- authorization_code grant ----------

type fakeUserLookup struct {
	user *domain.User
}

func (f *fakeUserLookup) GetByID(_ context.Context, _ uuid.UUID) (*domain.User, error) {
	return f.user, nil
}

type fakeSessionLookup struct {
	session *domain.Session
}

func (f *fakeSessionLookup) GetByID(_ context.Context, _ uuid.UUID) (*domain.Session, error) {
	return f.session, nil
}

type fakeOrgLookup struct {
	org *domain.Organization
	err error
}

func (f *fakeOrgLookup) GetByID(_ context.Context, _ uuid.UUID) (*domain.Organization, error) {
	return f.org, f.err
}

// newAuthCodeEngine builds a /token route wired with the full
// authorization_code grant stack: AuthCodeService backed by an
// in-memory repo, UserTokenService + IDTokenService bound to the
// same EdDSA key, fake user + session lookups.
func newAuthCodeEngine(t *testing.T, withIDToken bool) (*gin.Engine, *service.AuthorizationCodeService, *domain.User, *domain.Session) {
	r, codes, _, user, session := newAuthCodeEngineWithSessionSvc(t, withIDToken, false)
	return r, codes, user, session
}

// newAuthCodeEngineWithSessionSvc is the wider variant used by the
// offline_access tests. When withUserSession=true, the token deps
// thread a real UserSessionService backed by an in-memory repo so
// the grant can mint a refresh_token.
func newAuthCodeEngineWithSessionSvc(t *testing.T, withIDToken, withUserSession bool) (*gin.Engine, *service.AuthorizationCodeService, *service.UserSessionService, *domain.User, *domain.Session) {
	t.Helper()
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	ed := genEdDSA(t, "kid-eddsa")
	keys := &keyProvider{keys: []domain.SigningKey{ed}}

	codes := service.NewAuthorizationCodeService(nil, newAuthCodeRepoForHandlers(), service.AuthorizationCodeServiceOptions{TTL: time.Hour})
	tokenSvc := service.NewTokenService(nil, keys, service.TokenServiceOptions{Issuer: "https://idp.test"})
	userTokens := service.NewUserTokenService(nil, keys, service.UserTokenServiceOptions{Issuer: "https://idp.test", AccessTokenTTL: time.Hour})

	user := &domain.User{
		ID:             uuid.New(),
		OrganizationID: uuid.New(),
		Email:          "alice@example.com",
		EmailVerified:  true,
		Role:           domain.RoleOrgUser,
	}
	session := &domain.Session{
		ID:        uuid.New(),
		UserID:    user.ID,
		CreatedAt: time.Now().Add(-time.Minute),
		ExpiresAt: time.Now().Add(time.Hour),
		IsValid:   true,
		Acr:       "0",
		Amr:       []string{"pwd"},
	}

	deps := TokenHandlerDeps{
		TokenService:    tokenSvc,
		ClientAuth:      tokenStubAllow{kind: service.AuthenticatedClientKindOAuth},
		Audit:           &audit.Recorder{},
		AuthCodeService: codes,
		UserToken:       userTokens,
		UserLookup:      &fakeUserLookup{user: user},
		SessionLookup:   &fakeSessionLookup{session: session},
		OrgLookup:       &fakeOrgLookup{org: &domain.Organization{ID: user.OrganizationID, Active: true}},
	}
	if withIDToken {
		deps.IDToken = service.NewIDTokenService(nil, keys, service.IDTokenServiceOptions{Issuer: "https://idp.test", TTL: time.Hour})
	}
	var userSession *service.UserSessionService
	if withUserSession {
		userSession = service.NewUserSessionService(nil, newHandlersSessionRepo(), service.UserSessionServiceOptions{})
		deps.UserSession = userSession
	}
	RegisterTokenRoutes(r, deps)
	return r, codes, userSession, user, session
}

// newAuthCodeRepoForHandlers is the handlers-package twin of the
// in-memory AuthCode repo used in service-package tests.
type handlerAuthCodeRepo struct {
	byID   map[uuid.UUID]*domain.OAuthAuthorizationCode
	byHash map[string]*domain.OAuthAuthorizationCode
}

func newAuthCodeRepoForHandlers() *handlerAuthCodeRepo {
	return &handlerAuthCodeRepo{
		byID:   map[uuid.UUID]*domain.OAuthAuthorizationCode{},
		byHash: map[string]*domain.OAuthAuthorizationCode{},
	}
}

func (r *handlerAuthCodeRepo) Insert(_ context.Context, c *domain.OAuthAuthorizationCode) error {
	cp := *c
	r.byID[c.ID] = &cp
	r.byHash[c.CodeHash] = &cp
	return nil
}

func (r *handlerAuthCodeRepo) GetActiveByCodeHash(_ context.Context, hash string, now time.Time) (*domain.OAuthAuthorizationCode, error) {
	row, ok := r.byHash[hash]
	if !ok {
		return nil, nil
	}
	if row.ConsumedAt != nil {
		return nil, nil
	}
	if !row.ExpiresAt.After(now) {
		return nil, nil
	}
	cp := *row
	return &cp, nil
}

// GetByCodeHashAnyState looks the code up with NO state predicate — neither
// consumed_at nor expires_at is considered. That is the whole point: reuse
// detection (P0-1b, RFC 6819 5.2.1.1) has to be able to see a code that
// GetActiveByCodeHash has already stopped returning, otherwise a replayed code
// is indistinguishable from one that never existed.
func (r *handlerAuthCodeRepo) GetByCodeHashAnyState(_ context.Context, hash string) (*domain.OAuthAuthorizationCode, error) {
	row, ok := r.byHash[hash]
	if !ok {
		return nil, nil
	}
	cp := *row
	return &cp, nil
}

func (r *handlerAuthCodeRepo) MarkConsumed(_ context.Context, id uuid.UUID, at time.Time) (bool, error) {
	row, ok := r.byID[id]
	if !ok {
		return false, nil
	}
	if row.ConsumedAt != nil {
		return false, nil
	}
	row.ConsumedAt = &at
	return true, nil
}

func (r *handlerAuthCodeRepo) DeleteExpiredBefore(_ context.Context, _ time.Time) (int64, error) {
	return 0, nil
}

func (r *handlerAuthCodeRepo) RecordIssuedTokens(_ context.Context, id uuid.UUID, accessJTI string, accessExpiresAt time.Time, refreshTokenID *uuid.UUID) error {
	row, ok := r.byID[id]
	if !ok {
		return errors.New("no such code")
	}
	row.IssuedAccessJTI = accessJTI
	exp := accessExpiresAt
	row.IssuedAccessExpiresAt = &exp
	row.IssuedRefreshTokenID = refreshTokenID
	return nil
}

// newHandlersSessionRepo is a minimal SessionRepository for the
// handlers package — used by the offline_access auth-code grant
// tests so UserSessionService can mint a refresh token.
func newHandlersSessionRepo() *handlersSessionRepo {
	return &handlersSessionRepo{
		byID:       map[uuid.UUID]*domain.Session{},
		bySelector: map[uuid.UUID]*domain.Session{},
	}
}

type handlersSessionRepo struct {
	byID       map[uuid.UUID]*domain.Session
	bySelector map[uuid.UUID]*domain.Session
}

func (r *handlersSessionRepo) Create(_ context.Context, s *domain.Session) (*domain.Session, error) {
	if s.ID == uuid.Nil {
		s.ID = uuid.New()
	}
	cp := *s
	r.byID[s.ID] = &cp
	if s.TokenSelector != nil {
		r.bySelector[*s.TokenSelector] = &cp
	}
	return &cp, nil
}
func (r *handlersSessionRepo) GetByID(_ context.Context, id uuid.UUID) (*domain.Session, error) {
	s, ok := r.byID[id]
	if !ok {
		return nil, nil
	}
	cp := *s
	return &cp, nil
}
func (r *handlersSessionRepo) GetByTokenSelector(_ context.Context, sel uuid.UUID) (*domain.Session, error) {
	s, ok := r.bySelector[sel]
	if !ok {
		return nil, nil
	}
	cp := *s
	return &cp, nil
}
func (r *handlersSessionRepo) Update(_ context.Context, s *domain.Session, _ uuid.UUID) error {
	old, ok := r.byID[s.ID]
	if !ok {
		return errors.New("not found")
	}
	if old.TokenSelector != nil {
		delete(r.bySelector, *old.TokenSelector)
	}
	cp := *s
	r.byID[s.ID] = &cp
	if s.TokenSelector != nil {
		r.bySelector[*s.TokenSelector] = &cp
	}
	return nil
}

func (r *handlersSessionRepo) RotateToken(_ context.Context, sessionID uuid.UUID, expectedValidatorHash, newValidatorHash string, newExpiresAt, lastUsedAt time.Time) (*domain.Session, bool, error) {
	s, ok := r.byID[sessionID]
	if !ok || s.TokenValidatorHash == nil || *s.TokenValidatorHash != expectedValidatorHash || !s.IsValid || s.RevokedAt != nil {
		return nil, false, nil
	}
	s.TokenValidatorHash = &newValidatorHash
	s.ExpiresAt = newExpiresAt
	s.LastUsedAt = &lastUsedAt
	cp := *s
	return &cp, true, nil
}
func (r *handlersSessionRepo) RecordACRUplift(context.Context, uuid.UUID, time.Time, string) error {
	panic("not used")
}
func (r *handlersSessionRepo) Revoke(_ context.Context, sessionID, _ uuid.UUID, reason string) error {
	if s, ok := r.byID[sessionID]; ok {
		t := time.Now()
		s.IsValid = false
		s.RevokedAt = &t
		s.RevokedReason = &reason
	}
	return nil
}
func (r *handlersSessionRepo) RevokeByUserID(_ context.Context, _ uuid.UUID, _ string) error {
	return nil
}
func (r *handlersSessionRepo) DeleteExpiredReturning(context.Context, time.Duration, int) ([]*domain.Session, error) {
	return nil, nil
}
func (r *handlersSessionRepo) CountActiveByUserID(context.Context, uuid.UUID) (int, error) {
	return 0, nil
}
func (r *handlersSessionRepo) ListByUserID(context.Context, uuid.UUID, bool) ([]*domain.Session, error) {
	return nil, nil
}
func (r *handlersSessionRepo) ListActiveByUserID(context.Context, uuid.UUID) ([]*domain.Session, error) {
	return nil, nil
}
func (r *handlersSessionRepo) RevokeByOrganizationID(context.Context, uuid.UUID, string) error {
	return nil
}
func (r *handlersSessionRepo) Delete(context.Context, uuid.UUID, uuid.UUID) error {
	return nil
}
func (r *handlersSessionRepo) GetSessionWithUserAndOrgStatus(context.Context, uuid.UUID) (*domain.SessionValidationInfo, error) {
	return nil, nil
}
func (r *handlersSessionRepo) GetStats(context.Context) (map[string]int, error) {
	return nil, nil
}

// authCodePKCEPair returns a PKCE verifier + matching S256 challenge.
func authCodePKCEPair(t *testing.T) (string, string) {
	t.Helper()
	const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	sum := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(sum[:])
}

// exchangeAuthCodeWithReval builds a self-contained authorization_code
// /token engine, lets the caller mutate the (user, session, org) triple
// the grant will revalidate at exchange time (P0-2), then performs one
// exchange with a valid PKCE verifier and returns the recorder. The
// mutate callback receives the exact pointers wired into the lookups, so
// flipping session.RevokedAt / user.Banned / org.Active is observed by
// handleAuthorizationCodeGrant. A nil mutate leaves a fully live
// principal + tenant (happy path).
func exchangeAuthCodeWithReval(t *testing.T, mutate func(u *domain.User, s *domain.Session, o *domain.Organization)) *httptest.ResponseRecorder {
	t.Helper()
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	ed := genEdDSA(t, "kid-eddsa")
	keys := &keyProvider{keys: []domain.SigningKey{ed}}
	codes := service.NewAuthorizationCodeService(nil, newAuthCodeRepoForHandlers(), service.AuthorizationCodeServiceOptions{TTL: time.Hour})
	tokenSvc := service.NewTokenService(nil, keys, service.TokenServiceOptions{Issuer: "https://idp.test"})
	userTokens := service.NewUserTokenService(nil, keys, service.UserTokenServiceOptions{Issuer: "https://idp.test", AccessTokenTTL: time.Hour})

	user := &domain.User{
		ID:             uuid.New(),
		OrganizationID: uuid.New(),
		Email:          "alice@example.com",
		EmailVerified:  true,
		Role:           domain.RoleOrgUser,
	}
	session := &domain.Session{
		ID:        uuid.New(),
		UserID:    user.ID,
		CreatedAt: time.Now().Add(-time.Minute),
		ExpiresAt: time.Now().Add(time.Hour),
		IsValid:   true,
		Acr:       "0",
		Amr:       []string{"pwd"},
	}
	org := &domain.Organization{ID: user.OrganizationID, Name: "Acme", Active: true}
	if mutate != nil {
		mutate(user, session, org)
	}

	deps := TokenHandlerDeps{
		TokenService:    tokenSvc,
		ClientAuth:      tokenStubAllow{kind: service.AuthenticatedClientKindOAuth},
		Audit:           &audit.Recorder{},
		AuthCodeService: codes,
		UserToken:       userTokens,
		UserLookup:      &fakeUserLookup{user: user},
		SessionLookup:   &fakeSessionLookup{session: session},
		OrgLookup:       &fakeOrgLookup{org: org},
	}
	RegisterTokenRoutes(r, deps)

	verifier, challenge := authCodePKCEPair(t)
	created, err := codes.Create(context.Background(), service.CreateAuthorizationCodeInput{
		ClientID:            "cli-1",
		UserID:              user.ID,
		SessionID:           session.ID,
		RedirectURI:         "https://app.example.com/cb",
		Scope:               "profile",
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
	})
	if err != nil {
		t.Fatalf("create code: %v", err)
	}
	body := strings.NewReader("grant_type=authorization_code&code=" + created.Code +
		"&client_id=cli-1&client_secret=S&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb" +
		"&code_verifier=" + verifier)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/oauth/token", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func assertAuthCodeInvalidGrant(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body = %q", w.Code, w.Body.String())
	}
	var resp map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["error"] != "invalid_grant" {
		t.Fatalf("error = %v, want invalid_grant; body = %q", resp["error"], w.Body.String())
	}
}

// P0-2 regression: an outstanding, otherwise-valid code (correct client,
// redirect_uri, PKCE verifier) MUST be refused at exchange when the
// linked session was revoked in the interval before exchange.
func TestToken_AuthCodeGrant_RevokedSessionRejected(t *testing.T) {
	w := exchangeAuthCodeWithReval(t, func(_ *domain.User, s *domain.Session, _ *domain.Organization) {
		revokedAt := time.Now()
		reason := "revoked_by_admin"
		s.IsValid = false
		s.RevokedAt = &revokedAt
		s.RevokedReason = &reason
	})
	assertAuthCodeInvalidGrant(t, w)
}

// P0-2 regression: expired session → invalid_grant.
func TestToken_AuthCodeGrant_ExpiredSessionRejected(t *testing.T) {
	w := exchangeAuthCodeWithReval(t, func(_ *domain.User, s *domain.Session, _ *domain.Organization) {
		s.ExpiresAt = time.Now().Add(-time.Minute)
	})
	assertAuthCodeInvalidGrant(t, w)
}

// P0-2 regression: soft-deleted user → invalid_grant.
func TestToken_AuthCodeGrant_DeletedUserRejected(t *testing.T) {
	w := exchangeAuthCodeWithReval(t, func(u *domain.User, _ *domain.Session, _ *domain.Organization) {
		deletedAt := time.Now()
		u.DeletedAt = &deletedAt
	})
	assertAuthCodeInvalidGrant(t, w)
}

// P0-2 regression: banned user → invalid_grant.
func TestToken_AuthCodeGrant_BannedUserRejected(t *testing.T) {
	w := exchangeAuthCodeWithReval(t, func(u *domain.User, _ *domain.Session, _ *domain.Organization) {
		u.Banned = true
	})
	assertAuthCodeInvalidGrant(t, w)
}

// P0-2 regression: suspended tenant (Active=false) → invalid_grant.
func TestToken_AuthCodeGrant_SuspendedOrgRejected(t *testing.T) {
	w := exchangeAuthCodeWithReval(t, func(_ *domain.User, _ *domain.Session, o *domain.Organization) {
		o.Active = false
	})
	assertAuthCodeInvalidGrant(t, w)
}

// P0-2 regression: soft-deleted tenant (DeletedAt set) → invalid_grant.
func TestToken_AuthCodeGrant_DeletedOrgRejected(t *testing.T) {
	w := exchangeAuthCodeWithReval(t, func(_ *domain.User, _ *domain.Session, o *domain.Organization) {
		deletedAt := time.Now()
		o.DeletedAt = &deletedAt
	})
	assertAuthCodeInvalidGrant(t, w)
}

// Sanity: an unmutated (live session + live user + operational org)
// exchange still succeeds through the SAME helper — proving the
// rejections above are caused by the mutation, not the harness.
func TestToken_AuthCodeGrant_RevalHappyPathSucceeds(t *testing.T) {
	w := exchangeAuthCodeWithReval(t, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("live principal + tenant must succeed: status=%d body=%q", w.Code, w.Body.String())
	}
}

func TestToken_AuthorizationCodeGrant_ReturnsAccessToken(t *testing.T) {
	r, codes, _, session := newAuthCodeEngine(t, false)
	verifier, challenge := authCodePKCEPair(t)
	created, err := codes.Create(context.Background(), service.CreateAuthorizationCodeInput{
		ClientID:            "cli-1",
		UserID:              session.UserID,
		SessionID:           session.ID,
		RedirectURI:         "https://app.example.com/cb",
		Scope:               "profile",
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
	})
	if err != nil {
		t.Fatalf("create code: %v", err)
	}
	body := strings.NewReader("grant_type=authorization_code&code=" + created.Code +
		"&client_id=cli-1&client_secret=S&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb" +
		"&code_verifier=" + verifier)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/oauth/token", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %q", w.Code, w.Body.String())
	}
	var resp map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if _, ok := resp["access_token"].(string); !ok {
		t.Errorf("access_token missing")
	}
	if _, ok := resp["id_token"]; ok {
		t.Errorf("id_token must be absent (no openid scope): %v", resp["id_token"])
	}
}

func TestToken_AuthorizationCodeGrant_OpenIDScopeIssuesIDToken(t *testing.T) {
	r, codes, user, session := newAuthCodeEngine(t, true)
	verifier, challenge := authCodePKCEPair(t)
	created, err := codes.Create(context.Background(), service.CreateAuthorizationCodeInput{
		ClientID:            "cli-1",
		UserID:              session.UserID,
		SessionID:           session.ID,
		RedirectURI:         "https://app.example.com/cb",
		Scope:               "openid email",
		Nonce:               "test-nonce",
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
	})
	if err != nil {
		t.Fatalf("create code: %v", err)
	}
	body := strings.NewReader("grant_type=authorization_code&code=" + created.Code +
		"&client_id=cli-1&client_secret=S&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb" +
		"&code_verifier=" + verifier)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/oauth/token", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %q", w.Code, w.Body.String())
	}
	var resp map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	idTok, ok := resp["id_token"].(string)
	if !ok || idTok == "" {
		t.Fatalf("id_token missing")
	}
	tok, _, _ := jwt.NewParser(jwt.WithValidMethods([]string{"EdDSA"})).ParseUnverified(idTok, jwt.MapClaims{})
	claims := tok.Claims.(jwt.MapClaims)
	if claims["nonce"] != "test-nonce" {
		t.Errorf("nonce = %v", claims["nonce"])
	}
	if claims["aud"] != "cli-1" {
		t.Errorf("aud = %v", claims["aud"])
	}
	if claims["sub"] != user.ID.String() {
		t.Errorf("sub = %v", claims["sub"])
	}
	// THE-CONSENTED-SCOPE: scope=email releases email at userinfo, not in
	// the id_token (OIDC Core §5.4).
	if v, present := claims["email"]; present {
		t.Errorf("email = %v, want absent from the id_token", v)
	}
	if tok.Header["alg"] != "EdDSA" {
		t.Errorf("id_token alg = %v (must be EdDSA, never RS256)", tok.Header["alg"])
	}
}

// THE-CONSENTED-SCOPE through the wire: the exchanged access token's `scope`
// claim and the token response's `scope` are the consented scope ∩ what the
// user's role permits; the token names the client it was issued to.
func TestToken_AuthorizationCodeGrant_ScopeIsConsentedIntersectRole(t *testing.T) {
	r, codes, user, session := newAuthCodeEngine(t, true)
	verifier, challenge := authCodePKCEPair(t)
	const consented = "openid email clients:read no:such"
	created, err := codes.Create(context.Background(), service.CreateAuthorizationCodeInput{
		ClientID:            "cli-1",
		UserID:              session.UserID,
		SessionID:           session.ID,
		RedirectURI:         "https://app.example.com/cb",
		Scope:               consented,
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
	})
	if err != nil {
		t.Fatalf("create code: %v", err)
	}
	body := strings.NewReader("grant_type=authorization_code&code=" + created.Code +
		"&client_id=cli-1&client_secret=S&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb" +
		"&code_verifier=" + verifier)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/oauth/token", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %q", w.Code, w.Body.String())
	}
	var resp map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	want := domain.IntersectConsentedScope(consented, user.Role)
	if resp["scope"] != want {
		t.Errorf("token response scope = %v, want %q (consented ∩ role-permitted)", resp["scope"], want)
	}
	if user.Role != domain.RoleOrgAdmin && strings.Contains(want, "clients:read") {
		t.Fatalf("fixture role %q must not permit clients:read", user.Role)
	}
	if strings.Contains(want, "no:such") {
		t.Errorf("unknown consented scope survived the intersection: %q", want)
	}
	tok, _, _ := jwt.NewParser(jwt.WithValidMethods([]string{"EdDSA"})).ParseUnverified(resp["access_token"].(string), jwt.MapClaims{})
	claims := tok.Claims.(jwt.MapClaims)
	if claims["scope"] != want {
		t.Errorf("access token scope claim = %v, want %q", claims["scope"], want)
	}
	if claims["client_id"] != "cli-1" {
		t.Errorf("access token client_id = %v, want cli-1", claims["client_id"])
	}
}

func TestToken_AuthorizationCodeGrant_WrongVerifierInvalidGrant(t *testing.T) {
	r, codes, _, session := newAuthCodeEngine(t, false)
	_, challenge := authCodePKCEPair(t)
	created, _ := codes.Create(context.Background(), service.CreateAuthorizationCodeInput{
		ClientID:            "cli-1",
		UserID:              session.UserID,
		SessionID:           session.ID,
		RedirectURI:         "https://app.example.com/cb",
		Scope:               "profile",
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
	})
	body := strings.NewReader("grant_type=authorization_code&code=" + created.Code +
		"&client_id=cli-1&client_secret=S&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb" +
		"&code_verifier=wrong")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/oauth/token", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, body = %q", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"error":"invalid_grant"`) {
		t.Errorf("body = %q", w.Body.String())
	}
}

func TestToken_AuthorizationCodeGrant_ReusedCodeInvalidGrant(t *testing.T) {
	r, codes, _, session := newAuthCodeEngine(t, false)
	verifier, challenge := authCodePKCEPair(t)
	created, _ := codes.Create(context.Background(), service.CreateAuthorizationCodeInput{
		ClientID:            "cli-1",
		UserID:              session.UserID,
		SessionID:           session.ID,
		RedirectURI:         "https://app.example.com/cb",
		Scope:               "profile",
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
	})
	formBody := func() *strings.Reader {
		return strings.NewReader("grant_type=authorization_code&code=" + created.Code +
			"&client_id=cli-1&client_secret=S&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb" +
			"&code_verifier=" + verifier)
	}
	first := httptest.NewRequest(http.MethodPost, "/api/v1/oauth/token", formBody())
	first.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w1 := httptest.NewRecorder()
	r.ServeHTTP(w1, first)
	if w1.Code != http.StatusOK {
		t.Fatalf("first consume status = %d", w1.Code)
	}
	second := httptest.NewRequest(http.MethodPost, "/api/v1/oauth/token", formBody())
	second.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, second)
	if w2.Code != http.StatusBadRequest {
		t.Errorf("second consume status = %d, want 400", w2.Code)
	}
	if !strings.Contains(w2.Body.String(), `"error":"invalid_grant"`) {
		t.Errorf("body = %q", w2.Body.String())
	}
}

// inMemoryRefreshRepo is a minimal in-memory RefreshTokenRepository for the
// offline_access → refresh_token grant round-trip pin.
type inMemoryRefreshRepo struct {
	rows map[uuid.UUID]*domain.RefreshToken
}

func newInMemoryRefreshRepo() *inMemoryRefreshRepo {
	return &inMemoryRefreshRepo{rows: map[uuid.UUID]*domain.RefreshToken{}}
}

func (r *inMemoryRefreshRepo) Insert(_ context.Context, row *domain.RefreshToken) error {
	cp := *row
	r.rows[row.ID] = &cp
	return nil
}

func (r *inMemoryRefreshRepo) GetByID(_ context.Context, id uuid.UUID) (*domain.RefreshToken, error) {
	row, ok := r.rows[id]
	if !ok {
		return nil, nil
	}
	cp := *row
	return &cp, nil
}

func (r *inMemoryRefreshRepo) MarkRevoked(_ context.Context, id uuid.UUID, at time.Time) error {
	if row, ok := r.rows[id]; ok {
		row.RevokedAt = &at
	}
	return nil
}

func (r *inMemoryRefreshRepo) MarkRotated(_ context.Context, oldID, newID uuid.UUID, at time.Time) error {
	if row, ok := r.rows[oldID]; ok {
		row.RevokedAt = &at
		id := newID
		row.ReplacedBy = &id
	}
	return nil
}

func (r *inMemoryRefreshRepo) SetAccessJTI(_ context.Context, id uuid.UUID, jti string, _ time.Time) error {
	if row, ok := r.rows[id]; ok {
		row.AccessJTI = jti
	}
	return nil
}

func (r *inMemoryRefreshRepo) RevokeAllBySubject(_ context.Context, subject string, at time.Time) (int64, error) {
	var n int64
	for _, row := range r.rows {
		if row.Subject == subject && row.RevokedAt == nil {
			row.RevokedAt = &at
			n++
		}
	}
	return n, nil
}

func (r *inMemoryRefreshRepo) RevokeByFamily(_ context.Context, familyID string, at time.Time) (int64, error) {
	var n int64
	for _, row := range r.rows {
		if row.FamilyID == familyID && row.RevokedAt == nil {
			row.RevokedAt = &at
			n++
		}
	}
	return n, nil
}

func (r *inMemoryRefreshRepo) DeleteExpiredBefore(_ context.Context, cutoff time.Time) (int64, error) {
	var n int64
	for id, row := range r.rows {
		if row.ExpiresAt.Before(cutoff) {
			delete(r.rows, id)
			n++
		}
	}
	return n, nil
}

// THE-PKCE-DECISION (conformance-measured defect, oidcc-refresh-token): the
// refresh_token an offline_access exchange hands out MUST be redeemable at
// this endpoint's own refresh_token grant. The session-based token was
// redeemable only at /api/v1/auth/session/refresh, so the advertised grant
// always answered invalid_grant. Pin the full round trip.
// RULE: TOKEN-REFRESH-REDEEMABLE-1
func TestToken_OfflineAccessRefreshTokenRedeemsAtRefreshGrant(t *testing.T) {
	r, codes, _, _, session := newAuthCodeEngineWithRefreshSvc(t)
	verifier, challenge := authCodePKCEPair(t)
	created, _ := codes.Create(context.Background(), service.CreateAuthorizationCodeInput{
		ClientID:            "cli-1",
		UserID:              session.UserID,
		SessionID:           session.ID,
		RedirectURI:         "https://app.example.com/cb",
		Scope:               "openid offline_access",
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
	})
	body := strings.NewReader("grant_type=authorization_code&code=" + created.Code +
		"&client_id=cli-1&client_secret=S&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb" +
		"&code_verifier=" + verifier)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/oauth/token", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("exchange status = %d, body = %q", w.Code, w.Body.String())
	}
	var resp map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	refreshToken, ok := resp["refresh_token"].(string)
	if !ok || refreshToken == "" {
		t.Fatalf("refresh_token missing for offline_access: %+v", resp)
	}

	// The minted token redeems at grant_type=refresh_token on the SAME
	// endpoint — the grant we advertise in discovery.
	body2 := strings.NewReader("grant_type=refresh_token&refresh_token=" + refreshToken +
		"&client_id=cli-1&client_secret=S")
	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/oauth/token", body2)
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, req2)
	if w2.Code != http.StatusOK {
		t.Fatalf("refresh grant status = %d, want 200; body = %q", w2.Code, w2.Body.String())
	}
	var resp2 map[string]any
	_ = json.Unmarshal(w2.Body.Bytes(), &resp2)
	if at, _ := resp2["access_token"].(string); at == "" {
		t.Errorf("refresh grant returned no access_token: %+v", resp2)
	}
	if rt, _ := resp2["refresh_token"].(string); rt == "" || rt == refreshToken {
		t.Errorf("refresh grant must rotate the refresh token; got %q", rt)
	}
}

// newAuthCodeEngineWithRefreshSvc mirrors newAuthCodeEngineWithSessionSvc
// but wires a RefreshTokenService into BOTH seams: the deps (offline_access
// issuance) and the TokenService (the refresh_token grant that consumes it).
func newAuthCodeEngineWithRefreshSvc(t *testing.T) (*gin.Engine, *service.AuthorizationCodeService, *service.RefreshTokenService, *domain.User, *domain.Session) {
	t.Helper()
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	ed := genEdDSA(t, "kid-eddsa")
	keys := &keyProvider{keys: []domain.SigningKey{ed}}

	codes := service.NewAuthorizationCodeService(nil, newAuthCodeRepoForHandlers(), service.AuthorizationCodeServiceOptions{TTL: time.Hour})
	tokenSvc := service.NewTokenService(nil, keys, service.TokenServiceOptions{Issuer: "https://idp.test"})
	refresh := service.NewRefreshTokenService(nil, newInMemoryRefreshRepo(), service.RefreshTokenServiceOptions{})
	tokenSvc.WithRefreshTokenService(refresh)
	userTokens := service.NewUserTokenService(nil, keys, service.UserTokenServiceOptions{Issuer: "https://idp.test", AccessTokenTTL: time.Hour})

	user := &domain.User{
		ID:             uuid.New(),
		OrganizationID: uuid.New(),
		Email:          "alice@example.com",
		EmailVerified:  true,
		Role:           domain.RoleOrgUser,
	}
	session := &domain.Session{
		ID:        uuid.New(),
		UserID:    user.ID,
		CreatedAt: time.Now().Add(-time.Minute),
		ExpiresAt: time.Now().Add(time.Hour),
		IsValid:   true,
		Acr:       "0",
		Amr:       []string{"pwd"},
	}

	deps := TokenHandlerDeps{
		TokenService:    tokenSvc,
		ClientAuth:      tokenStubAllow{kind: service.AuthenticatedClientKindOAuth},
		Audit:           &audit.Recorder{},
		AuthCodeService: codes,
		UserToken:       userTokens,
		UserLookup:      &fakeUserLookup{user: user},
		SessionLookup:   &fakeSessionLookup{session: session},
		OrgLookup:       &fakeOrgLookup{org: &domain.Organization{ID: user.OrganizationID, Active: true}},
		RefreshTokens:   refresh,
	}
	RegisterTokenRoutes(r, deps)
	return r, codes, refresh, user, session
}

// recordingReuseRevoker captures the code rows the reuse seam hands over.
type recordingReuseRevoker struct {
	rows []*domain.OAuthAuthorizationCode
}

func (r *recordingReuseRevoker) RevokeForReusedCode(_ context.Context, code *domain.OAuthAuthorizationCode, _ time.Time) error {
	r.rows = append(r.rows, code)
	return nil
}

// THE-CODE-REUSE-REVOKER through the real handler: the exchange records the
// minted access token's jti + expiry and the OAuth refresh token's id on the
// code row, so a replay hands exactly those to the reuse revoker.
func TestToken_AuthorizationCodeGrant_RecordsIssuedTokensForReuseRevocation(t *testing.T) {
	r, codes, refresh, _, session := newAuthCodeEngineWithRefreshSvc(t)
	rec := &recordingReuseRevoker{}
	codes.WithReuseRevoker(rec)
	verifier, challenge := authCodePKCEPair(t)
	created, _ := codes.Create(context.Background(), service.CreateAuthorizationCodeInput{
		ClientID: "cli-1", UserID: session.UserID, SessionID: session.ID,
		RedirectURI: "https://app.example.com/cb", Scope: "openid offline_access",
		CodeChallenge: challenge, CodeChallengeMethod: "S256",
	})
	exchange := func() *httptest.ResponseRecorder {
		body := strings.NewReader("grant_type=authorization_code&code=" + created.Code +
			"&client_id=cli-1&client_secret=S&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb" +
			"&code_verifier=" + verifier)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/oauth/token", body)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w
	}
	first := exchange()
	if first.Code != http.StatusOK {
		t.Fatalf("first exchange status = %d, body = %q", first.Code, first.Body.String())
	}
	var resp map[string]any
	_ = json.Unmarshal(first.Body.Bytes(), &resp)
	tok, _, _ := jwt.NewParser(jwt.WithValidMethods([]string{"EdDSA"})).ParseUnverified(resp["access_token"].(string), jwt.MapClaims{})
	wantJTI, _ := tok.Claims.(jwt.MapClaims)["jti"].(string)
	if wantJTI == "" {
		t.Fatalf("access token carries no jti")
	}

	second := exchange()
	if second.Code != http.StatusBadRequest {
		t.Fatalf("replay status = %d, want 400 invalid_grant exactly as before", second.Code)
	}
	if len(rec.rows) != 1 {
		t.Fatalf("replay must hand the code row to the revoker once, got %d", len(rec.rows))
	}
	row := rec.rows[0]
	if row.IssuedAccessJTI != wantJTI {
		t.Errorf("recorded access jti = %q, want the minted token's jti %q", row.IssuedAccessJTI, wantJTI)
	}
	if row.IssuedAccessExpiresAt == nil || !row.IssuedAccessExpiresAt.After(time.Now()) {
		t.Errorf("recorded access expiry = %v, want the minted token's future expiry", row.IssuedAccessExpiresAt)
	}
	if row.IssuedRefreshTokenID == nil {
		t.Fatalf("offline_access exchange must record the refresh token id")
	}
	// The recorded refresh id is the row the refresh_token grant would rotate.
	if _, err := refresh.Consume(context.Background(), service.ConsumeRefreshTokenInput{RawToken: resp["refresh_token"].(string), ClientID: "cli-1"}); err != nil {
		t.Fatalf("control: the issued refresh token must still rotate (no revoker wired here): %v", err)
	}
}

func TestToken_AuthorizationCodeGrant_OfflineAccessIssuesRefreshToken(t *testing.T) {
	r, codes, _, _, session := newAuthCodeEngineWithSessionSvc(t, true, true)
	verifier, challenge := authCodePKCEPair(t)
	created, _ := codes.Create(context.Background(), service.CreateAuthorizationCodeInput{
		ClientID:            "cli-1",
		UserID:              session.UserID,
		SessionID:           session.ID,
		RedirectURI:         "https://app.example.com/cb",
		Scope:               "openid offline_access",
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
	})
	body := strings.NewReader("grant_type=authorization_code&code=" + created.Code +
		"&client_id=cli-1&client_secret=S&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb" +
		"&code_verifier=" + verifier)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/oauth/token", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %q", w.Code, w.Body.String())
	}
	var resp map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if _, ok := resp["refresh_token"].(string); !ok {
		t.Errorf("refresh_token missing for offline_access: %+v", resp)
	}
}

func TestToken_AuthorizationCodeGrant_NoOfflineAccessOmitsRefreshToken(t *testing.T) {
	r, codes, _, _, session := newAuthCodeEngineWithSessionSvc(t, true, true)
	verifier, challenge := authCodePKCEPair(t)
	created, _ := codes.Create(context.Background(), service.CreateAuthorizationCodeInput{
		ClientID:            "cli-1",
		UserID:              session.UserID,
		SessionID:           session.ID,
		RedirectURI:         "https://app.example.com/cb",
		Scope:               "openid email",
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
	})
	body := strings.NewReader("grant_type=authorization_code&code=" + created.Code +
		"&client_id=cli-1&client_secret=S&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb" +
		"&code_verifier=" + verifier)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/oauth/token", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %q", w.Code, w.Body.String())
	}
	var resp map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if _, ok := resp["refresh_token"]; ok {
		t.Errorf("refresh_token leaked without offline_access: %+v", resp)
	}
}
