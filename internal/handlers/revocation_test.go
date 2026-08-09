package handlers

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/mw"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// stubClientAuth always allows; used to mount the revocation
// route without exercising the full mw.RequireOAuthClient path.
type stubClientAuth struct{}

func (stubClientAuth) Authenticate(_ context.Context, id, _, _ string) (*service.AuthenticatedClient, error) {
	return &service.AuthenticatedClient{
		Kind: service.AuthenticatedClientKindOAuth, ClientID: id, AuthRecordID: uuid.New(),
	}, nil
}

type rejectAllClientAuth struct{}

func (rejectAllClientAuth) Authenticate(_ context.Context, _, _, _ string) (*service.AuthenticatedClient, error) {
	return nil, errors.New("denied")
}

func newRevocationEngine(t *testing.T, verifier service.TokenClaimsVerifier, revoker service.SessionRevoker, auth mw.OAuthClientAuthenticator) (*gin.Engine, *audit.Recorder) {
	t.Helper()
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	rec := &audit.Recorder{}
	RegisterRevocationRoutes(r, RevocationHandlerDeps{
		IntrospectionService: service.NewIntrospectionService(nil, verifier, nil),
		SessionRevoker:       revoker,
		ClientAuth:           auth,
		Audit:                rec,
	})
	return r, rec
}

// Reuse the same fake verifier shape from introspection tests.
type revFakeVerifier struct {
	claims *service.IntrospectionClaims
	err    error
}

func (f *revFakeVerifier) IntrospectToken(_ context.Context, _ string) (*service.IntrospectionClaims, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.claims, nil
}

// ---------- Route absence ----------

func TestRevocation_RouteAbsentWithoutIntrospectionService(t *testing.T) {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	RegisterRevocationRoutes(r, RevocationHandlerDeps{}) // nil
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/v1/oauth/revoke", nil))
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

// ---------- Client auth ----------

func TestRevocation_MissingClientAuth401(t *testing.T) {
	r, _ := newRevocationEngine(t, &revFakeVerifier{}, &service.RecorderSessionRevoker{}, rejectAllClientAuth{})
	body := strings.NewReader("token=anything")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/oauth/revoke", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
}

// ---------- Missing token ----------

func TestRevocation_MissingTokenReturns400(t *testing.T) {
	r, _ := newRevocationEngine(t, &revFakeVerifier{}, &service.RecorderSessionRevoker{}, stubClientAuth{})
	body := strings.NewReader("token=&client_id=cli-1&client_secret=S")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/oauth/revoke", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

// ---------- RFC 7009 §2.2: invalid token still returns 200 ----------

func TestRevocation_InvalidTokenReturns200NoOp(t *testing.T) {
	rev := &service.RecorderSessionRevoker{}
	r, rec := newRevocationEngine(t, &revFakeVerifier{err: errors.New("invalid")}, rev, stubClientAuth{})
	body := strings.NewReader("token=BAD-TOKEN-MUST-NOT-LEAK&client_id=cli-1&client_secret=S")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/oauth/revoke", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (RFC 7009 §2.2)", w.Code)
	}
	if len(rev.Calls()) != 0 {
		t.Errorf("revoker fired on invalid token: %+v", rev.Calls())
	}
	for _, e := range rec.Events() {
		if e.Action == "oauth_token.revoked" {
			t.Errorf("audit fired on invalid token: %+v", e)
		}
	}
	if strings.Contains(w.Body.String(), "BAD-TOKEN-MUST-NOT-LEAK") {
		t.Errorf("response leaked raw token: %q", w.Body.String())
	}
}

// ---------- Valid token → revoker fires ----------

func TestRevocation_ValidTokenFiresRevoker(t *testing.T) {
	uid := uuid.New()
	rev := &service.RecorderSessionRevoker{}
	r, rec := newRevocationEngine(t, &revFakeVerifier{claims: &service.IntrospectionClaims{
		Sub: uid.String(), UserID: uid, ClientID: "cli-1",
	}}, rev, stubClientAuth{})
	body := strings.NewReader("token=VALID-TOKEN-MUST-NOT-LEAK&client_id=cli-1&client_secret=S")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/oauth/revoke", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%q", w.Code, w.Body.String())
	}
	calls := rev.Calls()
	if len(calls) != 1 {
		t.Fatalf("revoker calls = %d, want 1", len(calls))
	}
	if calls[0].UserID != uid {
		t.Errorf("revoker uid = %s, want %s", calls[0].UserID, uid)
	}
	if calls[0].Reason != "oauth_token_revoked" {
		t.Errorf("reason = %q, want oauth_token_revoked", calls[0].Reason)
	}
	for k, v := range calls[0].Metadata {
		if k == "token" || k == "client_secret" || k == "scope" || k == "password" {
			t.Errorf("revoke metadata leaked banned key %q = %v", k, v)
		}
	}
	if strings.Contains(w.Body.String(), "VALID-TOKEN-MUST-NOT-LEAK") {
		t.Errorf("response leaked raw token: %q", w.Body.String())
	}
	var sawAudit bool
	for _, e := range rec.Events() {
		if e.Action == "oauth_token.revoked" {
			sawAudit = true
			if e.Metadata["client_id"] != "cli-1" {
				t.Errorf("audit client_id = %v", e.Metadata["client_id"])
			}
		}
	}
	if !sawAudit {
		t.Errorf("missing oauth_token.revoked audit")
	}
}

// ---------- Revoker error is swallowed ----------

func TestRevocation_RevokerErrorSwallowed(t *testing.T) {
	uid := uuid.New()
	rev := &service.RecorderSessionRevoker{Err: errors.New("revoker down")}
	// ClientID matches the authenticated client (cli-1) so the R4
	// client-binding gate admits the fan-out — this test exercises the
	// revoker-error-swallowing path, not the cross-client gate.
	r, _ := newRevocationEngine(t, &revFakeVerifier{claims: &service.IntrospectionClaims{
		Sub: uid.String(), UserID: uid, ClientID: "cli-1",
	}}, rev, stubClientAuth{})
	body := strings.NewReader("token=anything&client_id=cli-1&client_secret=S")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/oauth/revoke", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 (revoker error must not change response)", w.Code)
	}
	if len(rev.Calls()) != 1 {
		t.Errorf("revoker not invoked despite error policy; calls=%d", len(rev.Calls()))
	}
}

// ---------- Valid token with no UserID → no revoker call ----------

func TestRevocation_ValidTokenWithoutUserIDIsNoOp(t *testing.T) {
	rev := &service.RecorderSessionRevoker{}
	r, _ := newRevocationEngine(t, &revFakeVerifier{claims: &service.IntrospectionClaims{
		ClientID: "client-token", Sub: "client-token",
	}}, rev, stubClientAuth{})
	body := strings.NewReader("token=client-only&client_id=cli-1&client_secret=S")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/oauth/revoke", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	if len(rev.Calls()) != 0 {
		t.Errorf("revoker fired on client-only token: %+v", rev.Calls())
	}
}

// ---------- jti-based revocation ----------

// fakeRevocationRepo is reused from the service package shape but
// the handler tests own a copy because the service package one is
// unexported.
type handlerFakeRevocationRepo struct {
	inserts []domain.TokenRevocation
	exists  map[string]bool
}

func (f *handlerFakeRevocationRepo) Insert(_ context.Context, r *domain.TokenRevocation) error {
	if f.exists == nil {
		f.exists = map[string]bool{}
	}
	f.inserts = append(f.inserts, *r)
	f.exists[r.Jti] = true
	return nil
}

func (f *handlerFakeRevocationRepo) Exists(_ context.Context, jti string) (bool, error) {
	if f.exists == nil {
		return false, nil
	}
	return f.exists[jti], nil
}

func (f *handlerFakeRevocationRepo) DeleteExpiredBefore(_ context.Context, _ time.Time) (int64, error) {
	return 0, nil
}

func newRevocationEngineWithJTI(t *testing.T, verifier service.TokenClaimsVerifier, revoker service.SessionRevoker, auth mw.OAuthClientAuthenticator) (*gin.Engine, *handlerFakeRevocationRepo, *audit.Recorder) {
	t.Helper()
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	rec := &audit.Recorder{}
	repo := &handlerFakeRevocationRepo{}
	tokenRevSvc := service.NewTokenRevocationService(nil, repo)
	RegisterRevocationRoutes(r, RevocationHandlerDeps{
		IntrospectionService:   service.NewIntrospectionService(nil, verifier, nil),
		SessionRevoker:         revoker,
		TokenRevocationService: tokenRevSvc,
		ClientAuth:             auth,
		Audit:                  rec,
	})
	return r, repo, rec
}

func TestRevocation_ClientCredentialsTokenPersistsJTI(t *testing.T) {
	exp := time.Now().Add(time.Hour).Unix()
	verifier := &revFakeVerifier{claims: &service.IntrospectionClaims{
		Sub: "cli-1", ClientID: "cli-1", Jti: "jti-cc-1", Exp: exp,
	}}
	r, repo, rec := newRevocationEngineWithJTI(t, verifier, &service.RecorderSessionRevoker{}, stubClientAuth{})
	body := strings.NewReader("token=VALID-TOKEN-MUST-NOT-LEAK&client_id=cli-1&client_secret=S")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/oauth/revoke", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%q", w.Code, w.Body.String())
	}
	if len(repo.inserts) != 1 {
		t.Fatalf("repo inserts = %d, want 1", len(repo.inserts))
	}
	got := repo.inserts[0]
	if got.Jti != "jti-cc-1" {
		t.Errorf("jti = %q", got.Jti)
	}
	if got.ExpiresAt.Unix() != exp {
		t.Errorf("exp = %d, want %d", got.ExpiresAt.Unix(), exp)
	}
	// Raw token never leaks into audit metadata or response.
	for _, e := range rec.Events() {
		if e.Action != "oauth_token.revoked" {
			continue
		}
		for k, v := range e.Metadata {
			if k == "token" || k == "raw_token" {
				t.Errorf("audit metadata leaked %q = %v", k, v)
			}
			if s, ok := v.(string); ok && strings.Contains(s, "VALID-TOKEN-MUST-NOT-LEAK") {
				t.Errorf("audit metadata leaked raw token in %q", k)
			}
		}
	}
	if strings.Contains(w.Body.String(), "VALID-TOKEN-MUST-NOT-LEAK") {
		t.Errorf("response leaked raw token")
	}
}

// TestRevocation_AuditUsesTypedDomainConstant pins that the
// access-token branch emits its audit row via the typed
// domain.AuditOAuthTokenRevoked constant rather than a free-floating
// string literal. The wire value is checked to remain exactly
// "oauth_token.revoked" (the form external log consumers already
// filter on) — re-typing must not silently drift to a new shape.
func TestRevocation_AuditUsesTypedDomainConstant(t *testing.T) {
	// Defence in depth: the constant must literally equal the
	// historic string so the typed migration is backwards-
	// compatible with downstream log readers.
	if string(domain.AuditOAuthTokenRevoked) != "oauth_token.revoked" {
		t.Fatalf("AuditOAuthTokenRevoked = %q; want %q (must remain stable for external consumers)",
			string(domain.AuditOAuthTokenRevoked), "oauth_token.revoked")
	}
	uid := uuid.New()
	rev := &service.RecorderSessionRevoker{}
	r, rec := newRevocationEngine(t, &revFakeVerifier{claims: &service.IntrospectionClaims{
		Sub: uid.String(), UserID: uid, ClientID: "cli-typed", Jti: "JTI-TYPED",
	}}, rev, stubClientAuth{})
	body := strings.NewReader("token=ACCESS-TYPED-CANARY&client_id=cli-typed&client_secret=S")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/oauth/revoke", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	var matched int
	for _, e := range rec.Events() {
		if e.Action != string(domain.AuditOAuthTokenRevoked) {
			continue
		}
		matched++
		for k, v := range e.Metadata {
			if k == "token" || k == "raw_token" || k == "jti" || k == "validator_hash" {
				t.Errorf("audit metadata leaked banned key %q = %v", k, v)
			}
			if s, ok := v.(string); ok {
				if strings.Contains(s, "ACCESS-TYPED-CANARY") {
					t.Errorf("audit metadata leaked raw token in key %q: %q", k, s)
				}
				if strings.Contains(s, "JTI-TYPED") {
					t.Errorf("audit metadata leaked jti in key %q: %q", k, s)
				}
			}
		}
	}
	if matched == 0 {
		t.Errorf("no audit event with typed Action = %q emitted", domain.AuditOAuthTokenRevoked)
	}
	if strings.Contains(w.Body.String(), "ACCESS-TYPED-CANARY") {
		t.Errorf("response leaked raw token: %q", w.Body.String())
	}
}

// TestRevocation_RefreshAuditUsesTypedDomainConstant pins the same
// invariant for the refresh-token revocation branch: the audit row
// goes through string(domain.AuditOAuthTokenRevoked) and carries
// token_kind="refresh_token" without any token/jti/hash material.
func TestRevocation_RefreshAuditUsesTypedDomainConstant(t *testing.T) {
	repo := newInMemoryRefreshRepoHandlers()
	rec, rev := &audit.Recorder{}, &service.RecorderSessionRevoker{}
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	refreshSvc := service.NewRefreshTokenService(nil, repo, service.RefreshTokenServiceOptions{TTL: time.Hour})
	RegisterRevocationRoutes(r, RevocationHandlerDeps{
		IntrospectionService: service.NewIntrospectionService(nil, &revFakeVerifier{}, nil),
		SessionRevoker:       rev,
		RefreshTokenService:  refreshSvc,
		ClientAuth:           stubClientAuth{},
		Audit:                rec,
	})
	// Issue an active refresh row so RevokeByRawToken finds it.
	issued, err := refreshSvc.Issue(context.Background(), service.IssueRefreshTokenInput{
		ClientID: "cli-typed-refresh",
		Subject:  uuid.New().String(),
	})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	body := strings.NewReader("token=" + issued.Token + "&token_type_hint=refresh_token&client_id=cli-typed-refresh&client_secret=S")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/oauth/revoke", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%q", w.Code, w.Body.String())
	}
	var matched int
	for _, e := range rec.Events() {
		if e.Action != string(domain.AuditOAuthTokenRevoked) {
			continue
		}
		matched++
		if e.Metadata["token_kind"] != "refresh_token" {
			t.Errorf("token_kind = %v; want %q", e.Metadata["token_kind"], "refresh_token")
		}
		for k, v := range e.Metadata {
			if k == "token" || k == "raw_token" || k == "jti" || k == "validator_hash" {
				t.Errorf("audit metadata leaked banned key %q = %v", k, v)
			}
			if s, ok := v.(string); ok && strings.Contains(s, issued.Token) {
				t.Errorf("audit metadata leaked raw refresh token in key %q", k)
			}
		}
	}
	if matched == 0 {
		t.Errorf("no audit event with typed Action = %q emitted on refresh-revoke branch", domain.AuditOAuthTokenRevoked)
	}
	if strings.Contains(w.Body.String(), issued.Token) {
		t.Errorf("response leaked raw refresh token: %q", w.Body.String())
	}
}

func TestRevocation_NoJTIClaimDoesNotPersist(t *testing.T) {
	verifier := &revFakeVerifier{claims: &service.IntrospectionClaims{
		Sub: "cli-1", ClientID: "cli-1", Exp: time.Now().Add(time.Hour).Unix(),
	}}
	r, repo, _ := newRevocationEngineWithJTI(t, verifier, &service.RecorderSessionRevoker{}, stubClientAuth{})
	body := strings.NewReader("token=ANY&client_id=cli-1&client_secret=S")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/oauth/revoke", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	if len(repo.inserts) != 0 {
		t.Errorf("repo inserts = %d for no-jti claim", len(repo.inserts))
	}
}

// ---------- Refresh-token revocation ----------

// inMemoryRefreshTokenRepo is local to handlers_test for the
// revoke-handler integration tests.
type inMemoryRefreshTokenRepoHandlers struct {
	byID map[uuid.UUID]*domain.RefreshToken
}

func newInMemoryRefreshRepoHandlers() *inMemoryRefreshTokenRepoHandlers {
	return &inMemoryRefreshTokenRepoHandlers{byID: map[uuid.UUID]*domain.RefreshToken{}}
}

func (r *inMemoryRefreshTokenRepoHandlers) Insert(_ context.Context, rt *domain.RefreshToken) error {
	cp := *rt
	r.byID[rt.ID] = &cp
	return nil
}

func (r *inMemoryRefreshTokenRepoHandlers) GetByID(_ context.Context, id uuid.UUID) (*domain.RefreshToken, error) {
	row, ok := r.byID[id]
	if !ok {
		return nil, nil
	}
	cp := *row
	return &cp, nil
}

func (r *inMemoryRefreshTokenRepoHandlers) MarkRevoked(_ context.Context, id uuid.UUID, at time.Time) error {
	if row, ok := r.byID[id]; ok {
		row.RevokedAt = &at
	}
	return nil
}

func (r *inMemoryRefreshTokenRepoHandlers) MarkRotated(_ context.Context, _, _ uuid.UUID, _ time.Time) error {
	return nil
}

func (r *inMemoryRefreshTokenRepoHandlers) SetAccessJTI(_ context.Context, _ uuid.UUID, _ string, _ time.Time) error {
	return nil
}

func (r *inMemoryRefreshTokenRepoHandlers) RevokeAllBySubject(_ context.Context, _ string, _ time.Time) (int64, error) {
	return 0, nil
}

func (r *inMemoryRefreshTokenRepoHandlers) RevokeByFamily(_ context.Context, _ string, _ time.Time) (int64, error) {
	return 0, nil
}

func (r *inMemoryRefreshTokenRepoHandlers) DeleteExpiredBefore(_ context.Context, _ time.Time) (int64, error) {
	return 0, nil
}

func newRevocationEngineWithRefresh(t *testing.T, verifier service.TokenClaimsVerifier, refreshRepo *inMemoryRefreshTokenRepoHandlers) (*gin.Engine, *handlerFakeRevocationRepo, *audit.Recorder, *service.RefreshTokenService) {
	t.Helper()
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	rec := &audit.Recorder{}
	jtiRepo := &handlerFakeRevocationRepo{}
	tokenRevSvc := service.NewTokenRevocationService(nil, jtiRepo)
	refreshSvc := service.NewRefreshTokenService(nil, refreshRepo, service.RefreshTokenServiceOptions{TTL: time.Hour})
	RegisterRevocationRoutes(r, RevocationHandlerDeps{
		IntrospectionService:   service.NewIntrospectionService(nil, verifier, nil),
		SessionRevoker:         &service.RecorderSessionRevoker{},
		TokenRevocationService: tokenRevSvc,
		RefreshTokenService:    refreshSvc,
		ClientAuth:             stubClientAuth{},
		Audit:                  rec,
	})
	return r, jtiRepo, rec, refreshSvc
}

func TestRevocation_RefreshTokenRowIsRevoked(t *testing.T) {
	refreshRepo := newInMemoryRefreshRepoHandlers()
	r, _, _, svc := newRevocationEngineWithRefresh(t, &revFakeVerifier{}, refreshRepo)
	issued, err := svc.Issue(context.Background(), service.IssueRefreshTokenInput{
		ClientID: "cli-1", Subject: "cli-1", AccessJTI: "jti-cascade",
	})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	body := strings.NewReader("token=" + issued.Token + "&token_type_hint=refresh_token&client_id=cli-1&client_secret=S")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/oauth/revoke", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%q", w.Code, w.Body.String())
	}
	row := refreshRepo.byID[issued.ID]
	if row == nil || row.RevokedAt == nil {
		t.Errorf("refresh row not revoked: %+v", row)
	}
	if strings.Contains(w.Body.String(), issued.Token) {
		t.Errorf("response leaked raw refresh token")
	}
}

func TestRevocation_RefreshTokenCascadesAccessJTI(t *testing.T) {
	refreshRepo := newInMemoryRefreshRepoHandlers()
	r, jtiRepo, _, svc := newRevocationEngineWithRefresh(t, &revFakeVerifier{}, refreshRepo)
	issued, _ := svc.Issue(context.Background(), service.IssueRefreshTokenInput{
		ClientID: "cli-1", Subject: "cli-1", AccessJTI: "jti-AAA",
	})
	body := strings.NewReader("token=" + issued.Token + "&client_id=cli-1&client_secret=S")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/oauth/revoke", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	if len(jtiRepo.inserts) != 1 || jtiRepo.inserts[0].Jti != "jti-AAA" {
		t.Errorf("cascade did not persist jti revocation: %+v", jtiRepo.inserts)
	}
}

// (b) R4 — a non-owning authenticated client cannot revoke another client's
// refresh token. RFC 7009 §2.1: the row is recognized (validator matches) but
// deliberately NOT revoked; the response is a silent idempotent 200 and the
// token STAYS VALID. (Supersedes the pre-R4 contract where the row was revoked
// cross-client and only the JTI cascade was withheld.)
func TestRevocation_RefreshTokenCrossClientSilentNoOpTokenStaysValid(t *testing.T) {
	refreshRepo := newInMemoryRefreshRepoHandlers()
	r, jtiRepo, rec, svc := newRevocationEngineWithRefresh(t, &revFakeVerifier{}, refreshRepo)
	issued, _ := svc.Issue(context.Background(), service.IssueRefreshTokenInput{
		ClientID: "cli-OWNER", Subject: "cli-OWNER", AccessJTI: "jti-owner",
	})
	// stubClientAuth plants client_id from the form ⇒ authenticated as
	// "cli-INTRUDER", different from the row's owner "cli-OWNER".
	body := strings.NewReader("token=" + issued.Token + "&client_id=cli-INTRUDER&client_secret=S")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/oauth/revoke", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	t.Logf("EVIDENCE (b) cross-client refresh: status=%d jtiInserts=%d", w.Code, len(jtiRepo.inserts))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (silent no-op, no oracle)", w.Code)
	}
	// Row must NOT be revoked — the token stays valid.
	row := refreshRepo.byID[issued.ID]
	if row == nil || row.RevokedAt != nil {
		t.Errorf("cross-client revoke wrongly revoked the row: %+v", row)
	}
	// No JTI cascade for a token the caller does not own.
	if len(jtiRepo.inserts) != 0 {
		t.Errorf("cross-client cascade fired: %+v", jtiRepo.inserts)
	}
	// No "revoked" audit for a no-op.
	for _, e := range rec.Events() {
		if e.Action == string(domain.AuditOAuthTokenRevoked) {
			t.Errorf("revoked audit emitted on cross-client no-op: %+v", e)
		}
	}
	// And the owning client CAN still revoke it afterward (token was valid).
	body2 := strings.NewReader("token=" + issued.Token + "&client_id=cli-OWNER&client_secret=S")
	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/oauth/revoke", body2)
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, req2)
	if row := refreshRepo.byID[issued.ID]; row == nil || row.RevokedAt == nil {
		t.Errorf("owning client could not revoke after the cross-client no-op: %+v", row)
	}
}

func TestRevocation_RefreshTokenUnknownFallsThroughToAccessPath(t *testing.T) {
	refreshRepo := newInMemoryRefreshRepoHandlers()
	uid := uuid.New()
	verifier := &revFakeVerifier{claims: &service.IntrospectionClaims{
		Sub: uid.String(), UserID: uid, Jti: "jti-access", Exp: time.Now().Add(time.Hour).Unix(),
	}}
	r, jtiRepo, _, _ := newRevocationEngineWithRefresh(t, verifier, refreshRepo)
	// Looks like a refresh token (selector.validator shape) but no
	// row exists. The handler should fall through to the access-
	// token introspection path.
	fake := uuid.New().String() + ".AAAA"
	body := strings.NewReader("token=" + fake + "&client_id=cli-1&client_secret=S")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/oauth/revoke", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	if len(jtiRepo.inserts) != 1 || jtiRepo.inserts[0].Jti != "jti-access" {
		t.Errorf("did not fall through to access path: %+v", jtiRepo.inserts)
	}
}

func TestRevocation_InvalidTokenDoesNotPersist(t *testing.T) {
	verifier := &revFakeVerifier{err: errors.New("invalid")}
	r, repo, _ := newRevocationEngineWithJTI(t, verifier, &service.RecorderSessionRevoker{}, stubClientAuth{})
	body := strings.NewReader("token=BAD&client_id=cli-1&client_secret=S")
	req := httptest.NewRequest(http.MethodPost, "/api/v1/oauth/revoke", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	if len(repo.inserts) != 0 {
		t.Errorf("repo inserts = %d for invalid token (RFC 7009 §2.2)", len(repo.inserts))
	}
}
