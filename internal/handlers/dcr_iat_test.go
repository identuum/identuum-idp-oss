package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/mw"
	"github.com/identuum/identuum-idp-oss/internal/repository"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// memIATRepo is an in-memory implementation of
// repository.DynamicRegistrationTokenRepository sufficient to
// drive the service + handler layers end-to-end without
// Postgres.
type memIATRepo struct {
	mu   sync.Mutex
	rows map[uuid.UUID]*domain.DynamicRegistrationToken
}

func newMemIATRepo() *memIATRepo {
	return &memIATRepo{rows: map[uuid.UUID]*domain.DynamicRegistrationToken{}}
}

func (r *memIATRepo) Insert(_ context.Context, t *domain.DynamicRegistrationToken) (*domain.DynamicRegistrationToken, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now().UTC()
	t.CreatedAt = now
	t.UpdatedAt = now
	r.rows[t.ID] = t
	// Return a copy so the caller cannot mutate the row in place.
	cp := *t
	return &cp, nil
}

func (r *memIATRepo) GetByID(_ context.Context, id uuid.UUID) (*domain.DynamicRegistrationToken, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	row, ok := r.rows[id]
	if !ok {
		return nil, repository.ErrDynamicRegistrationTokenNotFound
	}
	cp := *row
	cp.TokenHash = ""
	return &cp, nil
}

func (r *memIATRepo) List(_ context.Context) ([]*domain.DynamicRegistrationToken, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*domain.DynamicRegistrationToken, 0, len(r.rows))
	for _, row := range r.rows {
		cp := *row
		cp.TokenHash = ""
		out = append(out, &cp)
	}
	return out, nil
}

func (r *memIATRepo) Revoke(_ context.Context, id uuid.UUID, at time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	row, ok := r.rows[id]
	if !ok {
		return repository.ErrDynamicRegistrationTokenNotFound
	}
	if row.RevokedAt == nil {
		t := at
		row.RevokedAt = &t
	}
	row.UpdatedAt = at
	return nil
}

func (r *memIATRepo) ConsumeByHash(_ context.Context, tokenHash string, at time.Time) (*domain.DynamicRegistrationToken, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var found *domain.DynamicRegistrationToken
	for _, row := range r.rows {
		if row.TokenHash == tokenHash {
			found = row
			break
		}
	}
	if found == nil {
		return nil, repository.ErrDynamicRegistrationTokenNotFound
	}
	if found.RevokedAt != nil {
		return nil, repository.ErrDynamicRegistrationTokenInactive
	}
	if !at.Before(found.ExpiresAt) {
		return nil, repository.ErrDynamicRegistrationTokenInactive
	}
	if found.MaxUses > 0 && found.UsesCount >= found.MaxUses {
		return nil, repository.ErrDynamicRegistrationTokenInactive
	}
	found.UsesCount++
	found.UpdatedAt = at
	cp := *found
	cp.TokenHash = ""
	return &cp, nil
}

func (r *memIATRepo) DeleteExpiredBefore(_ context.Context, cutoff time.Time) (int64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var n int64
	for id, row := range r.rows {
		if !row.ExpiresAt.After(cutoff) {
			delete(r.rows, id)
			n++
		}
	}
	return n, nil
}

// dcrIATEngine wires DCR + IAT issue/list/revoke + the
// underlying ClientService + IAT service over in-memory repos.
type dcrIATEngine struct {
	r          *gin.Engine
	clientRepo *memClientRepo
	iatRepo    *memIATRepo
	rec        *audit.Recorder
	iatSvc     *service.DCRInitialAccessTokenService
}

func newDCRIATEngine(t *testing.T, principal *domain.Principal) dcrIATEngine {
	t.Helper()
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	if principal != nil {
		r.Use(mw.InjectPrincipalForTest(principal))
	}
	clientRepo := newMemClientRepo()
	iatRepo := newMemIATRepo()
	rec := &audit.Recorder{}
	iatSvc := service.NewDCRInitialAccessTokenService(nil, iatRepo)
	RegisterDCRRoutes(r, DCRHandlerDeps{
		ClientService: service.NewClientService(nil, clientRepo),
		IATService:    iatSvc,
		Audit:         rec,
	})
	RegisterDCRInitialAccessTokenRoutes(r, DCRInitialAccessTokenHandlerDeps{
		IATService: iatSvc,
		Audit:      rec,
	})
	return dcrIATEngine{r: r, clientRepo: clientRepo, iatRepo: iatRepo, rec: rec, iatSvc: iatSvc}
}

func dcrIATJSON(t *testing.T, eng dcrIATEngine, method, path string, body any, bearer string) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			t.Fatalf("encode: %v", err)
		}
	}
	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	rec := httptest.NewRecorder()
	eng.r.ServeHTTP(rec, req)
	return rec
}

// issueIATViaService bypasses the HTTP issue endpoint and
// uses the service directly so a test can mint an IAT against
// a non-site_admin engine.
func issueIATViaService(t *testing.T, eng dcrIATEngine, opts service.IssueOptions) string {
	t.Helper()
	res, err := eng.iatSvc.Issue(context.Background(), opts)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	return res.RawIAT
}

// TestDCR_IAT_IssueReturnsRawOnceAndStoresHashOnly pins the
// one-shot invariant: the raw token appears exactly once in
// the issue response, the row carries only the hash, and the
// audit metadata does NOT carry the raw token.
func TestDCR_IAT_IssueReturnsRawOnceAndStoresHashOnly(t *testing.T) {
	eng := newDCRIATEngine(t, siteAdminPrincipal())
	rec := dcrIATJSON(t, eng, http.MethodPost, "/api/v1/dcr/initial-access-tokens", map[string]any{
		"max_uses":    1,
		"ttl_seconds": 60,
		"description": "test mint",
	}, "")
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%q", rec.Code, rec.Body.String())
	}
	var resp dcrIATIssueResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.InitialAccessToken == "" {
		t.Errorf("response missing initial_access_token field")
	}
	if len(resp.InitialAccessToken) < 32 {
		t.Errorf("initial_access_token is suspiciously short: %d chars", len(resp.InitialAccessToken))
	}
	// Stored row must not carry the raw token nor the hash.
	stored, _ := eng.iatRepo.GetByID(context.Background(), resp.Token.ID)
	if stored == nil {
		t.Fatalf("issued token not stored")
	}
	if stored.TokenHash != "" {
		t.Errorf("GetByID leaked token_hash: %q", stored.TokenHash)
	}
	if strings.Contains(rec.Body.String(), "token_hash") {
		t.Errorf("response body must not carry token_hash; got %s", rec.Body.String())
	}
	// Audit metadata must not contain the raw token.
	events := eng.rec.Events()
	if len(events) != 1 || events[0].Action != "dcr.iat_issued" {
		t.Fatalf("expected one dcr.iat_issued audit event, got %+v", events)
	}
	for k, v := range events[0].Metadata {
		if s, ok := v.(string); ok && strings.Contains(s, resp.InitialAccessToken) {
			t.Errorf("audit metadata key %q carries raw IAT: %v", k, v)
		}
	}
}

// TestDCR_IAT_IssueRequiresSiteAdmin pins that a non-site-admin
// cannot mint an IAT via the HTTP surface.
func TestDCR_IAT_IssueRequiresSiteAdmin(t *testing.T) {
	eng := newDCRIATEngine(t, &domain.Principal{
		UserID:         uuid.New(),
		OrganizationID: uuid.New(),
		Role:           domain.RoleOrgAdmin,
	})
	rec := dcrIATJSON(t, eng, http.MethodPost, "/api/v1/dcr/initial-access-tokens", map[string]any{}, "")
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
	}
}

// TestDCR_IAT_ListAndRevoke pins the list + revoke admin flow.
// The list response carries no token_hash and the revoke
// response acknowledges idempotency.
func TestDCR_IAT_ListAndRevoke(t *testing.T) {
	eng := newDCRIATEngine(t, siteAdminPrincipal())
	mintRec := dcrIATJSON(t, eng, http.MethodPost, "/api/v1/dcr/initial-access-tokens", map[string]any{
		"ttl_seconds": 60,
	}, "")
	if mintRec.Code != http.StatusCreated {
		t.Fatalf("mint status = %d", mintRec.Code)
	}
	var mintResp dcrIATIssueResponse
	_ = json.Unmarshal(mintRec.Body.Bytes(), &mintResp)

	listRec := dcrIATJSON(t, eng, http.MethodGet, "/api/v1/dcr/initial-access-tokens", nil, "")
	if listRec.Code != http.StatusOK {
		t.Fatalf("list status = %d", listRec.Code)
	}
	if strings.Contains(listRec.Body.String(), "token_hash") {
		t.Errorf("list response must not contain token_hash")
	}
	if strings.Contains(listRec.Body.String(), mintResp.InitialAccessToken) {
		t.Errorf("list response leaks raw IAT")
	}

	revokeRec := dcrIATJSON(t, eng, http.MethodPost, "/api/v1/dcr/initial-access-tokens/"+mintResp.Token.ID.String()+"/revoke", nil, "")
	if revokeRec.Code != http.StatusOK {
		t.Fatalf("revoke status = %d", revokeRec.Code)
	}

	// Idempotent: re-revoke returns 200.
	revokeRec2 := dcrIATJSON(t, eng, http.MethodPost, "/api/v1/dcr/initial-access-tokens/"+mintResp.Token.ID.String()+"/revoke", nil, "")
	if revokeRec2.Code != http.StatusOK {
		t.Errorf("idempotent re-revoke status = %d, want 200", revokeRec2.Code)
	}

	// Revoke unknown id returns 404.
	missingRec := dcrIATJSON(t, eng, http.MethodPost, "/api/v1/dcr/initial-access-tokens/"+uuid.New().String()+"/revoke", nil, "")
	if missingRec.Code != http.StatusNotFound {
		t.Errorf("revoke unknown status = %d, want 404", missingRec.Code)
	}
}

// TestDCR_SiteAdminStillWorks pins the prior-slice authority
// path: site_admin without bearer auth still registers
// clients. The IAT path is opt-in.
func TestDCR_SiteAdminStillWorks(t *testing.T) {
	eng := newDCRIATEngine(t, siteAdminPrincipal())
	rec := dcrIATJSON(t, eng, http.MethodPost, "/api/v1/oauth/register", map[string]any{
		"client_name":   "Site Admin Client",
		"redirect_uris": []string{"https://example.com/cb"},
	}, "")
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%q", rec.Code, rec.Body.String())
	}
}

// TestDCR_NoAuthStillDenied pins that an absent principal AND
// no bearer header still produces 401.
func TestDCR_NoAuthStillDenied(t *testing.T) {
	eng := newDCRIATEngine(t, nil)
	rec := dcrIATJSON(t, eng, http.MethodPost, "/api/v1/oauth/register", map[string]any{
		"client_name":   "X",
		"redirect_uris": []string{"https://example.com/cb"},
	}, "")
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

// TestDCR_IATBearerPermitsRegistrationAndIncrementsUses pins
// the canonical IAT-mode happy path: a fresh IAT lets a
// non-site-admin caller register, and the IAT row's
// uses_count increments.
func TestDCR_IATBearerPermitsRegistration(t *testing.T) {
	eng := newDCRIATEngine(t, nil) // no principal — pure bearer path
	raw := issueIATViaService(t, eng, service.IssueOptions{
		TTL:     time.Hour,
		MaxUses: 3,
	})
	rec := dcrIATJSON(t, eng, http.MethodPost, "/api/v1/oauth/register", map[string]any{
		"client_name":   "Bearer Client",
		"redirect_uris": []string{"https://bearer.example.com/cb"},
	}, raw)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%q", rec.Code, rec.Body.String())
	}
	// uses_count must have incremented.
	rows, _ := eng.iatRepo.List(context.Background())
	if len(rows) != 1 {
		t.Fatalf("rows = %d, want 1", len(rows))
	}
	if rows[0].UsesCount != 1 {
		t.Errorf("uses_count = %d, want 1", rows[0].UsesCount)
	}
}

// TestDCR_IATExpiredRejected pins that an IAT past its
// expires_at returns the opaque invalid_token envelope.
func TestDCR_IATExpiredRejected(t *testing.T) {
	eng := newDCRIATEngine(t, nil)
	// Mint an IAT with a 1-minute TTL, then rewind the row's
	// expires_at by 2 minutes to simulate expiry.
	raw := issueIATViaService(t, eng, service.IssueOptions{TTL: time.Minute, MaxUses: 1})
	for _, r := range eng.iatRepo.rows {
		r.ExpiresAt = time.Now().Add(-2 * time.Minute)
	}
	rec := dcrIATJSON(t, eng, http.MethodPost, "/api/v1/oauth/register", map[string]any{
		"client_name":   "X",
		"redirect_uris": []string{"https://x.example.com/cb"},
	}, raw)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	var env map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &env)
	if env["error"] != "invalid_token" {
		t.Errorf("error = %v; want invalid_token", env["error"])
	}
}

// TestDCR_IATRevokedRejected pins that a manually revoked IAT
// returns the opaque invalid_token envelope, distinct from
// expired by the row state but indistinguishable on the wire.
func TestDCR_IATRevokedRejected(t *testing.T) {
	eng := newDCRIATEngine(t, nil)
	raw := issueIATViaService(t, eng, service.IssueOptions{TTL: time.Hour, MaxUses: 5})
	for _, r := range eng.iatRepo.rows {
		now := time.Now()
		r.RevokedAt = &now
	}
	rec := dcrIATJSON(t, eng, http.MethodPost, "/api/v1/oauth/register", map[string]any{
		"client_name":   "X",
		"redirect_uris": []string{"https://x.example.com/cb"},
	}, raw)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

// TestDCR_IATExhaustedRejected pins that an IAT whose
// uses_count has reached MaxUses returns invalid_token.
func TestDCR_IATExhaustedRejected(t *testing.T) {
	eng := newDCRIATEngine(t, nil)
	raw := issueIATViaService(t, eng, service.IssueOptions{TTL: time.Hour, MaxUses: 1})
	// First call consumes the only available use.
	first := dcrIATJSON(t, eng, http.MethodPost, "/api/v1/oauth/register", map[string]any{
		"client_name":   "First",
		"redirect_uris": []string{"https://x.example.com/cb"},
	}, raw)
	if first.Code != http.StatusCreated {
		t.Fatalf("first status = %d", first.Code)
	}
	// Second call against the same single-use IAT must fail.
	second := dcrIATJSON(t, eng, http.MethodPost, "/api/v1/oauth/register", map[string]any{
		"client_name":   "Second",
		"redirect_uris": []string{"https://x.example.com/cb"},
	}, raw)
	if second.Code != http.StatusUnauthorized {
		t.Fatalf("second status = %d, want 401", second.Code)
	}
}

// TestDCR_IATGrantTypeConstraintEnforced pins that an IAT
// with allowed_grant_types=["authorization_code"] rejects a
// DCR request asking for client_credentials.
func TestDCR_IATGrantTypeConstraintEnforced(t *testing.T) {
	eng := newDCRIATEngine(t, nil)
	raw := issueIATViaService(t, eng, service.IssueOptions{
		TTL:               time.Hour,
		MaxUses:           1,
		AllowedGrantTypes: []string{"authorization_code"},
	})
	rec := dcrIATJSON(t, eng, http.MethodPost, "/api/v1/oauth/register", map[string]any{
		"client_name":   "Wrong Grant",
		"redirect_uris": []string{"https://x.example.com/cb"},
		"grant_types":   []string{"client_credentials"},
	}, raw)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%q", rec.Code, rec.Body.String())
	}
}

// TestDCR_IATTokenEndpointAuthMethodConstraintEnforced pins
// that an IAT with allowed_token_endpoint_auth_methods=
// ["client_secret_basic"] rejects token_endpoint_auth_method=
// none.
func TestDCR_IATTokenEndpointAuthMethodConstraintEnforced(t *testing.T) {
	eng := newDCRIATEngine(t, nil)
	raw := issueIATViaService(t, eng, service.IssueOptions{
		TTL:                             time.Hour,
		MaxUses:                         1,
		AllowedTokenEndpointAuthMethods: []string{"client_secret_basic"},
	})
	rec := dcrIATJSON(t, eng, http.MethodPost, "/api/v1/oauth/register", map[string]any{
		"client_name":                "Wrong Auth",
		"redirect_uris":              []string{"https://x.example.com/cb"},
		"token_endpoint_auth_method": "none",
	}, raw)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
}

// TestDCR_IATOrgScopeBindsRegistration pins that an IAT with
// an OrganizationID forces the registered client to that org.
// The created client carries the IAT's org.
func TestDCR_IATOrgScopeBindsRegistration(t *testing.T) {
	eng := newDCRIATEngine(t, nil)
	org := uuid.New()
	raw := issueIATViaService(t, eng, service.IssueOptions{
		TTL:            time.Hour,
		MaxUses:        1,
		OrganizationID: &org,
	})
	rec := dcrIATJSON(t, eng, http.MethodPost, "/api/v1/oauth/register", map[string]any{
		"client_name":   "Org Bound",
		"redirect_uris": []string{"https://x.example.com/cb"},
	}, raw)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%q", rec.Code, rec.Body.String())
	}
	// Pull the persisted client back and assert its OrganizationID.
	if len(eng.clientRepo.rows) != 1 {
		t.Fatalf("clients = %d, want 1", len(eng.clientRepo.rows))
	}
	for _, c := range eng.clientRepo.rows {
		if c.OrganizationID == nil || *c.OrganizationID != org {
			t.Errorf("registered client OrganizationID = %v; want %s", c.OrganizationID, org)
		}
	}
}

// TestDCR_IATAuditMetadataContainsIATIDNotRawToken pins the
// audit-side leak invariant: dcr.iat_issued AND
// client.dcr_registered events carry the IAT id but never
// the raw token bytes.
func TestDCR_IATAuditMetadataContainsIATIDNotRawToken(t *testing.T) {
	eng := newDCRIATEngine(t, siteAdminPrincipal())
	// Mint via the HTTP path so dcr.iat_issued audits.
	mintRec := dcrIATJSON(t, eng, http.MethodPost, "/api/v1/dcr/initial-access-tokens", map[string]any{
		"ttl_seconds": 60,
	}, "")
	if mintRec.Code != http.StatusCreated {
		t.Fatalf("mint status = %d", mintRec.Code)
	}
	var mintResp dcrIATIssueResponse
	_ = json.Unmarshal(mintRec.Body.Bytes(), &mintResp)

	// Register via bearer path so client.dcr_registered audits.
	regRec := dcrIATJSON(t, eng, http.MethodPost, "/api/v1/oauth/register", map[string]any{
		"client_name":   "Audited",
		"redirect_uris": []string{"https://example.com/cb"},
	}, mintResp.InitialAccessToken)
	if regRec.Code != http.StatusCreated {
		t.Fatalf("register status = %d", regRec.Code)
	}

	var sawIssued, sawRegistered bool
	for _, e := range eng.rec.Events() {
		switch e.Action {
		case "dcr.iat_issued":
			sawIssued = true
		case "client.dcr_registered":
			sawRegistered = true
			if e.Metadata["iat_id"] != mintResp.Token.ID.String() {
				t.Errorf("client.dcr_registered.iat_id = %v; want %s",
					e.Metadata["iat_id"], mintResp.Token.ID.String())
			}
			if e.Metadata["auth_mode"] != "iat" {
				t.Errorf("auth_mode = %v; want iat", e.Metadata["auth_mode"])
			}
		}
		for k, v := range e.Metadata {
			if s, ok := v.(string); ok && strings.Contains(s, mintResp.InitialAccessToken) {
				t.Errorf("event %s metadata key %q carries raw IAT: %v",
					e.Action, k, v)
			}
		}
	}
	if !sawIssued {
		t.Errorf("missing dcr.iat_issued event")
	}
	if !sawRegistered {
		t.Errorf("missing client.dcr_registered event")
	}
}

// TestDCR_IATIssueRejectsOutOfHandlerAllowlist pins that the
// IAT issue endpoint rejects an allowed_grant_types entry the
// DCR handler itself does not recognise — otherwise the IAT
// would be un-consumable.
func TestDCR_IATIssueRejectsOutOfHandlerAllowlist(t *testing.T) {
	eng := newDCRIATEngine(t, siteAdminPrincipal())
	rec := dcrIATJSON(t, eng, http.MethodPost, "/api/v1/dcr/initial-access-tokens", map[string]any{
		"allowed_grant_types": []string{"password"}, // banned at handler level
	}, "")
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400; body=%q", rec.Code, rec.Body.String())
	}
}

// TestDCR_IATServiceConsumeOpaqueOnUnknownHash pins that the
// service-layer Consume on an unknown hash returns the same
// opaque sentinel as the repository's not-found path. Used
// indirectly by the handler to produce the invalid_token
// envelope.
func TestDCR_IATServiceConsumeOpaqueOnUnknownHash(t *testing.T) {
	repo := newMemIATRepo()
	svc := service.NewDCRInitialAccessTokenService(nil, repo)
	_, err := svc.Consume(context.Background(), "no-such-token")
	if !errors.Is(err, service.ErrIATInvalid) {
		t.Errorf("Consume error = %v; want ErrIATInvalid", err)
	}
}
