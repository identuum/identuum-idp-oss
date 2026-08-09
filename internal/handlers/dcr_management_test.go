package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/mw"
	"github.com/identuum/identuum-idp-oss/internal/repository"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// memRATRepo is an in-memory implementation of
// repository.DCRClientRegistrationTokenRepository.
type memRATRepo struct {
	mu   sync.Mutex
	rows map[uuid.UUID]*domain.DCRClientRegistrationToken
}

func newMemRATRepo() *memRATRepo {
	return &memRATRepo{rows: map[uuid.UUID]*domain.DCRClientRegistrationToken{}}
}

func (r *memRATRepo) Upsert(_ context.Context, clientID uuid.UUID, hash string) (*domain.DCRClientRegistrationToken, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	row := &domain.DCRClientRegistrationToken{
		ClientID:  clientID,
		TokenHash: hash,
	}
	r.rows[clientID] = row
	cp := *row
	cp.TokenHash = ""
	return &cp, nil
}

func (r *memRATRepo) GetByClientID(_ context.Context, clientID uuid.UUID) (*domain.DCRClientRegistrationToken, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	row, ok := r.rows[clientID]
	if !ok {
		return nil, repository.ErrDCRClientRegistrationTokenNotFound
	}
	cp := *row
	cp.TokenHash = ""
	return &cp, nil
}

func (r *memRATRepo) LookupByClientIDAndHash(_ context.Context, clientID uuid.UUID, hash string) (*domain.DCRClientRegistrationToken, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	row, ok := r.rows[clientID]
	if !ok || row.TokenHash != hash {
		return nil, repository.ErrDCRClientRegistrationTokenNotFound
	}
	cp := *row
	cp.TokenHash = ""
	return &cp, nil
}

func (r *memRATRepo) DeleteByClientID(_ context.Context, clientID uuid.UUID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.rows, clientID)
	return nil
}

// dcrMgmtEngine wires DCR /register (with RAT minting) + the
// RFC 7592 management routes against in-memory repos.
type dcrMgmtEngine struct {
	r          *gin.Engine
	clientRepo *memClientRepo
	ratRepo    *memRATRepo
	rec        *audit.Recorder
	ratSvc     *service.DCRRegistrationAccessTokenService
}

func newDCRMgmtEngine(t *testing.T, principal *domain.Principal) dcrMgmtEngine {
	t.Helper()
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	if principal != nil {
		r.Use(mw.InjectPrincipalForTest(principal))
	}
	clientRepo := newMemClientRepo()
	ratRepo := newMemRATRepo()
	rec := &audit.Recorder{}
	clientSvc := service.NewClientService(nil, clientRepo)
	ratSvc := service.NewDCRRegistrationAccessTokenService(nil, ratRepo)
	RegisterDCRRoutes(r, DCRHandlerDeps{
		ClientService:       clientSvc,
		RATService:          ratSvc,
		RegistrationBaseURL: "https://idp.example.com",
		Audit:               rec,
	})
	RegisterDCRManagementRoutes(r, DCRManagementHandlerDeps{
		ClientService: clientSvc,
		RATService:    ratSvc,
		Audit:         rec,
	})
	return dcrMgmtEngine{r: r, clientRepo: clientRepo, ratRepo: ratRepo, rec: rec, ratSvc: ratSvc}
}

func dcrMgmtJSON(t *testing.T, eng dcrMgmtEngine, method, path string, body any, bearer string) *httptest.ResponseRecorder {
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

// registerDCRClient registers a fresh client (site_admin path)
// and returns (client_uuid, raw_rat) for use in subsequent
// management calls.
func registerDCRClient(t *testing.T, eng dcrMgmtEngine) (uuid.UUID, string) {
	t.Helper()
	rec := dcrMgmtJSON(t, eng, http.MethodPost, "/api/v1/oauth/register", map[string]any{
		"client_name":   "Test Client",
		"redirect_uris": []string{"https://rp.example.com/cb"},
	}, "")
	if rec.Code != http.StatusCreated {
		t.Fatalf("register status = %d; body=%q", rec.Code, rec.Body.String())
	}
	var resp dcrResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.RegistrationAccessToken == "" {
		t.Fatalf("register response missing registration_access_token")
	}
	if resp.RegistrationClientURI == "" {
		t.Fatalf("register response missing registration_client_uri")
	}
	// Recover the UUID from the persisted row.
	for id := range eng.clientRepo.rows {
		return id, resp.RegistrationAccessToken
	}
	t.Fatalf("client not persisted")
	return uuid.Nil, ""
}

// TestRFC7592_RegisterEmitsRATAndAuditDoesNotLeakIt pins the
// minting half: /register response carries
// registration_access_token + registration_client_uri exactly
// once; the audit row carries rat_issued=true but no raw token.
func TestRFC7592_RegisterEmitsRATAndAuditDoesNotLeakIt(t *testing.T) {
	eng := newDCRMgmtEngine(t, siteAdminPrincipal())
	rec := dcrMgmtJSON(t, eng, http.MethodPost, "/api/v1/oauth/register", map[string]any{
		"client_name":   "RAT Pin",
		"redirect_uris": []string{"https://rp.example.com/cb"},
	}, "")
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d; body=%q", rec.Code, rec.Body.String())
	}
	var resp dcrResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if len(resp.RegistrationAccessToken) < 32 {
		t.Errorf("registration_access_token suspiciously short: %d chars", len(resp.RegistrationAccessToken))
	}
	wantPrefix := "https://idp.example.com/api/v1/oauth/register/"
	if !strings.HasPrefix(resp.RegistrationClientURI, wantPrefix) {
		t.Errorf("registration_client_uri = %q; want prefix %s", resp.RegistrationClientURI, wantPrefix)
	}
	events := eng.rec.Events()
	if len(events) != 1 || events[0].Action != "client.dcr_registered" {
		t.Fatalf("expected one client.dcr_registered event, got %+v", events)
	}
	if events[0].Metadata["rat_issued"] != true {
		t.Errorf("rat_issued = %v; want true", events[0].Metadata["rat_issued"])
	}
	for k, v := range events[0].Metadata {
		if s, ok := v.(string); ok && strings.Contains(s, resp.RegistrationAccessToken) {
			t.Errorf("audit metadata %q leaks raw RAT: %v", k, v)
		}
	}
}

// TestRFC7592_GetReturnsMetadataWithoutSecret pins that GET
// /:client_id returns the safe projection. client_secret MUST
// NOT appear on management reads.
func TestRFC7592_GetReturnsMetadataWithoutSecret(t *testing.T) {
	eng := newDCRMgmtEngine(t, siteAdminPrincipal())
	id, raw := registerDCRClient(t, eng)
	rec := dcrMgmtJSON(t, eng, http.MethodGet, "/api/v1/oauth/register/"+id.String(), nil, raw)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d; body=%q", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if strings.Contains(body, "client_secret") {
		t.Errorf("management GET must not echo client_secret; body=%s", body)
	}
	if strings.Contains(body, "client_secret_hash") {
		t.Errorf("management GET must not echo client_secret_hash")
	}
	if strings.Contains(body, "registration_access_token") {
		t.Errorf("management GET must not re-emit registration_access_token")
	}
	events := eng.rec.Events()
	var got bool
	for _, e := range events {
		if e.Action == "dcr.client_read" {
			got = true
		}
	}
	if !got {
		t.Errorf("missing dcr.client_read audit event")
	}
}

// TestRFC7592_PutUpdatesAllowedFields pins that PUT updates
// only the safe mutable subset; immutable fields are not
// touched.
func TestRFC7592_PutUpdatesAllowedFields(t *testing.T) {
	eng := newDCRMgmtEngine(t, siteAdminPrincipal())
	id, raw := registerDCRClient(t, eng)
	rec := dcrMgmtJSON(t, eng, http.MethodPut, "/api/v1/oauth/register/"+id.String(), map[string]any{
		"client_name":   "Renamed",
		"redirect_uris": []string{"https://rp.example.com/cb", "https://rp.example.com/cb2"},
	}, raw)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d; body=%q", rec.Code, rec.Body.String())
	}
	persisted := eng.clientRepo.rows[id]
	if persisted == nil {
		t.Fatalf("client missing after PUT")
	}
	if persisted.Name != "Renamed" {
		t.Errorf("name = %q; want Renamed", persisted.Name)
	}
	if len(persisted.RedirectURIs) != 2 {
		t.Errorf("redirect_uris len = %d; want 2", len(persisted.RedirectURIs))
	}
	events := eng.rec.Events()
	var got bool
	for _, e := range events {
		if e.Action == "dcr.client_updated" {
			got = true
		}
	}
	if !got {
		t.Errorf("missing dcr.client_updated audit event")
	}
}

// TestRFC7592_PutRejectsInvalidRedirectURI pins that the
// metadata error envelope fires on invalid redirect_uris.
func TestRFC7592_PutRejectsInvalidRedirectURI(t *testing.T) {
	eng := newDCRMgmtEngine(t, siteAdminPrincipal())
	id, raw := registerDCRClient(t, eng)
	rec := dcrMgmtJSON(t, eng, http.MethodPut, "/api/v1/oauth/register/"+id.String(), map[string]any{
		"redirect_uris": []string{"javascript:alert(1)"},
	}, raw)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d; want 400", rec.Code)
	}
	var env map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &env)
	if env["error"] != "invalid_redirect_uri" {
		t.Errorf("error = %v; want invalid_redirect_uri", env["error"])
	}
}

// TestRFC7592_DeleteRemovesClientAndRAT pins that DELETE wipes
// both the client row and the associated RAT row, returns 204,
// and audit fires.
func TestRFC7592_DeleteRemovesClientAndRAT(t *testing.T) {
	eng := newDCRMgmtEngine(t, siteAdminPrincipal())
	id, raw := registerDCRClient(t, eng)
	rec := dcrMgmtJSON(t, eng, http.MethodDelete, "/api/v1/oauth/register/"+id.String(), nil, raw)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d; want 204", rec.Code)
	}
	if _, ok := eng.clientRepo.rows[id]; ok {
		t.Errorf("client row still present after DELETE")
	}
	if _, ok := eng.ratRepo.rows[id]; ok {
		t.Errorf("RAT row still present after DELETE")
	}
	events := eng.rec.Events()
	var got bool
	for _, e := range events {
		if e.Action == "dcr.client_deleted" {
			got = true
		}
	}
	if !got {
		t.Errorf("missing dcr.client_deleted audit event")
	}
}

// TestRFC7592_RATMismatchReturns401 pins that a wrong Bearer
// (right client_id, wrong token) returns invalid_token 401.
func TestRFC7592_RATMismatchReturns401(t *testing.T) {
	eng := newDCRMgmtEngine(t, siteAdminPrincipal())
	id, _ := registerDCRClient(t, eng)
	rec := dcrMgmtJSON(t, eng, http.MethodGet, "/api/v1/oauth/register/"+id.String(), nil, "wrong-rat")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d; want 401", rec.Code)
	}
	var env map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &env)
	if env["error"] != "invalid_token" {
		t.Errorf("error = %v; want invalid_token", env["error"])
	}
}

// TestRFC7592_NoAuthReturns401 pins that no Bearer + no site_admin
// principal returns 401 invalid_token. The test seeds the
// underlying repos directly so the management call runs against
// a no-principal engine.
func TestRFC7592_NoAuthReturns401(t *testing.T) {
	eng := newDCRMgmtEngine(t, nil)
	// Seed a client + RAT directly so we do not need a site_admin
	// principal to set up state.
	cs := service.NewClientService(nil, eng.clientRepo)
	c, _, err := cs.RegisterClient(context.Background(), service.RegisterClientOptions{
		Name:         "Seed",
		RedirectURIs: []string{"https://x.example.com/cb"},
	})
	if err != nil {
		t.Fatalf("seed client: %v", err)
	}
	if _, err := eng.ratSvc.Mint(context.Background(), c.ID); err != nil {
		t.Fatalf("mint RAT: %v", err)
	}
	rec := dcrMgmtJSON(t, eng, http.MethodGet, "/api/v1/oauth/register/"+c.ID.String(), nil, "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d; want 401", rec.Code)
	}
}

// TestRFC7592_NotDCRCreatedReturns404 pins that a client created
// via the site_admin /api/v1/clients surface (no RAT row) is
// NOT addressable through the RFC 7592 endpoint.
func TestRFC7592_NotDCRCreatedReturns404(t *testing.T) {
	eng := newDCRMgmtEngine(t, siteAdminPrincipal())
	// Mint a client directly via the underlying service (no RAT
	// row) — simulates a site_admin-created client.
	cs := service.NewClientService(nil, eng.clientRepo)
	c, _, err := cs.RegisterClient(context.Background(), service.RegisterClientOptions{
		Name:         "Admin Created",
		RedirectURIs: []string{"https://x.example.com/cb"},
	})
	if err != nil {
		t.Fatalf("RegisterClient: %v", err)
	}
	rec := dcrMgmtJSON(t, eng, http.MethodGet, "/api/v1/oauth/register/"+c.ID.String(), nil, "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d; want 404 (non-DCR client invisible via RFC 7592 surface)", rec.Code)
	}
}

// TestRFC7592_SiteAdminEscapeHatchWorksWithoutRAT pins that a
// site_admin principal can manage a DCR-created client even
// without the original RAT (operator-recovery story).
func TestRFC7592_SiteAdminEscapeHatchWorksWithoutRAT(t *testing.T) {
	eng := newDCRMgmtEngine(t, siteAdminPrincipal())
	id, _ := registerDCRClient(t, eng)
	rec := dcrMgmtJSON(t, eng, http.MethodGet, "/api/v1/oauth/register/"+id.String(), nil, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d; want 200 (site_admin escape hatch)", rec.Code)
	}
}

// TestRFC7592_UnknownClientReturns404 pins that an unknown
// :client_id UUID returns 404 invalid_client (NOT 401) so the
// existence of /api/v1/oauth/register/<uuid> cannot be probed
// without authentication.
func TestRFC7592_UnknownClientReturns404(t *testing.T) {
	eng := newDCRMgmtEngine(t, siteAdminPrincipal())
	rec := dcrMgmtJSON(t, eng, http.MethodGet, "/api/v1/oauth/register/"+uuid.New().String(), nil, "anything")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d; want 404", rec.Code)
	}
}
