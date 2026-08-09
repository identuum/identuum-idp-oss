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
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/mw"
	"github.com/identuum/identuum-idp-oss/internal/repository"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// memClientRepo is a minimal in-memory ClientRepository sufficient
// to drive the OSS ClientService through the handler layer.
type memClientRepo struct {
	mu   sync.Mutex
	rows map[uuid.UUID]*domain.Client
}

func newMemClientRepo() *memClientRepo {
	return &memClientRepo{rows: map[uuid.UUID]*domain.Client{}}
}

func (r *memClientRepo) RegisterClient(_ context.Context, c *domain.Client) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.rows[c.ID] = c
	return nil
}
func (r *memClientRepo) GetClientByID(_ context.Context, id uuid.UUID) (*domain.Client, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.rows[id], nil
}
func (r *memClientRepo) GetClientByClientID(_ context.Context, _ string) (*domain.Client, error) {
	panic("not used")
}
func (r *memClientRepo) Update(_ context.Context, c *domain.Client) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.rows[c.ID] = c
	return nil
}
func (r *memClientRepo) Delete(_ context.Context, id uuid.UUID, _ *uuid.UUID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.rows, id)
	return nil
}
func (r *memClientRepo) List(_ context.Context, _ repository.Pagination, _ *uuid.UUID) ([]*domain.Client, int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*domain.Client, 0, len(r.rows))
	for _, c := range r.rows {
		out = append(out, c)
	}
	return out, len(out), nil
}
func (r *memClientRepo) ListByServiceAccountID(_ context.Context, _, _ uuid.UUID) ([]*domain.Client, error) {
	panic("not used")
}
func (r *memClientRepo) SaveConsent(_ context.Context, _ *domain.Consent) error { panic("not used") }
func (r *memClientRepo) GetConsent(_ context.Context, _, _ uuid.UUID, _ *uuid.UUID) (*domain.Consent, error) {
	panic("not used")
}

// memAPIResourceRepo is a minimal in-memory APIResourceRepository.
type memAPIResourceRepo struct {
	mu   sync.Mutex
	rows map[uuid.UUID]*domain.APIResource
}

func newMemAPIResourceRepo() *memAPIResourceRepo {
	return &memAPIResourceRepo{rows: map[uuid.UUID]*domain.APIResource{}}
}

func (r *memAPIResourceRepo) Create(_ context.Context, res *domain.APIResource, _ []domain.APIScope) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.rows[res.ID] = res
	return nil
}
func (r *memAPIResourceRepo) GetByID(_ context.Context, id uuid.UUID, _ *uuid.UUID) (*domain.APIResource, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.rows[id], nil
}
func (r *memAPIResourceRepo) GetByAudienceGlobal(_ context.Context, _ string) (*domain.APIResource, error) {
	panic("not used")
}
func (r *memAPIResourceRepo) Update(_ context.Context, res *domain.APIResource) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.rows[res.ID] = res
	return nil
}
func (r *memAPIResourceRepo) Delete(_ context.Context, id uuid.UUID, _ *uuid.UUID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.rows, id)
	return nil
}
func (r *memAPIResourceRepo) List(_ context.Context, _ repository.Pagination, _ *uuid.UUID) ([]*domain.APIResource, int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*domain.APIResource, 0, len(r.rows))
	for _, v := range r.rows {
		out = append(out, v)
	}
	return out, len(out), nil
}
func (r *memAPIResourceRepo) AddScopes(_ context.Context, _ uuid.UUID, _ []domain.APIScope) error {
	return nil
}
func (r *memAPIResourceRepo) RemoveScope(_ context.Context, _, _ uuid.UUID) error { return nil }
func (r *memAPIResourceRepo) ReplaceScopes(_ context.Context, _ uuid.UUID, _ []domain.APIScope) error {
	return nil
}
func (r *memAPIResourceRepo) UpdateWithScopes(_ context.Context, res *domain.APIResource, scopes []domain.APIScope) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	res.Scopes = scopes
	r.rows[res.ID] = res
	return nil
}

// memScopeTemplateRepo is a minimal in-memory ScopeTemplateRepository.
type memScopeTemplateRepo struct {
	mu   sync.Mutex
	rows map[uuid.UUID]*domain.ScopeTemplate
}

func newMemScopeTemplateRepo() *memScopeTemplateRepo {
	return &memScopeTemplateRepo{rows: map[uuid.UUID]*domain.ScopeTemplate{}}
}

func (r *memScopeTemplateRepo) Create(_ context.Context, t *domain.ScopeTemplate) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.rows[t.ID] = t
	return nil
}
func (r *memScopeTemplateRepo) GetByID(_ context.Context, id, _ uuid.UUID) (*domain.ScopeTemplate, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.rows[id], nil
}
func (r *memScopeTemplateRepo) List(_ context.Context, _ uuid.UUID) ([]*domain.ScopeTemplate, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*domain.ScopeTemplate, 0, len(r.rows))
	for _, v := range r.rows {
		out = append(out, v)
	}
	return out, nil
}
func (r *memScopeTemplateRepo) Update(_ context.Context, t *domain.ScopeTemplate) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.rows[t.ID] = t
	return nil
}
func (r *memScopeTemplateRepo) Delete(_ context.Context, id, _ uuid.UUID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.rows, id)
	return nil
}

// liveEngine wires the three handler groups with services in front of
// in-memory repos plus an audit Recorder. Caller plugs in the principal.
type liveEngine struct {
	r          *gin.Engine
	clientRepo *memClientRepo
	apiRepo    *memAPIResourceRepo
	stRepo     *memScopeTemplateRepo
	rec        *audit.Recorder
}

func newLiveEngine(t *testing.T, principal *domain.Principal) liveEngine {
	t.Helper()
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	if principal != nil {
		r.Use(mw.InjectPrincipalForTest(principal))
	}
	clientRepo := newMemClientRepo()
	apiRepo := newMemAPIResourceRepo()
	stRepo := newMemScopeTemplateRepo()
	rec := &audit.Recorder{}
	RegisterClientsRoutes(r, ClientsHandlerDeps{
		ClientService: service.NewClientService(nil, clientRepo),
		Audit:         rec,
	})
	RegisterAPIResourcesRoutes(r, APIResourcesHandlerDeps{
		APIResourceService: service.NewAPIResourceService(nil, apiRepo),
		Audit:              rec,
	})
	RegisterScopeTemplatesRoutes(r, ScopeTemplatesHandlerDeps{
		ScopeTemplateService: service.NewScopeTemplateService(nil, stRepo),
		Audit:                rec,
	})
	return liveEngine{r: r, clientRepo: clientRepo, apiRepo: apiRepo, stRepo: stRepo, rec: rec}
}

func doJSON(t *testing.T, eng liveEngine, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			t.Fatalf("encode body: %v", err)
		}
	}
	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	eng.r.ServeHTTP(rec, req)
	return rec
}

// ----- Clients live mutations -----------------------------------

func TestLive_ClientCreateReturnsSecretOnceAndAuditEmits(t *testing.T) {
	eng := newLiveEngine(t, siteAdminPrincipal())
	rec := doJSON(t, eng, http.MethodPost, "/api/v1/clients", map[string]any{
		"name":          "Live Client",
		"redirect_uris": []string{"https://example.com/cb"},
		"is_public":     false,
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%q", rec.Code, rec.Body.String())
	}
	var resp struct {
		Client       map[string]any `json:"client"`
		ClientSecret string         `json:"client_secret"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.ClientSecret == "" {
		t.Errorf("confidential client must receive one-time client_secret in body")
	}
	if _, ok := resp.Client["client_secret_hash"]; ok {
		t.Errorf("response leaked client_secret_hash field")
	}
	if strings.Contains(rec.Body.String(), "SECRET-HASH-MUST-NOT-LEAK") {
		t.Errorf("body must not leak sentinel hash")
	}
	events := eng.rec.Events()
	if len(events) != 1 || events[0].Action != "client.created" || events[0].Outcome != "success" {
		t.Fatalf("expected one client.created audit event, got %+v", events)
	}
	for k, v := range events[0].Metadata {
		if s, ok := v.(string); ok && (s == resp.ClientSecret || strings.Contains(s, "secret")) {
			t.Errorf("audit metadata key %q contains secret-like material: %v", k, v)
		}
	}
}

func TestLive_ClientCreatePublicHasNoSecret(t *testing.T) {
	eng := newLiveEngine(t, siteAdminPrincipal())
	rec := doJSON(t, eng, http.MethodPost, "/api/v1/clients", map[string]any{
		"name":          "Live Public",
		"redirect_uris": []string{"https://example.com/cb"},
		"is_public":     true,
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201", rec.Code)
	}
	var resp struct {
		ClientSecret string `json:"client_secret"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.ClientSecret != "" {
		t.Errorf("public client must NOT receive client_secret; got %q", resp.ClientSecret)
	}
}

func TestLive_ClientRegenerateRotatesAndAudits(t *testing.T) {
	eng := newLiveEngine(t, siteAdminPrincipal())
	create := doJSON(t, eng, http.MethodPost, "/api/v1/clients", map[string]any{
		"name":          "Live Client",
		"redirect_uris": []string{"https://example.com/cb"},
		"is_public":     false,
	})
	if create.Code != http.StatusCreated {
		t.Fatalf("create status = %d", create.Code)
	}
	var created struct {
		Client       map[string]any `json:"client"`
		ClientSecret string         `json:"client_secret"`
	}
	_ = json.Unmarshal(create.Body.Bytes(), &created)
	id := created.Client["id"].(string)
	rec := doJSON(t, eng, http.MethodPost, "/api/v1/clients/"+id+"/secret/regenerate", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%q", rec.Code, rec.Body.String())
	}
	var rotated struct {
		ClientSecret string `json:"client_secret"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &rotated)
	if rotated.ClientSecret == "" || rotated.ClientSecret == created.ClientSecret {
		t.Errorf("rotation must return a new plaintext secret distinct from original")
	}
	// At least one event for create + one for rotate.
	events := eng.rec.Events()
	var rotateFound bool
	for _, e := range events {
		if e.Action == "client.secret_rotated" {
			rotateFound = true
		}
	}
	if !rotateFound {
		t.Errorf("expected client.secret_rotated audit event; got %+v", events)
	}
}

func TestLive_ClientDeleteReturnsOKAndAudits(t *testing.T) {
	eng := newLiveEngine(t, siteAdminPrincipal())
	create := doJSON(t, eng, http.MethodPost, "/api/v1/clients", map[string]any{
		"name":          "Doomed",
		"redirect_uris": []string{"https://example.com/cb"},
		"is_public":     true,
	})
	var created struct {
		Client map[string]any `json:"client"`
	}
	_ = json.Unmarshal(create.Body.Bytes(), &created)
	id := created.Client["id"].(string)
	rec := doJSON(t, eng, http.MethodDelete, "/api/v1/clients/"+id, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	events := eng.rec.Events()
	var delFound bool
	for _, e := range events {
		if e.Action == "client.deleted" {
			delFound = true
		}
	}
	if !delFound {
		t.Errorf("expected client.deleted audit event")
	}
}

func TestLive_ClientMutationsNonSiteAdminReturns403(t *testing.T) {
	eng := newLiveEngine(t, &domain.Principal{
		UserID: uuid.New(),
		Role:   domain.RoleOrgAdmin,
	})
	rec := doJSON(t, eng, http.MethodPost, "/api/v1/clients", map[string]any{
		"name":          "X",
		"redirect_uris": []string{"https://example.com/cb"},
	})
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
	}
}

// ----- API Resources live mutations -----------------------------

func TestLive_APIResourceCreateReturnsResourceSecretOnce(t *testing.T) {
	eng := newLiveEngine(t, siteAdminPrincipal())
	rec := doJSON(t, eng, http.MethodPost, "/api/v1/api-resources", map[string]any{
		"organization_id": uuid.New().String(),
		"name":            "Resource",
		"audience":        "https://api.example.com",
		"active":          true,
		"token_ttl_secs":  3600,
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%q", rec.Code, rec.Body.String())
	}
	var resp struct {
		APIResource    map[string]any `json:"api_resource"`
		ResourceSecret string         `json:"resource_secret"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.ResourceSecret == "" {
		t.Errorf("api-resource create must return one-time resource_secret")
	}
	if _, ok := resp.APIResource["resource_secret_hash"]; ok {
		t.Errorf("response leaked resource_secret_hash")
	}
	if strings.Contains(rec.Body.String(), "RESOURCE-HASH-MUST-NOT-LEAK") {
		t.Errorf("body must not leak sentinel hash")
	}
	events := eng.rec.Events()
	if len(events) != 1 || events[0].Action != "api_resource.created" {
		t.Fatalf("expected one api_resource.created event, got %+v", events)
	}
	for k, v := range events[0].Metadata {
		if s, ok := v.(string); ok && s == resp.ResourceSecret {
			t.Errorf("audit metadata key %q contains plaintext resource secret", k)
		}
	}
}

func TestLive_APIResourceRegenerateRotates(t *testing.T) {
	eng := newLiveEngine(t, siteAdminPrincipal())
	create := doJSON(t, eng, http.MethodPost, "/api/v1/api-resources", map[string]any{
		"organization_id": uuid.New().String(),
		"name":            "R",
		"audience":        "https://api.example.com",
		"active":          true,
		"token_ttl_secs":  3600,
	})
	var created struct {
		APIResource    map[string]any `json:"api_resource"`
		ResourceSecret string         `json:"resource_secret"`
	}
	_ = json.Unmarshal(create.Body.Bytes(), &created)
	id := created.APIResource["id"].(string)
	rec := doJSON(t, eng, http.MethodPost, "/api/v1/api-resources/"+id+"/secret/regenerate", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%q", rec.Code, rec.Body.String())
	}
	var rotated struct {
		ResourceSecret string `json:"resource_secret"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &rotated)
	if rotated.ResourceSecret == "" || rotated.ResourceSecret == created.ResourceSecret {
		t.Errorf("rotation must return new plaintext distinct from original")
	}
	var rotateFound bool
	for _, e := range eng.rec.Events() {
		if e.Action == "api_resource.secret_rotated" {
			rotateFound = true
		}
	}
	if !rotateFound {
		t.Errorf("expected api_resource.secret_rotated audit event")
	}
}

func TestLive_APIResourceDeleteAudits(t *testing.T) {
	eng := newLiveEngine(t, siteAdminPrincipal())
	create := doJSON(t, eng, http.MethodPost, "/api/v1/api-resources", map[string]any{
		"organization_id": uuid.New().String(),
		"name":            "R",
		"audience":        "https://api.example.com",
		"active":          true,
		"token_ttl_secs":  3600,
	})
	var created struct {
		APIResource map[string]any `json:"api_resource"`
	}
	_ = json.Unmarshal(create.Body.Bytes(), &created)
	id := created.APIResource["id"].(string)
	rec := doJSON(t, eng, http.MethodDelete, "/api/v1/api-resources/"+id, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var delFound bool
	for _, e := range eng.rec.Events() {
		if e.Action == "api_resource.deleted" {
			delFound = true
		}
	}
	if !delFound {
		t.Errorf("expected api_resource.deleted audit event")
	}
}

// ----- Scope Templates live mutations ---------------------------

func TestLive_ScopeTemplateCreateAudits(t *testing.T) {
	orgID := uuid.New()
	eng := newLiveEngine(t, &domain.Principal{
		UserID:         uuid.New(),
		OrganizationID: orgID,
		Role:           domain.RoleSiteAdmin,
	})
	rec := doJSON(t, eng, http.MethodPost, "/api/v1/scope-templates", map[string]any{
		"name":        "Admin Template",
		"description": "Admin shortcut",
		"scopes":      []string{"org:read", "org:write"},
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%q", rec.Code, rec.Body.String())
	}
	var resp safeScopeTemplate
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.OrganizationID != orgID {
		t.Errorf("response org id = %s, want %s", resp.OrganizationID, orgID)
	}
	var found bool
	for _, e := range eng.rec.Events() {
		if e.Action == "scope_template.created" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected scope_template.created event")
	}
}

func TestLive_ScopeTemplateUpdateAndDelete(t *testing.T) {
	orgID := uuid.New()
	eng := newLiveEngine(t, &domain.Principal{
		UserID:         uuid.New(),
		OrganizationID: orgID,
		Role:           domain.RoleSiteAdmin,
	})
	create := doJSON(t, eng, http.MethodPost, "/api/v1/scope-templates", map[string]any{
		"name":   "Initial",
		"scopes": []string{"a"},
	})
	if create.Code != http.StatusCreated {
		t.Fatalf("create status = %d; body=%q", create.Code, create.Body.String())
	}
	var created safeScopeTemplate
	_ = json.Unmarshal(create.Body.Bytes(), &created)
	upd := doJSON(t, eng, http.MethodPut, "/api/v1/scope-templates/"+created.ID.String(), map[string]any{
		"name":   "Renamed",
		"scopes": []string{"a", "b"},
	})
	if upd.Code != http.StatusOK {
		t.Fatalf("update status = %d; body=%q", upd.Code, upd.Body.String())
	}
	var updated safeScopeTemplate
	_ = json.Unmarshal(upd.Body.Bytes(), &updated)
	if updated.Name != "Renamed" || len(updated.Scopes) != 2 {
		t.Errorf("update did not apply: %+v", updated)
	}
	del := doJSON(t, eng, http.MethodDelete, "/api/v1/scope-templates/"+created.ID.String(), nil)
	if del.Code != http.StatusOK {
		t.Errorf("delete status = %d", del.Code)
	}
	var sawUpd, sawDel bool
	for _, e := range eng.rec.Events() {
		switch e.Action {
		case "scope_template.updated":
			sawUpd = true
		case "scope_template.deleted":
			sawDel = true
		}
	}
	if !sawUpd || !sawDel {
		t.Errorf("missing audit events: update=%v delete=%v", sawUpd, sawDel)
	}
	_ = time.Second
}
