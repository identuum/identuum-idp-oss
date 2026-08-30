package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/mw"
	"github.com/identuum/identuum-idp-oss/internal/repository"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// inMemoryClientRepoForBundleHandlers is the smallest
// repository.ClientRepository the bundle handler needs end-to-end.
type inMemoryClientRepoForBundleHandlers struct {
	byID        map[uuid.UUID]*domain.Client
	registerErr error
}

func newClientRepoForBundleHandlers() *inMemoryClientRepoForBundleHandlers {
	return &inMemoryClientRepoForBundleHandlers{byID: map[uuid.UUID]*domain.Client{}}
}

func (r *inMemoryClientRepoForBundleHandlers) RegisterClient(_ context.Context, c *domain.Client) error {
	if r.registerErr != nil {
		return r.registerErr
	}
	cp := *c
	r.byID[c.ID] = &cp
	return nil
}
func (r *inMemoryClientRepoForBundleHandlers) GetClientByID(_ context.Context, id uuid.UUID) (*domain.Client, error) {
	c, ok := r.byID[id]
	if !ok {
		return nil, nil
	}
	cp := *c
	return &cp, nil
}
func (r *inMemoryClientRepoForBundleHandlers) GetClientByClientID(_ context.Context, cid string) (*domain.Client, error) {
	for _, c := range r.byID {
		if c.ClientID == cid {
			cp := *c
			return &cp, nil
		}
	}
	return nil, nil
}
func (r *inMemoryClientRepoForBundleHandlers) Update(_ context.Context, c *domain.Client) error {
	cp := *c
	r.byID[c.ID] = &cp
	return nil
}
func (r *inMemoryClientRepoForBundleHandlers) Delete(_ context.Context, id uuid.UUID, _ *uuid.UUID) error {
	delete(r.byID, id)
	return nil
}
func (r *inMemoryClientRepoForBundleHandlers) List(context.Context, repository.Pagination, *uuid.UUID) ([]*domain.Client, int, error) {
	return nil, 0, nil
}
func (r *inMemoryClientRepoForBundleHandlers) ListByServiceAccountID(context.Context, uuid.UUID, uuid.UUID) ([]*domain.Client, error) {
	return nil, nil
}
func (r *inMemoryClientRepoForBundleHandlers) SaveConsent(context.Context, *domain.Consent) error {
	return nil
}
func (r *inMemoryClientRepoForBundleHandlers) GetConsent(context.Context, uuid.UUID, uuid.UUID, *uuid.UUID) (*domain.Consent, error) {
	return nil, nil
}

// bundleRepoForHandlers is a test double for
// repository.ServiceAccountClientBundleRepository. It presents the atomic
// both-or-nothing contract over the in-memory SA + client fakes: on a
// client-register failure it removes the SA it just added, so the handler
// tests observe the same "no orphan SA" result the real pgx transaction
// guarantees. (Real DB atomicity is proven by the e2e pgx test.)
type bundleRepoForHandlers struct {
	sa     *inMemorySARepoForHandlers
	client *inMemoryClientRepoForBundleHandlers
}

func (r *bundleRepoForHandlers) CreateWithClient(ctx context.Context, sa *domain.ServiceAccount, client *domain.Client) (*domain.ServiceAccount, *domain.Client, error) {
	createdSA, err := r.sa.Create(ctx, sa)
	if err != nil {
		return nil, nil, err
	}
	client.ServiceAccountID = &createdSA.ID
	if err := r.client.RegisterClient(ctx, client); err != nil {
		_ = r.sa.Delete(ctx, createdSA.ID, createdSA.OrganizationID)
		return nil, nil, err
	}
	return createdSA, client, nil
}

var _ repository.ServiceAccountClientBundleRepository = (*bundleRepoForHandlers)(nil)

func newBundleEngine(t *testing.T, principal *domain.Principal, clientErr error) (*gin.Engine, *inMemorySARepoForHandlers, *inMemoryClientRepoForBundleHandlers, *audit.Recorder) {
	t.Helper()
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	if principal != nil {
		r.Use(mw.InjectPrincipalForTest(principal))
	}
	saRepo := newSARepoForHandlers()
	clientRepo := newClientRepoForBundleHandlers()
	clientRepo.registerErr = clientErr
	saSvc := service.NewServiceAccountService(nil, saRepo)
	clientSvc := service.NewClientService(nil, clientRepo).WithServiceAccountBindingValidator(saSvc)
	bundleRepo := &bundleRepoForHandlers{sa: saRepo, client: clientRepo}
	bundleSvc := service.NewServiceAccountClientBundleService(nil, saSvc, clientSvc, bundleRepo)
	rec := &audit.Recorder{}
	RegisterServiceAccountClientBundleRoutes(r, ServiceAccountClientBundleHandlerDeps{
		BundleService: bundleSvc,
		Audit:         rec,
	})
	return r, saRepo, clientRepo, rec
}

// bundleSiteAdmin was removed by THE-REMAINING-FOUR (2026-08-30): the bundle
// route answers to the org's own org_admin now (site_admin refused on tenant
// service accounts).

func bundleOrgAdmin(orgID uuid.UUID) *domain.Principal {
	return &domain.Principal{UserID: uuid.New(), OrganizationID: orgID, Role: domain.RoleOrgAdmin}
}

func bundleOrgUser(orgID uuid.UUID) *domain.Principal {
	return &domain.Principal{UserID: uuid.New(), OrganizationID: orgID, Role: domain.RoleOrgUser}
}

// ---------- Route absence ----------

func TestBundleRoute_AbsentWithoutService(t *testing.T) {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	RegisterServiceAccountClientBundleRoutes(r, ServiceAccountClientBundleHandlerDeps{})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/v1/organizations/"+uuid.NewString()+"/service-accounts/with-client", nil))
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d", w.Code)
	}
}

// ---------- Auth ----------

func TestBundleRoute_UnauthenticatedIs401(t *testing.T) {
	r, _, _, _ := newBundleEngine(t, nil, nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/v1/organizations/"+uuid.NewString()+"/service-accounts/with-client", strings.NewReader(`{}`)))
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d", w.Code)
	}
}

// ---------- Authorization ----------

func TestBundleRoute_OrgUserForbidden(t *testing.T) {
	orgID := uuid.New()
	r, _, _, _ := newBundleEngine(t, bundleOrgUser(orgID), nil)
	body := strings.NewReader(`{"service_account":{"name":"ci","role":"org_user"}}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/organizations/"+orgID.String()+"/service-accounts/with-client", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d", w.Code)
	}
}

func TestBundleRoute_CrossOrgOrgAdminNotFound(t *testing.T) {
	other := uuid.New()
	r, _, _, _ := newBundleEngine(t, bundleOrgAdmin(uuid.New()), nil)
	body := strings.NewReader(`{"service_account":{"name":"ci","role":"org_user"}}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/organizations/"+other.String()+"/service-accounts/with-client", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d", w.Code)
	}
}

// ---------- Happy path: site_admin ----------

// THE-REMAINING-FOUR: the SA+client bundle is created by the org's own
// org_admin now (site_admin refused on tenant service accounts).
func TestBundleRoute_OrgAdminCreatesBundleWithOneTimeSecret(t *testing.T) {
	orgID := uuid.New()
	r, saRepo, clientRepo, rec := newBundleEngine(t, bundleOrgAdmin(orgID), nil)
	body := strings.NewReader(`{"service_account":{"name":"deploy-bot","role":"org_user"}}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/organizations/"+orgID.String()+"/service-accounts/with-client", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, body = %q", w.Code, w.Body.String())
	}
	var resp map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	sa, _ := resp["service_account"].(map[string]any)
	client, _ := resp["client"].(map[string]any)
	if sa == nil || client == nil {
		t.Fatalf("response missing sa or client: %s", w.Body.String())
	}
	if resp["client_secret"] == nil || resp["client_secret"] == "" {
		t.Errorf("client_secret missing from one-time response")
	}
	// Confirm wire DTO doesn't leak secret material that shouldn't
	// be there.
	for _, banned := range []string{"client_secret_hash", "owner_user_id", "metadata"} {
		if _, ok := client[banned]; ok {
			t.Errorf("client DTO leaked %q: %v", banned, client[banned])
		}
	}
	// Confirm the SA was persisted bound to the client.
	if len(saRepo.byID) != 1 {
		t.Errorf("SA rows = %d", len(saRepo.byID))
	}
	if len(clientRepo.byID) != 1 {
		t.Errorf("client rows = %d", len(clientRepo.byID))
	}
	var saw bool
	for _, e := range rec.Events() {
		if e.Action == "service_account_client.created" {
			saw = true
			if e.Metadata["service_account_id"] == nil {
				t.Errorf("audit missing service_account_id")
			}
			for k, v := range e.Metadata {
				if k == "client_secret" || k == "secret" || k == "client_secret_hash" {
					t.Errorf("audit leaked banned key %q = %v", k, v)
				}
			}
		}
	}
	if !saw {
		t.Errorf("audit service_account_client.created not fired")
	}
}

// ---------- Same-org org_admin happy path ----------

func TestBundleRoute_SameOrgOrgAdminCreatesBundle(t *testing.T) {
	orgID := uuid.New()
	r, _, _, _ := newBundleEngine(t, bundleOrgAdmin(orgID), nil)
	body := strings.NewReader(`{"service_account":{"name":"ci","role":"org_user"}}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/organizations/"+orgID.String()+"/service-accounts/with-client", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Errorf("status = %d, body = %q", w.Code, w.Body.String())
	}
}

// ---------- Rollback ----------

func TestBundleRoute_ClientCreateFailureRollsBackSAAndReturnsError(t *testing.T) {
	orgID := uuid.New()
	r, saRepo, _, _ := newBundleEngine(t, bundleOrgAdmin(orgID), errors.New("simulated"))
	body := strings.NewReader(`{"service_account":{"name":"ephemeral","role":"org_user"}}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/organizations/"+orgID.String()+"/service-accounts/with-client", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
	if len(saRepo.byID) != 0 {
		t.Errorf("rollback failed; SA rows remaining = %d", len(saRepo.byID))
	}
}
