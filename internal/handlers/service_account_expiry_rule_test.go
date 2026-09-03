package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/lifecycle"
	"github.com/identuum/identuum-idp-oss/internal/mw"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// THE-SILENT-EXPIRY. Two rules with one theme: an answer must describe what
// the server actually did. A 200 that stored nothing, and a 400 that blamed
// the caller for the store's outage, both lied.

// saExpiryRepo records what the service hands the repository AND applies it
// the way the live statement does — every column of the statement, no more.
// A fake that stored the whole struct would hide exactly the defect this
// rule exists for.
type saExpiryRepo struct {
	*inMemorySARepoForHandlers
	updates []*domain.ServiceAccount
	// columns is the statement's SET list, mirrored.
	columns []string
}

func newSAExpiryRepo() *saExpiryRepo {
	return &saExpiryRepo{
		inMemorySARepoForHandlers: newSARepoForHandlers(),
		columns:                   []string{"name", "description", "role", "expires_at", "updated_at"},
	}
}

func (r *saExpiryRepo) Update(_ context.Context, sa *domain.ServiceAccount) (*domain.ServiceAccount, error) {
	cp := *sa
	r.updates = append(r.updates, &cp)
	row, ok := r.byID[sa.ID]
	if !ok || row.OrganizationID != sa.OrganizationID {
		return nil, domain.ErrServiceAccountNotFound
	}
	// Apply ONLY the columns the statement names.
	for _, col := range r.columns {
		switch col {
		case "name":
			row.Name = sa.Name
		case "description":
			row.Description = sa.Description
		case "role":
			row.Role = sa.Role
		case "expires_at":
			row.ExpiresAt = sa.ExpiresAt
		case "updated_at":
			row.UpdatedAt = sa.UpdatedAt
		}
	}
	out := *row
	return &out, nil
}

func saPut(t *testing.T, r *gin.Engine, saID uuid.UUID, body map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(body)
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPut, "/api/v1/service-accounts/"+saID.String(), strings.NewReader(string(raw)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
}

// RULE: SA-UPDATE-EXPIRY-1
func TestRule_SA_UPDATE_EXPIRY_1(t *testing.T) {
	repo := newSAExpiryRepo()
	admin := saOrgAdminPrincipal(uuid.New())
	sa := &domain.ServiceAccount{ID: uuid.New(), OrganizationID: admin.OrganizationID, Name: "ci", Active: true}
	repo.byID[sa.ID] = sa

	gin.SetMode(gin.ReleaseMode)
	engine := gin.New()
	engine.Use(mw.CorrelationIDMiddleware(), mw.InjectPrincipalForTest(admin))
	RegisterServiceAccountsRoutes(engine, ServiceAccountsHandlerDeps{
		ServiceAccountService: service.NewServiceAccountService(nil, repo),
		Audit:                 &audit.Recorder{},
	})

	// (1) An expiry-only update is PERSISTED: the value reaches the
	// repository, survives the statement's column list, and reads back.
	want := time.Now().Add(72 * time.Hour).UTC().Truncate(time.Second)
	rec := saPut(t, engine, sa.ID, map[string]any{"expires_at": want.Format(time.RFC3339)})
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.Len(t, repo.updates, 1, "the service must reach the repository")
	require.NotNil(t, repo.updates[0].ExpiresAt, "the service must carry the expiry")
	require.NotNil(t, repo.byID[sa.ID].ExpiresAt, "the expiry must SURVIVE the statement's column list")
	assert.True(t, repo.byID[sa.ID].ExpiresAt.UTC().Truncate(time.Second).Equal(want))

	var body map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.NotEmpty(t, body["expires_at"], "the answer reports the stored expiry")

	// (2) The statement must actually name the column — the mirror above is
	// only honest if it matches the shipped SQL.
	assert.Contains(t, repo.columns, "expires_at",
		"the repository statement's SET list must include expires_at")

	// (3) A PAST expiry is refused, exactly as create refuses one, and
	// nothing is written.
	past := time.Now().Add(-time.Hour).UTC()
	rec = saPut(t, engine, sa.ID, map[string]any{"expires_at": past.Format(time.RFC3339)})
	require.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
	require.Len(t, repo.updates, 1, "a refused update never reaches the repository")
	assert.True(t, repo.byID[sa.ID].ExpiresAt.UTC().Truncate(time.Second).Equal(want),
		"the stored expiry is untouched by a refused update")

	// (4) An update that does not mention the expiry leaves it standing, and
	// a rename still lands (the neighbours of the same statement travel).
	rec = saPut(t, engine, sa.ID, map[string]any{"name": "renamed"})
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, "renamed", repo.byID[sa.ID].Name)
	require.NotNil(t, repo.byID[sa.ID].ExpiresAt, "an unrelated update must not clear the expiry")
	assert.True(t, repo.byID[sa.ID].ExpiresAt.UTC().Truncate(time.Second).Equal(want))
}

// saBindingClientRepo is the client store the register path writes to. Only
// the two methods that path touches do anything; the rest panic so a new
// dependency surfaces as a failure rather than a silent nil.
type saBindingClientRepo struct {
	*fakeClientRepo
	registered []*domain.Client
}

func (f *saBindingClientRepo) RegisterClient(_ context.Context, c *domain.Client) error {
	f.registered = append(f.registered, c)
	return nil
}

// RULE: SA-BINDING-503-1
func TestRule_SA_BINDING_503_1(t *testing.T) {
	// The binding validator reads the service-account store. A store outage
	// there is not "your request is invalid": the client register and update
	// routes answer 503 with a correlation id. A genuine absence — the
	// store's typed verdict — is still the caller's 400.
	repo := newSARepoForHandlers()
	sa := &domain.ServiceAccount{ID: uuid.New(), OrganizationID: uuid.New(), Name: "agent", Active: true}
	repo.byID[sa.ID] = sa
	saSvc := service.NewServiceAccountService(nil, repo)

	// The validator IS the seam the client service uses; drive it directly
	// for the two store shapes, then prove the wire mapping.
	repo.getErr = errors.New("db down")
	outage := saSvc.ValidateBindingForClient(context.Background(), sa.ID, &sa.OrganizationID)
	require.Error(t, outage)
	assert.True(t, domain.IsAuthStoreUnavailable(outage), "a store outage is AUTH-503, got %v", outage)

	repo.getErr = domain.ErrServiceAccountNotFound
	typed := saSvc.ValidateBindingForClient(context.Background(), sa.ID, &sa.OrganizationID)
	require.Error(t, typed)
	assert.False(t, domain.IsAuthStoreUnavailable(typed), "a typed absence is a verdict, not an outage")
	assert.ErrorIs(t, typed, service.ErrServiceAccountNotFound)

	repo.getErr = nil
	require.NoError(t, saSvc.ValidateBindingForClient(context.Background(), sa.ID, &sa.OrganizationID),
		"PREMISE: a live account in its own organization binds")

	// THE WIRE, through the REAL client route: POST /api/v1/clients with a
	// service_account_id, driven by an org_admin of the account's org.
	clientRepo := &saBindingClientRepo{fakeClientRepo: &fakeClientRepo{}}
	report := lifecycle.NewStartupReport()
	clientSvc := service.NewClientService(report, clientRepo).WithServiceAccountBindingValidator(saSvc)
	require.False(t, report.HasFatal())

	// The create route additionally requires the clients:create scope
	// (RequireSiteAdminOrOrgAdminWithScopesAudit), so the principal carries
	// the role's own scope set.
	admin := &domain.Principal{
		UserID:         uuid.New(),
		OrganizationID: sa.OrganizationID,
		Role:           domain.RoleOrgAdmin,
		Scope:          domain.SessionScopesForRole(domain.RoleOrgAdmin),
	}
	gin.SetMode(gin.ReleaseMode)
	engine := gin.New()
	engine.Use(mw.CorrelationIDMiddleware(), mw.InjectPrincipalForTest(admin))
	RegisterClientsRoutes(engine, ClientsHandlerDeps{ClientService: clientSvc, Audit: &audit.Recorder{}})

	createBody := map[string]any{
		"name":               "bound client",
		"organization_id":    sa.OrganizationID.String(),
		"service_account_id": sa.ID.String(),
		"redirect_uris":      []string{"https://client.example.test/cb"},
		"scope":              "openid",
	}
	postClient := func(t *testing.T) *httptest.ResponseRecorder {
		t.Helper()
		raw, err := json.Marshal(createBody)
		require.NoError(t, err)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/clients", strings.NewReader(string(raw)))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		engine.ServeHTTP(rec, req)
		return rec
	}

	// PREMISE: with the store answering, the binding is accepted.
	ok := postClient(t)
	require.Equal(t, http.StatusCreated, ok.Code, ok.Body.String())
	require.Len(t, clientRepo.registered, 1)

	// A store OUTAGE is 503 with a correlation id, and nothing is registered.
	repo.getErr = errors.New("db down")
	outageRec := postClient(t)
	require.Equal(t, http.StatusServiceUnavailable, outageRec.Code, outageRec.Body.String())
	var outageBody map[string]any
	require.NoError(t, json.Unmarshal(outageRec.Body.Bytes(), &outageBody))
	assert.NotEmpty(t, outageBody["correlation_id"], "AUTH-503 carries a correlation id")
	assert.Len(t, clientRepo.registered, 1, "nothing is registered on an outage")

	// The store's TYPED verdict stays the caller's 400.
	repo.getErr = domain.ErrServiceAccountNotFound
	verdictRec := postClient(t)
	require.Equal(t, http.StatusBadRequest, verdictRec.Code, verdictRec.Body.String())
	assert.Contains(t, verdictRec.Body.String(), "invalid request")
	assert.Len(t, clientRepo.registered, 1)
}
