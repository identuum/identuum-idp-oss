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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/lifecycle"
	"github.com/identuum/identuum-idp-oss/internal/mw"
	"github.com/identuum/identuum-idp-oss/internal/repository"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// boundStoreDownClientRepo fails the bound create the way the store does when
// the database cannot begin, lock or commit (OSS-0913-O9-FIX).
type boundStoreDownClientRepo struct {
	saBindingClientRepo
	boundCalls int
}

func (f *boundStoreDownClientRepo) RegisterClientBound(context.Context, *domain.Client, repository.ServiceAccountLock) error {
	f.boundCalls++
	return domain.AuthStoreUnavailable("register client bound", errors.New("db down"))
}

// OSS-0913-O9-FIX-REVIEW N2: a store failure on a bound create answers 503
// with Retry-After, not 400, and nothing is registered.
func TestCreateClient_BoundCreateStoreFailureAnswers503(t *testing.T) {
	saRepo := newSARepoForHandlers()
	sa := &domain.ServiceAccount{ID: uuid.New(), OrganizationID: uuid.New(), Name: "agent", Active: true}
	saRepo.byID[sa.ID] = sa
	saSvc := service.NewServiceAccountService(nil, saRepo)

	clientRepo := &boundStoreDownClientRepo{saBindingClientRepo: saBindingClientRepo{fakeClientRepo: &fakeClientRepo{}}}
	report := lifecycle.NewStartupReport()
	clientSvc := service.NewClientService(report, clientRepo).WithServiceAccountBindingValidator(saSvc)
	require.False(t, report.HasFatal())

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

	raw, err := json.Marshal(map[string]any{
		"name":               "bound client",
		"organization_id":    sa.OrganizationID.String(),
		"service_account_id": sa.ID.String(),
		"redirect_uris":      []string{"https://client.example.test/cb"},
		"scope":              "openid",
	})
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/clients", strings.NewReader(string(raw)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	engine.ServeHTTP(rec, req)

	require.Equal(t, 1, clientRepo.boundCalls, "PREMISE: a create with a live service account takes the bound path")
	require.Equal(t, http.StatusServiceUnavailable, rec.Code, rec.Body.String())
	assert.Equal(t, "1", rec.Header().Get("Retry-After"))
	var body map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.Equal(t, "temporarily_unavailable", body["error"])
	assert.NotEmpty(t, body["correlation_id"])
	assert.Empty(t, clientRepo.registered, "nothing is registered")
}
