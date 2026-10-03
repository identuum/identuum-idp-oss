package handlers

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/mw"
	"github.com/identuum/identuum-idp-oss/internal/repository"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// regenerateRepo serves one client and fails Update with a storage error whose
// text must never reach the caller.
type regenerateRepo struct {
	repository.ClientRepository
	client    *domain.Client
	updateErr error
}

func (r regenerateRepo) GetClientByID(context.Context, uuid.UUID) (*domain.Client, error) {
	if r.client == nil {
		return nil, errors.New("no rows in result set")
	}
	cp := *r.client
	return &cp, nil
}

func (r regenerateRepo) Update(context.Context, *domain.Client) error { return r.updateErr }

func regenerate(t *testing.T, repo regenerateRepo, org uuid.UUID) *httptest.ResponseRecorder {
	t.Helper()
	gin.SetMode(gin.TestMode)
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	id := uuid.New()
	c.Request = httptest.NewRequest(http.MethodPost, "/", nil)
	c.Params = gin.Params{{Key: "id", Value: id.String()}}
	mw.SetPrincipal(c, &domain.Principal{Role: domain.RoleOrgAdmin, OrganizationID: org})
	HandleRegenerateClientSecret(ClientsHandlerDeps{ClientService: service.NewClientService(nil, repo)})(c)
	return rec
}

// The regenerate route answers with fixed messages: a storage failure is a
// 500 that carries no driver text, a public client is a 400, and nothing in
// the body comes from an internal error.
func TestRegenerateClientSecret_ErrorsCarryNoInternalText(t *testing.T) {
	org := uuid.New()
	internal := errors.New("failed to update client: SQLSTATE 08006 host db-internal user identuum_idp")

	rec := regenerate(t, regenerateRepo{
		client:    &domain.Client{ID: uuid.New(), OrganizationID: &org, ClientSecretHash: "h"},
		updateErr: internal,
	}, org)
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("a storage failure must be 500, got %d", rec.Code)
	}
	for _, leak := range []string{"SQLSTATE", "db-internal", "identuum_idp", "failed to update"} {
		if strings.Contains(rec.Body.String(), leak) {
			t.Errorf("response body carries internal text %q: %s", leak, rec.Body.String())
		}
	}

	rec = regenerate(t, regenerateRepo{
		client: &domain.Client{ID: uuid.New(), OrganizationID: &org},
	}, org)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("a public client must be 400, got %d", rec.Code)
	}
}
