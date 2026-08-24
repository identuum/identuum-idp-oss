package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/mw"
	"github.com/identuum/identuum-idp-oss/internal/repository"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// crossOrgClientRepo returns one fixed client regardless of the requested id,
// so its organization can be pinned for the cross-org refusal test.
type crossOrgClientRepo struct {
	repository.ClientRepository
	client *domain.Client
}

func (r crossOrgClientRepo) GetClientByID(context.Context, uuid.UUID) (*domain.Client, error) {
	return r.client, nil
}

// TestRequireClientInActorOrg_RefusesCrossOrg pins the org-admin client scope: an
// org_admin acting on a client that belongs to ANOTHER organization is refused
// with 404 (not-found, never a 403 that would confirm the client exists), while
// a site_admin carries no org filter and is allowed through.
// RULE: CLIENT-ORG-REFUSE-1
func TestRequireClientInActorOrg_RefusesCrossOrg(t *testing.T) {
	gin.SetMode(gin.TestMode)
	actorOrg := uuid.New()
	otherOrg := uuid.New()
	clientID := uuid.New()

	repo := crossOrgClientRepo{client: &domain.Client{ID: clientID, OrganizationID: &otherOrg}}
	deps := ClientsHandlerDeps{ClientService: service.NewClientService(nil, repo)}

	// org_admin of actorOrg acting on a client in otherOrg -> refused 404.
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
	mw.SetPrincipal(c, &domain.Principal{Role: domain.RoleOrgAdmin, OrganizationID: actorOrg})
	if ok := requireClientInActorOrg(c, deps, clientID); ok {
		t.Errorf("an org_admin acting on a cross-org client must be refused, got allowed")
	}
	if rec.Code != http.StatusNotFound {
		t.Errorf("a cross-org refusal must be 404, got %d", rec.Code)
	}

	// site_admin has no org filter -> allowed.
	rec2 := httptest.NewRecorder()
	c2, _ := gin.CreateTestContext(rec2)
	c2.Request = httptest.NewRequest(http.MethodGet, "/", nil)
	mw.SetPrincipal(c2, &domain.Principal{Role: domain.RoleSiteAdmin})
	if ok := requireClientInActorOrg(c2, deps, clientID); !ok {
		t.Errorf("a site_admin must be allowed (no org filter), got refused")
	}
}
