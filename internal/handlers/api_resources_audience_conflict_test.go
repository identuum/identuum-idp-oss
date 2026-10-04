package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/mw"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// H7: creating an API resource whose audience another resource already holds is
// an honest 409 (as the update already is), and an audience the issuer or an
// application owns is a 400 the caller can read — not a bare "invalid request".

type takenAudienceRepo struct{ *memAPIResourceRepo }

func (takenAudienceRepo) Create(context.Context, *domain.APIResource, []domain.APIScope) error {
	return domain.ErrAPIResourceAlreadyExists
}

func createResourceBody(t *testing.T, svc *service.APIResourceService) (int, map[string]any) {
	t.Helper()
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(mw.InjectPrincipalForTest(tenantAdminOf(uuid.New())))
	RegisterAPIResourcesRoutes(r, APIResourcesHandlerDeps{APIResourceService: svc, Audit: &audit.Recorder{}})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/api-resources", bytes.NewReader([]byte(`{"name":"r","audience":"https://a.example.test"}`)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

func TestCreateAPIResource_TakenAudienceIs409(t *testing.T) {
	svc := service.NewAPIResourceService(nil, takenAudienceRepo{newMemAPIResourceRepo()})
	if st, m := createResourceBody(t, svc); st != http.StatusConflict || m["error"] != "audience_exists" {
		t.Errorf("= %d %v; want 409 audience_exists", st, m)
	}
}

func TestCreateAPIResource_ReservedAudienceIs400WithAReason(t *testing.T) {
	svc := service.NewAPIResourceService(nil, newMemAPIResourceRepo()).
		WithReservedAudiences(func(context.Context, string) (bool, error) { return true, nil })
	st, m := createResourceBody(t, svc)
	if st != http.StatusBadRequest || m["error"] != "invalid request" || m["message"] == nil {
		t.Errorf("= %d %v; want 400 invalid request with a message", st, m)
	}
}
