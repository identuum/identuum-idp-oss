package handlers

import (
	"context"
	"errors"
	"fmt"
	"net/http"
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

// O3 + O4 (OSS-0913-A, D10): handler-level answers of PUT /api/v1/clients/:id
// for the two locked-save failures the service already returns. O3: a service
// account changed during the save answers 400 invalid_request with a plain
// reason. O4: a save whose lock, write or commit fails answers 503 and nothing
// is audited as updated.

// failingMutateRepo answers every locked save with err and writes nothing.
type failingMutateRepo struct {
	*memClientRepo
	err error
}

func (r *failingMutateRepo) MutateClient(context.Context, uuid.UUID, *repository.ServiceAccountLock, func(*domain.Client) error) (*domain.Client, *domain.Client, error) {
	return nil, nil, r.err
}

func newFailingMutateEngine(t *testing.T, err error) skipConsentEngine {
	t.Helper()
	gin.SetMode(gin.ReleaseMode)
	admin := tenantAdminOf(uuid.New())
	r := gin.New()
	r.Use(mw.InjectPrincipalForTest(admin))
	repo := &failingMutateRepo{memClientRepo: newMemClientRepo(), err: err}
	rec := &audit.Recorder{}
	RegisterClientsRoutes(r, ClientsHandlerDeps{
		ClientService:      service.NewClientService(nil, repo),
		Audit:              rec,
		ClientTokenRevoker: &fakeClientTokenRevoker{},
		SkipConsentProver:  &fakeSkipConsentProver{},
	})
	return skipConsentEngine{r: r, repo: repo.memClientRepo, rec: rec, admin: admin}
}

func TestUpdateClient_ServiceAccountChangedDuringSaveAnswers400(t *testing.T) {
	e := newFailingMutateEngine(t, fmt.Errorf("the service account was deactivated; %w", service.ErrServiceAccountChangedDuringSave))
	id := e.seedClient(false, false)

	st, m := e.do(t, http.MethodPut, "/api/v1/clients/"+id.String(), `{"name":"renamed"}`)
	if st != http.StatusBadRequest || m["error"] != "invalid_request" {
		t.Fatalf("O3: = %d %v; want 400 invalid_request", st, m)
	}
	if d, _ := m["error_description"].(string); !strings.Contains(d, "deactivated") {
		t.Errorf("O3: error_description %q; want the plain reason", d)
	}
	if n := len(updatedEvents(e.rec, "client.updated")); n != 0 {
		t.Errorf("O3: client.updated events=%d; want none", n)
	}
}

func TestUpdateClient_StoreFailureAnswers503(t *testing.T) {
	e := newFailingMutateEngine(t, domain.AuthStoreUnavailable("client.mutate", errors.New("commit failed")))
	id := e.seedClient(false, false)

	st, m := e.do(t, http.MethodPut, "/api/v1/clients/"+id.String(), `{"name":"renamed"}`)
	if st != http.StatusServiceUnavailable {
		t.Fatalf("O4: = %d %v; want 503", st, m)
	}
	if e.repo.rows[id].Name != "app" {
		t.Errorf("O4: stored name %q; want unchanged", e.repo.rows[id].Name)
	}
	if n := len(updatedEvents(e.rec, "client.updated")); n != 0 {
		t.Errorf("O4: client.updated events=%d; want none", n)
	}
}
