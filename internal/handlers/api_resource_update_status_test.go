package handlers

import (
	"context"
	"net/http"
	"testing"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/repository"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// statusAPIResourceRepo is the minimum repository the update path touches.
// The embedded interface is nil on purpose: a method this test does not stub
// is one a REFUSED update must never reach, and a nil dereference names it.
type statusAPIResourceRepo struct {
	repository.APIResourceRepository
	stored      domain.APIResource
	updateCalls int
}

func (r *statusAPIResourceRepo) GetByID(_ context.Context, _ uuid.UUID, _ *uuid.UUID) (*domain.APIResource, error) {
	c := r.stored
	return &c, nil
}

func (r *statusAPIResourceRepo) Update(_ context.Context, _ *domain.APIResource) error {
	r.updateCalls++
	return nil
}

func (r *statusAPIResourceRepo) UpdateWithScopes(_ context.Context, _ *domain.APIResource, _ []domain.APIScope) error {
	r.updateCalls++
	return nil
}

// THE-UNVALIDATED-REST (2026-08-31): APIResourceService.Update already
// validated correctly — resource.Validate() and domain.ValidateAPIScopes both
// run before any write (P2-16) — but HandleUpdateAPIResource's switch had no
// branch for a validation error, so every refusal fell to the default and
// answered 500 internal_error. The guard was right; only the status lied.
//
// Run through the REAL handler over the REAL service, so the test fails
// whether the 400 mapping is removed OR the service stops refusing.
//
// RULE: API-RESOURCE-REFUSAL-STATUS-1
func TestAPIResourceUpdateStatus_RefusalIsBadRequestNotInternalError(t *testing.T) {
	orgID := uuid.New()
	resID := uuid.New()
	actor := &domain.Principal{
		UserID:         uuid.New(),
		OrganizationID: orgID,
		Role:           domain.RoleOrgAdmin,
	}

	newFixture := func() (*statusAPIResourceRepo, APIResourcesHandlerDeps) {
		repo := &statusAPIResourceRepo{stored: domain.APIResource{
			ID:             resID,
			OrganizationID: orgID,
			Name:           "Billing API",
			Audience:       "https://billing.example.test",
			TokenTTLSecs:   3600,
			Active:         true,
		}}
		return repo, APIResourcesHandlerDeps{
			Audit:              audit.NoopService{},
			APIResourceService: service.NewAPIResourceService(nil, repo),
		}
	}

	for _, bad := range []struct {
		why  string
		body string
	}{
		{"a blank name", `{"name":"","audience":"https://billing.example.test","token_ttl_secs":3600}`},
		{"a blank audience", `{"name":"Billing API","audience":"","token_ttl_secs":3600}`},
		{"a zero token TTL", `{"name":"Billing API","audience":"https://billing.example.test","token_ttl_secs":0}`},
		{"a negative token TTL", `{"name":"Billing API","audience":"https://billing.example.test","token_ttl_secs":-5}`},
		{"a reserved scope prefix", `{"name":"Billing API","audience":"https://billing.example.test","token_ttl_secs":3600,"scopes":[{"name":"system:root"}]}`},
	} {
		repo, deps := newFixture()
		code := runHandlerAs(t, actor, http.MethodPut, "/r/:id", "/r/"+resID.String(),
			bad.body, HandleUpdateAPIResource(deps))
		if code == http.StatusInternalServerError {
			t.Errorf("%s answered 500 — a bad request reported as a server fault", bad.why)
		} else if code != http.StatusBadRequest {
			t.Errorf("%s answered %d, want 400", bad.why, code)
		}
		if repo.updateCalls != 0 {
			t.Errorf("%s: the refused update still reached the repository %d time(s)", bad.why, repo.updateCalls)
		}
	}

	// ── CONTROL: a legitimate update still lands, so a handler that answered
	// 400 for everything would not pass this test ──
	repo, deps := newFixture()
	if code := runHandlerAs(t, actor, http.MethodPut, "/r/:id", "/r/"+resID.String(),
		`{"name":"Billing API v2","audience":"https://billing.example.test","token_ttl_secs":7200}`,
		HandleUpdateAPIResource(deps)); code != http.StatusOK {
		t.Errorf("a well-formed update answered %d, want 200", code)
	}
	if repo.updateCalls != 1 {
		t.Errorf("the accepted update reached the repository %d time(s), want 1", repo.updateCalls)
	}
}
