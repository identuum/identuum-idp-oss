package handlers

import (
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

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/repository"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// claimRepoOnce is a single-claim repository.ClaimRepository: GetByTokenHash
// returns the claim until Delete burns it, after which it returns nil — exactly
// the single-use semantics the service relies on.
type claimRepoOnce struct {
	repository.ClaimRepository
	mu     sync.Mutex
	claim  *domain.OrganizationClaim
	burned bool
}

func (r *claimRepoOnce) GetByTokenHash(context.Context, string) (*domain.OrganizationClaim, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.burned {
		return nil, nil
	}
	return r.claim, nil
}

func (r *claimRepoOnce) Delete(_ context.Context, _ uuid.UUID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.burned {
		return context.Canceled // a second burn removes nothing (the loser)
	}
	r.burned = true
	return nil
}

func (r *claimRepoOnce) IncrementAttemptCount(_ context.Context, _ uuid.UUID) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.claim.AttemptCount++
	return r.claim.AttemptCount, nil
}

type claimOrgLookup struct{ org *domain.Organization }

func (o claimOrgLookup) GetByID(context.Context, uuid.UUID) (*domain.Organization, error) {
	return o.org, nil
}

type claimUserCreatorSpy struct {
	mu      sync.Mutex
	created int
}

func (u *claimUserCreatorSpy) Create(_ context.Context, user *domain.User) (*domain.User, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.created++
	return user, nil
}

func (u *claimUserCreatorSpy) count() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.created
}

type claimExistsNone struct{}

func (claimExistsNone) FindUsersByEmail(context.Context, string) ([]*domain.User, error) {
	return nil, nil
}

// A claim link is consumable EXACTLY ONCE: GET /claim/validate is read-only (it
// never burns the claim, so a consume right after a validate still succeeds),
// and POST /claim burns-before-write so a replay after a successful consume
// mints no second org_admin and reports failure. Driven through the ROUTED
// handlers (HandleValidateClaim/HandleConsumeClaim) over a real ClaimService.
// RULE: CLAIM-CONSUME-ONCE-1
func TestClaim_ConsumableExactlyOnce(t *testing.T) {
	orgID := uuid.New()
	users := &claimUserCreatorSpy{}
	repo := &claimRepoOnce{claim: &domain.OrganizationClaim{
		ID: uuid.New(), OrganizationID: orgID, ExpiresAt: time.Now().Add(time.Hour),
	}}
	svc := service.NewClaimService(service.ClaimServiceConfig{
		Claims: repo,
		Orgs:   claimOrgLookup{org: &domain.Organization{ID: orgID, Active: false, Name: "Acme"}},
		Users:  users,
		Exists: claimExistsNone{},
	})

	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	RegisterAccountLifecycleRoutes(r, AccountLifecycleHandlerDeps{Claim: svc})

	validate := func() (code int, valid bool) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/claim/validate?token=rawtok", nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		var body struct {
			Valid bool `json:"valid"`
		}
		_ = json.Unmarshal(w.Body.Bytes(), &body)
		return w.Code, body.Valid
	}
	consume := func() (code int, success bool) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/claim",
			strings.NewReader(`{"token":"rawtok","email":"admin@acme.test","name":"A","password":"SuperSecret123!x"}`))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		var body struct {
			Success bool `json:"success"`
		}
		_ = json.Unmarshal(w.Body.Bytes(), &body)
		return w.Code, body.Success
	}

	// Validate is read-only: it reports the live claim and does NOT burn it.
	if code, valid := validate(); code != http.StatusOK || !valid {
		t.Fatalf("PREMISE FAILED: validate of a live claim must be 200+valid, got %d valid=%v", code, valid)
	}
	// Consume right after validate still succeeds (proves validate did not consume).
	if code, ok := consume(); code != http.StatusOK || !ok {
		t.Fatalf("consume after validate must succeed (validate must be read-only), got %d success=%v", code, ok)
	}
	if n := users.count(); n != 1 {
		t.Fatalf("a successful consume must mint exactly one org_admin, got %d", n)
	}
	// Replay: a second consume of the burned claim mints NO second admin.
	if _, ok := consume(); ok {
		t.Errorf("a replayed claim must not consume twice")
	}
	if n := users.count(); n != 1 {
		t.Errorf("a replayed claim must mint no second org_admin, but Create ran %d times", n)
	}
	// The burned claim no longer validates.
	if _, valid := validate(); valid {
		t.Errorf("a consumed claim must no longer validate")
	}
}
