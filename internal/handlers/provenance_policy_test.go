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
	"github.com/identuum/identuum-idp-oss/internal/repository"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// runHandlerAs mirrors runHandler with a caller-chosen principal — the
// provenance assertion needs to KNOW the actor's id, and the policy
// assertions need an org_admin inside the target org.
func runHandlerAs(t *testing.T, p *domain.Principal, method, route, path, body string, h gin.HandlerFunc) int {
	t.Helper()
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(mw.InjectPrincipalForTest(p))
	r.Handle(method, route, h)
	req := httptest.NewRequest(method, path, bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec.Code
}

// provenanceKeyRepo records the signing key that reaches persistence.
// Only CreateSigningKey is exercised by KeyService.Generate; the
// embedded nil interface loudly panics on anything else.
type provenanceKeyRepo struct {
	repository.KeyRepository
	created *domain.SigningKey
}

func (r *provenanceKeyRepo) CreateSigningKey(_ context.Context, key *domain.SigningKey) error {
	r.created = key
	return nil
}

// RULE: PROVENANCE-POLICY-1
func TestProvenanceAndOrgPolicyReachTheService(t *testing.T) {
	// simplepassword: ≥8 chars, lowercase-only — PASSES relaxed
	// complexity, FAILS strict (needs upper+digit+special). The
	// discriminating observable for the policy plumbing.
	const relaxedOnlyPassword = "simplepassword"

	t.Run("generated signing key carries the authenticated principal as created_by", func(t *testing.T) {
		actor := &domain.Principal{UserID: uuid.New(), Role: domain.RoleSiteAdmin}
		repo := &provenanceKeyRepo{}
		deps := KeysHandlerDeps{Audit: audit.NoopService{}, KeyService: service.NewKeyService(repo)}
		code := runHandlerAs(t, actor, http.MethodPost, "/k", "/k", `{"algorithm":"EdDSA"}`, HandleGenerateSigningKey(deps))
		if code != http.StatusCreated {
			t.Fatalf("generate status = %d, want 201", code)
		}
		if repo.created == nil {
			t.Fatal("no key reached persistence")
		}
		if repo.created.CreatedBy == nil {
			t.Fatal("stored key has BLANK provenance — created_by must carry the authenticated principal")
		}
		if *repo.created.CreatedBy != actor.UserID {
			t.Fatalf("created_by = %s, want the authenticated principal %s", *repo.created.CreatedBy, actor.UserID)
		}
	})

	orgAdminIn := func(orgID uuid.UUID) *domain.Principal {
		return &domain.Principal{UserID: uuid.New(), OrganizationID: orgID, Role: domain.RoleOrgAdmin}
	}
	relaxedOrgFixture := func(t *testing.T) (uuid.UUID, *memOrgRepo, *memUserRepo) {
		t.Helper()
		orgID := uuid.New()
		orgs := newMemOrgRepo()
		if _, err := orgs.Create(context.Background(), &domain.Organization{
			ID: orgID, Name: "Relaxed", Active: true, PasswordComplexityEnabled: false,
		}); err != nil {
			t.Fatal(err)
		}
		return orgID, orgs, newMemUserRepo()
	}

	t.Run("create honors the target org's relaxed complexity policy", func(t *testing.T) {
		orgID, orgs, users := relaxedOrgFixture(t)
		deps := UsersHandlerDeps{Audit: audit.NoopService{}, UserService: service.NewUserService(nil, users), PolicyOrgs: orgs}
		code := runHandlerAs(t, orgAdminIn(orgID), http.MethodPost, "/u", "/u",
			`{"email":"a@relaxed.test","password":"`+relaxedOnlyPassword+`","role":"org_user"}`, HandleCreateUser(deps))
		if code != http.StatusCreated {
			t.Fatalf("create status = %d, want 201 — the org's relaxed policy did not reach the service", code)
		}
	})

	t.Run("bulk create honors the target org's relaxed complexity policy", func(t *testing.T) {
		orgID, orgs, users := relaxedOrgFixture(t)
		deps := UsersHandlerDeps{Audit: audit.NoopService{}, UserService: service.NewUserService(nil, users), PolicyOrgs: orgs}
		// Bulk is best-effort 200 with per-row results — the ROW
		// outcome is the observable, not the status.
		gin.SetMode(gin.ReleaseMode)
		r := gin.New()
		r.Use(mw.InjectPrincipalForTest(orgAdminIn(orgID)))
		r.Handle(http.MethodPost, "/u/bulk", HandleBulkCreateUsers(deps))
		req := httptest.NewRequest(http.MethodPost, "/u/bulk",
			bytes.NewReader([]byte(`{"users":[{"email":"b@relaxed.test","password":"`+relaxedOnlyPassword+`","role":"org_user"}]}`)))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("bulk status = %d, want 200", rec.Code)
		}
		var body struct {
			Created []map[string]any `json:"created"`
			Failed  []map[string]any `json:"failed"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("decode bulk response: %v", err)
		}
		if len(body.Created) != 1 || len(body.Failed) != 0 {
			t.Fatalf("bulk row outcome created=%d failed=%d (%s) — the org's relaxed policy did not reach the per-row service call",
				len(body.Created), len(body.Failed), rec.Body.String())
		}
	})

	t.Run("update password honors the TARGET user's org policy", func(t *testing.T) {
		orgID, orgs, users := relaxedOrgFixture(t)
		target := &domain.User{ID: uuid.New(), OrganizationID: orgID, Role: domain.RoleOrgUser, Email: "c@relaxed.test"}
		if _, err := users.Create(context.Background(), target); err != nil {
			t.Fatal(err)
		}
		deps := UsersHandlerDeps{
			Audit:               audit.NoopService{},
			UserService:         service.NewUserService(nil, users),
			SessionRevoker:      service.NoopSessionRevoker{},
			RefreshTokenRevoker: service.NoopRefreshTokenRevoker{},
			PolicyOrgs:          orgs,
		}
		code := runHandlerAs(t, orgAdminIn(orgID), http.MethodPut, "/u/:id", "/u/"+target.ID.String(),
			`{"password":"`+relaxedOnlyPassword+`"}`, HandleUpdateUser(deps))
		if code != http.StatusOK {
			t.Fatalf("update status = %d, want 200 — the target org's relaxed policy did not reach the service", code)
		}
	})
}
