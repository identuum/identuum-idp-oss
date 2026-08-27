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

// honestRefusalCall runs a handler as the given principal and returns
// status + decoded body — the refusal SHAPE is the subject here.
func honestRefusalCall(t *testing.T, p *domain.Principal, method, route, path, body string, h gin.HandlerFunc) (int, map[string]any) {
	t.Helper()
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(mw.InjectPrincipalForTest(p))
	r.Handle(method, route, h)
	req := httptest.NewRequest(method, path, bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

// RULE: HONEST-REFUSAL-1
func TestRefusalShapesTellTheTruth(t *testing.T) {
	// Strict policy is the default (no PolicyOrgs wired); this password
	// passes relaxed and fails strict — the live matrix's discriminator.
	const weak = "simplepassword"
	orgID := uuid.New()
	orgAdmin := &domain.Principal{UserID: uuid.New(), OrganizationID: orgID, Role: domain.RoleOrgAdmin}
	newDeps := func(users *memUserRepo) UsersHandlerDeps {
		return UsersHandlerDeps{
			Audit:               audit.NoopService{},
			UserService:         service.NewUserService(nil, users),
			SessionRevoker:      service.NoopSessionRevoker{},
			RefreshTokenRevoker: service.NoopRefreshTokenRevoker{},
		}
	}
	seedUser := func(users *memUserRepo, org uuid.UUID) *domain.User {
		u := &domain.User{ID: uuid.New(), OrganizationID: org, Role: domain.RoleOrgUser, Email: "t@refusal.test"}
		if _, err := users.Create(context.Background(), u); err != nil {
			t.Fatal(err)
		}
		return u
	}

	t.Run("policy-refused password change answers 400 weak_password, not 404", func(t *testing.T) {
		users := newMemUserRepo()
		target := seedUser(users, orgID)
		code, body := honestRefusalCall(t, orgAdmin, http.MethodPut, "/u/:id", "/u/"+target.ID.String(),
			`{"password":"`+weak+`"}`, HandleUpdateUser(newDeps(users)))
		if code != http.StatusBadRequest {
			t.Fatalf("policy refusal status = %d, want 400 (the 404 lie the live matrix caught)", code)
		}
		if body["error"] != "weak_password" {
			t.Fatalf("policy refusal error = %v, want weak_password", body["error"])
		}
		if msg, _ := body["message"].(string); msg == "" {
			t.Fatal("weak_password must carry the displayable policy text")
		}
	})

	t.Run("a genuinely missing user still answers 404", func(t *testing.T) {
		users := newMemUserRepo()
		code, body := honestRefusalCall(t, orgAdmin, http.MethodPut, "/u/:id", "/u/"+uuid.NewString(),
			`{"password":"`+weak+`"}`, HandleUpdateUser(newDeps(users)))
		if code != http.StatusNotFound || body["error"] == "weak_password" {
			t.Fatalf("missing user = %d %v, want plain 404 not-found", code, body)
		}
	})

	t.Run("RG10 intact: a FOREIGN target with a weak password is a plain miss, never weak_password", func(t *testing.T) {
		users := newMemUserRepo()
		foreign := seedUser(users, uuid.New()) // exists, someone else's org
		code, body := honestRefusalCall(t, orgAdmin, http.MethodPut, "/u/:id", "/u/"+foreign.ID.String(),
			`{"password":"`+weak+`"}`, HandleUpdateUser(newDeps(users)))
		if code != http.StatusNotFound || body["error"] == "weak_password" {
			t.Fatalf("foreign probe = %d %v — weak_password here would be an existence oracle", code, body)
		}
	})

	t.Run("bulk per-row reason names the policy failure class", func(t *testing.T) {
		users := newMemUserRepo()
		code, body := honestRefusalCall(t, orgAdmin, http.MethodPost, "/u/bulk", "/u/bulk",
			`{"users":[{"email":"w@refusal.test","password":"`+weak+`","role":"org_user"}]}`,
			HandleBulkCreateUsers(newDeps(users)))
		if code != http.StatusOK {
			t.Fatalf("bulk envelope = %d, want the best-effort 200", code)
		}
		failed, _ := body["failed"].([]any)
		if len(failed) != 1 {
			t.Fatalf("failed rows = %d, want 1 (%v)", len(failed), body)
		}
		row, _ := failed[0].(map[string]any)
		if row["reason"] != "weak_password" {
			t.Fatalf("per-row reason = %v, want weak_password (the generic collapse the live matrix caught)", row["reason"])
		}
	})
}
