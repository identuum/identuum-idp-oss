package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/repository"
)

const bulkValidPassword = "Password-Sentinel-Must-Not-Leak-1!"

func bulkOrgAdminEngine(t *testing.T, org uuid.UUID, scope string) tenantEngine {
	return newTenantEngine(t, &domain.Principal{
		UserID:         uuid.New(),
		OrganizationID: org,
		Role:           domain.RoleOrgAdmin,
		Scope:          scope,
	})
}

func bulkPersistedCount(eng tenantEngine) int {
	all, _, _ := eng.userRepo.List(context.Background(), repository.ListUserOptions{})
	return len(all)
}

// (a) A valid batch creates every user through the single-create path,
// returns per-item created (safe projection), persists them, and mints a
// UUIDv7 id for each. No plaintext password is echoed.
func TestBulkCreate_ValidBatch_AllCreated(t *testing.T) {
	org := uuid.New()
	eng := bulkOrgAdminEngine(t, org, "users:create")
	body := map[string]any{"users": []map[string]any{
		{"email": "a@t.test", "password": bulkValidPassword, "role": "org_user"},
		{"email": "b@t.test", "password": bulkValidPassword, "role": "org_user"},
		{"email": "c@t.test", "password": bulkValidPassword, "role": "org_user"},
	}}
	rec := tenantReq(t, eng, http.MethodPost, "/api/v1/users/bulk", body)
	if rec.Code == http.StatusNotImplemented {
		t.Fatalf("bulk still returns 501 — the OSS port did not take effect")
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var resp bulkCreateUsersResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.CreatedCount != 3 || len(resp.Created) != 3 || resp.FailedCount != 0 {
		t.Fatalf("created=%d failed=%d, want 3/0; body=%s", resp.CreatedCount, resp.FailedCount, rec.Body.String())
	}
	for _, u := range resp.Created {
		if u.OrganizationID != org {
			t.Errorf("created in org %s, want %s (org_admin own-org enforcement)", u.OrganizationID, org)
		}
		if u.ID == uuid.Nil {
			t.Errorf("created id is nil")
		}
		if u.ID.Version() != 7 {
			t.Errorf("created id %s is UUID v%d, want v7 (uuidgen.NewV7)", u.ID, u.ID.Version())
		}
	}
	if strings.Contains(rec.Body.String(), bulkValidPassword) {
		t.Errorf("bulk response leaked the plaintext password")
	}
	if got := bulkPersistedCount(eng); got != 3 {
		t.Errorf("persisted %d users, want 3", got)
	}
}

// (b) Best-effort: an invalid row (weak password) does not abort the
// batch — the valid rows are created and persisted, the invalid row is
// reported per-item, and succeeded rows are NOT rolled back.
func TestBulkCreate_BestEffort_PartialFailure(t *testing.T) {
	org := uuid.New()
	eng := bulkOrgAdminEngine(t, org, "users:create")
	body := map[string]any{"users": []map[string]any{
		{"email": "ok1@t.test", "password": bulkValidPassword, "role": "org_user"},
		{"email": "bad@t.test", "password": "x", "role": "org_user"}, // weak → fails validation
		{"email": "ok2@t.test", "password": bulkValidPassword, "role": "org_user"},
	}}
	rec := tenantReq(t, eng, http.MethodPost, "/api/v1/users/bulk", body)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var resp bulkCreateUsersResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.CreatedCount != 2 || resp.FailedCount != 1 {
		t.Fatalf("created=%d failed=%d, want 2/1 (best-effort)", resp.CreatedCount, resp.FailedCount)
	}
	f := resp.Failed[0]
	if f.Index != 1 || f.Email != "bad@t.test" || f.Reason == "" {
		t.Errorf("failed item = %+v, want {index:1, email:bad@t.test, reason:non-empty}", f)
	}
	// Succeeded rows are NOT rolled back.
	if got := bulkPersistedCount(eng); got != 2 {
		t.Errorf("persisted %d, want 2 (succeeded not rolled back)", got)
	}
}

// (c) Cap: a batch >50 (or empty) is rejected whole (400) before any row
// is created.
func TestBulkCreate_Over50_Rejected(t *testing.T) {
	org := uuid.New()
	eng := bulkOrgAdminEngine(t, org, "users:create")
	users := make([]map[string]any, 51)
	for i := range users {
		users[i] = map[string]any{"email": fmt.Sprintf("u%d@t.test", i), "password": bulkValidPassword, "role": "org_user"}
	}
	rec := tenantReq(t, eng, http.MethodPost, "/api/v1/users/bulk", map[string]any{"users": users})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("51 users = %d, want 400", rec.Code)
	}
	if got := bulkPersistedCount(eng); got != 0 {
		t.Errorf("cap breach created %d users, want 0 (nothing processed)", got)
	}
}

func TestBulkCreate_EmptyBatch_Rejected(t *testing.T) {
	org := uuid.New()
	eng := bulkOrgAdminEngine(t, org, "users:create")
	rec := tenantReq(t, eng, http.MethodPost, "/api/v1/users/bulk", map[string]any{"users": []map[string]any{}})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("empty batch = %d, want 400", rec.Code)
	}
}

// exactly 50 is allowed (boundary).
func TestBulkCreate_Exactly50_Allowed(t *testing.T) {
	org := uuid.New()
	eng := bulkOrgAdminEngine(t, org, "users:create")
	users := make([]map[string]any, 50)
	for i := range users {
		users[i] = map[string]any{"email": fmt.Sprintf("u%d@t.test", i), "password": bulkValidPassword, "role": "org_user"}
	}
	rec := tenantReq(t, eng, http.MethodPost, "/api/v1/users/bulk", map[string]any{"users": users})
	if rec.Code != http.StatusOK {
		t.Fatalf("50 users = %d, want 200 (boundary allowed)", rec.Code)
	}
	var resp bulkCreateUsersResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.CreatedCount != 50 {
		t.Errorf("created=%d, want 50", resp.CreatedCount)
	}
}

// (d) Auth: no users:create scope → 403 (route gate); unauthenticated → 401.
func TestBulkCreate_NoScope_Forbidden(t *testing.T) {
	eng := bulkOrgAdminEngine(t, uuid.New(), "users:read") // NOT users:create
	rec := tenantReq(t, eng, http.MethodPost, "/api/v1/users/bulk", map[string]any{"users": []map[string]any{
		{"email": "a@t.test", "password": bulkValidPassword, "role": "org_user"},
	}})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("no users:create = %d, want 403", rec.Code)
	}
}

func TestBulkCreate_Unauthenticated_401(t *testing.T) {
	eng := newTenantEngine(t, nil)
	rec := tenantReq(t, eng, http.MethodPost, "/api/v1/users/bulk", map[string]any{"users": []map[string]any{
		{"email": "a@t.test", "password": bulkValidPassword, "role": "org_user"},
	}})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated = %d, want 401", rec.Code)
	}
}

// (d) Own-org scoping: an org_admin cannot bulk into another tenant — the
// cross-org rows are forbidden per-item and nothing is created.
func TestBulkCreate_OrgAdminCrossOrg_Rejected(t *testing.T) {
	adminOrg := uuid.New()
	otherOrg := uuid.New()
	eng := bulkOrgAdminEngine(t, adminOrg, "users:create")
	rec := tenantReq(t, eng, http.MethodPost, "/api/v1/users/bulk", map[string]any{"users": []map[string]any{
		{"organization_id": otherOrg.String(), "email": "x@t.test", "password": bulkValidPassword, "role": "org_user"},
	}})
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var resp bulkCreateUsersResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.CreatedCount != 0 || resp.FailedCount != 1 {
		t.Fatalf("created=%d failed=%d, want 0/1 (cross-org forbidden)", resp.CreatedCount, resp.FailedCount)
	}
	if resp.Failed[0].Reason != "forbidden" {
		t.Errorf("cross-org reason = %q, want forbidden", resp.Failed[0].Reason)
	}
	if got := bulkPersistedCount(eng); got != 0 {
		t.Errorf("cross-org bulk created %d users, want 0", got)
	}
}

// (e) No-bypass: bulk enforces the SAME guards as the single-create route.
// An org_admin cannot bulk-create a site_admin (identical to the single
// route's CreateUserForActor guard).
func TestBulkCreate_NoBypass_OrgAdminCannotCreateSiteAdmin(t *testing.T) {
	org := uuid.New()
	eng := bulkOrgAdminEngine(t, org, "users:create")
	rec := tenantReq(t, eng, http.MethodPost, "/api/v1/users/bulk", map[string]any{"users": []map[string]any{
		{"email": "wannabe-admin@t.test", "password": bulkValidPassword, "role": "site_admin"},
	}})
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d", rec.Code)
	}
	var resp bulkCreateUsersResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.CreatedCount != 0 || resp.FailedCount != 1 {
		t.Fatalf("created=%d failed=%d, want 0/1 (org_admin cannot bulk-create site_admin)", resp.CreatedCount, resp.FailedCount)
	}
	if resp.Failed[0].Reason != "forbidden" {
		t.Errorf("reason=%q, want forbidden", resp.Failed[0].Reason)
	}
}

// (e) No-bypass: the same password policy the single route enforces
// applies per-row — a weak password is rejected, not silently accepted.
func TestBulkCreate_NoBypass_WeakPasswordRejected(t *testing.T) {
	org := uuid.New()
	eng := bulkOrgAdminEngine(t, org, "users:create")
	rec := tenantReq(t, eng, http.MethodPost, "/api/v1/users/bulk", map[string]any{"users": []map[string]any{
		{"email": "weak@t.test", "password": "short", "role": "org_user"},
	}})
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d", rec.Code)
	}
	var resp bulkCreateUsersResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.CreatedCount != 0 || resp.FailedCount != 1 {
		t.Fatalf("weak-password created=%d failed=%d, want 0/1 (password policy enforced same as single-create)", resp.CreatedCount, resp.FailedCount)
	}
	if got := bulkPersistedCount(eng); got != 0 {
		t.Errorf("weak-password bulk persisted %d, want 0", got)
	}
}
