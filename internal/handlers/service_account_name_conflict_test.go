package handlers

// THE-V032-ALL-GREEN gap E red-proof (2026-08-08). The UI's rename flow maps a
// duplicate service-account name to an inline 409 error, but the backend
// accepted duplicates — the 409 path was unreachable. Migration 0030 adds the
// per-organization live-name unique index; the repository maps its violation
// to domain.ErrServiceAccountNameTaken; this file pins the HANDLER mapping:
// the sentinel MUST surface as 409, not the generic 500.
//
// Both tests were observed RED against the unmodified tree (the fake repo
// accepted duplicates and respondSAError had no 409 branch).

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

func TestCreateServiceAccount_DuplicateNameIs409(t *testing.T) {
	org := uuid.New()
	actor := orgAdminActorPrincipal(org)
	r, _, _ := newSAEngine(t, actor)

	first := doSAJSON(t, r, http.MethodPost, "/api/v1/organizations/"+org.String()+"/service-accounts", map[string]any{
		"name": "conflict-sa",
		"role": "org_user",
	})
	if first.Code != http.StatusCreated {
		t.Fatalf("first create status = %d; body=%q", first.Code, first.Body.String())
	}

	second := doSAJSON(t, r, http.MethodPost, "/api/v1/organizations/"+org.String()+"/service-accounts", map[string]any{
		"name": "conflict-sa",
		"role": "org_user",
	})
	if second.Code != http.StatusConflict {
		t.Fatalf("duplicate create status = %d, want 409; body=%q", second.Code, second.Body.String())
	}
}

func TestUpdateServiceAccount_RenameToSiblingNameIs409(t *testing.T) {
	org := uuid.New()
	actor := orgAdminActorPrincipal(org)
	r, _, _ := newSAEngine(t, actor)

	if resp := doSAJSON(t, r, http.MethodPost, "/api/v1/organizations/"+org.String()+"/service-accounts", map[string]any{
		"name": "sibling-a",
		"role": "org_user",
	}); resp.Code != http.StatusCreated {
		t.Fatalf("create a status = %d; body=%q", resp.Code, resp.Body.String())
	}
	createB := doSAJSON(t, r, http.MethodPost, "/api/v1/organizations/"+org.String()+"/service-accounts", map[string]any{
		"name": "sibling-b",
		"role": "org_user",
	})
	if createB.Code != http.StatusCreated {
		t.Fatalf("create b status = %d; body=%q", createB.Code, createB.Body.String())
	}
	var b struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(createB.Body.Bytes(), &b); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	rename := doSAJSON(t, r, http.MethodPut, "/api/v1/service-accounts/"+b.ID, map[string]any{
		"name": "sibling-a",
	})
	if rename.Code != http.StatusConflict {
		t.Fatalf("rename-to-sibling status = %d, want 409; body=%q", rename.Code, rename.Body.String())
	}
}

// The fake repo mirrors migration 0030's index, so a regression that stopped
// mapping the sentinel would fail these tests rather than silently reverting
// to duplicates-allowed. This pin makes the mirroring itself load-bearing.
func TestFakeSARepo_MirrorsLiveNameUniqueness(t *testing.T) {
	repo := newSARepoForHandlers()
	org := uuid.New()
	if _, err := repo.Create(t.Context(), &domain.ServiceAccount{OrganizationID: org, Name: "dup", Active: true}); err != nil {
		t.Fatalf("first create: %v", err)
	}
	if _, err := repo.Create(t.Context(), &domain.ServiceAccount{OrganizationID: org, Name: "dup", Active: true}); err == nil {
		t.Fatalf("second create with the same live name must fail with ErrServiceAccountNameTaken")
	}
}
