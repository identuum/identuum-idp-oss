package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// OSS-IDP-ACTIVE-FIELD (owner Q-P1 (a), Q-A1 (a), judge Q-PR1 (a)): OSS has
// no way to switch a sign-in provider off, and it has one provider per
// organization, so it has no priority to change. A provider PUT whose
// `active` or `priority` differs from the stored value answers 400 with a
// plain message and writes nothing. A value equal to the stored one, or no
// value, behaves as before. Until this change both fields were bound and
// dropped: 200, nothing changed, and the client was told "saved".

const (
	wantErrActiveNotSupported   = "active_not_supported"
	wantMsgActiveNotSupported   = "This server cannot switch a sign-in provider off. Remove it instead."
	wantErrPriorityNotSupported = "priority_not_supported"
	wantMsgPriorityNotSupported = "This server has only one sign-in provider and cannot change its priority. Leave priority out."
)

// seedProvider stores one oidc provider for org directly in the fake. Its
// priority is 0, the value create always stores.
func seedProvider(t *testing.T, repo *fakeIDPConfigRepoH, org uuid.UUID, active bool) uuid.UUID {
	t.Helper()
	p, err := repo.Create(context.Background(), &domain.IdentityProvider{
		OrganizationID: org,
		Type:           domain.IDPTypeOIDC,
		Name:           "Before",
		Slug:           "oidc",
		Active:         active,
		Config: domain.ProviderConfig{
			IssuerURL: "https://accounts.google.com",
			ClientID:  "cid.apps.googleusercontent.com",
		},
	})
	if err != nil {
		t.Fatalf("seed provider: %v", err)
	}
	return p.ID
}

// activeFieldBody is a complete PUT that also renames the provider, so a
// write that should not happen is visible in the stored name.
func activeFieldBody(active *bool, priority *int) map[string]any {
	b := map[string]any{
		"name":   "After",
		"config": map[string]any{"issuer_url": "https://accounts.google.com", "client_id": "cid.apps.googleusercontent.com"},
	}
	if active != nil {
		b["active"] = *active
	}
	if priority != nil {
		b["priority"] = *priority
	}
	return b
}

// RULE: IDP-ACTIVE-NOT-SILENT-1
func TestIDPConfig_PutActiveIsNeverSilent(t *testing.T) {
	on, off := true, false
	zero, five := 0, 5
	refused := []struct {
		name     string
		stored   bool
		active   *bool
		priority *int
		wantErr  string
		wantMsg  string
	}{
		{"switch off an active provider", true, &off, nil, wantErrActiveNotSupported, wantMsgActiveNotSupported},
		{"switch on an inactive provider", false, &on, nil, wantErrActiveNotSupported, wantMsgActiveNotSupported},
		{"change the priority", true, nil, &five, wantErrPriorityNotSupported, wantMsgPriorityNotSupported},
	}
	for _, tc := range refused {
		t.Run(tc.name, func(t *testing.T) {
			org := uuid.New()
			r, repo, _ := newIDPConfigEngine(t, idpConfigOrgAdmin(org))
			id := seedProvider(t, repo, org, tc.stored)
			w := idpDo(t, r, http.MethodPut, idpPath(org), activeFieldBody(tc.active, tc.priority))
			if w.Code != http.StatusBadRequest {
				t.Fatalf("%s: PUT = %d; want 400 %s", tc.name, w.Code, tc.wantErr)
			}
			var body map[string]any
			_ = json.Unmarshal(w.Body.Bytes(), &body)
			if body["error"] != tc.wantErr || body["message"] != tc.wantMsg {
				t.Errorf("refusal error=%v message=%v; want %q with the plain message", body["error"], body["message"], tc.wantErr)
			}
			got := repo.byID[id]
			if got.Active != tc.stored || got.Priority != 0 || got.Name != "Before" {
				t.Errorf("after the refusal: active=%v priority=%d name=%q; want active=%v priority 0 name %q (nothing written)", got.Active, got.Priority, got.Name, tc.stored, "Before")
			}
		})
	}

	// Controls: green before and after the change.
	controls := []struct {
		name     string
		stored   bool
		active   *bool
		priority *int
	}{
		{"control: active=true on an active provider", true, &on, nil},
		{"control: no active field on an active provider", true, nil, nil},
		{"control: no active field on an inactive provider", false, nil, nil},
		{"control: priority=0, the stored priority", true, nil, &zero},
	}
	for _, tc := range controls {
		t.Run(tc.name, func(t *testing.T) {
			org := uuid.New()
			r, repo, _ := newIDPConfigEngine(t, idpConfigOrgAdmin(org))
			id := seedProvider(t, repo, org, tc.stored)
			w := idpDo(t, r, http.MethodPut, idpPath(org), activeFieldBody(tc.active, tc.priority))
			if w.Code != http.StatusOK {
				t.Fatalf("%s = %d %s; want 200", tc.name, w.Code, w.Body.String())
			}
			got := repo.byID[id]
			if got.Active != tc.stored || got.Name != "After" {
				t.Errorf("after the save: active=%v name=%q; want active=%v name %q", got.Active, got.Name, tc.stored, "After")
			}
		})
	}
}
