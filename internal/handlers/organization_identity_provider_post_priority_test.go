package handlers

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/google/uuid"
)

// O2 (OSS-IDP-ACTIVE-FIELD-REVIEW; v0.9.14): the provider POST bound
// `priority` and stored 0 whatever was sent, so a create with a priority
// answered 201 and the value was dropped. OSS has one provider per
// organization and no priority to set, so a POST whose priority is not 0
// answers 400 priority_not_supported with the PUT's plain message and stores
// nothing. No priority, or 0, creates as before.

// postPriorityBody is a complete POST; priority is left out when nil.
func postPriorityBody(priority *int) map[string]any {
	b := map[string]any{
		"type":   "oidc",
		"name":   "Upstream",
		"slug":   "oidc",
		"config": map[string]any{"issuer_url": "https://accounts.google.com", "client_id": "cid.apps.googleusercontent.com"},
	}
	if priority != nil {
		b["priority"] = *priority
	}
	return b
}

// RULE: IDP-POST-PRIORITY-NOT-SILENT-1
func TestIDPConfig_PostPriorityIsNeverSilent(t *testing.T) {
	zero, five, minusOne := 0, 5, -1
	for _, tc := range []struct {
		name     string
		priority *int
	}{
		{"create with priority 5", &five},
		{"create with priority -1", &minusOne},
	} {
		t.Run(tc.name, func(t *testing.T) {
			org := uuid.New()
			r, repo, _ := newIDPConfigEngine(t, idpConfigOrgAdmin(org))
			w := idpDo(t, r, http.MethodPost, idpPath(org), postPriorityBody(tc.priority))
			if w.Code != http.StatusBadRequest {
				t.Fatalf("%s: POST = %d; want 400 %s", tc.name, w.Code, wantErrPriorityNotSupported)
			}
			var body map[string]any
			_ = json.Unmarshal(w.Body.Bytes(), &body)
			if body["error"] != wantErrPriorityNotSupported || body["message"] != wantMsgPriorityNotSupported {
				t.Errorf("refusal error=%v message=%v; want %q with the plain message", body["error"], body["message"], wantErrPriorityNotSupported)
			}
			if n := len(repo.byID); n != 0 {
				t.Errorf("%d provider(s) stored after the refusal; want 0", n)
			}
		})
	}

	// Controls: green before and after the change.
	for _, tc := range []struct {
		name     string
		priority *int
	}{
		{"control: no priority", nil},
		{"control: priority 0", &zero},
	} {
		t.Run(tc.name, func(t *testing.T) {
			org := uuid.New()
			r, repo, _ := newIDPConfigEngine(t, idpConfigOrgAdmin(org))
			w := idpDo(t, r, http.MethodPost, idpPath(org), postPriorityBody(tc.priority))
			if w.Code != http.StatusCreated {
				t.Fatalf("%s = %d %s; want 201", tc.name, w.Code, w.Body.String())
			}
			if n := len(repo.byID); n != 1 {
				t.Fatalf("%d provider(s) stored; want 1", n)
			}
			for _, p := range repo.byID {
				if p.Priority != 0 {
					t.Errorf("stored priority %d; want 0", p.Priority)
				}
			}
		})
	}
}
