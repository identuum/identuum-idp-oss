package handlers

// THE-V032-ALL-GREEN Order A red-proofs (2026-08-08). v0.3.1 subject-tagged
// client.secret_rotated, but the released-appliance e2e suite proved that
// insufficient: resource lifecycle events were still invisible to the tenant
// because the emits carried no OrganizationID (the audit tenant clamp filters
// on actor_organization_id) and no actor identity, and only the rotation
// carried a subject. This file pins the COMPLETE contract for client +
// service-account lifecycle emits:
//
//   - SubjectType/SubjectID name the resource,
//   - OrganizationID names the RESOURCE'S org (the tenant whose trail this
//     is — for org_admin actors identical to their own org; for site_admin
//     actions on tenant resources still the tenant's),
//   - Actor* name the acting principal,
//   - binding/unbinding a service account through the client-update surface
//     additionally emits an SA-subject event so the SA detail trail shows it.
//
// Every test below was observed RED against the unmodified tree.

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// doSAJSON issues a JSON request against a bare engine (the SA engine helper
// returns *gin.Engine rather than the clients' liveEngine wrapper).
func doSAJSON(t *testing.T, r *gin.Engine, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			t.Fatalf("encode body: %v", err)
		}
	}
	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func orgAdminActorPrincipal(org uuid.UUID) *domain.Principal {
	return &domain.Principal{
		UserID:         uuid.New(),
		OrganizationID: org,
		Email:          "org-admin@enrich.test",
		Role:           domain.RoleOrgAdmin,
		Scope:          domain.SessionScopesForRole(domain.RoleOrgAdmin),
	}
}

func findEvents(rec *audit.Recorder, action string) []audit.Event {
	var out []audit.Event
	for _, ev := range rec.Events() {
		if ev.Action == action {
			out = append(out, ev)
		}
	}
	return out
}

func assertEnriched(t *testing.T, ev audit.Event, actor *domain.Principal, org uuid.UUID, subjType string, subj uuid.UUID) {
	t.Helper()
	if ev.SubjectType != subjType {
		t.Errorf("%s SubjectType = %q, want %q", ev.Action, ev.SubjectType, subjType)
	}
	if ev.SubjectID != subj {
		t.Errorf("%s SubjectID = %s, want %s", ev.Action, ev.SubjectID, subj)
	}
	if ev.OrganizationID != org {
		t.Errorf("%s OrganizationID = %s, want the resource org %s (the tenant clamp filters on it)", ev.Action, ev.OrganizationID, org)
	}
	if ev.ActorID != actor.UserID {
		t.Errorf("%s ActorID = %s, want the acting principal %s", ev.Action, ev.ActorID, actor.UserID)
	}
	if ev.ActorEmail != actor.Email {
		t.Errorf("%s ActorEmail = %q, want %q", ev.Action, ev.ActorEmail, actor.Email)
	}
	if ev.ActorRole != string(actor.Role) {
		t.Errorf("%s ActorRole = %q, want %q", ev.Action, ev.ActorRole, string(actor.Role))
	}
	if ev.ActorType != "user" {
		t.Errorf("%s ActorType = %q, want %q", ev.Action, ev.ActorType, "user")
	}
}

type createdClientResp struct {
	Client struct {
		ID             string `json:"id"`
		OrganizationID string `json:"organization_id"`
	} `json:"client"`
}

func mustCreateClient(t *testing.T, eng liveEngine, isPublic bool) uuid.UUID {
	t.Helper()
	rec := doJSON(t, eng, http.MethodPost, "/api/v1/clients", map[string]any{
		"name":          "Enrichment Client",
		"redirect_uris": []string{"https://example.com/cb"},
		"is_public":     isPublic,
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create client status = %d; body=%q", rec.Code, rec.Body.String())
	}
	var resp createdClientResp
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	id, err := uuid.Parse(resp.Client.ID)
	if err != nil {
		t.Fatalf("client id not a uuid: %v", err)
	}
	return id
}

func TestClientLifecycleEmits_CarrySubjectActorAndTenantOrg(t *testing.T) {
	org := uuid.New()
	actor := orgAdminActorPrincipal(org)
	eng := newLiveEngine(t, actor)

	clientID := mustCreateClient(t, eng, false)

	if rec := doJSON(t, eng, http.MethodPut, "/api/v1/clients/"+clientID.String(), map[string]any{
		"name": "Enrichment Client Renamed",
	}); rec.Code != http.StatusOK {
		t.Fatalf("update status = %d; body=%q", rec.Code, rec.Body.String())
	}
	if rec := doJSON(t, eng, http.MethodPost, "/api/v1/clients/"+clientID.String()+"/secret/regenerate", nil); rec.Code != http.StatusOK {
		t.Fatalf("rotate status = %d; body=%q", rec.Code, rec.Body.String())
	}
	if rec := doJSON(t, eng, http.MethodDelete, "/api/v1/clients/"+clientID.String(), nil); rec.Code != http.StatusOK {
		t.Fatalf("delete status = %d; body=%q", rec.Code, rec.Body.String())
	}

	for _, action := range []string{"client.created", "client.updated", "client.secret_rotated", "client.deleted"} {
		evs := findEvents(eng.rec, action)
		if len(evs) != 1 {
			t.Fatalf("%s events = %d, want 1", action, len(evs))
		}
		assertEnriched(t, evs[0], actor, org, "oauth_client", clientID)
	}
}

func TestServiceAccountLifecycleEmits_CarrySubjectActorAndTenantOrg(t *testing.T) {
	org := uuid.New()
	actor := orgAdminActorPrincipal(org)
	r, _, rec := newSAEngine(t, actor)

	create := doSAJSON(t, r, http.MethodPost, "/api/v1/organizations/"+org.String()+"/service-accounts", map[string]any{
		"name": "enrichment-sa",
		"role": "org_user",
	})
	if create.Code != http.StatusCreated {
		t.Fatalf("create SA status = %d; body=%q", create.Code, create.Body.String())
	}
	var created struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(create.Body.Bytes(), &created); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	saID, err := uuid.Parse(created.ID)
	if err != nil {
		t.Fatalf("sa id not a uuid: %v", err)
	}

	if resp := doSAJSON(t, r, http.MethodPut, "/api/v1/service-accounts/"+saID.String(), map[string]any{
		"name": "enrichment-sa-renamed",
	}); resp.Code != http.StatusOK {
		t.Fatalf("update SA status = %d; body=%q", resp.Code, resp.Body.String())
	}
	if resp := doSAJSON(t, r, http.MethodDelete, "/api/v1/service-accounts/"+saID.String(), nil); resp.Code != http.StatusNoContent {
		t.Fatalf("delete SA status = %d; body=%q", resp.Code, resp.Body.String())
	}

	for _, action := range []string{"service_account.created", "service_account.updated", "service_account.deleted"} {
		evs := findEvents(rec, action)
		if len(evs) != 1 {
			t.Fatalf("%s events = %d, want 1", action, len(evs))
		}
		assertEnriched(t, evs[0], actor, org, "service_account", saID)
	}
}

func TestClientSABindEmitsSASubjectLinkAndUnlinkEvents(t *testing.T) {
	org := uuid.New()
	actor := orgAdminActorPrincipal(org)
	eng := newLiveEngine(t, actor)

	clientID := mustCreateClient(t, eng, false)
	saID := uuid.New() // no binding validator wired in the live engine — accepted verbatim

	if rec := doJSON(t, eng, http.MethodPut, "/api/v1/clients/"+clientID.String(), map[string]any{
		"service_account_id": saID.String(),
	}); rec.Code != http.StatusOK {
		t.Fatalf("bind status = %d; body=%q", rec.Code, rec.Body.String())
	}
	linked := findEvents(eng.rec, "service_account.linked_oauth_client")
	if len(linked) != 1 {
		t.Fatalf("service_account.linked_oauth_client events = %d, want 1 (the SA's own trail must show the bind)", len(linked))
	}
	assertEnriched(t, linked[0], actor, org, "service_account", saID)
	if got := linked[0].Metadata["oauth_client_id"]; got != clientID.String() {
		t.Errorf("linked event metadata oauth_client_id = %v, want %s", got, clientID)
	}

	if rec := doJSON(t, eng, http.MethodPut, "/api/v1/clients/"+clientID.String(), map[string]any{
		"service_account_id": uuid.Nil.String(),
	}); rec.Code != http.StatusOK {
		t.Fatalf("unbind status = %d; body=%q", rec.Code, rec.Body.String())
	}
	unlinked := findEvents(eng.rec, "service_account.unlinked_oauth_client")
	if len(unlinked) != 1 {
		t.Fatalf("service_account.unlinked_oauth_client events = %d, want 1", len(unlinked))
	}
	assertEnriched(t, unlinked[0], actor, org, "service_account", saID)
}
