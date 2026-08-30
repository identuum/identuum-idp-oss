package handlers

// THE-V031-TWO-GAPS red-proofs (2026-08-08). Two additive response/audit gaps
// measured by the released-appliance e2e suite against v0.3.0:
//
//   A. safeClient omitted is_public, and the admin-API create path never
//      persisted opts.IsPublic (prepareClient dropped it — DCR set it, the
//      admin path lost it), so operators could not distinguish public from
//      confidential clients on ANY read.
//   B. client.secret_rotated carried no resource subject, so subject-keyed
//      audit reads (the application detail page's Recent-activity card)
//      could never surface a rotation.
//
// Each test below was written BEFORE the fix and observed RED against the
// unmodified tree; the fix flips it GREEN without weakening any assertion.

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/google/uuid"
)

// Gap A — the wire: is_public must be PRESENT and TRUE for a public client.
func TestLive_ClientCreatePublic_ResponseCarriesIsPublicTrue(t *testing.T) {
	eng := newLiveEngine(t, orgAdminClientPrincipal(uuid.New()))
	rec := doJSON(t, eng, http.MethodPost, "/api/v1/clients", map[string]any{
		"name":          "Gap-A Public Client",
		"redirect_uris": []string{"https://example.com/cb"},
		"is_public":     true,
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%q", rec.Code, rec.Body.String())
	}
	var resp struct {
		Client       map[string]any `json:"client"`
		ClientSecret string         `json:"client_secret"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.ClientSecret != "" {
		t.Errorf("public client must not receive a client_secret")
	}
	got, present := resp.Client["is_public"]
	if !present {
		t.Fatalf("response client omits is_public — operators cannot tell public from confidential")
	}
	if got != true {
		t.Errorf("is_public = %v, want true", got)
	}
}

// Gap A — the wire, confidential branch: present and FALSE (not merely
// omitted-and-defaulted): a reader must never have to infer publicness
// from secret presence (private_key_jwt clients are secretless AND
// confidential, so that inference is wrong).
func TestLive_ClientCreateConfidential_ResponseCarriesIsPublicFalse(t *testing.T) {
	eng := newLiveEngine(t, orgAdminClientPrincipal(uuid.New()))
	rec := doJSON(t, eng, http.MethodPost, "/api/v1/clients", map[string]any{
		"name":          "Gap-A Confidential Client",
		"redirect_uris": []string{"https://example.com/cb"},
		"is_public":     false,
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%q", rec.Code, rec.Body.String())
	}
	var resp struct {
		Client map[string]any `json:"client"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	got, present := resp.Client["is_public"]
	if !present {
		t.Fatalf("response client omits is_public on the confidential branch")
	}
	if got != false {
		t.Errorf("is_public = %v, want false", got)
	}
}

// Gap A — persistence: the admin create path must STORE IsPublic, and the
// list read must round-trip it. Before the fix prepareClient dropped the
// flag, so a public client persisted is_public=false — which also let a
// "public" client slip past UpdateClient's public-clients-may-not-bind-a-
// service-account guard (the guard reads the STORED flag).
func TestLive_ClientListRoundTripsIsPublic(t *testing.T) {
	eng := newLiveEngine(t, orgAdminClientPrincipal(uuid.New()))
	create := doJSON(t, eng, http.MethodPost, "/api/v1/clients", map[string]any{
		"name":          "Gap-A Round-Trip Client",
		"redirect_uris": []string{"https://example.com/cb"},
		"is_public":     true,
	})
	if create.Code != http.StatusCreated {
		t.Fatalf("create status = %d, want 201; body=%q", create.Code, create.Body.String())
	}
	list := doJSON(t, eng, http.MethodGet, "/api/v1/clients", nil)
	if list.Code != http.StatusOK {
		t.Fatalf("list status = %d, want 200", list.Code)
	}
	var resp struct {
		Clients []map[string]any `json:"clients"`
	}
	if err := json.Unmarshal(list.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(resp.Clients) != 1 {
		t.Fatalf("clients = %d, want 1", len(resp.Clients))
	}
	if got := resp.Clients[0]["is_public"]; got != true {
		t.Errorf("stored/listed is_public = %v, want true (create must persist the flag)", got)
	}
}

// Gap B — the rotate audit event must carry the resource subject so
// subject_id-keyed audit reads can surface the rotation.
func TestLive_ClientSecretRotateAuditCarriesOAuthClientSubject(t *testing.T) {
	eng := newLiveEngine(t, orgAdminClientPrincipal(uuid.New()))
	create := doJSON(t, eng, http.MethodPost, "/api/v1/clients", map[string]any{
		"name":          "Gap-B Rotate Client",
		"redirect_uris": []string{"https://example.com/cb"},
		"is_public":     false,
	})
	if create.Code != http.StatusCreated {
		t.Fatalf("create status = %d, want 201; body=%q", create.Code, create.Body.String())
	}
	var created struct {
		Client struct {
			ID string `json:"id"`
		} `json:"client"`
	}
	if err := json.Unmarshal(create.Body.Bytes(), &created); err != nil {
		t.Fatalf("unmarshal create: %v", err)
	}
	clientUUID, err := uuid.Parse(created.Client.ID)
	if err != nil {
		t.Fatalf("created client id is not a uuid: %v", err)
	}

	rotate := doJSON(t, eng, http.MethodPost, "/api/v1/clients/"+created.Client.ID+"/secret/regenerate", nil)
	if rotate.Code != http.StatusOK {
		t.Fatalf("rotate status = %d, want 200; body=%q", rotate.Code, rotate.Body.String())
	}

	var found bool
	for _, ev := range eng.rec.Events() {
		if ev.Action != "client.secret_rotated" {
			continue
		}
		found = true
		if ev.SubjectType != "oauth_client" {
			t.Errorf("client.secret_rotated SubjectType = %q, want %q", ev.SubjectType, "oauth_client")
		}
		if ev.SubjectID != clientUUID {
			t.Errorf("client.secret_rotated SubjectID = %s, want the client uuid %s", ev.SubjectID, clientUUID)
		}
	}
	if !found {
		t.Fatalf("no client.secret_rotated audit event recorded")
	}
}
