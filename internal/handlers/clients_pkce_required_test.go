package handlers

import (
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// OSS-PUBLIC-CLIENT-PKCE-OPTION (owner decision 2026-10-10): the client admin
// API carries a per-client "PKCE required" setting, pkce_required, on by
// default. The org_admin may turn it off for a public client only; every read
// shows it, a client with it off carries a plain warning, and a change is
// audited with who made it and its before and after values. Dynamic
// registration can never turn it off.

const pkcePublicCreateBody = `{"name":"conformance public","redirect_uris":["https://app.example.com/cb"],"scope":"openid","is_public":true,"token_endpoint_auth_method":"none"`

func (e skipConsentEngine) seedPublicClient(dynamic bool) uuid.UUID {
	id := uuid.New()
	org := e.admin.OrganizationID
	e.repo.rows[id] = &domain.Client{
		ID: id, ClientID: "pub-" + id.String()[:8], Name: "spa", OrganizationID: &org,
		RedirectURIs: []string{"https://app.example.com/cb"}, Scope: "openid",
		IsPublic: true, TokenEndpointAuthMethod: "none", DynamicallyRegistered: dynamic,
	}
	return id
}

func onlyEvent(t *testing.T, rec *audit.Recorder, action string) audit.Event {
	t.Helper()
	ev := rec.Events()
	if len(ev) != 1 || ev[0].Action != action {
		t.Fatalf("audit = %+v; want exactly one %s", ev, action)
	}
	return ev[0]
}

func TestCreateClient_PKCERequiredDefaultsOnAndTurnsOffOnlyForAPublicClient(t *testing.T) {
	t.Run("absent: on, shown, no warning", func(t *testing.T) {
		e := newSkipConsentEngine(t, nil)
		st, m := e.do(t, http.MethodPost, "/api/v1/clients", pkcePublicCreateBody+`}`)
		client, _ := m["client"].(map[string]any)
		if st != http.StatusCreated || client["pkce_required"] != true || client["pkce_warning"] != nil {
			t.Fatalf("= %d %v; want 201 with pkce_required true and no warning", st, client)
		}
		if ev := onlyEvent(t, e.rec, "client.created"); ev.Metadata["pkce_required"] != true {
			t.Errorf("client.created metadata = %v; want pkce_required true", ev.Metadata)
		}
	})
	t.Run("false on a public client: stored off, echoed false with the warning, audited", func(t *testing.T) {
		e := newSkipConsentEngine(t, nil)
		st, m := e.do(t, http.MethodPost, "/api/v1/clients", pkcePublicCreateBody+`,"pkce_required":false}`)
		client, _ := m["client"].(map[string]any)
		if st != http.StatusCreated || client["pkce_required"] != false {
			t.Fatalf("= %d %v; want 201 with pkce_required false", st, m)
		}
		if w, _ := client["pkce_warning"].(string); !strings.Contains(w, "intercepted authorization code") {
			t.Errorf("pkce_warning = %q; want the plain warning", w)
		}
		for _, c := range e.repo.rows {
			if !c.PKCEOptOut {
				t.Error("stored client keeps PKCE required; want it off")
			}
		}
		ev := onlyEvent(t, e.rec, "client.created")
		if ev.Metadata["pkce_required"] != false || ev.ActorID != e.admin.UserID {
			t.Errorf("client.created = %+v; want pkce_required false and the admin as actor", ev)
		}
	})
	t.Run("false on a confidential client: refused, nothing created", func(t *testing.T) {
		e := newSkipConsentEngine(t, nil)
		st, m := e.do(t, http.MethodPost, "/api/v1/clients", `{"name":"web","redirect_uris":["https://app.example.com/cb"],"scope":"openid","pkce_required":false}`)
		if st != http.StatusBadRequest || m["error"] != "invalid_request" || !strings.Contains(m["error_description"].(string), "public client") {
			t.Errorf("= %d %v; want 400 invalid_request naming the public-client rule", st, m)
		}
		if len(e.repo.rows) != 0 {
			t.Error("a refused create must store nothing")
		}
	})
}

func TestUpdateClient_PKCERequiredChangeIsAuditedWithItsBeforeAndAfter(t *testing.T) {
	e := newSkipConsentEngine(t, nil)
	id := e.seedPublicClient(false)

	st, m := e.do(t, http.MethodPut, "/api/v1/clients/"+id.String(), `{"pkce_required":false}`)
	if st != http.StatusOK || m["pkce_required"] != false || m["pkce_warning"] == nil {
		t.Fatalf("turn off = %d %v; want 200 with pkce_required false and the warning", st, m)
	}
	if !e.repo.rows[id].PKCEOptOut {
		t.Error("stored client keeps PKCE required after turning it off")
	}
	ev := onlyEvent(t, e.rec, "client.updated")
	if ev.Metadata["pkce_required_before"] != true || ev.Metadata["pkce_required_after"] != false ||
		ev.ActorID != e.admin.UserID || ev.SubjectID != id {
		t.Errorf("client.updated = %+v; want before true, after false, the admin as actor and the client as subject", ev)
	}

	st, m = e.do(t, http.MethodGet, "/api/v1/clients/"+id.String(), "")
	if st != http.StatusOK || m["pkce_required"] != false || m["pkce_warning"] == nil {
		t.Errorf("read = %d %v; want pkce_required false with the warning", st, m)
	}

	e.rec.Reset()
	st, m = e.do(t, http.MethodPut, "/api/v1/clients/"+id.String(), `{"pkce_required":true}`)
	if st != http.StatusOK || m["pkce_required"] != true || m["pkce_warning"] != nil || e.repo.rows[id].PKCEOptOut {
		t.Fatalf("turn on = %d %v; want 200 with pkce_required true and no warning", st, m)
	}
	ev = onlyEvent(t, e.rec, "client.updated")
	if ev.Metadata["pkce_required_before"] != false || ev.Metadata["pkce_required_after"] != true {
		t.Errorf("client.updated metadata = %v; want before false, after true", ev.Metadata)
	}
}

func TestUpdateClient_PKCERequiredCannotBeTurnedOffForAConfidentialOrDynamicApp(t *testing.T) {
	e := newSkipConsentEngine(t, nil)
	for name, id := range map[string]uuid.UUID{
		"confidential":           e.seedClient(false, false),
		"dynamically registered": e.seedPublicClient(true),
	} {
		st, m := e.do(t, http.MethodPut, "/api/v1/clients/"+id.String(), `{"pkce_required":false}`)
		if st != http.StatusBadRequest || m["error"] != "invalid_request" {
			t.Errorf("%s: = %d %v; want 400 invalid_request", name, st, m)
		}
		// The refusal comes from Client.Validate before the repository is
		// written (the in-memory repository shares its row with the service,
		// so the row itself cannot show that); nothing is audited as changed.
		for _, ev := range e.rec.Events() {
			if ev.Action == "client.updated" {
				t.Errorf("%s: a refused change was audited as client.updated: %+v", name, ev)
			}
		}
	}
}

func TestDCR_CannotTurnPKCEOff(t *testing.T) {
	eng := newDCREngine(t, siteAdminPrincipal())
	rec := dcrPost(t, eng, map[string]any{
		"client_name":                "Public RP",
		"redirect_uris":              []string{"https://rp.example.com/cb"},
		"token_endpoint_auth_method": "none",
		"pkce_required":              false,
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%q", rec.Code, rec.Body.String())
	}
	for _, c := range eng.clientRepo.rows {
		if !c.IsPublic || c.PKCEOptOut || !c.RequiresPKCE() {
			t.Errorf("stored DCR client public=%v opt-out=%v; want a public client that requires PKCE", c.IsPublic, c.PKCEOptOut)
		}
	}
	if strings.Contains(rec.Body.String(), `"pkce_required":false`) {
		t.Errorf("DCR response echoes pkce_required false: %s", rec.Body.String())
	}
}
