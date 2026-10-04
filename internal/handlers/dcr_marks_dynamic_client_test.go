package handlers

import (
	"net/http"
	"testing"
)

// D-026: an app created through dynamic client registration is marked as such
// when it is stored, so no later path can give it "skip consent". An app an
// org_admin creates in the console is not marked.
func TestDCR_RegisteredClientIsMarkedDynamicallyRegistered(t *testing.T) {
	eng := newDCREngine(t, siteAdminPrincipal())
	rec := dcrPost(t, eng, map[string]any{
		"client_name":   "Acme RP",
		"redirect_uris": []string{"https://rp.example.com/cb"},
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%q", rec.Code, rec.Body.String())
	}
	if len(eng.clientRepo.rows) != 1 {
		t.Fatalf("stored clients = %d, want 1", len(eng.clientRepo.rows))
	}
	for _, c := range eng.clientRepo.rows {
		if !c.DynamicallyRegistered {
			t.Error("a client created through dynamic registration must be stored with DynamicallyRegistered")
		}
		if c.SkipConsent {
			t.Error("a dynamically registered client must not skip consent")
		}
	}
}
