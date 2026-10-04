package handlers

import (
	"encoding/json"
	"net/http"
	"slices"
	"testing"
)

// RFC 7591 grant_types is stored, returned and enforced, not just echoed: a
// registration records the grant types it asked for (authorization_code when it
// asked for none), a management read returns them, and a management update can
// change them.

func storedGrantTypes(t *testing.T, eng dcrMgmtEngine) []string {
	t.Helper()
	if len(eng.clientRepo.rows) != 1 {
		t.Fatalf("stored clients = %d, want 1", len(eng.clientRepo.rows))
	}
	for _, c := range eng.clientRepo.rows {
		return c.GrantTypes
	}
	return nil
}

func TestDCR_TheRegisteredGrantTypesAreStored(t *testing.T) {
	eng := newDCRMgmtEngine(t, siteAdminPrincipal())
	rec := dcrMgmtJSON(t, eng, http.MethodPost, "/api/v1/oauth/register", map[string]any{
		"client_name":   "Grants",
		"redirect_uris": []string{"https://rp.example.com/cb"},
		"grant_types":   []string{"refresh_token", "authorization_code"},
	}, "")
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d; body=%q", rec.Code, rec.Body.String())
	}
	if got := storedGrantTypes(t, eng); !slices.Equal(got, []string{"authorization_code", "refresh_token"}) {
		t.Errorf("stored grant types = %v; want [authorization_code refresh_token]", got)
	}
	var resp dcrResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if !slices.Equal(resp.GrantTypes, []string{"authorization_code", "refresh_token"}) {
		t.Errorf("response grant_types = %v; want what was stored", resp.GrantTypes)
	}
}

func TestDCR_ARegistrationThatAsksForNoGrantTypesGetsAuthorizationCode(t *testing.T) {
	eng := newDCRMgmtEngine(t, siteAdminPrincipal())
	rec := dcrMgmtJSON(t, eng, http.MethodPost, "/api/v1/oauth/register", map[string]any{
		"client_name":   "Default",
		"redirect_uris": []string{"https://rp.example.com/cb"},
	}, "")
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d; body=%q", rec.Code, rec.Body.String())
	}
	if got := storedGrantTypes(t, eng); !slices.Equal(got, []string{"authorization_code"}) {
		t.Errorf("stored grant types = %v; want the RFC 7591 default [authorization_code]", got)
	}
}

func TestRFC7592_GrantTypesAreReadAndUpdated(t *testing.T) {
	eng := newDCRMgmtEngine(t, siteAdminPrincipal())
	id, raw := registerDCRClient(t, eng)

	rec := dcrMgmtJSON(t, eng, http.MethodPut, "/api/v1/oauth/register/"+id.String(), map[string]any{
		"grant_types": []string{"authorization_code", "refresh_token"},
	}, raw)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT status = %d; body=%q", rec.Code, rec.Body.String())
	}
	if got := eng.clientRepo.rows[id].GrantTypes; !slices.Equal(got, []string{"authorization_code", "refresh_token"}) {
		t.Errorf("after PUT stored grant types = %v; want [authorization_code refresh_token]", got)
	}

	rec = dcrMgmtJSON(t, eng, http.MethodGet, "/api/v1/oauth/register/"+id.String(), nil, raw)
	var resp dcrResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if !slices.Equal(resp.GrantTypes, []string{"authorization_code", "refresh_token"}) {
		t.Errorf("GET grant_types = %v; want what was stored", resp.GrantTypes)
	}

	// A PUT that does not mention grant_types leaves them alone.
	rec = dcrMgmtJSON(t, eng, http.MethodPut, "/api/v1/oauth/register/"+id.String(), map[string]any{"client_name": "Renamed"}, raw)
	if rec.Code != http.StatusOK || !slices.Equal(eng.clientRepo.rows[id].GrantTypes, []string{"authorization_code", "refresh_token"}) {
		t.Errorf("a PUT without grant_types changed them: %v", eng.clientRepo.rows[id].GrantTypes)
	}
}
