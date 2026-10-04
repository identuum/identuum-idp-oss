//go:build integration

package e2e

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// A service-account token has no session, so only its own account state can
// stop it. Through the whole engine: a token that works stops working the
// moment the account is disabled, not an hour later.
func TestE2E_OSS_ServiceAccountTokenStopsWhenTheAccountIsDisabled(t *testing.T) {
	w := startInviteEngine(t, map[string]string{"UI": inviteUIBase, "IDENTUUM_IDP_RATE_LIMIT_LOGIN_REQUESTS": "1000"})
	orgPath := "/api/v1/organizations/" + w.orgA.ID.String() + "/service-accounts"

	st, sa, _ := w.call(w.bearers["adminA"], http.MethodPost, orgPath, `{"name":"liveness-sa","role":"org_admin"}`)
	saID, _ := sa["id"].(string)
	if st != http.StatusCreated || saID == "" {
		t.Fatalf("create the service account = %d %v; want 201", st, sa)
	}
	st, m, _ := w.call(w.bearers["adminA"], http.MethodPost, "/api/v1/clients",
		`{"name":"liveness-client","redirect_uris":["https://rp.example.test/cb"],"service_account_id":"`+saID+`"}`)
	client, _ := m["client"].(map[string]any)
	clientID, _ := client["client_id"].(string)
	secret, _ := m["client_secret"].(string)
	if st != http.StatusCreated || clientID == "" || secret == "" {
		t.Fatalf("create the client = %d; want 201 with credentials", st)
	}

	req, _ := http.NewRequest(http.MethodPost, w.base+"/api/v1/oauth/token", strings.NewReader(url.Values{"grant_type": {"client_credentials"}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(url.QueryEscape(clientID), url.QueryEscape(secret))
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	_ = json.NewDecoder(res.Body).Decode(&tok)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusOK || tok.AccessToken == "" {
		t.Fatalf("client_credentials = %d; want 200 with an access token", res.StatusCode)
	}

	if st, _, body := w.call(tok.AccessToken, http.MethodGet, orgPath, ""); st != http.StatusOK {
		t.Fatalf("the service account's token before it is disabled = %d %s; want 200", st, body)
	}
	if st, _, body := w.call(w.bearers["adminA"], http.MethodPost, "/api/v1/service-accounts/"+saID+"/disable", ""); st != http.StatusOK && st != http.StatusNoContent {
		t.Fatalf("disable the service account = %d %s; want 200", st, body)
	}
	if st, _, body := w.call(tok.AccessToken, http.MethodGet, orgPath, ""); st != http.StatusUnauthorized {
		t.Errorf("the same token after the account is disabled = %d %s; want 401", st, body)
	}
}
