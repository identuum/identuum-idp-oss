//go:build integration

package e2e

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// H8 through the whole engine: a client_credentials request for an API resource
// succeeds only when the audience is in the client's allowed_audiences and the
// resource belongs to the client's own organization.
func TestE2E_OSS_ClientCredentialsAudienceIsAllowedAndOwn(t *testing.T) {
	w := startInviteEngine(t, map[string]string{"UI": inviteUIBase, "IDENTUUM_IDP_RATE_LIMIT_LOGIN_REQUESTS": "1000"})
	audience := "https://billing-" + uuid.NewString() + ".example.test"

	if st, m, _ := w.call(w.bearers["adminA"], http.MethodPost, "/api/v1/api-resources",
		`{"name":"billing","audience":"`+audience+`","scopes":[{"name":"billing:read"}]}`); st != http.StatusCreated {
		t.Fatalf("create the resource = %d %v; want 201", st, m)
	}

	type made struct{ id, secret string }
	newClient := func(bearer, body string) made {
		t.Helper()
		st, m, _ := w.call(bearer, http.MethodPost, "/api/v1/clients", body)
		c, _ := m["client"].(map[string]any)
		id, _ := c["client_id"].(string)
		secret, _ := m["client_secret"].(string)
		if st != http.StatusCreated || id == "" || secret == "" {
			t.Fatalf("create a client = %d; want 201 with credentials", st)
		}
		return made{id, secret}
	}
	const redirect = `"redirect_uris":["https://rp.example.test/cb"]`
	// A client takes part in client_credentials as a service account.
	st, sa, _ := w.call(w.bearers["adminA"], http.MethodPost, "/api/v1/organizations/"+w.orgA.ID.String()+"/service-accounts", `{"name":"sa-a","role":"org_user"}`)
	saID, _ := sa["id"].(string)
	if st != http.StatusCreated || saID == "" {
		t.Fatalf("create the service account = %d %v; want 201", st, sa)
	}
	allowed := newClient(w.bearers["adminA"], `{"name":"allowed",`+redirect+`,"service_account_id":"`+saID+`","scope":"billing:read","allowed_audiences":["`+audience+`"]}`)
	unlisted := newClient(w.bearers["adminA"], `{"name":"unlisted",`+redirect+`,"scope":"billing:read"}`)
	otherTenant := newClient(w.bearers["adminB"], `{"name":"other-tenant",`+redirect+`,"scope":"billing:read","allowed_audiences":["`+audience+`"]}`)

	token := func(c made) (int, string) {
		t.Helper()
		form := url.Values{"grant_type": {"client_credentials"}, "audience": {audience}, "scope": {"billing:read"}}
		req, _ := http.NewRequest(http.MethodPost, w.base+"/api/v1/oauth/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth(url.QueryEscape(c.id), url.QueryEscape(c.secret))
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("token: %v", err)
		}
		defer res.Body.Close()
		var body struct {
			Error string `json:"error"`
		}
		_ = json.NewDecoder(res.Body).Decode(&body)
		return res.StatusCode, body.Error
	}

	if st, e := token(allowed); st != http.StatusOK {
		t.Errorf("a client that lists the audience, in the resource's organization = %d %q; want 200", st, e)
	}
	if st, e := token(unlisted); st != http.StatusBadRequest || e != "invalid_target" {
		t.Errorf("a client that does not list the audience = %d %q; want 400 invalid_target", st, e)
	}
	if st, e := token(otherTenant); st != http.StatusBadRequest || e != "invalid_target" {
		t.Errorf("another organization's client, even listing it = %d %q; want 400 invalid_target", st, e)
	}
}
