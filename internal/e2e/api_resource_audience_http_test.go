//go:build integration

package e2e

import (
	"net/http"
	"testing"

	"github.com/google/uuid"
)

// H7 through the whole engine: an API resource's audience is unique across the
// installation (a second organization cannot take it), and it is never the
// issuer or an application's client id.
func TestE2E_OSS_APIResourceAudienceIsUniqueAndNeverReserved(t *testing.T) {
	w := startInviteEngine(t, map[string]string{"UI": inviteUIBase, "IDENTUUM_IDP_RATE_LIMIT_LOGIN_REQUESTS": "1000"})
	create := func(bearer, audience string) (int, map[string]any) {
		st, m, _ := w.call(bearer, http.MethodPost, "/api/v1/api-resources", `{"name":"res","audience":"`+audience+`"}`)
		return st, m
	}

	audience := "https://res-" + uuid.NewString() + ".example.test"
	if st, m := create(w.bearers["adminA"], audience); st != http.StatusCreated {
		t.Fatalf("first create = %d %v; want 201", st, m)
	}
	if st, m := create(w.bearers["adminB"], audience); st != http.StatusConflict || m["error"] != "audience_exists" {
		t.Errorf("another organization takes the same audience = %d %v; want 409 audience_exists", st, m)
	}
	if st, m := create(w.bearers["adminA"], inviteIssuer); st != http.StatusBadRequest {
		t.Errorf("audience equal to the issuer = %d %v; want 400", st, m)
	}

	st, m, _ := w.call(w.bearers["adminA"], http.MethodPost, "/api/v1/clients", `{"name":"app","redirect_uris":["https://rp.example.test/cb"],"scope":"openid"}`)
	client, _ := m["client"].(map[string]any)
	clientID, _ := client["client_id"].(string)
	if st != http.StatusCreated || clientID == "" {
		t.Fatalf("create a client = %d %v; want 201", st, m)
	}
	if st, m := create(w.bearers["adminB"], clientID); st != http.StatusBadRequest {
		t.Errorf("audience equal to another organization's client id = %d %v; want 400", st, m)
	}
}
