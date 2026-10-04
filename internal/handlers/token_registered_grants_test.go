package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// A client registered for some grant types (RFC 7591 grant_types) may use only
// those at the token endpoint: the registration is enforced, not just echoed.
// A client that registered none (an app created in the console, or one
// registered before the field existed) is unrestricted, as it always was.

type grantsStub struct{ grants []string }

func (s grantsStub) Authenticate(_ context.Context, id, _, _ string) (*service.AuthenticatedClient, error) {
	return &service.AuthenticatedClient{
		Kind: service.AuthenticatedClientKindOAuth, ClientID: id, AuthRecordID: uuid.New(), GrantTypes: s.grants,
	}, nil
}

func tokenErrorFor(t *testing.T, grants []string, grantType string) string {
	t.Helper()
	r := newTokenEngine(t, &keyProvider{keys: []domain.SigningKey{genEdDSA(t, "k")}}, nil, grantsStub{grants: grants}, &audit.Recorder{})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/oauth/token",
		strings.NewReader("grant_type="+grantType+"&client_id=cli-1&client_secret=s"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	var body map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	e, _ := body["error"].(string)
	return e
}

func TestToken_AGrantTheClientDidNotRegisterIsRefused(t *testing.T) {
	registered := []string{"authorization_code"}
	for _, grant := range []string{"refresh_token", "client_credentials"} {
		if got := tokenErrorFor(t, registered, grant); got != "unauthorized_client" {
			t.Errorf("client registered for authorization_code only, grant %s: error = %q; want unauthorized_client", grant, got)
		}
	}
}

func TestToken_AClientWithNoRegisteredGrantsIsUnrestricted(t *testing.T) {
	for _, grants := range [][]string{nil, {}} {
		if got := tokenErrorFor(t, grants, "refresh_token"); got == "unauthorized_client" {
			t.Errorf("client with grants %v was refused a grant it never restricted", grants)
		}
	}
}

func TestToken_ARegisteredGrantIsNotRefusedForBeingUnregistered(t *testing.T) {
	// The registered grant passes this check and meets whatever the grant itself
	// requires (here: an authorization code it did not bring).
	if got := tokenErrorFor(t, []string{"authorization_code"}, "authorization_code"); got == "unauthorized_client" {
		t.Errorf("a registered grant was refused as unauthorized_client")
	}
}
