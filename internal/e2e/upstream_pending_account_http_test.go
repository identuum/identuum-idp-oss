//go:build integration

// Package e2e — OSS-0913-A-FIX (review finding F1, O19): the refusal of a
// pending account at upstream sign-in is proved through the runtime's own
// composition (runtime.New + Start on the test database, the loopback
// provider of upstream_console_session_http_test.go), not through a service
// the test wires itself. A self-registrant held for approval and an invitee
// who has not accepted are both sent to the sign-in page with their reason,
// with no cookie and no link written; an active member of the same
// organization signs in. If buildDeps stops wiring the registration state
// reader, the held registrant is no longer answered registration_pending, so
// this test fails.
//
// Tokens, codes, cookie values, secrets and passwords are never printed.
package e2e

import (
	"net/http"
	"testing"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// RULE: OIDC-PENDING-RUNTIME-1
func TestE2E_OSS_UpstreamSignInRefusesPendingAccountsThroughTheRuntime(t *testing.T) {
	const clientID = "pending-upstream-client"
	prov := newUpstreamProvider(t, clientID)
	w := startInviteEngine(t, map[string]string{"UI": inviteUIBase, "IDENTUUM_IDP_RATE_LIMIT_LOGIN_REQUESTS": "1000",
		"IDENTUUM_IDP_TEST_ALLOW_PRIVATE_UPSTREAM_ISSUER": "true"})
	if _, err := w.pool.Exec(w.ctx, `UPDATE organizations SET auth_policy = 'mixed' WHERE id = $1`, w.orgA.ID); err != nil {
		t.Fatalf("set auth_policy mixed: %v", err)
	}
	emailDomain := "pend-" + uuid.NewString()[:8] + ".example.invalid"
	st, m, _ := w.call(w.bearers["adminA"], http.MethodPost, "/api/v1/organizations/"+w.orgA.ID.String()+"/identity-provider",
		`{"type":"oidc","name":"Loopback provider","slug":"pending-`+uuid.NewString()[:8]+`","config":{"issuer_url":"`+prov.srv.URL+`","client_id":"`+clientID+`","client_secret":"not-a-secret-fixture-value","scopes":["openid","email","profile"],"email_domains":["`+emailDomain+`"]}}`)
	idp, _ := m["identity_provider"].(map[string]any)
	pid, _ := idp["id"].(string)
	if st != http.StatusCreated || pid == "" {
		t.Fatalf("register the provider = %d %v; want 201 with the provider", st, m)
	}

	member := func(name string) *domain.User {
		t.Helper()
		u, err := w.repos.User.Create(w.ctx, &domain.User{ID: uuid.New(), OrganizationID: w.orgA.ID, Email: name + "-" + uuid.NewString()[:8] + "@" + emailDomain,
			PasswordHash: "dm-" + uuid.NewString(), Role: domain.RoleOrgUser, AuthSource: domain.AuthSourceLocal})
		if err != nil {
			t.Fatalf("seed %s: %v", name, err)
		}
		return u
	}
	held := member("held")
	if err := w.repos.Registration.SetUserState(w.ctx, held.ID, domain.RegistrationStatePendingApproval); err != nil {
		t.Fatalf("hold the registrant for approval: %v", err)
	}
	inviteeEmail := "invitee-" + uuid.NewString()[:8] + "@" + emailDomain
	inviteeID, _, _ := w.invite(inviteeEmail)
	active := member("active")

	unlinked := func(id string) bool {
		t.Helper()
		var ext *string
		var linked bool
		if err := w.pool.QueryRow(w.ctx, `SELECT external_id, oidc_linked FROM users WHERE id = $1`, id).Scan(&ext, &linked); err != nil {
			t.Fatalf("read user %s: %v", id, err)
		}
		return ext == nil && !linked
	}

	for _, c := range []struct {
		name, email, id, reason string
	}{
		{"a self-registrant held for approval", held.Email, held.ID.String(), "registration_pending"},
		{"an invitee who has not accepted", inviteeEmail, inviteeID, "invitation_pending"},
	} {
		t.Run(c.name, func(t *testing.T) {
			prov.signIn(c.email)
			res := upstreamSignIn(t, newConsoleClient(t, w.base), pid)
			want := "/login?reason=" + c.reason
			if res.StatusCode != http.StatusFound || res.Header.Get("Location") != want || len(res.Cookies()) != 0 {
				t.Errorf("upstream sign-in of %s = %d to %q with %d cookies; want 302 to %s and no cookie (O19 through the runtime's wiring)",
					c.name, res.StatusCode, res.Header.Get("Location"), len(res.Cookies()), want)
			}
			if !unlinked(c.id) {
				t.Errorf("the refused sign-in linked %s to the upstream identity", c.name)
			}
		})
	}

	// Control: an active member of the same organization signs in, so the
	// refusals above are the pending states', not the fixture's.
	prov.signIn(active.Email)
	res := upstreamSignIn(t, newConsoleClient(t, w.base), pid)
	if res.StatusCode != http.StatusFound || res.Header.Get("Location") != "/" || cookieNamed(res.Cookies(), "access_token") == nil {
		t.Fatalf("upstream sign-in of an active member = %d to %q; want 302 to / with the console's cookies", res.StatusCode, res.Header.Get("Location"))
	}
}
