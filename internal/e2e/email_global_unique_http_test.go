//go:build integration

// Package e2e — OSS-0914-STAGE-2 (owner decision EMAIL-SCOPE (a),
// 2026-10-13): one live email address is one account across the whole
// server. Sign-in asks only for the address, so a second live account with
// the same address in another organization locked both out of password and
// passkey-by-email sign-in. Every writer refuses an address that a live
// account anywhere already uses, whatever its case, and stores the address
// lowercased and trimmed. Proved through the runtime (runtime.New + Start on
// the test database) per writer: organization create, user create, bulk,
// invite, email update, federated first sign-in and organization claim.
//
// Addresses are fixtures under example.invalid; tokens, links, cookies and
// passwords are never printed.
package e2e

import (
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// liveWithEmail counts the live accounts whose address equals email in any
// case and organization.
func (w *inviteWorld) liveWithEmail(email string) int {
	w.t.Helper()
	var n int
	if err := w.pool.QueryRow(w.ctx, `SELECT count(*) FROM users WHERE lower(email) = lower($1) AND deleted_at IS NULL`, email).Scan(&n); err != nil {
		w.t.Fatalf("count live accounts: %v", err)
	}
	return n
}

// storedEmail reads the address stored for a user id.
func (w *inviteWorld) storedEmail(id string) string {
	w.t.Helper()
	var e string
	if err := w.pool.QueryRow(w.ctx, `SELECT email FROM users WHERE id = $1`, id).Scan(&e); err != nil {
		w.t.Fatalf("read user %s: %v", id, err)
	}
	return e
}

// takenIn seeds a live org_user of org with a fresh lowercase address at
// domain and returns the address.
func (w *inviteWorld) takenIn(org uuid.UUID, domainPart string) string {
	w.t.Helper()
	email := "taken-" + uuid.NewString()[:8] + "@" + domainPart
	if _, err := w.repos.User.Create(w.ctx, &domain.User{ID: uuid.New(), OrganizationID: org, Email: email,
		PasswordHash: "dm-" + uuid.NewString(), Role: domain.RoleOrgUser, AuthSource: domain.AuthSourceLocal, EmailVerified: true}); err != nil {
		w.t.Fatalf("seed the address holder: %v", err)
	}
	return email
}

// RULE: EMAIL-GLOBAL-UNIQUE-1
func TestE2E_OSS_EmailGlobalUnique(t *testing.T) {
	w := startInviteEngine(t, map[string]string{"UI": inviteUIBase, "IDENTUUM_IDP_RATE_LIMIT_LOGIN_REQUESTS": "1000"})
	// Each writer gets its own address, held in organization B, so one
	// writer's outcome cannot decide another's.
	held := func() (string, map[string]string) {
		taken := w.takenIn(w.orgB.ID, "example.invalid")
		return taken, map[string]string{"same case": taken, "other case": strings.ToUpper(taken)}
	}

	t.Run("organization_create", func(t *testing.T) {
		taken, variants := held()
		for name, addr := range variants {
			d := "eg-" + uuid.NewString()[:8] + ".example.invalid"
			st, m, _ := w.call(w.bearers["site"], http.MethodPost, "/api/v1/organizations", `{"name":"EG `+d+`","domain":"`+d+`","admin_email":"`+addr+`"}`)
			var orgs int
			_ = w.pool.QueryRow(w.ctx, `SELECT count(*) FROM organizations WHERE domain = $1`, d).Scan(&orgs)
			if st != http.StatusConflict || m["error"] != "email_exists" || orgs != 0 || w.liveWithEmail(taken) != 1 {
				t.Errorf("%s: create = %d %v, organizations %d, accounts %d; want 409 email_exists, nothing created", name, st, m["error"], orgs, w.liveWithEmail(taken))
			}
		}
	})

	t.Run("user_create", func(t *testing.T) {
		taken, variants := held()
		for name, addr := range variants {
			st, m, _ := w.call(w.bearers["adminA"], http.MethodPost, "/api/v1/users", `{"email":"`+addr+`","password":"`+invitePassword+`","role":"org_user"}`)
			if st != http.StatusConflict || m["error"] != "email_exists" || w.liveWithEmail(taken) != 1 {
				t.Errorf("%s: create = %d %v, accounts %d; want 409 email_exists, nothing created", name, st, m["error"], w.liveWithEmail(taken))
			}
		}
		// The same organization: 409 email_exists, as everywhere (was 400).
		own := "own-" + uuid.NewString()[:8] + "@example.invalid"
		body := `{"email":"` + own + `","password":"` + invitePassword + `","role":"org_user"}`
		if st, _, _ := w.call(w.bearers["adminA"], http.MethodPost, "/api/v1/users", body); st != http.StatusCreated {
			t.Fatalf("first create = %d; want 201", st)
		}
		if st, m, _ := w.call(w.bearers["adminA"], http.MethodPost, "/api/v1/users", body); st != http.StatusConflict || m["error"] != "email_exists" {
			t.Errorf("same-organization duplicate = %d %v; want 409 email_exists", st, m["error"])
		}
	})

	t.Run("bulk_create", func(t *testing.T) {
		taken, _ := held()
		fresh := "bulk-" + uuid.NewString()[:8] + "@example.invalid"
		st, m, _ := w.call(w.bearers["adminA"], http.MethodPost, "/api/v1/users/bulk", `{"users":[`+
			`{"email":"`+taken+`","password":"`+invitePassword+`","role":"org_user"},`+
			`{"email":"`+strings.ToUpper(taken)+`","password":"`+invitePassword+`","role":"org_user"},`+
			`{"email":"`+fresh+`","password":"`+invitePassword+`","role":"org_user"}]}`)
		failed, _ := m["failed"].([]any)
		reasons := []string{}
		for _, f := range failed {
			item, _ := f.(map[string]any)
			r, _ := item["reason"].(string)
			reasons = append(reasons, r)
		}
		if st != http.StatusOK || m["created_count"] != float64(1) || len(reasons) != 2 || reasons[0] != "email already exists" || reasons[1] != "email already exists" || w.liveWithEmail(taken) != 1 {
			t.Errorf("bulk = %d created %v reasons %v, accounts %d; want 200, one created, two \"email already exists\"", st, m["created_count"], reasons, w.liveWithEmail(taken))
		}
	})

	t.Run("invite", func(t *testing.T) {
		taken, variants := held()
		for name, addr := range variants {
			st, m, _ := w.call(w.bearers["adminA"], http.MethodPost, "/api/v1/users", `{"email":"`+addr+`","name":"Invitee"}`)
			if st != http.StatusConflict || m["error"] != "email_exists" || m["invite_token"] != nil || w.liveWithEmail(taken) != 1 {
				t.Errorf("%s: invite = %d %v, accounts %d; want 409 email_exists, nothing created", name, st, m["error"], w.liveWithEmail(taken))
			}
		}
	})

	t.Run("email_update", func(t *testing.T) {
		_, variants := held()
		before := w.storedEmail(w.ids["userA"].String())
		for name, addr := range variants {
			st, m, _ := w.call(w.bearers["adminA"], http.MethodPut, "/api/v1/users/"+w.ids["userA"].String(), `{"email":"`+addr+`"}`)
			if st != http.StatusConflict || m["error"] != "email_exists" || w.storedEmail(w.ids["userA"].String()) != before {
				t.Errorf("%s: update = %d %v; want 409 email_exists, the address unchanged", name, st, m["error"])
			}
		}
	})

	t.Run("organization_claim", func(t *testing.T) {
		taken, variants := held()
		org := seedTestOrganization(t, w.ctx, w.repos) // operational, no admin
		_, _, tok := w.issueClaim(org.ID, "")
		for name, addr := range variants {
			if r := w.consumeClaim(tok, addr, claimPassword); r["success"] != false || w.orgAdmins(org.ID) != 0 || w.liveWithEmail(taken) != 1 {
				t.Errorf("%s: claim = %v, org_admins %d, accounts %d; want {success:false}, nothing created", name, r, w.orgAdmins(org.ID), w.liveWithEmail(taken))
			}
		}
	})

	// Every writer stores the address lowercased and trimmed.
	t.Run("stored_lowercase", func(t *testing.T) {
		mixed := func(prefix string) string {
			return prefix + "-" + strings.ToUpper(uuid.NewString()[:8]) + "@Example.Invalid"
		}
		check := func(path, id, sent string) {
			t.Helper()
			if got := w.storedEmail(id); got != strings.ToLower(sent) {
				t.Errorf("%s stored %q; want %q", path, got, strings.ToLower(sent))
			}
		}
		e := mixed("Create")
		st, m, _ := w.call(w.bearers["adminA"], http.MethodPost, "/api/v1/users", `{"email":"`+e+`","password":"`+invitePassword+`","role":"org_user"}`)
		id, _ := m["id"].(string)
		if st != http.StatusCreated {
			t.Fatalf("create = %d; want 201", st)
		}
		check("user create", id, e)

		e = mixed("Invite")
		invited, _, _ := w.invite(e)
		check("invite", invited, e)

		e = mixed("Bulk")
		_, m, _ = w.call(w.bearers["adminA"], http.MethodPost, "/api/v1/users/bulk", `{"users":[{"email":"`+e+`","password":"`+invitePassword+`","role":"org_user"}]}`)
		created, _ := m["created"].([]any)
		if len(created) != 1 {
			t.Fatalf("bulk created %d; want 1", len(created))
		}
		row, _ := created[0].(map[string]any)
		bulkID, _ := row["id"].(string)
		check("bulk", bulkID, e)

		e = mixed("Update")
		if st, _, _ := w.call(w.bearers["adminA"], http.MethodPut, "/api/v1/users/"+id, `{"email":"`+e+`"}`); st != http.StatusOK {
			t.Fatalf("update = %d; want 200", st)
		}
		check("email update", id, e)

		d := "eg-" + uuid.NewString()[:8] + ".example.invalid"
		e = mixed("Org")
		st, m, _ = w.call(w.bearers["site"], http.MethodPost, "/api/v1/organizations", `{"name":"EG `+d+`","domain":"`+d+`","admin_email":" `+e+` "}`)
		if st != http.StatusCreated {
			t.Fatalf("organization create = %d %v; want 201", st, m["error"])
		}
		var adminID string
		if err := w.pool.QueryRow(w.ctx, `SELECT u.id FROM users u JOIN organizations o ON o.id = u.organization_id WHERE o.domain = $1`, d).Scan(&adminID); err != nil {
			t.Fatalf("read the new admin: %v", err)
		}
		check("organization create", adminID, e)

		org := seedTestOrganization(t, w.ctx, w.repos)
		_, _, tok := w.issueClaim(org.ID, "")
		e = mixed("Claim")
		if r := w.consumeClaim(tok, e, claimPassword); r["success"] != true {
			t.Fatalf("claim = %v; want {success:true}", r)
		}
		var claimedID string
		if err := w.pool.QueryRow(w.ctx, `SELECT id FROM users WHERE organization_id = $1 AND role = 'org_admin'`, org.ID).Scan(&claimedID); err != nil {
			t.Fatalf("read the claimed admin: %v", err)
		}
		check("claim", claimedID, e)
	})

	// Control: a fresh address is created, so the refusals above are the
	// address's, not the fixture's.
	t.Run("control: a fresh address is created", func(t *testing.T) {
		fresh := "fresh-" + uuid.NewString()[:8] + "@example.invalid"
		if st, _, _ := w.call(w.bearers["adminB"], http.MethodPost, "/api/v1/users", `{"email":"`+fresh+`","password":"`+invitePassword+`","role":"org_user"}`); st != http.StatusCreated {
			t.Errorf("fresh create = %d; want 201", st)
		}
	})
}

// The federated writer of EMAIL-GLOBAL-UNIQUE-1 (tagged on TestE2E_OSS_EmailGlobalUnique).
func TestE2E_OSS_EmailGlobalUniqueFederatedFirstSignIn(t *testing.T) {
	const clientID = "email-global-upstream-client"
	prov := newUpstreamProvider(t, clientID)
	w := startInviteEngine(t, map[string]string{"UI": inviteUIBase, "IDENTUUM_IDP_RATE_LIMIT_LOGIN_REQUESTS": "1000",
		"IDENTUUM_IDP_TEST_ALLOW_PRIVATE_UPSTREAM_ISSUER": "true"})
	if _, err := w.pool.Exec(w.ctx, `UPDATE organizations SET auth_policy = 'mixed' WHERE id = $1`, w.orgA.ID); err != nil {
		t.Fatalf("set auth_policy mixed: %v", err)
	}
	emailDomain := "eg-" + uuid.NewString()[:8] + ".example.invalid"
	st, m, _ := w.call(w.bearers["adminA"], http.MethodPost, "/api/v1/organizations/"+w.orgA.ID.String()+"/identity-provider",
		`{"type":"oidc","name":"Loopback provider","slug":"eg-`+uuid.NewString()[:8]+`","config":{"issuer_url":"`+prov.srv.URL+`","client_id":"`+clientID+`","client_secret":"not-a-secret-fixture-value","scopes":["openid","email","profile"],"email_domains":["`+emailDomain+`"]}}`)
	idp, _ := m["identity_provider"].(map[string]any)
	pid, _ := idp["id"].(string)
	if st != http.StatusCreated || pid == "" {
		t.Fatalf("register the provider = %d %v; want 201 with the provider", st, m)
	}
	taken := w.takenIn(w.orgB.ID, emailDomain)
	inA := func(email string) int {
		t.Helper()
		var n int
		_ = w.pool.QueryRow(w.ctx, `SELECT count(*) FROM users WHERE organization_id = $1 AND lower(email) = lower($2)`, w.orgA.ID, email).Scan(&n)
		return n
	}

	for name, addr := range map[string]string{"same case": taken, "other case": strings.ToUpper(taken)} {
		t.Run("in use in another organization, "+name, func(t *testing.T) {
			prov.signIn(addr)
			res := upstreamSignIn(t, newConsoleClient(t, w.base), pid)
			want := "/login?reason=sign_in_not_permitted"
			if res.StatusCode != http.StatusFound || res.Header.Get("Location") != want || len(res.Cookies()) != 0 || inA(taken) != 0 {
				t.Errorf("first sign-in = %d to %q with %d cookies, accounts in the provider's organization %d; want 302 to %s, no cookie, nothing created",
					res.StatusCode, res.Header.Get("Location"), len(res.Cookies()), inA(taken), want)
			}
		})
	}

	// Control: a fresh address signs in and is created, lowercased.
	fresh := "Fresh-" + strings.ToUpper(uuid.NewString()[:8]) + "@" + emailDomain
	prov.signIn(fresh)
	res := upstreamSignIn(t, newConsoleClient(t, w.base), pid)
	if res.StatusCode != http.StatusFound || res.Header.Get("Location") != "/" || cookieNamed(res.Cookies(), "access_token") == nil {
		t.Fatalf("first sign-in of a fresh address = %d to %q; want 302 to / with the console's cookies", res.StatusCode, res.Header.Get("Location"))
	}
	var stored string
	if err := w.pool.QueryRow(w.ctx, `SELECT email FROM users WHERE organization_id = $1 AND lower(email) = lower($2)`, w.orgA.ID, fresh).Scan(&stored); err != nil || stored != strings.ToLower(fresh) {
		t.Errorf("the created address is %q (%v); want it lowercased", stored, err)
	}
}
