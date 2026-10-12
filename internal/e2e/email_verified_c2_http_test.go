//go:build integration

// Package e2e — OSS-0912-C2 (owner answers Q1 (a), Q2 (b), Q3 (a) and
// Q-C2-1..4 (a)): `email_verified` in tokens says the mailbox was PROVEN,
// through the whole OSS engine (runtime.New + Start on the test database).
//
//   - An invited user who redeems an administrator's link is activated
//     (users.email_verified) but not proven: email_verified_via is
//     admin_link and userinfo answers email_verified false. Opening a
//     verification email proves it: email_link, userinfo true.
//   - A pending invitee who opens a verification email proves the mailbox
//     and stays pending: the invite link still works (Q-C2-2).
//   - An administrator's edit records admin_set, never a proof; an address
//     change drops a proof; a pre-upgrade row ('legacy') stays verified
//     (Q2). Sign-in and the verified-org_admin count keep reading the
//     activation flag.
//   - POST /api/v1/me/email/verification sends the signed-in user's own
//     link: 401 without a principal, already_verified for a proven mailbox,
//     email_delivery_not_configured without SMTP, the mail with SMTP. The
//     token is never in the body.
//
// Tokens, links and passwords are never printed.
package e2e

import (
	"net"
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// c2Bearers mints, for one user, a token bound to a registered client of
// the user's organization with scope "openid email" (userinfo releases
// email and email_verified under it) and a login-session token (the /me and
// /profile routes).
func (w *inviteWorld) c2Bearers(userID uuid.UUID) (client, session string) {
	w.t.Helper()
	u, err := w.repos.User.GetByID(w.ctx, userID)
	if err != nil {
		w.t.Fatalf("load user: %v", err)
	}
	orgID := u.OrganizationID
	c := &domain.Client{ID: uuid.New(), Name: "c2-" + uuid.NewString()[:8], OrganizationID: &orgID, RedirectURIs: []string{"https://c2.example/cb"}}
	if err := w.repos.Client.RegisterClient(w.ctx, c); err != nil {
		w.t.Fatalf("register client: %v", err)
	}
	sessions := service.NewUserSessionService(nil, w.repos.Session, service.UserSessionServiceOptions{})
	tokens := service.NewUserTokenService(nil, service.NewKeyService(w.repos.Key), service.UserTokenServiceOptions{Issuer: inviteIssuer})
	issued, err := sessions.CreateUserSession(w.ctx, service.CreateUserSessionInput{UserID: u.ID})
	if err != nil {
		w.t.Fatalf("session: %v", err)
	}
	ct, err := tokens.IssueForConsentedClient(w.ctx, u, issued.Session, c.ClientID, "openid email", nil)
	if err != nil {
		w.t.Fatalf("client token: %v", err)
	}
	st, err := tokens.IssueForSession(w.ctx, u, issued.Session)
	if err != nil {
		w.t.Fatalf("session token: %v", err)
	}
	return ct.AccessToken, st.AccessToken
}

// userinfoEmailVerified answers the userinfo email_verified member.
func (w *inviteWorld) userinfoEmailVerified(bearer string) any {
	w.t.Helper()
	st, m, _ := w.call(bearer, http.MethodGet, "/api/v1/oidc/userinfo", "")
	if st != http.StatusOK {
		w.t.Fatalf("userinfo = %d; want 200", st)
	}
	return m["email_verified"]
}

// wantRow checks the activation flag and how the mailbox was proven
// ("" for NULL, never proven).
func (w *inviteWorld) wantRow(what, id string, verified bool, via string) {
	w.t.Helper()
	var gotVerified bool
	var gotVia *string
	if err := w.pool.QueryRow(w.ctx, `SELECT email_verified, email_verified_via FROM users WHERE id = $1`, id).Scan(&gotVerified, &gotVia); err != nil {
		w.t.Errorf("%s: read email_verified_via: %v", what, err)
		return
	}
	v := ""
	if gotVia != nil {
		v = *gotVia
	}
	if gotVerified != verified || v != via {
		w.t.Errorf("%s: email_verified %v, via %q; want %v, %q", what, gotVerified, v, verified, via)
	}
}

// verificationLink stores a verification row for the user, mailed to the
// user's current address, and returns its raw token, as the mailed link
// would carry it.
func (w *inviteWorld) verificationLink(id string) string {
	w.t.Helper()
	var email string
	if err := w.pool.QueryRow(w.ctx, `SELECT email FROM users WHERE id = $1`, id).Scan(&email); err != nil {
		w.t.Fatalf("read address: %v", err)
	}
	return w.verificationLinkFor(id, email)
}

func (w *inviteWorld) redeem(tok string) int {
	w.t.Helper()
	st, _, _ := w.call("", http.MethodPost, "/api/v1/auth/invite", `{"token":"`+tok+`","password":"`+invitePassword+`"}`)
	return st
}

func TestE2E_OSS_C2_RedeemedInviteIsActivatedNotProven(t *testing.T) {
	w := startInviteEngine(t, map[string]string{"UI": inviteUIBase, "IDENTUUM_IDP_RATE_LIMIT_LOGIN_REQUESTS": "1000"})
	id, tok, _ := w.invite("c2-redeemed-" + uuid.NewString() + "@example.invalid")
	if st := w.redeem(tok); st != http.StatusOK {
		t.Fatalf("redeem = %d; want 200", st)
	}
	clientBearer, sessionBearer := w.c2Bearers(uuid.MustParse(id))
	if got := w.userinfoEmailVerified(clientBearer); got != false {
		t.Errorf("userinfo email_verified after an administrator's invite = %v; want false (the administrator also holds the link)", got)
	}
	w.wantRow("after redeem", id, true, "admin_link")
	st, pm, _ := w.call(sessionBearer, http.MethodGet, "/api/v1/profile", "")
	if st != http.StatusOK || pm["email_verified"] != true || pm["email_proven"] != false || pm["email_verified_via"] != "admin_link" {
		t.Errorf("profile = %d email_verified %v email_proven %v email_verified_via %v; want 200, true, false, admin_link",
			st, pm["email_verified"], pm["email_proven"], pm["email_verified_via"])
	}

	// Opening a verification email proves the mailbox.
	if st, _, _ := w.call("", http.MethodGet, "/api/v1/auth/verify-email?token="+w.verificationLink(id), ""); st != http.StatusOK {
		t.Fatalf("verify-email = %d; want 200", st)
	}
	w.wantRow("after the verification email", id, true, "email_link")
	if got := w.userinfoEmailVerified(clientBearer); got != true {
		t.Errorf("userinfo email_verified after the verification email = %v; want true", got)
	}
	if _, pm, _ := w.call(sessionBearer, http.MethodGet, "/api/v1/profile", ""); pm["email_proven"] != true || pm["email_verified_via"] != "email_link" {
		t.Errorf("profile after proof: email_proven %v via %v; want true, email_link", pm["email_proven"], pm["email_verified_via"])
	}
}

func TestE2E_OSS_C2_PendingInviteeProvesMailboxAndKeepsInvite(t *testing.T) {
	w := startInviteEngine(t, map[string]string{"UI": inviteUIBase, "IDENTUUM_IDP_RATE_LIMIT_LOGIN_REQUESTS": "1000"})
	id, tok, _ := w.invite("c2-pending-" + uuid.NewString() + "@example.invalid")
	if st, _, _ := w.call("", http.MethodGet, "/api/v1/auth/verify-email?token="+w.verificationLink(id), ""); st != http.StatusOK {
		t.Fatalf("verify-email = %d; want 200", st)
	}
	w.wantRow("pending invitee after the verification email", id, false, "email_link")
	var pending bool
	if err := w.pool.QueryRow(w.ctx, `SELECT activation_token_hash IS NOT NULL FROM users WHERE id = $1`, id).Scan(&pending); err != nil || !pending {
		t.Errorf("the invite token is gone after the verification email (err %v); want it kept", err)
	}
	if st := w.redeem(tok); st != http.StatusOK {
		t.Fatalf("redeem after the verification email = %d; want 200 (the invite stays usable)", st)
	}
	w.wantRow("after redeem", id, true, "email_link")
	clientBearer, _ := w.c2Bearers(uuid.MustParse(id))
	if got := w.userinfoEmailVerified(clientBearer); got != true {
		t.Errorf("userinfo email_verified for a proven, redeemed invitee = %v; want true", got)
	}
}

func TestE2E_OSS_C2_AdministratorEditsRecordNoProof(t *testing.T) {
	w := startInviteEngine(t, map[string]string{"UI": inviteUIBase, "IDENTUUM_IDP_RATE_LIMIT_LOGIN_REQUESTS": "1000"})
	email := "c2-admin-set-" + uuid.NewString() + "@example.invalid"
	st, pm, _ := w.call(w.bearers["adminA"], http.MethodPost, "/api/v1/users", `{"email":"`+email+`","password":"`+invitePassword+`","role":"org_user"}`)
	id, _ := pm["id"].(string)
	if st != http.StatusCreated || id == "" {
		t.Fatalf("password create = %d; want 201", st)
	}
	w.wantRow("admin create with a password", id, true, "admin_set")
	clientBearer, _ := w.c2Bearers(uuid.MustParse(id))
	if got := w.userinfoEmailVerified(clientBearer); got != false {
		t.Errorf("userinfo email_verified for an admin-created user = %v; want false", got)
	}
	// The sign-in gate reads the activation flag: the admin-set user signs in.
	st, lm, _ := w.call("", http.MethodPost, "/api/v1/auth/login", `{"email":"`+email+`","password":"`+invitePassword+`"}`)
	if lm["error"] == "invalid credentials" || lm["error"] == "email not verified" || !(st == http.StatusOK || lm["error"] == "mfa_enrollment_required" || lm["error"] == "password_change_required" || lm["requires_password_change"] == true) {
		t.Errorf("sign-in of an admin-set user = %d %v; want past the password", st, lm["error"])
	}

	put := func(body string) {
		t.Helper()
		if st, _, _ := w.call(w.bearers["adminA"], http.MethodPut, "/api/v1/users/"+id, body); st != http.StatusOK {
			t.Fatalf("PUT %s = %d; want 200", body, st)
		}
	}
	put(`{"email_verified":false}`)
	w.wantRow("admin sets false", id, false, "")
	put(`{"email_verified":true}`)
	w.wantRow("admin sets true", id, true, "admin_set")
	if _, err := w.pool.Exec(w.ctx, `UPDATE users SET email_verified_via = 'email_link' WHERE id = $1`, id); err != nil {
		t.Errorf("mark proven: %v", err)
	}
	put(`{"email_verified":true}`)
	w.wantRow("admin sets true on a proven mailbox", id, true, "email_link")
	put(`{"name":"Renamed"}`)
	w.wantRow("an unrelated edit", id, true, "email_link")
	put(`{"email":"` + email + `"}`)
	w.wantRow("the same address again", id, true, "email_link")
	put(`{"email":"c2-moved-` + uuid.NewString() + `@example.invalid"}`)
	w.wantRow("an address change", id, true, "admin_set")

	// Q2: a row that was verified before the upgrade keeps its value.
	if _, err := w.pool.Exec(w.ctx, `UPDATE users SET email_verified_via = 'legacy' WHERE id = $1`, id); err != nil {
		t.Errorf("mark legacy: %v", err)
	}
	if got := w.userinfoEmailVerified(clientBearer); got != true {
		t.Errorf("userinfo email_verified for a pre-upgrade verified row = %v; want true", got)
	}

	// The verified-org_admin count reads the activation flag: an activated,
	// unproven org_admin still counts.
	before, err := w.repos.User.CountVerifiedOrgAdminsByOrganization(w.ctx, w.orgA.ID)
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	admin, err := w.repos.User.Create(w.ctx, &domain.User{ID: uuid.New(), OrganizationID: w.orgA.ID, Email: "c2-org-admin-" + uuid.NewString() + "@example.invalid",
		PasswordHash: "dm-" + uuid.NewString(), Role: domain.RoleOrgAdmin, AuthSource: domain.AuthSourceLocal, EmailVerified: true})
	if err != nil {
		t.Fatalf("seed org_admin: %v", err)
	}
	if _, err := w.pool.Exec(w.ctx, `UPDATE users SET email_verified_via = 'admin_link' WHERE id = $1`, admin.ID); err != nil {
		t.Errorf("mark admin_link: %v", err)
	}
	if after, err := w.repos.User.CountVerifiedOrgAdminsByOrganization(w.ctx, w.orgA.ID); err != nil || after != before+1 {
		t.Errorf("verified org_admins = %d (err %v); want %d: an activated org_admin counts whether or not the mailbox is proven", after, err, before+1)
	}
}

var c2TokenShape = regexp.MustCompile(`[0-9a-f]{64}`)

func TestE2E_OSS_C2_SendOwnVerification_NoSMTP(t *testing.T) {
	w := startInviteEngine(t, map[string]string{"UI": inviteUIBase, "IDENTUUM_IDP_RATE_LIMIT_LOGIN_REQUESTS": "1000"})
	const path = "/api/v1/me/email/verification"
	if st, _, _ := w.call("", http.MethodPost, path, ""); st != http.StatusUnauthorized {
		t.Errorf("send without a principal = %d; want 401", st)
	}
	id, tok, _ := w.invite("c2-send-" + uuid.NewString() + "@example.invalid")
	if st := w.redeem(tok); st != http.StatusOK {
		t.Fatalf("redeem = %d; want 200", st)
	}
	_, sessionBearer := w.c2Bearers(uuid.MustParse(id))
	st, m, raw := w.call(sessionBearer, http.MethodPost, path, "")
	if st != http.StatusServiceUnavailable || m["error"] != "email_delivery_not_configured" || c2TokenShape.MatchString(raw) {
		t.Errorf("send without SMTP = %d %v; want 503 email_delivery_not_configured and no token", st, m["error"])
	}
	if _, err := w.pool.Exec(w.ctx, `UPDATE users SET email_verified_via = 'email_link' WHERE id = $1`, id); err != nil {
		t.Errorf("mark proven: %v", err)
	}
	if st, m, _ := w.call(sessionBearer, http.MethodPost, path, ""); st != http.StatusOK || m["status"] != "already_verified" {
		t.Errorf("send for a proven mailbox = %d %v; want 200 already_verified", st, m)
	}
}

func TestE2E_OSS_C2_SendOwnVerification_SMTP(t *testing.T) {
	addr, mails := startInviteFakeSMTP(t)
	host, port, _ := net.SplitHostPort(addr)
	w := startInviteEngine(t, map[string]string{
		"UI":                                     inviteUIBase,
		"IDENTUUM_IDP_RATE_LIMIT_LOGIN_REQUESTS": "1000",
		"IDENTUUM_IDP_SMTP_HOST":                 host,
		"IDENTUUM_IDP_SMTP_PORT":                 port,
		"IDENTUUM_IDP_SMTP_FROM":                 "no-reply@idp.test",
		"IDENTUUM_IDP_SMTP_ALLOW_INSECURE":       "true",
	})
	// A password create mails nothing, so the one fake delivery is the link.
	email := "c2-mailed-" + uuid.NewString() + "@example.invalid"
	st, pm, _ := w.call(w.bearers["adminA"], http.MethodPost, "/api/v1/users", `{"email":"`+email+`","password":"`+invitePassword+`","role":"org_user"}`)
	id, _ := pm["id"].(string)
	if st != http.StatusCreated || id == "" {
		t.Fatalf("password create = %d; want 201", st)
	}
	_, sessionBearer := w.c2Bearers(uuid.MustParse(id))
	st, m, raw := w.call(sessionBearer, http.MethodPost, "/api/v1/me/email/verification", "")
	if st != http.StatusOK || m["status"] != "sent" || c2TokenShape.MatchString(raw) {
		t.Fatalf("send = %d %v; want 200 sent and no token in the body", st, m)
	}
	var link string
	select {
	case got := <-mails:
		if !strings.Contains(got.rcpt, email) {
			t.Errorf("the mail did not go to the user's own address")
		}
		link = c2TokenShape.FindString(got.data)
	case <-time.After(15 * time.Second):
		t.Fatalf("no verification mail reached the SMTP server")
	}
	if link == "" {
		t.Fatalf("the mail carries no verification token")
	}
	if st, _, _ := w.call("", http.MethodGet, "/api/v1/auth/verify-email?token="+link, ""); st != http.StatusOK {
		t.Fatalf("verify-email with the mailed link = %d; want 200", st)
	}
	w.wantRow("after the mailed link", id, true, "email_link")
}
