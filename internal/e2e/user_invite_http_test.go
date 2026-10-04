//go:build integration

// Package e2e — OSS-ONBOARD-A (owner ruling D-016): an org_admin invites a
// user with a one-time link, through the whole OSS engine (runtime.New +
// Start on the test database).
//
//   - POST /api/v1/users without a password creates a PENDING user and
//     answers the invite once: {user, invite_token, invite_url |
//     invite_url_unavailable, expires_at}. The password create is unchanged.
//   - POST /api/v1/users/:id/invite re-issues for a pending user (older
//     links stop working); a user who is not pending answers 409.
//   - GET /api/v1/auth/invite/:token and POST /api/v1/auth/invite
//     (public) validate and redeem: the password is held to the policy,
//     the user becomes verified and active, the token is spent; expired,
//     spent and unknown share one answer; rate limited like login.
//   - user.invited, user.invite_reissued and user.invite_redeemed are
//     audited with no token in any row.
//   - With SMTP configured (a fake SMTP server in this test) the invite is
//     also mailed and the response still carries it.
//
// Tokens, links and passwords are never printed.
package e2e

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/postgres"
	"github.com/identuum/identuum-idp-oss/internal/runtime"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

const (
	inviteIssuer   = "http://127.0.0.1:7115"
	inviteUIBase   = "http://ui.invite.test"
	invitePassword = "Invite-Pass-2026!x"
	// inviteEncryptionKey is the TEST-ONLY AES-256-GCM key the engine is
	// started with; a helper that seeds a stored secret seals it under the
	// same key.
	inviteEncryptionKey = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
)

type inviteWorld struct {
	t       *testing.T
	ctx     context.Context
	base    string
	pool    *pgxpool.Pool
	repos   *postgres.Repositories
	orgA    *domain.Organization
	orgB    *domain.Organization
	bearers map[string]string
	ids     map[string]uuid.UUID
}

// startInviteEngine starts a runtime with env applied, and bearer tokens
// for an org_admin of A and B, an org_user of A and a site_admin.
func startInviteEngine(t *testing.T, env map[string]string) *inviteWorld {
	t.Helper()
	dbURL := testDBURL(t)
	applyMigrations(t, dbURL)
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	t.Cleanup(cancel)
	pool, err := postgres.NewPool(ctx, dbURL, nil)
	if err != nil {
		t.Fatalf("open pool: error returned (URL redacted): %s", classifyOpenError(err))
	}
	t.Cleanup(pool.Close)
	repos := postgres.NewPgxRepositories(pool, e2eSigningKeyCipher())
	keySvc := service.NewKeyService(repos.Key)
	if active, err := keySvc.ListActive(ctx); err != nil {
		t.Fatalf("ListActive keys: %v", err)
	} else if len(active) == 0 {
		if _, err := keySvc.Generate(ctx, service.GenerateKeyOptions{Algorithm: string(domain.KeyAlgorithmEdDSA), State: domain.KeyStateActive}); err != nil {
			t.Fatalf("Generate signing key: %v", err)
		}
	}
	t.Setenv("IDENTUUM_IDP_ENCRYPTION_KEY", inviteEncryptionKey)
	t.Setenv("IDENTUUM_IDP_ALLOW_MULTI_REPLICA", "true")
	for k, v := range env {
		t.Setenv(k, v)
	}
	rt, err := runtime.New(runtime.Config{Addr: "127.0.0.1:0", Issuer: inviteIssuer, UIPublicBaseURL: env["UI"], JWKSDBURL: dbURL, DataDir: t.TempDir(), Stdout: io.Discard, Stderr: io.Discard})
	if err != nil {
		t.Fatalf("runtime.New: %v", err)
	}
	if err := rt.Start(ctx); err != nil {
		t.Fatalf("runtime.Start: %v", err)
	}
	t.Cleanup(func() {
		sctx, scancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer scancel()
		_ = rt.Shutdown(sctx)
	})
	w := &inviteWorld{t: t, ctx: ctx, base: "http://" + rt.Addr(), pool: pool, repos: repos, bearers: map[string]string{}, ids: map[string]uuid.UUID{}}
	w.orgA = seedTestOrganization(t, ctx, repos)
	w.orgB = seedTestOrganization(t, ctx, repos)
	sessions := service.NewUserSessionService(nil, repos.Session, service.UserSessionServiceOptions{})
	tokens := service.NewUserTokenService(nil, keySvc, service.UserTokenServiceOptions{Issuer: inviteIssuer})
	mint := func(name string, org uuid.UUID, role domain.UserRole) {
		var u *domain.User
		var existing uuid.UUID
		// The installation holds one site_admin; reuse it when present.
		if role == domain.RoleSiteAdmin && pool.QueryRow(ctx, `SELECT id FROM users WHERE role = 'site_admin' AND deleted_at IS NULL LIMIT 1`).Scan(&existing) == nil {
			if u, err = repos.User.GetByID(ctx, existing); err != nil {
				t.Fatalf("load the site_admin: %v", err)
			}
		} else if u, err = repos.User.Create(ctx, &domain.User{ID: uuid.New(), OrganizationID: org, Email: "e2e-invite-" + name + "-" + uuid.NewString() + "@example.invalid",
			PasswordHash: "dm-" + uuid.NewString(), Role: role, AuthSource: domain.AuthSourceLocal, EmailVerified: true}); err != nil {
			t.Fatalf("seed %s: %v", name, err)
		}
		issued, err := sessions.CreateUserSession(ctx, service.CreateUserSessionInput{UserID: u.ID})
		if err != nil {
			t.Fatalf("session %s: %v", name, err)
		}
		tok, err := tokens.IssueForSession(ctx, u, issued.Session)
		if err != nil {
			t.Fatalf("token %s: %v", name, err)
		}
		w.bearers[name] = tok.AccessToken
		w.ids[name] = u.ID
	}
	mint("adminA", w.orgA.ID, domain.RoleOrgAdmin)
	mint("adminB", w.orgB.ID, domain.RoleOrgAdmin)
	mint("userA", w.orgA.ID, domain.RoleOrgUser)
	mint("site", uuid.MustParse(domain.SystemOrgID), domain.RoleSiteAdmin)
	return w
}

func (w *inviteWorld) call(bearer, method, path, body string) (int, map[string]any, string) {
	w.t.Helper()
	req, _ := http.NewRequest(method, w.base+path, strings.NewReader(body))
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		w.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	return res.StatusCode, m, string(raw)
}

// invite creates a pending user as adminA and returns its id and token.
func (w *inviteWorld) invite(email string) (string, string, map[string]any) {
	w.t.Helper()
	st, m, _ := w.call(w.bearers["adminA"], http.MethodPost, "/api/v1/users", `{"email":"`+email+`","name":"Invited Person"}`)
	user, _ := m["user"].(map[string]any)
	id, _ := user["id"].(string)
	tok, _ := m["invite_token"].(string)
	if st != http.StatusCreated || id == "" || tok == "" {
		w.t.Fatalf("invite %s = %d; want 201 with a user and an invite token", email, st)
	}
	return id, tok, m
}

func sha256Hex(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }

func TestE2E_OSS_UserInvite(t *testing.T) {
	w := startInviteEngine(t, map[string]string{"UI": inviteUIBase, "IDENTUUM_IDP_RATE_LIMIT_LOGIN_REQUESTS": "1000"})
	db := w.pool

	// ── 1. Create without a password ───────────────────────────────────────
	email := "invitee-" + uuid.NewString() + "@example.invalid"
	id, tok1, m := w.invite(email)
	user, _ := m["user"].(map[string]any)
	if user["email"] != email || user["email_verified"] != false || user["invitation_pending"] != true {
		t.Errorf("invited user = %v; want the email, email_verified false, invitation_pending true", user)
	}
	if len(tok1) < 64 {
		t.Errorf("invite token has %d characters; want at least 64 hex (256-bit)", len(tok1))
	}
	wantLink := inviteUIBase + "/invite?" + url.Values{"token": {tok1}}.Encode()
	if link, _ := m["invite_url"].(string); link != wantLink || m["invite_url_unavailable"] != nil {
		t.Errorf("invite_url is not the UI's /invite link for this token")
	}
	if exp, _ := m["expires_at"].(string); exp == "" {
		t.Errorf("expires_at missing")
	} else if at, err := time.Parse(time.RFC3339, exp); err != nil || !at.After(time.Now()) {
		t.Errorf("expires_at %q is not a future RFC 3339 time", exp)
	}
	var stored string
	var verified bool
	if err := db.QueryRow(w.ctx, `SELECT activation_token_hash, email_verified FROM users WHERE id = $1`, id).Scan(&stored, &verified); err != nil {
		t.Fatalf("read the invited row: %v", err)
	}
	if stored != sha256Hex(tok1) || stored == tok1 || verified {
		t.Errorf("the invite is stored raw or the user is verified; want only the SHA-256 of the token, unverified")
	}
	if st, _, _ := w.call("", http.MethodPost, "/api/v1/auth/login", `{"email":"`+email+`","password":"`+invitePassword+`"}`); st == http.StatusOK {
		t.Errorf("a pending user signed in before redeeming")
	}
	// The password create keeps working, unchanged.
	st, pm, _ := w.call(w.bearers["adminA"], http.MethodPost, "/api/v1/users", `{"email":"pw-`+uuid.NewString()+`@example.invalid","password":"`+invitePassword+`","role":"org_user"}`)
	if st != http.StatusCreated || pm["id"] == nil || pm["invite_token"] != nil {
		t.Errorf("password create = %d %v; want 201 with the bare safe user and no invite", st, pm)
	}
	pwUserID, _ := pm["id"].(string)

	// Role matrix at today's POST /api/v1/users statuses.
	body := `{"email":"matrix-` + uuid.NewString() + `@example.invalid","organization_id":"` + w.orgA.ID.String() + `"}`
	for _, c := range []struct {
		who  string
		want int
	}{{"", http.StatusUnauthorized}, {"userA", http.StatusForbidden}, {"adminB", http.StatusForbidden}, {"site", http.StatusForbidden}} {
		if st, _, raw := w.call(w.bearers[c.who], http.MethodPost, "/api/v1/users", body); st != c.want || strings.Contains(raw, "invite_token") {
			t.Errorf("invite as %q = %d; want %d and no token", c.who, st, c.want)
		}
	}

	// ── 2. Re-issue ────────────────────────────────────────────────────────
	for _, c := range []struct {
		who  string
		want int
	}{{"", http.StatusUnauthorized}, {"userA", http.StatusForbidden}, {"adminB", http.StatusNotFound}, {"site", http.StatusForbidden}} {
		if st, _, raw := w.call(w.bearers[c.who], http.MethodPost, "/api/v1/users/"+id+"/invite", ""); st != c.want || strings.Contains(raw, "invite_token") {
			t.Errorf("re-issue as %q = %d; want %d and no token", c.who, st, c.want)
		}
	}
	st, rm, _ := w.call(w.bearers["adminA"], http.MethodPost, "/api/v1/users/"+id+"/invite", "")
	tok2, _ := rm["invite_token"].(string)
	if st != http.StatusOK || tok2 == "" || tok2 == tok1 || rm["email"] != email || rm["invite_url"] == nil || rm["expires_at"] == nil {
		t.Fatalf("re-issue = %d; want 200 with a new token, the email, invite_url and expires_at", st)
	}
	for _, c := range []struct{ name, id string }{{"a password-created user", pwUserID}} {
		if st, _, _ := w.call(w.bearers["adminA"], http.MethodPost, "/api/v1/users/"+c.id+"/invite", ""); st != http.StatusConflict {
			t.Errorf("re-issue for %s = %d; want 409", c.name, st)
		}
	}

	// ── 3. Validate and redeem ─────────────────────────────────────────────
	invalid := func(what string, st int, m map[string]any) {
		t.Helper()
		if st != http.StatusBadRequest || m["error"] != "invalid_token" {
			t.Errorf("%s = %d %v; want 400 {\"error\":\"invalid_token\"}", what, st, m)
		}
	}
	st, vm, _ := w.call("", http.MethodGet, "/api/v1/auth/invite/"+tok2, "")
	if st != http.StatusOK || vm["email"] != email {
		t.Errorf("validate = %d %v; want 200 with the email", st, vm)
	}
	st, vm, _ = w.call("", http.MethodGet, "/api/v1/auth/invite/"+tok1, "")
	invalid("validate the retired token", st, vm)
	redeem := func(tok, pw string) (int, map[string]any) {
		st, m, _ := w.call("", http.MethodPost, "/api/v1/auth/invite", `{"token":"`+tok+`","password":"`+pw+`"}`)
		return st, m
	}
	st, vm = redeem(tok1, invitePassword)
	invalid("redeem the retired token", st, vm)
	if st, vm := redeem(tok2, "short"); st != http.StatusBadRequest || vm["error"] != "weak_password" {
		t.Errorf("redeem a weak password = %d %v; want 400 weak_password", st, vm)
	}
	if st, vm := redeem(tok2, invitePassword); st != http.StatusOK || vm["success"] != true {
		t.Fatalf("redeem = %d %v; want 200 success (the weak attempt must not spend the token)", st, vm)
	}
	var hashAfter *string
	if err := db.QueryRow(w.ctx, `SELECT activation_token_hash, email_verified FROM users WHERE id = $1`, id).Scan(&hashAfter, &verified); err != nil || hashAfter != nil || !verified {
		t.Errorf("after redeem: token hash %v, verified %v (err %v); want spent and verified", hashAfter != nil, verified, err)
	}
	st, vm = redeem(tok2, invitePassword)
	invalid("redeem the spent token", st, vm)
	st, vm = redeem(strings.Repeat("ab", 32), invitePassword)
	invalid("redeem an unknown token", st, vm)
	st, vm, _ = w.call("", http.MethodGet, "/api/v1/auth/invite/"+strings.Repeat("ab", 32), "")
	invalid("validate an unknown token", st, vm)
	if st, _, _ := w.call(w.bearers["adminA"], http.MethodPost, "/api/v1/users/"+id+"/invite", ""); st != http.StatusConflict {
		t.Errorf("re-issue for the redeemed user = %d; want 409", st)
	}
	// The redeemed user signs in: past the password (MFA per org policy).
	st, lm, _ := w.call("", http.MethodPost, "/api/v1/auth/login", `{"email":"`+email+`","password":"`+invitePassword+`"}`)
	if lm["error"] == "invalid credentials" || !(st == http.StatusOK || lm["error"] == "mfa_enrollment_required") {
		t.Errorf("sign-in after redeem = %d %v; want past the password", st, lm["error"])
	}
	// Expiry: a fixed instant in the past, set in the row.
	expEmail := "expired-" + uuid.NewString() + "@example.invalid"
	expID, expTok, _ := w.invite(expEmail)
	if _, err := db.Exec(w.ctx, `UPDATE users SET activation_token_expires_at = '2020-01-01T00:00:00Z' WHERE id = $1`, expID); err != nil {
		t.Fatalf("expire: %v", err)
	}
	st, vm, _ = w.call("", http.MethodGet, "/api/v1/auth/invite/"+expTok, "")
	invalid("validate an expired token", st, vm)
	st, vm = redeem(expTok, invitePassword)
	invalid("redeem an expired token", st, vm)
	if st, _, _ := w.call(w.bearers["adminA"], http.MethodPost, "/api/v1/users/"+expID+"/invite", ""); st != http.StatusOK {
		t.Errorf("re-issue for an expired invite = %d; want 200 (still pending)", st)
	}

	// ── 4. Audit: the three events, no token anywhere ──────────────────────
	for ev, want := range map[string]int{"user.invited": 2, "user.invite_reissued": 2, "user.invite_redeemed": 1} {
		var n int
		if err := db.QueryRow(w.ctx, `SELECT count(*) FROM audit_events WHERE event_type = $1 AND actor_organization_id = $2`, ev, w.orgA.ID).Scan(&n); err != nil || n != want {
			t.Errorf("%s rows = %d (err %v); want %d", ev, n, err, want)
		}
	}
	var leaked int
	if err := db.QueryRow(w.ctx, `SELECT count(*) FROM audit_events WHERE metadata::text LIKE '%' || $1 || '%' OR metadata::text LIKE '%' || $2 || '%' OR metadata::text LIKE '%' || $3 || '%'`, tok1, tok2, expTok).Scan(&leaked); err != nil || leaked != 0 {
		t.Errorf("audit rows carrying a token = %d (err %v); want 0", leaked, err)
	}

	// ── 5. The capability the UI gates on ──────────────────────────────────
	st, cm, _ := w.call("", http.MethodGet, "/api/v1/component", "")
	caps, _ := cm["capabilities"].(map[string]any)
	if st != http.StatusOK || caps["user_invite"] != true {
		t.Errorf("capabilities.user_invite = %v; want true", caps["user_invite"])
	}
}

// SMTP configured (a fake SMTP server): the invite is also mailed with
// the /invite link, and the response still carries it. The public routes
// hold the login-class limit (5 per minute by default).
func TestE2E_OSS_UserInvite_SMTPAndRateLimit(t *testing.T) {
	addr, mails := startInviteFakeSMTP(t)
	host, port, _ := net.SplitHostPort(addr)
	w := startInviteEngine(t, map[string]string{
		"UI":                               inviteUIBase,
		"IDENTUUM_IDP_SMTP_HOST":           host,
		"IDENTUUM_IDP_SMTP_PORT":           port,
		"IDENTUUM_IDP_SMTP_FROM":           "no-reply@idp.test",
		"IDENTUUM_IDP_SMTP_ALLOW_INSECURE": "true",
	})
	email := "mailed-" + uuid.NewString() + "@example.invalid"
	_, tok, m := w.invite(email)
	if m["invite_url"] == nil {
		t.Errorf("with SMTP the response no longer carries the link")
	}
	select {
	case got := <-mails:
		if !strings.Contains(got.rcpt, email) || !strings.Contains(got.data, inviteUIBase+"/invite?token="+tok) {
			t.Errorf("the mail did not go to the invitee with the /invite link")
		}
	case <-time.After(15 * time.Second):
		t.Fatalf("no invite mail reached the SMTP server")
	}

	unknown := strings.Repeat("cd", 32)
	var last int
	for i := 0; i < 6; i++ {
		last, _, _ = w.call("", http.MethodPost, "/api/v1/auth/invite", `{"token":"`+unknown+`","password":"`+invitePassword+`"}`)
	}
	if last != http.StatusTooManyRequests {
		t.Errorf("the 6th redeem in a minute = %d; want 429 (login-class limit)", last)
	}
}

type inviteMail struct{ rcpt, data string }

// startInviteFakeSMTP accepts one plaintext SMTP delivery on 127.0.0.1:0.
func startInviteFakeSMTP(t *testing.T) (string, <-chan inviteMail) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("fake smtp listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	ch := make(chan inviteMail, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
		r, wr := bufio.NewReader(conn), bufio.NewWriter(conn)
		reply := func(s string) { _, _ = wr.WriteString(s + "\r\n"); _ = wr.Flush() }
		reply("220 fakesmtp ready")
		var m inviteMail
		var data strings.Builder
		inData := false
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			line = strings.TrimRight(line, "\r\n")
			if inData {
				if line == "." {
					inData = false
					m.data = data.String()
					reply("250 OK")
					continue
				}
				data.WriteString(line + "\n")
				continue
			}
			up := strings.ToUpper(line)
			switch {
			case strings.HasPrefix(up, "EHLO"), strings.HasPrefix(up, "HELO"):
				reply("250-fakesmtp")
				reply("250 8BITMIME")
			case strings.HasPrefix(up, "RCPT TO:"):
				m.rcpt = line
				reply("250 OK")
			case up == "DATA":
				inData = true
				reply("354 go ahead")
			case up == "QUIT":
				reply("221 Bye")
				ch <- m
				return
			default:
				reply("250 OK")
			}
		}
	}()
	return ln.Addr().String(), ch
}
