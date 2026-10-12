//go:build integration

// Package e2e — OSS-0912-C2-FIX (review OSS-0912-C2-REVIEW R1, R4), through
// the whole OSS engine on the test database:
//
//   - A verification link mailed to a user's OLD address never proves the
//     NEW address (R1; the review's scratch test, kept).
//   - An address change retires the user's open links in the same write;
//     an unrelated edit or the same address again does not.
//   - A link whose row names another address is refused with a plain
//     reason, 400 email_changed, and records nothing.
//   - The site_admin's own send answers 409 not_available_for_this_account
//     (R4).
//
// Tokens, links and passwords are never printed.
package e2e

import (
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// verificationLinkFor stores a live verification row for the user, mailed to
// address, and returns its raw token.
func (w *inviteWorld) verificationLinkFor(id, address string) string {
	w.t.Helper()
	raw := sha256Hex(uuid.NewString())
	if _, err := w.pool.Exec(w.ctx, `INSERT INTO email_verifications (token_hash, user_id, email_hash, expires_at) VALUES ($1, $2, $3, NOW() + INTERVAL '1 hour')`,
		sha256Hex(raw), id, domain.EmailAddressHash(address)); err != nil {
		w.t.Fatalf("seed verification: %v", err)
	}
	return raw
}

// openLinks counts the user's unused verification rows.
func (w *inviteWorld) openLinks(id string) int {
	w.t.Helper()
	var n int
	if err := w.pool.QueryRow(w.ctx, `SELECT count(*) FROM email_verifications WHERE user_id = $1 AND used_at IS NULL`, id).Scan(&n); err != nil {
		w.t.Fatalf("count open links: %v", err)
	}
	return n
}

// adminSetUser creates an org_user with a password (admin_set) and returns
// its id.
func (w *inviteWorld) adminSetUser(email string) string {
	w.t.Helper()
	st, pm, _ := w.call(w.bearers["adminA"], http.MethodPost, "/api/v1/users", `{"email":"`+email+`","password":"`+invitePassword+`","role":"org_user"}`)
	id, _ := pm["id"].(string)
	if st != http.StatusCreated || id == "" {
		w.t.Fatalf("password create = %d; want 201", st)
	}
	return id
}

// R1, the review's red test: the user asks for a link (mailed to the old
// address), an administrator changes the address, the old link is opened.
func TestE2E_OSS_C2_OldAddressLinkDoesNotProveNewAddress(t *testing.T) {
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
	oldAddr := "c2fix-old-" + uuid.NewString() + "@example.invalid"
	id := w.adminSetUser(oldAddr)
	clientBearer, sessionBearer := w.c2Bearers(uuid.MustParse(id))
	if st, m, _ := w.call(sessionBearer, http.MethodPost, "/api/v1/me/email/verification", ""); st != http.StatusOK || m["status"] != "sent" {
		t.Fatalf("send = %d %v; want 200 sent", st, m)
	}
	var link string
	select {
	case got := <-mails:
		if !strings.Contains(got.rcpt, oldAddr) {
			t.Fatalf("mail did not go to the old address")
		}
		link = c2TokenShape.FindString(got.data)
	case <-time.After(15 * time.Second):
		t.Fatalf("no mail")
	}
	if link == "" {
		t.Fatalf("the mail carries no verification token")
	}
	newAddr := "c2fix-new-" + uuid.NewString() + "@example.invalid"
	if st, _, _ := w.call(w.bearers["adminA"], http.MethodPut, "/api/v1/users/"+id, `{"email":"`+newAddr+`"}`); st != http.StatusOK {
		t.Fatalf("PUT email = %d; want 200", st)
	}
	w.wantRow("after the address change", id, true, "admin_set")
	if st, _, _ := w.call("", http.MethodGet, "/api/v1/auth/verify-email?token="+link, ""); st != http.StatusBadRequest {
		t.Errorf("verify-email with the old-address link = %d; want 400", st)
	}
	w.wantRow("after the old-address link", id, true, "admin_set")
	if got := w.userinfoEmailVerified(clientBearer); got != false {
		t.Errorf("userinfo email_verified for the NEW, never-mailed address = %v; want false", got)
	}
}

func TestE2E_OSS_C2_AddressChangeRetiresOpenLinks(t *testing.T) {
	w := startInviteEngine(t, map[string]string{"UI": inviteUIBase, "IDENTUUM_IDP_RATE_LIMIT_LOGIN_REQUESTS": "1000"})
	email := "c2fix-retire-" + uuid.NewString() + "@example.invalid"
	id := w.adminSetUser(email)
	other := w.adminSetUser("c2fix-other-" + uuid.NewString() + "@example.invalid")
	w.verificationLinkFor(id, email)
	w.verificationLinkFor(id, email)
	w.verificationLinkFor(other, "c2fix-other@example.invalid")

	put := func(body string) {
		t.Helper()
		if st, _, _ := w.call(w.bearers["adminA"], http.MethodPut, "/api/v1/users/"+id, body); st != http.StatusOK {
			t.Fatalf("PUT %s = %d; want 200", body, st)
		}
	}
	put(`{"name":"Renamed"}`)
	if n := w.openLinks(id); n != 2 {
		t.Errorf("open links after an unrelated edit = %d; want 2", n)
	}
	put(`{"email":"` + email + `"}`)
	if n := w.openLinks(id); n != 2 {
		t.Errorf("open links after the same address again = %d; want 2", n)
	}
	put(`{"email":"c2fix-moved-` + uuid.NewString() + `@example.invalid"}`)
	if n := w.openLinks(id); n != 0 {
		t.Errorf("open links after an address change = %d; want 0", n)
	}
	if n := w.openLinks(other); n != 1 {
		t.Errorf("another user's open links after the change = %d; want 1", n)
	}
}

func TestE2E_OSS_C2_LinkForAnEarlierAddressIsRefused(t *testing.T) {
	w := startInviteEngine(t, map[string]string{"UI": inviteUIBase, "IDENTUUM_IDP_RATE_LIMIT_LOGIN_REQUESTS": "1000"})
	email := "c2fix-current-" + uuid.NewString() + "@example.invalid"
	id := w.adminSetUser(email)
	stale := w.verificationLinkFor(id, "c2fix-earlier-"+uuid.NewString()+"@example.invalid")
	st, m, _ := w.call("", http.MethodGet, "/api/v1/auth/verify-email?token="+stale, "")
	if st != http.StatusBadRequest || m["error"] != "email_changed" {
		t.Errorf("verify-email with a link for another address = %d %v; want 400 email_changed", st, m["error"])
	}
	w.wantRow("after the refused link", id, true, "admin_set")
	// A link for the current address still proves it.
	if st, _, _ := w.call("", http.MethodGet, "/api/v1/auth/verify-email?token="+w.verificationLinkFor(id, email), ""); st != http.StatusOK {
		t.Fatalf("verify-email with a current link = %d; want 200", st)
	}
	w.wantRow("after the current link", id, true, "email_link")
}

func TestE2E_OSS_C2_SiteAdminOwnSendIsRefused(t *testing.T) {
	w := startInviteEngine(t, map[string]string{"UI": inviteUIBase, "IDENTUUM_IDP_RATE_LIMIT_LOGIN_REQUESTS": "1000"})
	st, m, _ := w.call(w.bearers["site"], http.MethodPost, "/api/v1/me/email/verification", "")
	if st != http.StatusConflict || m["error"] != "not_available_for_this_account" {
		t.Errorf("site_admin send = %d %v; want 409 not_available_for_this_account", st, m["error"])
	}
}
