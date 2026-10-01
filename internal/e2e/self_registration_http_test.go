//go:build integration

// OSS-REGISTER-API (owner ruling D-021, rulings a-c of 2026-10-01): self-
// registration through the real engine and its database. Both switches off
// by default; the instance switch is the ceiling; a closed, unknown or
// idp_only organization answers byte for byte alike, and so do a new and an
// existing address; a self-registrant is org_user only; the sign-in gate of
// every other user is unchanged. No password, token or link is printed.
package e2e

import (
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
)

const regPassword = "Self-Reg-Pass-2026!x"

func (w *inviteWorld) raw(bearer, method, path, body string) (int, string) {
	w.t.Helper()
	st, _, raw := w.call(bearer, method, path, body)
	return st, raw
}

func (w *inviteWorld) register(slug, email string) (int, string) {
	return w.raw("", http.MethodPost, "/api/v1/auth/register/"+slug, `{"email":"`+email+`","name":"Self Reg","password":"`+regPassword+`"}`)
}

func (w *inviteWorld) login(email string) (int, string) {
	st, m, _ := w.call("", http.MethodPost, "/api/v1/auth/login", `{"email":"`+email+`","password":"`+regPassword+`"}`)
	e, _ := m["error"].(string)
	return st, e
}

func (w *inviteWorld) regState(email string) (role, state string, verified bool, n int) {
	_ = w.pool.QueryRow(w.ctx, `SELECT count(*) FROM users WHERE email = $1 AND deleted_at IS NULL`, email).Scan(&n)
	_ = w.pool.QueryRow(w.ctx, `SELECT role, coalesce(registration_state,''), email_verified FROM users WHERE email = $1 AND deleted_at IS NULL`, email).Scan(&role, &state, &verified)
	return
}

func (w *inviteWorld) orgPolicy(bearer string, orgID uuid.UUID, body string) (int, string) {
	return w.raw(bearer, http.MethodPut, "/api/v1/organizations/"+orgID.String()+"/registration", body)
}

func TestE2E_OSS_SelfRegistration(t *testing.T) {
	w := startInviteEngine(t, map[string]string{"UI": inviteUIBase,
		"IDENTUUM_IDP_RATE_LIMIT_LOGIN_REQUESTS": "1000", "IDENTUUM_IDP_RATE_LIMIT_REGISTER_REQUESTS": "1000",
		// A configured but unreachable relay: verification can be required;
		// sends fail, which the flow tolerates.
		"IDENTUUM_IDP_SMTP_HOST": "127.0.0.1", "IDENTUUM_IDP_SMTP_PORT": "9", "IDENTUUM_IDP_SMTP_FROM": "idp@example.invalid"})
	// The shared test database: start from, and leave, the default.
	resetInstance := func() { w.pool.Exec(w.ctx, `UPDATE instance_settings SET self_registration_enabled = false`) }
	resetInstance()
	t.Cleanup(resetInstance)
	slug := w.orgA.OrgSlug
	email := func(p string) string { return p + "-" + uuid.NewString()[:8] + "@" + w.orgA.Domain }
	_, closed := w.raw("", http.MethodGet, "/api/v1/auth/register/"+slug, "")
	_, closedPost := w.register(slug, email("closed"))
	if closed != `{"open":false}` || closedPost != `{"accepted":true}` {
		t.Fatalf("defaults: GET %s POST %s; want both switches off", closed, closedPost)
	}
	if _, b := w.raw("", http.MethodGet, "/api/v1/auth/register/no-such-org-"+uuid.NewString()[:8], ""); b != closed {
		t.Fatalf("unknown org answers %s, not the closed body", b)
	}

	// Item 1: the instance switch is the ceiling; only an org_admin sets its org.
	policy := `{"allow_public_registration":true,"require_registration_approval":false,"verify_email":true,"email_domains":[]}`
	if st, b := w.orgPolicy(w.bearers["adminA"], w.orgA.ID, policy); st != http.StatusConflict || !strings.Contains(b, "instance_registration_disabled") {
		t.Fatalf("opening an org while the instance is off = %d %s; want 409", st, b)
	}
	if st, _ := w.raw(w.bearers["adminA"], http.MethodPut, "/api/v1/settings/self-registration", `{"enabled":true}`); st != http.StatusForbidden {
		t.Fatalf("org_admin sets the instance switch = %d; want 403", st)
	}
	if st, _ := w.raw(w.bearers["site"], http.MethodPut, "/api/v1/settings/self-registration", `{"enabled":true}`); st != http.StatusOK {
		t.Fatalf("site_admin instance switch = %d", st)
	}
	if st, _ := w.orgPolicy(w.bearers["site"], w.orgA.ID, policy); st != http.StatusForbidden {
		t.Fatalf("site_admin sets a tenant's policy = %d; want 403", st)
	}
	if st, _ := w.orgPolicy(w.bearers["adminB"], w.orgA.ID, policy); st != http.StatusForbidden {
		t.Fatalf("another org's admin = %d; want 403", st)
	}
	if st, b := w.orgPolicy(w.bearers["adminA"], w.orgA.ID, policy); st != http.StatusOK {
		t.Fatalf("org_admin opens its org = %d %s", st, b)
	}
	var audited int
	_ = w.pool.QueryRow(w.ctx, `SELECT count(*) FROM audit_events WHERE event_type IN ('instance.self_registration_updated','organization.registration_updated')`).Scan(&audited)
	if audited < 2 {
		t.Fatalf("switch changes audited %d times; want both", audited)
	}

	// Item 2: an open organization says what its form needs.
	if _, b := w.raw("", http.MethodGet, "/api/v1/auth/register/"+slug, ""); !strings.Contains(b, `"open":true`) || !strings.Contains(b, `"verify_email":true`) || !strings.Contains(b, `"min_length":8`) {
		t.Fatalf("open org info = %s", b)
	}
	// Ruling c: idp_only (and the unknown org above) answer as closed.
	if _, err := w.pool.Exec(w.ctx, `UPDATE organizations SET auth_policy = 'idp_only', allow_public_registration = true WHERE id = $1`, w.orgB.ID); err != nil {
		t.Fatal(err)
	}
	if _, b := w.raw("", http.MethodGet, "/api/v1/auth/register/"+w.orgB.OrgSlug, ""); b != closed {
		t.Fatalf("idp_only org answers %s", b)
	}
	if _, b := w.register(w.orgB.OrgSlug, "x-"+uuid.NewString()[:8]+"@"+w.orgB.Domain); b != closedPost {
		t.Fatalf("idp_only POST answers %s", b)
	}

	// Item 3: one 202; a weak password is the only other answer.
	if st, b := w.raw("", http.MethodPost, "/api/v1/auth/register/"+slug, `{"email":"`+email("weak")+`","password":"short"}`); st != http.StatusBadRequest || !strings.Contains(b, "weak_password") {
		t.Fatalf("weak password = %d %s", st, b)
	}
	reg := email("reg")
	if st, b := w.register(slug, reg); st != http.StatusAccepted || b != closedPost {
		t.Fatalf("new address = %d %s", st, b)
	}
	if role, state, verified, n := w.regState(reg); n != 1 || role != "org_user" || state != "active" || verified {
		t.Fatalf("self-registrant = %s %s verified %v count %d; want one unverified active org_user", role, state, verified, n)
	}
	if st, b := w.register(slug, reg); st != http.StatusAccepted || b != closedPost {
		t.Fatalf("existing address = %d %s; want the same 202", st, b)
	}
	if _, _, _, n := w.regState(reg); n != 1 {
		t.Fatalf("existing address created a second row")
	}

	// Item 4: verification on: refused as today; resend works.
	if st, e := w.login(reg); st != http.StatusUnauthorized || e != "account_unverified" {
		t.Fatalf("unverified sign-in with verify on = %d %s", st, e)
	}
	var before, after int
	_ = w.pool.QueryRow(w.ctx, `SELECT count(*) FROM email_verifications v JOIN users u ON u.id = v.user_id WHERE u.email = $1`, reg).Scan(&before)
	if st, _ := w.raw("", http.MethodPost, "/api/v1/auth/resend-verification", `{"email":"`+reg+`"}`); st != http.StatusOK {
		t.Fatalf("resend = %d", st)
	}
	_ = w.pool.QueryRow(w.ctx, `SELECT count(*) FROM email_verifications v JOIN users u ON u.id = v.user_id WHERE u.email = $1`, reg).Scan(&after)
	if before != 1 || after != 2 {
		t.Fatalf("verification rows %d then %d; want the initial one, then a resend", before, after)
	}

	// Ruling b: verification off, the self-registrant signs in unverified;
	// MFA follows the org's policy (item 5).
	w.orgPolicy(w.bearers["adminA"], w.orgA.ID, strings.Replace(policy, `"verify_email":true`, `"verify_email":false`, 1))
	if st, e := w.login(reg); st != http.StatusOK {
		t.Fatalf("self-registrant, verify off = %d %s; want a session", st, e)
	}
	w.pool.Exec(w.ctx, `UPDATE organizations SET mfa_policy = 'required' WHERE id = $1`, w.orgA.ID)
	if st, e := w.login(reg); st != http.StatusUnauthorized || e != "mfa_enrollment_required" {
		t.Fatalf("MFA required by the org = %d %s", st, e)
	}
	w.pool.Exec(w.ctx, `UPDATE organizations SET mfa_policy = 'optional' WHERE id = $1`, w.orgA.ID)
	// Ruling b: a user who did not self-register stays refused unverified.
	plain := email("plain")
	if _, err := w.pool.Exec(w.ctx, `INSERT INTO users (id, organization_id, email, password_hash, role, auth_source, email_verified)
		SELECT gen_random_uuid(), $1, $2, password_hash, 'org_user', 'local', false FROM users WHERE email = $3`, w.orgA.ID, plain, reg); err != nil {
		t.Fatal(err)
	}
	if st, e := w.login(plain); st != http.StatusUnauthorized || e != "account_unverified" {
		t.Fatalf("non-self-registered unverified = %d %s; want today's refusal", st, e)
	}

	// Domains: another domain is accepted and creates nothing.
	w.orgPolicy(w.bearers["adminA"], w.orgA.ID, `{"allow_public_registration":true,"email_domains":["`+w.orgA.Domain+`"]}`)
	other := "other-" + uuid.NewString()[:8] + "@elsewhere.invalid"
	if _, b := w.register(slug, other); b != closedPost {
		t.Fatalf("wrong domain = %s", b)
	}
	if _, _, _, n := w.regState(other); n != 0 {
		t.Fatalf("wrong domain created a user")
	}

	// Item 6: approval holds a registrant; org_admin lists, approves, rejects.
	w.orgPolicy(w.bearers["adminA"], w.orgA.ID, `{"allow_public_registration":true,"require_registration_approval":true}`)
	held, gone := email("held"), email("gone")
	w.register(slug, held)
	w.register(slug, gone)
	if st, e := w.login(held); st != http.StatusForbidden || e != "registration_pending" {
		t.Fatalf("pending sign-in = %d %s", st, e)
	}
	_, list := w.raw(w.bearers["adminA"], http.MethodGet, "/api/v1/organizations/"+w.orgA.ID.String()+"/registrations", "")
	if !strings.Contains(list, held) || !strings.Contains(list, gone) {
		t.Fatalf("pending list misses a registrant")
	}
	var heldID, goneID string
	w.pool.QueryRow(w.ctx, `SELECT id::text FROM users WHERE email = $1`, held).Scan(&heldID)
	w.pool.QueryRow(w.ctx, `SELECT id::text FROM users WHERE email = $1`, gone).Scan(&goneID)
	if st, _ := w.raw(w.bearers["adminB"], http.MethodPost, "/api/v1/users/"+heldID+"/reject", ""); st != http.StatusNotFound {
		t.Fatalf("cross-org reject = %d; want 404", st)
	}
	if st, _ := w.raw(w.bearers["adminA"], http.MethodPost, "/api/v1/users/"+heldID+"/approve", ""); st != http.StatusOK {
		t.Fatalf("approve = %d", st)
	}
	if st, _ := w.login(held); st != http.StatusOK {
		t.Fatalf("approved sign-in = %d", st)
	}
	if st, _ := w.raw(w.bearers["adminA"], http.MethodPost, "/api/v1/users/"+goneID+"/reject", ""); st != http.StatusNoContent {
		t.Fatalf("reject = %d", st)
	}
	if _, _, _, n := w.regState(gone); n != 0 {
		t.Fatalf("rejected registrant still present")
	}
	if st, _ := w.raw(w.bearers["adminA"], http.MethodPost, "/api/v1/users/"+heldID+"/reject", ""); st != http.StatusConflict {
		t.Fatalf("reject of an approved user = %d; want 409", st)
	}
	var registered int
	_ = w.pool.QueryRow(w.ctx, `SELECT count(*) FROM audit_events WHERE event_type IN ('user.self_registered','user.registration_approved','user.registration_rejected')`).Scan(&registered)
	if registered < 4 {
		t.Fatalf("registration events audited %d times", registered)
	}

	// The instance switch overrides an open organization.
	w.raw(w.bearers["site"], http.MethodPut, "/api/v1/settings/self-registration", `{"enabled":false}`)
	if _, b := w.raw("", http.MethodGet, "/api/v1/auth/register/"+slug, ""); b != closed {
		t.Fatalf("instance off answers %s", b)
	}
}

// Without SMTP verification cannot be required; sign-up is rate-limited.
func TestE2E_OSS_SelfRegistration_NoSMTPAndRateLimit(t *testing.T) {
	w := startInviteEngine(t, map[string]string{"UI": inviteUIBase, "IDENTUUM_IDP_RATE_LIMIT_REGISTER_REQUESTS": "2"})
	w.raw(w.bearers["site"], http.MethodPut, "/api/v1/settings/self-registration", `{"enabled":true}`)
	t.Cleanup(func() { w.pool.Exec(w.ctx, `UPDATE instance_settings SET self_registration_enabled = false`) })
	if st, b := w.orgPolicy(w.bearers["adminA"], w.orgA.ID, `{"allow_public_registration":true,"verify_email":true}`); st != http.StatusBadRequest || !strings.Contains(b, "smtp_not_configured") {
		t.Fatalf("verify without SMTP = %d %s; want 400 smtp_not_configured", st, b)
	}
	codes := []int{}
	for i := 0; i < 3; i++ {
		st, _ := w.register(w.orgA.OrgSlug, "rl-"+uuid.NewString()[:8]+"@"+w.orgA.Domain)
		codes = append(codes, st)
	}
	if codes[0] != http.StatusAccepted || codes[1] != http.StatusAccepted || codes[2] != http.StatusTooManyRequests {
		t.Fatalf("register under a limit of 2 = %v; want 202 202 429", codes)
	}
}
