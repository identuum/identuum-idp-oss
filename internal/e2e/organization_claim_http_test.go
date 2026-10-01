//go:build integration

// OSS-CLAIM (owner ruling D-022, rulings a, b, c of 2026-10-01): a site_admin
// issues an organization claim link; a re-issue retires the earlier one; the
// claim wire (validate {valid}, consume {success}, always 200) is unchanged;
// consume re-checks the organization under the claim lock. Through the real
// engine and its database. No token, link or password is printed.
package e2e

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/google/uuid"
)

const claimPassword = "Claim-Admin-Pass-2026!x"

// issueClaim posts the issue as the site_admin and returns status, body and
// the raw token parsed out of claim_url.
func (w *inviteWorld) issueClaim(orgID uuid.UUID, body string) (int, map[string]any, string) {
	w.t.Helper()
	st, m, _ := w.call(w.bearers["site"], http.MethodPost, "/api/v1/organizations/"+orgID.String()+"/claim", body)
	link, _ := m["claim_url"].(string)
	tok := ""
	if u, err := url.Parse(link); err == nil && link != "" {
		if !strings.HasPrefix(link, inviteUIBase+"/claim?") {
			w.t.Fatalf("claim_url is not the UI's /claim page")
		}
		tok = u.Query().Get("token")
	}
	return st, m, tok
}

func (w *inviteWorld) validateClaim(tok string) bool {
	w.t.Helper()
	st, m, _ := w.call("", http.MethodGet, "/api/v1/auth/claim/validate?token="+url.QueryEscape(tok), "")
	if st != http.StatusOK {
		w.t.Fatalf("validate = %d; the wire is always 200", st)
	}
	v, _ := m["valid"].(bool)
	return v
}

func (w *inviteWorld) consumeClaim(tok, email, password string) map[string]any {
	w.t.Helper()
	st, m, _ := w.call("", http.MethodPost, "/api/v1/auth/claim", `{"token":"`+tok+`","email":"`+email+`","name":"Claim Admin","password":"`+password+`"}`)
	if st != http.StatusOK {
		w.t.Fatalf("consume = %d; the wire is always 200", st)
	}
	return m
}

func (w *inviteWorld) liveClaims(orgID uuid.UUID) int {
	var n int
	_ = w.pool.QueryRow(w.ctx, `SELECT count(*) FROM organization_claims WHERE organization_id = $1`, orgID).Scan(&n)
	return n
}

func (w *inviteWorld) orgAdmins(orgID uuid.UUID) int {
	var n int
	_ = w.pool.QueryRow(w.ctx, `SELECT count(*) FROM users WHERE organization_id = $1 AND role = 'org_admin' AND deleted_at IS NULL`, orgID).Scan(&n)
	return n
}

func TestE2E_OSS_OrganizationClaim(t *testing.T) {
	w := startInviteEngine(t, map[string]string{"UI": inviteUIBase, "IDENTUUM_IDP_RATE_LIMIT_LOGIN_REQUESTS": "1000"})
	org := seedTestOrganization(t, w.ctx, w.repos) // operational, no admin

	// Item 1: issue, site_admin only.
	if st, _, _ := w.call(w.bearers["adminA"], http.MethodPost, "/api/v1/organizations/"+org.ID.String()+"/claim", ""); st != http.StatusForbidden {
		t.Fatalf("org_admin issue = %d; want 403 (site_admin only)", st)
	}
	st, m, first := w.issueClaim(org.ID, "")
	if st != http.StatusCreated || first == "" || m["email_bound"] != false || m["expires_at"] == nil {
		t.Fatalf("issue = %d %v; want 201 {claim_url, expires_at, email_bound:false}", st, m["email_bound"])
	}
	if _, has := m["token"]; has {
		t.Fatalf("the response carries the token only inside claim_url")
	}
	var actor, meta string
	if err := w.pool.QueryRow(w.ctx, `SELECT coalesce(actor_role,''), metadata::text FROM audit_events WHERE event_type = 'claim.generated' AND organization_id = $1 ORDER BY created_at DESC LIMIT 1`, org.ID).Scan(&actor, &meta); err != nil {
		t.Fatalf("claim.generated audit row: %v", err)
	}
	if actor != "site_admin" || strings.Contains(meta, first) || strings.Contains(meta, "claim?") {
		t.Fatalf("claim.generated: actor role %q; carries the token or link %v", actor, strings.Contains(meta, first))
	}
	if !w.validateClaim(first) {
		t.Fatalf("a fresh link validates {valid:true}")
	}

	// Item 2: a re-issue (email-bound) retires the first link.
	st, m, second := w.issueClaim(org.ID, `{"email":"Owner-`+org.ID.String()[:8]+`@example.invalid"}`)
	if st != http.StatusCreated || m["email_bound"] != true || w.liveClaims(org.ID) != 1 {
		t.Fatalf("re-issue = %d bound %v live %d; want 201, bound, one live link", st, m["email_bound"], w.liveClaims(org.ID))
	}
	if w.validateClaim(first) {
		t.Fatalf("the retired link must validate {valid:false}")
	}
	if r := w.consumeClaim(first, "x-"+uuid.NewString()[:8]+"@example.invalid", claimPassword); r["success"] != false {
		t.Fatalf("the retired link must consume {success:false}")
	}

	// A bound link refuses another email, opaquely, and stays usable.
	if r := w.consumeClaim(second, "other@example.invalid", claimPassword); r["success"] != false || len(r) != 1 {
		t.Fatalf("bound-email mismatch = %v; want exactly {success:false}", r)
	}
	if !w.validateClaim(second) {
		t.Fatalf("a mismatch costs an attempt, it does not burn the link")
	}

	// Item 3: consume; the wire is unchanged; the new org_admin enrols MFA.
	owner := "owner-" + org.ID.String()[:8] + "@example.invalid"
	if r := w.consumeClaim(second, owner, claimPassword); r["success"] != true {
		t.Fatalf("consume = %v; want {success:true}", r)
	}
	var consumedActor string
	if err := w.pool.QueryRow(w.ctx, `SELECT coalesce(actor_email,'') FROM audit_events WHERE event_type = 'claim.consumed' AND organization_id = $1 ORDER BY created_at DESC LIMIT 1`, org.ID).Scan(&consumedActor); err != nil || consumedActor != owner {
		t.Fatalf("claim.consumed actor = %q (%v); want the new org_admin", consumedActor, err)
	}
	if st, lm, _ := w.call("", http.MethodPost, "/api/v1/auth/login", `{"email":"`+owner+`","password":"`+claimPassword+`"}`); st != http.StatusUnauthorized || lm["error"] != "mfa_enrollment_required" {
		t.Fatalf("first sign-in = %d %v; want 401 mfa_enrollment_required (org_admin MFA policy)", st, lm["error"])
	}

	// Ruling a: an organization with an active org_admin is not claimable.
	if st, m, _ := w.issueClaim(org.ID, ""); st != http.StatusConflict || m["error"] != "organization_not_claimable" {
		t.Fatalf("issue after the claim = %d %v; want 409 organization_not_claimable", st, m["error"])
	}
	if st, m, _ := w.issueClaim(w.orgA.ID, ""); st != http.StatusConflict || m["error"] != "organization_not_claimable" {
		t.Fatalf("issue on an org with an admin = %d %v; want 409", st, m["error"])
	}
	if st, _, _ := w.issueClaim(uuid.New(), ""); st != http.StatusNotFound {
		t.Fatalf("issue on an unknown org = %d; want 404", st)
	}

	// Ruling a, the race: the organization gains its first admin through the
	// first-admin exception after the link was issued; consume refuses.
	org2 := seedTestOrganization(t, w.ctx, w.repos)
	_, _, raced := w.issueClaim(org2.ID, "")
	if st, _, _ := w.call(w.bearers["site"], http.MethodPost, "/api/v1/users", `{"email":"first-`+org2.ID.String()[:8]+`@example.invalid","password":"`+claimPassword+`","role":"org_admin","organization_id":"`+org2.ID.String()+`"}`); st != http.StatusCreated {
		t.Fatalf("seed the first admin through the exception = %d", st)
	}
	if r := w.consumeClaim(raced, "late-"+uuid.NewString()[:8]+"@example.invalid", claimPassword); r["success"] != false || w.orgAdmins(org2.ID) != 1 {
		t.Fatalf("consume after the org gained an admin = %v, admins %d; want {success:false}, one admin", r, w.orgAdmins(org2.ID))
	}

	// Attempt exhaustion is unchanged: three weak passwords, then exhausted.
	org3 := seedTestOrganization(t, w.ctx, w.repos)
	_, _, weak := w.issueClaim(org3.ID, "")
	for i := 0; i < 3; i++ {
		if r := w.consumeClaim(weak, "weak@example.invalid", "short"); r["success"] != false || r["attempts_remaining"] == nil {
			t.Fatalf("weak attempt %d = %v; want attempts_remaining", i+1, r)
		}
	}
	if r := w.consumeClaim(weak, "weak@example.invalid", claimPassword); r["attempts_exhausted"] != true || w.validateClaim(weak) {
		t.Fatalf("after three weak attempts = %v; want attempts_exhausted and a dead link", r)
	}
}

// Item 1: without a UI base URL no link can be built, so nothing is issued.
func TestE2E_OSS_OrganizationClaim_URLUnavailable(t *testing.T) {
	w := startInviteEngine(t, map[string]string{})
	org := seedTestOrganization(t, w.ctx, w.repos)
	st, m, _ := w.call(w.bearers["site"], http.MethodPost, "/api/v1/organizations/"+org.ID.String()+"/claim", "")
	why, _ := m["claim_url_unavailable"].(string)
	if st != http.StatusConflict || m["error"] != "claim_url_unavailable" || !strings.Contains(why, "IDENTUUM_IDP_UI_PUBLIC_BASE_URL") {
		t.Fatalf("issue without a UI base URL = %d %v; want 409 claim_url_unavailable naming the setting", st, m["error"])
	}
	if n := w.liveClaims(org.ID); n != 0 {
		t.Fatalf("a refused issue left %d claim row(s); want none", n)
	}
}
