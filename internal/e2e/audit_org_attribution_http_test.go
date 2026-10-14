//go:build integration

package e2e

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/crypto"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/repository"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// This runs the production mux, writers and PostgreSQL reader. Credentials and
// response bodies stay local to the HTTP call; diagnostics contain no material.
// RULE: AUDIT-ORG-ATTRIBUTION-1
func TestE2E_OSSAuditOrgAttribution(t *testing.T) {
	w := startInviteEngine(t, map[string]string{"UI": "http://localhost:7104", "ISSUER": "http://localhost:7113", "IDENTUUM_IDP_RATE_LIMIT_LOGIN_REQUESTS": "1000"})
	historicalID := uuid.New()
	if _, err := w.pool.Exec(w.ctx, `INSERT INTO audit_events (id, event_type, actor_type, actor_organization_id, priority, metadata) VALUES ($1, 'mfa_disabled', 'user', $2, 'normal', '{"legacy":true}')`, historicalID, w.orgA.ID); err != nil {
		t.Fatal("seed historical audit row failed")
	}
	var historicalBefore string
	if err := w.pool.QueryRow(w.ctx, `SELECT row_to_json(e)::text FROM audit_events e WHERE id=$1`, historicalID).Scan(&historicalBefore); err != nil {
		t.Fatal("read historical fixture failed")
	}
	probe := t
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	call := func(bearer, method, path, body, contentType string, cookies ...*http.Cookie) (int, map[string]any, string, []*http.Cookie) {
		probe.Helper()
		ua := "audit-org-" + uuid.NewString()
		req, err := http.NewRequest(method, w.base+path, strings.NewReader(body))
		if err != nil {
			probe.Fatal("construct request failed")
		}
		req.Header.Set("User-Agent", ua)
		for _, cookie := range cookies {
			req.AddCookie(cookie)
		}
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}
		res, err := client.Do(req)
		if err != nil {
			probe.Fatal("HTTP request failed")
		}
		defer res.Body.Close()
		out := map[string]any{}
		_ = json.NewDecoder(res.Body).Decode(&out)
		return res.StatusCode, out, ua, res.Cookies()
	}
	must := func(want, got int, step string) {
		probe.Helper()
		if got != want {
			probe.Fatalf("%s status %d; want %d", step, got, want)
		}
	}
	visible := func(action, ua string, org uuid.UUID) {
		probe.Helper()
		var id uuid.UUID
		var target *uuid.UUID
		if err := w.pool.QueryRow(w.ctx, `SELECT id, organization_id FROM audit_events WHERE event_type=$1 AND user_agent=$2`, action, ua).Scan(&id, &target); err != nil {
			probe.Errorf("%s: expected writer row not found", action)
			return
		}
		if target == nil || *target != org {
			probe.Errorf("%s: target organization missing or wrong", action)
		}
		for _, who := range []string{"adminA", "adminB"} {
			st, out, _, _ := call(w.bearers[who], http.MethodGet, "/api/v1/audit/events?limit=200&event_type="+url.QueryEscape(action)+"&actor_organization_id="+w.orgA.ID.String(), "", "")
			must(http.StatusOK, st, "read audit as "+who)
			seen := false
			for _, raw := range out["events"].([]any) {
				e := raw.(map[string]any)
				seen = seen || e["id"] == id.String()
			}
			if seen != (who == "adminA") {
				probe.Errorf("%s: %s visibility %v; want %v", action, who, seen, who == "adminA")
			}
		}
	}
	seed := func(mfa bool, role domain.UserRole) *domain.User {
		probe.Helper()
		hash, err := crypto.GenerateHash([]byte("Audit-Org-Test-Password-1!"))
		if err != nil {
			probe.Fatal("hash fixture password failed")
		}
		u, err := w.repos.User.Create(w.ctx, &domain.User{ID: uuid.New(), OrganizationID: w.orgA.ID,
			Email: "audit-org-" + uuid.NewString() + "@example.invalid", PasswordHash: hash, Role: role,
			AuthSource: domain.AuthSourceLocal, EmailVerified: true, MFAEnabled: mfa,
			MFARecoveryCodes: []string{crypto.HashSecret("audit-org-fixture-recovery")}})
		if err != nil {
			probe.Fatal("seed tenant user failed")
		}
		if mfa {
			if _, err := w.repos.User.Update(w.ctx, u.ID, w.orgA.ID, repository.UpdateUserOptions{MFARecoveryCodes: []string{crypto.HashSecret("audit-org-fixture-recovery")}}); err != nil {
				probe.Fatal("store fixture recovery proof failed")
			}
		}
		return u
	}
	loginBody := func(u *domain.User, extra string) string {
		return `{"email":"` + u.Email + `","password":"Audit-Org-Test-Password-1!"` + extra + `}`
	}

	t.Run("MFA disable already attributed", func(t *testing.T) {
		probe = t
		if _, err := w.repos.User.Update(w.ctx, w.ids["userA"], w.orgA.ID, repository.UpdateUserOptions{
			MFAEnabled: boolPtr(true), MFARecoveryCodes: []string{crypto.HashSecret("audit-org-fixture-recovery")},
		}); err != nil {
			t.Fatal("seed disable proof failed")
		}
		st, _, ua, _ := call(w.bearers["userA"], http.MethodPost, "/api/v1/me/mfa/disable", `{"code":"audit-org-fixture-recovery"}`, "application/json")
		must(http.StatusNoContent, st, "disable MFA")
		visible("mfa_disabled", ua, w.orgA.ID)
	})
	t.Run("failed replay already attributed", func(t *testing.T) {
		probe = t
		app := &domain.Client{ID: uuid.New(), ClientID: "audit-replay-" + uuid.NewString(), Name: "Audit replay", OrganizationID: &w.orgA.ID,
			IsPublic: true, RedirectURIs: []string{"https://example.invalid/cb"}, BackchannelLogoutURI: "https://127.0.0.1:1/logout"}
		if err := w.repos.Client.RegisterClient(w.ctx, app); err != nil {
			t.Fatal("seed replay app failed")
		}
		userID := w.ids["userA"]
		row := &domain.BackchannelLogoutDelivery{ID: uuid.New(), ClientID: app.ClientID, UserID: &userID, LogoutJTI: uuid.NewString(), Status: domain.BackchannelLogoutDeliveryFailed}
		if err := w.repos.BackchannelLogoutDelivery.Insert(w.ctx, row); err != nil {
			t.Fatal("seed delivery failed")
		}
		st, _, ua, _ := call(w.bearers["adminA"], http.MethodPost, "/api/v1/admin/backchannel-logout-deliveries/"+row.ID.String()+"/replay", "", "")
		must(http.StatusAccepted, st, "failed replay")
		visible("backchannel_logout_delivery.replayed", ua, w.orgA.ID)
	})
	t.Run("recovery sign-in", func(t *testing.T) {
		probe = t
		u := seed(true, domain.RoleOrgUser)
		st, _, ua, _ := call("", http.MethodPost, "/api/v1/auth/login", loginBody(u, `,"totp_code":"audit-org-fixture-recovery"`), "application/json")
		must(http.StatusOK, st, "recovery sign-in")
		visible("user_session.login.mfa_recovery_code_consumed", ua, w.orgA.ID)
	})
	t.Run("MFA sign-in step", func(t *testing.T) {
		probe = t
		u := seed(true, domain.RoleOrgUser)
		st, _, ua, _ := call("", http.MethodPost, "/api/v1/auth/login", loginBody(u, ""), "application/json")
		must(http.StatusUnauthorized, st, "MFA step")
		visible("user_session.login.mfa_required", ua, w.orgA.ID)
	})
	t.Run("MFA enrollment sign-in step", func(t *testing.T) {
		probe = t
		u := seed(false, domain.RoleOrgAdmin)
		st, _, ua, _ := call("", http.MethodPost, "/api/v1/auth/login", loginBody(u, ""), "application/json")
		must(http.StatusUnauthorized, st, "MFA enrollment step")
		visible("user_session.login.mfa_enrollment_required", ua, w.orgA.ID)
	})
	t.Run("required password changed", func(t *testing.T) {
		probe = t
		u := seed(false, domain.RoleOrgUser)
		if _, err := w.pool.Exec(w.ctx, `UPDATE users SET requires_password_change=true, admin_password_set_at=NOW() WHERE id=$1`, u.ID); err != nil {
			t.Fatal("seed required change failed")
		}
		st, out, _, _ := call("", http.MethodPost, "/api/v1/auth/login", loginBody(u, ""), "application/json")
		must(http.StatusUnauthorized, st, "password change step")
		handle, _ := out["session_id"].(string)
		st, _, ua, _ := call("", http.MethodPost, "/api/v1/auth/login/password-change", `{"session_id":"`+handle+`","new_password":"Audit-Org-New-Password-2!"}`, "application/json")
		must(http.StatusOK, st, "complete required password change")
		visible("user_session.login.password_changed", ua, w.orgA.ID)
	})
	t.Run("refresh without bearer", func(t *testing.T) {
		probe = t
		u := seed(false, domain.RoleOrgUser)
		st, out, _, _ := call("", http.MethodPost, "/api/v1/auth/login", loginBody(u, `,"remember_me":true`), "application/json")
		must(http.StatusOK, st, "sign in for refresh")
		refresh, _ := out["refresh_token"].(string)
		st, _, ua, _ := call("", http.MethodPost, "/api/v1/auth/session/refresh", `{"refresh_token":"`+refresh+`"}`, "application/json")
		must(http.StatusOK, st, "rotate refresh")
		visible("user_session.refresh.success", ua, w.orgA.ID)
	})
	t.Run("browser sign-in", func(t *testing.T) {
		probe = t
		u := seed(false, domain.RoleOrgUser)
		res, err := client.Get(w.base + "/api/v1/auth/browser-login")
		if err != nil {
			t.Fatal("browser form request failed")
		}
		raw, err := io.ReadAll(res.Body)
		res.Body.Close()
		if err != nil {
			t.Fatal("browser form read failed")
		}
		match := regexp.MustCompile(`name="csrf_token" value="([^"]+)"`).FindSubmatch(raw)
		if len(match) != 2 {
			t.Fatal("browser form proof absent")
		}
		form := url.Values{"email": {u.Email}, "password": {"Audit-Org-Test-Password-1!"}, "csrf_token": {string(match[1])}}
		st, _, ua, _ := call("", http.MethodPost, "/api/v1/auth/browser-login", form.Encode(), "application/x-www-form-urlencoded", res.Cookies()...)
		must(http.StatusSeeOther, st, "browser sign-in")
		visible("user_session.browser_login.success", ua, w.orgA.ID)
	})
	t.Run("token issued for tenant resource", func(t *testing.T) {
		probe = t
		audience := "https://audit-org-" + uuid.NewString() + ".example.invalid"
		st, out, _, _ := call(w.bearers["adminA"], http.MethodPost, "/api/v1/api-resources", `{"name":"audit proof","audience":"`+audience+`","scopes":[{"name":"read"}]}`, "application/json")
		must(http.StatusCreated, st, "create resource")
		secret, _ := out["resource_secret"].(string)
		form := url.Values{"grant_type": {"client_credentials"}, "client_id": {audience}, "client_secret": {secret}, "scope": {"read"}}
		st, issued, ua, _ := call("", http.MethodPost, "/api/v1/oauth/token", form.Encode(), "application/x-www-form-urlencoded")
		must(http.StatusOK, st, "tenant resource token")
		visible("oauth_token.issued", ua, w.orgA.ID)
		_ = issued
		st, account, _, _ := call(w.bearers["adminA"], http.MethodPost, "/api/v1/organizations/"+w.orgA.ID.String()+"/service-accounts", `{"name":"audit token subject","role":"org_user"}`, "application/json")
		must(http.StatusCreated, st, "create token subject")
		saID, err := uuid.Parse(account["id"].(string))
		if err != nil {
			t.Fatal("token subject identity absent")
		}
		app := &domain.Client{ID: uuid.New(), ClientID: "audit-revoke-" + uuid.NewString(), Name: "Audit revoke", OrganizationID: &w.orgA.ID,
			ServiceAccountID: &saID, RedirectURIs: []string{"https://example.invalid/cb"}, ClientSecretHash: crypto.HashSecret("audit-app-fixture"), TokenEndpointAuthMethod: "client_secret_post", Scope: "read", AllowedAudiences: []string{audience}}
		if err := w.repos.Client.RegisterClient(w.ctx, app); err != nil {
			t.Fatal("seed revocation app failed")
		}
		form.Set("client_id", app.ClientID)
		form.Set("client_secret", "audit-app-fixture")
		form.Set("audience", audience)
		st, issued, _, _ = call("", http.MethodPost, "/api/v1/oauth/token", form.Encode(), "application/x-www-form-urlencoded")
		must(http.StatusOK, st, "tenant app token")
		access, _ := issued["access_token"].(string)
		form.Set("token", access)
		form.Set("token_type_hint", "access_token")
		st, _, ua, _ = call("", http.MethodPost, "/api/v1/oauth/revoke", form.Encode(), "application/x-www-form-urlencoded")
		must(http.StatusOK, st, "revoke tenant resource token")
		visible(string(domain.AuditOAuthTokenRevoked), ua, w.orgA.ID)
	})
	t.Run("cookie logout and redirect", func(t *testing.T) {
		probe = t
		app := &domain.Client{ID: uuid.New(), ClientID: "audit-logout-" + uuid.NewString(), Name: "Audit logout", OrganizationID: &w.orgA.ID,
			RedirectURIs: []string{"https://example.invalid/cb"}, PostLogoutRedirectURIs: []string{"https://example.invalid/bye"}}
		if err := w.repos.Client.RegisterClient(w.ctx, app); err != nil {
			t.Fatal("seed logout app failed")
		}
		cookie := &http.Cookie{Name: browserSessionCookieName, Value: w.browserSession("userA")}
		mac := hmac.New(sha256.New, []byte(cookie.Value))
		mac.Write([]byte("identuum end-session confirmation"))
		query := url.Values{"client_id": {app.ClientID}, "post_logout_redirect_uri": {app.PostLogoutRedirectURIs[0]}, "confirm": {hex.EncodeToString(mac.Sum(nil))}}
		st, _, ua, _ := call("", http.MethodGet, "/api/v1/oidc/logout?"+query.Encode(), "", "", cookie)
		must(http.StatusFound, st, "cookie logout")
		visible("user_session.logout.cookie_revoked", ua, w.orgA.ID)
		visible("user_session.logout.redirected", ua, w.orgA.ID)
	})
	t.Run("browser authorization code", func(t *testing.T) {
		probe = t
		app := &domain.Client{ID: uuid.New(), ClientID: "audit-authorize-" + uuid.NewString(), Name: "Audit authorize", OrganizationID: &w.orgA.ID,
			RedirectURIs: []string{"https://example.invalid/cb"}, Scope: "openid", SkipConsent: true, ClientSecretHash: crypto.HashSecret("audit-app-fixture")}
		if err := w.repos.Client.RegisterClient(w.ctx, app); err != nil {
			t.Fatal("seed authorize app failed")
		}
		cookie := &http.Cookie{Name: browserSessionCookieName, Value: w.browserSession("userA")}
		query := url.Values{"client_id": {app.ClientID}, "redirect_uri": {app.RedirectURIs[0]}, "response_type": {"code"}, "scope": {"openid"}}
		st, _, ua, _ := call("", http.MethodGet, "/api/v1/oauth/authorize?"+query.Encode(), "", "", cookie)
		must(http.StatusFound, st, "browser authorization")
		visible("oauth_authorize.code_issued", ua, w.orgA.ID)
	})
	for _, decision := range []string{"approve", "deny"} {
		t.Run("browser consent "+decision, func(t *testing.T) {
			probe = t
			app := &domain.Client{ID: uuid.New(), ClientID: "audit-consent-" + uuid.NewString(), Name: "Audit consent", OrganizationID: &w.orgA.ID,
				RedirectURIs: []string{"https://example.invalid/cb"}, Scope: "openid", ClientSecretHash: crypto.HashSecret("audit-app-fixture")}
			if err := w.repos.Client.RegisterClient(w.ctx, app); err != nil {
				t.Fatal("seed consent app failed")
			}
			cookie := &http.Cookie{Name: browserSessionCookieName, Value: w.browserSession("userA")}
			res, err := client.Get(w.base + "/api/v1/auth/browser-login")
			if err != nil {
				t.Fatal("consent form request failed")
			}
			raw, err := io.ReadAll(res.Body)
			res.Body.Close()
			if err != nil {
				t.Fatal("consent form read failed")
			}
			match := regexp.MustCompile(`name="csrf_token" value="([^"]+)"`).FindSubmatch(raw)
			if len(match) != 2 {
				t.Fatal("consent form proof absent")
			}
			cookies := append(res.Cookies(), cookie)
			form := url.Values{"action": {decision}, "client_id": {app.ClientID}, "redirect_uri": {app.RedirectURIs[0]}, "response_type": {"code"}, "scope": {"openid"}, "csrf_token": {string(match[1])}}
			st, _, ua, _ := call("", http.MethodPost, "/api/v1/oauth/consent", form.Encode(), "application/x-www-form-urlencoded", cookies...)
			must(http.StatusFound, st, "browser consent")
			action := "oauth_consent.granted"
			if decision == "deny" {
				action = "oauth_consent.denied"
			}
			visible(action, ua, w.orgA.ID)
		})
	}
	t.Run("step-up failure has known user", func(t *testing.T) {
		probe = t
		cookie := &http.Cookie{Name: browserSessionCookieName, Value: w.browserSession("userA")}
		res, err := client.Get(w.base + "/api/v1/auth/browser-login")
		if err != nil {
			t.Fatal("step-up form request failed")
		}
		raw, err := io.ReadAll(res.Body)
		res.Body.Close()
		if err != nil {
			t.Fatal("step-up form read failed")
		}
		match := regexp.MustCompile(`name="csrf_token" value="([^"]+)"`).FindSubmatch(raw)
		if len(match) != 2 {
			t.Fatal("step-up form proof absent")
		}
		cookies := append(res.Cookies(), cookie)
		form := url.Values{"totp_code": {"invalid"}, "csrf_token": {string(match[1])}}
		st, _, ua, _ := call("", http.MethodPost, "/api/v1/auth/step-up", form.Encode(), "application/x-www-form-urlencoded", cookies...)
		must(http.StatusForbidden, st, "step-up without MFA")
		visible("user_session.step_up.failure", ua, w.orgA.ID)
	})
	t.Run("passkey step-up failure has known user", func(t *testing.T) {
		probe = t
		cookie := &http.Cookie{Name: browserSessionCookieName, Value: w.browserSession("userA")}
		st, _, ua, _ := call("", http.MethodPost, "/api/v1/auth/step-up/passkey?session_id="+uuid.NewString(), `{}`, "application/json", cookie)
		must(http.StatusUnauthorized, st, "step-up with invalid assertion")
		visible("user_session.step_up.passkey_failure", ua, w.orgA.ID)
	})

	t.Run("frontchannel cookie logout", func(t *testing.T) {
		probe = t
		cookie := &http.Cookie{Name: browserSessionCookieName, Value: w.browserSession("userA")}
		st, _, ua, _ := call("", http.MethodGet, "/api/v1/oidc/frontchannel-logout", "", "", cookie)
		must(http.StatusOK, st, "frontchannel logout")
		visible("user_session.frontchannel_logout", ua, w.orgA.ID)
	})
	t.Run("TOTP step-up success", func(t *testing.T) {
		probe = t
		cipher, err := crypto.NewCryptoService(inviteEncryptionKey)
		if err != nil {
			t.Fatal("fixture cipher unavailable")
		}
		const seed = "JBSWY3DPEHPK3PXP"
		sealed, err := cipher.Encrypt(seed)
		if err != nil {
			t.Fatal("seal fixture failed")
		}
		if _, err := w.repos.User.Update(w.ctx, w.ids["userA"], w.orgA.ID, repository.UpdateUserOptions{MFAEnabled: boolPtr(true), MFASecret: &sealed}); err != nil {
			t.Fatal("store fixture enrollment failed")
		}
		cookie := &http.Cookie{Name: browserSessionCookieName, Value: w.browserSession("userA")}
		res, err := client.Get(w.base + "/api/v1/auth/browser-login")
		if err != nil {
			t.Fatal("step-up form request failed")
		}
		raw, err := io.ReadAll(res.Body)
		res.Body.Close()
		if err != nil {
			t.Fatal("step-up form read failed")
		}
		match := regexp.MustCompile(`name="csrf_token" value="([^"]+)"`).FindSubmatch(raw)
		if len(match) != 2 {
			t.Fatal("step-up form proof absent")
		}
		cookies := append(res.Cookies(), cookie)
		form := url.Values{"totp_code": {computeTOTPCodeForTest(t, seed, uint64(time.Now().Unix()/30))}, "csrf_token": {string(match[1])}}
		st, _, ua, _ := call("", http.MethodPost, "/api/v1/auth/step-up", form.Encode(), "application/x-www-form-urlencoded", cookies...)
		must(http.StatusSeeOther, st, "verified step-up")
		visible("user_session.step_up.success", ua, w.orgA.ID)
	})
	// Infrastructure events have no tenant target and remain outside both views.
	probe = t
	globalUA := "audit-org-global-" + uuid.NewString()
	if err := service.NewPersistentAuditService(w.repos.Audit).Record(w.ctx, audit.Event{Action: "key.generated", ActorType: "system", UserAgent: globalUA, Timestamp: time.Now()}); err != nil {
		t.Fatal("write infrastructure control failed")
	}
	for _, who := range []string{"adminA", "adminB"} {
		st, out, _, _ := call(w.bearers[who], http.MethodGet, "/api/v1/audit/events?event_type=key.generated", "", "")
		must(http.StatusOK, st, "read infrastructure control")
		if len(out["events"].([]any)) != 0 {
			t.Error("tenant sees infrastructure event")
		}
	}
	var historicalAfter string
	if err := w.pool.QueryRow(w.ctx, `SELECT row_to_json(e)::text FROM audit_events e WHERE id=$1`, historicalID).Scan(&historicalAfter); err != nil || historicalAfter != historicalBefore {
		t.Error("an existing audit row changed")
	}
}
