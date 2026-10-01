//go:build integration

// OSS-HARDEN item 3 (owner ruling, the F5 follow-up): under the step-status
// opt-in (X-Identuum-Login-Step-Status: 200) the remaining expected next-step
// answers — password_change_required at POST /api/v1/auth/login, and the MFA
// continuation of POST /api/v1/auth/login/password-change — answer 200 with
// the same body (the one-time handle aside), never a session, a cookie or a
// token. Without the opt-in they are unchanged. Through the real engine.
//
// Passwords, tokens and handles are never printed.
package e2e

import (
	"io"
	"net/http"
	"regexp"
	"strings"
	"testing"
)

var stepHandle = regexp.MustCompile(`"session_id":"[^"]*"`)

// stepCall posts body to path with or without the opt-in; it returns the
// status, the body with the one-time handle blanked, the handle, and whether
// any cookie was set.
func stepCall(w *inviteWorld, path, body string, optIn bool) (int, string, string, bool) {
	w.t.Helper()
	req, _ := http.NewRequest(http.MethodPost, w.base+path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if optIn {
		req.Header.Set("X-Identuum-Login-Step-Status", "200")
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		w.t.Fatalf("POST %s: %v", path, err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	handle := ""
	if m := stepHandle.FindString(string(raw)); m != "" {
		handle = strings.TrimSuffix(strings.TrimPrefix(m, `"session_id":"`), `"`)
	}
	return res.StatusCode, stepHandle.ReplaceAllString(string(raw), `"session_id":""`), handle, len(res.Cookies()) > 0
}

func assertNoCredential(t *testing.T, label, body string, cookie bool) {
	t.Helper()
	if cookie {
		t.Errorf("%s: a cookie was set", label)
	}
	if strings.Contains(body, "access_token") || strings.Contains(body, "refresh_token") {
		t.Errorf("%s: the answer carried a token", label)
	}
}

func TestE2E_OSS_LoginStepStatus_PasswordChange(t *testing.T) {
	w := startInviteEngine(t, map[string]string{"UI": inviteUIBase, "IDENTUUM_IDP_RATE_LIMIT_LOGIN_REQUESTS": "1000"})
	login := func(email string, optIn bool) (int, string, string, bool) {
		return stepCall(w, "/api/v1/auth/login", `{"email":"`+email+`","password":"`+adminSetPassword+`"}`, optIn)
	}

	// password_change_required at the password step.
	_, emailA := w.createWithPassword("")
	_, emailB := w.createWithPassword("")
	defSt, defBody, defHandle, defCookie := login(emailA, false)
	optSt, optBody, optHandle, optCookie := login(emailB, true)
	if defSt != http.StatusUnauthorized || !strings.Contains(defBody, `"error":"password_change_required"`) || defHandle == "" {
		t.Fatalf("default password step = %d %s; want 401 password_change_required with a handle", defSt, defBody)
	}
	if optSt != http.StatusOK || optBody != defBody || optHandle == "" {
		t.Fatalf("opt-in password step = %d %s; want 200 with the default body %s", optSt, optBody, defBody)
	}
	assertNoCredential(t, "password step, default", defBody, defCookie)
	assertNoCredential(t, "password step, opt-in", optBody, optCookie)

	// The MFA continuation of the password change, under an MFA policy.
	if _, err := w.pool.Exec(w.ctx, `UPDATE organizations SET mfa_policy = 'required' WHERE id = $1`, w.orgA.ID); err != nil {
		t.Fatalf("require MFA in the organization: %v", err)
	}
	_, emailC := w.createWithPassword("")
	_, emailD := w.createWithPassword("")
	change := func(email string, optIn bool) (int, string, string, bool) {
		_, _, h, _ := login(email, false)
		if h == "" {
			t.Fatalf("no change handle for a password user")
		}
		return stepCall(w, "/api/v1/auth/login/password-change", `{"session_id":"`+h+`","new_password":"`+firstOwnPassword+`"}`, optIn)
	}
	cDefSt, cDefBody, cDefHandle, cDefCookie := change(emailC, false)
	cOptSt, cOptBody, cOptHandle, cOptCookie := change(emailD, true)
	if cDefSt != http.StatusUnauthorized || !strings.Contains(cDefBody, `"error":"mfa_enrollment_required"`) || cDefHandle == "" {
		t.Fatalf("default continuation = %d %s; want 401 mfa_enrollment_required with a handle", cDefSt, cDefBody)
	}
	if cOptSt != http.StatusOK || cOptBody != cDefBody || cOptHandle == "" {
		t.Fatalf("opt-in continuation = %d %s; want 200 with the default body %s", cOptSt, cOptBody, cDefBody)
	}
	assertNoCredential(t, "continuation, default", cDefBody, cDefCookie)
	assertNoCredential(t, "continuation, opt-in", cOptBody, cOptCookie)

	// A wrong password is unchanged by the opt-in.
	for _, optIn := range []bool{false, true} {
		st, body, _, _ := stepCall(w, "/api/v1/auth/login", `{"email":"`+emailA+`","password":"wrong-Pass-1!"}`, optIn)
		if st != http.StatusUnauthorized || body != `{"error":"invalid_credentials"}` {
			t.Errorf("wrong password, opt-in %v = %d %s; want 401 invalid_credentials", optIn, st, body)
		}
	}
}
