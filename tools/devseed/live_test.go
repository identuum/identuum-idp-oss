package main

import (
	"bytes"
	"encoding/base32"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/identuum/identuum-idp-oss/pkg/totp"
)

// TestDevseedLive is the credential half of `make devseed-live` (owner ruling
// u, 2026-10-07): every credential `make dev-seed` prints really signs in on
// a live appliance. It runs ONLY when the target hands it the seeded
// credentials (IDENTUUM_DEVSEED_LIVE_CREDS, devseed's --json output in a
// mode-600 file) and otherwise skips, so a plain `go test` touches no network.
//
// Nothing secret is printed: a failure names the check, the HTTP status and
// the response's `error` code, never a body, a password, a secret or a token.
func TestDevseedLive(t *testing.T) {
	path := os.Getenv("IDENTUUM_DEVSEED_LIVE_CREDS")
	if path == "" {
		t.Skip("IDENTUUM_DEVSEED_LIVE_CREDS is unset: run through `make devseed-live`")
	}
	creds := readSeeded(t, path)
	base := strings.TrimRight(creds.Issuer, "/")
	if base == "" {
		t.Fatal("the seeded credentials name no issuer")
	}

	// devseed spent the CURRENT TOTP step of both admins on their enrolment,
	// and a step is single-use (TOTP-SINGLE-USE-1). Wait, once and at most one
	// period, for the next step, so each sign-in below presents an unspent code.
	waitForNextTOTPStep()

	t.Run("site_admin password and TOTP sign in", func(t *testing.T) {
		signInWithTOTP(t, base, creds.SiteAdminUser, creds.SiteAdminPass, creds.SiteAdminTOTP)
	})
	t.Run("org_admin password and TOTP sign in", func(t *testing.T) {
		signInWithTOTP(t, base, creds.OrgAdminUser, creds.OrgAdminPass, creds.OrgAdminTOTP)
	})
	// An org_user is asked for TOTP only under an organization mfa_policy
	// "required" (internal/service.IsMFARequiredForUser); devseed's organization
	// sets none, so the password alone signs it in (MANUAL-TEST authn.4).
	t.Run("org_user password alone signs in", func(t *testing.T) {
		status, p := loginStep(t, base, creds.OrgUserUser, creds.OrgUserPass)
		bearer := p.AccessToken != "" || p.Token != ""
		if status != http.StatusOK || !bearer || p.MFARequired || p.MFAEnrollmentRequired {
			t.Fatalf("org_user login: status %d, error %q, bearer issued %v, mfa_required %v, mfa_enrollment_required %v; want 200 with a bearer",
				status, p.Error, bearer, p.MFARequired, p.MFAEnrollmentRequired)
		}
	})
	t.Run("client secret authenticates at the token endpoint and a wrong one does not", func(t *testing.T) {
		endpoint := tokenEndpoint(t, base)
		status, code := tokenRequest(t, endpoint, creds.ClientID, creds.ClientSecret+"-wrong")
		if status != http.StatusUnauthorized || code != "invalid_client" {
			t.Fatalf("wrong secret: status %d, error %q; want 401 invalid_client", status, code)
		}
		status, code = tokenRequest(t, endpoint, creds.ClientID, creds.ClientSecret)
		if code == "invalid_client" || status == http.StatusUnauthorized {
			t.Fatalf("right secret: status %d, error %q; the client did not authenticate", status, code)
		}
		t.Logf("right secret: status %d, error %q (authenticated; the grant is judged after)", status, code)
	})
}

func readSeeded(t *testing.T, path string) seeded {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read the seeded credentials: %v", err)
	}
	// devseed prints its progress lines before the JSON document.
	start := bytes.IndexByte(raw, '{')
	if start < 0 {
		t.Fatal("the seeded credentials file holds no JSON document")
	}
	var s seeded
	if err := json.Unmarshal(raw[start:], &s); err != nil {
		t.Fatalf("the seeded credentials are not devseed's JSON: %v", err)
	}
	return s
}

func waitForNextTOTPStep() {
	now := time.Now().UTC()
	next := now.Truncate(30 * time.Second).Add(30 * time.Second)
	time.Sleep(next.Sub(now) + time.Second)
}

type loginAnswer struct {
	Error                 string `json:"error"`
	SessionID             string `json:"session_id"`
	MFARequired           bool   `json:"mfa_required"`
	MFAEnrollmentRequired bool   `json:"mfa_enrollment_required"`
	AccessToken           string `json:"access_token"`
	Token                 string `json:"token"`
}

func loginStep(t *testing.T, base, email, password string) (int, loginAnswer) {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"email": email, "password": password})
	status, raw, err := postJSON(base+"/api/v1/auth/login", "", body)
	if err != nil {
		t.Fatalf("login request: %v", err)
	}
	var p loginAnswer
	_ = json.Unmarshal(raw, &p)
	return status, p
}

func signInWithTOTP(t *testing.T, base, email, password, secret string) {
	t.Helper()
	if secret == "" {
		t.Fatal("devseed printed no TOTP secret for this account")
	}
	// The password step of an enrolled admin answers 401 mfa_required with the
	// pending session the TOTP step completes.
	status, p := loginStep(t, base, email, password)
	if status != http.StatusUnauthorized || p.Error != "mfa_required" || !p.MFARequired || p.SessionID == "" {
		t.Fatalf("password step: status %d, error %q, mfa_required %v, session %v; want 401 mfa_required with a session",
			status, p.Error, p.MFARequired, p.SessionID != "")
	}
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
	if err != nil {
		t.Fatalf("the printed TOTP secret is not base32: %v", err)
	}
	code := totp.Code(key, uint64(time.Now().UTC().Unix()/30), 6)
	body, _ := json.Marshal(map[string]string{"session_id": p.SessionID, "code": code})
	status, raw, err := postJSON(base+"/api/v1/auth/login/mfa", "", body)
	if err != nil {
		t.Fatalf("TOTP step request: %v", err)
	}
	var done loginAnswer
	_ = json.Unmarshal(raw, &done)
	if status != http.StatusOK || (done.AccessToken == "" && done.Token == "") {
		t.Fatalf("TOTP step: status %d, error %q, bearer issued %v; want 200 with a bearer",
			status, done.Error, done.AccessToken != "" || done.Token != "")
	}
}

func tokenEndpoint(t *testing.T, base string) string {
	t.Helper()
	status, raw, err := getJSON(base+"/.well-known/openid-configuration", "")
	if err != nil || status != http.StatusOK {
		t.Fatalf("discovery: status %d, err %v", status, err)
	}
	var d struct {
		TokenEndpoint string `json:"token_endpoint"`
	}
	if err := json.Unmarshal(raw, &d); err != nil || d.TokenEndpoint == "" {
		t.Fatal("discovery names no token_endpoint")
	}
	// The discovery document names the issuer's host; call the same path on
	// the base the seed used, which is the published port on loopback.
	u, err := url.Parse(d.TokenEndpoint)
	if err != nil {
		t.Fatalf("token_endpoint is not a URL: %v", err)
	}
	return base + u.Path
}

func tokenRequest(t *testing.T, endpoint, clientID, secret string) (int, string) {
	t.Helper()
	form := url.Values{"grant_type": {"client_credentials"}, "scope": {"openid"}}
	req, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("token request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(url.QueryEscape(clientID), url.QueryEscape(secret))
	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("token request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	var p struct {
		Error string `json:"error"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&p)
	return resp.StatusCode, p.Error
}
