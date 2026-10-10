package handlers

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	"github.com/identuum/identuum-idp-oss/internal/service"
)

// OSS-PUBLIC-CLIENT-PKCE-OPTION (owner decision 2026-10-10): "PKCE required" is
// a per-client setting, on by default. A public client an org_admin turned it
// off for redeems a code minted without a challenge with client_id alone; a
// challenge bound to its code is still verified; every other client's
// credential-less exchange without a verifier is refused exactly as before.

// codeWithoutChallenge mints a code bound to no PKCE challenge, as /authorize
// does for a confidential client or a public client with PKCE turned off.
func (f *publicExchangeFixture) codeWithoutChallenge(t *testing.T, clientID string) string {
	t.Helper()
	created, err := f.codes.Create(context.Background(), service.CreateAuthorizationCodeInput{
		ClientID: clientID, UserID: f.user.ID, SessionID: f.session.ID, RedirectURI: publicTestRedirect, Scope: "openid",
	})
	if err != nil {
		t.Fatalf("create code: %v", err)
	}
	return created.Code
}

// RULE: PKCE-REQUIRED-DEFAULT-1
func TestToken_PKCERequiredIsPerClient_OnByDefault_OffOnlyForTheOptedOutPublicClient(t *testing.T) {
	t.Run("opted-out public client redeems a challenge-less code without a verifier", func(t *testing.T) {
		f := newPublicExchangeFixture(t)
		status, body := f.post(url.Values{
			"grant_type": {"authorization_code"}, "client_id": {publicNoPKCETestClientID},
			"code": {f.codeWithoutChallenge(t, publicNoPKCETestClientID)}, "redirect_uri": {publicTestRedirect},
		})
		if status != http.StatusOK {
			t.Fatalf("opted-out public client exchange = %d %v; want 200", status, body["error"])
		}
		if tok, _ := body["access_token"].(string); tok == "" {
			t.Error("no access_token")
		}
	})
	t.Run("a public client with PKCE on (the default) is refused as before", func(t *testing.T) {
		f := newPublicExchangeFixture(t)
		status, body := f.post(url.Values{
			"grant_type": {"authorization_code"}, "client_id": {publicTestClientID},
			"code": {f.codeWithoutChallenge(t, publicTestClientID)}, "redirect_uri": {publicTestRedirect},
		})
		if status != http.StatusUnauthorized || body["error"] != "invalid_client" {
			t.Fatalf("default public client without verifier = %d %v; want 401 invalid_client", status, body["error"])
		}
	})
	t.Run("a confidential client without its secret is refused as before", func(t *testing.T) {
		f := newPublicExchangeFixture(t)
		status, body := f.post(url.Values{
			"grant_type": {"authorization_code"}, "client_id": {confidentialTestClientID},
			"code": {f.codeWithoutChallenge(t, confidentialTestClientID)}, "redirect_uri": {publicTestRedirect},
		})
		if status != http.StatusUnauthorized || body["error"] != "invalid_client" {
			t.Fatalf("confidential client without secret = %d %v; want 401 invalid_client", status, body["error"])
		}
	})
	t.Run("a challenge bound to the opted-out client's code is still verified", func(t *testing.T) {
		f := newPublicExchangeFixture(t)
		code, verifier := f.code(t, publicNoPKCETestClientID, "openid")
		for _, tc := range []struct {
			name, verifier string
		}{{"missing verifier", ""}, {"wrong verifier", verifier + "x"}} {
			form := url.Values{
				"grant_type": {"authorization_code"}, "client_id": {publicNoPKCETestClientID},
				"code": {code}, "redirect_uri": {publicTestRedirect},
			}
			if tc.verifier != "" {
				form.Set("code_verifier", tc.verifier)
			}
			if status, body := f.post(form); status != http.StatusBadRequest || body["error"] != "invalid_grant" {
				t.Errorf("%s = %d %v; want 400 invalid_grant", tc.name, status, body["error"])
			}
		}
		code, verifier = f.code(t, publicNoPKCETestClientID, "openid")
		status, body := f.post(url.Values{
			"grant_type": {"authorization_code"}, "client_id": {publicNoPKCETestClientID},
			"code": {code}, "redirect_uri": {publicTestRedirect}, "code_verifier": {verifier},
		})
		if status != http.StatusOK {
			t.Errorf("right verifier = %d %v; want 200", status, body["error"])
		}
	})
	t.Run("the opted-out client's redirect_uri must still match exactly", func(t *testing.T) {
		f := newPublicExchangeFixture(t)
		status, body := f.post(url.Values{
			"grant_type": {"authorization_code"}, "client_id": {publicNoPKCETestClientID},
			"code": {f.codeWithoutChallenge(t, publicNoPKCETestClientID)}, "redirect_uri": {publicTestRedirect + "/other"},
		})
		if status != http.StatusBadRequest || body["error"] != "invalid_grant" {
			t.Fatalf("redirect_uri mismatch = %d %v; want 400 invalid_grant", status, body["error"])
		}
	})
}
