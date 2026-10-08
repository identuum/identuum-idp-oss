package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/identuum/identuum-idp-oss/internal/service"
)

// F7 P15 (owner ruling bb): the refresh family a code exchange starts records
// the acr of the sign-in behind the code, so the refresh grant can apply an
// organization's MFA floor at every later renewal.
func TestToken_OfflineAccessFamilyRecordsTheSignInACR(t *testing.T) {
	r, codes, refresh, _, session := newAuthCodeEngineWithRefreshSvc(t)
	session.Acr = service.ACRMFA
	verifier, challenge := authCodePKCEPair(t)
	created, _ := codes.Create(context.Background(), service.CreateAuthorizationCodeInput{
		ClientID: "cli-1", UserID: session.UserID, SessionID: session.ID,
		RedirectURI: "https://app.example.com/cb", Scope: "openid offline_access",
		CodeChallenge: challenge, CodeChallengeMethod: "S256",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/oauth/token", strings.NewReader("grant_type=authorization_code&code="+created.Code+
		"&client_id=cli-1&client_secret=S&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb&code_verifier="+verifier))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("exchange status = %d", w.Code)
	}
	var resp struct {
		RefreshToken string `json:"refresh_token"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.RefreshToken == "" {
		t.Fatal("no refresh_token for offline_access")
	}
	consumed, err := refresh.Consume(context.Background(), service.ConsumeRefreshTokenInput{RawToken: resp.RefreshToken, ClientID: "cli-1"})
	if err != nil {
		t.Fatalf("consume: %v", err)
	}
	if consumed.AuthACR != service.ACRMFA {
		t.Fatalf("the family records acr %q; want the sign-in's %q", consumed.AuthACR, service.ACRMFA)
	}
}
