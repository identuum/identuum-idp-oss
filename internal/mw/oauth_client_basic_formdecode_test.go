package mw

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/service"
)

// FUNC-M8 (audits/oss-functionality-2026-10-05.md): RFC 6749 §2.3.1 says the
// client identifier and secret are form-encoded before they are joined for
// HTTP Basic. A resource server whose identifier is its audience URL
// (https://api.example.com) has a ':' in it, so the raw form splits at the
// wrong place; the encoded form must be decoded before the check.
func TestRequireOAuthClient_BasicCredentialsAreFormDecoded(t *testing.T) {
	const id = "https://api.example.com/v1"
	const secret = "s3cr et+/%x"
	st := &stubAuthn{want: &service.AuthenticatedClient{
		Kind: service.AuthenticatedClientKindAPIResource, ClientID: id, AuthRecordID: uuid.New(),
	}}
	r := buildEngine(t, st)
	req := httptest.NewRequest(http.MethodPost, "/x", nil)
	req.SetBasicAuth(url.QueryEscape(id), url.QueryEscape(secret))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK || st.gotID != id || st.gotSecret != secret {
		t.Fatalf("form-encoded Basic = %d, authn got id ok=%v secret ok=%v; want 200 with the decoded values", w.Code, st.gotID == id, st.gotSecret == secret)
	}

	// A malformed escape is not a credential: 401 invalid_client, never a 500.
	bad := httptest.NewRequest(http.MethodPost, "/x", nil)
	bad.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("cli%zz:secret")))
	w = httptest.NewRecorder()
	r.ServeHTTP(w, bad)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("a malformed escape = %d; want 401", w.Code)
	}
}
