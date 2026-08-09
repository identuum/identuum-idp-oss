package mw

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/lifecycle"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// stubAuthn returns canned results.
type stubAuthn struct {
	want      *service.AuthenticatedClient
	err       error
	gotID     string
	gotSecret string
}

func (s *stubAuthn) Authenticate(_ context.Context, id, secret, _ string) (*service.AuthenticatedClient, error) {
	s.gotID = id
	s.gotSecret = secret
	if s.err != nil {
		return nil, s.err
	}
	return s.want, nil
}

func buildEngine(t *testing.T, authn OAuthClientAuthenticator) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.POST("/x", RequireOAuthClient(nil, authn), func(c *gin.Context) {
		ac, _ := AuthenticatedClientFromContext(c)
		c.JSON(http.StatusOK, gin.H{"client_id": ac.ClientID, "kind": string(ac.Kind)})
	})
	return r
}

// ---------- Construction ----------

// P-018: a nil authenticator must NOT panic. The factory records a fatal
// fault and returns a fail-closed middleware that rejects every request
// (invalid_client), so the token/introspection/revocation surface is
// refused rather than crashing the process.
func TestRequireOAuthClient_NilAuthnFailsClosed(t *testing.T) {
	report := lifecycle.NewStartupReport()

	var h gin.HandlerFunc
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("RequireOAuthClient(nil authn) panicked: %v", r)
			}
		}()
		h = RequireOAuthClient(report, nil)
	}()

	if !report.HasFatal() {
		t.Fatalf("nil authenticator must record a fatal fault")
	}
	named := false
	for _, f := range report.Faults() {
		if f.Component == "RequireOAuthClient" && f.Severity == lifecycle.SeverityFatal {
			named = true
		}
	}
	if !named {
		t.Errorf("fault must name RequireOAuthClient; got %+v", report.Faults())
	}

	// The returned middleware rejects every request (fail-closed).
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.POST("/x", h, func(c *gin.Context) { c.Status(http.StatusOK) })
	req := httptest.NewRequest(http.MethodPost, "/x", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	// POSITIVE CONTROL — the route must EXIST for "not 200" to mean the guard
	// rejected rather than that nothing was mounted. It is mounted three lines
	// above, in this test, so this can only fail if that line stops working —
	// which is exactly when the assertion below would otherwise go quiet.
	if rec.Code == http.StatusNotFound {
		t.Fatalf("CONTROL FAILED: POST /x is not mounted (404) — the fail-closed assertion " +
			"below would pass against an absent route instead of a rejecting guard")
	}
	if rec.Code == http.StatusOK {
		t.Errorf("fail-closed guard admitted a request (status %d); must reject", rec.Code)
	}
	t.Logf("EVIDENCE RequireOAuthClient nil-authn: no panic; faults=%+v; route status=%d", report.Faults(), rec.Code)
}

// ---------- 401 paths ----------

func TestRequireOAuthClient_NoCredentials401(t *testing.T) {
	st := &stubAuthn{}
	r := buildEngine(t, st)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/x", nil))
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
	if w.Header().Get("WWW-Authenticate") != `Basic realm="oauth-client"` {
		t.Errorf("WWW-Authenticate = %q", w.Header().Get("WWW-Authenticate"))
	}
	body := w.Body.String()
	if !strings.Contains(body, `"error":"invalid_client"`) {
		t.Errorf("body = %q", body)
	}
	if st.gotID != "" || st.gotSecret != "" {
		t.Errorf("authn called despite missing creds: id=%q secret=%q", st.gotID, st.gotSecret)
	}
}

func TestRequireOAuthClient_WrongSecret401(t *testing.T) {
	st := &stubAuthn{err: errors.New("invalid")}
	r := buildEngine(t, st)
	body := strings.NewReader("client_id=cli-1&client_secret=WRONG-SECRET-MUST-NOT-LEAK")
	req := httptest.NewRequest(http.MethodPost, "/x", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
	if strings.Contains(w.Body.String(), "WRONG-SECRET-MUST-NOT-LEAK") {
		t.Errorf("response leaked secret sentinel: %q", w.Body.String())
	}
	// 401 body must NOT contain the secret or any verifier detail.
	if !strings.Contains(w.Body.String(), `"error":"invalid_client"`) || strings.Contains(w.Body.String(), "wrong") {
		t.Errorf("body = %q", w.Body.String())
	}
}

// ---------- Happy paths ----------

func TestRequireOAuthClient_BasicAuthSucceeds(t *testing.T) {
	st := &stubAuthn{want: &service.AuthenticatedClient{
		Kind: service.AuthenticatedClientKindOAuth, ClientID: "cli-1", AuthRecordID: uuid.New(),
	}}
	r := buildEngine(t, st)
	req := httptest.NewRequest(http.MethodPost, "/x", nil)
	creds := base64.StdEncoding.EncodeToString([]byte("cli-1:SEKRET-MUST-NOT-LEAK"))
	req.Header.Set("Authorization", "Basic "+creds)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%q", w.Code, w.Body.String())
	}
	if st.gotID != "cli-1" || st.gotSecret != "SEKRET-MUST-NOT-LEAK" {
		t.Errorf("authn got id=%q secret=%q", st.gotID, st.gotSecret)
	}
	if strings.Contains(w.Body.String(), "SEKRET-MUST-NOT-LEAK") {
		t.Errorf("response leaked secret sentinel")
	}
	if !strings.Contains(w.Body.String(), `"kind":"oauth_client"`) {
		t.Errorf("kind not echoed: %q", w.Body.String())
	}
}

func TestRequireOAuthClient_PostBodySucceeds(t *testing.T) {
	st := &stubAuthn{want: &service.AuthenticatedClient{
		Kind: service.AuthenticatedClientKindOAuth, ClientID: "cli-1",
	}}
	r := buildEngine(t, st)
	body := strings.NewReader("client_id=cli-1&client_secret=POST-SEKRET")
	req := httptest.NewRequest(http.MethodPost, "/x", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	if st.gotID != "cli-1" || st.gotSecret != "POST-SEKRET" {
		t.Errorf("authn got id=%q secret=%q", st.gotID, st.gotSecret)
	}
	if strings.Contains(w.Body.String(), "POST-SEKRET") {
		t.Errorf("response leaked secret")
	}
}

// ---------- Empty fields ----------

func TestRequireOAuthClient_EmptySecretRejected(t *testing.T) {
	st := &stubAuthn{}
	r := buildEngine(t, st)
	body := strings.NewReader("client_id=cli-1&client_secret=")
	req := httptest.NewRequest(http.MethodPost, "/x", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
	if st.gotID != "" {
		t.Errorf("authn called despite empty secret: id=%q", st.gotID)
	}
}

// stubAssertionAuthn satisfies both OAuthClientAuthenticator AND
// OAuthClientAssertionAuthenticator so the middleware's assertion
// path can be exercised.
type stubAssertionAuthn struct {
	stubAuthn
	wantAssert      *service.AuthenticatedClient
	assertErr       error
	gotAssertionID  string
	gotAssertionJWT string
}

func (s *stubAssertionAuthn) AuthenticateAssertion(_ context.Context, id, jwt string) (*service.AuthenticatedClient, error) {
	s.gotAssertionID = id
	s.gotAssertionJWT = jwt
	if s.assertErr != nil {
		return nil, s.assertErr
	}
	return s.wantAssert, nil
}

func TestRequireOAuthClient_AssertionPathSuccess(t *testing.T) {
	want := &service.AuthenticatedClient{Kind: service.AuthenticatedClientKindOAuth, ClientID: "jwt-cli"}
	authn := &stubAssertionAuthn{wantAssert: want}
	r := buildEngine(t, authn)
	body := strings.NewReader(
		"client_id=jwt-cli" +
			"&client_assertion_type=" + service.ClientAssertionTypeJWTBearer +
			"&client_assertion=FAKE-BUT-OPAQUE-JWT",
	)
	req := httptest.NewRequest(http.MethodPost, "/x", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%q", w.Code, w.Body.String())
	}
	if authn.gotAssertionID != "jwt-cli" {
		t.Errorf("assertion id = %q", authn.gotAssertionID)
	}
	if authn.gotAssertionJWT != "FAKE-BUT-OPAQUE-JWT" {
		t.Errorf("assertion jwt not forwarded")
	}
	// The body must not echo the raw assertion.
	if strings.Contains(w.Body.String(), "FAKE-BUT-OPAQUE-JWT") {
		t.Errorf("response leaked raw assertion: %q", w.Body.String())
	}
}

func TestRequireOAuthClient_AssertionPathFailureIs401NoFallback(t *testing.T) {
	authn := &stubAssertionAuthn{assertErr: errors.New("invalid")}
	r := buildEngine(t, authn)
	body := strings.NewReader(
		"client_id=jwt-cli" +
			"&client_secret=correct-secret" + // even with a valid secret, fallback is forbidden
			"&client_assertion_type=" + service.ClientAssertionTypeJWTBearer +
			"&client_assertion=BAD",
	)
	req := httptest.NewRequest(http.MethodPost, "/x", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 (no fallback to secret)", w.Code)
	}
	if authn.gotSecret != "" {
		t.Errorf("middleware fell back to secret auth: %q", authn.gotSecret)
	}
}

func TestRequireOAuthClient_AssertionWithoutClientIDIs401(t *testing.T) {
	authn := &stubAssertionAuthn{wantAssert: &service.AuthenticatedClient{ClientID: "x"}}
	r := buildEngine(t, authn)
	body := strings.NewReader(
		"client_assertion_type=" + service.ClientAssertionTypeJWTBearer +
			"&client_assertion=ANY",
	)
	req := httptest.NewRequest(http.MethodPost, "/x", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 for missing client_id", w.Code)
	}
}

func TestRequireOAuthClient_AssertionUnwiredAuthn401(t *testing.T) {
	// Plain stubAuthn does NOT implement OAuthClientAssertionAuthenticator.
	authn := &stubAuthn{want: &service.AuthenticatedClient{ClientID: "x"}}
	r := buildEngine(t, authn)
	body := strings.NewReader(
		"client_id=jwt-cli" +
			"&client_assertion_type=" + service.ClientAssertionTypeJWTBearer +
			"&client_assertion=ANY",
	)
	req := httptest.NewRequest(http.MethodPost, "/x", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 when assertion seam is unwired", w.Code)
	}
}

func TestRequireOAuthClient_AuthenticatedClientPlantedInContext(t *testing.T) {
	want := &service.AuthenticatedClient{
		Kind: service.AuthenticatedClientKindAPIResource, ClientID: "https://api.example.com",
	}
	r := buildEngine(t, &stubAuthn{want: want})
	body := strings.NewReader("client_id=https://api.example.com&client_secret=RES-S")
	req := httptest.NewRequest(http.MethodPost, "/x", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), `"kind":"api_resource"`) {
		t.Errorf("api_resource kind not echoed: %q", w.Body.String())
	}
}
