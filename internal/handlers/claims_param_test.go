package handlers

// claims_param_test.go — THE-CLAIMS-PARAMETER through the handlers: the
// consent page lists and echoes the §5.5 request, approval persists the
// claim tokens and the code row, the exchange stamps userinfo_claims and
// mints id_token claims, and userinfo releases a consented claim.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/mw"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

const claimsParamRequest = `{"userinfo":{"name":{"essential":true}},"id_token":{"email":null},"foo":{"bar":null},"userinfo_extra":1}`

func newClaimsConsentEngine(t *testing.T) (*gin.Engine, *captureConsentRepo, *handlerAuthCodeRepo) {
	t.Helper()
	gin.SetMode(gin.ReleaseMode)
	consentRepo := &captureConsentRepo{}
	consentSvc := service.NewConsentService(nil, consentRepo)
	client := &domain.Client{
		ClientID: "cli-1", Name: "Test", RedirectURIs: []string{"https://app.example.com/cb"},
		SkipConsent: false, Scope: "openid profile email",
	}
	clients := &fakeAuthorizeClientLookup{client: client}
	codeRepo := newAuthCodeRepoForHandlers()
	codes := service.NewAuthorizationCodeService(nil, codeRepo, service.AuthorizationCodeServiceOptions{TTL: time.Hour})
	authzSvc := service.NewAuthorizeService(nil, clients, codes, service.AuthorizeServiceOptions{Issuer: "https://idp.test"}).
		WithConsentService(consentSvc)
	r := gin.New()
	r.Use(func(c *gin.Context) { mw.SetPrincipal(c, authorizePrincipal()); c.Next() })
	deps := ConsentHandlerDeps{
		ConsentService: consentSvc, AuthorizeService: authzSvc, CookieSession: nil,
		Clients: clients, Audit: &audit.Recorder{},
	}
	r.GET("/api/v1/oauth/consent", HandleConsentForm(deps))
	r.POST("/api/v1/oauth/consent", HandleConsentSubmit(deps))
	return r, consentRepo, codeRepo
}

func TestConsentForm_ListsRequestedClaimsAndEchoesThem(t *testing.T) {
	r, _, _ := newClaimsConsentEngine(t)
	q := url.Values{}
	q.Set("client_id", "cli-1")
	q.Set("redirect_uri", "https://app.example.com/cb")
	q.Set("scope", "openid")
	q.Set("claims", claimsParamRequest)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/oauth/consent?"+q.Encode(), nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%q", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if !strings.Contains(body, "name (shared with the application)") {
		t.Errorf("consent page must list the requested userinfo claim: %s", body)
	}
	if !strings.Contains(body, "email (included in the ID token)") {
		t.Errorf("consent page must list the requested id_token claim: %s", body)
	}
	// The LIST never shows unknown claims/members; the hidden field still
	// echoes the raw parameter verbatim so the approval resumes the request.
	if strings.Contains(body, "<li>bar") || strings.Contains(body, "<li>foo") {
		t.Errorf("unknown claims/members must never be listed: %s", body)
	}
	if !strings.Contains(body, `name="claims"`) {
		t.Errorf("consent page must echo the claims parameter as a hidden field so approval resumes the request: %s", body)
	}
}

func TestConsentSubmit_PersistsClaimTokensAndCodeCarriesThem(t *testing.T) {
	r, consentRepo, codeRepo := newClaimsConsentEngine(t)
	form := url.Values{}
	form.Set("action", "approve")
	form.Set("client_id", "cli-1")
	form.Set("redirect_uri", "https://app.example.com/cb")
	form.Set("scope", "openid")
	form.Set("response_type", "code")
	form.Set("code_challenge", "testchallenge")
	form.Set("code_challenge_method", "S256")
	form.Set("claims", claimsParamRequest)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/oauth/consent", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusFound {
		t.Fatalf("approve status = %d, want 302; body=%q", w.Code, w.Body.String())
	}
	if consentRepo.last == nil || consentRepo.last.Claims != "id_token:email userinfo:name" {
		t.Fatalf("persisted consent claims = %+v, want the two emittable tokens (unknown never consented)", consentRepo.last)
	}
	if len(codeRepo.byID) != 1 {
		t.Fatalf("one code row expected, got %d", len(codeRepo.byID))
	}
	for _, row := range codeRepo.byID {
		if !equalStrings(row.RequestedClaims.UserInfo, []string{"name"}) || !equalStrings(row.RequestedClaims.IDToken, []string{"email"}) {
			t.Errorf("code row requested claims = %+v, want userinfo [name] id_token [email]", row.RequestedClaims)
		}
	}
}

// A returning client asking for a claim the user never consented to is sent
// back to consent — coverage is scope AND claims.
func TestAuthorize_UnconsentedClaimRequiresConsentAgain(t *testing.T) {
	r, consentRepo, _ := newClaimsConsentEngine(t)
	// Stored consent covers the scope but no claims.
	consentRepo.last = &domain.OAuthConsent{UserID: authorizePrincipal().UserID, ClientID: "cli-1", Scope: "openid", GrantedAt: time.Now()}
	// Drive Authorize through the consent-submit path is not what we test;
	// use the AuthorizeService directly via a fresh engine mounting HandleAuthorize.
	client := &domain.Client{ClientID: "cli-1", RedirectURIs: []string{"https://app.example.com/cb"}, SkipConsent: false, Scope: "openid profile"}
	clients := &fakeAuthorizeClientLookup{client: client}
	codes := service.NewAuthorizationCodeService(nil, newAuthCodeRepoForHandlers(), service.AuthorizationCodeServiceOptions{TTL: time.Hour})
	authzSvc := service.NewAuthorizeService(nil, clients, codes, service.AuthorizeServiceOptions{Issuer: "https://idp.test"}).
		WithConsentService(service.NewConsentService(nil, consentRepo))
	gin.SetMode(gin.ReleaseMode)
	eng := gin.New()
	eng.Use(func(c *gin.Context) { mw.SetPrincipal(c, authorizePrincipal()); c.Next() })
	RegisterAuthorizeRoutes(eng, AuthorizeHandlerDeps{AuthorizeService: authzSvc, Audit: &audit.Recorder{}})
	_ = r
	w := httptest.NewRecorder()
	eng.ServeHTTP(w, httptest.NewRequest(http.MethodGet, authorizeURL(map[string]string{
		"client_id": "cli-1", "redirect_uri": "https://app.example.com/cb", "scope": "openid",
		"code_challenge": "x", "code_challenge_method": "S256", "state": "abc",
		"claims": `{"userinfo":{"name":null}}`,
	}), nil))
	loc := w.Header().Get("Location")
	if w.Code != http.StatusFound || !strings.HasPrefix(loc, "/api/v1/oauth/consent?") {
		t.Fatalf("unconsented claim must route to consent: status=%d location=%q", w.Code, loc)
	}
	if !strings.Contains(loc, "claims=") {
		t.Errorf("the consent redirect must carry the claims parameter: %q", loc)
	}
	// Malformed claims → redirect-safe invalid_request.
	w = httptest.NewRecorder()
	eng.ServeHTTP(w, httptest.NewRequest(http.MethodGet, authorizeURL(map[string]string{
		"client_id": "cli-1", "redirect_uri": "https://app.example.com/cb", "scope": "openid",
		"code_challenge": "x", "code_challenge_method": "S256", "state": "abc",
		"claims": `[not-an-object`,
	}), nil))
	if w.Code != http.StatusFound || !strings.Contains(w.Header().Get("Location"), "error=invalid_request") {
		t.Errorf("malformed claims: status=%d location=%q, want 302 error=invalid_request", w.Code, w.Header().Get("Location"))
	}
}

// The exchange stamps the userinfo member on the access token and mints the
// id_token member into the id_token.
func TestToken_AuthorizationCodeGrant_HonorsRequestedClaims(t *testing.T) {
	r, codes, user, session := newAuthCodeEngine(t, true)
	verifier, challenge := authCodePKCEPair(t)
	created, err := codes.Create(context.Background(), service.CreateAuthorizationCodeInput{
		ClientID: "cli-1", UserID: session.UserID, SessionID: session.ID,
		RedirectURI: "https://app.example.com/cb", Scope: "openid", Nonce: "n",
		CodeChallenge: challenge, CodeChallengeMethod: "S256",
		RequestedClaims: domain.ClaimsRequest{UserInfo: []string{"name"}, IDToken: []string{"email"}},
	})
	if err != nil {
		t.Fatalf("create code: %v", err)
	}
	body := strings.NewReader("grant_type=authorization_code&code=" + created.Code +
		"&client_id=cli-1&client_secret=S&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb" +
		"&code_verifier=" + verifier)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/oauth/token", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %q", w.Code, w.Body.String())
	}
	var resp map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	parser := jwt.NewParser(jwt.WithValidMethods([]string{"EdDSA"}))
	at, _, _ := parser.ParseUnverified(resp["access_token"].(string), jwt.MapClaims{})
	uc, _ := at.Claims.(jwt.MapClaims)["userinfo_claims"].([]any)
	if len(uc) != 1 || uc[0] != "name" {
		t.Errorf("access token userinfo_claims = %v, want [name]", uc)
	}
	idt, _, _ := parser.ParseUnverified(resp["id_token"].(string), jwt.MapClaims{})
	idc := idt.Claims.(jwt.MapClaims)
	if idc["email"] != user.Email {
		t.Errorf("id_token email = %v, want the requested id_token claim %q", idc["email"], user.Email)
	}
	if v, present := idc["name"]; present {
		t.Errorf("id_token name = %v, want absent (requested for userinfo, not the id_token)", v)
	}
}

// userinfo releases a consented claim carried by the token, without the scope.
func TestUserinfo_ReleasesConsentedRequestedClaim(t *testing.T) {
	uid := uuid.New()
	serve := func(t *testing.T, userinfoClaims []string) map[string]any {
		t.Helper()
		v := &userinfoFakeVerifier{claims: &service.IntrospectionClaims{
			Sub: uid.String(), UserID: uid, Email: "user@example.com", Scope: "openid", UserInfoClaims: userinfoClaims,
		}}
		gin.SetMode(gin.ReleaseMode)
		r := gin.New()
		RegisterUserinfoRoutes(r, UserinfoHandlerDeps{
			IntrospectionService: service.NewIntrospectionService(nil, v, nil),
			UserLookup:           &fakeUserinfoUserLookup{user: &domain.User{ID: uid, Name: userinfoStrPtr("Alice Example"), EmailVerified: true}},
		})
		req := httptest.NewRequest(http.MethodGet, "/api/v1/oidc/userinfo", nil)
		req.Header.Set("Authorization", "Bearer ANY")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, body=%q", w.Code, w.Body.String())
		}
		var body map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &body)
		return body
	}
	body := serve(t, []string{"name"})
	if body["name"] != "Alice Example" {
		t.Errorf("name = %v, want released via the consented claim (no profile scope)", body["name"])
	}
	if v, present := body["email"]; present {
		t.Errorf("email = %v, want absent (neither scope nor claim)", v)
	}
	body = serve(t, []string{"email_verified"})
	if body["email"] != "user@example.com" || body["email_verified"] != true {
		t.Errorf("email group = %v/%v, want released via the consented claim", body["email"], body["email_verified"])
	}
	body = serve(t, nil)
	for _, k := range []string{"name", "email", "email_verified"} {
		if v, present := body[k]; present {
			t.Errorf("%s = %v, want absent without scope or claim", k, v)
		}
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
