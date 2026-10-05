//go:build integration

// Package e2e — OSS-V0.9.6 guards, through the whole OSS engine (runtime.New +
// Start on the test database), with the authorization code minted by the real
// AuthorizationCodeService on a real session as oauth_client_delete_http_test
// does:
//
//   - The H1 guard. The 2026-10-05 functionality audit reported that an access
//     token minted by the refresh grant was refused by userinfo and read
//     inactive at introspection (FUNC-H1); the cause was the audit's own
//     relying party, which replayed the old refresh token and so revoked the
//     family (the reuse rule). The finding is withdrawn; these assertions keep
//     both halves true: a refreshed access token works wherever the first one
//     does, and a replay of the old refresh token kills it.
//   - FUNC-H2 on the real engine: a public client (token_endpoint_auth_method
//     none) redeems its code with PKCE and no secret, and discovery says so.
//
// Tokens, codes and secrets are never printed.
package e2e

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/postgres"
	"github.com/identuum/identuum-idp-oss/internal/runtime"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

const refreshGuardIssuer = "http://127.0.0.1:7113"

// The PKCE pair RFC 7636 appendix B uses.
const (
	refreshGuardVerifier  = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	refreshGuardChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	refreshGuardCallback  = "https://rp.example.test/cb"
)

type refreshGuardWorld struct {
	t       *testing.T
	ctx     context.Context
	base    string
	adminA  string
	member  *domain.User
	session uuid.UUID
	orgA    uuid.UUID
	codes   *service.AuthorizationCodeService
}

func startRefreshGuardEngine(t *testing.T) *refreshGuardWorld {
	t.Helper()
	dbURL := testDBURL(t)
	applyMigrations(t, dbURL)
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	t.Cleanup(cancel)
	pool, err := postgres.NewPool(ctx, dbURL, nil)
	if err != nil {
		t.Fatalf("open pool: error returned (URL redacted): %s", classifyOpenError(err))
	}
	t.Cleanup(pool.Close)
	repos := postgres.NewPgxRepositories(pool, e2eSigningKeyCipher())
	org := seedTestOrganization(t, ctx, repos)
	keySvc := service.NewKeyService(repos.Key)
	if active, err := keySvc.ListActive(ctx); err != nil {
		t.Fatalf("ListActive keys: %v", err)
	} else if len(active) == 0 {
		if _, err := keySvc.Generate(ctx, service.GenerateKeyOptions{Algorithm: string(domain.KeyAlgorithmEdDSA), State: domain.KeyStateActive}); err != nil {
			t.Fatalf("Generate signing key: %v", err)
		}
	}
	t.Setenv("IDENTUUM_IDP_ENCRYPTION_KEY", "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
	t.Setenv("IDENTUUM_IDP_ALLOW_MULTI_REPLICA", "true")
	rt, err := runtime.New(runtime.Config{Addr: "127.0.0.1:0", Issuer: refreshGuardIssuer, JWKSDBURL: dbURL, DataDir: t.TempDir(), Stdout: io.Discard, Stderr: io.Discard})
	if err != nil {
		t.Fatalf("runtime.New: %v", err)
	}
	if err := rt.Start(ctx); err != nil {
		t.Fatalf("runtime.Start: %v", err)
	}
	t.Cleanup(func() {
		sctx, scancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer scancel()
		_ = rt.Shutdown(sctx)
	})
	sessions := service.NewUserSessionService(nil, repos.Session, service.UserSessionServiceOptions{})
	tokens := service.NewUserTokenService(nil, keySvc, service.UserTokenServiceOptions{Issuer: refreshGuardIssuer})
	user := func(role domain.UserRole) (*domain.User, string, uuid.UUID) {
		u, err := repos.User.Create(ctx, &domain.User{ID: uuid.New(), OrganizationID: org.ID, Email: "e2e-refresh-" + uuid.NewString() + "@example.invalid",
			PasswordHash: "dm-" + uuid.NewString(), Role: role, AuthSource: domain.AuthSourceLocal, EmailVerified: true})
		if err != nil {
			t.Fatalf("seed user: %v", err)
		}
		issued, err := sessions.CreateUserSession(ctx, service.CreateUserSessionInput{UserID: u.ID})
		if err != nil {
			t.Fatalf("session: %v", err)
		}
		tok, err := tokens.IssueForSession(ctx, u, issued.Session)
		if err != nil {
			t.Fatalf("token: %v", err)
		}
		return u, tok.AccessToken, issued.Session.ID
	}
	_, admin, _ := user(domain.RoleOrgAdmin)
	member, _, memberSession := user(domain.RoleOrgUser)
	return &refreshGuardWorld{t: t, ctx: ctx, base: "http://" + rt.Addr(), adminA: admin, member: member, session: memberSession, orgA: org.ID,
		codes: service.NewAuthorizationCodeService(nil, repos.OAuthAuthorizationCode, service.AuthorizationCodeServiceOptions{})}
}

func (w *refreshGuardWorld) do(req *http.Request) (int, string) {
	w.t.Helper()
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		w.t.Fatalf("%s %s: %v", req.Method, req.URL.Path, err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res.StatusCode, string(b)
}

func (w *refreshGuardWorld) api(bearer, method, path, body string) (int, string) {
	req, _ := http.NewRequest(method, w.base+path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+bearer)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	return w.do(req)
}

// form posts to a client-authenticated endpoint: HTTP Basic for a client with
// a secret, client_id in the body for a public one.
func (w *refreshGuardWorld) form(path string, c ossClient, v url.Values) (int, string) {
	if c.secret == "" {
		v.Set("client_id", c.ClientID)
	}
	req, _ := http.NewRequest(http.MethodPost, w.base+path, strings.NewReader(v.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if c.secret != "" {
		req.SetBasicAuth(url.QueryEscape(c.ClientID), url.QueryEscape(c.secret))
	}
	return w.do(req)
}

func (w *refreshGuardWorld) client(body string) ossClient {
	st, raw := w.api(w.adminA, http.MethodPost, "/api/v1/clients", body)
	var out struct {
		Client       ossClient `json:"client"`
		ClientSecret string    `json:"client_secret"`
	}
	_ = json.Unmarshal([]byte(raw), &out)
	if st != http.StatusCreated || out.Client.ClientID == "" {
		w.t.Fatalf("create client = %d; want 201", st)
	}
	out.Client.secret = out.ClientSecret
	return out.Client
}

func (w *refreshGuardWorld) code(c ossClient, scope string) string {
	code, err := w.codes.Create(w.ctx, service.CreateAuthorizationCodeInput{ClientID: c.ClientID, UserID: w.member.ID, OrganizationID: &w.orgA, SessionID: w.session,
		RedirectURI: refreshGuardCallback, Scope: scope, CodeChallenge: refreshGuardChallenge, CodeChallengeMethod: "S256"})
	if err != nil {
		w.t.Fatalf("mint code: %v", err)
	}
	return code.Code
}

type refreshGuardTokens struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
}

func TestE2E_OSS_ARefreshedAccessTokenWorksUntilTheOldRefreshTokenIsReplayed(t *testing.T) {
	w := startRefreshGuardEngine(t)
	rp := w.client(`{"name":"e2e-refresh-rp","redirect_uris":["` + refreshGuardCallback + `"],"scope":"openid offline_access"}`)

	st, body := w.form("/api/v1/oauth/token", rp, url.Values{"grant_type": {"authorization_code"}, "code": {w.code(rp, "openid offline_access")},
		"redirect_uri": {refreshGuardCallback}, "code_verifier": {refreshGuardVerifier}})
	var first refreshGuardTokens
	_ = json.Unmarshal([]byte(body), &first)
	if st != http.StatusOK || first.AccessToken == "" || first.RefreshToken == "" {
		t.Fatalf("code exchange = %d; want 200 with an access and a refresh token", st)
	}
	st, body = w.form("/api/v1/oauth/token", rp, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {first.RefreshToken}})
	var second refreshGuardTokens
	_ = json.Unmarshal([]byte(body), &second)
	if st != http.StatusOK || second.AccessToken == "" || second.RefreshToken == "" || second.RefreshToken == first.RefreshToken {
		t.Fatalf("refresh grant = %d; want 200 with a new access token and a rotated refresh token", st)
	}
	userinfo := func(at string) int { st, _ := w.api(at, http.MethodGet, "/api/v1/oidc/userinfo", ""); return st }
	active := func(at string) bool {
		_, raw := w.form("/api/v1/oauth/introspection", rp, url.Values{"token": {at}})
		var v struct {
			Active bool `json:"active"`
		}
		_ = json.Unmarshal([]byte(raw), &v)
		return v.Active
	}
	if st := userinfo(second.AccessToken); st != http.StatusOK {
		t.Errorf("userinfo with the refreshed access token = %d; want 200, as for the first", st)
	}
	if !active(second.AccessToken) {
		t.Error("the issuing client's introspection of the refreshed access token = inactive; want active")
	}

	// A replay of the rotated-out refresh token is reuse (RFC 9700 §4.14.2):
	// the whole family is revoked, the access token it last minted with it.
	if st, _ := w.form("/api/v1/oauth/token", rp, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {first.RefreshToken}}); st == http.StatusOK {
		t.Fatal("the rotated-out refresh token was accepted again")
	}
	if st := userinfo(second.AccessToken); st != http.StatusUnauthorized {
		t.Errorf("userinfo with the refreshed access token after the replay = %d; want 401", st)
	}
	if active(second.AccessToken) {
		t.Error("introspection of the refreshed access token after the replay = active; want inactive")
	}
	if st, _ := w.form("/api/v1/oauth/token", rp, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {second.RefreshToken}}); st == http.StatusOK {
		t.Error("the family's newest refresh token still works after the replay; want it revoked")
	}
}

func TestE2E_OSS_APublicClientRedeemsItsCodeWithPKCE(t *testing.T) {
	w := startRefreshGuardEngine(t)
	pub := w.client(`{"name":"e2e-spa","redirect_uris":["` + refreshGuardCallback + `"],"scope":"openid offline_access","is_public":true,"token_endpoint_auth_method":"none"}`)
	if pub.secret != "" {
		t.Fatal("a public client was given a secret")
	}
	st, body := w.form("/api/v1/oauth/token", pub, url.Values{"grant_type": {"authorization_code"}, "code": {w.code(pub, "openid offline_access")},
		"redirect_uri": {refreshGuardCallback}, "code_verifier": {refreshGuardVerifier}})
	var tok refreshGuardTokens
	_ = json.Unmarshal([]byte(body), &tok)
	if st != http.StatusOK || tok.AccessToken == "" || tok.IDToken == "" {
		t.Fatalf("public client code exchange = %d; want 200 with an access and an ID token", st)
	}
	if tok.RefreshToken != "" {
		t.Error("a public client received a refresh token it cannot redeem")
	}
	if st, _ := w.api(tok.AccessToken, http.MethodGet, "/api/v1/oidc/userinfo", ""); st != http.StatusOK {
		t.Errorf("userinfo with the public client's access token = %d; want 200", st)
	}
	// Without the verifier the same client is not admitted.
	if st, _ := w.form("/api/v1/oauth/token", pub, url.Values{"grant_type": {"authorization_code"}, "code": {w.code(pub, "openid")},
		"redirect_uri": {refreshGuardCallback}}); st != http.StatusUnauthorized {
		t.Errorf("public client exchange without code_verifier = %d; want 401", st)
	}
	st, body = w.api("", http.MethodGet, "/.well-known/openid-configuration", "")
	var disc struct {
		Methods []string `json:"token_endpoint_auth_methods_supported"`
	}
	_ = json.Unmarshal([]byte(body), &disc)
	if st != http.StatusOK || !strings.Contains(strings.Join(disc.Methods, " "), "none") {
		t.Errorf("discovery token_endpoint_auth_methods_supported = %v; want none listed", disc.Methods)
	}
}
