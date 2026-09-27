//go:build integration

// Package e2e — OSS-CLIENTS: a deleted OAuth client's tokens stop working at
// once, and DELETE /api/v1/clients/:id tells the truth.
//
// Measured on 611ba18: userinfo and introspection judge a token by its
// signature, subject and jti revocation (IntrospectionService
// IntrospectActiveClaimsVerdict / IntrospectVerdict) and never look at the
// client; HandleDeleteClient deletes without revoking anything, answers 200
// {"deleted": id} and records "client.deleted" (outcome success) even when no
// row matched — another organization's client or an unknown id.
//
// The whole OSS engine runs (runtime.New + Start on the test database); only
// the authorization code is minted by the real AuthorizationCodeService on a
// real session, as the token handler tests do, instead of driving the browser
// login and consent pages. Tokens and secrets are never printed.
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

const clientDeleteIssuer = "http://127.0.0.1:7113"

type ossClient struct {
	ID       string `json:"id"`
	ClientID string `json:"client_id"`
	secret   string
}

func TestE2E_OSS_ADeletedClientsTokensStopAtOnce(t *testing.T) {
	dbURL := testDBURL(t)
	applyMigrations(t, dbURL)
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()
	pool, err := postgres.NewPool(ctx, dbURL, nil)
	if err != nil {
		t.Fatalf("open pool: error returned (URL redacted): %s", classifyOpenError(err))
	}
	defer pool.Close()
	repos := postgres.NewPgxRepositories(pool, e2eSigningKeyCipher())
	orgA := seedTestOrganization(t, ctx, repos)
	orgB := seedTestOrganization(t, ctx, repos)
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
	rt, err := runtime.New(runtime.Config{Addr: "127.0.0.1:0", Issuer: clientDeleteIssuer, JWKSDBURL: dbURL, DataDir: t.TempDir(), Stdout: io.Discard, Stderr: io.Discard})
	if err != nil {
		t.Fatalf("runtime.New: %v", err)
	}
	if err := rt.Start(ctx); err != nil {
		t.Fatalf("runtime.Start: %v", err)
	}
	defer func() {
		sctx, scancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer scancel()
		_ = rt.Shutdown(sctx)
	}()
	base := "http://" + rt.Addr()

	sessions := service.NewUserSessionService(nil, repos.Session, service.UserSessionServiceOptions{})
	tokens := service.NewUserTokenService(nil, keySvc, service.UserTokenServiceOptions{Issuer: clientDeleteIssuer})
	user := func(org uuid.UUID, role domain.UserRole) *domain.User {
		u, err := repos.User.Create(ctx, &domain.User{ID: uuid.New(), OrganizationID: org, Email: "e2e-clients-" + uuid.NewString() + "@example.invalid",
			PasswordHash: "dm-" + uuid.NewString(), Role: role, AuthSource: domain.AuthSourceLocal, EmailVerified: true})
		if err != nil {
			t.Fatalf("seed user: %v", err)
		}
		return u
	}
	bearerOf := func(u *domain.User) (string, uuid.UUID) {
		issued, err := sessions.CreateUserSession(ctx, service.CreateUserSessionInput{UserID: u.ID})
		if err != nil {
			t.Fatalf("session: %v", err)
		}
		tok, err := tokens.IssueForSession(ctx, u, issued.Session)
		if err != nil {
			t.Fatalf("token: %v", err)
		}
		return tok.AccessToken, issued.Session.ID
	}
	adminA, _ := bearerOf(user(orgA.ID, domain.RoleOrgAdmin))
	adminB, _ := bearerOf(user(orgB.ID, domain.RoleOrgAdmin))
	member := user(orgA.ID, domain.RoleOrgUser)
	_, memberSession := bearerOf(member)

	do := func(req *http.Request) (int, string) {
		t.Helper()
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", req.Method, req.URL.Path, err)
		}
		defer res.Body.Close()
		b, _ := io.ReadAll(res.Body)
		return res.StatusCode, string(b)
	}
	api := func(bearer, method, path, body string) (int, string) {
		req, _ := http.NewRequest(method, base+path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+bearer)
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		return do(req)
	}
	form := func(path string, c ossClient, v url.Values, bearer string) (int, string) {
		req, _ := http.NewRequest(http.MethodPost, base+path, strings.NewReader(v.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		} else {
			req.SetBasicAuth(url.QueryEscape(c.ClientID), url.QueryEscape(c.secret))
		}
		return do(req)
	}
	create := func(name string) ossClient {
		st, body := api(adminA, http.MethodPost, "/api/v1/clients", `{"name":"`+name+`","redirect_uris":["https://rp.example.test/cb"],"scope":"openid offline_access"}`)
		var out struct {
			Client       ossClient `json:"client"`
			ClientSecret string    `json:"client_secret"`
		}
		_ = json.Unmarshal([]byte(body), &out)
		if st != http.StatusCreated || out.Client.ClientID == "" || out.ClientSecret == "" {
			t.Fatalf("create client %s = %d; want 201 with a secret", name, st)
		}
		out.Client.secret = out.ClientSecret
		return out.Client
	}
	rp := create("e2e-rp")
	inspector := create("e2e-inspector")

	// A real code, exchanged at the real token endpoint for an access and a
	// refresh token.
	const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	codes := service.NewAuthorizationCodeService(nil, repos.OAuthAuthorizationCode, service.AuthorizationCodeServiceOptions{})
	mint := func(scope string) string {
		code, err := codes.Create(ctx, service.CreateAuthorizationCodeInput{ClientID: rp.ClientID, UserID: member.ID, OrganizationID: &orgA.ID, SessionID: memberSession,
			RedirectURI: "https://rp.example.test/cb", Scope: scope, CodeChallenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", CodeChallengeMethod: "S256"})
		if err != nil {
			t.Fatalf("mint code: %v", err)
		}
		return code.Code
	}
	exchange := func(code string) (int, string) {
		return form("/api/v1/oauth/token", rp, url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {"https://rp.example.test/cb"}, "code_verifier": {verifier}}, "")
	}
	type tokenPair struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	st, body := exchange(mint("openid offline_access"))
	var tok tokenPair
	_ = json.Unmarshal([]byte(body), &tok)
	if st != http.StatusOK || tok.AccessToken == "" || tok.RefreshToken == "" {
		t.Fatalf("code exchange = %d; want 200 with an access and a refresh token", st)
	}
	// An access token with no refresh token: nothing links it to a revocable
	// row, so only the client-liveness check can stop it.
	st, body = exchange(mint("openid"))
	var bare tokenPair
	_ = json.Unmarshal([]byte(body), &bare)
	if st != http.StatusOK || bare.AccessToken == "" || bare.RefreshToken != "" {
		t.Fatalf("openid-only exchange = %d; want 200 with an access token and no refresh token", st)
	}
	// A code minted before the delete and never exchanged.
	unused := mint("openid")
	userinfoOf := func(at string) int { st, _ := api(at, http.MethodGet, "/api/v1/oidc/userinfo", ""); return st }
	activeOf := func(at string) bool {
		_, body := form("/api/v1/oauth/introspection", inspector, url.Values{"token": {at}}, "")
		var v struct {
			Active bool `json:"active"`
		}
		_ = json.Unmarshal([]byte(body), &v)
		return v.Active
	}
	userinfo := func() int { return userinfoOf(tok.AccessToken) }
	active := func() bool { return activeOf(tok.AccessToken) }
	if st := userinfo(); st != http.StatusOK || !active() {
		t.Fatalf("before the delete: userinfo %d, introspection active %v; want 200 and true", st, active())
	}
	if st := userinfoOf(bare.AccessToken); st != http.StatusOK || !activeOf(bare.AccessToken) {
		t.Fatalf("before the delete, the openid-only token: userinfo %d; want 200 and active", st)
	}

	deleted := func(id string) int {
		var n int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE event_type = 'client.deleted' AND subject_id = $1`, id).Scan(&n); err != nil {
			t.Fatalf("audit count: %v", err)
		}
		return n
	}
	// Another organization's client and an unknown id: 404, nothing written.
	if st, body := api(adminB, http.MethodDelete, "/api/v1/clients/"+rp.ID, ""); st != http.StatusNotFound {
		t.Errorf("org B's admin deleting org A's client = %d %s; want 404", st, body)
	}
	ghost := uuid.NewString()
	if st, body := api(adminA, http.MethodDelete, "/api/v1/clients/"+ghost, ""); st != http.StatusNotFound {
		t.Errorf("deleting an unknown client = %d %s; want 404", st, body)
	}
	if n := deleted(rp.ID) + deleted(ghost); n != 0 {
		t.Errorf("%d client.deleted audit row(s) for deletes that deleted nothing; want 0", n)
	}
	if st := userinfo(); st != http.StatusOK {
		t.Fatalf("org A's client after the refused deletes: userinfo %d; want 200 (untouched)", st)
	}

	// The owner deletes it: 200, and the client's tokens stop at once.
	if st, body := api(adminA, http.MethodDelete, "/api/v1/clients/"+rp.ID, ""); st != http.StatusOK {
		t.Fatalf("own-org DELETE = %d %s; want 200", st, body)
	}
	if n := deleted(rp.ID); n != 1 {
		t.Errorf("client.deleted audit rows after the delete = %d; want 1", n)
	}
	if st := userinfo(); st != http.StatusUnauthorized {
		t.Errorf("userinfo with the deleted client's access token = %d; want 401", st)
	}
	if active() {
		t.Errorf("introspection of the deleted client's access token = active; want active:false")
	}
	if st := userinfoOf(bare.AccessToken); st != http.StatusUnauthorized {
		t.Errorf("userinfo with the deleted client's openid-only access token = %d; want 401", st)
	}
	if activeOf(bare.AccessToken) {
		t.Errorf("introspection of the deleted client's openid-only access token = active; want active:false")
	}
	if st, _ := exchange(unused); st == http.StatusOK {
		t.Errorf("exchanging a code minted before the delete = 200; want refused")
	}
	var live int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM oauth_refresh_tokens WHERE client_id = $1 AND revoked_at IS NULL`, rp.ClientID).Scan(&live); err != nil {
		t.Fatalf("refresh count: %v", err)
	}
	if live != 0 {
		t.Errorf("%d live refresh token(s) of the deleted client; want 0 (revoked before the delete)", live)
	}
	if st, _ := form("/api/v1/oauth/token", rp, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tok.RefreshToken}}, ""); st == http.StatusOK {
		t.Errorf("refresh with the deleted client's refresh token = 200; want refused")
	}
}
