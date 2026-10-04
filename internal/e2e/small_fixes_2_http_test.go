//go:build integration

// Package e2e — SMALL-FIXES-2, through the whole OSS engine (runtime.New +
// Start on the test database):
//
//  1. A store error on a client read is not a verdict: GET, PUT,
//     regenerate and DELETE /api/v1/clients/:id answer 503 (AUTH-503's
//     temporarily_unavailable / auth_store_error body) while the store
//     errs, and 404 stays 404 for an unknown client. The store error is
//     produced by renaming a column the client read selects, in the
//     isolated test database, and restored before the test ends.
//  2. A revoked access token refused by the bearer middleware answers 401
//     with WWW-Authenticate: Bearer error="invalid_token" (RFC 6750 §3.1),
//     as userinfo's own refusals do.
//
// Tokens and secrets are never printed.
package e2e

import (
	"context"
	"encoding/base64"
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

const smallFixes2Issuer = "http://127.0.0.1:7114"

func TestE2E_OSS_SmallFixes2_ClientStoreErrorAndRevokedBearer(t *testing.T) {
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
	rt, err := runtime.New(runtime.Config{Addr: "127.0.0.1:0", Issuer: smallFixes2Issuer, JWKSDBURL: dbURL, DataDir: t.TempDir(), Stdout: io.Discard, Stderr: io.Discard})
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
	tokens := service.NewUserTokenService(nil, keySvc, service.UserTokenServiceOptions{Issuer: smallFixes2Issuer})
	user := func(role domain.UserRole) *domain.User {
		u, err := repos.User.Create(ctx, &domain.User{ID: uuid.New(), OrganizationID: orgA.ID, Email: "e2e-sf2-" + uuid.NewString() + "@example.invalid",
			PasswordHash: "dm-" + uuid.NewString(), Role: role, AuthSource: domain.AuthSourceLocal, EmailVerified: true})
		if err != nil {
			t.Fatalf("seed user: %v", err)
		}
		return u
	}
	admin := user(domain.RoleOrgAdmin)
	issued, err := sessions.CreateUserSession(ctx, service.CreateUserSessionInput{UserID: admin.ID})
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	tok, err := tokens.IssueForSession(ctx, admin, issued.Session)
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	bearer := tok.AccessToken

	do := func(req *http.Request) (int, http.Header, string) {
		t.Helper()
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", req.Method, req.URL.Path, err)
		}
		defer res.Body.Close()
		b, _ := io.ReadAll(res.Body)
		return res.StatusCode, res.Header, string(b)
	}
	api := func(bearer, method, path, body string) (int, http.Header, string) {
		req, _ := http.NewRequest(method, base+path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+bearer)
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		return do(req)
	}

	st, _, body := api(bearer, http.MethodPost, "/api/v1/clients", `{"name":"sf2-rp","redirect_uris":["https://rp.example.test/cb"],"scope":"openid offline_access"}`)
	var created struct {
		Client struct {
			ID       string `json:"id"`
			ClientID string `json:"client_id"`
		} `json:"client"`
		ClientSecret string `json:"client_secret"`
	}
	_ = json.Unmarshal([]byte(body), &created)
	if st != http.StatusCreated || created.Client.ID == "" || created.ClientSecret == "" {
		t.Fatalf("create client = %d; want 201 with a secret", st)
	}
	id := created.Client.ID

	// ── 1. A store error is 503, a miss is 404 ──────────────────────────────
	if st, _, _ := api(bearer, http.MethodGet, "/api/v1/clients/"+uuid.NewString(), ""); st != http.StatusNotFound {
		t.Errorf("GET an unknown client = %d; want 404", st)
	}
	if _, err := pool.Exec(ctx, `ALTER TABLE oauth_clients RENAME COLUMN jwks TO jwks_small_fixes_2`); err != nil {
		t.Fatalf("break the client read: %v", err)
	}
	restored := false
	restore := func() {
		if restored {
			return
		}
		restored = true
		if _, err := pool.Exec(context.Background(), `ALTER TABLE oauth_clients RENAME COLUMN jwks_small_fixes_2 TO jwks`); err != nil {
			t.Fatalf("restore the client read: %v", err)
		}
	}
	defer restore()
	for _, c := range []struct{ name, method, path, body string }{
		{"get", http.MethodGet, "/api/v1/clients/" + id, ""},
		{"update", http.MethodPut, "/api/v1/clients/" + id, `{"name":"sf2-rp-renamed"}`},
		{"regenerate", http.MethodPost, "/api/v1/clients/" + id + "/secret/regenerate", ""},
		{"delete", http.MethodDelete, "/api/v1/clients/" + id, ""},
	} {
		st, _, body := api(bearer, c.method, c.path, c.body)
		if st != http.StatusServiceUnavailable || !strings.Contains(body, `"reason":"auth_store_error"`) {
			t.Errorf("%s while the client store errs = %d %s; want 503 with reason auth_store_error", c.name, st, body)
		}
		if strings.Contains(body, "client_secret") {
			t.Errorf("%s while the client store errs: the body carries a secret field", c.name)
		}
	}
	restore()
	if st, _, _ := api(bearer, http.MethodGet, "/api/v1/clients/"+id, ""); st != http.StatusOK {
		t.Errorf("GET after the store recovers = %d; want 200", st)
	}
	if st, _, _ := api(bearer, http.MethodGet, "/api/v1/clients/"+uuid.NewString(), ""); st != http.StatusNotFound {
		t.Errorf("GET an unknown client after the store recovers = %d; want 404", st)
	}

	// ── 2. A revoked access token at the bearer middleware ──────────────────
	if st, _, _ := api(bearer, http.MethodGet, "/api/v1/oidc/userinfo", ""); st != http.StatusOK {
		t.Fatalf("userinfo before the revocation = %d; want 200", st)
	}
	// Revoke the token's jti the way the revocation endpoint records it. The
	// endpoint itself revokes only a client's OWN tokens, and this is a login
	// token that belongs to no client, so the unrelated client above cannot.
	payload, err := base64.RawURLEncoding.DecodeString(strings.Split(bearer, ".")[1])
	if err != nil {
		t.Fatalf("decode the token payload: %v", err)
	}
	var claims struct {
		Jti string `json:"jti"`
		Exp int64  `json:"exp"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil || claims.Jti == "" || claims.Exp == 0 {
		t.Fatalf("the token carries no jti or exp: %v", err)
	}
	if err := service.NewTokenRevocationService(nil, repos.TokenRevocation).RevokeJTI(ctx, claims.Jti, time.Unix(claims.Exp, 0), "e2e", nil); err != nil {
		t.Fatalf("revoke the jti: %v", err)
	}
	// And the endpoint leaves a token that is not the caller's alone.
	rev, _ := http.NewRequest(http.MethodPost, base+"/api/v1/oauth/revoke", strings.NewReader(url.Values{"token": {bearer}, "token_type_hint": {"access_token"}}.Encode()))
	rev.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rev.SetBasicAuth(url.QueryEscape(created.Client.ClientID), url.QueryEscape(created.ClientSecret))
	if st, _, _ := do(rev); st != http.StatusOK {
		t.Fatalf("revoke = %d; want 200", st)
	}
	for _, path := range []string{"/api/v1/oidc/userinfo", "/api/v1/clients/" + id} {
		st, hdr, body := api(bearer, http.MethodGet, path, "")
		if st != http.StatusUnauthorized || !strings.Contains(body, `"reason":"token_revoked"`) {
			t.Errorf("GET %s with the revoked token = %d %s; want 401 token_revoked", path, st, body)
		}
		if got := hdr.Get("WWW-Authenticate"); !strings.HasPrefix(got, "Bearer ") || !strings.Contains(got, `error="invalid_token"`) {
			t.Errorf("GET %s with the revoked token: WWW-Authenticate = %q; want Bearer error=\"invalid_token\"", path, got)
		}
	}
	// A malformed token is the same RFC 6750 class.
	st, hdr, body := api("not-a-jwt", http.MethodGet, "/api/v1/clients/"+id, "")
	if st != http.StatusUnauthorized || !strings.Contains(body, `"reason":"token_invalid"`) || !strings.Contains(hdr.Get("WWW-Authenticate"), `error="invalid_token"`) {
		t.Errorf("a malformed token = %d %s, WWW-Authenticate %q; want 401 token_invalid with error=\"invalid_token\"", st, body, hdr.Get("WWW-Authenticate"))
	}
}
