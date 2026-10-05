//go:build integration

// Package e2e — FUNC-M1 (audits/oss-functionality-2026-10-05.md): a signed-in
// user adds an authenticator from account settings. The console posts to
// /api/v1/mfa/setup/initiate and /complete; OSS mounted neither, so the
// button answered 404 and no user could enrol outside a sign-in that forced
// it. Through the whole OSS engine (runtime.New + Start on the test
// database). No password, secret, code or cookie value is printed.
package e2e

import (
	"context"
	"encoding/base32"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/crypto"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/postgres"
	"github.com/identuum/identuum-idp-oss/internal/runtime"
	"github.com/identuum/identuum-idp-oss/pkg/totp"
	"github.com/identuum/identuum-idp-oss/pkg/uiserve"
)

func TestE2E_OSS_AccountSettingsEnrolsAnAuthenticator(t *testing.T) {
	dbURL := testDBURL(t)
	applyMigrations(t, dbURL)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	pool, err := postgres.NewPool(ctx, dbURL, nil)
	if err != nil {
		t.Fatalf("open pool: error returned (URL redacted): %s", classifyOpenError(err))
	}
	defer pool.Close()
	repos := postgres.NewPgxRepositories(pool, e2eSigningKeyCipher())
	org := seedTestOrganization(t, ctx, repos)

	const password = "Self-Enrol-Pass-1!"
	hash, err := crypto.GenerateHash([]byte(password))
	if err != nil {
		t.Fatal(err)
	}
	email := "e2e-selfenrol-" + uuid.NewString() + "@example.invalid"
	if _, err := repos.User.Create(ctx, &domain.User{ID: uuid.New(), OrganizationID: org.ID, Email: email,
		PasswordHash: hash, Role: domain.RoleOrgUser, AuthSource: domain.AuthSourceLocal, EmailVerified: true}); err != nil {
		t.Fatalf("seed user: %v", err)
	}

	t.Setenv("IDENTUUM_IDP_ENCRYPTION_KEY", "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
	t.Setenv("IDENTUUM_IDP_ALLOW_MULTI_REPLICA", "true")
	rt, err := runtime.New(runtime.Config{Addr: "127.0.0.1:0", Issuer: "http://127.0.0.1:7113", JWKSDBURL: dbURL, DataDir: t.TempDir(), Stdout: io.Discard, Stderr: io.Discard})
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

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}
	base := "http://" + rt.Addr()
	// Signed-in calls go through the browser boundary, as the console's do:
	// it lifts the access cookie into a bearer and forwards no cookie.
	post := func(path, body string) (int, map[string]any) {
		t.Helper()
		if !strings.HasPrefix(path, "/api/v1/auth/login") {
			path = uiserve.BFFPrefix + path
		}
		req, _ := http.NewRequest(http.MethodPost, base+path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", base)
		req.Header.Set(uiserve.RequestHeader, uiserve.RequestHeaderValue)
		res, err := client.Do(req)
		if err != nil {
			t.Fatalf("POST %s: %v", path, err)
		}
		defer res.Body.Close()
		out := map[string]any{}
		_ = json.NewDecoder(res.Body).Decode(&out)
		return res.StatusCode, out
	}

	if st, _ := post("/api/v1/auth/login", `{"email":"`+email+`","password":"`+password+`"}`); st != http.StatusOK {
		t.Fatalf("login = %d; want 200", st)
	}

	// A wrong password is no proof.
	if st, out := post("/api/v1/mfa/setup/initiate", `{"password":"not-the-password"}`); st != http.StatusUnauthorized || out["error"] != "invalid_proof" {
		t.Fatalf("initiate with a wrong password = %d %v; want 401 invalid_proof", st, out["error"])
	}
	st, out := post("/api/v1/mfa/setup/initiate", `{"password":"`+password+`"}`)
	if st != http.StatusOK {
		t.Fatalf("initiate = %d %v; want 200", st, out["error"])
	}
	secret, _ := out["secret"].(string)
	if secret == "" || !strings.HasPrefix(out["otpauth_url"].(string), "otpauth://totp/") {
		t.Fatalf("initiate answered no secret or no otpauth URL")
	}
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(strings.TrimRight(secret, "=")))
	if err != nil {
		t.Fatalf("the secret is not base32")
	}

	if st, _ := post("/api/v1/mfa/setup/complete", `{"code":"000000x"}`); st != http.StatusUnauthorized {
		t.Fatalf("complete with a wrong code = %d; want 401", st)
	}
	code := totp.Code(key, uint64(time.Now().Unix()/30), 6)
	st, out = post("/api/v1/mfa/setup/complete", `{"code":"`+code+`"}`)
	if st != http.StatusOK {
		t.Fatalf("complete = %d %v; want 200", st, out["error"])
	}
	if codes, _ := out["recovery_codes"].([]any); len(codes) != 10 {
		t.Fatalf("complete returned %d recovery codes; want 10", len(codes))
	}

	sreq, _ := http.NewRequest(http.MethodGet, base+uiserve.BFFPrefix+"/api/v1/me/mfa/status", nil)
	sreq.Header.Set(uiserve.RequestHeader, uiserve.RequestHeaderValue)
	res, err := client.Do(sreq)
	if err != nil {
		t.Fatal(err)
	}
	status := map[string]any{}
	_ = json.NewDecoder(res.Body).Decode(&status)
	_ = res.Body.Close()
	if status["mfa_enabled"] != true {
		t.Fatalf("after enrolment /me/mfa/status mfa_enabled = %v; want true", status["mfa_enabled"])
	}
	// An enrolled user is told so, not handed a second secret.
	if st, out := post("/api/v1/mfa/setup/initiate", `{"password":"`+password+`"}`); st != http.StatusConflict {
		t.Fatalf("a second initiate = %d %v; want 409", st, out["error"])
	}
}
