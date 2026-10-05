//go:build integration

// Package e2e — FUNC-M15 (audits/oss-functionality-2026-10-05.md): a
// completed sign-in records users.last_login_at. It was NULL for every user
// after console, JSON, passkey and OIDC sign-ins, because UpdateLastLogin had
// no production caller, so the console's "Last login" column was always "—".
// Through the whole OSS engine (runtime.New + Start on the test database).
// No password, token or session id is printed.
package e2e

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/crypto"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/postgres"
	"github.com/identuum/identuum-idp-oss/internal/runtime"
)

func TestE2E_OSS_ASignInRecordsLastLogin(t *testing.T) {
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

	const password = "Last-Login-Pass-1!"
	hash, err := crypto.GenerateHash([]byte(password))
	if err != nil {
		t.Fatal(err)
	}
	email := "e2e-lastlogin-" + uuid.NewString() + "@example.invalid"
	u, err := repos.User.Create(ctx, &domain.User{ID: uuid.New(), OrganizationID: org.ID, Email: email,
		PasswordHash: hash, Role: domain.RoleOrgUser, AuthSource: domain.AuthSourceLocal, EmailVerified: true})
	if err != nil {
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

	lastLogin := func() *time.Time {
		var at *time.Time
		if err := pool.QueryRow(ctx, `SELECT last_login_at FROM users WHERE id = $1`, u.ID).Scan(&at); err != nil {
			t.Fatalf("read last_login_at: %v", err)
		}
		return at
	}
	if at := lastLogin(); at != nil {
		t.Fatalf("a user who never signed in has last_login_at set")
	}
	before := time.Now().Add(-time.Minute)
	res, err := http.Post("http://"+rt.Addr()+"/api/v1/auth/login", "application/json",
		strings.NewReader(`{"email":"`+email+`","password":"`+password+`"}`))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	_ = res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("login = %d; want 200", res.StatusCode)
	}
	if at := lastLogin(); at == nil || at.Before(before) {
		t.Errorf("after a sign-in last_login_at = %v; want the time of the sign-in", at)
	}
	// A failed sign-in is not a login.
	var first time.Time
	if at := lastLogin(); at != nil {
		first = *at
	}
	res, err = http.Post("http://"+rt.Addr()+"/api/v1/auth/login", "application/json",
		strings.NewReader(`{"email":"`+email+`","password":"wrong-password"}`))
	if err == nil {
		_ = res.Body.Close()
	}
	if at := lastLogin(); at == nil || !at.Equal(first) {
		t.Errorf("a failed sign-in moved last_login_at")
	}
}
