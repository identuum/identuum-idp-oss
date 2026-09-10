//go:build integration

// THE-OSS-HALF-OF-THE-RULING (2026-09-10). POST /api/v1/me/mfa/
// recovery-codes/regenerate took the session as its only proof and
// handed back a fresh list of recovery codes, while the disable beside
// it accepts a recovery code as a valid proof. A stolen session could
// therefore regenerate, take a valid proof from the response, and disarm
// the second factor with no factor, no password and no rate limit in the
// way. Owner ruling (b), the same as identuum-idp-ce's: A TOTP CODE ONLY
// — a recovery code must not buy more recovery codes.
//
// Pinned end-to-end against live compose Postgres on 127.0.0.1:5513: an
// enrolled org_user (MFA optional in its organization, so the disable is
// not policy-blocked) drives the self-service routes through the router
// with the principal the bearer middleware would set — installed through
// mw.InjectPrincipalForTest, the exported seam the handler tests use.
// The refusal is the route family's existing `invalid_code` 401 and is
// cause-neutral — absent, empty, wrong and a valid RECOVERY code all read
// the same — and a refused recovery code is NOT burned, so it still
// disarms through the disable (the route the ruling leaves open to a
// user without the authenticator).
//
// Test discipline mirrors the other e2e tests: randomized email, the
// TOTP secret is the RFC 6238 test vector, no secret or code is ever
// echoed, the user row is deleted on cleanup.
package e2e

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/crypto"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/handlers"
	"github.com/identuum/identuum-idp-oss/internal/mw"
	"github.com/identuum/identuum-idp-oss/internal/postgres"
	"github.com/identuum/identuum-idp-oss/internal/repository"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// regenerateE2EFixture is one enrolled org_user with the router, the
// repositories and the plaintext recovery codes the row was seeded with.
type regenerateE2EFixture struct {
	router *gin.Engine
	repos  *postgres.Repositories
	ctx    context.Context
	user   *domain.User
	secret string
	codes  []string
}

func newRegenerateE2EFixture(t *testing.T) *regenerateE2EFixture {
	t.Helper()
	dbURL := testDBURL(t)
	applyMigrations(t, dbURL)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)

	pool, err := postgres.NewPool(ctx, dbURL, nil)
	if err != nil {
		t.Fatalf("open pool: error returned (URL redacted): %s", classifyOpenError(err))
	}
	t.Cleanup(pool.Close)

	repos := postgres.NewPgxRepositories(pool, e2eSigningKeyCipher())
	if repos == nil || repos.User == nil || repos.MFAPendingLoginSession == nil {
		t.Fatal("repository factory returned nil required repo")
	}

	org := seedTestOrganization(t, ctx, repos) // MFAPolicy optional
	email := strings.ToLower("e2e-mfa-regen-" + uuid.NewString() + "@example.invalid")
	// The RFC 6238 test-vector secret (the same one the service unit
	// tests use); stored unchanged under the identity cipher below.
	secret := "JBSWY3DPEHPK3PXP"
	codes := []string{
		"e2e-rec-" + uuid.NewString()[:8],
		"e2e-rec-" + uuid.NewString()[:8],
		"e2e-rec-" + uuid.NewString()[:8],
	}
	hashed := make([]string, 0, len(codes))
	for _, c := range codes {
		hashed = append(hashed, crypto.HashSecret(c))
	}
	seededID, err := uuid.NewRandom()
	if err != nil {
		t.Fatalf("seed uuid: %v", err)
	}
	created, err := repos.User.Create(ctx, &domain.User{
		ID:             seededID,
		OrganizationID: org.ID,
		Email:          email,
		PasswordHash:   "not-a-password-hash-marker",
		Role:           domain.RoleOrgUser,
		AuthSource:     domain.AuthSourceLocal,
		EmailVerified:  true,
	})
	if err != nil {
		t.Fatalf("seed Create: %v", err)
	}
	t.Cleanup(func() {
		_ = repos.User.Delete(context.Background(), created.ID, created.OrganizationID)
	})
	// The enrolment, written the way the service writes it (Create does
	// not persist the recovery-code column).
	enabled := true
	seed := secret
	if _, err := repos.User.Update(ctx, created.ID, created.OrganizationID, repository.UpdateUserOptions{
		MFAEnabled:       &enabled,
		MFASecret:        &seed,
		MFARecoveryCodes: hashed,
	}); err != nil {
		t.Fatalf("seed enrolment Update: %v", err)
	}

	enrollment := service.NewMFAEnrollmentService(nil, service.MFAEnrollmentRepoOptions{
		Pending: repos.MFAPendingLoginSession,
		Users:   repos.User,
		Issuer:  "Identuum",
		Cipher:  e2eMFAIdentityCipher{},
	}, service.MFAEnrollmentServiceOptions{})

	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(mw.InjectPrincipalForTest(&domain.Principal{
		UserID:         created.ID,
		OrganizationID: created.OrganizationID,
		Email:          email,
		Role:           domain.RoleOrgUser,
	}))
	handlers.RegisterAuthSessionRoutes(r, handlers.AuthSessionsHandlerDeps{
		UserLookup:          repos.User,
		MFAEnrollment:       enrollment,
		SessionRevoker:      service.NoopSessionRevoker{},
		RefreshTokenRevoker: service.NoopRefreshTokenRevoker{},
		Audit:               &audit.NoopService{},
	})
	return &regenerateE2EFixture{router: r, repos: repos, ctx: ctx, user: created, secret: secret, codes: codes}
}

// post sends a JSON body (nil = no body at all) to a self-service route
// and returns the status and the trimmed body.
func (f *regenerateE2EFixture) post(t *testing.T, path string, body map[string]string) (int, string) {
	t.Helper()
	var req *http.Request
	if body == nil {
		req = httptest.NewRequest(http.MethodPost, path, nil)
	} else {
		raw, _ := json.Marshal(body)
		req = httptest.NewRequest(http.MethodPost, path, strings.NewReader(string(raw)))
		req.Header.Set("Content-Type", "application/json")
	}
	req.Host = "localhost:7113"
	w := httptest.NewRecorder()
	f.router.ServeHTTP(w, req)
	return w.Code, strings.TrimSpace(w.Body.String())
}

// storedCodes reads the user row's persisted (hashed) recovery codes.
func (f *regenerateE2EFixture) storedCodes(t *testing.T) []string {
	t.Helper()
	u, err := f.repos.User.GetByID(f.ctx, f.user.ID)
	if err != nil || u == nil {
		t.Fatalf("read user row: %v", err)
	}
	return u.MFARecoveryCodes
}

func (f *regenerateE2EFixture) currentTOTP(t *testing.T) string {
	t.Helper()
	return computeTOTPCodeForTest(t, f.secret, uint64(time.Now().Unix())/uint64(service.TOTPPeriodSeconds))
}

// TestE2E_OSS_MFARecoveryRegenerate_RecoveryCodeIsRefused is the ruling
// itself: a VALID recovery code does not regenerate — 401 invalid_code —
// it is not burned, absent / empty / wrong proofs read byte-identically,
// and the same recovery code still disarms through the disable.
func TestE2E_OSS_MFARecoveryRegenerate_RecoveryCodeIsRefused(t *testing.T) {
	f := newRegenerateE2EFixture(t)
	before := f.storedCodes(t)
	if len(before) != len(f.codes) {
		t.Fatalf("seeded recovery codes = %d, want %d", len(before), len(f.codes))
	}

	status, body := f.post(t, "/api/v1/me/mfa/recovery-codes/regenerate", map[string]string{"code": f.codes[1]})
	if status != http.StatusUnauthorized || !strings.Contains(body, `"invalid_code"`) {
		t.Fatalf("regenerate with a VALID recovery code = %d %s, want 401 invalid_code — a recovery code must not buy recovery codes", status, redactCodes(body))
	}
	want := body
	cases := []struct {
		label string
		body  map[string]string
	}{
		{"absent body", nil},
		{"empty code", map[string]string{"code": ""}},
		{"wrong six-character code", map[string]string{"code": "abcdef"}},
		{"wrong-length code", map[string]string{"code": "12345"}},
	}
	for _, c := range cases {
		status, body := f.post(t, "/api/v1/me/mfa/recovery-codes/regenerate", c.body)
		if status != http.StatusUnauthorized || body != want {
			t.Errorf("%s: regenerate = %d %q, want 401 %q (one cause-neutral refusal)", c.label, status, redactCodes(body), want)
		}
	}
	// Not burned, not replaced.
	after := f.storedCodes(t)
	if len(after) != len(before) {
		t.Fatalf("stored recovery codes after refusals = %d, want %d (a refused recovery code must not be burned)", len(after), len(before))
	}
	for i := range before {
		if after[i] != before[i] {
			t.Fatalf("stored recovery code %d changed under a refused regenerate", i)
		}
	}
	// The chain the ruling leaves open: the same recovery code disarms
	// through the disable.
	status, body = f.post(t, "/api/v1/me/mfa/disable", map[string]string{"code": f.codes[1]})
	if status != http.StatusNoContent {
		t.Fatalf("disable with the same (unburned) recovery code = %d %s, want 204", status, redactCodes(body))
	}
	u, err := f.repos.User.GetByID(f.ctx, f.user.ID)
	if err != nil || u == nil || u.MFAEnabled {
		t.Fatalf("after the disable MFAEnabled = %v (err %v), want false", u != nil && u.MFAEnabled, err)
	}
}

// TestE2E_OSS_MFARecoveryRegenerate_TOTPCodeAccepted: a current TOTP
// code regenerates — the enrolment's count of fresh codes, none of the
// seeded ones, the row replaced, MFA still enabled with the same secret.
func TestE2E_OSS_MFARecoveryRegenerate_TOTPCodeAccepted(t *testing.T) {
	f := newRegenerateE2EFixture(t)
	status, body := f.post(t, "/api/v1/me/mfa/recovery-codes/regenerate", map[string]string{"code": f.currentTOTP(t)})
	if status != http.StatusOK {
		t.Fatalf("regenerate with a current TOTP code = %d %s, want 200", status, redactCodes(body))
	}
	var resp struct {
		RecoveryCodes []string `json:"recovery_codes"`
		Count         int      `json:"count"`
	}
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		t.Fatalf("decode regenerate response: %v", err)
	}
	if resp.Count != len(resp.RecoveryCodes) || len(resp.RecoveryCodes) == 0 {
		t.Fatalf("regenerate returned count=%d over %d codes, want a non-empty consistent list", resp.Count, len(resp.RecoveryCodes))
	}
	for _, c := range resp.RecoveryCodes {
		for _, old := range f.codes {
			if c == old {
				t.Errorf("a regenerated code equals one of the seeded codes")
			}
		}
	}
	stored := f.storedCodes(t)
	if len(stored) != len(resp.RecoveryCodes) {
		t.Fatalf("stored recovery codes = %d, want %d (the returned list)", len(stored), len(resp.RecoveryCodes))
	}
	for i, c := range resp.RecoveryCodes {
		if stored[i] != crypto.HashSecret(c) {
			t.Errorf("stored code %d is not the hash of the returned code", i)
		}
	}
	u, err := f.repos.User.GetByID(f.ctx, f.user.ID)
	if err != nil || u == nil || !u.MFAEnabled || u.MFASecret == nil || *u.MFASecret != f.secret {
		t.Fatalf("after the regenerate the enrolment moved (err %v)", err)
	}
	// The seeded codes are gone for the disable too.
	if status, _ := f.post(t, "/api/v1/me/mfa/disable", map[string]string{"code": f.codes[0]}); status != http.StatusUnauthorized {
		t.Fatalf("disable with a REPLACED recovery code = %d, want 401", status)
	}
}

// redactCodes keeps a failure message honest without echoing recovery
// codes: a body carrying a recovery_codes list is reduced to its shape.
func redactCodes(body string) string {
	if strings.Contains(body, `"recovery_codes"`) {
		return `{"recovery_codes":[…redacted…]}`
	}
	return body
}
