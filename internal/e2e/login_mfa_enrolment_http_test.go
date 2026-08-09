//go:build integration

// Package e2e — integration coverage for the OSS MFA enrolment +
// MFA verify HTTP flow added by slice
// agent-a-identuum-idp-oss-mfa-totp-enrolment-endpoints.
//
// Pins end-to-end against live compose Postgres on 127.0.0.1:5513:
//
//   - admin without MFA: /api/v1/auth/login returns 401
//     mfa_enrollment_required + pending session_id; NO Set-Cookie;
//   - /api/v1/auth/login/mfa/enroll/initiate returns otpauth URL +
//     secret + recovery codes; Cache-Control no-store; NO Set-Cookie;
//   - /api/v1/auth/login/mfa/enroll/complete with a correct TOTP
//     code persists mfa_enabled=true + mfa_secret onto the user row,
//     marks pending consumed, issues full session + Set-Cookie;
//   - replay of the consumed pending handle is rejected with
//     401 invalid_code;
//   - subsequent /api/v1/auth/login still requires MFA but now hits
//     the verify path (returns mfa_required + pending verify-kind
//     session_id, not mfa_enrollment_required);
//   - /api/v1/auth/login/mfa with a correct TOTP code completes the
//     login;
//   - GET /api/v1/validate with the access_token cookie returns 200.
//
// Test discipline mirrors the other e2e tests: randomized email +
// password; assertion never echoes the secret / TOTP code; pending
// row + user soft-deleted on cleanup.
package e2e

import (
	"context"
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // SHA-1 mandated by RFC 6238 §1.
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/auth"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/handlers"
	"github.com/identuum/identuum-idp-oss/internal/postgres"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

func TestE2E_OSS_MFAEnrolment_FullRoundTrip(t *testing.T) {
	dbURL := testDBURL(t)
	applyMigrations(t, dbURL)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	pool, err := postgres.NewPool(ctx, dbURL, nil)
	if err != nil {
		t.Fatalf("open pool: error returned (URL redacted): %s", classifyOpenError(err))
	}
	t.Cleanup(pool.Close)

	repos := postgres.NewPgxRepositories(pool, e2eSigningKeyCipher())
	if repos == nil || repos.User == nil || repos.Session == nil || repos.Key == nil || repos.MFAPendingLoginSession == nil {
		t.Fatal("repository factory returned nil required repo")
	}

	org := seedTestOrganization(t, ctx, repos)
	email := strings.ToLower("e2e-mfa-enrol-" + uuid.NewString() + "@example.invalid")
	plaintext := "enrol-" + uuid.NewString() + "-marker-not-printed"

	seededID, err := uuid.NewRandom()
	if err != nil {
		t.Fatalf("seed uuid: %v", err)
	}
	created, err := repos.User.Create(ctx, &domain.User{
		ID:             seededID,
		OrganizationID: org.ID,
		Email:          email,
		PasswordHash:   plaintext,
		Role:           domain.RoleOrgAdmin, // admin role → MFA-required by policy
		AuthSource:     domain.AuthSourceLocal,
		EmailVerified:  true,
		// MFAEnabled is the zero value (false).
	})
	if err != nil {
		t.Fatalf("seed Create: %v", err)
	}
	t.Cleanup(func() {
		_ = repos.User.Delete(context.Background(), created.ID, created.OrganizationID)
	})

	keySvc := service.NewKeyService(repos.Key)
	active, err := keySvc.ListActive(ctx)
	if err != nil {
		t.Fatalf("ListActive: %v", err)
	}
	if len(active) == 0 {
		if _, err := keySvc.Generate(ctx, service.GenerateKeyOptions{
			Algorithm: string(domain.KeyAlgorithmEdDSA),
			State:     domain.KeyStateActive,
		}); err != nil {
			t.Fatalf("Generate signing key: %v", err)
		}
	}

	const issuer = "http://localhost:7113"
	sessions := service.NewUserSessionService(nil, repos.Session, service.UserSessionServiceOptions{})
	mfa := service.NewMFAVerifierService(nil, service.PlaintextTOTPSecretResolver{}, service.MFAVerifierOptions{})
	login := service.NewLocalLoginService(nil, repos.User, sessions, mfa)
	userToken := service.NewUserTokenService(nil, keySvc, service.UserTokenServiceOptions{Issuer: issuer})
	verifier := auth.NewRepositoryVerifier(nil, repos.Key, auth.VerifierOptions{ExpectedIssuer: issuer})
	enrollment := service.NewMFAEnrollmentService(nil, service.MFAEnrollmentRepoOptions{
		Pending: repos.MFAPendingLoginSession,
		Users:   repos.User,
		Issuer:  "Identuum",
		// Identity cipher for the e2e roundtrip: the at-rest seed is
		// stored unchanged so the PlaintextTOTPSecretResolver above still
		// resolves it; real AES-256-GCM encryption is unit-proven in
		// internal/service/mfa_at_rest_test.go.
		Cipher: e2eMFAIdentityCipher{},
	}, service.MFAEnrollmentServiceOptions{})

	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	handlers.RegisterAuthSessionRoutes(r, handlers.AuthSessionsHandlerDeps{
		LocalLogin:    login,
		UserSession:   sessions,
		UserToken:     userToken,
		UserLookup:    repos.User,
		SessionLookup: repos.Session,
		TokenVerifier: verifier,
		MFAEnrollment: enrollment,
	})

	// ---------- Step 1: /login returns mfa_enrollment_required + pending session_id ----------

	loginBody := `{"email":"` + email + `","password":"` + plaintext + `","remember_me":false}`
	loginReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(loginBody))
	loginReq.Header.Set("Content-Type", "application/json")
	loginReq.Host = "localhost:7113"
	loginW := httptest.NewRecorder()
	r.ServeHTTP(loginW, loginReq)

	if loginW.Code != http.StatusUnauthorized {
		t.Fatalf("step 1: want 401, got %d (body shape: %s)", loginW.Code, classifyLoginBody(loginW.Body.String()))
	}
	var step1 map[string]any
	_ = json.Unmarshal(loginW.Body.Bytes(), &step1)
	if step1["error"] != "mfa_enrollment_required" {
		t.Fatalf("step 1 error: want mfa_enrollment_required, got %v", step1["error"])
	}
	if step1["mfa_required"] != true {
		t.Fatal("step 1 body must carry mfa_required:true")
	}
	if step1["mfa_enrollment_required"] != true {
		t.Fatal("step 1 body must carry mfa_enrollment_required:true")
	}
	pendingID, _ := step1["session_id"].(string)
	if pendingID == "" {
		t.Fatal("step 1: session_id MUST be present on mfa_enrollment_required body")
	}
	if len(loginW.Result().Cookies()) != 0 {
		t.Fatal("step 1: Set-Cookie MUST be absent on mfa_enrollment_required path")
	}

	// ---------- Step 2: /enroll/initiate returns otpauth URL + secret ----------

	initiateBody := `{"session_id":"` + pendingID + `"}`
	initReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login/mfa/enroll/initiate", strings.NewReader(initiateBody))
	initReq.Header.Set("Content-Type", "application/json")
	initReq.Host = "localhost:7113"
	initW := httptest.NewRecorder()
	r.ServeHTTP(initW, initReq)

	if initW.Code != http.StatusOK {
		t.Fatalf("step 2: want 200, got %d", initW.Code)
	}
	if cc := initW.Header().Get("Cache-Control"); !strings.Contains(cc, "no-store") {
		t.Fatalf("step 2: Cache-Control must contain no-store, got %q", cc)
	}
	if len(initW.Result().Cookies()) != 0 {
		t.Fatal("step 2: Set-Cookie MUST be absent on /initiate")
	}
	var step2 map[string]any
	_ = json.Unmarshal(initW.Body.Bytes(), &step2)
	otpauthURL, _ := step2["otpauth_url"].(string)
	secret, _ := step2["secret"].(string)
	codes, _ := step2["recovery_codes"].([]any)
	if otpauthURL == "" || secret == "" || len(codes) == 0 {
		t.Fatal("step 2: otpauth_url, secret, recovery_codes must all be populated")
	}
	if !strings.HasPrefix(otpauthURL, "otpauth://totp/Identuum:") {
		t.Fatal("step 2: otpauth URL malformed")
	}
	// Defence in depth: parse the secret out of the otpauth query to
	// confirm it matches the top-level secret field (the server
	// returns both so the test does not need to URL-parse, but the
	// equality is a useful contract guard).
	u, err := url.Parse(otpauthURL)
	if err != nil {
		t.Fatalf("step 2: parse otpauth URL: %v", err)
	}
	if u.Query().Get("secret") != secret {
		t.Fatal("step 2: otpauth URL secret query must match top-level secret field")
	}

	// ---------- Step 3: /enroll/complete with correct code completes login + sets cookies ----------

	counter := uint64(time.Now().Unix()) / uint64(service.TOTPPeriodSeconds)
	code := computeTOTPCodeForTest(t, secret, counter)
	completeBody := `{"session_id":"` + pendingID + `","code":"` + code + `"}`
	completeReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login/mfa/enroll/complete", strings.NewReader(completeBody))
	completeReq.Header.Set("Content-Type", "application/json")
	completeReq.Host = "localhost:7113"
	completeW := httptest.NewRecorder()
	r.ServeHTTP(completeW, completeReq)

	if completeW.Code != http.StatusOK {
		t.Fatalf("step 3: want 200, got %d (body shape: %s)", completeW.Code, classifyLoginBody(completeW.Body.String()))
	}
	var step3 map[string]any
	_ = json.Unmarshal(completeW.Body.Bytes(), &step3)
	if step3["role"] != "org_admin" {
		t.Fatalf("step 3: role: want org_admin, got %v", step3["role"])
	}
	if step3["email"] != email {
		t.Fatalf("step 3: email mismatch")
	}
	if access, _ := step3["access_token"].(string); access == "" {
		t.Fatal("step 3: access_token must be present on enrolment-complete success")
	}
	cookies := completeW.Result().Cookies()
	if findCookieByName(cookies, "access_token") == nil {
		t.Fatal("step 3: access_token Set-Cookie missing after enrolment complete")
	}

	// Verify the user row in the DB now carries MFAEnabled=true +
	// non-empty MFASecret.
	persisted, err := repos.User.GetByEmailAndOrgID(ctx, org.ID, email)
	if err != nil {
		t.Fatalf("step 3: post-enrol user lookup: %v", err)
	}
	if !persisted.MFAEnabled {
		t.Fatal("step 3: persisted user must have MFAEnabled=true")
	}
	if persisted.MFASecret == nil || *persisted.MFASecret == "" {
		t.Fatal("step 3: persisted user must have MFASecret set")
	}

	// ---------- Step 4: replay of the consumed pending handle is rejected ----------

	replayReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login/mfa/enroll/complete", strings.NewReader(completeBody))
	replayReq.Header.Set("Content-Type", "application/json")
	replayW := httptest.NewRecorder()
	r.ServeHTTP(replayW, replayReq)
	if replayW.Code != http.StatusUnauthorized {
		t.Fatalf("step 4 replay: want 401, got %d", replayW.Code)
	}
	if !strings.Contains(replayW.Body.String(), `"invalid_code"`) {
		t.Fatal("step 4 replay: body must use invalid_code sentinel")
	}
	if len(replayW.Result().Cookies()) != 0 {
		t.Fatal("step 4 replay: Set-Cookie MUST be absent")
	}

	// ---------- Step 5: subsequent /login hits the verify path (not enrolment) ----------

	loginAgainReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(loginBody))
	loginAgainReq.Header.Set("Content-Type", "application/json")
	loginAgainReq.Host = "localhost:7113"
	loginAgainW := httptest.NewRecorder()
	r.ServeHTTP(loginAgainW, loginAgainReq)
	if loginAgainW.Code != http.StatusUnauthorized {
		t.Fatalf("step 5: want 401, got %d", loginAgainW.Code)
	}
	var step5 map[string]any
	_ = json.Unmarshal(loginAgainW.Body.Bytes(), &step5)
	if step5["error"] != "mfa_required" {
		t.Fatalf("step 5: want error=mfa_required (NOT enrollment), got %v", step5["error"])
	}
	if step5["mfa_enrollment_required"] != false {
		t.Fatal("step 5: mfa_enrollment_required must be false on verify path")
	}
	verifyPendingID, _ := step5["session_id"].(string)
	if verifyPendingID == "" {
		t.Fatal("step 5: verify-kind pending session_id MUST be present")
	}
	if len(loginAgainW.Result().Cookies()) != 0 {
		t.Fatal("step 5: Set-Cookie MUST be absent on mfa_required path")
	}

	// ---------- Step 6: /login/mfa with correct code completes login ----------

	verifyCode := computeTOTPCodeForTest(t, *persisted.MFASecret, uint64(time.Now().Unix())/uint64(service.TOTPPeriodSeconds))
	verifyBody := `{"session_id":"` + verifyPendingID + `","code":"` + verifyCode + `"}`
	verifyReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login/mfa", strings.NewReader(verifyBody))
	verifyReq.Header.Set("Content-Type", "application/json")
	verifyReq.Host = "localhost:7113"
	verifyW := httptest.NewRecorder()
	r.ServeHTTP(verifyW, verifyReq)
	if verifyW.Code != http.StatusOK {
		t.Fatalf("step 6: want 200, got %d (body shape: %s)", verifyW.Code, classifyLoginBody(verifyW.Body.String()))
	}
	verifyCookies := verifyW.Result().Cookies()
	verifyAccess := findCookieByName(verifyCookies, "access_token")
	if verifyAccess == nil || verifyAccess.Value == "" {
		t.Fatal("step 6: access_token Set-Cookie missing on /login/mfa success")
	}

	// ---------- Step 7: /validate with the access_token cookie returns 200 ----------

	validateReq := httptest.NewRequest(http.MethodGet, "/api/v1/validate", nil)
	validateReq.AddCookie(&http.Cookie{Name: "access_token", Value: verifyAccess.Value})
	validateW := httptest.NewRecorder()
	r.ServeHTTP(validateW, validateReq)
	if validateW.Code != http.StatusOK {
		t.Fatalf("step 7: validate after MFA verify: want 200, got %d", validateW.Code)
	}
}

// computeTOTPCodeForTest mirrors the service-internal computeHOTP
// (which is unexported from internal/service) by re-implementing
// the RFC 6238 step for test purposes. Kept identical to the
// service's defaultTOTPPeriod / defaultTOTPDigits so the test
// produces the code the service expects.
//
// Implementation note: rather than re-export the service helper,
// we wrap the existing TOTP verifier by computing the code via the
// public MFAVerifierService.Verify path is not possible (Verify
// only matches, never generates). We therefore inline the
// HOTP/SHA1 step here. Keep the algorithm in sync with
// internal/service/mfa_verifier.go::computeHOTP.
func computeTOTPCodeForTest(t *testing.T, secret string, counter uint64) string {
	t.Helper()
	code, err := computeHOTPForTest(secret, counter)
	if err != nil {
		t.Fatalf("computeHOTPForTest: %v", err)
	}
	return code
}

// computeHOTPForTest mirrors internal/service/mfa_verifier.go::computeHOTP.
// Kept in sync (SHA-1 / 6-digit / base32 NoPad-tolerant) so the test
// produces the same code the production verifier expects.
func computeHOTPForTest(secret string, counter uint64) (string, error) {
	normalised := strings.ToUpper(strings.TrimSpace(secret))
	normalised = strings.ReplaceAll(normalised, " ", "")
	if pad := len(normalised) % 8; pad != 0 {
		normalised += strings.Repeat("=", 8-pad)
	}
	key, err := base32.StdEncoding.DecodeString(normalised)
	if err != nil {
		return "", err
	}
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, counter)
	mac := hmac.New(sha1.New, key)
	_, _ = mac.Write(buf)
	sum := mac.Sum(nil)
	offset := int(sum[len(sum)-1] & 0x0f)
	bin := int(sum[offset]&0x7f)<<24 |
		int(sum[offset+1])<<16 |
		int(sum[offset+2])<<8 |
		int(sum[offset+3])
	const digits = 6
	mod := 1
	for range digits {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", digits, bin%mod), nil
}

// e2eMFAIdentityCipher round-trips the TOTP seed unchanged so the enrollment
// roundtrip works with the PlaintextTOTPSecretResolver in this e2e harness.
type e2eMFAIdentityCipher struct{}

func (e2eMFAIdentityCipher) Encrypt(plaintext string) (string, error)  { return plaintext, nil }
func (e2eMFAIdentityCipher) Decrypt(ciphertext string) (string, error) { return ciphertext, nil }
