//go:build integration

// MFA at-rest encryption — real-cipher E2E integration test.
//
// Closes the verification gap left by login_mfa_enrolment_http_test.go, which
// wires e2eMFAIdentityCipher{} + PlaintextTOTPSecretResolver and therefore
// does NOT exercise real AES-256-GCM encryption.
//
// This test wires the real CryptoService (keyed from
// IDENTUUM_IDP_ENCRYPTION_KEY, the same TEST-ONLY key the
// integration-test Makefile target exports) and the real
// EncryptedTOTPSecretResolver, then asserts at the DATABASE LAYER:
//
//	(a) users.mfa_secret is AES-256-GCM ciphertext ("v2:…"), not the raw seed.
//	(b) A subsequent TOTP verification SUCCEEDS, proving decrypt-on-read
//	    round-trips correctly through real Postgres.
//	(c) users.mfa_recovery_codes are SHA-256 hashes, not raw codes;
//	    a correct raw code is accepted (hash match) and single-use;
//	    a wrong code is rejected.
//	(d) mfa_pending_login_sessions.secret is ciphertext and .recovery_codes
//	    are hashes mid-enrollment (before Complete) — no plaintext side-channel.

package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/auth"
	localcrypto "github.com/identuum/identuum-idp-oss/internal/crypto"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/handlers"
	"github.com/identuum/identuum-idp-oss/internal/postgres"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

func TestE2E_OSS_MFAAtRestRealCipher(t *testing.T) {
	// Resolve the AES-256-GCM key. The Makefile exports a TEST-ONLY
	// cafebabe×8 default via $${IDENTUUM_IDP_ENCRYPTION_KEY:-...}.
	hexKey := os.Getenv("IDENTUUM_IDP_ENCRYPTION_KEY")
	if hexKey == "" {
		hexKey = os.Getenv("AUTH_SERVICE_ENCRYPTION_KEY")
	}
	// MISSING OR INVALID KEY IS A FAILURE, NOT A SKIP (CE-DB-PROVISION,
	// 2026-08-02). Same reasoning as testDBURL/P2-20 above: this file is behind
	// `//go:build integration`, so the caller asked for this test by name. A skip
	// let the at-rest cipher — the whole point of the test — go unexercised while
	// the run printed `ok`. An INVALID key is worse than an absent one: it means
	// someone supplied a key and it does not work, which is a misconfiguration to
	// report, not a condition to tiptoe around. The key is a credential and is
	// never echoed; only the parse error is.
	if hexKey == "" {
		t.Fatal("IDENTUUM_IDP_ENCRYPTION_KEY (or AUTH_SERVICE_ENCRYPTION_KEY) is not set; " +
			"the real-cipher MFA at-rest e2e test was requested via -tags integration and " +
			"requires a 64-hex AES-256-GCM key. `make integration-test` supplies a TEST-ONLY " +
			"default automatically (Makefile); to run manually, export it yourself")
	}
	cs, err := localcrypto.NewCryptoService(hexKey)
	if err != nil {
		t.Fatalf("IDENTUUM_IDP_ENCRYPTION_KEY is invalid (%v); supply a valid 64-hex key", err)
	}

	dbURL := testDBURL(t)
	applyMigrations(t, dbURL)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	pool, poolErr := postgres.NewPool(ctx, dbURL, nil)
	if poolErr != nil {
		t.Fatalf("open pool: %v", classifyOpenError(poolErr))
	}
	t.Cleanup(pool.Close)

	repos := postgres.NewPgxRepositories(pool, e2eSigningKeyCipher())
	if repos == nil || repos.User == nil || repos.Session == nil || repos.Key == nil || repos.MFAPendingLoginSession == nil {
		t.Fatal("repository factory returned nil required repo")
	}

	org := seedTestOrganization(t, ctx, repos)
	email := strings.ToLower("e2e-mfa-real-" + uuid.NewString() + "@example.invalid")
	password := "real-cipher-" + uuid.NewString()

	userID, err := uuid.NewRandom()
	if err != nil {
		t.Fatalf("seed uuid: %v", err)
	}
	created, err := repos.User.Create(ctx, &domain.User{
		ID:             userID,
		OrganizationID: org.ID,
		Email:          email,
		PasswordHash:   password,
		Role:           domain.RoleOrgAdmin,
		AuthSource:     domain.AuthSourceLocal,
		EmailVerified:  true,
	})
	if err != nil {
		t.Fatalf("seed user: %v", err)
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
			t.Fatalf("generate signing key: %v", err)
		}
	}

	const issuer = "http://localhost:7113"
	sessions := service.NewUserSessionService(nil, repos.Session, service.UserSessionServiceOptions{})

	// Real EncryptedTOTPSecretResolver — decrypts at-rest ciphertext before TOTP verify.
	mfa := service.NewMFAVerifierService(nil, service.EncryptedTOTPSecretResolver{Cipher: cs}, service.MFAVerifierOptions{})
	login := service.NewLocalLoginService(nil, repos.User, sessions, mfa)
	userToken := service.NewUserTokenService(nil, keySvc, service.UserTokenServiceOptions{Issuer: issuer})
	verifier := auth.NewRepositoryVerifier(nil, repos.Key, auth.VerifierOptions{ExpectedIssuer: issuer})

	// Real CryptoService cipher — encryptSeed/decryptSeed use AES-256-GCM.
	enrollment := service.NewMFAEnrollmentService(nil, service.MFAEnrollmentRepoOptions{
		Pending: repos.MFAPendingLoginSession,
		Users:   repos.User,
		Issuer:  "Identuum",
		Cipher:  cs,
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

	loginBody := fmt.Sprintf(`{"email":%q,"password":%q,"remember_me":false}`, email, password)

	// ── Step 1: login → mfa_enrollment_required ────────────────────────────────

	loginW := httptest.NewRecorder()
	loginReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(loginBody))
	loginReq.Header.Set("Content-Type", "application/json")
	loginReq.Host = "localhost:7113"
	r.ServeHTTP(loginW, loginReq)
	if loginW.Code != http.StatusUnauthorized {
		t.Fatalf("step 1: want 401, got %d", loginW.Code)
	}
	var step1 map[string]any
	_ = json.Unmarshal(loginW.Body.Bytes(), &step1)
	if step1["error"] != "mfa_enrollment_required" {
		t.Fatalf("step 1: want mfa_enrollment_required, got %v", step1["error"])
	}
	pendingEnrollIDStr, _ := step1["session_id"].(string)
	if pendingEnrollIDStr == "" {
		t.Fatal("step 1: session_id must be present")
	}
	pendingEnrollID, err := uuid.Parse(pendingEnrollIDStr)
	if err != nil {
		t.Fatalf("step 1: session_id is not a valid UUID: %v", err)
	}

	// ── Step 2: /enroll/initiate → raw seed + raw recovery codes ──────────────

	initBody := fmt.Sprintf(`{"session_id":%q}`, pendingEnrollIDStr)
	initReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login/mfa/enroll/initiate", strings.NewReader(initBody))
	initReq.Header.Set("Content-Type", "application/json")
	initReq.Host = "localhost:7113"
	initW := httptest.NewRecorder()
	r.ServeHTTP(initW, initReq)
	if initW.Code != http.StatusOK {
		t.Fatalf("step 2: want 200, got %d", initW.Code)
	}
	var step2 map[string]any
	_ = json.Unmarshal(initW.Body.Bytes(), &step2)
	rawSeed, _ := step2["secret"].(string)
	if rawSeed == "" {
		t.Fatal("step 2: secret must be non-empty")
	}
	codesAny, _ := step2["recovery_codes"].([]any)
	if len(codesAny) == 0 {
		t.Fatal("step 2: recovery_codes must be non-empty")
	}
	rawCodes := make([]string, len(codesAny))
	for i, c := range codesAny {
		rawCodes[i], _ = c.(string)
	}

	// ── Assertion (d): pending row stores CIPHERTEXT seed + HASHED codes ───────
	// Query AFTER initiate, BEFORE complete — no plaintext side-channel.

	t.Run("d_pending_row_no_plaintext_side_channel", func(t *testing.T) {
		var storedSecret string
		var codesJSON []byte
		if err := pool.QueryRow(ctx,
			`SELECT secret, recovery_codes FROM mfa_pending_login_sessions WHERE id = $1`,
			pendingEnrollID,
		).Scan(&storedSecret, &codesJSON); err != nil {
			t.Fatalf("query pending row: %v", err)
		}

		if storedSecret == "" {
			t.Error("d: pending.secret is empty after /initiate")
		}
		// Must be ciphertext — starts with "v2:" (AES-256-GCM keyed).
		if !strings.HasPrefix(storedSecret, "v2:") {
			t.Errorf("d: pending.secret lacks v2: prefix (got shape %s); plaintext may be stored", mfaCiphertextShape(storedSecret))
		}
		// Must NOT equal the raw seed (encryption must have changed it).
		if storedSecret == rawSeed {
			t.Error("d: pending.secret == raw seed; plaintext was stored (expected ciphertext)")
		}

		var storedCodes []string
		if err := json.Unmarshal(codesJSON, &storedCodes); err != nil {
			t.Fatalf("d: unmarshal pending recovery_codes: %v", err)
		}
		if len(storedCodes) != len(rawCodes) {
			t.Fatalf("d: want %d pending recovery codes, got %d", len(rawCodes), len(storedCodes))
		}
		for i, rc := range rawCodes {
			// Must NOT equal the raw code.
			if storedCodes[i] == rc {
				t.Errorf("d: pending.recovery_codes[%d] == raw code; plaintext stored", i)
			}
			// Must equal SHA-256(rawCode) — the exact hash stored by hashRecoveryCodes.
			if storedCodes[i] != localcrypto.HashSecret(rc) {
				t.Errorf("d: pending.recovery_codes[%d] does not match SHA-256 of raw code", i)
			}
		}
	})

	// ── Step 3: /enroll/complete ───────────────────────────────────────────────

	enrollCode := computeTOTPCodeForTest(t, rawSeed, uint64(time.Now().Unix())/uint64(service.TOTPPeriodSeconds))
	completeBody := fmt.Sprintf(`{"session_id":%q,"code":%q}`, pendingEnrollIDStr, enrollCode)
	completeReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login/mfa/enroll/complete", strings.NewReader(completeBody))
	completeReq.Header.Set("Content-Type", "application/json")
	completeReq.Host = "localhost:7113"
	completeW := httptest.NewRecorder()
	r.ServeHTTP(completeW, completeReq)
	if completeW.Code != http.StatusOK {
		t.Fatalf("step 3: enroll/complete: want 200, got %d (shape: %s)",
			completeW.Code, classifyLoginBody(completeW.Body.String()))
	}

	// ── Assertions (a) + (c): user row stores CIPHERTEXT seed + HASHED codes ──

	t.Run("a_c_user_row_at_rest", func(t *testing.T) {
		var storedMFASecret string
		var codesJSON []byte
		if err := pool.QueryRow(ctx,
			`SELECT mfa_secret, mfa_recovery_codes FROM users WHERE id = $1`,
			created.ID,
		).Scan(&storedMFASecret, &codesJSON); err != nil {
			t.Fatalf("query users row: %v", err)
		}

		// (a) mfa_secret is AES-256-GCM ciphertext, not the raw seed.
		if storedMFASecret == "" {
			t.Error("a: users.mfa_secret is empty after enrollment")
		}
		if !strings.HasPrefix(storedMFASecret, "v2:") {
			t.Errorf("a: users.mfa_secret lacks v2: prefix (shape %s); plaintext may be stored",
				mfaCiphertextShape(storedMFASecret))
		}
		if storedMFASecret == rawSeed {
			t.Error("a: users.mfa_secret == raw seed; plaintext was stored (expected ciphertext)")
		}

		// (c) mfa_recovery_codes are SHA-256 hashes, not raw codes.
		var storedCodes []string
		if err := json.Unmarshal(codesJSON, &storedCodes); err != nil {
			t.Fatalf("c: unmarshal mfa_recovery_codes: %v", err)
		}
		if len(storedCodes) != len(rawCodes) {
			t.Fatalf("c: want %d recovery codes, got %d", len(rawCodes), len(storedCodes))
		}
		for i, rc := range rawCodes {
			if storedCodes[i] == rc {
				t.Errorf("c: mfa_recovery_codes[%d] == raw code; plaintext stored", i)
			}
			if storedCodes[i] != localcrypto.HashSecret(rc) {
				t.Errorf("c: mfa_recovery_codes[%d] does not match SHA-256 of raw code", i)
			}
		}
	})

	// ── Assertion (b): TOTP verify succeeds — real decrypt-on-read round-trip ──

	// Re-login → verify-kind pending session.
	loginW2 := httptest.NewRecorder()
	loginReq2 := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(loginBody))
	loginReq2.Header.Set("Content-Type", "application/json")
	loginReq2.Host = "localhost:7113"
	r.ServeHTTP(loginW2, loginReq2)
	if loginW2.Code != http.StatusUnauthorized {
		t.Fatalf("b: re-login: want 401, got %d", loginW2.Code)
	}
	var loginResp2 map[string]any
	_ = json.Unmarshal(loginW2.Body.Bytes(), &loginResp2)
	if loginResp2["error"] != "mfa_required" {
		t.Fatalf("b: re-login: want mfa_required, got %v", loginResp2["error"])
	}
	pendingVerifyIDStr, _ := loginResp2["session_id"].(string)
	if pendingVerifyIDStr == "" {
		t.Fatal("b: re-login: session_id must be present")
	}

	t.Run("b_totp_verify_real_decrypt_succeeds", func(t *testing.T) {
		verifyCode := computeTOTPCodeForTest(t, rawSeed, uint64(time.Now().Unix())/uint64(service.TOTPPeriodSeconds))
		verifyBody := fmt.Sprintf(`{"session_id":%q,"code":%q}`, pendingVerifyIDStr, verifyCode)
		verifyReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login/mfa", strings.NewReader(verifyBody))
		verifyReq.Header.Set("Content-Type", "application/json")
		verifyReq.Host = "localhost:7113"
		verifyW := httptest.NewRecorder()
		r.ServeHTTP(verifyW, verifyReq)
		if verifyW.Code != http.StatusOK {
			t.Fatalf("b: TOTP verify with real cipher: want 200, got %d (shape: %s)",
				verifyW.Code, classifyLoginBody(verifyW.Body.String()))
		}
	})

	// ── Assertion (c continued): recovery code accepted, single-use, wrong rejected ──

	// Third login → another verify-kind pending.
	loginW3 := httptest.NewRecorder()
	loginReq3 := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(loginBody))
	loginReq3.Header.Set("Content-Type", "application/json")
	loginReq3.Host = "localhost:7113"
	r.ServeHTTP(loginW3, loginReq3)
	var loginResp3 map[string]any
	_ = json.Unmarshal(loginW3.Body.Bytes(), &loginResp3)
	pendingVerify2IDStr, _ := loginResp3["session_id"].(string)
	if pendingVerify2IDStr == "" {
		t.Fatal("c: third login: session_id must be present")
	}

	t.Run("c_recovery_code_hash_match_and_single_use", func(t *testing.T) {
		// Submit rawCodes[0] as "code". VerifyAndConsume: TOTP fails (base32 ≠
		// 6 decimal digits), falls through to consumeRecoveryCode which hashes
		// the candidate and matches it against the stored SHA-256 hashes.
		recBody := fmt.Sprintf(`{"session_id":%q,"code":%q}`, pendingVerify2IDStr, rawCodes[0])
		recReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login/mfa", strings.NewReader(recBody))
		recReq.Header.Set("Content-Type", "application/json")
		recReq.Host = "localhost:7113"
		recW := httptest.NewRecorder()
		r.ServeHTTP(recW, recReq)
		if recW.Code != http.StatusOK {
			t.Fatalf("c: recovery code login: want 200, got %d", recW.Code)
		}

		// Code must be burned: mfa_recovery_codes count decreased by 1.
		var codesJSON []byte
		if err := pool.QueryRow(ctx,
			`SELECT mfa_recovery_codes FROM users WHERE id = $1`,
			created.ID,
		).Scan(&codesJSON); err != nil {
			t.Fatalf("c: query codes after burn: %v", err)
		}
		var remaining []string
		if err := json.Unmarshal(codesJSON, &remaining); err != nil {
			t.Fatalf("c: unmarshal codes after burn: %v", err)
		}
		if len(remaining) != len(rawCodes)-1 {
			t.Errorf("c: single-use: want %d codes remaining, got %d", len(rawCodes)-1, len(remaining))
		}

		// Single-use: same code rejected when replayed (burned from the list).
		loginW4 := httptest.NewRecorder()
		loginReq4 := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(loginBody))
		loginReq4.Header.Set("Content-Type", "application/json")
		loginReq4.Host = "localhost:7113"
		r.ServeHTTP(loginW4, loginReq4)
		var loginResp4 map[string]any
		_ = json.Unmarshal(loginW4.Body.Bytes(), &loginResp4)
		pendingVerify3IDStr, _ := loginResp4["session_id"].(string)
		if pendingVerify3IDStr == "" {
			t.Fatal("c: fourth login: session_id must be present")
		}
		burnedBody := fmt.Sprintf(`{"session_id":%q,"code":%q}`, pendingVerify3IDStr, rawCodes[0])
		burnedReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login/mfa", strings.NewReader(burnedBody))
		burnedReq.Header.Set("Content-Type", "application/json")
		burnedReq.Host = "localhost:7113"
		burnedW := httptest.NewRecorder()
		r.ServeHTTP(burnedW, burnedReq)
		if burnedW.Code != http.StatusUnauthorized {
			t.Errorf("c: burned recovery code must be rejected; want 401, got %d", burnedW.Code)
		}

		// Wrong code (never valid): also rejected.
		loginW5 := httptest.NewRecorder()
		loginReq5 := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(loginBody))
		loginReq5.Header.Set("Content-Type", "application/json")
		loginReq5.Host = "localhost:7113"
		r.ServeHTTP(loginW5, loginReq5)
		var loginResp5 map[string]any
		_ = json.Unmarshal(loginW5.Body.Bytes(), &loginResp5)
		pendingVerify4IDStr, _ := loginResp5["session_id"].(string)
		if pendingVerify4IDStr == "" {
			t.Fatal("c: fifth login: session_id must be present")
		}
		wrongBody := fmt.Sprintf(`{"session_id":%q,"code":"WRONGRECOVERYXXX"}`, pendingVerify4IDStr)
		wrongReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login/mfa", strings.NewReader(wrongBody))
		wrongReq.Header.Set("Content-Type", "application/json")
		wrongReq.Host = "localhost:7113"
		wrongW := httptest.NewRecorder()
		r.ServeHTTP(wrongW, wrongReq)
		if wrongW.Code != http.StatusUnauthorized {
			t.Errorf("c: wrong recovery code must be rejected; want 401, got %d", wrongW.Code)
		}
	})
}

// mfaCiphertextShape returns a non-secret shape label for assertion messages.
// Never echoes the actual ciphertext value.
func mfaCiphertextShape(s string) string {
	switch {
	case strings.HasPrefix(s, "v2:"):
		return "v2:<...>"
	case strings.HasPrefix(s, "v1:"):
		return "v1:<...>"
	default:
		return "<no-version-prefix>"
	}
}
