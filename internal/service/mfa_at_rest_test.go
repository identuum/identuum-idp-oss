package service

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/crypto"
	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// MFA at-rest protection proof (scenarios a-e). These use a REAL
// AES-256-GCM crypto.CryptoService (not the identity test double) to prove the
// seed is encrypted and recovery codes are hashed at rest, and that a missing
// cipher fails closed without a plaintext write or panic.

const mfaTestHexKey = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" // 32-byte hex

func realMFACipher(t *testing.T) *crypto.CryptoService {
	t.Helper()
	c, err := crypto.NewCryptoService(mfaTestHexKey)
	if err != nil {
		t.Fatalf("NewCryptoService: %v", err)
	}
	return c
}

// enrollViaService drives CreatePending → Initiate → Complete with the given
// cipher and returns the harness + the plaintext seed/codes shown once.
func enrollViaService(t *testing.T, cipher MFASecretCipher) (*MFAEnrollmentService, *stubUserRepoForMFAEnroll, *domain.User, string, []string) {
	t.Helper()
	pendingRepo := newStubPendingRepo()
	userRepo := newStubUserRepoForMFAEnroll()
	uid := uuid.New()
	user := &domain.User{
		ID: uid, OrganizationID: uuid.New(), Email: "atrest@test", Role: domain.RoleOrgUser,
		AuthSource: domain.AuthSourceLocal, EmailVerified: true,
	}
	userRepo.byID[uid] = user
	svc := NewMFAEnrollmentService(nil, MFAEnrollmentRepoOptions{
		Pending: pendingRepo, Users: userRepo, Issuer: "Identuum", Cipher: cipher,
	}, MFAEnrollmentServiceOptions{})

	row, err := svc.CreatePending(context.Background(), user, domain.MFAPendingKindEnroll, false)
	if err != nil {
		t.Fatalf("CreatePending: %v", err)
	}
	init, err := svc.Initiate(context.Background(), row.ID)
	if err != nil {
		t.Fatalf("Initiate: %v", err)
	}
	counter := uint64(time.Now().Unix()) / defaultTOTPPeriod
	code, _ := computeHOTP(init.Secret, counter, defaultTOTPDigits)
	if _, err := svc.Complete(context.Background(), row.ID, code); err != nil {
		t.Fatalf("Complete: %v", err)
	}
	return svc, userRepo, user, init.Secret, init.RecoveryCodes
}

// (a) enroll TOTP → stored users.mfa_secret is CIPHERTEXT (not the raw seed),
// and a later verify round-trips (decrypt-then-verify).
func TestMFAAtRest_TOTPSeedEncryptedAndVerifies(t *testing.T) {
	cipher := realMFACipher(t)
	_, userRepo, user, plaintextSeed, _ := enrollViaService(t, cipher)

	stored := userRepo.byID[user.ID]
	if stored.MFASecret == nil || *stored.MFASecret == "" {
		t.Fatal("MFASecret not persisted")
	}
	if *stored.MFASecret == plaintextSeed {
		t.Fatalf("(a) MFASecret stored as RAW seed — at-rest regression not closed")
	}
	if !strings.HasPrefix(*stored.MFASecret, "v2:") {
		t.Fatalf("(a) MFASecret is not AES-256-GCM ciphertext (no v2 prefix): %.8q…", *stored.MFASecret)
	}
	// decrypt-then-verify round-trips.
	resolver := EncryptedTOTPSecretResolver{Cipher: cipher}
	got, err := resolver.Resolve(context.Background(), stored)
	if err != nil || got != plaintextSeed {
		t.Fatalf("(a) resolver did not decrypt back to the seed: err=%v", err)
	}
	verifier := NewMFAVerifierService(nil, resolver, MFAVerifierOptions{})
	stored.MFAEnabled = true
	counter := uint64(time.Now().Unix()) / defaultTOTPPeriod
	code, _ := computeHOTP(plaintextSeed, counter, defaultTOTPDigits)
	if err := verifier.Verify(context.Background(), stored, code); err != nil {
		t.Fatalf("(a) decrypt-then-verify failed: %v", err)
	}
	t.Logf("EVIDENCE (a) mfa_secret stored ciphertext (v2:…), decrypt-then-verify OK; raw seed NOT at rest")
}

// (b) recovery codes stored as HASHES (not raw); a correct code is accepted
// (hash match) and single-use; a wrong code rejected.
// RULE: MFA-RECOVERY-1
func TestMFAAtRest_RecoveryCodesHashedAcceptedSingleUseWrongRejected(t *testing.T) {
	cipher := realMFACipher(t)
	svc, userRepo, user, _, codes := enrollViaService(t, cipher)
	stored := userRepo.byID[user.ID]

	for _, raw := range codes {
		for _, h := range stored.MFARecoveryCodes {
			if h == raw {
				t.Fatalf("(b) recovery code stored RAW: %q", raw)
			}
		}
	}
	if len(stored.MFARecoveryCodes) > 0 && stored.MFARecoveryCodes[0] != crypto.HashSecret(codes[0]) {
		t.Fatalf("(b) stored recovery code is not the SHA-256 hash of the plaintext")
	}
	// Login via a verify-kind pending row, redeeming a recovery code.
	row, _ := svc.CreatePending(context.Background(), stored, domain.MFAPendingKindVerify, false)
	stored.MFAEnabled = true
	res, err := svc.VerifyAndConsume(context.Background(), row.ID, codes[1])
	if err != nil || !res.RecoveryCodeUsed {
		t.Fatalf("(b) correct recovery code not accepted by hash: err=%v used=%v", err, res != nil && res.RecoveryCodeUsed)
	}
	// Single-use: the same code on a fresh pending row is rejected.
	row2, _ := svc.CreatePending(context.Background(), userRepo.byID[user.ID], domain.MFAPendingKindVerify, false)
	if _, err := svc.VerifyAndConsume(context.Background(), row2.ID, codes[1]); err == nil {
		t.Fatalf("(b) burned recovery code was reusable")
	}
	// Wrong code rejected.
	row3, _ := svc.CreatePending(context.Background(), userRepo.byID[user.ID], domain.MFAPendingKindVerify, false)
	if _, err := svc.VerifyAndConsume(context.Background(), row3.ID, "WRONG-CODE-XYZ"); err == nil {
		t.Fatalf("(b) wrong recovery code accepted")
	}
	t.Logf("EVIDENCE (b) recovery codes stored as SHA-256 hashes; correct accepted+burned; wrong rejected")
}

// (c) the pending enrollment row holds an ENCRYPTED seed + HASHED codes, not
// plaintext, so the pending table is not a plaintext side-channel.
func TestMFAAtRest_PendingRowEncryptedAndHashed(t *testing.T) {
	cipher := realMFACipher(t)
	pendingRepo := newStubPendingRepo()
	userRepo := newStubUserRepoForMFAEnroll()
	uid := uuid.New()
	user := &domain.User{ID: uid, OrganizationID: uuid.New(), Email: "p@test", Role: domain.RoleOrgUser, AuthSource: domain.AuthSourceLocal, EmailVerified: true}
	userRepo.byID[uid] = user
	svc := NewMFAEnrollmentService(nil, MFAEnrollmentRepoOptions{Pending: pendingRepo, Users: userRepo, Issuer: "Identuum", Cipher: cipher}, MFAEnrollmentServiceOptions{})
	row, _ := svc.CreatePending(context.Background(), user, domain.MFAPendingKindEnroll, false)
	init, err := svc.Initiate(context.Background(), row.ID)
	if err != nil {
		t.Fatalf("Initiate: %v", err)
	}
	pending := pendingRepo.rows[row.ID]
	if pending.Secret == nil || *pending.Secret == init.Secret {
		t.Fatalf("(c) pending seed stored RAW")
	}
	if !strings.HasPrefix(*pending.Secret, "v2:") {
		t.Fatalf("(c) pending seed is not ciphertext")
	}
	for _, raw := range init.RecoveryCodes {
		for _, h := range pending.RecoveryCodes {
			if h == raw {
				t.Fatalf("(c) pending recovery code stored RAW: %q", raw)
			}
		}
	}
	t.Logf("EVIDENCE (c) pending row holds ciphertext seed + hashed codes — no plaintext side-channel")
}

// (d) a nil/unavailable cipher (missing/invalid key at startup) makes the MFA
// write path fail CLOSED: Initiate returns an error and writes NO plaintext
// seed; no panic.
func TestMFAAtRest_NilCipherFailsClosedNoPlaintextNoPanic(t *testing.T) {
	pendingRepo := newStubPendingRepo()
	userRepo := newStubUserRepoForMFAEnroll()
	uid := uuid.New()
	user := &domain.User{ID: uid, OrganizationID: uuid.New(), Email: "d@test", Role: domain.RoleOrgUser, AuthSource: domain.AuthSourceLocal, EmailVerified: true}
	userRepo.byID[uid] = user
	// Cipher omitted (nil) — mirrors a missing/invalid MFA encryption key.
	svc := NewMFAEnrollmentService(nil, MFAEnrollmentRepoOptions{Pending: pendingRepo, Users: userRepo, Issuer: "Identuum"}, MFAEnrollmentServiceOptions{})
	row, _ := svc.CreatePending(context.Background(), user, domain.MFAPendingKindEnroll, false)
	_, err := svc.Initiate(context.Background(), row.ID)
	if err == nil {
		t.Fatalf("(d) Initiate must FAIL CLOSED with no cipher")
	}
	// No plaintext seed was written to the pending row.
	if pending := pendingRepo.rows[row.ID]; pending.Secret != nil && *pending.Secret != "" {
		t.Fatalf("(d) a seed was written despite the fail-closed path: %q", *pending.Secret)
	}
	t.Logf("EVIDENCE (d) nil cipher → Initiate fails closed (err=%v), no plaintext seed written, no panic", err)
}
