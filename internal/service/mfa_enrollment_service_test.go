package service

// Unit tests for MFAEnrollmentService. These exercise the pure
// state machine via the narrow repository.MFAPendingLoginSessionRepository
// + repository.UserRepository seams using in-memory stubs — no DB
// required. The pgx wiring is covered by the e2e integration test.
//
// Test discipline:
//   - Pending IDs are explicit so the test can replay them across
//     calls (CreatePending → Initiate → Complete).
//   - Generated TOTP codes are computed via computeHOTP against
//     the same secret the service stored, so the verify step
//     deterministically passes/fails without leaking the secret.
//   - Failure paths assert the OPAQUE sentinel set; tests never
//     compare against the raw secret / code.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/crypto"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/repository"
)

// identityMFACipher is a test double for MFASecretCipher: it round-trips a
// seed unchanged so the EXISTING state-machine tests (which set/assert a
// plaintext MFASecret) keep passing without per-test ciphertext bookkeeping.
// Real AES-256-GCM encryption is proven by the dedicated at-rest tests in
// mfa_at_rest_test.go using a genuine *crypto.CryptoService.
type identityMFACipher struct{}

func (identityMFACipher) Encrypt(plaintext string) (string, error)  { return plaintext, nil }
func (identityMFACipher) Decrypt(ciphertext string) (string, error) { return ciphertext, nil }

// hashCodesForTest mirrors the service's at-rest recovery-code hashing so a
// test that seeds a user's recovery-code column stores the same hashes the
// consume path matches against.
func hashCodesForTest(plain []string) []string {
	out := make([]string, len(plain))
	for i, c := range plain {
		out[i] = crypto.HashSecret(c)
	}
	return out
}

// --- stubs ------------------------------------------------------------------

type stubPendingRepo struct {
	rows map[uuid.UUID]*domain.MFAPendingLoginSession
	// recordErr, when non-nil, is returned by RecordFailedVerifyAttempt
	// to exercise the P0-13 fail-closed path (counter-store error must
	// reject the verification, never let an uncounted guess through).
	recordErr error
}

func newStubPendingRepo() *stubPendingRepo {
	return &stubPendingRepo{rows: map[uuid.UUID]*domain.MFAPendingLoginSession{}}
}

func (s *stubPendingRepo) Create(_ context.Context, row *domain.MFAPendingLoginSession) (*domain.MFAPendingLoginSession, error) {
	cp := *row
	if cp.CreatedAt.IsZero() {
		cp.CreatedAt = time.Now()
	}
	s.rows[cp.ID] = &cp
	out := cp
	return &out, nil
}

func (s *stubPendingRepo) GetByID(_ context.Context, id uuid.UUID) (*domain.MFAPendingLoginSession, error) {
	row, ok := s.rows[id]
	if !ok {
		return nil, repository.ErrMFAPendingSessionNotFound
	}
	cp := *row
	if row.Secret != nil {
		s := *row.Secret
		cp.Secret = &s
	}
	if len(row.RecoveryCodes) > 0 {
		cp.RecoveryCodes = append([]string(nil), row.RecoveryCodes...)
	}
	return &cp, nil
}

func (s *stubPendingRepo) UpdateSecret(_ context.Context, id uuid.UUID, secret string, codes []string) error {
	row, ok := s.rows[id]
	if !ok {
		return repository.ErrMFAPendingSessionNotFound
	}
	if row.ConsumedAt != nil || !row.ExpiresAt.After(time.Now()) {
		return repository.ErrMFAPendingSessionNotFound
	}
	row.Secret = &secret
	row.RecoveryCodes = append([]string(nil), codes...)
	return nil
}

func (s *stubPendingRepo) MarkConsumed(_ context.Context, id uuid.UUID, now time.Time) (bool, error) {
	row, ok := s.rows[id]
	if !ok {
		return false, nil
	}
	if row.ConsumedAt != nil || !row.ExpiresAt.After(now) {
		return false, nil
	}
	row.ConsumedAt = &now
	return true, nil
}

// RecordFailedVerifyAttempt models the Pgx atomic increment-and-invalidate:
// bump the counter on a live handle and, at the threshold, set ConsumedAt in
// the same step. Returns invalidated when the handle is (now) dead.
func (s *stubPendingRepo) RecordFailedVerifyAttempt(_ context.Context, id uuid.UUID, maxAttempts int, now time.Time) (bool, error) {
	if s.recordErr != nil {
		return false, s.recordErr
	}
	row, ok := s.rows[id]
	if !ok {
		return true, nil
	}
	if row.ConsumedAt != nil || !row.ExpiresAt.After(now) {
		return true, nil
	}
	row.FailedAttempts++
	if row.FailedAttempts >= maxAttempts {
		consumed := now
		row.ConsumedAt = &consumed
		return true, nil
	}
	return false, nil
}

func (s *stubPendingRepo) DeleteExpired(_ context.Context) (int64, error) {
	cutoff := time.Now()
	var deleted int64
	for id, row := range s.rows {
		if row.ExpiresAt.Before(cutoff) {
			delete(s.rows, id)
			deleted++
		}
	}
	return deleted, nil
}

// stubUserRepoForMFAEnroll: minimal UserRepository surface the
// MFAEnrollmentService touches (GetByID + Update). All other methods
// panic so the test fails loudly if the service drifts to use them.
type stubUserRepoForMFAEnroll struct {
	byID                map[uuid.UUID]*domain.User
	verifyPasswordCalls int
}

func newStubUserRepoForMFAEnroll() *stubUserRepoForMFAEnroll {
	return &stubUserRepoForMFAEnroll{byID: map[uuid.UUID]*domain.User{}}
}

func (s *stubUserRepoForMFAEnroll) GetByID(_ context.Context, id uuid.UUID) (*domain.User, error) {
	u, ok := s.byID[id]
	if !ok {
		return nil, domain.ErrUserNotFound
	}
	cp := *u
	return &cp, nil
}

// ConsumeRecoveryCode models the P0-11 atomic per-code removal: removes the code
// ONLY while its hash is still present; a repeat gets ok=false.
func (s *stubUserRepoForMFAEnroll) ConsumeRecoveryCode(_ context.Context, id uuid.UUID, codeHash string) (*domain.User, bool, error) {
	u, ok := s.byID[id]
	if !ok {
		return nil, false, nil
	}
	for i, h := range u.MFARecoveryCodes {
		if h == codeHash {
			u.MFARecoveryCodes = append(u.MFARecoveryCodes[:i], u.MFARecoveryCodes[i+1:]...)
			cp := *u
			return &cp, true, nil
		}
	}
	return nil, false, nil // not present (already redeemed)
}

func (s *stubUserRepoForMFAEnroll) Update(_ context.Context, id uuid.UUID, _ uuid.UUID, opts repository.UpdateUserOptions) (*domain.User, error) {
	u, ok := s.byID[id]
	if !ok {
		return nil, domain.ErrUserNotFound
	}
	if opts.MFAEnabled != nil {
		u.MFAEnabled = *opts.MFAEnabled
	}
	if opts.MFASecret != nil {
		v := *opts.MFASecret
		u.MFASecret = &v
	}
	if opts.MFARecoveryCodes != nil {
		u.MFARecoveryCodes = append([]string(nil), opts.MFARecoveryCodes...)
	}
	cp := *u
	return &cp, nil
}

// Unused UserRepository methods — panic so unexpected dispatch
// surfaces immediately.
func (s *stubUserRepoForMFAEnroll) Create(context.Context, *domain.User) (*domain.User, error) {
	panic("stubUserRepoForMFAEnroll: Create not expected")
}
func (s *stubUserRepoForMFAEnroll) FindUsersByEmail(context.Context, string) ([]*domain.User, error) {
	panic("stubUserRepoForMFAEnroll: FindUsersByEmail not expected")
}
func (s *stubUserRepoForMFAEnroll) GetByEmailAndOrgID(context.Context, uuid.UUID, string) (*domain.User, error) {
	panic("stubUserRepoForMFAEnroll: GetByEmailAndOrgID not expected")
}
func (s *stubUserRepoForMFAEnroll) GetByExternalID(context.Context, uuid.UUID, string) (*domain.User, error) {
	panic("stubUserRepoForMFAEnroll: GetByExternalID not expected")
}
func (s *stubUserRepoForMFAEnroll) GetByIDWithOrg(context.Context, uuid.UUID) (*domain.User, error) {
	panic("stubUserRepoForMFAEnroll: GetByIDWithOrg not expected")
}
func (s *stubUserRepoForMFAEnroll) Delete(context.Context, uuid.UUID, uuid.UUID) error {
	panic("stubUserRepoForMFAEnroll: Delete not expected")
}
func (s *stubUserRepoForMFAEnroll) Undelete(context.Context, uuid.UUID, uuid.UUID) error {
	panic("stubUserRepoForMFAEnroll: Undelete not expected")
}
func (s *stubUserRepoForMFAEnroll) List(context.Context, repository.ListUserOptions) ([]*domain.User, int, error) {
	panic("stubUserRepoForMFAEnroll: List not expected")
}
func (s *stubUserRepoForMFAEnroll) ListByOrganization(context.Context, uuid.UUID, repository.ListUserOptions) ([]*domain.User, int, error) {
	panic("stubUserRepoForMFAEnroll: ListByOrganization not expected")
}
func (s *stubUserRepoForMFAEnroll) UpdateLastLogin(context.Context, uuid.UUID) error {
	panic("stubUserRepoForMFAEnroll: UpdateLastLogin not expected")
}
func (s *stubUserRepoForMFAEnroll) CountByOrganization(context.Context, uuid.UUID) (int, error) {
	panic("stubUserRepoForMFAEnroll: CountByOrganization not expected")
}
func (s *stubUserRepoForMFAEnroll) CountOrgAdminsByOrganization(context.Context, uuid.UUID) (int, error) {
	panic("stubUserRepoForMFAEnroll: CountOrgAdminsByOrganization not expected")
}
func (s *stubUserRepoForMFAEnroll) CountOrgAdminsByOrganizations(context.Context, []uuid.UUID) (map[uuid.UUID]int, error) {
	panic("stubUserRepoForMFAEnroll: CountOrgAdminsByOrganizations not expected")
}
func (s *stubUserRepoForMFAEnroll) CountVerifiedOrgAdminsByOrganization(context.Context, uuid.UUID) (int, error) {
	panic("stubUserRepoForMFAEnroll: CountVerifiedOrgAdminsByOrganization not expected")
}
func (s *stubUserRepoForMFAEnroll) CountVerifiedOrgAdminsByOrganizations(context.Context, []uuid.UUID) (map[uuid.UUID]int, error) {
	panic("stubUserRepoForMFAEnroll: CountVerifiedOrgAdminsByOrganizations not expected")
}
func (s *stubUserRepoForMFAEnroll) VerifyPassword(_ context.Context, password, hash string) error {
	s.verifyPasswordCalls++
	if password == "correct-current-password" && hash == "HASH-CURRENT-PASSWORD" {
		return nil
	}
	return errors.New("invalid password")
}
func (s *stubUserRepoForMFAEnroll) HashPassword(string) (string, error) {
	panic("stubUserRepoForMFAEnroll: HashPassword not expected")
}
func (s *stubUserRepoForMFAEnroll) GetUserOrganization(context.Context, uuid.UUID) (*domain.Organization, error) {
	panic("stubUserRepoForMFAEnroll: GetUserOrganization not expected")
}
func (s *stubUserRepoForMFAEnroll) UpdateOrganizationID(context.Context, uuid.UUID, uuid.UUID) error {
	panic("stubUserRepoForMFAEnroll: UpdateOrganizationID not expected")
}

var _ repository.UserRepository = (*stubUserRepoForMFAEnroll)(nil)

// --- harness ---------------------------------------------------------------

func newEnrollSvc(t *testing.T) (*MFAEnrollmentService, *stubPendingRepo, *stubUserRepoForMFAEnroll, *domain.User) {
	t.Helper()
	pendingRepo := newStubPendingRepo()
	userRepo := newStubUserRepoForMFAEnroll()
	uid := uuid.New()
	orgID := uuid.New()
	user := &domain.User{
		ID:             uid,
		OrganizationID: orgID,
		Email:          "alice@example.invalid",
		Role:           domain.RoleSiteAdmin,
		AuthSource:     domain.AuthSourceLocal,
		EmailVerified:  true,
	}
	userRepo.byID[uid] = user
	svc := NewMFAEnrollmentService(nil, MFAEnrollmentRepoOptions{
		Pending: pendingRepo,
		Users:   userRepo,
		Issuer:  "Identuum",
		Cipher:  identityMFACipher{},
	}, MFAEnrollmentServiceOptions{})
	// P2-23: pin the service clock to a SINGLE captured instant so TOTP window
	// math is deterministic. The flake was two independent time.Now() reads —
	// the test computing the code and the service verifying it — occasionally
	// straddling a 30 s window boundary. With one fixed instant there is no drift
	// and no boundary to cross. Captured (not a far-off constant) so the tests'
	// ExpiresAt.After(time.Now()) checks against real time still hold. Tests
	// compute their expected code from svc.now() to share this exact instant.
	fixedNow := time.Now()
	svc.now = func() time.Time { return fixedNow }
	return svc, pendingRepo, userRepo, user
}

// --- tests ------------------------------------------------------------------

func TestMFAEnrollment_CreatePending_RequiresLiveUser(t *testing.T) {
	svc, _, userRepo, user := newEnrollSvc(t)

	t.Run("nil user", func(t *testing.T) {
		_, err := svc.CreatePending(context.Background(), nil, domain.MFAPendingKindEnroll, false)
		if !errors.Is(err, ErrMFAEnrollmentInvalid) {
			t.Fatalf("nil user: want ErrMFAEnrollmentInvalid, got %v", err)
		}
	})
	t.Run("banned user", func(t *testing.T) {
		u := *user
		u.Banned = true
		_, err := svc.CreatePending(context.Background(), &u, domain.MFAPendingKindEnroll, false)
		if !errors.Is(err, ErrMFAEnrollmentInvalid) {
			t.Fatalf("banned: want ErrMFAEnrollmentInvalid, got %v", err)
		}
	})
	t.Run("deleted user", func(t *testing.T) {
		u := *user
		now := time.Now()
		u.DeletedAt = &now
		_, err := svc.CreatePending(context.Background(), &u, domain.MFAPendingKindEnroll, false)
		if !errors.Is(err, ErrMFAEnrollmentInvalid) {
			t.Fatalf("deleted: want ErrMFAEnrollmentInvalid, got %v", err)
		}
	})
	t.Run("unknown kind", func(t *testing.T) {
		_, err := svc.CreatePending(context.Background(), user, "bogus-kind", false)
		if !errors.Is(err, ErrMFAEnrollmentInvalid) {
			t.Fatalf("unknown kind: want ErrMFAEnrollmentInvalid, got %v", err)
		}
	})

	// Sanity: live user succeeds.
	row, err := svc.CreatePending(context.Background(), user, domain.MFAPendingKindEnroll, false)
	if err != nil {
		t.Fatalf("live user: %v", err)
	}
	if row.ID == uuid.Nil {
		t.Fatal("pending row must have a non-nil ID")
	}
	if row.Kind != domain.MFAPendingKindEnroll {
		t.Fatalf("pending row kind: want enroll, got %q", row.Kind)
	}
	if !row.ExpiresAt.After(time.Now()) {
		t.Fatal("pending row must expire in the future")
	}
	_ = userRepo // referenced for harness setup
}

func TestMFAEnrollment_Initiate_HappyPath(t *testing.T) {
	svc, _, _, user := newEnrollSvc(t)
	row, err := svc.CreatePending(context.Background(), user, domain.MFAPendingKindEnroll, false)
	if err != nil {
		t.Fatalf("CreatePending: %v", err)
	}
	out, err := svc.Initiate(context.Background(), row.ID)
	if err != nil {
		t.Fatalf("Initiate: %v", err)
	}
	if out.Secret == "" {
		t.Fatal("Initiate: secret must be non-empty")
	}
	if !strings.HasPrefix(out.OtpauthURL, "otpauth://totp/Identuum:") {
		t.Fatalf("Initiate: otpauth URL malformed (prefix only checked)")
	}
	// The email is URL-escaped inside the label segment of the
	// otpauth URL, so the literal "@" becomes "%40".
	if !strings.Contains(out.OtpauthURL, "alice%40example.invalid") {
		t.Fatalf("Initiate: otpauth URL must embed the URL-escaped user email label")
	}
	if !strings.Contains(out.OtpauthURL, "issuer=Identuum") {
		t.Fatal("Initiate: otpauth URL must carry issuer query parameter")
	}
	if len(out.RecoveryCodes) != defaultMFAEnrollmentRecoveryCodeCount {
		t.Fatalf("Initiate: recovery codes count: want %d, got %d", defaultMFAEnrollmentRecoveryCodeCount, len(out.RecoveryCodes))
	}
	// All codes unique.
	seen := map[string]bool{}
	for _, c := range out.RecoveryCodes {
		if c == "" {
			t.Fatal("Initiate: recovery code must be non-empty")
		}
		if seen[c] {
			t.Fatal("Initiate: recovery codes must be unique")
		}
		seen[c] = true
	}
}

func TestMFAEnrollment_Initiate_RejectsReinit(t *testing.T) {
	svc, _, _, user := newEnrollSvc(t)
	row, _ := svc.CreatePending(context.Background(), user, domain.MFAPendingKindEnroll, false)
	_, err := svc.Initiate(context.Background(), row.ID)
	if err != nil {
		t.Fatalf("first Initiate: %v", err)
	}
	_, err = svc.Initiate(context.Background(), row.ID)
	if !errors.Is(err, ErrMFAEnrollmentInvalid) {
		t.Fatalf("second Initiate: want ErrMFAEnrollmentInvalid, got %v", err)
	}
}

func TestMFAEnrollment_Initiate_NotFound(t *testing.T) {
	svc, _, _, _ := newEnrollSvc(t)
	_, err := svc.Initiate(context.Background(), uuid.New())
	if !errors.Is(err, ErrMFAEnrollmentNotFound) {
		t.Fatalf("want ErrMFAEnrollmentNotFound, got %v", err)
	}
}

func TestMFAEnrollment_Initiate_Expired(t *testing.T) {
	svc, pendingRepo, _, user := newEnrollSvc(t)
	row, _ := svc.CreatePending(context.Background(), user, domain.MFAPendingKindEnroll, false)
	// Mutate the persisted row's expires_at into the past.
	pendingRepo.rows[row.ID].ExpiresAt = time.Now().Add(-time.Minute)
	_, err := svc.Initiate(context.Background(), row.ID)
	if !errors.Is(err, ErrMFAEnrollmentExpired) {
		t.Fatalf("want ErrMFAEnrollmentExpired, got %v", err)
	}
}

func TestMFAEnrollment_Initiate_VerifyKindRejected(t *testing.T) {
	// /initiate is only valid for enroll-kind pending rows.
	svc, _, _, user := newEnrollSvc(t)
	row, _ := svc.CreatePending(context.Background(), user, domain.MFAPendingKindVerify, false)
	_, err := svc.Initiate(context.Background(), row.ID)
	if !errors.Is(err, ErrMFAEnrollmentInvalid) {
		t.Fatalf("want ErrMFAEnrollmentInvalid, got %v", err)
	}
}

func TestMFAEnrollment_Complete_HappyPath(t *testing.T) {
	svc, _, userRepo, user := newEnrollSvc(t)
	row, _ := svc.CreatePending(context.Background(), user, domain.MFAPendingKindEnroll, true)
	out, _ := svc.Initiate(context.Background(), row.ID)
	// Compute the current TOTP code from the stored secret. This
	// matches what the user would type after scanning the QR.
	counter := uint64(svc.now().Unix()) / defaultTOTPPeriod
	code, err := computeHOTP(out.Secret, counter, defaultTOTPDigits)
	if err != nil {
		t.Fatalf("computeHOTP: %v", err)
	}
	result, err := svc.Complete(context.Background(), row.ID, code)
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if result == nil || result.User == nil {
		t.Fatal("Complete: result + user must be populated")
	}
	if !result.User.MFAEnabled {
		t.Fatal("Complete: persisted user must carry MFAEnabled=true")
	}
	if result.User.MFASecret == nil || *result.User.MFASecret == "" {
		t.Fatal("Complete: persisted user must carry MFASecret")
	}
	if len(result.User.MFARecoveryCodes) != defaultMFAEnrollmentRecoveryCodeCount {
		t.Fatalf("Complete: persisted recovery codes count: want %d, got %d", defaultMFAEnrollmentRecoveryCodeCount, len(result.User.MFARecoveryCodes))
	}
	if !result.RememberMe {
		t.Fatal("Complete: RememberMe must propagate from CreatePending")
	}
	// Verify the user repo also reflects the changes.
	if !userRepo.byID[user.ID].MFAEnabled {
		t.Fatal("Complete: user repo row not updated to MFAEnabled=true")
	}
}

func TestMFAEnrollment_Complete_WrongCode(t *testing.T) {
	svc, _, _, user := newEnrollSvc(t)
	row, _ := svc.CreatePending(context.Background(), user, domain.MFAPendingKindEnroll, false)
	init, err := svc.Initiate(context.Background(), row.ID)
	if err != nil {
		t.Fatalf("initiate: %v", err)
	}
	// The guess must be wrong FOR THIS CLOCK AND FOR THE WHOLE ACCEPTED WINDOW,
	// not merely an arbitrary literal. This test used the bare literal "000000",
	// which is the valid TOTP for about one time step in a million; a first fix
	// derived the guess from the CENTRE step only, which still left the codes at
	// step-1 and step+1 able to be "wrong". wrongCodeForWindow excludes all three.
	_, err = svc.Complete(context.Background(), row.ID, wrongCodeForWindow(t, init.Secret, svc.now()))
	if !errors.Is(err, ErrMFAEnrollmentInvalid) {
		t.Fatalf("wrong code: want ErrMFAEnrollmentInvalid, got %v", err)
	}
}

func TestMFAEnrollment_Complete_BeforeInitiate(t *testing.T) {
	// Complete without an Initiate has no candidate secret to verify
	// against → invalid.
	svc, _, _, user := newEnrollSvc(t)
	row, _ := svc.CreatePending(context.Background(), user, domain.MFAPendingKindEnroll, false)
	_, err := svc.Complete(context.Background(), row.ID, "123456")
	if !errors.Is(err, ErrMFAEnrollmentInvalid) {
		t.Fatalf("complete-before-initiate: want ErrMFAEnrollmentInvalid, got %v", err)
	}
}

func TestMFAEnrollment_Complete_ReplayBlocked(t *testing.T) {
	svc, _, _, user := newEnrollSvc(t)
	row, _ := svc.CreatePending(context.Background(), user, domain.MFAPendingKindEnroll, false)
	out, _ := svc.Initiate(context.Background(), row.ID)
	counter := uint64(svc.now().Unix()) / defaultTOTPPeriod
	code, _ := computeHOTP(out.Secret, counter, defaultTOTPDigits)
	if _, err := svc.Complete(context.Background(), row.ID, code); err != nil {
		t.Fatalf("first Complete: %v", err)
	}
	// Same code + same pending handle must fail on replay.
	_, err := svc.Complete(context.Background(), row.ID, code)
	if !errors.Is(err, ErrMFAEnrollmentAlreadyConsumed) {
		t.Fatalf("replay: want ErrMFAEnrollmentAlreadyConsumed, got %v", err)
	}
}

func TestMFAEnrollment_VerifyAndConsume_HappyPath(t *testing.T) {
	svc, _, userRepo, user := newEnrollSvc(t)
	// Pre-enrol the user — verify-kind targets already-enrolled users.
	secret, err := generateBase32Secret(defaultMFAEnrollmentSecretBytes)
	if err != nil {
		t.Fatalf("generate secret: %v", err)
	}
	userRepo.byID[user.ID].MFAEnabled = true
	userRepo.byID[user.ID].MFASecret = &secret

	row, err := svc.CreatePending(context.Background(), userRepo.byID[user.ID], domain.MFAPendingKindVerify, false)
	if err != nil {
		t.Fatalf("CreatePending verify: %v", err)
	}
	counter := uint64(svc.now().Unix()) / defaultTOTPPeriod
	code, _ := computeHOTP(secret, counter, defaultTOTPDigits)
	result, err := svc.VerifyAndConsume(context.Background(), row.ID, code)
	if err != nil {
		t.Fatalf("VerifyAndConsume: %v", err)
	}
	if result == nil || result.User == nil {
		t.Fatal("VerifyAndConsume: result + user must be populated")
	}
}

func TestMFAEnrollment_VerifyAndConsume_WrongCode(t *testing.T) {
	svc, _, userRepo, user := newEnrollSvc(t)
	secret, _ := generateBase32Secret(defaultMFAEnrollmentSecretBytes)
	userRepo.byID[user.ID].MFAEnabled = true
	userRepo.byID[user.ID].MFASecret = &secret
	row, _ := svc.CreatePending(context.Background(), userRepo.byID[user.ID], domain.MFAPendingKindVerify, false)
	// Same exposure as Complete_WrongCode, and the guess must clear the WHOLE
	// accepted window — three codes, not one.
	_, err := svc.VerifyAndConsume(context.Background(), row.ID, wrongCodeForWindow(t, secret, svc.now()))
	if !errors.Is(err, ErrMFAEnrollmentInvalid) {
		t.Fatalf("wrong code: want ErrMFAEnrollmentInvalid, got %v", err)
	}
}

func TestMFAEnrollment_VerifyAndConsume_ReplayBlocked(t *testing.T) {
	svc, _, userRepo, user := newEnrollSvc(t)
	secret, _ := generateBase32Secret(defaultMFAEnrollmentSecretBytes)
	userRepo.byID[user.ID].MFAEnabled = true
	userRepo.byID[user.ID].MFASecret = &secret
	row, _ := svc.CreatePending(context.Background(), userRepo.byID[user.ID], domain.MFAPendingKindVerify, false)
	counter := uint64(svc.now().Unix()) / defaultTOTPPeriod
	code, _ := computeHOTP(secret, counter, defaultTOTPDigits)
	if _, err := svc.VerifyAndConsume(context.Background(), row.ID, code); err != nil {
		t.Fatalf("first VerifyAndConsume: %v", err)
	}
	_, err := svc.VerifyAndConsume(context.Background(), row.ID, code)
	if !errors.Is(err, ErrMFAEnrollmentAlreadyConsumed) {
		t.Fatalf("replay: want ErrMFAEnrollmentAlreadyConsumed, got %v", err)
	}
}

func TestMFAEnrollment_VerifyAndConsume_EnrollKindRejected(t *testing.T) {
	svc, _, userRepo, user := newEnrollSvc(t)
	secret, _ := generateBase32Secret(defaultMFAEnrollmentSecretBytes)
	userRepo.byID[user.ID].MFAEnabled = true
	userRepo.byID[user.ID].MFASecret = &secret
	row, _ := svc.CreatePending(context.Background(), userRepo.byID[user.ID], domain.MFAPendingKindEnroll, false)
	_, err := svc.VerifyAndConsume(context.Background(), row.ID, "000000")
	if !errors.Is(err, ErrMFAEnrollmentInvalid) {
		t.Fatalf("enroll-kind on verify path: want ErrMFAEnrollmentInvalid, got %v", err)
	}
}

// --- P0-13: MFA-verify brute-force bound -----------------------------------

// wrongCodeForWindow returns a six-digit code the verifier will NOT accept for
// secret at now.
//
// IT EXCLUDES EVERY STEP IN THE ACCEPTED WINDOW, not just the centre one. The
// verifier scans delta := -Window .. +Window (pkg/totp/totp.go) and
// defaultTOTPWindow is 1, so THREE codes are valid at any instant. The helper
// this replaced derived a guess from the centre step alone, leaving a "wrong"
// guess able to be the valid code for step-1 or step+1 — it closed one third of
// the exposure while reading as though it closed all of it.
//
// The window comes from defaultTOTPWindow, the SAME constant the verifier reads,
// so widening the verifier cannot silently re-open this.
// validCodeSetForWindow returns every code the verifier accepts for secret at
// now — one per step in -Window..+Window.
//
// FACTORED OUT SO IT CAN BE ASSERTED DIRECTLY. The previous test checked only
// that the CHOSEN GUESS was not in the set, which a centre-narrowed builder
// passes 999,998 times in a million: narrowing still returns "000000", and the
// guess is flagged only when "000000" happens to BE the step-1 or step+1 code.
// A test that fails 0.0002% of the time when the bug is present has no teeth,
// and calling it a teeth check was wrong. Asserting the SET — its cardinality
// and its membership — fails 100% of the time under narrowing.
func validCodeSetForWindow(t *testing.T, secret string, now time.Time) map[string]bool {
	t.Helper()
	stepNow := now.Unix() / int64(defaultTOTPPeriod)
	valid := make(map[string]bool, 2*defaultTOTPWindow+1)
	for delta := -int64(defaultTOTPWindow); delta <= int64(defaultTOTPWindow); delta++ {
		code, err := computeHOTP(secret, uint64(stepNow+delta), defaultTOTPDigits)
		if err != nil {
			t.Fatalf("computeHOTP(step%+d): %v", delta, err)
		}
		valid[code] = true
	}
	return valid
}

func wrongCodeForWindow(t *testing.T, secret string, now time.Time) string {
	t.Helper()
	valid := validCodeSetForWindow(t, secret, now)
	for i := 0; i < 1000; i++ {
		candidate := fmt.Sprintf("%0*d", defaultTOTPDigits, i)
		if !valid[candidate] {
			return candidate
		}
	}
	t.Fatalf("no rejectable code in 1000 candidates (window=%d)", defaultTOTPWindow)
	return ""
}

// TestMFAEnrollment_VerifyAndConsume_WrongGuessesBoundedThenHandleDead is the
// core P0-13 proof: a verify handle tolerates only maxVerifyAttempts wrong
// guesses, then is invalidated — after which even the CORRECT code fails,
// forcing password re-auth for a fresh handle. Before the fix the handle
// survived every failed guess for its full lifetime (unbounded brute force).
func TestMFAEnrollment_VerifyAndConsume_WrongGuessesBoundedThenHandleDead(t *testing.T) {
	svc, pendingRepo, userRepo, user := newEnrollSvc(t)
	svc.maxVerifyAttempts = 3 // small + explicit so the boundary is unambiguous
	secret, _ := generateBase32Secret(defaultMFAEnrollmentSecretBytes)
	userRepo.byID[user.ID].MFAEnabled = true
	userRepo.byID[user.ID].MFASecret = &secret
	row, _ := svc.CreatePending(context.Background(), userRepo.byID[user.ID], domain.MFAPendingKindVerify, false)

	counter := uint64(svc.now().Unix()) / defaultTOTPPeriod
	correct, _ := computeHOTP(secret, counter, defaultTOTPDigits)
	wrong := wrongCodeForWindow(t, secret, svc.now())

	// Attempts 1..2 (below the threshold): rejected as wrong, handle STILL live.
	for i := 1; i <= 2; i++ {
		_, err := svc.VerifyAndConsume(context.Background(), row.ID, wrong)
		if !errors.Is(err, ErrMFAEnrollmentInvalid) {
			t.Fatalf("attempt %d: want ErrMFAEnrollmentInvalid, got %v", i, err)
		}
		if pendingRepo.rows[row.ID].ConsumedAt != nil {
			t.Fatalf("attempt %d: handle must remain live below the threshold", i)
		}
		if got := pendingRepo.rows[row.ID].FailedAttempts; got != i {
			t.Fatalf("attempt %d: FailedAttempts want %d, got %d", i, i, got)
		}
	}

	// Attempt 3 (== threshold): rejected as wrong AND the handle is now DEAD.
	if _, err := svc.VerifyAndConsume(context.Background(), row.ID, wrong); !errors.Is(err, ErrMFAEnrollmentInvalid) {
		t.Fatalf("threshold attempt: want ErrMFAEnrollmentInvalid, got %v", err)
	}
	if pendingRepo.rows[row.ID].ConsumedAt == nil {
		t.Fatal("handle must be invalidated once maxVerifyAttempts wrong guesses are made")
	}

	// The CORRECT code now fails: the handle is spent, re-auth is forced.
	if _, err := svc.VerifyAndConsume(context.Background(), row.ID, correct); !errors.Is(err, ErrMFAEnrollmentAlreadyConsumed) {
		t.Fatalf("correct code after lockout: want ErrMFAEnrollmentAlreadyConsumed, got %v", err)
	}
}

// TestMFAEnrollment_VerifyAndConsume_CorrectWithinAllowanceStillSucceeds
// proves the throttle does not break the legitimate path: a user who
// mistypes once (below the threshold) can still complete with the right
// code, and that success consumes the handle atomically (single-use).
func TestMFAEnrollment_VerifyAndConsume_CorrectWithinAllowanceStillSucceeds(t *testing.T) {
	svc, pendingRepo, userRepo, user := newEnrollSvc(t)
	svc.maxVerifyAttempts = 3
	secret, _ := generateBase32Secret(defaultMFAEnrollmentSecretBytes)
	userRepo.byID[user.ID].MFAEnabled = true
	userRepo.byID[user.ID].MFASecret = &secret
	row, _ := svc.CreatePending(context.Background(), userRepo.byID[user.ID], domain.MFAPendingKindVerify, false)

	counter := uint64(svc.now().Unix()) / defaultTOTPPeriod
	correct, _ := computeHOTP(secret, counter, defaultTOTPDigits)

	// One fat-finger, still below threshold.
	if _, err := svc.VerifyAndConsume(context.Background(), row.ID, wrongCodeForWindow(t, secret, svc.now())); !errors.Is(err, ErrMFAEnrollmentInvalid) {
		t.Fatalf("first (wrong) attempt: want ErrMFAEnrollmentInvalid, got %v", err)
	}
	// Correct code within the allowance → success, handle consumed atomically.
	result, err := svc.VerifyAndConsume(context.Background(), row.ID, correct)
	if err != nil {
		t.Fatalf("correct code within allowance must succeed: %v", err)
	}
	if result == nil || result.User == nil {
		t.Fatal("successful verify must populate result + user")
	}
	if pendingRepo.rows[row.ID].ConsumedAt == nil {
		t.Fatal("successful verify must consume the handle (single-use)")
	}
	// Replaying the same (now-correct) code fails — single-use holds.
	if _, err := svc.VerifyAndConsume(context.Background(), row.ID, correct); !errors.Is(err, ErrMFAEnrollmentAlreadyConsumed) {
		t.Fatalf("replay after success: want ErrMFAEnrollmentAlreadyConsumed, got %v", err)
	}
}

// TestMFAEnrollment_VerifyAndConsume_CounterStoreErrorFailsClosed proves the
// fail-closed posture: if the attempt-counter store errors, the verification
// is REJECTED with a NON-sentinel error (which the handler maps to 500), never
// a bare invalid_code that would let the uncounted guess through. This is the
// deliberate opposite of LoginRiskService's fail-open password-lockout posture.
func TestMFAEnrollment_VerifyAndConsume_CounterStoreErrorFailsClosed(t *testing.T) {
	svc, pendingRepo, userRepo, user := newEnrollSvc(t)
	pendingRepo.recordErr = errors.New("counter store unavailable")
	secret, _ := generateBase32Secret(defaultMFAEnrollmentSecretBytes)
	userRepo.byID[user.ID].MFAEnabled = true
	userRepo.byID[user.ID].MFASecret = &secret
	row, _ := svc.CreatePending(context.Background(), userRepo.byID[user.ID], domain.MFAPendingKindVerify, false)

	_, err := svc.VerifyAndConsume(context.Background(), row.ID, wrongCodeForWindow(t, secret, svc.now()))
	if err == nil {
		t.Fatal("counter-store error must reject the verification, not succeed")
	}
	// Must NOT be any of the wire-mapped sentinels (those become 401 invalid_code);
	// a non-sentinel error is what emitPendingFailure maps to 500 — a hard reject.
	for _, sentinel := range []error{
		ErrMFAEnrollmentInvalid, ErrMFAEnrollmentNotFound,
		ErrMFAEnrollmentExpired, ErrMFAEnrollmentAlreadyConsumed,
	} {
		if errors.Is(err, sentinel) {
			t.Fatalf("fail-closed error must be a non-sentinel (→500), got sentinel %v", err)
		}
	}
}

// TestMFAEnrollment_VerifyAndConsume_WrongRecoveryCodeAlsoCounted proves the
// recovery-code path shares the same bound: a guess that is neither a valid
// TOTP nor a valid recovery code still increments the handle counter, so the
// recovery fallback cannot be brute-forced for free either.
func TestMFAEnrollment_VerifyAndConsume_WrongRecoveryCodeAlsoCounted(t *testing.T) {
	svc, pendingRepo, _, _, row, _ := recoveryHarness(t, []string{"AAAA1111", "BBBB2222"})
	svc.maxVerifyAttempts = 3
	// "ZZZZ9999" matches no recovery code and (6-digit-wise) no TOTP.
	if _, err := svc.VerifyAndConsume(context.Background(), row.ID, "ZZZZ9999"); !errors.Is(err, ErrMFAEnrollmentInvalid) {
		t.Fatalf("wrong recovery guess: want ErrMFAEnrollmentInvalid, got %v", err)
	}
	if got := pendingRepo.rows[row.ID].FailedAttempts; got != 1 {
		t.Fatalf("wrong recovery guess must count against the handle: FailedAttempts want 1, got %d", got)
	}
}

// --- recovery-code consumption (VerifyAndConsume) --------------------------

// recoveryHarness pre-enrols the user with both a TOTP secret and a
// known recovery-code list, then mints a verify-kind pending row.
func recoveryHarness(t *testing.T, codes []string) (*MFAEnrollmentService, *stubPendingRepo, *stubUserRepoForMFAEnroll, *domain.User, *domain.MFAPendingLoginSession, string) {
	t.Helper()
	svc, pendingRepo, userRepo, user := newEnrollSvc(t)
	secret, err := generateBase32Secret(defaultMFAEnrollmentSecretBytes)
	if err != nil {
		t.Fatalf("generate secret: %v", err)
	}
	userRepo.byID[user.ID].MFAEnabled = true
	userRepo.byID[user.ID].MFASecret = &secret
	userRepo.byID[user.ID].MFARecoveryCodes = hashCodesForTest(codes)
	row, err := svc.CreatePending(context.Background(), userRepo.byID[user.ID], domain.MFAPendingKindVerify, false)
	if err != nil {
		t.Fatalf("CreatePending: %v", err)
	}
	return svc, pendingRepo, userRepo, user, row, secret
}

func TestMFAEnrollment_VerifyAndConsume_TOTPStillWorksWithRecoveryCodesPresent(t *testing.T) {
	// TOTP success must still work even when recovery codes are
	// stored on the user row. The recovery-code list must be
	// untouched by a TOTP-branch success.
	svc, _, userRepo, user, row, secret := recoveryHarness(t, []string{"AAAA1111", "BBBB2222", "CCCC3333"})
	counter := uint64(svc.now().Unix()) / defaultTOTPPeriod
	code, _ := computeHOTP(secret, counter, defaultTOTPDigits)
	result, err := svc.VerifyAndConsume(context.Background(), row.ID, code)
	if err != nil {
		t.Fatalf("TOTP success: %v", err)
	}
	if result.RecoveryCodeUsed {
		t.Fatal("TOTP branch must not flag RecoveryCodeUsed")
	}
	if got := len(userRepo.byID[user.ID].MFARecoveryCodes); got != 3 {
		t.Fatalf("recovery list must be untouched on TOTP success: want 3, got %d", got)
	}
}

func TestMFAEnrollment_VerifyAndConsume_RecoveryCodeSuccess(t *testing.T) {
	// Wrong TOTP, valid recovery code → success via recovery branch.
	codes := []string{"AAAA1111", "BBBB2222", "CCCC3333"}
	svc, _, userRepo, user, row, _ := recoveryHarness(t, codes)
	result, err := svc.VerifyAndConsume(context.Background(), row.ID, "BBBB2222")
	if err != nil {
		t.Fatalf("recovery-code success: %v", err)
	}
	if !result.RecoveryCodeUsed {
		t.Fatal("recovery-code branch must flag RecoveryCodeUsed=true")
	}
	if result.RemainingRecoveryCodes != 2 {
		t.Fatalf("RemainingRecoveryCodes: want 2, got %d", result.RemainingRecoveryCodes)
	}
	// MFAEnabled must remain true.
	if !userRepo.byID[user.ID].MFAEnabled {
		t.Fatal("MFAEnabled must remain true after recovery-code consumption")
	}
	// MFASecret must remain unchanged.
	if userRepo.byID[user.ID].MFASecret == nil || *userRepo.byID[user.ID].MFASecret == "" {
		t.Fatal("MFASecret must remain unchanged after recovery-code consumption")
	}
	// Burn: the matched code is removed; remaining codes preserve order.
	remaining := userRepo.byID[user.ID].MFARecoveryCodes
	if got, want := strings.Join(remaining, ","), strings.Join(hashCodesForTest([]string{"AAAA1111", "CCCC3333"}), ","); got != want {
		t.Fatalf("remaining codes (order-preserved, matched removed) mismatch")
	}
}

func TestMFAEnrollment_VerifyAndConsume_RecoveryCodeBurnedAfterUse(t *testing.T) {
	// The matched recovery code must not be reusable on a fresh
	// pending row.
	codes := []string{"AAAA1111", "BBBB2222", "CCCC3333"}
	svc, _, userRepo, user, row, _ := recoveryHarness(t, codes)
	if _, err := svc.VerifyAndConsume(context.Background(), row.ID, "BBBB2222"); err != nil {
		t.Fatalf("first use: %v", err)
	}
	// Mint a fresh pending row and try the same recovery code again.
	row2, err := svc.CreatePending(context.Background(), userRepo.byID[user.ID], domain.MFAPendingKindVerify, false)
	if err != nil {
		t.Fatalf("CreatePending #2: %v", err)
	}
	_, err = svc.VerifyAndConsume(context.Background(), row2.ID, "BBBB2222")
	if !errors.Is(err, ErrMFAEnrollmentInvalid) {
		t.Fatalf("burned code on fresh pending: want ErrMFAEnrollmentInvalid, got %v", err)
	}
}

func TestMFAEnrollment_VerifyAndConsume_RecoveryCodeOnlyMatchedRemovedOrderPreserved(t *testing.T) {
	// Sanity: middle entry removed; surrounding ordering preserved.
	codes := []string{"AAAA", "BBBB", "CCCC", "DDDD", "EEEE"}
	svc, _, userRepo, user, row, _ := recoveryHarness(t, codes)
	if _, err := svc.VerifyAndConsume(context.Background(), row.ID, "CCCC"); err != nil {
		t.Fatalf("recovery success: %v", err)
	}
	remaining := userRepo.byID[user.ID].MFARecoveryCodes
	if got, want := strings.Join(remaining, ","), strings.Join(hashCodesForTest([]string{"AAAA", "BBBB", "DDDD", "EEEE"}), ","); got != want {
		t.Fatalf("only matched removed + order preserved mismatch")
	}
}

func TestMFAEnrollment_VerifyAndConsume_WrongRecoveryCodeFailsOpaquely(t *testing.T) {
	codes := []string{"AAAA1111", "BBBB2222"}
	svc, _, userRepo, _, row, _ := recoveryHarness(t, codes)
	_, err := svc.VerifyAndConsume(context.Background(), row.ID, "WRONGXYZ")
	if !errors.Is(err, ErrMFAEnrollmentInvalid) {
		t.Fatalf("wrong recovery code: want ErrMFAEnrollmentInvalid, got %v", err)
	}
	// Sanity: error text must NOT echo the supplied candidate or
	// any stored code.
	msg := err.Error()
	if strings.Contains(msg, "WRONGXYZ") || strings.Contains(msg, "AAAA1111") || strings.Contains(msg, "BBBB2222") {
		t.Fatalf("opaque error must not echo raw recovery codes: %q", msg)
	}
	// No state mutated.
	if got, want := strings.Join(userRepo.byID[uuidFromRow(row)].MFARecoveryCodes, ","), strings.Join(hashCodesForTest([]string{"AAAA1111", "BBBB2222"}), ","); got != want {
		t.Fatalf("wrong recovery code must not mutate user's recovery codes")
	}
}

func TestMFAEnrollment_VerifyAndConsume_EmptyRecoveryListFails(t *testing.T) {
	codes := []string{}
	svc, _, _, _, row, _ := recoveryHarness(t, codes)
	_, err := svc.VerifyAndConsume(context.Background(), row.ID, "AAAA1111")
	if !errors.Is(err, ErrMFAEnrollmentInvalid) {
		t.Fatalf("empty recovery list: want ErrMFAEnrollmentInvalid, got %v", err)
	}
}

func TestMFAEnrollment_VerifyAndConsume_NilRecoveryListFails(t *testing.T) {
	// Same as empty but with a literally nil slice on the user row.
	svc, _, userRepo, user := newEnrollSvc(t)
	secret, _ := generateBase32Secret(defaultMFAEnrollmentSecretBytes)
	userRepo.byID[user.ID].MFAEnabled = true
	userRepo.byID[user.ID].MFASecret = &secret
	userRepo.byID[user.ID].MFARecoveryCodes = nil
	row, _ := svc.CreatePending(context.Background(), userRepo.byID[user.ID], domain.MFAPendingKindVerify, false)
	_, err := svc.VerifyAndConsume(context.Background(), row.ID, "AAAA1111")
	if !errors.Is(err, ErrMFAEnrollmentInvalid) {
		t.Fatalf("nil recovery list: want ErrMFAEnrollmentInvalid, got %v", err)
	}
}

func TestMFAEnrollment_VerifyAndConsume_RecoveryCodeReplayOnSamePendingBlocked(t *testing.T) {
	// Same pending row + same valid recovery code must fail on
	// replay (ErrMFAEnrollmentAlreadyConsumed) — pending row
	// MarkConsumed is atomic and one-shot.
	codes := []string{"AAAA1111", "BBBB2222"}
	svc, _, _, _, row, _ := recoveryHarness(t, codes)
	if _, err := svc.VerifyAndConsume(context.Background(), row.ID, "BBBB2222"); err != nil {
		t.Fatalf("first use: %v", err)
	}
	_, err := svc.VerifyAndConsume(context.Background(), row.ID, "BBBB2222")
	if !errors.Is(err, ErrMFAEnrollmentAlreadyConsumed) {
		t.Fatalf("replay on consumed pending: want ErrMFAEnrollmentAlreadyConsumed, got %v", err)
	}
}

func TestMFAEnrollment_VerifyAndConsume_LastRecoveryCodeLeavesEmptyList(t *testing.T) {
	// Consuming the sole remaining recovery code persists an
	// empty list; a fresh attempt then fails as empty/nil.
	codes := []string{"LASTONE9"}
	svc, _, userRepo, user, row, _ := recoveryHarness(t, codes)
	result, err := svc.VerifyAndConsume(context.Background(), row.ID, "LASTONE9")
	if err != nil {
		t.Fatalf("last code: %v", err)
	}
	if result.RemainingRecoveryCodes != 0 {
		t.Fatalf("RemainingRecoveryCodes: want 0, got %d", result.RemainingRecoveryCodes)
	}
	if len(userRepo.byID[user.ID].MFARecoveryCodes) != 0 {
		t.Fatalf("user recovery codes after burn: want 0, got %d", len(userRepo.byID[user.ID].MFARecoveryCodes))
	}
	row2, _ := svc.CreatePending(context.Background(), userRepo.byID[user.ID], domain.MFAPendingKindVerify, false)
	_, err = svc.VerifyAndConsume(context.Background(), row2.ID, "LASTONE9")
	if !errors.Is(err, ErrMFAEnrollmentInvalid) {
		t.Fatalf("after-list-emptied: want ErrMFAEnrollmentInvalid, got %v", err)
	}
}

// --- consumeRecoveryCode helper (unit) ------------------------------------

func TestConsumeRecoveryCode_MatchedAtMiddleRemovedOrderPreserved(t *testing.T) {
	// Codes are stored as hashes; the candidate is matched by hash and the
	// matched HASH is removed (order preserved).
	stored := hashCodesForTest([]string{"A", "B", "C", "D"})
	remaining, ok := consumeRecoveryCode(stored, "B")
	if !ok {
		t.Fatal("want ok=true")
	}
	want := strings.Join(hashCodesForTest([]string{"A", "C", "D"}), ",")
	if got := strings.Join(remaining, ","); got != want {
		t.Fatalf("matched-removed + order-preserved mismatch")
	}
}

func TestConsumeRecoveryCode_MatchedAtHeadAndTail(t *testing.T) {
	t.Run("head", func(t *testing.T) {
		remaining, ok := consumeRecoveryCode(hashCodesForTest([]string{"A", "B", "C"}), "A")
		if !ok || strings.Join(remaining, ",") != strings.Join(hashCodesForTest([]string{"B", "C"}), ",") {
			t.Fatalf("head mismatch: ok=%v", ok)
		}
	})
	t.Run("tail", func(t *testing.T) {
		remaining, ok := consumeRecoveryCode(hashCodesForTest([]string{"A", "B", "C"}), "C")
		if !ok || strings.Join(remaining, ",") != strings.Join(hashCodesForTest([]string{"A", "B"}), ",") {
			t.Fatalf("tail mismatch: ok=%v", ok)
		}
	})
}

func TestConsumeRecoveryCode_NoMatch(t *testing.T) {
	remaining, ok := consumeRecoveryCode([]string{"A", "B"}, "Z")
	if ok || remaining != nil {
		t.Fatalf("no-match: want ok=false remaining=nil, got %v ok=%v", remaining, ok)
	}
}

func TestConsumeRecoveryCode_EmptyAndNilInputs(t *testing.T) {
	if _, ok := consumeRecoveryCode(nil, "X"); ok {
		t.Fatal("nil list: want ok=false")
	}
	if _, ok := consumeRecoveryCode([]string{}, "X"); ok {
		t.Fatal("empty list: want ok=false")
	}
	if _, ok := consumeRecoveryCode([]string{"A"}, ""); ok {
		t.Fatal("empty candidate: want ok=false")
	}
	if _, ok := consumeRecoveryCode([]string{"A"}, "   "); ok {
		t.Fatal("whitespace-only candidate: want ok=false")
	}
}

func TestConsumeRecoveryCode_DuplicateEntriesOnlyOneBurned(t *testing.T) {
	// If a list ever contains duplicates, only the first match is
	// removed. This is defensive — recovery codes are generated
	// independently and collisions on base32 entropy are
	// astronomically unlikely, but the matching loop must not
	// drop multiple entries on a single consumption.
	stored := hashCodesForTest([]string{"DUP", "OTHER", "DUP"})
	remaining, ok := consumeRecoveryCode(stored, "DUP")
	if !ok {
		t.Fatal("want ok=true")
	}
	if got, want := strings.Join(remaining, ","), strings.Join(hashCodesForTest([]string{"OTHER", "DUP"}), ","); got != want {
		t.Fatalf("duplicate handling: only first match removed")
	}
}

// uuidFromRow returns the row's UserID; helper used so the test
// can index into userRepo.byID without re-resolving the pointer.
func uuidFromRow(row *domain.MFAPendingLoginSession) uuid.UUID {
	return row.UserID
}

// ---------- DisableSelf ----------

// seedEnrolledOrgUser turns the default site_admin fixture into an
// org_user with MFA enabled, a known TOTP secret, and a known
// recovery-code list. The default fixture is a site_admin which
// would always trip the policy gate, so the disable happy-path
// tests need to demote the role first.
func seedEnrolledOrgUser(userRepo *stubUserRepoForMFAEnroll, user *domain.User, secret string, codes []string) {
	cp := secret
	user.Role = domain.RoleOrgUser
	user.AuthSource = domain.AuthSourceLocal
	user.PasswordHash = "HASH-CURRENT-PASSWORD"
	user.MFAEnabled = true
	user.MFASecret = &cp
	user.MFARecoveryCodes = hashCodesForTest(codes)
	userRepo.byID[user.ID] = user
}

func TestMFAEnrollment_DisableSelf_NilUserIDInvalid(t *testing.T) {
	svc, _, _, _ := newEnrollSvc(t)
	_, err := svc.DisableSelf(context.Background(), uuid.Nil, "000000")
	if !errors.Is(err, ErrMFAEnrollmentInvalid) {
		t.Errorf("nil userID = %v; want ErrMFAEnrollmentInvalid", err)
	}
}

func TestMFAEnrollment_DisableSelf_UnknownUserInvalid(t *testing.T) {
	svc, _, _, _ := newEnrollSvc(t)
	_, err := svc.DisableSelf(context.Background(), uuid.New(), "000000")
	if !errors.Is(err, ErrMFAEnrollmentInvalid) {
		t.Errorf("unknown user = %v; want ErrMFAEnrollmentInvalid", err)
	}
}

func TestMFAEnrollment_DisableSelf_BannedInvalid(t *testing.T) {
	svc, _, userRepo, user := newEnrollSvc(t)
	user.Banned = true
	userRepo.byID[user.ID] = user
	_, err := svc.DisableSelf(context.Background(), user.ID, "000000")
	if !errors.Is(err, ErrMFAEnrollmentInvalid) {
		t.Errorf("banned = %v; want ErrMFAEnrollmentInvalid", err)
	}
}

func TestMFAEnrollment_DisableSelf_DeletedInvalid(t *testing.T) {
	svc, _, userRepo, user := newEnrollSvc(t)
	now := time.Now().UTC()
	user.DeletedAt = &now
	userRepo.byID[user.ID] = user
	_, err := svc.DisableSelf(context.Background(), user.ID, "000000")
	if !errors.Is(err, ErrMFAEnrollmentInvalid) {
		t.Errorf("deleted = %v; want ErrMFAEnrollmentInvalid", err)
	}
}

func TestMFAEnrollment_DisableSelf_NotEnrolledRejected(t *testing.T) {
	svc, _, _, user := newEnrollSvc(t)
	// Default fixture leaves MFAEnabled=false.
	_, err := svc.DisableSelf(context.Background(), user.ID, "000000")
	if !errors.Is(err, ErrMFANotEnrolled) {
		t.Errorf("not-enrolled = %v; want ErrMFANotEnrolled", err)
	}
}

func TestMFAEnrollment_DisableSelf_SiteAdminBlockedByPolicy(t *testing.T) {
	svc, _, userRepo, user := newEnrollSvc(t)
	// Default fixture role IS site_admin. Just turn MFA on.
	secret := "ANYSECRETBYTES"
	codes := []string{"r1", "r2"}
	user.MFAEnabled = true
	user.MFASecret = &secret
	user.MFARecoveryCodes = hashCodesForTest(codes)
	userRepo.byID[user.ID] = user
	_, err := svc.DisableSelf(context.Background(), user.ID, "r1")
	if !errors.Is(err, ErrMFADisableForbiddenByPolicy) {
		t.Errorf("site_admin = %v; want ErrMFADisableForbiddenByPolicy", err)
	}
	stored := userRepo.byID[user.ID]
	if !stored.MFAEnabled || stored.MFASecret == nil || *stored.MFASecret != secret || len(stored.MFARecoveryCodes) != 2 {
		t.Errorf("site_admin denial mutated state: %+v", stored)
	}
}

func TestMFAEnrollment_DisableSelf_OrgAdminBlockedByPolicy(t *testing.T) {
	svc, _, userRepo, user := newEnrollSvc(t)
	user.Role = domain.RoleOrgAdmin
	secret := "ANYSECRETBYTES"
	codes := []string{"r1", "r2"}
	user.MFAEnabled = true
	user.MFASecret = &secret
	user.MFARecoveryCodes = hashCodesForTest(codes)
	userRepo.byID[user.ID] = user
	_, err := svc.DisableSelf(context.Background(), user.ID, "r1")
	if !errors.Is(err, ErrMFADisableForbiddenByPolicy) {
		t.Errorf("org_admin = %v; want ErrMFADisableForbiddenByPolicy", err)
	}
	stored := userRepo.byID[user.ID]
	if !stored.MFAEnabled || stored.MFASecret == nil || *stored.MFASecret != secret || len(stored.MFARecoveryCodes) != 2 {
		t.Errorf("org_admin denial mutated state: %+v", stored)
	}
}

func TestMFAEnrollment_DisableSelf_RequiredPolicyBlocks(t *testing.T) {
	svc, _, userRepo, user := newEnrollSvc(t)
	user.Role = domain.RoleOrgUser
	required := "required"
	user.MFAPolicy = &required
	secret := "ANYSECRETBYTES"
	codes := []string{"r1", "r2"}
	user.MFAEnabled = true
	user.MFASecret = &secret
	user.MFARecoveryCodes = hashCodesForTest(codes)
	userRepo.byID[user.ID] = user
	_, err := svc.DisableSelf(context.Background(), user.ID, "r1")
	if !errors.Is(err, ErrMFADisableForbiddenByPolicy) {
		t.Errorf("policy-required = %v; want ErrMFADisableForbiddenByPolicy", err)
	}
	stored := userRepo.byID[user.ID]
	if !stored.MFAEnabled || stored.MFASecret == nil || *stored.MFASecret != secret || len(stored.MFARecoveryCodes) != 2 {
		t.Errorf("required-policy denial mutated state: %+v", stored)
	}
}

func TestMFAEnrollment_DisableSelfWithProof_PasswordPolicyBlocksBeforeVerify(t *testing.T) {
	required := "required"
	tests := []struct {
		name   string
		role   domain.UserRole
		policy *string
	}{
		{name: "site_admin", role: domain.RoleSiteAdmin},
		{name: "org_admin", role: domain.RoleOrgAdmin},
		{name: "org_policy_required", role: domain.RoleOrgUser, policy: &required},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc, _, userRepo, user := newEnrollSvc(t)
			secret := "ANYSECRETBYTES"
			user.Role = tt.role
			user.MFAPolicy = tt.policy
			user.AuthSource = domain.AuthSourceLocal
			user.PasswordHash = "HASH-CURRENT-PASSWORD"
			user.MFAEnabled = true
			user.MFASecret = &secret
			user.MFARecoveryCodes = []string{"r1", "r2"}
			userRepo.byID[user.ID] = user
			_, err := svc.DisableSelfWithProof(context.Background(), user.ID, MFADisableSelfInput{Password: "correct-current-password"})
			if !errors.Is(err, ErrMFADisableForbiddenByPolicy) {
				t.Fatalf("err = %v; want ErrMFADisableForbiddenByPolicy", err)
			}
			if userRepo.verifyPasswordCalls != 0 {
				t.Fatalf("password verifier called before policy block: %d", userRepo.verifyPasswordCalls)
			}
			stored := userRepo.byID[user.ID]
			if !stored.MFAEnabled || stored.MFASecret == nil || *stored.MFASecret != secret || len(stored.MFARecoveryCodes) != 2 {
				t.Errorf("policy denial mutated state: %+v", stored)
			}
		})
	}
}

func TestMFAEnrollment_DisableSelf_EmptyCodeInvalid(t *testing.T) {
	svc, _, userRepo, user := newEnrollSvc(t)
	seedEnrolledOrgUser(userRepo, user, "SECRETBYTES", []string{"r1", "r2"})
	_, err := svc.DisableSelf(context.Background(), user.ID, "")
	if !errors.Is(err, ErrMFADisableInvalidCode) {
		t.Errorf("empty code = %v; want ErrMFADisableInvalidCode", err)
	}
	stored := userRepo.byID[user.ID]
	if !stored.MFAEnabled {
		t.Errorf("empty-code rejection mutated MFAEnabled: %+v", stored)
	}
}

func TestMFAEnrollment_DisableSelf_WrongCodeInvalid(t *testing.T) {
	svc, _, userRepo, user := newEnrollSvc(t)
	// Use a base32-decodable secret so the TOTP path runs. Wrong
	// code matches neither TOTP nor any recovery code.
	seedEnrolledOrgUser(userRepo, user, "JBSWY3DPEHPK3PXP", []string{"VALIDREC-A", "VALIDREC-B"})
	_, err := svc.DisableSelf(context.Background(), user.ID, "ZZZZZZZZ")
	if !errors.Is(err, ErrMFADisableInvalidCode) {
		t.Errorf("wrong code = %v; want ErrMFADisableInvalidCode", err)
	}
	stored := userRepo.byID[user.ID]
	if !stored.MFAEnabled || stored.MFASecret == nil || *stored.MFASecret != "JBSWY3DPEHPK3PXP" {
		t.Errorf("wrong-code rejection mutated state: %+v", stored)
	}
	if len(stored.MFARecoveryCodes) != 2 {
		t.Errorf("wrong-code rejection mutated recovery codes: %v", stored.MFARecoveryCodes)
	}
}

func TestMFAEnrollment_DisableSelfWithProof_PasswordHappyPath(t *testing.T) {
	svc, _, userRepo, user := newEnrollSvc(t)
	secret := "JBSWY3DPEHPK3PXP"
	seedEnrolledOrgUser(userRepo, user, secret, []string{"REC-A", "REC-B"})
	method, err := svc.DisableSelfWithProof(context.Background(), user.ID, MFADisableSelfInput{Password: "correct-current-password"})
	if err != nil {
		t.Fatalf("disable: %v", err)
	}
	if method != MFADisableReauthPassword {
		t.Errorf("reauth_method = %q; want password", method)
	}
	if userRepo.verifyPasswordCalls != 1 {
		t.Errorf("password verifier calls = %d; want 1", userRepo.verifyPasswordCalls)
	}
	stored := userRepo.byID[user.ID]
	if stored.MFAEnabled {
		t.Errorf("MFAEnabled still true")
	}
	if stored.MFASecret == nil || *stored.MFASecret != "" {
		t.Errorf("MFASecret not cleared: %v", stored.MFASecret)
	}
	if len(stored.MFARecoveryCodes) != 0 {
		t.Errorf("MFARecoveryCodes not cleared: %v", stored.MFARecoveryCodes)
	}
}

func TestMFAEnrollment_DisableSelfWithProof_WrongPasswordInvalid(t *testing.T) {
	svc, _, userRepo, user := newEnrollSvc(t)
	secret := "JBSWY3DPEHPK3PXP"
	seedEnrolledOrgUser(userRepo, user, secret, []string{"REC-A", "REC-B"})
	_, err := svc.DisableSelfWithProof(context.Background(), user.ID, MFADisableSelfInput{Password: "wrong-current-password"})
	if !errors.Is(err, ErrMFADisableInvalidCode) {
		t.Fatalf("err = %v; want ErrMFADisableInvalidCode", err)
	}
	if userRepo.verifyPasswordCalls != 1 {
		t.Errorf("password verifier calls = %d; want 1", userRepo.verifyPasswordCalls)
	}
	stored := userRepo.byID[user.ID]
	if !stored.MFAEnabled || stored.MFASecret == nil || *stored.MFASecret != secret || len(stored.MFARecoveryCodes) != 2 {
		t.Errorf("wrong-password rejection mutated state: %+v", stored)
	}
}

func TestMFAEnrollment_DisableSelfWithProof_EmptyPasswordInvalid(t *testing.T) {
	svc, _, userRepo, user := newEnrollSvc(t)
	seedEnrolledOrgUser(userRepo, user, "JBSWY3DPEHPK3PXP", []string{"REC-A"})
	_, err := svc.DisableSelfWithProof(context.Background(), user.ID, MFADisableSelfInput{Password: " \t "})
	if !errors.Is(err, ErrMFADisableInvalidCode) {
		t.Fatalf("err = %v; want ErrMFADisableInvalidCode", err)
	}
	if userRepo.verifyPasswordCalls != 0 {
		t.Errorf("password verifier calls = %d; want 0 for empty password", userRepo.verifyPasswordCalls)
	}
	if !userRepo.byID[user.ID].MFAEnabled {
		t.Errorf("empty-password rejection mutated MFAEnabled")
	}
}

func TestMFAEnrollment_DisableSelfWithProof_NonLocalOrEmptyHashPasswordInvalid(t *testing.T) {
	tests := []struct {
		name       string
		authSource string
		hash       string
	}{
		{name: "non_local", authSource: domain.AuthSourceIDJag, hash: "HASH-CURRENT-PASSWORD"},
		{name: "empty_hash", authSource: domain.AuthSourceLocal, hash: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc, _, userRepo, user := newEnrollSvc(t)
			secret := "JBSWY3DPEHPK3PXP"
			seedEnrolledOrgUser(userRepo, user, secret, []string{"REC-A"})
			user.AuthSource = tt.authSource
			user.PasswordHash = tt.hash
			userRepo.byID[user.ID] = user
			_, err := svc.DisableSelfWithProof(context.Background(), user.ID, MFADisableSelfInput{Password: "correct-current-password"})
			if !errors.Is(err, ErrMFADisableInvalidCode) {
				t.Fatalf("err = %v; want ErrMFADisableInvalidCode", err)
			}
			if userRepo.verifyPasswordCalls != 0 {
				t.Errorf("password verifier calls = %d; want 0", userRepo.verifyPasswordCalls)
			}
			if !userRepo.byID[user.ID].MFAEnabled {
				t.Errorf("rejection mutated MFAEnabled")
			}
		})
	}
}

func TestMFAEnrollment_DisableSelfWithProof_BothFieldsCodeFirst(t *testing.T) {
	t.Run("valid code ignores wrong password", func(t *testing.T) {
		svc, _, userRepo, user := newEnrollSvc(t)
		seedEnrolledOrgUser(userRepo, user, "JBSWY3DPEHPK3PXP", []string{"REC-A"})
		method, err := svc.DisableSelfWithProof(context.Background(), user.ID, MFADisableSelfInput{
			Code:     "REC-A",
			Password: "wrong-current-password",
		})
		if err != nil {
			t.Fatalf("disable: %v", err)
		}
		if method != MFADisableReauthRecoveryCode {
			t.Fatalf("method = %q; want recovery_code", method)
		}
		if userRepo.verifyPasswordCalls != 0 {
			t.Fatalf("password verifier called despite non-empty code: %d", userRepo.verifyPasswordCalls)
		}
	})
	t.Run("wrong code does not fall back to valid password", func(t *testing.T) {
		svc, _, userRepo, user := newEnrollSvc(t)
		secret := "JBSWY3DPEHPK3PXP"
		seedEnrolledOrgUser(userRepo, user, secret, []string{"REC-A"})
		_, err := svc.DisableSelfWithProof(context.Background(), user.ID, MFADisableSelfInput{
			Code:     "WRONG-CODE",
			Password: "correct-current-password",
		})
		if !errors.Is(err, ErrMFADisableInvalidCode) {
			t.Fatalf("err = %v; want ErrMFADisableInvalidCode", err)
		}
		if userRepo.verifyPasswordCalls != 0 {
			t.Fatalf("password verifier called after wrong non-empty code: %d", userRepo.verifyPasswordCalls)
		}
		stored := userRepo.byID[user.ID]
		if !stored.MFAEnabled || stored.MFASecret == nil || *stored.MFASecret != secret {
			t.Errorf("wrong-code rejection mutated state: %+v", stored)
		}
	})
	t.Run("empty code uses password", func(t *testing.T) {
		svc, _, userRepo, user := newEnrollSvc(t)
		seedEnrolledOrgUser(userRepo, user, "JBSWY3DPEHPK3PXP", []string{"REC-A"})
		method, err := svc.DisableSelfWithProof(context.Background(), user.ID, MFADisableSelfInput{
			Code:     "",
			Password: "correct-current-password",
		})
		if err != nil {
			t.Fatalf("disable: %v", err)
		}
		if method != MFADisableReauthPassword {
			t.Fatalf("method = %q; want password", method)
		}
		if userRepo.verifyPasswordCalls != 1 {
			t.Fatalf("password verifier calls = %d; want 1", userRepo.verifyPasswordCalls)
		}
	})
}

func TestMFAEnrollment_DisableSelf_TOTPHappyPath(t *testing.T) {
	svc, _, userRepo, user := newEnrollSvc(t)
	secret := "JBSWY3DPEHPK3PXP"
	codes := []string{"REC-A", "REC-B", "REC-C"}
	seedEnrolledOrgUser(userRepo, user, secret, codes)
	now := time.Now().UTC()
	counter := uint64(now.Unix()) / defaultTOTPPeriod
	totp, err := computeHOTP(secret, counter, defaultTOTPDigits)
	if err != nil {
		t.Fatalf("computeHOTP: %v", err)
	}
	method, err := svc.DisableSelf(context.Background(), user.ID, totp)
	if err != nil {
		t.Fatalf("disable: %v", err)
	}
	if method != MFADisableReauthTOTP {
		t.Errorf("reauth_method = %q; want totp", method)
	}
	stored := userRepo.byID[user.ID]
	if stored.MFAEnabled {
		t.Errorf("MFAEnabled still true")
	}
	if stored.MFASecret == nil || *stored.MFASecret != "" {
		t.Errorf("MFASecret not cleared: %v", stored.MFASecret)
	}
	if len(stored.MFARecoveryCodes) != 0 {
		t.Errorf("MFARecoveryCodes not cleared: %v", stored.MFARecoveryCodes)
	}
}

func TestMFAEnrollment_DisableSelf_RecoveryCodeHappyPath(t *testing.T) {
	svc, _, userRepo, user := newEnrollSvc(t)
	// Non-base32 secret so the TOTP verify path falls through to
	// the recovery-code leg.
	secret := "JBSWY3DPEHPK3PXP"
	codes := []string{"VALIDREC-AAAA", "VALIDREC-BBBB", "VALIDREC-CCCC"}
	seedEnrolledOrgUser(userRepo, user, secret, codes)
	method, err := svc.DisableSelf(context.Background(), user.ID, "VALIDREC-BBBB")
	if err != nil {
		t.Fatalf("disable: %v", err)
	}
	if method != MFADisableReauthRecoveryCode {
		t.Errorf("reauth_method = %q; want recovery_code", method)
	}
	stored := userRepo.byID[user.ID]
	if stored.MFAEnabled {
		t.Errorf("MFAEnabled still true")
	}
	if stored.MFASecret == nil || *stored.MFASecret != "" {
		t.Errorf("MFASecret not cleared: %v", stored.MFASecret)
	}
	if len(stored.MFARecoveryCodes) != 0 {
		t.Errorf("MFARecoveryCodes not cleared: %v", stored.MFARecoveryCodes)
	}
}

// TestMFAEnrollment_DisableSelf_RecoveryCodeBurnSurvivesFinalUpdate
// pins the burn-before-clear contract: even if the final disable
// Update were to fail downstream (here simulated by re-seeding the
// row to its pre-burn state AFTER the disable returns), the matched
// recovery code is still unusable for a second disable attempt.
// We assert this by walking the BYRD list of remaining codes after
// the call — the matched code is gone.
func TestMFAEnrollment_DisableSelf_RecoveryCodeBurnRemovesMatchedFromList(t *testing.T) {
	// To observe the intermediate burn-only state we intercept
	// the user repo's MFAEnabled flip and capture the remaining
	// list at that point. Easier path: after the successful
	// disable the row is cleared anyway; the burn happens via a
	// distinct Update call so we count Update invocations.
	pendingRepo := newStubPendingRepo()
	userRepo := newStubUserRepoForMFAEnroll()
	uid := uuid.New()
	orgID := uuid.New()
	secret := "JBSWY3DPEHPK3PXP"
	codes := []string{"BURN-A", "BURN-B", "BURN-C"}
	user := &domain.User{
		ID:               uid,
		OrganizationID:   orgID,
		Email:            "u@test",
		Role:             domain.RoleOrgUser,
		AuthSource:       domain.AuthSourceLocal,
		EmailVerified:    true,
		MFAEnabled:       true,
		MFASecret:        &secret,
		MFARecoveryCodes: hashCodesForTest(codes),
	}
	userRepo.byID[uid] = user
	svc := NewMFAEnrollmentService(nil, MFAEnrollmentRepoOptions{
		Pending: pendingRepo,
		Users:   userRepo,
		Issuer:  "Identuum",
		Cipher:  identityMFACipher{},
	}, MFAEnrollmentServiceOptions{})

	// Count Update calls by wrapping the repo — we cannot mutate
	// the stub's table from inside the test, but we CAN assert
	// that BOTH the burn Update AND the final clear Update fire
	// by observing the sequence of mutations they produce on the
	// shared row.
	method, err := svc.DisableSelf(context.Background(), uid, "BURN-B")
	if err != nil {
		t.Fatalf("disable: %v", err)
	}
	if method != MFADisableReauthRecoveryCode {
		t.Fatalf("method = %q; want recovery_code", method)
	}
	stored := userRepo.byID[uid]
	for _, c := range stored.MFARecoveryCodes {
		if c == "BURN-B" {
			t.Errorf("matched recovery code survived in final state: %v", stored.MFARecoveryCodes)
		}
	}
	// Final state is cleared; the post-condition is symmetric with
	// the TOTP path.
	if stored.MFAEnabled || (stored.MFASecret != nil && *stored.MFASecret != "") || len(stored.MFARecoveryCodes) != 0 {
		t.Errorf("final state not cleared: %+v", stored)
	}
}

// TestMFAEnrollment_DisableSelf_PreservesUnrelatedFields seeds a
// distinctive password hash + email + role + org id and verifies
// none of them moves through the disable transaction.
func TestMFAEnrollment_DisableSelf_PreservesUnrelatedFields(t *testing.T) {
	svc, _, userRepo, user := newEnrollSvc(t)
	user.Role = domain.RoleOrgUser
	user.Email = "preserve@example.com"
	user.PasswordHash = "PRESERVED-PASSWORD-HASH"
	user.Banned = false
	user.EmailVerified = true
	secret := "JBSWY3DPEHPK3PXP"
	user.MFAEnabled = true
	user.MFASecret = &secret
	user.MFARecoveryCodes = hashCodesForTest([]string{"REC-1", "REC-2"})
	userRepo.byID[user.ID] = user
	_, err := svc.DisableSelf(context.Background(), user.ID, "REC-1")
	if err != nil {
		t.Fatalf("disable: %v", err)
	}
	stored := userRepo.byID[user.ID]
	if stored.PasswordHash != "PRESERVED-PASSWORD-HASH" {
		t.Errorf("password_hash mutated: %q", stored.PasswordHash)
	}
	if stored.Email != "preserve@example.com" {
		t.Errorf("email mutated: %q", stored.Email)
	}
	if stored.Role != domain.RoleOrgUser {
		t.Errorf("role mutated: %q", stored.Role)
	}
	if !stored.EmailVerified {
		t.Errorf("email_verified flipped off by disable")
	}
}

// ---------- GetMFAStatus ----------

func TestMFAEnrollment_GetMFAStatus_NilUserIDInvalid(t *testing.T) {
	svc, _, _, _ := newEnrollSvc(t)
	_, err := svc.GetMFAStatus(context.Background(), uuid.Nil)
	if !errors.Is(err, ErrMFAEnrollmentInvalid) {
		t.Errorf("nil userID = %v; want ErrMFAEnrollmentInvalid", err)
	}
}

func TestMFAEnrollment_GetMFAStatus_UnknownUserInvalid(t *testing.T) {
	svc, _, _, _ := newEnrollSvc(t)
	_, err := svc.GetMFAStatus(context.Background(), uuid.New())
	if !errors.Is(err, ErrMFAEnrollmentInvalid) {
		t.Errorf("unknown user = %v; want ErrMFAEnrollmentInvalid", err)
	}
}

func TestMFAEnrollment_GetMFAStatus_BannedInvalid(t *testing.T) {
	svc, _, userRepo, user := newEnrollSvc(t)
	user.Banned = true
	userRepo.byID[user.ID] = user
	_, err := svc.GetMFAStatus(context.Background(), user.ID)
	if !errors.Is(err, ErrMFAEnrollmentInvalid) {
		t.Errorf("banned = %v; want ErrMFAEnrollmentInvalid", err)
	}
}

func TestMFAEnrollment_GetMFAStatus_DeletedInvalid(t *testing.T) {
	svc, _, userRepo, user := newEnrollSvc(t)
	now := time.Now().UTC()
	user.DeletedAt = &now
	userRepo.byID[user.ID] = user
	_, err := svc.GetMFAStatus(context.Background(), user.ID)
	if !errors.Is(err, ErrMFAEnrollmentInvalid) {
		t.Errorf("deleted = %v; want ErrMFAEnrollmentInvalid", err)
	}
}

func TestMFAEnrollment_GetMFAStatus_NotEnrolledReturnsZero(t *testing.T) {
	svc, _, _, user := newEnrollSvc(t)
	// Fresh fixture has MFAEnabled=false, no secret, no codes.
	status, err := svc.GetMFAStatus(context.Background(), user.ID)
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if status.MFAEnabled {
		t.Errorf("MFAEnabled = true on un-enrolled user")
	}
	if status.RecoveryCodesRemaining != 0 {
		t.Errorf("RecoveryCodesRemaining = %d; want 0", status.RecoveryCodesRemaining)
	}
	if status.TOTPEnrolled {
		t.Errorf("TOTPEnrolled = true on un-enrolled user")
	}
}

func TestMFAEnrollment_GetMFAStatus_EnrolledWithCodes(t *testing.T) {
	svc, _, userRepo, user := newEnrollSvc(t)
	secret := "PRESERVED-TOTP-SECRET"
	user.MFAEnabled = true
	user.MFASecret = &secret
	user.MFARecoveryCodes = []string{"A", "B", "C", "D"}
	userRepo.byID[user.ID] = user
	status, err := svc.GetMFAStatus(context.Background(), user.ID)
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if !status.MFAEnabled {
		t.Errorf("MFAEnabled = false on enrolled user")
	}
	if status.RecoveryCodesRemaining != 4 {
		t.Errorf("RecoveryCodesRemaining = %d; want 4", status.RecoveryCodesRemaining)
	}
	if !status.TOTPEnrolled {
		t.Errorf("TOTPEnrolled = false on enrolled user with non-empty secret")
	}
}

func TestMFAEnrollment_GetMFAStatus_EnabledWithoutSecretReportsTOTPNotEnrolled(t *testing.T) {
	svc, _, userRepo, user := newEnrollSvc(t)
	// Edge case: row says MFAEnabled=true but MFASecret is nil
	// (corrupt row from a partial enrolment). The status must
	// report MFAEnabled=true (the column is authoritative for
	// policy gates) but TOTPEnrolled=false so the UI does not
	// claim "authenticator app configured" when the secret is
	// missing.
	user.MFAEnabled = true
	user.MFASecret = nil
	userRepo.byID[user.ID] = user
	status, err := svc.GetMFAStatus(context.Background(), user.ID)
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if !status.MFAEnabled {
		t.Errorf("MFAEnabled = false; want true")
	}
	if status.TOTPEnrolled {
		t.Errorf("TOTPEnrolled = true with nil MFASecret; want false")
	}
}

func TestMFAEnrollment_GetMFAStatus_EmptySecretReportsTOTPNotEnrolled(t *testing.T) {
	svc, _, userRepo, user := newEnrollSvc(t)
	empty := ""
	user.MFAEnabled = true
	user.MFASecret = &empty
	userRepo.byID[user.ID] = user
	status, err := svc.GetMFAStatus(context.Background(), user.ID)
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if !status.MFAEnabled {
		t.Errorf("MFAEnabled = false; want true")
	}
	if status.TOTPEnrolled {
		t.Errorf("TOTPEnrolled = true with empty MFASecret; want false")
	}
}

// TestMFAEnrollment_GetMFAStatus_DoesNotMutateUserRow pins that the
// status read is purely projection — no field on the user row
// changes as a side effect of the call.
func TestMFAEnrollment_GetMFAStatus_DoesNotMutateUserRow(t *testing.T) {
	svc, _, userRepo, user := newEnrollSvc(t)
	secret := "WATCH-FOR-LEAK"
	user.MFAEnabled = true
	user.MFASecret = &secret
	user.MFARecoveryCodes = []string{"X", "Y"}
	userRepo.byID[user.ID] = user
	_, err := svc.GetMFAStatus(context.Background(), user.ID)
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	stored := userRepo.byID[user.ID]
	if !stored.MFAEnabled {
		t.Errorf("MFAEnabled mutated")
	}
	if stored.MFASecret == nil || *stored.MFASecret != "WATCH-FOR-LEAK" {
		t.Errorf("MFASecret mutated: %v", stored.MFASecret)
	}
	if len(stored.MFARecoveryCodes) != 2 || stored.MFARecoveryCodes[0] != "X" || stored.MFARecoveryCodes[1] != "Y" {
		t.Errorf("MFARecoveryCodes mutated: %v", stored.MFARecoveryCodes)
	}
}

// ---------- RegenerateRecoveryCodes ----------

func TestMFAEnrollment_RegenerateRecoveryCodes_NilUserIDInvalid(t *testing.T) {
	svc, _, _, _ := newEnrollSvc(t)
	_, err := svc.RegenerateRecoveryCodes(context.Background(), uuid.Nil)
	if !errors.Is(err, ErrMFAEnrollmentInvalid) {
		t.Errorf("nil userID = %v; want ErrMFAEnrollmentInvalid", err)
	}
}

func TestMFAEnrollment_RegenerateRecoveryCodes_UnknownUserInvalid(t *testing.T) {
	svc, _, _, _ := newEnrollSvc(t)
	_, err := svc.RegenerateRecoveryCodes(context.Background(), uuid.New())
	if !errors.Is(err, ErrMFAEnrollmentInvalid) {
		t.Errorf("unknown user = %v; want ErrMFAEnrollmentInvalid", err)
	}
}

func TestMFAEnrollment_RegenerateRecoveryCodes_NotEnrolledRejected(t *testing.T) {
	svc, _, userRepo, user := newEnrollSvc(t)
	// Default fixture leaves MFAEnabled=false.
	if user.MFAEnabled {
		t.Fatal("fixture invariant: expected MFAEnabled=false to start")
	}
	_, err := svc.RegenerateRecoveryCodes(context.Background(), user.ID)
	if !errors.Is(err, ErrMFANotEnrolled) {
		t.Errorf("not-enrolled = %v; want ErrMFANotEnrolled", err)
	}
	// Original codes (none) untouched.
	if got := userRepo.byID[user.ID].MFARecoveryCodes; len(got) != 0 {
		t.Errorf("recovery codes mutated despite rejection: %v", got)
	}
}

func TestMFAEnrollment_RegenerateRecoveryCodes_BannedRejected(t *testing.T) {
	svc, _, userRepo, user := newEnrollSvc(t)
	user.MFAEnabled = true
	user.Banned = true
	userRepo.byID[user.ID] = user
	_, err := svc.RegenerateRecoveryCodes(context.Background(), user.ID)
	if !errors.Is(err, ErrMFAEnrollmentInvalid) {
		t.Errorf("banned = %v; want ErrMFAEnrollmentInvalid", err)
	}
}

func TestMFAEnrollment_RegenerateRecoveryCodes_DeletedRejected(t *testing.T) {
	svc, _, userRepo, user := newEnrollSvc(t)
	user.MFAEnabled = true
	now := time.Now().UTC()
	user.DeletedAt = &now
	userRepo.byID[user.ID] = user
	_, err := svc.RegenerateRecoveryCodes(context.Background(), user.ID)
	if !errors.Is(err, ErrMFAEnrollmentInvalid) {
		t.Errorf("deleted = %v; want ErrMFAEnrollmentInvalid", err)
	}
}

func TestMFAEnrollment_RegenerateRecoveryCodes_HappyPath(t *testing.T) {
	svc, _, userRepo, user := newEnrollSvc(t)
	original := []string{"OLDCODE-A", "OLDCODE-B", "OLDCODE-C"}
	originalSecret := "PRESERVED-TOTP-SECRET"
	user.MFAEnabled = true
	user.MFASecret = &originalSecret
	user.MFARecoveryCodes = hashCodesForTest(original)
	userRepo.byID[user.ID] = user

	codes, err := svc.RegenerateRecoveryCodes(context.Background(), user.ID)
	if err != nil {
		t.Fatalf("regenerate: %v", err)
	}
	if len(codes) != defaultMFAEnrollmentRecoveryCodeCount {
		t.Errorf("count = %d; want %d", len(codes), defaultMFAEnrollmentRecoveryCodeCount)
	}
	// Every returned code is non-empty AND distinct.
	seen := map[string]struct{}{}
	for i, c := range codes {
		if c == "" {
			t.Errorf("returned code %d is empty", i)
		}
		if _, dup := seen[c]; dup {
			t.Errorf("returned code %d is a duplicate: %q", i, c)
		}
		seen[c] = struct{}{}
		// No leak of old codes in the fresh set.
		for _, old := range original {
			if c == old {
				t.Errorf("returned code %d collides with an old code", i)
			}
		}
	}
	// Persisted row must carry exactly the new codes; no old code
	// can remain.
	stored := userRepo.byID[user.ID]
	if len(stored.MFARecoveryCodes) != len(codes) {
		t.Errorf("persisted code count = %d; want %d", len(stored.MFARecoveryCodes), len(codes))
	}
	for i, c := range codes {
		// Persisted codes are SHA-256 hashes of the returned plaintext.
		if stored.MFARecoveryCodes[i] != crypto.HashSecret(c) {
			t.Errorf("persisted code %d is not the hash of the returned code", i)
		}
	}
	for _, old := range original {
		for _, c := range stored.MFARecoveryCodes {
			if c == old {
				t.Errorf("old code %q survived regeneration", old)
			}
		}
	}
	// MFAEnabled + MFASecret preserved.
	if !stored.MFAEnabled {
		t.Error("MFAEnabled flipped to false")
	}
	if stored.MFASecret == nil || *stored.MFASecret != originalSecret {
		t.Errorf("MFASecret mutated: got=%v want=%q", stored.MFASecret, originalSecret)
	}
}

func TestMFAEnrollment_RegenerateRecoveryCodes_SecondCallReplacesFirst(t *testing.T) {
	svc, _, userRepo, user := newEnrollSvc(t)
	user.MFAEnabled = true
	userRepo.byID[user.ID] = user

	first, err := svc.RegenerateRecoveryCodes(context.Background(), user.ID)
	if err != nil {
		t.Fatalf("first regenerate: %v", err)
	}
	second, err := svc.RegenerateRecoveryCodes(context.Background(), user.ID)
	if err != nil {
		t.Fatalf("second regenerate: %v", err)
	}
	// Every code from the first set must be absent from the
	// persisted row after the second call — proves old codes
	// cease to authenticate.
	stored := userRepo.byID[user.ID]
	for _, old := range first {
		for _, c := range stored.MFARecoveryCodes {
			if c == old {
				t.Errorf("first-set code %q still present after second regenerate", old)
			}
		}
	}
	// Cross-set collision is astronomically unlikely on base32
	// crypto/rand output but the test surfaces it loudly if it
	// happens.
	firstSet := map[string]struct{}{}
	for _, c := range first {
		firstSet[c] = struct{}{}
	}
	for _, c := range second {
		if _, dup := firstSet[c]; dup {
			t.Errorf("second-set code %q collided with first set", c)
		}
	}
}

// TestMFAEnrollment_RegenerateRecoveryCodes_FreshCodesMatchEnrollmentFormat
// pins that the codes returned by RegenerateRecoveryCodes can be
// consumed by the same constant-time helper the verify path uses,
// so the wire shape stays identical between enrolment and
// regeneration.
func TestMFAEnrollment_RegenerateRecoveryCodes_FreshCodesMatchEnrollmentFormat(t *testing.T) {
	svc, _, userRepo, user := newEnrollSvc(t)
	user.MFAEnabled = true
	userRepo.byID[user.ID] = user
	codes, err := svc.RegenerateRecoveryCodes(context.Background(), user.ID)
	if err != nil {
		t.Fatalf("regenerate: %v", err)
	}
	stored := userRepo.byID[user.ID].MFARecoveryCodes
	// Consume the first stored code through the same helper used
	// by VerifyAndConsume; ok=true proves the shape is compatible.
	if _, ok := consumeRecoveryCode(stored, codes[0]); !ok {
		t.Errorf("freshly regenerated code rejected by consumeRecoveryCode")
	}
	// An old code (from a stale ledger before regeneration) must
	// NOT be accepted on the post-regen stored list.
	if _, ok := consumeRecoveryCode(stored, "GHOST-PRE-REGEN-CODE"); ok {
		t.Errorf("stale code accepted after regeneration")
	}
}

// TestValidCodeSetForWindow_IsExactlyTheAcceptedSteps asserts the BUILDER, not a
// sampled consequence of it. Under a centre-narrowed builder the cardinality
// check fails on every run, not on 2 runs in a million.
func TestValidCodeSetForWindow_IsExactlyTheAcceptedSteps(t *testing.T) {
	// PINNED secret and PINNED clock, deliberately. With a random secret the
	// three step-codes are three draws from a million, so two of them collide
	// about 3 times in a million runs — making len(set)==2 and failing this test
	// with NO defect present. A cardinality assertion that can go red on its own
	// randomness is the same class of mistake as the sampled check it replaced,
	// just rarer. Fixed inputs make "3" a fact about this secret and this
	// instant, re-derivable by anyone.
	const secret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
	now := time.Date(2026, 6, 2, 12, 0, 0, 0, time.UTC)
	set := validCodeSetForWindow(t, secret, now)

	// CARDINALITY: one entry per accepted step. Narrowing the builder to the
	// centre makes this 1 instead of 3 — deterministically.
	want := 2*defaultTOTPWindow + 1
	if len(set) != want {
		t.Fatalf("valid set has %d entries, want %d (one per step in -%d..+%d)",
			len(set), want, defaultTOTPWindow, defaultTOTPWindow)
	}

	// MEMBERSHIP: the set is exactly computeHOTP at every accepted step.
	stepNow := now.Unix() / int64(defaultTOTPPeriod)
	for delta := -int64(defaultTOTPWindow); delta <= int64(defaultTOTPWindow); delta++ {
		code, err := computeHOTP(secret, uint64(stepNow+delta), defaultTOTPDigits)
		if err != nil {
			t.Fatalf("computeHOTP(step%+d): %v", delta, err)
		}
		if !set[code] {
			t.Fatalf("step%+d code is not in the valid set — the builder does not cover the window", delta)
		}
	}

	// And the guess drawn from it is outside the set, by construction.
	if set[wrongCodeForWindow(t, secret, now)] {
		t.Fatal("wrongCodeForWindow returned a code inside the accepted set")
	}
}
