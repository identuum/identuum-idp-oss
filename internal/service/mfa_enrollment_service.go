// Package service — MFAEnrollmentService is the OSS-resident
// orchestrator for the multi-request MFA-pending login state added
// by slice agent-a-identuum-idp-oss-mfa-totp-enrolment-endpoints.
//
// Two pending kinds:
//
//   - MFAPendingKindEnroll — created by HandleLocalLogin when an
//     admin / required-policy user passes password but has
//     MFAEnabled=false. The /api/v1/auth/login/mfa/enroll/initiate
//     handler calls Initiate to populate the candidate TOTP secret
//     and recovery codes; /api/v1/auth/login/mfa/enroll/complete calls
//     Complete to verify the supplied TOTP code, persist the secret
//     onto the user row, mark the pending row consumed, and return
//     the resolved user so HandleLocalLogin can issue the full
//     session.
//
//   - MFAPendingKindVerify — created by HandleLocalLogin when a
//     user with MFAEnabled=true passes password without supplying
//     a TOTPCode. The /api/v1/auth/login/mfa handler calls
//     VerifyAndConsume to check the TOTP code against the user's
//     persisted MFASecret, mark the pending row consumed, and
//     return the resolved user so HandleLocalLogin can issue the
//     full session.
//
// SAFETY: the service NEVER logs the candidate secret, the recovery
// codes, the TOTP code, the otpauth URL, or any other credential
// material. Errors collapse to opaque sentinels (ErrMFAEnrollmentInvalid
// or ErrMFAEnrollmentExpired) so the HTTP layer cannot leak the
// underlying cause.
package service

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/crypto"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/lifecycle"
	"github.com/identuum/identuum-idp-oss/internal/repository"
	"github.com/identuum/identuum-idp-oss/internal/utils/uuidgen"
	"github.com/identuum/identuum-idp-oss/pkg/totp"
)

// MFAEnrollmentRepoOptions is the dependency bundle. All three
// fields are required; nil panics at constructor time.
type MFAEnrollmentRepoOptions struct {
	Pending repository.MFAPendingLoginSessionRepository
	Users   repository.UserRepository
	// Issuer is the value embedded in the otpauth URL as the
	// `issuer` query parameter (e.g. "Identuum"). MUST NOT be
	// empty — authenticator apps use it as the label namespace
	// and an empty value produces confusing UX.
	Issuer string
	// Cipher protects the TOTP seed at rest (AES-256-GCM, all tiers).
	// REQUIRED: a nil cipher makes the write/verify paths fail closed
	// (no plaintext seed is ever stored or read — closing the MFA
	// at-rest regression). *crypto.CryptoService satisfies it.
	Cipher MFASecretCipher
}

// MFAEnrollmentService owns the pending-MFA login state machine.
type MFAEnrollmentService struct {
	pending           repository.MFAPendingLoginSessionRepository
	users             repository.UserRepository
	issuer            string
	cipher            MFASecretCipher
	ttl               time.Duration
	secretBytes       int
	codeCount         int
	codeBytes         int
	maxVerifyAttempts int
	now               func() time.Time
}

// MFAEnrollmentServiceOptions tunes the service. Zero values fall
// back to the defaults documented inline.
type MFAEnrollmentServiceOptions struct {
	// TTL is the pending-row lifetime. Defaults to 5 minutes —
	// matches domain.MFAPendingTTL.
	TTL time.Duration
	// SecretBytes is the raw entropy in the candidate TOTP secret
	// before base32 encoding. RFC 6238 §5.1 recommends at least
	// HMAC-SHA1 key length (20 bytes / 160 bits). Defaults to 20.
	SecretBytes int
	// RecoveryCodeCount is the number of recovery codes generated
	// at /initiate time. Defaults to 10.
	RecoveryCodeCount int
	// RecoveryCodeBytes is the raw entropy per recovery code
	// before base32 encoding. Defaults to 5 (8 base32 chars).
	RecoveryCodeBytes int
	// MaxVerifyAttempts is the number of wrong TOTP/recovery-code
	// guesses a single verify-kind handle tolerates before it is
	// invalidated (P0-13). Defaults to 5 — matches the password-login
	// lockout threshold (LoginRiskService: 5 failures / 15 min) for
	// operator consistency; against a 6-digit TOTP (with the ±1-step
	// skew window verifyTOTPCodeAgainstSecret allows, ~3 acceptable
	// codes of 1e6) five guesses is ≈1.5e-5 success probability —
	// negligible — while tolerating a couple of legitimate mistypes /
	// clock-skew retries inside the handle's ~5-minute lifetime.
	MaxVerifyAttempts int
}

// Sentinel errors. The HTTP layer maps these to opaque 401 / 400
// responses; the wire NEVER distinguishes which check failed.
var (
	// ErrMFAEnrollmentNotFound — pending handle does not exist.
	ErrMFAEnrollmentNotFound = errors.New("service: mfa pending session not found")

	// ErrMFAEnrollmentInvalid — handle exists but is not redeemable
	// for this kind, OR the TOTP code does not match, OR the
	// pending row has not yet been /initiate'd (secret is nil).
	ErrMFAEnrollmentInvalid = errors.New("service: mfa pending session invalid")

	// ErrMFAEnrollmentExpired — handle exists but is past
	// expires_at. Mapped to the same 401 as Invalid.
	ErrMFAEnrollmentExpired = errors.New("service: mfa pending session expired")

	// ErrMFAEnrollmentAlreadyConsumed — handle has already been
	// successfully redeemed. Mapped to the same 401 as Invalid.
	ErrMFAEnrollmentAlreadyConsumed = errors.New("service: mfa pending session already consumed")

	// ErrMFANotEnrolled — the authenticated user has not enrolled
	// MFA yet (MFAEnabled=false). Returned by RegenerateRecoveryCodes
	// and DisableSelf so the wire layer can map this to a distinct
	// 400 mfa_not_enrolled response rather than collapsing it onto
	// the opaque pending-MFA sentinel set.
	ErrMFANotEnrolled = errors.New("service: mfa not enrolled")

	// ErrMFADisableForbiddenByPolicy — DisableSelf is refused because
	// the user's role or organization policy requires MFA
	// (site_admin / org_admin / mfa_policy="required"). The wire
	// layer maps this to a distinct 403 mfa_required_by_policy so a
	// UI can route the user back to enrolment instructions. The
	// policy decision is delegated to IsMFARequiredForUser so the
	// disable surface stays in lockstep with the local-login policy
	// gate.
	ErrMFADisableForbiddenByPolicy = errors.New("service: mfa disable forbidden by policy")

	// ErrMFADisableInvalidCode — the supplied proof matched neither
	// the user's TOTP secret (within the standard ±1-step window)
	// nor any stored recovery code, or the supplied current password
	// did not verify. The wire NEVER distinguishes "wrong TOTP" from
	// "wrong recovery code" from "wrong password" — all collapse to
	// 401 invalid_code on the disable surface.
	ErrMFADisableInvalidCode = errors.New("service: mfa disable invalid code")
)

// MFADisableReauthMethod identifies which leg of the re-auth chain
// succeeded on a DisableSelf call. The HTTP layer surfaces it as a
// safe audit-metadata field; it is NEVER a wire response field on
// the success path (the success path returns 204).
type MFADisableReauthMethod string

const (
	// MFADisableReauthTOTP indicates the supplied code matched the
	// user's persisted TOTP secret.
	MFADisableReauthTOTP MFADisableReauthMethod = "totp"
	// MFADisableReauthRecoveryCode indicates the supplied code
	// matched one of the user's stored recovery codes. The matched
	// code is burned BEFORE the disable Update so a downstream
	// failure cannot leave a reusable code on the row.
	MFADisableReauthRecoveryCode MFADisableReauthMethod = "recovery_code"
	// MFADisableReauthPassword indicates the supplied current
	// password verified against the authenticated local user's stored
	// password hash.
	MFADisableReauthPassword MFADisableReauthMethod = "password"
)

// MFADisableSelfInput carries the accepted step-up proof material
// for self-service MFA disable. Code is tried first when non-empty;
// Password is considered only when Code is empty.
type MFADisableSelfInput struct {
	Code     string
	Password string
}

const (
	defaultMFAEnrollmentTTL               = 5 * time.Minute
	defaultMFAEnrollmentSecretBytes       = 20
	defaultMFAEnrollmentRecoveryCodeCount = 10
	defaultMFAEnrollmentRecoveryCodeBytes = 5
	// defaultMFAMaxVerifyAttempts bounds wrong-guess attempts against a
	// single verify-kind handle before it is invalidated (P0-13). See
	// MFAEnrollmentServiceOptions.MaxVerifyAttempts for the rationale.
	defaultMFAMaxVerifyAttempts = 5
)

// NewMFAEnrollmentService constructs the service. Pending, Users,
// and Issuer are required; nil/empty panics so a misconfigured
// deployment cannot silently mint pending rows that no one can
// finalise.
func NewMFAEnrollmentService(report *lifecycle.StartupReport, repos MFAEnrollmentRepoOptions, opts MFAEnrollmentServiceOptions) *MFAEnrollmentService {
	if repos.Pending == nil {
		report.Fatal("NewMFAEnrollmentService", "service: NewMFAEnrollmentService requires non-nil Pending repo")
	}
	if repos.Users == nil {
		report.Fatal("NewMFAEnrollmentService", "service: NewMFAEnrollmentService requires non-nil Users repo")
	}
	if strings.TrimSpace(repos.Issuer) == "" {
		report.Fatal("NewMFAEnrollmentService", "service: NewMFAEnrollmentService requires non-empty Issuer")
	}
	ttl := opts.TTL
	if ttl <= 0 {
		ttl = defaultMFAEnrollmentTTL
	}
	secretBytes := opts.SecretBytes
	if secretBytes <= 0 {
		secretBytes = defaultMFAEnrollmentSecretBytes
	}
	codeCount := opts.RecoveryCodeCount
	if codeCount <= 0 {
		codeCount = defaultMFAEnrollmentRecoveryCodeCount
	}
	codeBytes := opts.RecoveryCodeBytes
	if codeBytes <= 0 {
		codeBytes = defaultMFAEnrollmentRecoveryCodeBytes
	}
	maxVerifyAttempts := opts.MaxVerifyAttempts
	if maxVerifyAttempts <= 0 {
		maxVerifyAttempts = defaultMFAMaxVerifyAttempts
	}
	return &MFAEnrollmentService{
		pending:           repos.Pending,
		users:             repos.Users,
		issuer:            repos.Issuer,
		cipher:            repos.Cipher,
		ttl:               ttl,
		secretBytes:       secretBytes,
		codeCount:         codeCount,
		codeBytes:         codeBytes,
		maxVerifyAttempts: maxVerifyAttempts,
		now:               time.Now,
	}
}

// CreatePending issues a fresh pending-MFA login session for the
// supplied user + kind. Returns the persisted row (with ID, ExpiresAt
// populated). The caller (HandleLocalLogin) emits row.ID in the JSON
// body as `session_id` so the UI can later call /enroll/initiate +
// /enroll/complete (kind=enroll) or /login/mfa (kind=verify).
//
// Defensive: returns an error WITHOUT writing a row when the
// supplied user is nil, banned, or soft-deleted — the HTTP layer
// MUST NOT have arrived here for such a user but the guard ensures
// no pending handle exists for an unloggable account.
func (s *MFAEnrollmentService) CreatePending(ctx context.Context, user *domain.User, kind domain.MFAPendingKind, rememberMe bool) (*domain.MFAPendingLoginSession, error) {
	if user == nil || user.ID == uuid.Nil {
		return nil, ErrMFAEnrollmentInvalid
	}
	if user.Banned || user.DeletedAt != nil {
		return nil, ErrMFAEnrollmentInvalid
	}
	if kind != domain.MFAPendingKindEnroll && kind != domain.MFAPendingKindVerify {
		return nil, ErrMFAEnrollmentInvalid
	}
	id, err := uuidgen.NewV7()
	if err != nil {
		return nil, fmt.Errorf("service: mfa pending uuid generation: %w", err)
	}
	now := s.now().UTC()
	row := &domain.MFAPendingLoginSession{
		ID:         id,
		UserID:     user.ID,
		Kind:       kind,
		RememberMe: rememberMe,
		ExpiresAt:  now.Add(s.ttl),
	}
	return s.pending.Create(ctx, row)
}

// MFAEnrollmentInitiateResult is the projection /enroll/initiate
// returns to the HTTP layer. Secret + RecoveryCodes are shown
// ONCE to the operator (UI generates QR from OtpauthURL; operator
// records recovery codes). The HTTP handler MUST set
// Cache-Control: no-store on the response.
type MFAEnrollmentInitiateResult struct {
	OtpauthURL    string
	Secret        string
	RecoveryCodes []string
	IssuedAt      time.Time
	ExpiresAt     time.Time
}

// Initiate populates the candidate secret + recovery codes on the
// pending row identified by pendingID and returns the otpauth URL
// + secret bytes + recovery codes for one-time client display.
// Must be invoked AFTER CreatePending. Repeated invocations on
// the same pending row are rejected (the underlying UPDATE refuses
// to overwrite when the row has been consumed, but the service
// layer also refuses when a secret is already set, so the operator
// cannot scrub-and-retry).
func (s *MFAEnrollmentService) Initiate(ctx context.Context, pendingID uuid.UUID) (*MFAEnrollmentInitiateResult, error) {
	row, err := s.pending.GetByID(ctx, pendingID)
	if err != nil {
		if errors.Is(err, repository.ErrMFAPendingSessionNotFound) {
			return nil, ErrMFAEnrollmentNotFound
		}
		return nil, ErrMFAEnrollmentInvalid
	}
	if ok, _ := row.CanBeUsed(s.now(), domain.MFAPendingKindEnroll); !ok {
		if row.ConsumedAt != nil {
			return nil, ErrMFAEnrollmentAlreadyConsumed
		}
		if !row.ExpiresAt.After(s.now()) {
			return nil, ErrMFAEnrollmentExpired
		}
		return nil, ErrMFAEnrollmentInvalid
	}
	if row.Secret != nil && *row.Secret != "" {
		// Initiate already ran for this handle. Refuse rather than
		// re-mint to prevent client-driven secret rotation.
		return nil, ErrMFAEnrollmentInvalid
	}
	user, err := s.users.GetByID(ctx, row.UserID)
	if err != nil || user == nil {
		return nil, ErrMFAEnrollmentInvalid
	}
	secret, err := generateBase32Secret(s.secretBytes)
	if err != nil {
		return nil, fmt.Errorf("service: mfa pending secret generation: %w", err)
	}
	codes, err := generateRecoveryCodes(s.codeCount, s.codeBytes)
	if err != nil {
		return nil, fmt.Errorf("service: mfa pending recovery codes generation: %w", err)
	}
	// At-rest protection: the pending row stores the ENCRYPTED seed + HASHED
	// recovery codes — never plaintext. The plaintext seed + codes are
	// returned ONCE below for one-time client display (QR + recovery list).
	// Fail-closed when the cipher is unavailable (missing/invalid MFA key).
	encSecret, err := s.encryptSeed(secret)
	if err != nil {
		return nil, err
	}
	if err := s.pending.UpdateSecret(ctx, pendingID, encSecret, hashRecoveryCodes(codes)); err != nil {
		if errors.Is(err, repository.ErrMFAPendingSessionNotFound) {
			return nil, ErrMFAEnrollmentExpired
		}
		return nil, fmt.Errorf("service: mfa pending update secret: %w", err)
	}
	return &MFAEnrollmentInitiateResult{
		OtpauthURL:    buildOtpauthURL(s.issuer, user.Email, secret),
		Secret:        secret,
		RecoveryCodes: codes,
		IssuedAt:      s.now().UTC(),
		ExpiresAt:     row.ExpiresAt,
	}, nil
}

// MFAEnrollmentCompleteResult is what Complete returns. The HTTP
// layer uses User + RememberMe to issue the full session via
// UserSessionService.CreateUserSession + UserTokenService.IssueForSession
// + setAuthCookies (matching the normal success path of /login).
//
// RecoveryCodeUsed + RemainingRecoveryCodes are populated ONLY by
// VerifyAndConsume on the recovery-code branch (when the supplied
// code matched a stored recovery code instead of the TOTP secret).
// The HTTP layer uses them to emit a distinct audit action — the
// raw code is NEVER surfaced through the result.
type MFAEnrollmentCompleteResult struct {
	User                   *domain.User
	RememberMe             bool
	RecoveryCodeUsed       bool
	RemainingRecoveryCodes int
}

// Complete verifies the supplied TOTP code against the secret
// previously stored by Initiate, persists mfa_enabled=true +
// mfa_secret + mfa_recovery_codes onto the user row, marks the
// pending row consumed, and returns the user for the HTTP layer
// to drive session issuance.
//
// Replay safety:
//
//   - pending.MarkConsumed is invoked BEFORE the user UPDATE. If
//     two requests race for the same pending ID, only one wins the
//     atomic UPDATE on consumed_at; the loser sees MarkConsumed
//     return false and gets ErrMFAEnrollmentInvalid.
//
//   - User.MFASecret + MFAEnabled persist via a single
//     UserRepository.Update. If that update fails after
//     MarkConsumed has succeeded, the pending row is gone but the
//     user is unmodified — the operator restarts the enrolment.
//     The lost pending row is acceptable; pending rows are
//     short-lived ephemera.
func (s *MFAEnrollmentService) Complete(ctx context.Context, pendingID uuid.UUID, code string) (*MFAEnrollmentCompleteResult, error) {
	row, err := s.pending.GetByID(ctx, pendingID)
	if err != nil {
		if errors.Is(err, repository.ErrMFAPendingSessionNotFound) {
			return nil, ErrMFAEnrollmentNotFound
		}
		return nil, ErrMFAEnrollmentInvalid
	}
	if ok, _ := row.CanBeUsed(s.now(), domain.MFAPendingKindEnroll); !ok {
		if row.ConsumedAt != nil {
			return nil, ErrMFAEnrollmentAlreadyConsumed
		}
		if !row.ExpiresAt.After(s.now()) {
			return nil, ErrMFAEnrollmentExpired
		}
		return nil, ErrMFAEnrollmentInvalid
	}
	if row.Secret == nil || *row.Secret == "" {
		// /initiate was never called for this handle.
		return nil, ErrMFAEnrollmentInvalid
	}
	// row.Secret holds the AES-256-GCM ciphertext of the candidate seed.
	// Decrypt it to verify the TOTP code; fail-closed if the cipher is
	// unavailable. The ciphertext (not the plaintext) is persisted onto the
	// user below.
	plaintextSeed, decErr := s.decryptSeed(*row.Secret)
	if decErr != nil {
		return nil, decErr
	}
	if !verifyTOTPCodeAgainstSecret(plaintextSeed, code, s.now()) {
		return nil, ErrMFAEnrollmentInvalid
	}
	ok, err := s.pending.MarkConsumed(ctx, pendingID, s.now())
	if err != nil {
		return nil, fmt.Errorf("service: mfa pending mark consumed: %w", err)
	}
	if !ok {
		return nil, ErrMFAEnrollmentAlreadyConsumed
	}
	user, err := s.users.GetByID(ctx, row.UserID)
	if err != nil || user == nil {
		return nil, ErrMFAEnrollmentInvalid
	}
	if user.Banned || user.DeletedAt != nil {
		return nil, ErrMFAEnrollmentInvalid
	}
	enabled := true
	secret := *row.Secret
	updated, err := s.users.Update(ctx, user.ID, user.OrganizationID, repository.UpdateUserOptions{
		MFAEnabled:       &enabled,
		MFASecret:        &secret,
		MFARecoveryCodes: row.RecoveryCodes,
	})
	if err != nil {
		return nil, fmt.Errorf("service: mfa pending persist: %w", err)
	}
	if updated == nil {
		return nil, ErrMFAEnrollmentInvalid
	}
	return &MFAEnrollmentCompleteResult{
		User:       updated,
		RememberMe: row.RememberMe,
	}, nil
}

// VerifyAndConsume drives the /api/v1/auth/login/mfa endpoint for
// already-enrolled users. Behaviour:
//
//   - Looks up the pending row by pendingID. Must be kind=verify.
//   - Verifies the supplied code against the user's persisted
//     MFASecret as a TOTP code. If TOTP verification fails, the
//     same code is checked against the user's persisted
//     MFARecoveryCodes via consumeRecoveryCode (constant-time).
//   - On TOTP success, MarkConsumed atomically claims the row and
//     returns the user unchanged.
//   - On recovery-code success, MarkConsumed atomically claims the
//     row AND a UserRepository.Update burns the matched code from
//     MFARecoveryCodes (MFAEnabled stays true; MFASecret stays
//     unchanged). The result carries RecoveryCodeUsed=true so the
//     HTTP layer can emit a distinct audit action.
//
// Replay safety mirrors Complete. The raw recovery code is NEVER
// logged, returned, included in errors, or surfaced via the
// result fields.
func (s *MFAEnrollmentService) VerifyAndConsume(ctx context.Context, pendingID uuid.UUID, code string) (*MFAEnrollmentCompleteResult, error) {
	row, err := s.pending.GetByID(ctx, pendingID)
	if err != nil {
		if errors.Is(err, repository.ErrMFAPendingSessionNotFound) {
			return nil, ErrMFAEnrollmentNotFound
		}
		return nil, ErrMFAEnrollmentInvalid
	}
	if ok, _ := row.CanBeUsed(s.now(), domain.MFAPendingKindVerify); !ok {
		if row.ConsumedAt != nil {
			return nil, ErrMFAEnrollmentAlreadyConsumed
		}
		if !row.ExpiresAt.After(s.now()) {
			return nil, ErrMFAEnrollmentExpired
		}
		return nil, ErrMFAEnrollmentInvalid
	}
	user, err := s.users.GetByID(ctx, row.UserID)
	if err != nil || user == nil {
		return nil, ErrMFAEnrollmentInvalid
	}
	if user.Banned || user.DeletedAt != nil {
		return nil, ErrMFAEnrollmentInvalid
	}
	if !user.MFAEnabled || user.MFASecret == nil || *user.MFASecret == "" {
		// The user is no longer in the enrolled state; the pending
		// row is no longer redeemable as verify-kind.
		return nil, ErrMFAEnrollmentInvalid
	}
	var (
		recoveryUsed     bool
		recoveryCodeHash string
	)
	// user.MFASecret is AES-256-GCM ciphertext; decrypt to verify TOTP.
	// A cipher/decrypt failure leaves totpOK=false (fail-closed for TOTP)
	// and falls through to the hash-matched recovery-code path, which needs
	// no cipher.
	totpOK := false
	if plaintextSeed, decErr := s.decryptSeed(*user.MFASecret); decErr == nil {
		totpOK = verifyTOTPCodeAgainstSecret(plaintextSeed, code, s.now())
	}
	if !totpOK {
		// TOTP did not match; fall back to the recovery-code list.
		// consumeRecoveryCode returns ok=false when the list is
		// nil/empty OR the code does not match any entry. The wire
		// NEVER distinguishes "wrong TOTP" from "wrong recovery
		// code" — both collapse to ErrMFAEnrollmentInvalid.
		// The in-memory match runs FIRST so a wrong code is rejected WITHOUT
		// burning the pending handle; the atomic per-code claim below (P0-11)
		// then handles concurrency (two handles racing the same valid code).
		if _, ok := consumeRecoveryCode(user.MFARecoveryCodes, code); !ok {
			// WRONG GUESS (both TOTP and recovery-code failed). P0-13: the
			// handle previously survived this branch untouched, so an
			// attacker holding a valid verify handle could guess six-digit
			// codes without limit for the handle's whole lifetime — a live
			// MFA bypass. Count this guess against the handle; at the
			// threshold the SAME statement invalidates it, forcing password
			// re-auth to obtain a fresh handle. FAIL CLOSED: a counter-store
			// error rejects the verification (returns a non-sentinel error →
			// 500) rather than letting an uncounted guess through — the
			// opposite of LoginRiskService's fail-open password-lockout
			// posture, deliberately, because this counter IS the MFA
			// brute-force bound.
			if _, recErr := s.pending.RecordFailedVerifyAttempt(ctx, pendingID, s.maxVerifyAttempts, s.now()); recErr != nil {
				return nil, fmt.Errorf("service: mfa record failed verify attempt: %w", recErr)
			}
			return nil, ErrMFAEnrollmentInvalid
		}
		recoveryUsed = true
		recoveryCodeHash = crypto.HashSecret(strings.TrimSpace(code))
	}
	ok, err := s.pending.MarkConsumed(ctx, pendingID, s.now())
	if err != nil {
		return nil, fmt.Errorf("service: mfa pending mark consumed: %w", err)
	}
	if !ok {
		return nil, ErrMFAEnrollmentAlreadyConsumed
	}
	remainingRecoveryCodes := 0
	if recoveryUsed {
		// P0-11: atomic per-code claim — remove THIS code only while it is still
		// present. A concurrent pending handle that already redeemed the same
		// code gets consumed=false → reject, so two DISTINCT handles cannot
		// redeem the same recovery code. Replaces the prior blind read-modify-
		// write of the whole recovery-code slice.
		updated, consumed, updErr := s.users.ConsumeRecoveryCode(ctx, user.ID, recoveryCodeHash)
		if updErr != nil {
			return nil, fmt.Errorf("service: mfa recovery code consume: %w", updErr)
		}
		if !consumed {
			return nil, ErrMFAEnrollmentInvalid
		}
		user = updated
		remainingRecoveryCodes = len(user.MFARecoveryCodes)
	}
	return &MFAEnrollmentCompleteResult{
		User:                   user,
		RememberMe:             row.RememberMe,
		RecoveryCodeUsed:       recoveryUsed,
		RemainingRecoveryCodes: remainingRecoveryCodes,
	}, nil
}

// RegenerateRecoveryCodes mints a fresh set of MFA recovery codes
// for the supplied user and persists them, replacing every
// previously stored code in one UPDATE. MFAEnabled and MFASecret
// are NOT touched — only mfa_recovery_codes is mutated. The fresh
// list is returned EXACTLY ONCE; the service has no recovery path
// once the response is gone.
//
// Authority: the HTTP handler MUST resolve userID from the
// authenticated principal and call this method with that id only.
// The service itself does not perform any actor check — it trusts
// the caller's authentication gate. This mirrors the existing
// /api/v1/profile + /api/v1/me/roles convention where the route
// middleware (RequireAuthenticated) plus the handler's reading of
// mw.PrincipalFromContext is the only same-user enforcement.
//
// Mappings:
//
//   - uuid.Nil userID → ErrMFAEnrollmentInvalid (programmer
//     error — the handler must never call with an empty id).
//   - user not found / banned / soft-deleted → ErrMFAEnrollmentInvalid.
//     The wire layer collapses this onto the same opaque sentinel
//     family the rest of the MFA flow uses, so a stale principal
//     cannot probe account state.
//   - MFAEnabled=false → ErrMFANotEnrolled. Distinct because the
//     wire layer maps it to a separate 400 mfa_not_enrolled so the
//     UI can show the right call-to-action ("enroll first").
//   - codes generation failure → wrapped error (rare;
//     crypto/rand exhaustion).
//   - persistence failure → wrapped error.
//
// Code count + byte length match the service's enrolment defaults
// (10 codes, 5 raw bytes each → 8 base32 chars) so an operator's
// muscle memory does not change between enrolment and
// regeneration.
//
// SAFETY: the raw codes are NEVER logged, returned in errors, or
// included in any audit/metadata path inside this method. The
// only escape route is the slice the method returns to the HTTP
// handler.
func (s *MFAEnrollmentService) RegenerateRecoveryCodes(ctx context.Context, userID uuid.UUID) ([]string, error) {
	if userID == uuid.Nil {
		return nil, ErrMFAEnrollmentInvalid
	}
	user, err := s.users.GetByID(ctx, userID)
	if err != nil || user == nil {
		return nil, ErrMFAEnrollmentInvalid
	}
	if user.Banned || user.DeletedAt != nil {
		return nil, ErrMFAEnrollmentInvalid
	}
	if !user.MFAEnabled {
		return nil, ErrMFANotEnrolled
	}
	codes, err := generateRecoveryCodes(s.codeCount, s.codeBytes)
	if err != nil {
		return nil, fmt.Errorf("service: mfa recovery codes regenerate: %w", err)
	}
	// Defensive: write a NON-NIL empty slice when the generator
	// returns nothing so the column is committed as `[]` rather
	// than left untouched (the pgx Update path only writes the
	// column when MFARecoveryCodes is non-nil; an unexpected
	// generator failure that returns nil would silently keep the
	// old codes). The generator only returns nil on a config
	// error that we already guard with codeCount>0 at
	// construction, but the belt-and-braces write costs nothing.
	// Persist the HASHED codes (never plaintext); return the plaintext set
	// exactly once for one-time display.
	persisted := hashRecoveryCodes(codes)
	if persisted == nil {
		persisted = []string{}
	}
	updated, err := s.users.Update(ctx, user.ID, user.OrganizationID, repository.UpdateUserOptions{
		MFARecoveryCodes: persisted,
	})
	if err != nil {
		return nil, fmt.Errorf("service: mfa recovery codes persist: %w", err)
	}
	if updated == nil {
		return nil, ErrMFAEnrollmentInvalid
	}
	return codes, nil
}

// DisableSelf disables MFA for the supplied user after verifying a
// fresh TOTP code OR one valid recovery code. It is the compatibility
// wrapper for the original code-only contract; callers that also
// accept a current password should call DisableSelfWithProof.
func (s *MFAEnrollmentService) DisableSelf(ctx context.Context, userID uuid.UUID, code string) (MFADisableReauthMethod, error) {
	return s.DisableSelfWithProof(ctx, userID, MFADisableSelfInput{Code: code})
}

// DisableSelfWithProof disables MFA for the supplied user after
// verifying a fresh TOTP code, one valid recovery code, OR the
// authenticated local user's current password. The HTTP handler MUST
// resolve userID from the authenticated principal (no actor check is
// performed in the service — mirrors the convention established by
// RegenerateRecoveryCodes / GetMFAStatus).
//
// Order of checks (every short-circuit returns BEFORE any state
// mutation, so a denied call leaves the user row byte-identical):
//
//  1. uuid.Nil userID → ErrMFAEnrollmentInvalid.
//  2. user missing / banned / soft-deleted → ErrMFAEnrollmentInvalid.
//  3. !MFAEnabled → ErrMFANotEnrolled.
//  4. IsMFARequiredForUser(user) → ErrMFADisableForbiddenByPolicy
//     (site_admin / org_admin / mfa_policy="required" → blocked).
//  5. non-empty code: TOTP/recovery-code proof is authoritative.
//     Password is ignored even when present.
//  6. empty code + non-empty password: verify current password.
//  7. empty code + empty password → ErrMFADisableInvalidCode.
//  8. TOTP first: verifyTOTPCodeAgainstSecret(user.MFASecret, code).
//     On match → reauthMethod=MFADisableReauthTOTP, proceed to
//     ResetMFA.
//  9. On TOTP miss, recovery-code fallback:
//     consumeRecoveryCode(user.MFARecoveryCodes, code). On match →
//     reauthMethod=MFADisableReauthRecoveryCode; burn the matched
//     code FIRST (an Update that writes the remaining list), THEN
//     run the final ResetMFA so a downstream failure cannot leave
//     a reusable code on the row.
//  10. Neither leg matched OR password did not verify →
//     ErrMFADisableInvalidCode.
//
// On success, the user row has MFAEnabled=false, MFASecret="", and
// MFARecoveryCodes=[]. Unrelated columns (password hash, role,
// organization, email, banned/email-verified, activation /
// verification tokens) are NOT in the Update payload so they are
// preserved exactly.
//
// SAFETY: the supplied code and password are NEVER logged, returned,
// or echoed in any error string. The MFASecret is NEVER returned. The
// matched recovery code is NEVER returned (only burned). The method's
// only escape route is the typed MFADisableReauthMethod return value
// plus the documented sentinel error set.
func (s *MFAEnrollmentService) DisableSelfWithProof(ctx context.Context, userID uuid.UUID, in MFADisableSelfInput) (MFADisableReauthMethod, error) {
	if userID == uuid.Nil {
		return "", ErrMFAEnrollmentInvalid
	}
	user, err := s.users.GetByID(ctx, userID)
	if err != nil || user == nil {
		return "", ErrMFAEnrollmentInvalid
	}
	if user.Banned || user.DeletedAt != nil {
		return "", ErrMFAEnrollmentInvalid
	}
	if !user.MFAEnabled {
		return "", ErrMFANotEnrolled
	}
	if IsMFARequiredForUser(user) {
		return "", ErrMFADisableForbiddenByPolicy
	}
	var reauth MFADisableReauthMethod
	trimmedCode := strings.TrimSpace(in.Code)
	if trimmedCode != "" {
		// Decrypt the at-rest seed ciphertext to verify TOTP; a cipher/
		// decrypt failure leaves totpOK=false and falls through to the
		// hash-matched recovery-code leg (no cipher needed).
		totpOK := false
		if user.MFASecret != nil && *user.MFASecret != "" {
			if plaintextSeed, decErr := s.decryptSeed(*user.MFASecret); decErr == nil {
				totpOK = verifyTOTPCodeAgainstSecret(plaintextSeed, trimmedCode, s.now())
			}
		}
		if totpOK {
			reauth = MFADisableReauthTOTP
		} else {
			remaining, ok := consumeRecoveryCode(user.MFARecoveryCodes, trimmedCode)
			if !ok {
				return "", ErrMFADisableInvalidCode
			}
			reauth = MFADisableReauthRecoveryCode
			// Burn the matched recovery code first. The final ResetMFA
			// below clears the whole list anyway, but a transient
			// failure between these two writes must not leave the
			// matched code reusable on the row.
			persisted := remaining
			if persisted == nil {
				persisted = []string{}
			}
			if _, burnErr := s.users.Update(ctx, user.ID, user.OrganizationID, repository.UpdateUserOptions{
				MFARecoveryCodes: persisted,
			}); burnErr != nil {
				return "", fmt.Errorf("service: mfa disable burn recovery code: %w", burnErr)
			}
		}
	} else {
		if strings.TrimSpace(in.Password) == "" {
			return "", ErrMFADisableInvalidCode
		}
		if err := s.verifyCurrentPasswordForStepUp(ctx, user, in.Password); err != nil {
			return "", ErrMFADisableInvalidCode
		}
		reauth = MFADisableReauthPassword
	}
	// Clear the MFA fields. Mirrors UserService.ResetMFA exactly —
	// MFAEnabled=false, MFASecret="", MFARecoveryCodes=[]. We
	// deliberately do not call UserService.ResetMFA from here to
	// keep the MFAEnrollmentService standalone (no new service
	// dependency on UserService); the Update payload is identical
	// so the on-disk result is the same.
	disabled := false
	secretCleared := ""
	updated, err := s.users.Update(ctx, user.ID, user.OrganizationID, repository.UpdateUserOptions{
		MFAEnabled:       &disabled,
		MFASecret:        &secretCleared,
		MFARecoveryCodes: []string{},
	})
	if err != nil {
		return "", fmt.Errorf("service: mfa disable persist: %w", err)
	}
	if updated == nil {
		return "", ErrMFAEnrollmentInvalid
	}
	return reauth, nil
}

func (s *MFAEnrollmentService) verifyCurrentPasswordForStepUp(ctx context.Context, user *domain.User, password string) error {
	if user == nil || strings.TrimSpace(password) == "" {
		return ErrMFADisableInvalidCode
	}
	if user.AuthSource != "" && user.AuthSource != domain.AuthSourceLocal {
		return ErrMFADisableInvalidCode
	}
	if strings.TrimSpace(user.PasswordHash) == "" {
		return ErrMFADisableInvalidCode
	}
	if err := s.users.VerifyPassword(ctx, password, user.PasswordHash); err != nil {
		return ErrMFADisableInvalidCode
	}
	return nil
}

// MFAStatus is the safe self-service projection returned by
// GetMFAStatus. Every field is a derived, NON-SECRET observation
// of the user row — no MFASecret, otpauth URL, recovery code
// values, or any other secret material may be added to this
// struct under any future change.
type MFAStatus struct {
	// MFAEnabled mirrors users.mfa_enabled directly.
	MFAEnabled bool
	// RecoveryCodesRemaining is the length of the user's stored
	// recovery-code slice. NEVER the code values themselves.
	RecoveryCodesRemaining int
	// TOTPEnrolled is true when MFAEnabled is true AND a non-empty
	// MFASecret is stored on the user row. The bool surfaces "the
	// TOTP authenticator is wired" without exposing the secret
	// itself; the UI can use it to render "Authenticator app:
	// configured / not configured" without a round-trip through
	// the MFA disable flow.
	TOTPEnrolled bool
}

// GetMFAStatus returns the safe self-service projection of the
// supplied user's MFA configuration. The HTTP handler MUST resolve
// userID from the authenticated principal — no actor check is
// performed inside the service (mirrors the convention established
// by RegenerateRecoveryCodes: the route middleware +
// mw.PrincipalFromContext is the only same-user enforcement).
//
// Mappings:
//
//   - uuid.Nil userID → ErrMFAEnrollmentInvalid (programmer
//     error — the handler must never call with an empty id).
//   - user not found / banned / soft-deleted → ErrMFAEnrollmentInvalid.
//     The wire layer collapses this onto the same opaque 401 the
//     rest of the /me MFA surface uses so a stale principal cannot
//     probe account state.
//
// SAFETY: the returned struct is the ONLY escape route. No raw
// secret, no recovery code, no otpauth URL, and no persistence
// detail ever leaks through this method. The user row read is
// scoped to the three documented fields.
func (s *MFAEnrollmentService) GetMFAStatus(ctx context.Context, userID uuid.UUID) (*MFAStatus, error) {
	if userID == uuid.Nil {
		return nil, ErrMFAEnrollmentInvalid
	}
	user, err := s.users.GetByID(ctx, userID)
	if err != nil || user == nil {
		return nil, ErrMFAEnrollmentInvalid
	}
	if user.Banned || user.DeletedAt != nil {
		return nil, ErrMFAEnrollmentInvalid
	}
	return &MFAStatus{
		MFAEnabled:             user.MFAEnabled,
		RecoveryCodesRemaining: len(user.MFARecoveryCodes),
		TOTPEnrolled:           user.MFAEnabled && user.MFASecret != nil && *user.MFASecret != "",
	}, nil
}

// generateBase32Secret returns a fresh crypto/rand-sourced base32-
// encoded secret of `byteLen` raw bytes. Base32 NoPad encoding is
// the format authenticator apps expect inside otpauth URLs.
func generateBase32Secret(byteLen int) (string, error) {
	if byteLen <= 0 {
		return "", errors.New("service: secret byte length must be positive")
	}
	buf := make([]byte, byteLen)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(buf), nil
}

// generateRecoveryCodes returns n fresh crypto/rand-sourced base32
// codes of `byteLen` raw bytes each. The PLAINTEXT codes are shown to
// the operator EXACTLY ONCE (the caller's return value); only their
// SHA-256 hashes (hashRecoveryCodes) are persisted on the pending row +
// the user, and consumeRecoveryCode matches by hash at rest.
func generateRecoveryCodes(n, byteLen int) ([]string, error) {
	if n <= 0 || byteLen <= 0 {
		return nil, errors.New("service: recovery code count and byte length must be positive")
	}
	codes := make([]string, 0, n)
	for range n {
		c, err := generateBase32Secret(byteLen)
		if err != nil {
			return nil, err
		}
		codes = append(codes, c)
	}
	return codes, nil
}

// encryptSeed encrypts a plaintext TOTP seed for at-rest storage. FAIL-CLOSED:
// a nil/unavailable cipher (missing or invalid MFA encryption key) returns an
// error so NO plaintext seed is ever persisted — this is the MFA at-rest
// invariant, never a plaintext fallback.
func (s *MFAEnrollmentService) encryptSeed(plaintext string) (string, error) {
	if s.cipher == nil {
		return "", ErrMFASecretUnavailable
	}
	ct, err := s.cipher.Encrypt(plaintext)
	if err != nil {
		return "", ErrMFASecretUnavailable
	}
	return ct, nil
}

// decryptSeed decrypts an at-rest TOTP seed ciphertext for verification.
// FAIL-CLOSED: a nil cipher or a decrypt failure returns an error (opaque).
func (s *MFAEnrollmentService) decryptSeed(ciphertext string) (string, error) {
	if s.cipher == nil {
		return "", ErrMFASecretUnavailable
	}
	pt, err := s.cipher.Decrypt(ciphertext)
	if err != nil {
		return "", ErrMFASecretUnavailable
	}
	return pt, nil
}

// hashRecoveryCodes maps each plaintext recovery code to its SHA-256
// at-rest hash (crypto.HashSecret) for storage. The plaintext codes are
// shown to the operator EXACTLY ONCE by the caller (Initiate /
// RegenerateRecoveryCodes return value); only these hashes are persisted.
func hashRecoveryCodes(plain []string) []string {
	hashed := make([]string, len(plain))
	for i, c := range plain {
		hashed[i] = crypto.HashSecret(c)
	}
	return hashed
}

// buildOtpauthURL constructs the standard otpauth URI an
// authenticator app expects. The label is `<issuer>:<email>`; the
// `issuer` query parameter mirrors the label namespace per RFC
// 6238 §4 (key URI format de-facto standard).
//
// SAFETY: the resulting URL contains the secret bytes. Callers
// MUST NOT log this string. The HTTP handler returns it ONCE in
// the response body for QR-display purposes.
func buildOtpauthURL(issuer, email, secret string) string {
	encIssuer := url.QueryEscape(issuer)
	encEmail := url.QueryEscape(email)
	v := url.Values{}
	v.Set("secret", secret)
	v.Set("issuer", issuer)
	v.Set("algorithm", "SHA1")
	v.Set("digits", "6")
	v.Set("period", "30")
	return fmt.Sprintf("otpauth://totp/%s:%s?%s", encIssuer, encEmail, v.Encode())
}

// verifyTOTPCodeAgainstSecret runs the RFC 6238 verification
// against the supplied secret. Mirrors MFAVerifierService.Verify's
// validation block but takes a raw secret (so it can verify against
// a pending-row candidate or a user's persisted secret without
// caring which). Window is hard-coded to ±1 step here — matches
// MFAVerifierService's default. Constant-time compare prevents
// timing leaks.
func verifyTOTPCodeAgainstSecret(secret, code string, now time.Time) bool {
	trimmed := strings.TrimSpace(code)
	if len(trimmed) != defaultTOTPDigits {
		return false
	}
	key, err := decodeBase32Secret(secret)
	if err != nil {
		return false
	}
	// Shared RFC 6238 ±1-step window match (constant-time across the
	// window) — same primitive MFAVerifierService.Verify uses.
	_, ok := totp.Match(key, trimmed, now, totp.Options{
		Period: defaultTOTPPeriod,
		Digits: defaultTOTPDigits,
		Window: defaultTOTPWindow,
	})
	return ok
}

// constantTimeEqualString is the package-local constant-time string
// comparison used by the recovery-code matcher (consumeRecoveryCode).
// Mirrors subtle.ConstantTimeCompare but avoids importing crypto/subtle a
// second time at that call site.
func constantTimeEqualString(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range len(a) {
		v |= a[i] ^ b[i]
	}
	return v == 0
}

// consumeRecoveryCode walks `codes` looking for a constant-time
// match against the supplied candidate. On match, it returns a
// copy of the list with the matched entry removed (order of the
// remaining entries is preserved) and ok=true. On no-match (or
// empty/nil input or empty candidate) it returns nil, false.
//
// The function NEVER logs or returns the candidate or any stored
// code. The full slice is walked even after a match is found so
// the timing profile does not leak the position of the match.
func consumeRecoveryCode(codes []string, candidate string) ([]string, bool) {
	trimmed := strings.TrimSpace(candidate)
	if trimmed == "" || len(codes) == 0 {
		return nil, false
	}
	// At-rest hashing (MFA recovery codes are stored as SHA-256 hashes, not
	// raw): hash the presented candidate and constant-time-compare against
	// the stored hashes. The full slice is still walked after a match so the
	// timing profile does not leak the match position.
	candidateHash := crypto.HashSecret(trimmed)
	matchedIdx := -1
	for i, h := range codes {
		if constantTimeEqualString(h, candidateHash) && matchedIdx < 0 {
			matchedIdx = i
		}
	}
	if matchedIdx < 0 {
		return nil, false
	}
	remaining := make([]string, 0, len(codes)-1)
	remaining = append(remaining, codes[:matchedIdx]...)
	remaining = append(remaining, codes[matchedIdx+1:]...)
	return remaining, true
}
