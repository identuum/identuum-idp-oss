// Package service — MFAVerifierService is the OSS-resident TOTP
// verifier that the local-login path consults before issuing a
// session for an MFA-enabled user. It implements RFC 6238 TOTP
// (HMAC-SHA1 over an 8-byte counter derived from the Unix epoch /
// step interval) inline so no new third-party dependency lands in
// OSS for this slice.
//
// Secret-storage seam: the monolith's MFAService.Validate decrypts
// the stored MFASecret via an internal CryptoService. OSS does NOT
// ship that CryptoService. To keep the verifier composable without
// silently regressing security, the service consumes a
// TOTPSecretResolver interface:
//
//   - PlaintextTOTPSecretResolver — ships in this package; treats
//     the stored MFASecret column verbatim as the base32 TOTP
//     secret. OSS deployments that use this resolver MUST ensure
//     the column is encrypted at rest (Postgres / KMS / disk
//     encryption) — the column is no longer in-application
//     encrypted.
//
//   - CE-side resolvers can wrap the OSS verifier with their own
//     decryptor; the public Resolve(ctx, user) signature is small
//     enough to satisfy with any field-level decryptor design.
//
// What the verifier WILL NOT do:
//
//   - Log or audit the TOTP secret.
//   - Log or audit the supplied code.
//   - Return the secret value in any error path.
//   - Touch recovery codes. Recovery-code consumption lives in
//     MFAEnrollmentService.VerifyAndConsume (the
//     /api/v1/auth/login/mfa pending-session path) so the burn
//     can be paired with the atomic MarkConsumed of the pending
//     row. The legacy single-step login that consults
//     MFAVerifierService stays TOTP-only.
package service

import (
	"context"
	"encoding/base32"
	"errors"
	"strings"
	"time"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/lifecycle"
	"github.com/identuum/identuum-idp-oss/pkg/totp"
)

// TOTPSecretResolver returns the plaintext base32-encoded TOTP
// secret for the supplied user. Implementations MUST NOT log the
// returned secret.
type TOTPSecretResolver interface {
	Resolve(ctx context.Context, user *domain.User) (string, error)
}

// PlaintextTOTPSecretResolver treats domain.User.MFASecret as the
// plaintext base32-encoded TOTP secret. OSS deployments that use
// this resolver MUST encrypt the users.mfa_secret column at rest
// at the storage layer (Postgres TDE / KMS / disk encryption).
//
// This is the OSS-safe default for operators that have not wired
// a CE field-level decryptor.
type PlaintextTOTPSecretResolver struct{}

// Resolve returns the user's stored MFASecret verbatim. Returns
// an error sentinel when the column is nil.
func (PlaintextTOTPSecretResolver) Resolve(_ context.Context, user *domain.User) (string, error) {
	if user == nil || user.MFASecret == nil || strings.TrimSpace(*user.MFASecret) == "" {
		return "", ErrMFASecretUnavailable
	}
	return *user.MFASecret, nil
}

// MFASecretCipher is the at-rest protection seam for MFA TOTP seeds.
// *crypto.CryptoService satisfies it (AES-256-GCM). The MFA write path
// encrypts the seed before persisting; the read path (the resolver, below)
// decrypts before TOTP verification. A nil cipher is fail-closed — the MFA
// path refuses rather than storing/reading plaintext (closing the
// at-rest regression). It NEVER falls back to plaintext.
type MFASecretCipher interface {
	Encrypt(plaintext string) (string, error)
	Decrypt(ciphertext string) (string, error)
}

// EncryptedTOTPSecretResolver decrypts the at-rest ciphertext stored in
// domain.User.MFASecret via the injected MFASecretCipher before returning the
// base32 TOTP secret. This is the OSS production resolver — it restores the
// all-tiers AES-256-GCM-at-rest invariant for MFA seeds. A nil cipher or a
// decrypt failure yields ErrMFASecretUnavailable (fail-closed, opaque).
type EncryptedTOTPSecretResolver struct {
	Cipher MFASecretCipher
}

// Resolve decrypts user.MFASecret and returns the plaintext base32 seed.
func (r EncryptedTOTPSecretResolver) Resolve(_ context.Context, user *domain.User) (string, error) {
	if user == nil || user.MFASecret == nil || strings.TrimSpace(*user.MFASecret) == "" {
		return "", ErrMFASecretUnavailable
	}
	if r.Cipher == nil {
		return "", ErrMFASecretUnavailable
	}
	plaintext, err := r.Cipher.Decrypt(*user.MFASecret)
	if err != nil || strings.TrimSpace(plaintext) == "" {
		return "", ErrMFASecretUnavailable
	}
	return plaintext, nil
}

// MFAVerifierService wraps a TOTPSecretResolver with the RFC 6238
// validation algorithm + a configurable clock-skew window.
type MFAVerifierService struct {
	resolver TOTPSecretResolver
	period   uint64
	digits   int
	window   int
	now      func() time.Time
}

// MFAVerifierOptions parameterises the verifier. Zero values fall
// back to the RFC 6238 §5.2 defaults (period 30 s, digits 6,
// skew window 1 step on either side).
type MFAVerifierOptions struct {
	Period uint64 // step interval in seconds. Default 30.
	Digits int    // code length. Default 6.
	Window int    // accepted ± steps. Default 1.
}

const (
	defaultTOTPPeriod = 30
	defaultTOTPDigits = 6
	defaultTOTPWindow = 1
)

// TOTPPeriodSeconds and TOTPWindowSteps EXPORT the verifier's own step size and
// skew tolerance so out-of-package tests can build the exact set of codes this
// verifier accepts, instead of mirroring the numbers by hand.
//
// internal/e2e previously hardcoded `const window = 1` and `/ 30` beside a
// comment asking the reader to keep them in step. A comment is not a mechanism:
// widening the window here would have left that test silently guessing inside
// the accepted set again — the exact defect that took three slices to close.
const (
	TOTPPeriodSeconds = defaultTOTPPeriod
	TOTPWindowSteps   = defaultTOTPWindow
)

// NewMFAVerifierService constructs the service. resolver is
// required; nil panics so a misconfigured deployment cannot
// silently accept any code.
func NewMFAVerifierService(report *lifecycle.StartupReport, resolver TOTPSecretResolver, opts MFAVerifierOptions) *MFAVerifierService {
	if resolver == nil {
		report.Fatal("NewMFAVerifierService", "service: NewMFAVerifierService requires a non-nil TOTPSecretResolver")
	}
	period := opts.Period
	if period == 0 {
		period = defaultTOTPPeriod
	}
	digits := opts.Digits
	if digits <= 0 {
		digits = defaultTOTPDigits
	}
	window := opts.Window
	// 0 → default (±1). The zero value MUST get the documented skew window:
	// the API exposes no "strict, no-skew" mode, and RFC 6238 §5.2 recommends
	// ±1 step as the minimum tolerance. Mirrors the `digits <= 0` default
	// above and verifyTOTPCodeAgainstSecret's hard-coded ±1. (A caller wanting
	// a wider window still passes an explicit positive Window.)
	if window <= 0 {
		window = defaultTOTPWindow
	}
	return &MFAVerifierService{
		resolver: resolver,
		period:   period,
		digits:   digits,
		window:   window,
		now:      time.Now,
	}
}

// Sentinel errors. The local-login service maps these to opaque
// wire responses (the wire NEVER distinguishes "wrong password"
// from "wrong TOTP" — only Login surfaces a separate
// ErrMFARequired so the caller can re-prompt).
var (
	// ErrMFANotEnabled is informational — returned to surface a
	// per-user check to a caller that wants to distinguish
	// "user has MFA on" from "user does not have MFA". The wire
	// layer NEVER returns this sentinel.
	ErrMFANotEnabled = errors.New("service: mfa not enabled for user")

	// ErrMFARequired is returned when the caller did NOT supply a
	// code but the user has MFA enabled. The wire layer maps this
	// to a structured 401 response that the UI uses to prompt for
	// a TOTP code.
	ErrMFARequired = errors.New("service: mfa required")

	// ErrMFASecretUnavailable is returned when the resolver cannot
	// produce a usable secret (missing column / decryption failure
	// / etc.). Treated as "MFA configured but unverifiable" — the
	// wire layer maps it to the same opaque 401 as ErrMFAInvalid.
	ErrMFASecretUnavailable = errors.New("service: mfa secret unavailable")

	// ErrMFAInvalid is the load-bearing sentinel: TOTP code does
	// not match the resolved secret within the configured skew
	// window. Wire layer maps to 401 with no detail.
	ErrMFAInvalid = errors.New("service: mfa invalid")
)

// Verify checks the supplied TOTP code against the user's
// resolved secret. Behavior:
//
//   - user == nil → ErrMFAInvalid (defensive).
//   - !user.MFAEnabled → ErrMFANotEnabled (informational only — the
//     login path treats this as "no MFA step needed").
//   - user.MFAEnabled && code == "" → ErrMFARequired.
//   - resolver returns an error → ErrMFASecretUnavailable.
//   - code does not match within window → ErrMFAInvalid.
//   - code matches → nil.
//
// The raw code and secret are NEVER logged or echoed.
func (s *MFAVerifierService) Verify(ctx context.Context, user *domain.User, code string) error {
	if user == nil {
		return ErrMFAInvalid
	}
	if !user.MFAEnabled {
		return ErrMFANotEnabled
	}
	trimmed := strings.TrimSpace(code)
	if trimmed == "" {
		return ErrMFARequired
	}
	secret, err := s.resolver.Resolve(ctx, user)
	if err != nil || secret == "" {
		return ErrMFASecretUnavailable
	}
	if len(trimmed) != s.digits {
		return ErrMFAInvalid
	}
	// Decode the base32 secret once, then delegate the RFC 6238 window
	// match to the shared pkg/totp. A decode failure keeps the existing
	// mapping (ErrMFASecretUnavailable); the match itself is constant-time
	// across the skew window.
	key, derr := decodeBase32Secret(secret)
	if derr != nil {
		return ErrMFASecretUnavailable
	}
	if _, ok := totp.Match(key, trimmed, s.now(), totp.Options{
		Period: s.period,
		Digits: s.digits,
		Window: s.window,
	}); ok {
		return nil
	}
	return ErrMFAInvalid
}

// decodeBase32Secret normalises and base32-decodes a TOTP shared secret to
// its raw key bytes. It accepts lower/upper case and space-separated
// secrets and re-pads to a multiple of 8 (some authenticator apps strip
// the '=' padding). Returns an error when the input is not valid base32.
// The HOTP/TOTP computation itself lives in the shared pkg/totp.
func decodeBase32Secret(secret string) ([]byte, error) {
	normalised := strings.ToUpper(strings.TrimSpace(secret))
	normalised = strings.ReplaceAll(normalised, " ", "")
	if pad := len(normalised) % 8; pad != 0 {
		normalised += strings.Repeat("=", 8-pad)
	}
	return base32.StdEncoding.DecodeString(normalised)
}

// computeHOTP decodes the base32 secret and returns the RFC 4226 / RFC 6238
// HOTP value for the supplied counter, delegating the truncation to the
// shared pkg/totp. Returns an error when the secret is not valid base32.
// It is retained as the in-package helper the service tests use to derive
// expected codes; production verification runs through totp.Match directly.
func computeHOTP(secret string, counter uint64, digits int) (string, error) {
	key, err := decodeBase32Secret(secret)
	if err != nil {
		return "", err
	}
	return totp.Code(key, counter, digits), nil
}
