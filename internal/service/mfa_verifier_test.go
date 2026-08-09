package service

import (
	"context"
	"encoding/base32"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// ---------- helper ----------

func freshTOTPSecret(t *testing.T) string {
	t.Helper()
	// 20-byte secret → base32 length 32.
	const raw = "ABCDEFGHIJKLMNOPQRST"
	return base32.StdEncoding.EncodeToString([]byte(raw))
}

func userWithMFA(secret string) *domain.User {
	s := secret
	return &domain.User{
		MFAEnabled: true,
		MFASecret:  &s,
	}
}

// ---------- Construction ----------

func TestNewMFAVerifierService_NilResolverPanics(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("nil resolver did not panic")
		}
	}()
	_ = NewMFAVerifierService(nil, nil, MFAVerifierOptions{})
}

// ---------- Verify ----------

func TestVerify_NilUserIsInvalid(t *testing.T) {
	svc := NewMFAVerifierService(nil, PlaintextTOTPSecretResolver{}, MFAVerifierOptions{})
	if err := svc.Verify(context.Background(), nil, "123456"); !errors.Is(err, ErrMFAInvalid) {
		t.Errorf("err = %v", err)
	}
}

func TestVerify_MFADisabledReturnsNotEnabled(t *testing.T) {
	svc := NewMFAVerifierService(nil, PlaintextTOTPSecretResolver{}, MFAVerifierOptions{})
	u := &domain.User{MFAEnabled: false}
	if err := svc.Verify(context.Background(), u, "000000"); !errors.Is(err, ErrMFANotEnabled) {
		t.Errorf("err = %v", err)
	}
}

func TestVerify_MFAEnabledMissingCodeIsRequired(t *testing.T) {
	svc := NewMFAVerifierService(nil, PlaintextTOTPSecretResolver{}, MFAVerifierOptions{})
	secret := freshTOTPSecret(t)
	u := userWithMFA(secret)
	if err := svc.Verify(context.Background(), u, ""); !errors.Is(err, ErrMFARequired) {
		t.Errorf("err = %v", err)
	}
}

func TestVerify_MFASecretMissingIsUnavailable(t *testing.T) {
	svc := NewMFAVerifierService(nil, PlaintextTOTPSecretResolver{}, MFAVerifierOptions{})
	u := &domain.User{MFAEnabled: true, MFASecret: nil}
	if err := svc.Verify(context.Background(), u, "123456"); !errors.Is(err, ErrMFASecretUnavailable) {
		t.Errorf("err = %v", err)
	}
}

func TestVerify_WrongLengthRejected(t *testing.T) {
	svc := NewMFAVerifierService(nil, PlaintextTOTPSecretResolver{}, MFAVerifierOptions{})
	secret := freshTOTPSecret(t)
	u := userWithMFA(secret)
	if err := svc.Verify(context.Background(), u, "12345"); !errors.Is(err, ErrMFAInvalid) {
		t.Errorf("err = %v", err)
	}
}

func TestVerify_ValidCodeAccepted(t *testing.T) {
	svc := NewMFAVerifierService(nil, PlaintextTOTPSecretResolver{}, MFAVerifierOptions{})
	secret := freshTOTPSecret(t)
	u := userWithMFA(secret)
	frozen := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	svc.now = func() time.Time { return frozen }
	counter := uint64(frozen.Unix()) / uint64(defaultTOTPPeriod)
	expected, _ := computeHOTP(secret, counter, 6)
	if err := svc.Verify(context.Background(), u, expected); err != nil {
		t.Errorf("valid code rejected: %v", err)
	}
}

func TestVerify_PreviousWindowAccepted(t *testing.T) {
	svc := NewMFAVerifierService(nil, PlaintextTOTPSecretResolver{}, MFAVerifierOptions{Window: 1})
	secret := freshTOTPSecret(t)
	u := userWithMFA(secret)
	frozen := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	svc.now = func() time.Time { return frozen }
	prevCounter := uint64(frozen.Unix())/uint64(defaultTOTPPeriod) - 1
	expected, _ := computeHOTP(secret, prevCounter, 6)
	if err := svc.Verify(context.Background(), u, expected); err != nil {
		t.Errorf("previous-window code rejected: %v", err)
	}
}

func TestVerify_OutsideWindowRejected(t *testing.T) {
	svc := NewMFAVerifierService(nil, PlaintextTOTPSecretResolver{}, MFAVerifierOptions{Window: 1})
	secret := freshTOTPSecret(t)
	u := userWithMFA(secret)
	frozen := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	svc.now = func() time.Time { return frozen }
	farCounter := uint64(frozen.Unix())/uint64(defaultTOTPPeriod) + 10
	expected, _ := computeHOTP(secret, farCounter, 6)
	if err := svc.Verify(context.Background(), u, expected); !errors.Is(err, ErrMFAInvalid) {
		t.Errorf("out-of-window code accepted: %v", err)
	}
}

// TestVerify_DefaultOptionsAcceptsPreviousWindow is the P2-23 teeth: the
// ZERO-VALUE MFAVerifierOptions{} (what runtime.go:892 passes in production)
// MUST yield the documented ±1 skew window, so a code from the PREVIOUS step
// (prevCounter = current-1) is accepted. This is the phone-one-step-off /
// 30 s-boundary case the inline-code login path was silently rejecting.
//
// TEETH: revert NewMFAVerifierService's guard from `window <= 0` back to
// `window < 0` → the zero value stays window 0 (exact step only) → this
// previous-window code is rejected → this test FAILS.
func TestVerify_DefaultOptionsAcceptsPreviousWindow(t *testing.T) {
	svc := NewMFAVerifierService(nil, PlaintextTOTPSecretResolver{}, MFAVerifierOptions{})
	secret := freshTOTPSecret(t)
	u := userWithMFA(secret)
	frozen := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	svc.now = func() time.Time { return frozen }
	prevCounter := uint64(frozen.Unix())/uint64(defaultTOTPPeriod) - 1
	expected, _ := computeHOTP(secret, prevCounter, 6)
	if err := svc.Verify(context.Background(), u, expected); err != nil {
		t.Errorf("default options rejected a previous-window code (window defaulted to 0, not ±1): %v", err)
	}
}

// TestVerify_DefaultOptionsRejectsOutsideWindow pins that the zero-value
// default is EXACTLY ±1, not wider: a code two steps back (current-2) — the
// tightest position just outside the ±1 window — is rejected.
func TestVerify_DefaultOptionsRejectsOutsideWindow(t *testing.T) {
	svc := NewMFAVerifierService(nil, PlaintextTOTPSecretResolver{}, MFAVerifierOptions{})
	secret := freshTOTPSecret(t)
	u := userWithMFA(secret)
	frozen := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	svc.now = func() time.Time { return frozen }
	outsideCounter := uint64(frozen.Unix())/uint64(defaultTOTPPeriod) - 2
	expected, _ := computeHOTP(secret, outsideCounter, 6)
	if err := svc.Verify(context.Background(), u, expected); !errors.Is(err, ErrMFAInvalid) {
		t.Errorf("default options accepted a code 2 steps out (window wider than ±1): %v", err)
	}
}

func TestVerify_ErrorPathDoesNotLeakSecretOrCode(t *testing.T) {
	svc := NewMFAVerifierService(nil, PlaintextTOTPSecretResolver{}, MFAVerifierOptions{})
	const secret = "RAW-SECRET-MUST-NOT-LEAK"
	const code = "RAW-CODE-MUST-NOT-LEAK"
	u := userWithMFA(secret)
	err := svc.Verify(context.Background(), u, code)
	if err == nil {
		t.Fatalf("expected error")
	}
	msg := err.Error()
	if strings.Contains(msg, secret) || strings.Contains(msg, code) {
		t.Errorf("error message leaked secret or code: %q", msg)
	}
}
