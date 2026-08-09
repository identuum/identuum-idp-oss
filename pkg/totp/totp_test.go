package totp_test

import (
	"testing"
	"time"

	"github.com/identuum/identuum-idp-oss/pkg/totp"
)

// rfcKey is the RFC 6238 Appendix B SHA-1 test seed: the ASCII string
// "12345678901234567890" (20 bytes) used verbatim as the HMAC key.
var rfcKey = []byte("12345678901234567890")

// TestCode_RFC6238Vectors pins Code against the RFC 6238 Appendix B SHA-1
// worked examples (T0=0, step=30 s). Each vector's 8-digit value is the
// authoritative one; the 6-digit form must be its trailing 6 digits.
func TestCode_RFC6238Vectors(t *testing.T) {
	const period = 30
	cases := []struct {
		unixTime int64
		want8    string
	}{
		{59, "94287082"},
		{1111111109, "07081804"},
		{1111111111, "14050471"},
		{1234567890, "89005924"},
		{2000000000, "69279037"},
		// RFC also lists 20000000000 but that overflows a signed 32-bit
		// counter step in some references; the five above suffice to pin
		// the truncation + padding across leading-zero and full-width cases.
	}
	for _, tc := range cases {
		counter := uint64(tc.unixTime / period)

		got8 := totp.Code(rfcKey, counter, 8)
		if got8 != tc.want8 {
			t.Errorf("Code(8) at T=%d = %q, want %q", tc.unixTime, got8, tc.want8)
		}

		got6 := totp.Code(rfcKey, counter, 6)
		if want6 := tc.want8[len(tc.want8)-6:]; got6 != want6 {
			t.Errorf("Code(6) at T=%d = %q, want %q (last 6 of %q)", tc.unixTime, got6, want6, tc.want8)
		}
	}
}

// TestMatch covers the window semantics: an exact-now code matches and
// reports the current step; a one-step-back code matches with Window=1; a
// two-step-back code does NOT with Window=1; and a wrong code never does.
func TestMatch(t *testing.T) {
	const (
		period = 30
		digits = 6
	)
	now := time.Unix(1111111111, 0)
	stepNow := now.Unix() / period
	opts := totp.Options{Period: period, Digits: digits, Window: 1}

	t.Run("exact now matches, correct step", func(t *testing.T) {
		code := totp.Code(rfcKey, uint64(stepNow), digits)
		step, ok := totp.Match(rfcKey, code, now, opts)
		if !ok {
			t.Fatalf("exact-now code rejected")
		}
		if step != stepNow {
			t.Errorf("matched step = %d, want %d", step, stepNow)
		}
	})

	t.Run("one step back matches with window 1", func(t *testing.T) {
		code := totp.Code(rfcKey, uint64(stepNow-1), digits)
		step, ok := totp.Match(rfcKey, code, now, opts)
		if !ok {
			t.Fatalf("previous-step code rejected with window 1")
		}
		if step != stepNow-1 {
			t.Errorf("matched step = %d, want %d", step, stepNow-1)
		}
	})

	t.Run("two steps back rejected with window 1", func(t *testing.T) {
		code := totp.Code(rfcKey, uint64(stepNow-2), digits)
		if _, ok := totp.Match(rfcKey, code, now, opts); ok {
			t.Errorf("code two steps back accepted with window 1 (should be out of window)")
		}
	})

	t.Run("wrong code rejected", func(t *testing.T) {
		if _, ok := totp.Match(rfcKey, "000000", now, opts); ok {
			// Guard against the astronomically-unlikely case that 000000 is
			// the real code at this instant.
			real := totp.Code(rfcKey, uint64(stepNow), digits)
			if real != "000000" {
				t.Errorf("wrong code accepted")
			}
		}
	})

	t.Run("defensive guards", func(t *testing.T) {
		code := totp.Code(rfcKey, uint64(stepNow), digits)
		if _, ok := totp.Match(rfcKey, code, now, totp.Options{Period: 0, Digits: digits, Window: 1}); ok {
			t.Errorf("Period=0 should return false")
		}
		if _, ok := totp.Match(rfcKey, code, now, totp.Options{Period: period, Digits: 0, Window: 1}); ok {
			t.Errorf("Digits<=0 should return false")
		}
		if _, ok := totp.Match(rfcKey, "1234567", now, opts); ok {
			t.Errorf("len(code)!=Digits should return false")
		}
	})
}
