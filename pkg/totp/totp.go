// Package totp is the public OSS seam for the RFC 4226 (HOTP)
// / RFC 6238 (TOTP) code-generation and skew-window matching primitives
// that OSS and CE otherwise duplicate byte-for-byte. It has no dependency
// on the OSS `internal/` tree, so both repositories can share ONE
// implementation.
//
// Scope is intentionally narrow: HMAC-SHA1 HOTP generation and a
// constant-time TOTP window match. It does NOT decode secrets (callers
// pass an already-decoded key, keeping each repo's own base32 handling),
// and it does NOT track replay / used steps (that policy stays with the
// caller).
package totp

import (
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // SHA-1 is mandated by RFC 6238 §1 / RFC 4226.
	"crypto/subtle"
	"encoding/binary"
	"time"
)

// Code returns the RFC 4226 HOTP value for the supplied DECODED key and
// counter: HMAC-SHA1(key, 8-byte big-endian counter), RFC 4226 §5.3
// dynamic truncation, reduced mod 10^digits and left-zero-padded to
// exactly digits characters. The key must already be decoded (this
// package never decodes base32).
func Code(key []byte, counter uint64, digits int) string {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)
	mac := hmac.New(sha1.New, key)
	_, _ = mac.Write(buf[:])
	sum := mac.Sum(nil)

	// RFC 4226 §5.3 dynamic truncation.
	offset := int(sum[len(sum)-1] & 0x0f)
	bin := int(sum[offset]&0x7f)<<24 |
		int(sum[offset+1])<<16 |
		int(sum[offset+2])<<8 |
		int(sum[offset+3])

	mod := 1
	for i := 0; i < digits; i++ {
		mod *= 10
	}
	val := bin % mod

	// Left-zero-pad to exactly digits characters. bin%mod < 10^digits, so
	// it never exceeds digits; this is byte-identical to
	// fmt.Sprintf("%0*d", digits, val) without pulling in fmt.
	out := make([]byte, digits)
	for i := digits - 1; i >= 0; i-- {
		out[i] = byte('0' + val%10)
		val /= 10
	}
	return string(out)
}

// Options parameterises Match.
type Options struct {
	Period uint64 // TOTP step interval in seconds (e.g. 30).
	Digits int    // code length (e.g. 6).
	Window int    // number of steps of clock skew accepted on EITHER side.
}

// Match reports whether code is a valid RFC 6238 TOTP for the DECODED key
// at time now, within ±opts.Window steps.
//
// It returns (0, false) defensively when opts.Period == 0, opts.Digits <=
// 0, or len(code) != opts.Digits. Otherwise it computes the current step
// (now.Unix() / Period) and, for every delta in [-Window, +Window],
// compares Code(key, step+delta) to code with crypto/subtle.
// ConstantTimeCompare. The scan is CONSTANT-TIME: it never breaks early on
// a match, so the total time does not reveal whether — or at which step —
// the code matched. On success it returns the matched absolute step and
// true; otherwise (0, false).
func Match(key []byte, code string, now time.Time, opts Options) (matchedStep int64, ok bool) {
	if opts.Period == 0 || opts.Digits <= 0 || len(code) != opts.Digits {
		return 0, false
	}
	stepNow := now.Unix() / int64(opts.Period)

	var matched int64
	found := 0
	for delta := -opts.Window; delta <= opts.Window; delta++ {
		step := stepNow + int64(delta)
		candidate := Code(key, uint64(step), opts.Digits)
		eq := subtle.ConstantTimeCompare([]byte(candidate), []byte(code)) // 1 iff equal
		// Record the matched step without a data-dependent branch or an
		// early return — keeps the whole scan constant-time.
		matched = int64(subtle.ConstantTimeSelect(eq, int(step), int(matched)))
		found |= eq
	}
	if found == 1 {
		return matched, true
	}
	return 0, false
}
