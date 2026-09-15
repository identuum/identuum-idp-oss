// Package totptest is the ONE test-only HOTP/TOTP code generator for this
// module's tests (THE-EIGHT-QUICK-ONES, OSS 4, 2026-09-16).
//
// boundaries.json keeps pkg/totp out of internal/handlers, tests included, so
// the RFC 4226 step was inlined twice — internal/handlers' recoveryTOTPAtOffset
// and internal/e2e's computeHOTPForTest — each "kept in sync by hand" with
// internal/service/mfa_verifier.go. This package sits under internal/service,
// a layer both internal/handlers (may_import internal/service/**) and
// internal/e2e may import, and it may import pkg/totp because internal/service
// may; the boundary rule is unchanged. It is imported by tests only: no
// non-test package of this module imports it, so it is outside the appliance's
// build closure (`go list -deps ./cmd/...`), which closure_test.go re-proves.
//
// Secret handling mirrors the production verifier's decodeBase32Secret:
// upper-cased, spaces stripped, padded to a multiple of eight so a NoPad seed
// decodes; the code itself is pkg/totp.Code, the production primitive.
package totptest

import (
	"encoding/base32"
	"fmt"
	"strings"
	"time"

	"github.com/identuum/identuum-idp-oss/pkg/totp"
)

// Digits is the code length the appliance verifies (RFC 6238 §5.3, six).
const Digits = 6

// PeriodSeconds is the appliance's TOTP step length (RFC 6238, 30 s).
const PeriodSeconds = 30

// HOTP returns the six-digit code for a base32 secret at an explicit counter.
func HOTP(secret string, counter uint64) (string, error) {
	normalised := strings.ReplaceAll(strings.ToUpper(strings.TrimSpace(secret)), " ", "")
	if pad := len(normalised) % 8; pad != 0 {
		normalised += strings.Repeat("=", 8-pad)
	}
	key, err := base32.StdEncoding.DecodeString(normalised)
	if err != nil {
		return "", fmt.Errorf("totptest: decode base32 secret: %w", err)
	}
	return totp.Code(key, counter, Digits), nil
}

// Step is the RFC 6238 step containing the instant at.
func Step(at time.Time) uint64 {
	return uint64(at.Unix() / PeriodSeconds)
}

// CodeAt returns the code for a base32 secret at the step containing at,
// shifted by stepOffset (0 = current, +1 = next, -1 = previous).
func CodeAt(secret string, at time.Time, stepOffset int64) (string, error) {
	return HOTP(secret, uint64(int64(Step(at))+stepOffset))
}
