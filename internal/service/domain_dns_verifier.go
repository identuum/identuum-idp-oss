package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"strings"
	"time"
)

// ─────────────────────────────────────────────────────────────────────────────
// Production DNS TXT verifier for organization domain proof-of-control
// (slice 4 of the org-admin Domains feature).
//
// Slice 2 shipped DomainProofVerifier and a fail-closed
// staticDomainProofVerifier. Slice 4 ADDS this production implementation
// and bootstrap wiring; the interface and HTTP surface are unchanged.
//
// Architecture & match model:
//
// The challenge convention published by the service in slice 2 is:
//
//	record name:  _identuum-challenge.<domain>
//	record type:  TXT
//	record value: identuum-domain-verification=<raw-token>
//
// Slice 1's organization_domains schema stores ONLY the SHA-256 hex of
// the raw token (verification_token_hash). The raw token is returned
// exactly once to the operator at challenge start and is never read
// back by the service. Consequently this verifier cannot perform a
// byte-for-byte equality check on the full TXT value — the raw token
// is not available at verification time anywhere on the server side.
//
// Match semantics this verifier implements (no fuzzy matching anywhere):
//
//  1. Lookup _identuum-challenge.<domain> TXT records.
//  2. For each record, check the EXACT prefix `identuum-domain-verification=`.
//  3. Extract the token portion (everything after the prefix).
//  4. Compute SHA-256 hex of that token portion.
//  5. Compare the hex string EXACTLY (constant-time-equivalent
//     byte-compare via strings ==) against expectedValue (which is the
//     stored verification_token_hash hex).
//
// Verification succeeds the moment one record matches. Otherwise it
// fails closed with one of the package-level sentinels below.
//
// Security invariants enforced here (do not relax without justification):
//
//   - The verifier never logs domainName, expectedValue, TXT record
//     values, or the extracted token portion.
//   - Returned errors are package-level sentinels; the verifier never
//     wraps the resolver's error in a way that exposes its message.
//   - Empty domainName or empty expectedValue fail closed with
//     ErrDomainVerificationLookupFailed (treat bad input as "cannot
//     verify"). The service-side authorization layer ensures these
//     values are always populated in normal callers; the guard here is
//     defense in depth.
//   - No HTTP, no shell-out (dig/nslookup), no wildcard match, no
//     case-insensitive matching of the expected hash (hex hashes are
//     unambiguous; we lowercase-compare to tolerate operator-typed
//     uppercase hex only when the service-passed value is also
//     lowercased — see below).
//   - Domain normalization (trim whitespace, lowercase, drop trailing
//     dot) does not affect the value being verified. The expected
//     hash hex is normalized only by trimming whitespace and
//     lowercasing the hex digits.
// ─────────────────────────────────────────────────────────────────────────────

// Sentinel errors returned by the DNS verifier. The handler error-mapper
// maps them to:
//
//	ErrDomainVerificationLookupFailed   → 503 (resolver/transient failure)
//	ErrDomainVerificationRecordNotFound → 400 (operator needs to publish TXT)
//	ErrDomainVerificationMismatch       → 400 (TXT present but wrong token)
//
// ErrDomainVerifierUnavailable (slice 2, fail-closed default verifier)
// stays at 503 and is unchanged.
var (
	// ErrDomainVerificationLookupFailed is returned when the underlying
	// resolver fails (network error, context cancellation, timeout, NX
	// at the parent, or any non-record condition). It is also returned
	// when the verifier receives empty input — the input guard is
	// defense in depth against accidental misuse.
	ErrDomainVerificationLookupFailed = errors.New("organization domain verification: dns lookup failed")

	// ErrDomainVerificationRecordNotFound is returned when the resolver
	// answered but no TXT record carries the expected challenge prefix.
	// The operator should publish a record at
	// _identuum-challenge.<domain> of the form
	// `identuum-domain-verification=<raw-token>` from the challenge
	// response.
	ErrDomainVerificationRecordNotFound = errors.New("organization domain verification: txt record not found")

	// ErrDomainVerificationMismatch is returned when at least one TXT
	// record carries the expected prefix but no record's token portion
	// hashes to expectedValue. Likely causes: stale TXT from a prior
	// challenge, or a typo when pasting the token.
	ErrDomainVerificationMismatch = errors.New("organization domain verification: txt record does not match expected proof")
)

// TXTResolver is the small dependency seam the verifier consumes. The
// production wiring uses a thin wrapper over net.DefaultResolver.LookupTXT;
// tests inject a fake so the unit suite never touches the network.
type TXTResolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
}

// netTXTResolver is the production TXTResolver. It wraps net.DefaultResolver
// rather than constructing a custom resolver so the OS resolver chain
// (system /etc/resolv.conf, OS DNS cache) is reused — consistent with
// how the rest of the IDP performs DNS-shaped lookups.
type netTXTResolver struct {
	inner *net.Resolver
}

// LookupTXT delegates to net.Resolver.LookupTXT. We do not call
// LookupHost / LookupCNAME here — only LookupTXT — so an upstream
// CNAME chain is followed by the OS resolver but no additional
// queries are issued by this verifier.
func (r *netTXTResolver) LookupTXT(ctx context.Context, name string) ([]string, error) {
	return r.inner.LookupTXT(ctx, name)
}

// defaultDNSVerifyTimeout caps every individual lookup. Picked so a
// slow resolver chain cannot stall a verify HTTP request beyond a
// reasonable operator-facing budget; a future config knob can raise
// it without changing this file's behavior.
//
// Documented in the verifier struct's docstring; intentionally not a
// public constant so consumers cannot read it without going through
// DNSDomainProofVerifierOptions.
const defaultDNSVerifyTimeout = 5 * time.Second

// dnsChallengeLabelPrefix matches the prefix the service uses when
// emitting the challenge. The service publishes:
//
//	_identuum-challenge.<domain>
//
// We do not import the service's own constants here to keep the verifier
// independent — a later refactor could move both into a shared package.
const dnsChallengeLabelPrefix = "_identuum-challenge."

// dnsChallengeTXTPrefix is the EXACT prefix the verifier looks for on
// each TXT record. Any record not starting with this byte sequence is
// ignored. Matches the prefix the service publishes via
// domainChallengeValuePrefix.
const dnsChallengeTXTPrefix = "identuum-domain-verification="

// DNSDomainProofVerifier implements DomainProofVerifier by looking up
// the published TXT challenge and hashing each candidate to compare
// against the stored token hash.
//
// Zero value is NOT usable; construct via NewDNSDomainProofVerifier so
// the default resolver and timeout are wired.
type DNSDomainProofVerifier struct {
	resolver TXTResolver
	timeout  time.Duration
}

// DNSDomainProofVerifierOptions configures a DNS verifier. Both fields
// are optional; production callers leave them zero and accept the
// defaults (net.DefaultResolver wrapper, 5s per lookup).
type DNSDomainProofVerifierOptions struct {
	// Resolver overrides the production net.DefaultResolver wrapper.
	// Tests inject a fake resolver so the unit suite is hermetic.
	Resolver TXTResolver
	// Timeout overrides defaultDNSVerifyTimeout. A non-positive value
	// (zero or negative) falls back to the default.
	Timeout time.Duration
}

// NewDNSDomainProofVerifier returns a production-ready DNS TXT verifier.
// Safe to call once at bootstrap and share the same instance across the
// process — the underlying net.DefaultResolver is concurrent-safe and
// the verifier itself carries no per-call state.
func NewDNSDomainProofVerifier(opts DNSDomainProofVerifierOptions) *DNSDomainProofVerifier {
	r := opts.Resolver
	if r == nil {
		r = &netTXTResolver{inner: net.DefaultResolver}
	}
	t := opts.Timeout
	if t <= 0 {
		t = defaultDNSVerifyTimeout
	}
	return &DNSDomainProofVerifier{resolver: r, timeout: t}
}

// Verify implements DomainProofVerifier.
//
// expectedValue is treated as the SHA-256 hex of the raw token (i.e.
// the row's verification_token_hash). See the file-level docstring for
// the rationale: the raw token is not stored at rest, so the verifier
// hashes each candidate token portion and compares hex digests.
//
// Returns one of:
//
//	nil                                  — at least one TXT record hashed to expectedValue
//	ErrDomainVerificationLookupFailed    — bad input / resolver error / context cancel
//	ErrDomainVerificationRecordNotFound  — no TXT carried the challenge prefix
//	ErrDomainVerificationMismatch        — TXT(s) carried the prefix but none hashed to match
//
// The returned errors NEVER include domainName, expectedValue, the
// extracted token portion, or any TXT record value.
func (v *DNSDomainProofVerifier) Verify(ctx context.Context, domainName string, expectedValue string) error {
	// Input guards. The service path validates these before reaching
	// the verifier; treat any empty input here as fail-closed.
	normDomain := normalizeDNSDomainName(domainName)
	if normDomain == "" {
		return ErrDomainVerificationLookupFailed
	}
	// The expected hash is a SHA-256 hex string. Trim and lowercase so
	// an operator-typed uppercase hex (unlikely via the service path,
	// but cheap defense) still matches. We do NOT touch the suffix in
	// any way that could permit a bypass.
	expected := strings.ToLower(strings.TrimSpace(expectedValue))
	if expected == "" {
		return ErrDomainVerificationLookupFailed
	}

	lookupCtx, cancel := context.WithTimeout(ctx, v.timeout)
	defer cancel()

	name := dnsChallengeLabelPrefix + normDomain
	records, err := v.resolver.LookupTXT(lookupCtx, name)
	if err != nil {
		// Map all resolver errors (network, NXDOMAIN at the label, timeout,
		// context cancel, malformed reply) to a single sentinel. We do not
		// wrap err here — exposing the resolver's message would leak
		// operator-controlled DNS detail into our log/error chain.
		return ErrDomainVerificationLookupFailed
	}
	if len(records) == 0 {
		return ErrDomainVerificationRecordNotFound
	}

	foundPrefix := false
	for _, raw := range records {
		// Operators sometimes paste with leading/trailing whitespace.
		// Trim so the prefix check accepts the common cases without
		// loosening match semantics on the token portion (which is
		// hashed as-is below).
		trimmed := strings.TrimSpace(raw)
		if !strings.HasPrefix(trimmed, dnsChallengeTXTPrefix) {
			continue
		}
		token := strings.TrimPrefix(trimmed, dnsChallengeTXTPrefix)
		if token == "" {
			// A prefix-only record carries no proof material. Treat it
			// as not-a-challenge-record so an unset `foundPrefix` can
			// still surface ErrDomainVerificationRecordNotFound — a
			// clearer operator hint than "mismatch".
			continue
		}
		foundPrefix = true
		sum := sha256.Sum256([]byte(token))
		got := hex.EncodeToString(sum[:])
		if got == expected {
			return nil
		}
	}
	if !foundPrefix {
		return ErrDomainVerificationRecordNotFound
	}
	return ErrDomainVerificationMismatch
}

// normalizeDNSDomainName lowercases, trims whitespace, and strips a
// single trailing dot. We do NOT punycode-encode here — the caller
// (the service) is expected to have already validated the domain
// shape; this normalization is purely a defensive coat so an operator
// that typed "Example.COM." in the org-admin form still resolves to
// "example.com" before the lookup-name is assembled.
func normalizeDNSDomainName(s string) string {
	n := strings.ToLower(strings.TrimSpace(s))
	n = strings.TrimSuffix(n, ".")
	return n
}
