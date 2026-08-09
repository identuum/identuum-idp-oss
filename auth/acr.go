package auth

// ACR — Authentication Context Class Reference vocabulary.
//
// These constants name the rungs of the Identuum LoA ladder. They are emitted
// as the access-token `acr` claim, persisted on user-session rows, surfaced
// at the OIDC `acr` claim, and consumed by downstream ACR floor enforcement
// on step-up flows.
//
// Stable wire identifiers — once minted, tokens carrying these strings MUST
// continue to be interpreted with the same semantics across versions.
//
// Adding a new tier:
//  1. Add the URN constant below.
//  2. Add a row to acrLadder with an explicit, unambiguous integer rank.
//  3. Update the ladder-monotonicity test in acr_test.go and the
//     SECURITY_INVARIANTS.md §2 register.
//
// Inserting a tier between existing rungs is only safe if every existing
// rank is renumbered atomically. Do not silently shift ranks.
const (
	// ACRPassword — password-only authentication. No MFA factor presented.
	ACRPassword = "urn:identuum:loa:password" //nolint:gosec // G101: URN identifier for an OIDC authentication-context class, not a credential.

	// ACRMFA — password plus a non-phishing-resistant second factor (TOTP,
	// SMS, push-notification approval).
	ACRMFA = "urn:identuum:loa:mfa"

	// ACRPhishingResistant — WebAuthn / FIDO2 / passkey. The presenter
	// proved possession of a private key bound to the relying-party origin,
	// rendering credential phishing infeasible under the assumed threat
	// model.
	ACRPhishingResistant = "urn:identuum:loa:phishing-resistant"
)

// acrLadder ranks each ACR by its position on the LoA ladder.
//
// The ranks are integers, intentionally non-contiguous (1, 2, 3) so future
// tiers inserted between rungs do not require renumbering. Comparison is by
// integer rank, never string equality.
//
// Unknown values do not appear in this map — IsKnownACR is the gate at the
// validation boundary, ACRRank reports zero+false for unknowns, and
// ACRMeetsFloor treats an unknown presented value as failing.
var acrLadder = map[string]int{
	ACRPassword:          1,
	ACRMFA:               2,
	ACRPhishingResistant: 3,
}

// IsKnownACR reports whether the given string is a recognised ACR ladder
// rung. Validators at the input boundary (org-settings PATCH, authorization
// flow validators) reject anything for which this returns false.
func IsKnownACR(s string) bool {
	_, ok := acrLadder[s]
	return ok
}

// ACRRank returns the ladder rank of the given ACR string and a boolean
// indicating whether it is known. Unknown values return (0, false). Zero is
// strictly below every known rung; ACRMeetsFloor relies on this so an
// unknown presented value never satisfies a non-empty floor.
func ACRRank(s string) (int, bool) {
	r, ok := acrLadder[s]
	return r, ok
}

// ACRMeetsFloor reports whether the presented ACR satisfies the required
// floor. Empty floor (no requirement set) returns true unconditionally —
// "no floor" is the default org posture.
//
// Comparison rules:
//   - Empty required → true (no floor).
//   - Unknown required → false (defensive; should be rejected at the
//     validation boundary, but if it slips through the floor never opens).
//   - Unknown presented → false (rank 0 < every known rung).
//   - Both known → presented rank >= required rank.
func ACRMeetsFloor(presented, required string) bool {
	if required == "" {
		return true
	}
	requiredRank, ok := acrLadder[required]
	if !ok {
		return false
	}
	presentedRank := acrLadder[presented]
	return presentedRank >= requiredRank
}

// ACRMax returns the higher of the two ACR rungs by ladder rank. The empty
// string is treated as "no value" and is below every known rung. Unknown
// non-empty values are treated as rank 0 — they will never win against a
// known rung but will compare equal to each other (meaning any unknown vs
// unknown call returns the first argument).
//
// Useful for computing an effective ACR floor when combining a caller-
// requested ACR with a policy minimum (e.g., max(org_floor, requested)).
func ACRMax(a, b string) string {
	rankA := acrLadder[a]
	rankB := acrLadder[b]
	if rankA >= rankB {
		return a
	}
	return b
}

// MapUpstreamACRToLadder maps a verbatim upstream-IDP `acr` claim to the
// Identuum ladder. Used by the SSO/federation login path to translate
// the upstream IdP's authentication-context attestation into the ladder
// rung that gets stamped on the locally-minted session.
//
// Mapping rules:
//   - Empty upstream ACR → ACRMFA. Per the design rationale, when the
//     upstream IdP does not attest an authentication context we assume
//     a federated IdP login is at least as strong as MFA (the operator
//     who wired the federation made that policy call). Callers should
//     emit a debug log with `assumed_default=true` so this is auditable.
//   - Verbatim Identuum URN (any of the three rungs) → pass through. A
//     federated provider may already be using our ladder.
//   - "0" → ACRPassword. NIST SP 800-63 / OIDC convention for "no MFA".
//   - "1" → ACRMFA. NIST SP 800-63 / OIDC convention for "AAL2-ish MFA".
//   - URN containing "phishing-resistant", "fido", "webauthn", "passkey"
//     (case-insensitive) → ACRPhishingResistant. Defensive substring
//     match for the diversity of vendor-specific ladder strings.
//   - Anything else → ACRMFA, with the upstream string preserved
//     verbatim on the AMR/audit trail (the caller's responsibility, not
//     this function's). Falling to MFA — rather than to ACRPassword —
//     matches the empty-ACR default rationale: a configured federation
//     is at least MFA-grade.
//
// Never invents a rung above what the upstream attested. Callers needing
// to differentiate "explicitly downgraded" from "passthrough" should
// keep the original upstream string for audit; this function only
// returns the local ladder rung.
func MapUpstreamACRToLadder(upstream string) (rung string, assumedDefault bool) {
	if upstream == "" {
		return ACRMFA, true
	}
	if _, ok := acrLadder[upstream]; ok {
		return upstream, false
	}
	switch upstream {
	case "0":
		return ACRPassword, false
	case "1":
		return ACRMFA, false
	}
	lower := toLowerASCII(upstream)
	for _, marker := range []string{"phishing-resistant", "fido", "webauthn", "passkey"} {
		if containsASCII(lower, marker) {
			return ACRPhishingResistant, false
		}
	}
	return ACRMFA, false
}

// toLowerASCII / containsASCII are tiny dependency-free helpers so this
// file does not import the strings package — keeps the auth package
// dependency graph minimal.
func toLowerASCII(s string) string {
	b := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		b[i] = c
	}
	return string(b)
}

func containsASCII(haystack, needle string) bool {
	if len(needle) == 0 {
		return true
	}
	if len(needle) > len(haystack) {
		return false
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		ok := true
		for j := 0; j < len(needle); j++ {
			if haystack[i+j] != needle[j] {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}
