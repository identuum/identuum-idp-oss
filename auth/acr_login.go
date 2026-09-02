package auth

// acr_login.go — THE-HONEST-ACR: the authentication contexts the OP
// actually performs for local logins, and what it advertises.
//
// Owner ruling (2026-09-02): REAL acr backed by performed authentication,
// never faked. Password and password+TOTP are the two honest contexts
// today; discovery advertises ONLY those two; the id_token/access token
// carry the context ACTUALLY performed.

// AMR values (RFC 8176) this OP stamps.
const (
	AMRPassword = "pwd" // password verified
	AMROTP      = "otp" // TOTP one-time password verified
)

// AdvertisedACRValues is the discovery acr_values_supported list — exactly
// the contexts a local login can perform or step up to. The ladder's
// phishing-resistant rung (WebAuthn) is stamped when performed but is NOT
// advertised: the owner named two honest contexts today.
func AdvertisedACRValues() []string {
	return []string{ACRPassword, ACRMFA}
}

// IsAdvertisedACR reports whether v is one of AdvertisedACRValues.
func IsAdvertisedACR(v string) bool {
	for _, a := range AdvertisedACRValues() {
		if a == v {
			return true
		}
	}
	return false
}

// LoginContext returns the acr rung and amr list for a local login that
// verified the password and, when mfaVerified, a TOTP code as well.
func LoginContext(mfaVerified bool) (acr string, amr []string) {
	if mfaVerified {
		return ACRMFA, []string{AMRPassword, AMROTP}
	}
	return ACRPassword, []string{AMRPassword}
}

// LowestRequestedRung picks, from a space-separated acr_values request,
// the KNOWN rung with the lowest rank — the cheapest context that would
// satisfy the request (OIDC Core §3.1.2.1: acr_values is a preference
// list; any one value satisfies it). Unknown values are ignored (voluntary
// claim, never an error). ok=false when no known rung was requested.
func LowestRequestedRung(acrValues string) (rung string, ok bool) {
	best := ""
	bestRank := 0
	for _, v := range fields(acrValues) {
		r, known := acrLadder[v]
		if !known {
			continue
		}
		if best == "" || r < bestRank {
			best, bestRank = v, r
		}
	}
	return best, best != ""
}

// RequestSatisfiedBy reports whether the presented (effective) rung meets
// AT LEAST ONE known requested rung. With no known rung requested the
// request is vacuously satisfied.
func RequestSatisfiedBy(presented, acrValues string) bool {
	anyKnown := false
	for _, v := range fields(acrValues) {
		if _, known := acrLadder[v]; !known {
			continue
		}
		anyKnown = true
		if ACRMeetsFloor(presented, v) {
			return true
		}
	}
	return !anyKnown
}

// fields splits on spaces/tabs without importing strings twice in a hot
// path; trivially small.
func fields(s string) []string {
	var out []string
	start := -1
	for i := 0; i < len(s); i++ {
		if s[i] == ' ' || s[i] == '\t' {
			if start >= 0 {
				out = append(out, s[start:i])
				start = -1
			}
			continue
		}
		if start < 0 {
			start = i
		}
	}
	if start >= 0 {
		out = append(out, s[start:])
	}
	return out
}
