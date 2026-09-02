package domain

// user_profile_address_phone.go — THE-ADDRESS-PHONE-CLAIMS: the OIDC Core
// §5.1 `address` (structured, §5.1.1) and `phone_number` /
// `phone_number_verified` claims, modeled as optional columns beside the
// profile fields on user_profiles (migration 0036) and released under
// scope=address / scope=phone or the claims parameter — consent-gated,
// role-intersected, humans only.
//
// Truthfulness rules (rule ADDRESS-PHONE-TRUTHFUL-1):
//   - an unset field is never emitted; the `address` object is emitted only
//     when at least one of its members is set, and carries only set members;
//   - `phone_number` is emitted only when set, E.164 well-formed;
//   - `phone_number_verified` is NEVER true: identuum has no phone
//     verification event. It is emitted as `false` — and only alongside
//     `phone_number` — because OIDC Core §5.1 defines false as "the OP has
//     not taken affirmative steps to ensure the number was controlled by
//     the End-User", which is exactly the truth, and because a relying party
//     asking for the phone scope expects the pair (the conformance suite's
//     VerifyScopesReturnedInUserInfoClaims requires both). Omitting it
//     would be honest too, but would say less: false states the fact.

import "regexp"

// Address / phone claim names (OIDC Core §5.1).
const (
	ClaimAddress             = "address"
	ClaimPhoneNumber         = "phone_number"
	ClaimPhoneNumberVerified = "phone_number_verified"
)

// AddressClaimNames and PhoneClaimNames are what scope=address and
// scope=phone release, respectively.
var (
	AddressClaimNames = []string{ClaimAddress}
	PhoneClaimNames   = []string{ClaimPhoneNumber, ClaimPhoneNumberVerified}
)

// phoneE164Re: E.164 — a leading +, a non-zero first digit, at most 15 digits.
var phoneE164Re = regexp.MustCompile(`^\+[1-9][0-9]{1,14}$`)

// IsAddressClaim / IsPhoneClaim classify a claim name for the release paths.
func IsAddressClaim(claim string) bool { return claim == ClaimAddress }

func IsPhoneClaim(claim string) bool {
	return claim == ClaimPhoneNumber || claim == ClaimPhoneNumberVerified
}

// AddressClaim builds the §5.1.1 structured address from the SET members
// only. nil when no member is set (the claim must then be absent).
func AddressClaim(p *UserProfile) map[string]any {
	if p == nil {
		return nil
	}
	out := map[string]any{}
	set := func(k string, v *string) {
		if v != nil && *v != "" {
			out[k] = *v
		}
	}
	set("formatted", p.AddressFormatted)
	set("street_address", p.AddressStreetAddress)
	set("locality", p.AddressLocality)
	set("region", p.AddressRegion)
	set("postal_code", p.AddressPostalCode)
	set("country", p.AddressCountry)
	if len(out) == 0 {
		return nil
	}
	return out
}

// addressPhoneClaims adds the address/phone claims ProfileClaims releases,
// honoring the same allow list. phone_number_verified rides ONLY with an
// emitted phone_number and is always false (see the file comment).
func addressPhoneClaims(out map[string]any, p *UserProfile, allow func(string) bool) {
	if p == nil {
		return
	}
	if allow(ClaimAddress) {
		if addr := AddressClaim(p); addr != nil {
			out[ClaimAddress] = addr
		}
	}
	if p.PhoneNumber != nil && *p.PhoneNumber != "" && (allow(ClaimPhoneNumber) || allow(ClaimPhoneNumberVerified)) {
		out[ClaimPhoneNumber] = *p.PhoneNumber
		out[ClaimPhoneNumberVerified] = false
	}
}
