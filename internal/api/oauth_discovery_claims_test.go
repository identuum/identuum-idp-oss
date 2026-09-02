package api

import "testing"

// THE-CLAIMS-PARAMETER: discovery advertises the §5.5 claims parameter and an
// honest claims_supported list — every entry emits somewhere (id_token or
// userinfo), and the individually requestable identity claims are present.
func TestDiscovery_ClaimsParameterAdvertised(t *testing.T) {
	body := fullChainDiscovery(t)
	if body["claims_parameter_supported"] != true {
		t.Errorf("claims_parameter_supported = %v, want true", body["claims_parameter_supported"])
	}
	raw, _ := body["claims_supported"].([]any)
	have := map[string]bool{}
	for _, c := range raw {
		if s, ok := c.(string); ok {
			have[s] = true
		}
	}
	for _, want := range []string{"sub", "name", "email", "email_verified", "organization_id", "role", "auth_time", "acr", "amr", "nonce",
		// THE-PROFILE-CLAIMS: the whole §5.1 profile family is modeled and emits when set.
		"given_name", "family_name", "middle_name", "nickname", "preferred_username", "profile", "picture", "website", "gender", "birthdate", "zoneinfo", "locale", "updated_at",
		// THE-ADDRESS-PHONE-CLAIMS: address + phone are modeled and emit when set
		// (phone_number_verified rides with phone_number, always false).
		"address", "phone_number", "phone_number_verified"} {
		if !have[want] {
			t.Errorf("claims_supported lacks %q (it emits): %v", want, raw)
		}
	}
	// scopes_supported advertises the scopes that release them.
	scopes, _ := body["scopes_supported"].([]any)
	haveScope := map[string]bool{}
	for _, s := range scopes {
		if str, ok := s.(string); ok {
			haveScope[str] = true
		}
	}
	for _, want := range []string{"openid", "profile", "email", "address", "phone"} {
		if !haveScope[want] {
			t.Errorf("scopes_supported lacks %q: %v", want, scopes)
		}
	}
}

// THE-HONEST-ACR / THE-PHISHING-RESISTANT-ACR: acr_values_supported
// advertises EXACTLY the three contexts the OP performs — password,
// password+TOTP, and the phishing-resistant rung (WebAuthn login or passkey
// step-up) — in ladder order. Pinned by value: the conformance suite requests
// every advertised value, so an extra entry here is a promise the OP cannot
// keep (measured: with three values the acr module still passes, the
// password login honestly satisfying the request).
func TestDiscovery_AcrValuesSupportedIsExactlyTheHonestThree(t *testing.T) {
	body := fullChainDiscovery(t)
	raw, ok := body["acr_values_supported"].([]any)
	if !ok {
		t.Fatalf("acr_values_supported = %v (%T), want a list", body["acr_values_supported"], body["acr_values_supported"])
	}
	want := []string{"urn:identuum:loa:password", "urn:identuum:loa:mfa", "urn:identuum:loa:phishing-resistant"}
	if len(raw) != len(want) {
		t.Fatalf("acr_values_supported = %v, want exactly %v", raw, want)
	}
	for i, w := range want {
		if raw[i] != w {
			t.Errorf("acr_values_supported[%d] = %v, want %q", i, raw[i], w)
		}
	}
}
