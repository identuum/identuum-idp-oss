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
		"given_name", "family_name", "middle_name", "nickname", "preferred_username", "profile", "picture", "website", "gender", "birthdate", "zoneinfo", "locale", "updated_at"} {
		if !have[want] {
			t.Errorf("claims_supported lacks %q (it emits): %v", want, raw)
		}
	}
	for _, never := range []string{"phone_number", "phone_number_verified", "address"} {
		if have[never] {
			t.Errorf("claims_supported advertises %q, which the OP never emits", never)
		}
	}
}
