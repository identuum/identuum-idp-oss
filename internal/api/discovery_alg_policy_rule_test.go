package api

import (
	"testing"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// THE-ADVERTISED-RS256. The discovery document advertised
// id_token_signing_alg_values_supported = [EdDSA ES256 RS256] from
// 2026-09-01, while the integration suite had asserted since 2026-08-19 that
// RS256 must not appear. Nothing failed for two days because the two lists
// were separate literals in separate files and the suite that disagreed is
// not part of `make verify`.
//
// The owner ruled for the suite: the issuer advertises only what it will
// SIGN an id_token with. This rule pins the shape that makes the drift
// impossible — ONE source of truth, read by BOTH discovery builders, and a
// subset relation to the registration allow-list that must always hold.
//
// (internal/api may not import testify — the boundary policy — so these are
// plain testing assertions.)

func algSetOf(t *testing.T, body map[string]any) map[string]bool {
	t.Helper()
	raw, ok := body["id_token_signing_alg_values_supported"].([]any)
	if !ok {
		// The production builder assigns a []string; a fetched document
		// round-trips through JSON as []any. Accept both.
		if strs, ok2 := body["id_token_signing_alg_values_supported"].([]string); ok2 {
			out := map[string]bool{}
			for _, s := range strs {
				out[s] = true
			}
			return out
		}
		t.Fatalf("id_token_signing_alg_values_supported missing or wrong type: %T",
			body["id_token_signing_alg_values_supported"])
	}
	out := map[string]bool{}
	for _, a := range raw {
		if s, ok := a.(string); ok {
			out[s] = true
		}
	}
	return out
}

// RULE: DISCOVERY-ALG-POLICY-1
func TestRule_DISCOVERY_ALG_POLICY_1(t *testing.T) {
	// (1) The source of truth is exactly the issuer's signing policy:
	// EdDSA (the per-client default) and ES256.
	advertised := map[string]bool{}
	for _, a := range domain.IDTokenAdvertisedSigningAlgorithms {
		advertised[a] = true
	}
	if len(domain.IDTokenAdvertisedSigningAlgorithms) != 2 || !advertised["EdDSA"] || !advertised["ES256"] {
		t.Fatalf("the advertised policy must be exactly EdDSA + ES256; got %v",
			domain.IDTokenAdvertisedSigningAlgorithms)
	}

	// (2) EVERY advertised algorithm must be one a client could register —
	// the OP never advertises what it would refuse to be configured with.
	for _, a := range domain.IDTokenAdvertisedSigningAlgorithms {
		if _, ok := domain.IDTokenSigningAlgorithms[a]; !ok {
			t.Errorf("advertised %q is not in the registration allow-list — the two lists have parted company", a)
		}
	}

	// (3) The relation is a STRICT subset: RS256 is registrable (a real
	// capability, testing-only) and deliberately not advertised. If a future
	// change advertises everything registrable, this fails.
	if _, ok := domain.IDTokenSigningAlgorithms["RS256"]; !ok {
		t.Errorf("RS256 must remain registrable per client (THE-PKCE-DECISION)")
	}
	if advertised["RS256"] {
		t.Errorf("RS256 must NOT be advertised (THE-ADVERTISED-RS256)")
	}
	if len(domain.IDTokenAdvertisedSigningAlgorithms) >= len(domain.IDTokenSigningAlgorithms) {
		t.Errorf("the advertised list must stay a strict subset of the registrable set; advertised=%v registrable=%d",
			domain.IDTokenAdvertisedSigningAlgorithms, len(domain.IDTokenSigningAlgorithms))
	}

	// (4) BOTH discovery builders answer with that exact list — the drift
	// this rule exists for was two literals in two files.
	production := algSetOf(t, fullChainDiscovery(t))
	if len(production) != len(advertised) {
		t.Fatalf("the production discovery list %v does not match the policy %v", production, advertised)
	}
	for a := range advertised {
		if !production[a] {
			t.Errorf("the production discovery document omits the advertised %q", a)
		}
	}
	for a := range production {
		if !advertised[a] {
			t.Errorf("the production discovery document advertises %q, which is not the issuer's signing policy", a)
		}
	}

	// (5) The banned set stays banned, in the advertised list AND in what a
	// client may register.
	for _, banned := range []string{"RS384", "RS512", "PS256", "PS384", "PS512", "HS256", "HS384", "HS512", "none", ""} {
		if advertised[banned] {
			t.Errorf("advertised list contains the banned %q", banned)
		}
		if production[banned] {
			t.Errorf("the production discovery document contains the banned %q", banned)
		}
		if _, ok := domain.IDTokenSigningAlgorithms[banned]; ok && banned != "" {
			t.Errorf("the registration allow-list contains the banned %q", banned)
		}
	}
}
