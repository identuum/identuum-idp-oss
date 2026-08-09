package auth

import (
	"sort"
	"testing"
)

// TestACR_LadderRanksAreMonotonic walks the declared ladder and confirms each
// rung has a strictly increasing rank, in declared order. Pins
// SECURITY_INVARIANTS.md §2.
func TestACR_LadderRanksAreMonotonic(t *testing.T) {
	declaredOrder := []string{
		ACRPassword,
		ACRMFA,
		ACRPhishingResistant,
	}

	ranks := make([]int, 0, len(declaredOrder))
	for _, acr := range declaredOrder {
		r, ok := ACRRank(acr)
		if !ok {
			t.Fatalf("declared ACR %q is not in the ladder map — invariant violated", acr)
		}
		ranks = append(ranks, r)
	}

	for i := 1; i < len(ranks); i++ {
		if ranks[i] <= ranks[i-1] {
			t.Fatalf("ladder ranks not strictly increasing at index %d: %v", i, ranks)
		}
	}

	// Defence in depth: every map entry must appear in the declared order.
	if len(acrLadder) != len(declaredOrder) {
		t.Fatalf("acrLadder has %d entries but declaredOrder has %d — a new rung was added without updating the test", len(acrLadder), len(declaredOrder))
	}

	// And every declared rung must have a unique rank.
	sortedRanks := append([]int(nil), ranks...)
	sort.Ints(sortedRanks)
	for i := 1; i < len(sortedRanks); i++ {
		if sortedRanks[i] == sortedRanks[i-1] {
			t.Fatalf("two ladder rungs share the same rank: %v", sortedRanks)
		}
	}
}

// TestACR_MeetsFloor_ByRank_NotByEquality asserts the comparison is rank-
// based, not string equality. A presented ACR strictly above the floor
// satisfies it.
func TestACR_MeetsFloor_ByRank_NotByEquality(t *testing.T) {
	cases := []struct {
		name      string
		presented string
		required  string
		want      bool
	}{
		{"empty floor accepts anything", ACRPassword, "", true},
		{"empty floor accepts unknown", "urn:identuum:loa:never-defined", "", true},
		{"phishing-resistant meets mfa floor", ACRPhishingResistant, ACRMFA, true},
		{"phishing-resistant meets password floor", ACRPhishingResistant, ACRPassword, true},
		{"mfa meets password floor", ACRMFA, ACRPassword, true},
		{"mfa meets mfa floor (equal rank)", ACRMFA, ACRMFA, true},
		{"password fails mfa floor", ACRPassword, ACRMFA, false},
		{"password fails phishing-resistant floor", ACRPassword, ACRPhishingResistant, false},
		{"mfa fails phishing-resistant floor", ACRMFA, ACRPhishingResistant, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ACRMeetsFloor(tc.presented, tc.required)
			if got != tc.want {
				t.Fatalf("ACRMeetsFloor(%q, %q) = %v, want %v", tc.presented, tc.required, got, tc.want)
			}
		})
	}
}

// TestACR_Max_StrictlyAdditive confirms the per-mint escalation contract —
// `max(floor, request)` returns whichever rung is higher on the ladder
// regardless of argument order. The mint request can never weaken the
// floor.
func TestACR_Max_StrictlyAdditive(t *testing.T) {
	cases := []struct {
		name string
		a, b string
		want string
	}{
		{"empty + password = password", "", ACRPassword, ACRPassword},
		{"password + empty = password", ACRPassword, "", ACRPassword},
		{"password + mfa = mfa", ACRPassword, ACRMFA, ACRMFA},
		{"mfa + password = mfa (commutative)", ACRMFA, ACRPassword, ACRMFA},
		{"mfa + phishing = phishing", ACRMFA, ACRPhishingResistant, ACRPhishingResistant},
		{"phishing + mfa = phishing", ACRPhishingResistant, ACRMFA, ACRPhishingResistant},
		{"equal rungs return either side (deterministic on a)", ACRMFA, ACRMFA, ACRMFA},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ACRMax(tc.a, tc.b)
			if got != tc.want {
				t.Fatalf("ACRMax(%q, %q) = %q, want %q", tc.a, tc.b, got, tc.want)
			}
		})
	}
}

// TestACR_Max_NeverWeakensFloor is the "request cannot lower the floor"
// invariant pinned at the function level. For every (floor, request) pair,
// the result rank MUST be >= the floor rank.
func TestACR_Max_NeverWeakensFloor(t *testing.T) {
	rungs := []string{"", ACRPassword, ACRMFA, ACRPhishingResistant}
	for _, floor := range rungs {
		for _, req := range rungs {
			result := ACRMax(floor, req)
			floorRank, _ := ACRRank(floor)
			resultRank, _ := ACRRank(result)
			if floorRank > resultRank {
				t.Fatalf("ACRMax(%q, %q) = %q (rank %d) — weaker than floor rank %d", floor, req, result, resultRank, floorRank)
			}
		}
	}
}

// TestACR_UnknownPresented_NeverMeetsNonEmptyFloor is the defensive
// behaviour — a malformed claim that slipped past validation must not
// satisfy any non-empty floor.
func TestACR_UnknownPresented_NeverMeetsNonEmptyFloor(t *testing.T) {
	floors := []string{ACRPassword, ACRMFA, ACRPhishingResistant}
	unknowns := []string{"", "garbage", "urn:identuum:loa:not-a-thing", "0", "1"}
	for _, floor := range floors {
		for _, presented := range unknowns {
			if ACRMeetsFloor(presented, floor) {
				t.Fatalf("ACRMeetsFloor(%q, %q) returned true — unknown presented should never satisfy a non-empty floor", presented, floor)
			}
		}
	}
}

// TestACR_MapUpstreamACRToLadder pins the SSO/federation pass-through
// rules: known URNs round-trip; "0"/"1" map to password/mfa; phishing-
// resistant markers map up; everything else lands on mfa with the
// upstream string preserved verbatim by the caller. Empty defaults to
// mfa with assumedDefault=true.
func TestACR_MapUpstreamACRToLadder(t *testing.T) {
	cases := []struct {
		name        string
		upstream    string
		want        string
		wantAssumed bool
	}{
		{"empty defaults to mfa with assumedDefault", "", ACRMFA, true},
		{"verbatim password URN passes through", ACRPassword, ACRPassword, false},
		{"verbatim mfa URN passes through", ACRMFA, ACRMFA, false},
		{"verbatim phishing-resistant URN passes through", ACRPhishingResistant, ACRPhishingResistant, false},
		{"oidc convention 0 → password", "0", ACRPassword, false},
		{"oidc convention 1 → mfa", "1", ACRMFA, false},
		{"phishing-resistant marker substring → top rung", "urn:vendor:phishing-resistant-aal2", ACRPhishingResistant, false},
		{"FIDO marker → top rung", "urn:vendor:auth:fido2", ACRPhishingResistant, false},
		{"webauthn marker → top rung", "https://example.com/acr/WebAuthn-attested", ACRPhishingResistant, false},
		{"passkey marker → top rung", "urn:vendor:passkey", ACRPhishingResistant, false},
		{"unknown vendor string → mfa floor", "urn:vendor:something-else", ACRMFA, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, assumed := MapUpstreamACRToLadder(tc.upstream)
			if got != tc.want || assumed != tc.wantAssumed {
				t.Fatalf("MapUpstreamACRToLadder(%q) = (%q, %v), want (%q, %v)", tc.upstream, got, assumed, tc.want, tc.wantAssumed)
			}
		})
	}
}

// TestACR_IsKnownACR is the validation-boundary helper — returns true only
// for ladder rungs.
func TestACR_IsKnownACR(t *testing.T) {
	known := []string{ACRPassword, ACRMFA, ACRPhishingResistant}
	for _, k := range known {
		if !IsKnownACR(k) {
			t.Fatalf("IsKnownACR(%q) = false, want true", k)
		}
	}
	unknown := []string{"", "0", "1", "loa:mfa", "urn:identuum:loa:passwords", "urn:identuum:loa:biometric"}
	for _, u := range unknown {
		if IsKnownACR(u) {
			t.Fatalf("IsKnownACR(%q) = true, want false", u)
		}
	}
}
