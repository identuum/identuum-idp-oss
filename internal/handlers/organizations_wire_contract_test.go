package handlers

// WIRE-CONTRACT-ORG-1 — the org read surface's JSON key set is pinned
// EXACTLY (THE-RED-PROOF-FLOOR, anti-drift for PHANTOM-NO-ADMIN's class).
//
// The defect class: the UI read a key (`is_claimed`) the backend never
// emitted, and nothing on either side noticed — the wire contract lived
// in two heads and matched in neither. This pin makes the emitting side
// loud: adding, removing, or renaming any safeOrganization JSON key, or
// flipping a field's omitempty, fails against the hard-coded contract
// below. The UI-side twin (WIRE-READ-ORG-1, identuum-ui) pins that the
// mappers read only these keys.

import (
	"encoding/json"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// The CONTRACT. Sorted. Changing safeOrganization means consciously
// editing these lists — and the UI twin — in the same review.
var (
	wireOrgKeysAlways = []string{
		"active",
		"allow_public_registration",
		"auth_policy",
		"created_at",
		"domain",
		"id",
		"local_admin_only",
		"max_sessions_per_user",
		"mfa_policy",
		"name",
		"org_slug",
		"password_complexity_enabled",
		"require_registration_approval",
		"require_strict_reauth",
		"tier",
		"updated_at",
	}
	// omitempty: ABSENT unless set. is_claimed/can_assign_admin are the
	// tri-state admin projection — their absence is load-bearing
	// (ABSENT ≠ NEGATIVE), so they must stay pointer+omitempty.
	wireOrgKeysOmitEmpty = []string{
		"api_authorization_policy",
		"can_assign_admin",
		"deleted_at",
		"is_claimed",
	}
)

func marshaledKeys(t *testing.T, v any) []string {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func sortedUnion(a, b []string) []string {
	out := append(append([]string{}, a...), b...)
	sort.Strings(out)
	return out
}

// RULE: WIRE-CONTRACT-ORG-1
func TestWireContractOrg_JSONKeySetIsPinned(t *testing.T) {
	// 1. STRUCT pin, by reflection over the whole field set: tag names
	// and omitempty flags must equal the contract exactly — a drifted
	// field fails here before any marshaling.
	var gotAlways, gotOmit []string
	rt := reflect.TypeOf(safeOrganization{})
	for i := 0; i < rt.NumField(); i++ {
		f := rt.Field(i)
		name, opts, _ := strings.Cut(f.Tag.Get("json"), ",")
		if name == "" || name == "-" {
			t.Fatalf("field %s: every safeOrganization field must carry an explicit json name", f.Name)
		}
		if strings.Contains(opts, "omitempty") {
			gotOmit = append(gotOmit, name)
		} else {
			gotAlways = append(gotAlways, name)
		}
	}
	sort.Strings(gotAlways)
	sort.Strings(gotOmit)
	if !reflect.DeepEqual(gotAlways, wireOrgKeysAlways) {
		t.Fatalf("always-emitted key set drifted:\n got  %v\n want %v", gotAlways, wireOrgKeysAlways)
	}
	if !reflect.DeepEqual(gotOmit, wireOrgKeysOmitEmpty) {
		t.Fatalf("omitempty key set drifted:\n got  %v\n want %v", gotOmit, wireOrgKeysOmitEmpty)
	}

	// 2. A fully-populated instance emits EXACTLY always ∪ omitempty.
	yes := true
	now := time.Now().UTC()
	full := safeOrganization{
		ID:                     uuid.Must(uuid.NewV7()),
		Name:                   "n",
		Domain:                 "d.test",
		OrgSlug:                "n",
		Active:                 true,
		MaxSessionsPerUser:     1,
		MFAPolicy:              "optional",
		AuthPolicy:             "local_only",
		ApiAuthorizationPolicy: "rbac",
		Tier:                   "starter",
		CreatedAt:              now,
		UpdatedAt:              now,
		DeletedAt:              &now,
		IsClaimed:              &yes,
		CanAssignAdmin:         &yes,
	}
	if got, want := marshaledKeys(t, full), sortedUnion(wireOrgKeysAlways, wireOrgKeysOmitEmpty); !reflect.DeepEqual(got, want) {
		t.Fatalf("full payload key set drifted:\n got  %v\n want %v", got, want)
	}

	// 3. A zero instance emits EXACTLY the always set: the tri-state
	// admin fields VANISH — they can never read as false-by-default.
	if got := marshaledKeys(t, safeOrganization{}); !reflect.DeepEqual(got, wireOrgKeysAlways) {
		t.Fatalf("zero payload key set drifted:\n got  %v\n want %v", got, wireOrgKeysAlways)
	}
	t.Logf("EVIDENCE wire contract: %d always + %d omitempty keys pinned", len(wireOrgKeysAlways), len(wireOrgKeysOmitEmpty))
}
