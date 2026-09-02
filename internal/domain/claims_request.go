package domain

// claims_request.go — the OIDC Core §5.5 `claims` request parameter
// (THE-CLAIMS-PARAMETER), reduced to what this OP can truthfully emit.
//
// §5.5.1: "The Claims requested by the profile, email, address, and phone
// scope values are requested to be returned from the UserInfo Endpoint ...
// The Claims parameter can also be used to request particular Claims."
// Unknown members and unknown claim names are IGNORED — never an error;
// only a `claims` value that is not a JSON object is malformed.

import (
	"encoding/json"
	"errors"
	"sort"
	"strings"
)

// EmittableIdentityClaims are the individually-requestable identity claims
// this OP can supply from the user record and its optional profile row
// (THE-PROFILE-CLAIMS): the whole OIDC §5.1 profile family plus the email
// pair. The order is canonical: every derived list (consent tokens, token
// claim, id_token emission) follows it.
var EmittableIdentityClaims = []string{
	"name", "given_name", "family_name", "middle_name", "nickname",
	"preferred_username", "profile", "picture", "website", "gender",
	"birthdate", "zoneinfo", "locale", "updated_at",
	"email", "email_verified",
	// THE-ADDRESS-PHONE-CLAIMS: the §5.1 address and phone claims.
	"address", "phone_number", "phone_number_verified",
}

// ErrClaimsRequestMalformed: the `claims` parameter was present but is not
// a JSON object (OIDC Core §5.5 requires one). Unknown content inside a
// valid object is never an error.
var ErrClaimsRequestMalformed = errors.New("domain: claims request is not a JSON object")

// ClaimsRequest is the parsed `claims` parameter: the emittable claim names
// requested for the userinfo response and for the id_token, each in
// canonical order, deduplicated. Essential vs voluntary is parsed and then
// treated identically — §5.5.1 lets an OP omit even an essential claim it
// cannot supply, and consent covers the claim NAME either way.
type ClaimsRequest struct {
	UserInfo []string `json:"userinfo,omitempty"`
	IDToken  []string `json:"id_token,omitempty"`
}

// IsEmpty reports whether nothing emittable was requested.
func (c ClaimsRequest) IsEmpty() bool { return len(c.UserInfo) == 0 && len(c.IDToken) == 0 }

// Tokens renders the request as consent tokens — "userinfo:name",
// "id_token:email" — the unit a consent row stores and covers.
func (c ClaimsRequest) Tokens() []string {
	out := make([]string, 0, len(c.UserInfo)+len(c.IDToken))
	for _, n := range c.UserInfo {
		out = append(out, "userinfo:"+n)
	}
	for _, n := range c.IDToken {
		out = append(out, "id_token:"+n)
	}
	return out
}

// Encode renders the canonical JSON persisted on the code row ("" when
// empty, so the column stays NULL).
func (c ClaimsRequest) Encode() string {
	if c.IsEmpty() {
		return ""
	}
	b, err := json.Marshal(c)
	if err != nil {
		return ""
	}
	return string(b)
}

// DecodeClaimsRequest is the inverse of Encode. Unparseable stored data
// yields an empty request — a persisted row can only have come from Encode.
func DecodeClaimsRequest(s string) ClaimsRequest {
	var out ClaimsRequest
	if strings.TrimSpace(s) == "" {
		return out
	}
	if err := json.Unmarshal([]byte(s), &out); err != nil {
		return ClaimsRequest{}
	}
	out.UserInfo = canonicalClaims(out.UserInfo)
	out.IDToken = canonicalClaims(out.IDToken)
	return out
}

// ParseClaimsRequest parses the raw `claims` parameter. "" → empty request.
// A value that is not a JSON object → ErrClaimsRequestMalformed. Inside the
// object: only the "userinfo" and "id_token" members are read; a member
// whose value is not an object is ignored; a claim whose name is not in
// EmittableIdentityClaims is ignored; the per-claim value (null, or an
// object carrying essential/value/values) is accepted and not interpreted.
func ParseClaimsRequest(raw string) (ClaimsRequest, error) {
	if strings.TrimSpace(raw) == "" {
		return ClaimsRequest{}, nil
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &top); err != nil || top == nil {
		return ClaimsRequest{}, ErrClaimsRequestMalformed
	}
	return ClaimsRequest{
		UserInfo: parseClaimsMember(top["userinfo"]),
		IDToken:  parseClaimsMember(top["id_token"]),
	}, nil
}

func parseClaimsMember(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var member map[string]json.RawMessage
	if err := json.Unmarshal(raw, &member); err != nil || member == nil {
		return nil // not an object → ignored (§5.5.1: unknown/unsupported is not an error)
	}
	names := make([]string, 0, len(member))
	for name := range member {
		names = append(names, name)
	}
	return canonicalClaims(names)
}

// canonicalClaims keeps the emittable names, deduplicated, in the canonical
// EmittableIdentityClaims order.
func canonicalClaims(names []string) []string {
	want := make(map[string]struct{}, len(names))
	for _, n := range names {
		want[n] = struct{}{}
	}
	var out []string
	for _, e := range EmittableIdentityClaims {
		if _, ok := want[e]; ok {
			out = append(out, e)
		}
	}
	return out
}

// PermittedClaimsForRole mirrors PermittedScopesForRole for individual
// identity claims: every human role may release its own identity claims to
// a consented client; an empty or unknown role (no authenticated human
// role) permits none. Roles authorize; consent restricts.
func PermittedClaimsForRole(role UserRole) []string {
	switch role {
	case RoleSiteAdmin, RoleOrgAdmin, RoleOrgUser:
		return append([]string(nil), EmittableIdentityClaims...)
	default:
		return nil
	}
}

// IntersectConsentedClaims is TOKEN-SCOPE-INTERSECTION-1 for claims: the
// consented claim names INTERSECTED with what the role permits, canonical
// order. Consent never grants a claim the role does not permit.
func IntersectConsentedClaims(consented []string, role UserRole) []string {
	permitted := make(map[string]struct{})
	for _, p := range PermittedClaimsForRole(role) {
		permitted[p] = struct{}{}
	}
	var kept []string
	for _, c := range consented {
		if _, ok := permitted[c]; ok {
			kept = append(kept, c)
		}
	}
	return canonicalClaims(kept)
}

// ClaimsCover reports whether every requested consent token already appears
// in the granted set (both space-separated). Empty requested → covered.
func ClaimsCover(granted string, requested []string) bool {
	if len(requested) == 0 {
		return true
	}
	have := map[string]struct{}{}
	for _, g := range strings.Fields(granted) {
		have[g] = struct{}{}
	}
	for _, r := range requested {
		if _, ok := have[r]; !ok {
			return false
		}
	}
	return true
}

// JoinClaimTokens renders consent tokens as the stored space-separated
// string, sorted for a stable row.
func JoinClaimTokens(tokens []string) string {
	if len(tokens) == 0 {
		return ""
	}
	cp := append([]string(nil), tokens...)
	sort.Strings(cp)
	return strings.Join(cp, " ")
}
