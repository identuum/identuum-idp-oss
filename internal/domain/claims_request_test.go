package domain

import (
	"errors"
	"reflect"
	"testing"
)

// THE-CLAIMS-PARAMETER — OIDC Core §5.5 parsing: unknown is ignored,
// malformed is refused, the result is canonical.
func TestParseClaimsRequest(t *testing.T) {
	cases := []struct {
		name    string
		raw     string
		want    ClaimsRequest
		wantErr error
	}{
		{"empty → nothing", "", ClaimsRequest{}, nil},
		{"essential name at userinfo", `{"userinfo":{"name":{"essential":true}}}`, ClaimsRequest{UserInfo: []string{"name"}}, nil},
		{"voluntary null value", `{"userinfo":{"email":null}}`, ClaimsRequest{UserInfo: []string{"email"}}, nil},
		{"id_token member", `{"id_token":{"email_verified":{"essential":true},"name":null}}`, ClaimsRequest{IDToken: []string{"name", "email_verified"}}, nil},
		{"unknown claim ignored, never an error", `{"userinfo":{"name":null,"shoe_size":null,"given_name":{"essential":true}}}`, ClaimsRequest{UserInfo: []string{"name", "given_name"}}, nil},
		{"unknown member ignored", `{"userinfo":{"name":null},"introspection":{"name":null}}`, ClaimsRequest{UserInfo: []string{"name"}}, nil},
		{"member that is not an object ignored", `{"userinfo":["name"],"id_token":{"email":null}}`, ClaimsRequest{IDToken: []string{"email"}}, nil},
		{"only unknown claims → empty request", `{"userinfo":{"shoe_size":null,"eye_color":null}}`, ClaimsRequest{}, nil},
		{"profile family is requestable (THE-PROFILE-CLAIMS)", `{"userinfo":{"locale":null,"picture":null,"updated_at":null}}`, ClaimsRequest{UserInfo: []string{"picture", "locale", "updated_at"}}, nil},
		{"canonical order + dedupe", `{"userinfo":{"email_verified":null,"name":null,"email":null}}`, ClaimsRequest{UserInfo: []string{"name", "email", "email_verified"}}, nil},
		{"malformed JSON → refused", `{"userinfo":`, ClaimsRequest{}, ErrClaimsRequestMalformed},
		{"JSON array → refused", `["userinfo"]`, ClaimsRequest{}, ErrClaimsRequestMalformed},
		{"JSON null → refused", `null`, ClaimsRequest{}, ErrClaimsRequestMalformed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseClaimsRequest(tc.raw)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("ParseClaimsRequest(%s) = %+v, want %+v", tc.raw, got, tc.want)
			}
		})
	}
}

func TestClaimsRequest_TokensEncodeDecode(t *testing.T) {
	req := ClaimsRequest{UserInfo: []string{"name", "email"}, IDToken: []string{"email_verified"}}
	if got := req.Tokens(); !reflect.DeepEqual(got, []string{"userinfo:name", "userinfo:email", "id_token:email_verified"}) {
		t.Errorf("Tokens = %v", got)
	}
	if got := DecodeClaimsRequest(req.Encode()); !reflect.DeepEqual(got, req) {
		t.Errorf("Encode/Decode round trip = %+v, want %+v", got, req)
	}
	if (ClaimsRequest{}).Encode() != "" {
		t.Errorf("empty request must encode to \"\" (NULL column)")
	}
	if got := DecodeClaimsRequest(`{"userinfo":["shoe_size","name"]}`); !reflect.DeepEqual(got, ClaimsRequest{UserInfo: []string{"name"}}) {
		t.Errorf("Decode must re-canonicalise stored data, got %+v", got)
	}
	if got := DecodeClaimsRequest("not json"); !got.IsEmpty() {
		t.Errorf("unparseable stored data → empty, got %+v", got)
	}
}

// Roles authorize, consent restricts — for claims exactly as for scopes.
func TestIntersectConsentedClaims(t *testing.T) {
	for _, role := range []UserRole{RoleOrgUser, RoleOrgAdmin, RoleSiteAdmin} {
		if got := IntersectConsentedClaims([]string{"email", "name"}, role); !reflect.DeepEqual(got, []string{"name", "email"}) {
			t.Errorf("%s: %v, want canonical name,email", role, got)
		}
	}
	if got := IntersectConsentedClaims([]string{"name", "email"}, UserRole("")); got != nil {
		t.Errorf("no role permits nothing, got %v", got)
	}
	if got := IntersectConsentedClaims([]string{"name"}, UserRole("service_account")); got != nil {
		t.Errorf("unknown role permits nothing, got %v", got)
	}
	if got := IntersectConsentedClaims([]string{"shoe_size"}, RoleOrgUser); got != nil {
		t.Errorf("a non-emittable claim never survives, got %v", got)
	}
	if got := IntersectConsentedClaims(nil, RoleOrgUser); got != nil {
		t.Errorf("nothing consented → nothing, got %v", got)
	}
}

func TestClaimsCoverAndJoin(t *testing.T) {
	granted := JoinClaimTokens([]string{"userinfo:name", "id_token:email"})
	if granted != "id_token:email userinfo:name" {
		t.Errorf("JoinClaimTokens must sort: %q", granted)
	}
	if !ClaimsCover(granted, []string{"userinfo:name"}) || !ClaimsCover(granted, nil) {
		t.Errorf("covered cases failed")
	}
	if ClaimsCover(granted, []string{"userinfo:email"}) || ClaimsCover("", []string{"userinfo:name"}) {
		t.Errorf("uncovered cases passed")
	}
}
