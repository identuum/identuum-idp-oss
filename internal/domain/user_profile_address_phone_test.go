package domain

// user_profile_address_phone_test.go — THE-ADDRESS-PHONE-CLAIMS: phone is
// E.164-validated when supplied; the address claim is built from set members
// only; phone_number_verified is emitted only with phone_number and is never
// true.

import (
	"errors"
	"testing"

	"github.com/google/uuid"
)

func TestUserProfilePatch_PhoneAndAddressValidate(t *testing.T) {
	uid := uuid.New()
	p, err := UserProfilePatch{
		PhoneNumber: sp(" +442079460000 "), AddressFormatted: sp("1 Way\nLondon"),
		AddressStreetAddress: sp("1 Way"), AddressLocality: sp("London"),
		AddressRegion: sp("Greater London"), AddressPostalCode: sp("SW1A 1AA"), AddressCountry: sp("United Kingdom"),
	}.Apply(nil, uid)
	if err != nil {
		t.Fatalf("valid patch: %v", err)
	}
	if *p.PhoneNumber != "+442079460000" || *p.AddressLocality != "London" || p.GivenName != nil {
		t.Errorf("apply = %+v", p)
	}
	// Clear with "".
	p2, err := UserProfilePatch{PhoneNumber: sp(""), AddressRegion: sp("")}.Apply(p, uid)
	if err != nil || p2.PhoneNumber != nil || p2.AddressRegion != nil || *p2.AddressLocality != "London" {
		t.Errorf("clear: err=%v profile=%+v", err, p2)
	}
	for i, bad := range []string{"02079460000", "+0123", "+44 20 7946 0000", "+4420794600001234567", "+", "phone"} {
		if _, err := (UserProfilePatch{PhoneNumber: sp(bad)}).Apply(nil, uid); !errors.Is(err, ErrUserProfileInvalid) {
			t.Errorf("bad[%d] %q: err = %v, want ErrUserProfileInvalid (E.164)", i, bad, err)
		}
	}
	if _, err := (UserProfilePatch{AddressCountry: sp(string(make([]byte, 257)))}).Apply(nil, uid); !errors.Is(err, ErrUserProfileInvalid) {
		t.Errorf("over-long address member must be refused: %v", err)
	}
	if (UserProfilePatch{}).IsEmpty() != true || (UserProfilePatch{AddressCountry: sp("x")}).IsEmpty() {
		t.Errorf("IsEmpty must see the address/phone members")
	}
}

func TestProfileClaims_AddressAndPhone(t *testing.T) {
	user := &User{ID: uuid.New()}
	t.Run("unset never emits, not even an empty object or a lone verified flag", func(t *testing.T) {
		got := ProfileClaims(user, &UserProfile{UserID: user.ID}, append(append([]string{}, AddressClaimNames...), PhoneClaimNames...))
		for _, k := range []string{ClaimAddress, ClaimPhoneNumber, ClaimPhoneNumberVerified} {
			if v, present := got[k]; present {
				t.Errorf("%s unset but emitted %v", k, v)
			}
		}
		if AddressClaim(&UserProfile{}) != nil || AddressClaim(nil) != nil {
			t.Errorf("AddressClaim of an empty profile must be nil")
		}
	})
	t.Run("set emits exactly the set members; verified rides with the number and is false", func(t *testing.T) {
		p := &UserProfile{UserID: user.ID, PhoneNumber: sp("+442079460000"), AddressLocality: sp("London"), AddressCountry: sp("GB")}
		got := ProfileClaims(user, p, append(append([]string{}, AddressClaimNames...), PhoneClaimNames...))
		addr, ok := got[ClaimAddress].(map[string]any)
		if !ok || addr["locality"] != "London" || addr["country"] != "GB" || len(addr) != 2 {
			t.Errorf("address = %v, want exactly {locality, country}", got[ClaimAddress])
		}
		if got[ClaimPhoneNumber] != "+442079460000" || got[ClaimPhoneNumberVerified] != false {
			t.Errorf("phone = %v / %v, want the number and verified=false", got[ClaimPhoneNumber], got[ClaimPhoneNumberVerified])
		}
		// Only the phone requested → address stays out; only address → no phone pair.
		if g := ProfileClaims(user, p, PhoneClaimNames); g[ClaimAddress] != nil || g[ClaimPhoneNumber] == nil {
			t.Errorf("phone-only request: %v", g)
		}
		if g := ProfileClaims(user, p, AddressClaimNames); g[ClaimPhoneNumber] != nil || g[ClaimPhoneNumberVerified] != nil || g[ClaimAddress] == nil {
			t.Errorf("address-only request: %v", g)
		}
	})
	t.Run("the three names are emittable and role-permitted for humans only", func(t *testing.T) {
		for _, n := range []string{ClaimAddress, ClaimPhoneNumber, ClaimPhoneNumberVerified} {
			found := false
			for _, e := range EmittableIdentityClaims {
				if e == n {
					found = true
				}
			}
			if !found {
				t.Errorf("%s must be emittable", n)
			}
		}
		if kept := IntersectConsentedClaims([]string{ClaimAddress, ClaimPhoneNumber}, RoleOrgUser); len(kept) != 2 {
			t.Errorf("human role must keep address+phone: %v", kept)
		}
		if kept := IntersectConsentedClaims([]string{ClaimAddress, ClaimPhoneNumber}, UserRole("service_account")); len(kept) != 0 {
			t.Errorf("non-human role must keep nothing: %v", kept)
		}
	})
}
