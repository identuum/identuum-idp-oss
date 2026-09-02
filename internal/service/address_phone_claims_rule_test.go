package service

// address_phone_claims_rule_test.go — RULE: ADDRESS-PHONE-TRUTHFUL-1
// (THE-ADDRESS-PHONE-CLAIMS). Through the profile service and the domain
// emitter: an unset address/phone never emits (no empty object, no lone
// verified flag, no placeholder); a set one emits exactly what was set;
// phone_number_verified is never true; consent and role gate the release.

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// RULE: ADDRESS-PHONE-TRUTHFUL-1
func TestAddressPhoneClaims_UnsetNeverEmitsSetEmitsVerifiedNeverTrueGated(t *testing.T) {
	repo := newUserProfileRepo()
	svc := NewUserProfileService(nil, repo)
	uid := uuid.New()
	user := &domain.User{ID: uid, Role: domain.RoleOrgUser, UpdatedAt: time.Date(2026, 9, 2, 0, 0, 0, 0, time.UTC)}
	want := append(append([]string{}, domain.AddressClaimNames...), domain.PhoneClaimNames...)

	t.Run("unset never emits", func(t *testing.T) {
		prof, err := svc.Get(context.Background(), uid)
		if err != nil || prof != nil {
			t.Fatalf("no row yet: %v %v", prof, err)
		}
		got := domain.ProfileClaims(user, prof, want)
		for _, k := range []string{"address", "phone_number", "phone_number_verified"} {
			if v, present := got[k]; present {
				t.Errorf("%s unset but emitted %v", k, v)
			}
		}
		// A profile row with other fields but no address/phone → still nothing.
		prof, err = svc.Apply(context.Background(), uid, domain.UserProfilePatch{GivenName: str("Alice")})
		if err != nil {
			t.Fatalf("Apply: %v", err)
		}
		got = domain.ProfileClaims(user, prof, want)
		for _, k := range []string{"address", "phone_number", "phone_number_verified"} {
			if v, present := got[k]; present {
				t.Errorf("%s unset (profile row exists) but emitted %v", k, v)
			}
		}
	})

	t.Run("set emits exactly what was set; verified is false, never true", func(t *testing.T) {
		prof, err := svc.Apply(context.Background(), uid, domain.UserProfilePatch{
			PhoneNumber: str("+442079460000"), AddressStreetAddress: str("1 Conformance Way"),
			AddressLocality: str("London"), AddressPostalCode: str("SW1A 1AA"), AddressCountry: str("United Kingdom"),
		})
		if err != nil {
			t.Fatalf("Apply: %v", err)
		}
		got := domain.ProfileClaims(user, prof, want)
		addr, ok := got["address"].(map[string]any)
		if !ok || addr["street_address"] != "1 Conformance Way" || addr["locality"] != "London" || addr["postal_code"] != "SW1A 1AA" || addr["country"] != "United Kingdom" {
			t.Fatalf("address = %v, want the four set members", got["address"])
		}
		for _, unset := range []string{"formatted", "region"} {
			if v, present := addr[unset]; present {
				t.Errorf("address.%s was never set and must be absent: %v", unset, v)
			}
		}
		if got["phone_number"] != "+442079460000" {
			t.Errorf("phone_number = %v", got["phone_number"])
		}
		if v, ok := got["phone_number_verified"].(bool); !ok || v {
			t.Errorf("phone_number_verified = %v, want false (identuum has no phone verification event)", got["phone_number_verified"])
		}
		// A malformed number is refused before it can ever be emitted.
		if _, err := svc.Apply(context.Background(), uid, domain.UserProfilePatch{PhoneNumber: str("020 7946 0000")}); err == nil {
			t.Errorf("non-E.164 phone must be refused")
		}
		// Clearing the number removes the pair.
		prof, err = svc.Apply(context.Background(), uid, domain.UserProfilePatch{PhoneNumber: str("")})
		if err != nil {
			t.Fatalf("clear: %v", err)
		}
		got = domain.ProfileClaims(user, prof, want)
		if _, p1 := got["phone_number"]; p1 {
			t.Errorf("cleared phone_number must be absent")
		}
		if _, p2 := got["phone_number_verified"]; p2 {
			t.Errorf("phone_number_verified must never stand alone")
		}
	})

	t.Run("consent and role gate the release", func(t *testing.T) {
		prof, _ := svc.Get(context.Background(), uid)
		// Consented via the claims parameter: only the consented names.
		consented := domain.IntersectConsentedClaims([]string{"address", "given_name"}, domain.RoleOrgUser)
		got := domain.ProfileClaims(user, prof, consented)
		if got["address"] == nil || got["given_name"] != "Alice" || len(got) != 2 {
			t.Errorf("consented address+given_name only: %v", got)
		}
		// Scope-shaped want without address → none.
		if got := domain.ProfileClaims(user, prof, domain.PhoneClaimNames); got["address"] != nil {
			t.Errorf("phone scope must not release the address: %v", got)
		}
		// Empty consent → nothing.
		if got := domain.ProfileClaims(user, prof, []string{}); len(got) != 0 {
			t.Errorf("empty consent must release nothing: %v", got)
		}
		// Non-human role → the intersection is empty, nothing personal.
		if kept := domain.IntersectConsentedClaims([]string{"address", "phone_number"}, domain.UserRole("service_account")); len(kept) != 0 {
			t.Errorf("service accounts never receive address/phone: %v", kept)
		}
	})
}
