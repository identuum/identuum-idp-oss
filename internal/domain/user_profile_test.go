package domain

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

func sp(s string) *string { return &s }

// THE-PROFILE-CLAIMS: every field optional; formats validated; "" clears.
func TestUserProfilePatch_ApplyValidates(t *testing.T) {
	uid := uuid.New()
	p, err := UserProfilePatch{
		GivenName: sp(" Alice "), FamilyName: sp("Example"), Nickname: sp("ali"),
		PreferredUsername: sp("alice"), Profile: sp("https://example.com/alice"),
		Picture: sp("https://example.com/alice.png"), Website: sp("http://example.com"),
		Gender: sp("female"), Birthdate: sp("1990-05-17"), Zoneinfo: sp("Europe/Paris"), Locale: sp("fr-FR"),
	}.Apply(nil, uid)
	if err != nil {
		t.Fatalf("valid patch: %v", err)
	}
	if p.UserID != uid || *p.GivenName != "Alice" || p.MiddleName != nil {
		t.Errorf("apply = %+v (trimmed given_name, untouched middle_name expected)", p)
	}
	// Clear with "" → nil, never "".
	p2, err := UserProfilePatch{GivenName: sp("")}.Apply(p, uid)
	if err != nil || p2.GivenName != nil || *p2.FamilyName != "Example" {
		t.Errorf("clear: err=%v profile=%+v", err, p2)
	}
	bad := []UserProfilePatch{
		{Website: sp("example.com")}, {Picture: sp("ftp://x/y.png")}, {Profile: sp("javascript:alert(1)")},
		{Birthdate: sp("17/05/1990")}, {Birthdate: sp("1990-13-01")},
		{Zoneinfo: sp("Mars/Olympus")}, {Zoneinfo: sp("Local")},
		{Locale: sp("not a locale!!")},
		{Gender: sp(string(make([]byte, 65)))},
		{Nickname: sp(string(make([]byte, 257)))},
	}
	for i, b := range bad {
		if _, err := b.Apply(nil, uid); !errors.Is(err, ErrUserProfileInvalid) {
			t.Errorf("bad[%d] %+v: err = %v, want ErrUserProfileInvalid", i, b, err)
		}
	}
	for _, ok := range []string{"1990", "0000-05-17"} {
		if _, err := (UserProfilePatch{Birthdate: sp(ok)}).Apply(nil, uid); err != nil {
			t.Errorf("birthdate %q must be accepted (§5.1): %v", ok, err)
		}
	}
}

// Unset is NEVER emitted; set emits; updated_at is the later row time.
func TestProfileClaims_TruthfulEmission(t *testing.T) {
	userUpdated := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	profileUpdated := time.Date(2026, 9, 2, 10, 0, 0, 0, time.UTC)
	user := &User{ID: uuid.New(), Name: sp("Alice Example"), UpdatedAt: userUpdated}

	// No profile row: only name + updated_at (from the user row).
	got := ProfileClaims(user, nil, nil)
	if len(got) != 2 || got["name"] != "Alice Example" || got["updated_at"] != userUpdated.Unix() {
		t.Errorf("no profile row: %v", got)
	}
	// Partially set profile: exactly the set fields.
	prof := &UserProfile{GivenName: sp("Alice"), Locale: sp("fr-FR"), Gender: sp(""), UpdatedAt: profileUpdated}
	got = ProfileClaims(user, prof, nil)
	if got["given_name"] != "Alice" || got["locale"] != "fr-FR" {
		t.Errorf("set fields missing: %v", got)
	}
	for _, unset := range []string{"family_name", "middle_name", "nickname", "preferred_username", "profile", "picture", "website", "gender", "birthdate", "zoneinfo"} {
		if _, present := got[unset]; present {
			t.Errorf("%s is unset and must be ABSENT (no placeholder): %v", unset, got[unset])
		}
	}
	if got["updated_at"] != profileUpdated.Unix() {
		t.Errorf("updated_at = %v, want the later profile row time %d", got["updated_at"], profileUpdated.Unix())
	}
	// want limits the output to the named claims.
	got = ProfileClaims(user, prof, []string{"locale", "middle_name"})
	if len(got) != 1 || got["locale"] != "fr-FR" {
		t.Errorf("want-filter: %v", got)
	}
	// A user without a name emits no name.
	if got := ProfileClaims(&User{UpdatedAt: userUpdated}, nil, nil); got["name"] != nil {
		t.Errorf("nameless user emitted name: %v", got)
	}
	if ProfileClaims(nil, prof, nil)["given_name"] != nil {
		t.Errorf("nil user must emit nothing")
	}
}

func TestProfileClaimNames_MatchEmittableIdentityClaims(t *testing.T) {
	for _, c := range ProfileClaimNames {
		found := false
		for _, e := range EmittableIdentityClaims {
			if e == c {
				found = true
			}
		}
		if !found || !IsProfileClaim(c) {
			t.Errorf("%q must be emittable and a profile claim", c)
		}
	}
	if IsProfileClaim("email") {
		t.Errorf("email is not a profile-family claim")
	}
}
