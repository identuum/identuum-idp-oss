package domain

// user_profile.go — the OIDC Core §5.1 standard profile claims
// (THE-PROFILE-CLAIMS). Every field is optional; an unset field is NEVER
// emitted, and a value is emitted only when it is truthfully present.

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"
	_ "time/tzdata" // zoneinfo validation must not depend on the host's tz database

	"github.com/google/uuid"
)

// UserProfile is one user's optional OIDC profile row (user_profiles).
// nil pointer = unset. UpdatedAt is the row's last write.
type UserProfile struct {
	UserID            uuid.UUID
	GivenName         *string
	FamilyName        *string
	MiddleName        *string
	Nickname          *string
	PreferredUsername *string
	Profile           *string
	Picture           *string
	Website           *string
	Gender            *string
	Birthdate         *string
	Zoneinfo          *string
	Locale            *string
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

// UserProfilePatch is a partial update: nil = unchanged, pointer to "" =
// clear (unset), any other value = set after validation.
type UserProfilePatch struct {
	GivenName         *string
	FamilyName        *string
	MiddleName        *string
	Nickname          *string
	PreferredUsername *string
	Profile           *string
	Picture           *string
	Website           *string
	Gender            *string
	Birthdate         *string
	Zoneinfo          *string
	Locale            *string
}

// IsEmpty reports whether the patch touches nothing.
func (p UserProfilePatch) IsEmpty() bool {
	for _, f := range p.fields() {
		if f.value != nil {
			return false
		}
	}
	return true
}

type patchField struct {
	claim string
	value *string
}

func (p UserProfilePatch) fields() []patchField {
	return []patchField{
		{"given_name", p.GivenName}, {"family_name", p.FamilyName}, {"middle_name", p.MiddleName},
		{"nickname", p.Nickname}, {"preferred_username", p.PreferredUsername}, {"profile", p.Profile},
		{"picture", p.Picture}, {"website", p.Website}, {"gender", p.Gender},
		{"birthdate", p.Birthdate}, {"zoneinfo", p.Zoneinfo}, {"locale", p.Locale},
	}
}

// ProfileClaimNames are the OIDC §5.1 claims the `profile` scope releases,
// in emission order. `name` comes from users.name; `updated_at` from the
// rows; the twelve in between from UserProfile.
var ProfileClaimNames = []string{
	"name", "given_name", "family_name", "middle_name", "nickname",
	"preferred_username", "profile", "picture", "website", "gender",
	"birthdate", "zoneinfo", "locale", "updated_at",
}

// IsProfileClaim reports whether claim belongs to the profile family.
func IsProfileClaim(claim string) bool {
	for _, c := range ProfileClaimNames {
		if c == claim {
			return true
		}
	}
	return false
}

// ErrUserProfileInvalid is the field-validation sentinel; the error text
// names the field and the rule.
var ErrUserProfileInvalid = errors.New("domain: user profile invalid")

// Field limits and formats. Names/handles are bounded free text; the three
// URL fields must be absolute http(s) URLs; birthdate follows §5.1
// (YYYY-MM-DD, YYYY, or 0000-MM-DD); zoneinfo must resolve in the IANA
// database; locale must be a well-formed BCP47 language tag (RFC 5646
// syntax — language[-script][-region][-variant…]; the domain layer is
// stdlib-only by architecture boundary, so this is a syntax check, not a
// subtag-registry lookup).
const profileTextMax = 256

var (
	birthdateRe = regexp.MustCompile(`^(\d{4}|0000)(-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01]))?$`)
	bcp47Re     = regexp.MustCompile(`^[A-Za-z]{2,8}(-[A-Za-z]{4})?(-(?:[A-Za-z]{2}|\d{3}))?(-(?:[A-Za-z0-9]{5,8}|\d[A-Za-z0-9]{3}))*(-[A-WY-Za-wy-z0-9](-[A-Za-z0-9]{2,8})+)*(-x(-[A-Za-z0-9]{1,8})+)?$`)
)

// Apply returns a copy of base (or an empty profile for userID) with the
// patch applied and validated. Clearing yields nil (unset), never "".
func (p UserProfilePatch) Apply(base *UserProfile, userID uuid.UUID) (*UserProfile, error) {
	out := UserProfile{UserID: userID}
	if base != nil {
		out = *base
		out.UserID = userID
	}
	set := func(dst **string, claim string, v *string) error {
		if v == nil {
			return nil
		}
		s := strings.TrimSpace(*v)
		if s == "" {
			*dst = nil
			return nil
		}
		if err := validateProfileField(claim, s); err != nil {
			return err
		}
		*dst = &s
		return nil
	}
	steps := []struct {
		dst   **string
		claim string
		v     *string
	}{
		{&out.GivenName, "given_name", p.GivenName}, {&out.FamilyName, "family_name", p.FamilyName},
		{&out.MiddleName, "middle_name", p.MiddleName}, {&out.Nickname, "nickname", p.Nickname},
		{&out.PreferredUsername, "preferred_username", p.PreferredUsername}, {&out.Profile, "profile", p.Profile},
		{&out.Picture, "picture", p.Picture}, {&out.Website, "website", p.Website},
		{&out.Gender, "gender", p.Gender}, {&out.Birthdate, "birthdate", p.Birthdate},
		{&out.Zoneinfo, "zoneinfo", p.Zoneinfo}, {&out.Locale, "locale", p.Locale},
	}
	for _, st := range steps {
		if err := set(st.dst, st.claim, st.v); err != nil {
			return nil, err
		}
	}
	return &out, nil
}

func validateProfileField(claim, v string) error {
	if len(v) > profileTextMax {
		return fmt.Errorf("%w: %s exceeds %d characters", ErrUserProfileInvalid, claim, profileTextMax)
	}
	switch claim {
	case "profile", "picture", "website":
		u, err := url.Parse(v)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return fmt.Errorf("%w: %s must be an absolute http(s) URL", ErrUserProfileInvalid, claim)
		}
	case "birthdate":
		if !birthdateRe.MatchString(v) {
			return fmt.Errorf("%w: birthdate must be YYYY-MM-DD, YYYY, or 0000-MM-DD", ErrUserProfileInvalid)
		}
	case "zoneinfo":
		if _, err := time.LoadLocation(v); err != nil || v == "" || v == "Local" {
			return fmt.Errorf("%w: zoneinfo must be an IANA time zone name", ErrUserProfileInvalid)
		}
	case "locale":
		if !bcp47Re.MatchString(v) {
			return fmt.Errorf("%w: locale must be a BCP47 language tag", ErrUserProfileInvalid)
		}
	case "gender":
		if len(v) > 64 {
			return fmt.Errorf("%w: gender exceeds 64 characters", ErrUserProfileInvalid)
		}
	}
	return nil
}

// ProfileClaims renders the profile-family claims that can be TRUTHFULLY
// emitted for user (+ optional profile row): `name` when the user has one,
// each set profile field, and `updated_at` (Unix seconds) as the later of
// the user row's and the profile row's update time. Unset fields are
// absent — never null, never "". `want` limits the output to the named
// claims (nil = every profile claim).
func ProfileClaims(user *User, profile *UserProfile, want []string) map[string]any {
	out := map[string]any{}
	if user == nil {
		return out
	}
	allow := func(claim string) bool {
		if want == nil {
			return true
		}
		for _, w := range want {
			if w == claim {
				return true
			}
		}
		return false
	}
	put := func(claim string, v *string) {
		if v != nil && strings.TrimSpace(*v) != "" && allow(claim) {
			out[claim] = *v
		}
	}
	put("name", user.Name)
	if profile != nil {
		put("given_name", profile.GivenName)
		put("family_name", profile.FamilyName)
		put("middle_name", profile.MiddleName)
		put("nickname", profile.Nickname)
		put("preferred_username", profile.PreferredUsername)
		put("profile", profile.Profile)
		put("picture", profile.Picture)
		put("website", profile.Website)
		put("gender", profile.Gender)
		put("birthdate", profile.Birthdate)
		put("zoneinfo", profile.Zoneinfo)
		put("locale", profile.Locale)
	}
	if allow("updated_at") {
		updated := user.UpdatedAt
		if profile != nil && profile.UpdatedAt.After(updated) {
			updated = profile.UpdatedAt
		}
		if !updated.IsZero() {
			out["updated_at"] = updated.Unix()
		}
	}
	return out
}
