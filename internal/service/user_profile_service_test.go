package service

// user_profile_service_test.go — THE-PROFILE-CLAIMS through the service:
// the profile row is patched and read back; emission (domain.ProfileClaims)
// releases ONLY what is set; consent (the claims parameter) and role
// (IntersectConsentedClaims) gate what a client may receive.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

type inMemoryUserProfileRepo struct {
	rows map[uuid.UUID]*domain.UserProfile
	now  time.Time
}

func newUserProfileRepo() *inMemoryUserProfileRepo {
	return &inMemoryUserProfileRepo{rows: map[uuid.UUID]*domain.UserProfile{}, now: time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)}
}

func (r *inMemoryUserProfileRepo) Get(_ context.Context, userID uuid.UUID) (*domain.UserProfile, error) {
	row, ok := r.rows[userID]
	if !ok {
		return nil, nil
	}
	cp := *row
	return &cp, nil
}

func (r *inMemoryUserProfileRepo) Upsert(_ context.Context, p *domain.UserProfile) (*domain.UserProfile, error) {
	cp := *p
	r.now = r.now.Add(time.Second)
	cp.UpdatedAt = r.now
	if existing, ok := r.rows[p.UserID]; ok {
		cp.CreatedAt = existing.CreatedAt
	} else {
		cp.CreatedAt = r.now
	}
	r.rows[p.UserID] = &cp
	out := cp
	return &out, nil
}

func str(s string) *string { return &s }

// RULE: PROFILE-CLAIMS-TRUTHFUL-1
func TestProfileClaims_UnsetNeverEmitsSetEmitsGated(t *testing.T) {
	repo := newUserProfileRepo()
	svc := NewUserProfileService(nil, repo)
	uid := uuid.New()
	user := &domain.User{ID: uid, Name: str("Alice Example"), Role: domain.RoleOrgUser, UpdatedAt: time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)}

	t.Run("unset never emits", func(t *testing.T) {
		prof, err := svc.Get(context.Background(), uid)
		if err != nil || prof != nil {
			t.Fatalf("no row yet: %v %v", prof, err)
		}
		got := domain.ProfileClaims(user, prof, domain.ProfileClaimNames)
		for _, k := range []string{"given_name", "family_name", "middle_name", "nickname", "preferred_username", "profile", "picture", "website", "gender", "birthdate", "zoneinfo", "locale"} {
			if v, present := got[k]; present {
				t.Errorf("%s unset but emitted %v", k, v)
			}
		}
		if got["name"] != "Alice Example" || got["updated_at"] != user.UpdatedAt.Unix() {
			t.Errorf("name/updated_at from the user row expected: %v", got)
		}
	})

	t.Run("set emits, exactly what was set", func(t *testing.T) {
		prof, err := svc.Apply(context.Background(), uid, domain.UserProfilePatch{GivenName: str("Alice"), Locale: str("en-GB"), Website: str("https://alice.example")})
		if err != nil {
			t.Fatalf("Apply: %v", err)
		}
		got := domain.ProfileClaims(user, prof, domain.ProfileClaimNames)
		if got["given_name"] != "Alice" || got["locale"] != "en-GB" || got["website"] != "https://alice.example" {
			t.Errorf("set fields must emit: %v", got)
		}
		if _, present := got["family_name"]; present {
			t.Errorf("family_name was never set and must be absent: %v", got)
		}
		if got["updated_at"] != prof.UpdatedAt.Unix() || !prof.UpdatedAt.After(user.UpdatedAt) {
			t.Errorf("updated_at must follow the profile write: %v vs %v", got["updated_at"], prof.UpdatedAt.Unix())
		}
		// Clearing a field removes it again.
		prof, err = svc.Apply(context.Background(), uid, domain.UserProfilePatch{Website: str("")})
		if err != nil {
			t.Fatalf("clear: %v", err)
		}
		if _, present := domain.ProfileClaims(user, prof, nil)["website"]; present {
			t.Errorf("cleared website must be absent")
		}
	})

	t.Run("consent and role gate the release", func(t *testing.T) {
		prof, _ := svc.Get(context.Background(), uid)
		// Consented via the claims parameter: only the consented names.
		consented := domain.IntersectConsentedClaims([]string{"given_name", "family_name"}, domain.RoleOrgUser)
		got := domain.ProfileClaims(user, prof, consented)
		if got["given_name"] != "Alice" || len(got) != 1 {
			t.Errorf("consented given_name only (family_name unset; locale unconsented): %v", got)
		}
		// No consented claim → nothing.
		if got := domain.ProfileClaims(user, prof, []string{}); len(got) != 0 {
			t.Errorf("empty consent must release nothing: %v", got)
		}
		// Role-forbidden (no human role) → the intersection is empty → nothing.
		if forbidden := domain.IntersectConsentedClaims([]string{"given_name", "locale"}, domain.UserRole("")); forbidden != nil {
			t.Errorf("no-role principal must be permitted nothing: %v", forbidden)
		}
	})

	t.Run("invalid formats are refused, nothing persisted", func(t *testing.T) {
		before, _ := svc.Get(context.Background(), uid)
		if _, err := svc.Apply(context.Background(), uid, domain.UserProfilePatch{Picture: str("not a url")}); !errors.Is(err, domain.ErrUserProfileInvalid) {
			t.Fatalf("err = %v, want ErrUserProfileInvalid", err)
		}
		after, _ := svc.Get(context.Background(), uid)
		if !after.UpdatedAt.Equal(before.UpdatedAt) {
			t.Errorf("a refused patch must not write")
		}
	})

	t.Run("empty patch is a read", func(t *testing.T) {
		before, _ := svc.Get(context.Background(), uid)
		after, err := svc.Apply(context.Background(), uid, domain.UserProfilePatch{})
		if err != nil || !after.UpdatedAt.Equal(before.UpdatedAt) {
			t.Errorf("empty patch: err=%v changed=%v", err, !after.UpdatedAt.Equal(before.UpdatedAt))
		}
	})
}
