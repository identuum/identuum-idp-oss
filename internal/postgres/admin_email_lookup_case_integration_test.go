//go:build integration

package postgres_test

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/postgres"
)

// TestUserRepository_GetByEmailAdmin uses real SQL: a mock cannot expose an
// exact-case WHERE clause. The exact stored spelling is a baseline control;
// the other spellings must find the same complete administrative record.
// Each address belongs to one row, including deleted rows. This test does
// not choose a winner when historical deleted addresses are reused.
func TestUserRepository_GetByEmailAdmin(t *testing.T) {
	pool := modelTeethPool(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	repo := postgres.NewPgxUserRepository(pool)
	stamp := time.Date(2026, time.October, 1, 12, 0, 0, 0, time.UTC)

	for _, tc := range []struct {
		name        string
		legacy      bool
		deleted     bool
		banned      bool
		inactiveOrg bool
		nullable    bool
	}{
		{name: "active"},
		{name: "legacy_mixed_case_storage", legacy: true},
		{name: "deleted_user", deleted: true},
		{name: "banned_user", banned: true},
		{name: "inactive_organization", inactiveOrg: true},
		{name: "nullable_fields", nullable: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			orgID := uuid.MustParse(seedScratchOrg(t, pool))
			email := "g4-" + uuid.NewString() + "@example.invalid"
			if tc.legacy {
				// Bypass current writers, which normalize the stored address.
				email = "Legacy-" + uuid.NewString() + "@Example.Invalid"
			}
			want := domain.User{
				ID: uuid.New(), OrganizationID: orgID, Email: email,
				Role: domain.RoleOrgAdmin, AuthSource: domain.AuthSourceLocal,
				PasswordHash: domain.NoPasswordSentinel, Banned: tc.banned,
				CreatedAt: stamp, UpdatedAt: stamp.Add(time.Minute),
			}
			if tc.deleted {
				deletedAt := stamp.Add(2 * time.Minute)
				want.DeletedAt = &deletedAt
			}
			var recoveryJSON any
			if !tc.nullable {
				name, externalID := "Admin lookup fixture", "g4-"+uuid.NewString()
				issuer := "https://idp.example.invalid"
				// Inert fixture markers; never print the returned record or
				// authentication material, even on assertion failure.
				mfa, activation, verification := "g4-inert-mfa", "g4-inert-activation", "g4-inert-verification"
				via := domain.EmailVerifiedViaUpstreamIDP
				lastLogin, expires, adminSet := stamp.Add(3*time.Minute), stamp.Add(time.Hour), stamp.Add(4*time.Minute)
				want.Name, want.ExternalID, want.OIDCIssuer = &name, &externalID, &issuer
				want.MFAEnabled, want.MFASecret = true, &mfa
				want.MFARecoveryCodes = []string{"g4-inert-recovery"}
				recoveryJSON = `["g4-inert-recovery"]`
				want.EmailVerified, want.EmailVerifiedVia = true, &via
				want.RequiresPasswordChange, want.OIDCLinked = true, true
				want.ActivationTokenHash, want.VerificationTokenHash = &activation, &verification
				want.LastLoginAt, want.ActivationTokenExpiresAt, want.AdminPasswordSetAt = &lastLogin, &expires, &adminSet
			}
			// Explicit timestamps and non-default fields pin the existing
			// scanUserWithPassword projection, including its nullable fields.
			_, err := pool.Exec(ctx, `INSERT INTO users
				(id, email, name, organization_id, role, password_hash, banned,
				 email_verified, deleted_at, created_at, updated_at, last_login_at,
				 mfa_enabled, mfa_secret, mfa_recovery_codes, auth_source, external_id,
				 requires_password_change, oidc_linked, oidc_issuer,
				 activation_token_expires_at, activation_token_hash, verification_token_hash,
				 email_verified_via, admin_password_set_at)
				VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15::jsonb,
				        $16,$17,$18,$19,$20,$21,$22,$23,$24,$25)`,
				want.ID, want.Email, want.Name, want.OrganizationID, string(want.Role), want.PasswordHash,
				want.Banned, want.EmailVerified, want.DeletedAt, want.CreatedAt, want.UpdatedAt, want.LastLoginAt,
				want.MFAEnabled, want.MFASecret, recoveryJSON, want.AuthSource, want.ExternalID,
				want.RequiresPasswordChange, want.OIDCLinked, want.OIDCIssuer,
				want.ActivationTokenExpiresAt, want.ActivationTokenHash, want.VerificationTokenHash,
				want.EmailVerifiedVia, want.AdminPasswordSetAt)
			if err != nil {
				t.Fatal("seed administrative lookup row failed (details redacted)")
			}
			t.Cleanup(func() {
				if _, err := pool.Exec(context.Background(), `DELETE FROM users WHERE id = $1`, want.ID); err != nil {
					t.Error("cleanup administrative lookup row failed (details redacted)")
				}
			})
			if tc.inactiveOrg {
				if _, err := pool.Exec(ctx, `UPDATE organizations SET active = false WHERE id = $1`, orgID); err != nil {
					t.Fatal("deactivate fixture organization failed (details redacted)")
				}
			}

			for _, lookup := range []struct{ name, typed string }{
				{"exact_stored_spelling", email},
				{"lowercase", strings.ToLower(email)},
				{"uppercase", strings.ToUpper(email)},
				{"mixed_case", strings.ToLower(strings.Split(email, "@")[0]) + "@Example.INVALID"},
				{"spaces_only", " \t" + email + "\r\n"},
				{"case_and_spaces", " \t" + strings.ToUpper(email) + "\r\n"},
			} {
				t.Run(lookup.name, func(t *testing.T) {
					got, err := repo.GetByEmailAdmin(ctx, lookup.typed)
					if err != nil {
						t.Fatalf("admin lookup must find the singleton account; missing sentinel=%t (details redacted)", errors.Is(err, domain.ErrUserNotFound))
					}
					if got == nil {
						t.Fatal("admin lookup returned nil account without an error")
					}
					// pgx may decode timestamptz in a different location. Compare
					// instants in UTC; preserve every other field, including the
					// stored email spelling and absence of organization projections.
					got.CreatedAt, got.UpdatedAt = got.CreatedAt.UTC(), got.UpdatedAt.UTC()
					for _, at := range []**time.Time{&got.LastLoginAt, &got.DeletedAt, &got.ActivationTokenExpiresAt, &got.AdminPasswordSetAt} {
						if *at != nil {
							utc := (**at).UTC()
							*at = &utc
						}
					}
					if !reflect.DeepEqual(*got, want) {
						t.Error("admin lookup changed the account identity, stored spelling, or return shape (values redacted)")
					}
				})
			}
		})
	}

	t.Run("missing_account", func(t *testing.T) {
		missing := "g4-missing-" + uuid.NewString() + "@example.invalid"
		for _, typed := range []string{missing, " \t" + strings.ToUpper(missing) + "\r\n"} {
			got, err := repo.GetByEmailAdmin(ctx, typed)
			if !errors.Is(err, domain.ErrUserNotFound) {
				t.Error("missing admin lookup must return ErrUserNotFound (details redacted)")
			}
			if got != nil {
				t.Error("missing admin lookup must return a nil account")
			}
		}
	})
}
