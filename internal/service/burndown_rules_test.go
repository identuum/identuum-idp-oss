package service

import (
	"context"
	"reflect"
	"testing"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// A passwordless create must fail: this product has no invitation path on
// POST /users, so a user without a credential would be a dead row that still
// occupies an email.
// RULE: USER-PW-REQUIRED-1
func TestCreateUserForActor_EmptyPasswordRejected(t *testing.T) {
	repo := newUserRepo()
	svc := NewUserService(nil, repo)
	_, err := svc.CreateUserForActor(context.Background(), siteAdmin(), CreateUserOptions{
		OrganizationID: uuid.New(),
		Email:          "no-password@tenant.test",
		Password:       "",
		Role:           domain.RoleOrgAdmin,
	})
	if err == nil {
		t.Fatal("a passwordless create must be refused; there is no invitation path here")
	}
}

// Every user belongs to exactly one organization; a create that names none
// must be refused, not defaulted.
// RULE: USER-ORG-1
func TestCreateUserForActor_NilOrganizationRejected(t *testing.T) {
	repo := newUserRepo()
	svc := NewUserService(nil, repo)
	_, err := svc.CreateUserForActor(context.Background(), siteAdmin(), CreateUserOptions{
		Email:    "orgless@tenant.test",
		Password: "Tenant-Passw0rd-1!",
		Role:     domain.RoleOrgAdmin,
	})
	if err == nil {
		t.Fatal("a create without an organization must be refused: every user belongs to exactly one organization")
	}
}

// Cross-org moves are forbidden for every actor. The enforcement is
// structural — the update surface carries no organization field at all — so
// this pin covers the WHOLE field set by identity: any new field, organization
// or otherwise, fails the test and forces a deliberate ruling instead of a
// silent widening of the update surface.
// RULE: ORG-MOVE-1
func TestUpdateUserOptions_CarriesNoOrganizationField(t *testing.T) {
	want := map[string]bool{
		"Email":                     true,
		"Password":                  true,
		"Name":                      true,
		"Role":                      true,
		"Banned":                    true,
		"EmailVerified":             true,
		"PasswordComplexityEnabled": true,
		"MinPasswordLength":         true,
	}
	typ := reflect.TypeOf(UpdateUserOptions{})
	if typ.NumField() != len(want) {
		t.Fatalf("UpdateUserOptions has %d fields, want the pinned %d — a new field (an organization mover?) needs an owner ruling and a rule update", typ.NumField(), len(want))
	}
	for i := 0; i < typ.NumField(); i++ {
		if !want[typ.Field(i).Name] {
			t.Errorf("unexpected field %q in UpdateUserOptions — the update surface must not grow silently", typ.Field(i).Name)
		}
	}
}
