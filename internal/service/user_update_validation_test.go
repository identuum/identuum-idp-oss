package service

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/repository"
)

// recordingUserRepo records WHAT reached the repository. The embedded
// interface is nil on purpose: any method this test does not stub is a
// method the guard must never reach, and a nil-dereference names it loudly.
type recordingUserRepo struct {
	repository.UserRepository
	updateCalls int
	lastOpts    repository.UpdateUserOptions
}

func (r *recordingUserRepo) Update(_ context.Context, _ uuid.UUID, _ uuid.UUID, opts repository.UpdateUserOptions) (*domain.User, error) {
	r.updateCalls++
	r.lastOpts = opts
	return &domain.User{ID: uuid.New(), Email: "recorded@example.com", Role: domain.RoleOrgUser}, nil
}

// THE-UNVALIDATED-REST (2026-08-31): UserService.Update validated ONLY the
// password and handed Email and Role to the repository raw. The users
// chk_user_email_format CHECK constraint and the user_role ENUM were the
// only guards, so a malformed email or an unlisted role answered
// 500 internal_error — a server-fault status for the caller's own typo.
//
// The proof asserts THROUGH the service with a recording repository, not
// against validateUserUpdate directly: a helper-level proof survives the
// guard being deleted from Update(), which is exactly how the organization
// version of this test passed while the path was unguarded.
//
// RULE: USER-UPDATE-VALIDATION-1
func TestUserServiceUpdate_RefusesMalformedBeforeReachingTheRepository(t *testing.T) {
	orgID := uuid.New()

	// ── every shape the create path refuses, the update path must refuse ──
	for _, bad := range []struct {
		why  string
		opts UpdateUserOptions
	}{
		{"email with no @ or domain", UpdateUserOptions{Email: strPtr("not-an-email")}},
		{"email that is whitespace only", UpdateUserOptions{Email: strPtr("   ")}},
		{"email that is empty", UpdateUserOptions{Email: strPtr("")}},
		{"email with no local part", UpdateUserOptions{Email: strPtr("@example.com")}},
		{"email with no domain", UpdateUserOptions{Email: strPtr("someone@")}},
		{"role outside the user_role enum", UpdateUserOptions{Role: rolePtr(domain.UserRole("wizard"))}},
		{"role that is empty", UpdateUserOptions{Role: rolePtr(domain.UserRole(""))}},
	} {
		repo := &recordingUserRepo{}
		svc := NewUserService(nil, repo)
		if _, err := svc.Update(context.Background(), uuid.New(), orgID, bad.opts); err == nil {
			t.Errorf("Service.Update ACCEPTED %s — the update path is unguarded", bad.why)
		} else if !strings.Contains(err.Error(), "user invalid") {
			t.Errorf("%s: refusal is not the ErrUserInvalid sentinel (%v) — the handler would answer 500, not 400", bad.why, err)
		}
		if repo.updateCalls != 0 {
			t.Errorf("%s: the repository was called %d time(s) with an invalid value", bad.why, repo.updateCalls)
		}
	}

	// ── and every legitimate change must still reach the repository ──
	for _, ok := range []struct {
		why  string
		opts UpdateUserOptions
	}{
		{"an empty option set changes nothing", UpdateUserOptions{}},
		{"a well-formed email", UpdateUserOptions{Email: strPtr("someone@example.com")}},
		{"an address with a display name (RFC 5322)", UpdateUserOptions{Email: strPtr("Someone <someone@example.com>")}},
		{"a listed role", UpdateUserOptions{Role: rolePtr(domain.RoleOrgAdmin)}},
		{"a name", UpdateUserOptions{Name: strPtr("Someone")}},
		{"banned, a boolean with no grammar", UpdateUserOptions{Banned: boolPtr(true)}},
	} {
		repo := &recordingUserRepo{}
		svc := NewUserService(nil, repo)
		if _, err := svc.Update(context.Background(), uuid.New(), orgID, ok.opts); err != nil {
			t.Errorf("Service.Update rejected a legitimate change (%s): %v", ok.why, err)
		}
		if repo.updateCalls != 1 {
			t.Errorf("%s: repository update calls = %d, want 1", ok.why, repo.updateCalls)
		}
	}

	// ── NOT normalized, deliberately: create neither trims nor lowercases a
	// user email, so trimming here would make the two paths disagree about
	// what one address is. This pins the SAMENESS, not a transformation.
	repo := &recordingUserRepo{}
	svc := NewUserService(nil, repo)
	if _, err := svc.Update(context.Background(), uuid.New(), orgID, UpdateUserOptions{
		Email: strPtr("Someone@Example.COM"),
	}); err != nil {
		t.Fatalf("Service.Update rejected a mixed-case address: %v", err)
	}
	if repo.lastOpts.Email == nil || *repo.lastOpts.Email != "Someone@Example.COM" {
		t.Fatalf("the update path transformed the email to %v; create stores it verbatim, so the two paths must agree", repo.lastOpts.Email)
	}
}

func rolePtr(r domain.UserRole) *domain.UserRole { return &r }
func boolPtr(b bool) *bool                       { return &b }
