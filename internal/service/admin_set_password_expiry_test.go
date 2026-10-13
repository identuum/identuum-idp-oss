package service

// G2 (owner Q-G2 (a) + Q-G2b (a), 2026-10-13): every admin-set password that
// carries the must-change flag (create AND PUT) expires 24 hours after the
// admin set it. must_change_password:false gives a lasting password (no time
// stored). Rows set before the change carry a NULL time and never expire.
// Password sign-in with the flag set and the time passed answers
// ErrLoginPasswordExpired (HTTP 401 {"error":"password_expired",...}); the
// sign-in change step refuses it too. A chosen password (change step, own
// change, either reset) clears the flag AND the time.
//
// RED AT COMPILE at 495885c: the seam does not exist. The minimal seam a
// writer adds first (proposed names; rename here if the writer renames):
//   - migration 0055: users.admin_password_set_at TIMESTAMPTZ NULL;
//   - domain.User.AdminPasswordSetAt *time.Time (nil = no expiry);
//   - repository.UpdateUserOptions.AdminPasswordSetAt *time.Time (nil = leave,
//     pointer to the zero time = write NULL, otherwise write the value);
//   - service.AdminSetPasswordTTL = 24 * time.Hour (shared with the D9 admin
//     link TTL);
//   - service.ErrLoginPasswordExpired;
//   - (*LocalLoginService).WithClock and (*ChangePasswordService).WithClock
//     (func() time.Time; default time.Now), following the With* setters.
// Passwords are never printed.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/lifecycle"
	"github.com/identuum/identuum-idp-oss/internal/repository"
)

var g2Now = time.Date(2026, 10, 13, 9, 0, 0, 0, time.UTC)

func g2Clock() time.Time { return g2Now }

func g2At(d time.Duration) *time.Time { t := g2Now.Add(-d); return &t }

func g2LoginUser(t *testing.T, mustChange bool, setAt *time.Time) *domain.User {
	t.Helper()
	return &domain.User{
		ID: uuid.New(), OrganizationID: uuid.New(), Email: "g2-" + uuid.NewString()[:8] + "@example.com",
		Role: domain.RoleOrgUser, AuthSource: domain.AuthSourceLocal, EmailVerified: true,
		PasswordHash: hashPwd(t, "admin-set"), RequiresPasswordChange: mustChange, AdminPasswordSetAt: setAt,
	}
}

func g2Login(t *testing.T, u *domain.User) (*LoginResult, error) {
	t.Helper()
	svc, users := newLoginHarness(t)
	svc = svc.WithClock(g2Clock)
	users.byEmail[u.Email] = []*domain.User{u}
	return svc.Login(context.Background(), LoginInput{Email: u.Email, Password: "admin-set"})
}

// Within 24 hours the admin-set password still leads to the change step.
func TestG2_Login_WithinTTLAsksForChange(t *testing.T) {
	if AdminSetPasswordTTL != 24*time.Hour {
		t.Fatalf("AdminSetPasswordTTL = %s; want 24h (Q-G2 (a))", AdminSetPasswordTTL)
	}
	_, err := g2Login(t, g2LoginUser(t, true, g2At(AdminSetPasswordTTL-time.Minute)))
	if !errors.Is(err, ErrLoginPasswordChangeRequired) {
		t.Fatalf("err = %v; want ErrLoginPasswordChangeRequired (inside 24h)", err)
	}
}

// After 24 hours the admin-set password is refused: no session, no change step.
// RULE: ADMIN-SET-PASSWORD-EXPIRES-1
func TestG2_Login_AfterTTLIsExpired(t *testing.T) {
	res, err := g2Login(t, g2LoginUser(t, true, g2At(AdminSetPasswordTTL+time.Second)))
	if !errors.Is(err, ErrLoginPasswordExpired) {
		t.Fatalf("err = %v; want ErrLoginPasswordExpired (past 24h)", err)
	}
	if res != nil && (res.Session != nil || res.RefreshToken != "") {
		t.Errorf("an expired admin-set password produced a session or token")
	}
}

// Review F5 (OSS-0913-B-REVIEW): the password is proven before the expiry
// check, so the refusal names its user (the partial-result contract of the
// change step) and the handler's audit row can carry subject and
// organization. Still no session and no token.
func TestG2_Login_ExpiredNamesTheUser(t *testing.T) {
	u := g2LoginUser(t, true, g2At(AdminSetPasswordTTL+time.Second))
	res, err := g2Login(t, u)
	if !errors.Is(err, ErrLoginPasswordExpired) {
		t.Fatalf("err = %v; want ErrLoginPasswordExpired (past 24h)", err)
	}
	if res == nil || res.User == nil || res.User.ID != u.ID {
		t.Fatalf("the expired refusal does not name its user (result %v)", res)
	}
	if res.Session != nil || res.RefreshToken != "" {
		t.Errorf("an expired admin-set password produced a session or token")
	}
}

// A row set before this change (NULL time) never expires; it keeps the
// change step.
func TestG2_Login_NullTimeNeverExpires(t *testing.T) {
	svc, users := newLoginHarness(t)
	svc = svc.WithClock(func() time.Time { return g2Now.Add(365 * 24 * time.Hour) })
	u := g2LoginUser(t, true, nil)
	users.byEmail[u.Email] = []*domain.User{u}
	if _, err := svc.Login(context.Background(), LoginInput{Email: u.Email, Password: "admin-set"}); !errors.Is(err, ErrLoginPasswordChangeRequired) {
		t.Fatalf("err = %v; want ErrLoginPasswordChangeRequired (NULL time: no expiry)", err)
	}
}

// must_change_password:false: a lasting password, no flag, no time.
func TestG2_Login_LastingPasswordDoesNotExpire(t *testing.T) {
	res, err := g2Login(t, g2LoginUser(t, false, nil))
	if err != nil || res == nil || res.Session == nil {
		t.Fatalf("err = %v; want a session for a lasting admin-set password", err)
	}
}

// ---- change step and own change ----

type g2Repo struct {
	repository.UserRepository
	user    *domain.User
	updates int
	last    *repository.UpdateUserOptions
}

func (r *g2Repo) GetByIDWithOrg(_ context.Context, id uuid.UUID) (*domain.User, error) {
	if r.user == nil || r.user.ID != id {
		return nil, domain.ErrUserNotFound
	}
	cp := *r.user
	return &cp, nil
}

func (r *g2Repo) VerifyPassword(_ context.Context, pw, hash string) error {
	if hash != "h:"+pw {
		return errors.New("mismatch")
	}
	return nil
}

func (r *g2Repo) HashPassword(_ context.Context, pw string) (string, error) { return "h:" + pw, nil }

func (r *g2Repo) Update(_ context.Context, _, _ uuid.UUID, o repository.UpdateUserOptions) (*domain.User, error) {
	r.updates++
	cp := o
	r.last = &cp
	if o.Password != nil {
		r.user.PasswordHash = *o.Password
	}
	if o.RequiresPasswordChange != nil {
		r.user.RequiresPasswordChange = *o.RequiresPasswordChange
	}
	if o.AdminPasswordSetAt != nil {
		if o.AdminPasswordSetAt.IsZero() {
			r.user.AdminPasswordSetAt = nil
		} else {
			v := *o.AdminPasswordSetAt
			r.user.AdminPasswordSetAt = &v
		}
	}
	out := *r.user
	return &out, nil
}

func g2ChangeUser(setAt *time.Time) *domain.User {
	return &domain.User{ID: uuid.New(), OrganizationID: uuid.New(), Email: "c@example.test", Role: domain.RoleOrgUser,
		AuthSource: domain.AuthSourceLocal, EmailVerified: true, PasswordHash: "h:Admin-Set-2026!a",
		RequiresPasswordChange: true, AdminPasswordSetAt: setAt}
}

// The change step refuses an expired admin-set password (a handle minted just
// before the 24 hours ran out and redeemed after), and writes nothing.
func TestG2_ChangeStep_RefusesExpired(t *testing.T) {
	repo := &g2Repo{user: g2ChangeUser(g2At(AdminSetPasswordTTL + time.Second))}
	svc := NewChangePasswordService(repo, 8).WithClock(g2Clock)
	if _, err := svc.ChangeRequiredAtSignIn(context.Background(), repo.user.ID, "Member-Own-2026!b"); !errors.Is(err, ErrLoginPasswordExpired) {
		t.Fatalf("err = %v; want ErrLoginPasswordExpired at the change step", err)
	}
	if repo.updates != 0 {
		t.Errorf("the change step wrote %d times for an expired password; want 0", repo.updates)
	}
}

// Inside 24 hours the change step clears the flag AND the time.
func TestG2_ChangeStep_ClearsFlagAndTime(t *testing.T) {
	repo := &g2Repo{user: g2ChangeUser(g2At(time.Hour))}
	svc := NewChangePasswordService(repo, 8).WithClock(g2Clock)
	if _, err := svc.ChangeRequiredAtSignIn(context.Background(), repo.user.ID, "Member-Own-2026!b"); err != nil {
		t.Fatalf("ChangeRequiredAtSignIn: %v", err)
	}
	if repo.user.RequiresPasswordChange || repo.user.AdminPasswordSetAt != nil {
		t.Errorf("after the change step: flag=%v time=%v; want false and NULL", repo.user.RequiresPasswordChange, repo.user.AdminPasswordSetAt)
	}
}

// The member's own change clears the flag AND the time (Q-B2 + G2).
func TestG2_OwnChange_ClearsFlagAndTime(t *testing.T) {
	repo := &g2Repo{user: g2ChangeUser(g2At(time.Hour))}
	svc := NewChangePasswordService(repo, 8).WithClock(g2Clock)
	if err := svc.ChangeOwnPassword(context.Background(), repo.user.ID, "Admin-Set-2026!a", "Member-Own-2026!b"); err != nil {
		t.Fatalf("ChangeOwnPassword: %v", err)
	}
	if repo.user.RequiresPasswordChange || repo.user.AdminPasswordSetAt != nil {
		t.Errorf("after the own change: flag=%v time=%v; want false and NULL", repo.user.RequiresPasswordChange, repo.user.AdminPasswordSetAt)
	}
}

// ---- create stamps the time (D-017 create; PUT is in the api test) ----

type g2CreateRepo struct {
	repository.UserRepository
	created *domain.User
}

func (r *g2CreateRepo) HashPassword(_ context.Context, pw string) (string, error) {
	return "h:" + pw, nil
}
func (r *g2CreateRepo) Create(_ context.Context, u *domain.User) (*domain.User, error) {
	cp := *u
	r.created = &cp
	return &cp, nil
}

// UserService.Create reads time.Now today (no clock seam): tolerance window.
func TestG2_Create_StampsTimeOnlyWithTheFlag(t *testing.T) {
	no := false
	for _, tc := range []struct {
		name  string
		must  *bool
		stamp bool
	}{
		{"default (must change)", nil, true},
		{"must_change_password:false", &no, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo := &g2CreateRepo{}
			svc := NewUserService(lifecycle.NewStartupReport(), repo)
			before := time.Now().Add(-time.Second)
			if _, err := svc.Create(context.Background(), CreateUserOptions{
				OrganizationID: uuid.New(), Email: "n@example.test", Password: "Admin-Set-2026!a",
				Role: domain.RoleOrgUser, MustChangePassword: tc.must,
			}); err != nil {
				t.Fatalf("Create: %v", err)
			}
			got := repo.created.AdminPasswordSetAt
			if !tc.stamp {
				if got != nil {
					t.Errorf("a lasting admin-set password stored a set time %v; want NULL", got)
				}
				return
			}
			if got == nil || got.Before(before) || got.After(time.Now().Add(time.Second)) {
				t.Errorf("AdminPasswordSetAt = %v; want the create time", got)
			}
		})
	}
}
