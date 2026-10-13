package service

// D9 (AGENTS.md §C): the administrator's reset link and its token never reach
// a log line, on issue or on redeem, including the redeem's error lines. The
// audit half is TestD9_AuditedWithoutTheLink (internal/api, which may not
// import zap).

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

var linkTestNow = time.Date(2026, 10, 13, 9, 0, 0, 0, time.UTC)

// linkStoreFake adds the D9 store method to the reset fake and claims on the
// test clock.
type linkStoreFake struct {
	*fakePasswordResetRepo
}

func (r linkStoreFake) CreateRetiringOthers(ctx context.Context, row *domain.PasswordReset) error {
	return r.Create(ctx, row)
}

func (r linkStoreFake) ClaimPasswordReset(_ context.Context, hash, _ string) (uuid.UUID, bool, error) {
	row, ok := r.rows[hash]
	if !ok || row.UsedAt != nil || !row.ExpiresAt.After(linkTestNow) {
		return uuid.Nil, false, nil
	}
	used := linkTestNow
	row.UsedAt = &used
	return row.UserID, true, nil
}

func TestIssueLink_LogsNeitherTokenNorLink(t *testing.T) {
	user := newPasswordResetUser(t, "member@example.test")
	user.EmailVerified = true
	user.PasswordHash = "$argon2id$test$old"
	core, logs := observer.New(zap.DebugLevel)
	svc := NewPasswordResetService(PasswordResetServiceConfig{
		Users:  newFakeUserRepo(user),
		Resets: linkStoreFake{newFakePasswordResetRepo()},
		Logger: zap.New(core),
		Now:    func() time.Time { return linkTestNow },
	}).WithRefreshTokenRevoker(&fakeRefreshTokenRevoker{err: errors.New("refresh store down")})

	raw, expires, err := svc.IssueLink(context.Background(), user)
	require.NoError(t, err)
	require.Equal(t, linkTestNow.Add(AdminSetPasswordTTL), expires)
	// A refused redeem, then one that sets the password and logs the failed
	// revocation (an ERROR line naming the user).
	require.ErrorIs(t, svc.ResetPassword(context.Background(), ResetPasswordInput{Token: raw, NewPassword: "short"}), ErrPasswordResetWeakPassword)
	require.ErrorIs(t, svc.ResetPassword(context.Background(), ResetPasswordInput{Token: raw, NewPassword: "Member-Own-Pass-2026!x"}), ErrPasswordResetRevocationFailed)

	if logs.Len() == 0 {
		t.Fatal("no log line was written; the check below would prove nothing")
	}
	for _, e := range logs.All() {
		line := e.Message + fmt.Sprintf("%v", e.ContextMap())
		if strings.Contains(line, raw) || strings.Contains(line, "reset-link") {
			t.Errorf("log line %q carries the token or the link", e.Message)
		}
	}
}
