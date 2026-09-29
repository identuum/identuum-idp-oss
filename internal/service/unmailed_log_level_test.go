package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// failingNotifier is a configured transport that fails to deliver.
type failingNotifier struct{ UnconfiguredEmailNotifier }

var errSMTPDown = errors.New("smtp: 421 service not available")

func (failingNotifier) SendUserInviteEmail(context.Context, *domain.User, string, time.Time) error {
	return errSMTPDown
}
func (failingNotifier) SendActivationEmail(context.Context, *domain.User, string, time.Time) error {
	return errSMTPDown
}

// OSS-POLISH item 4 (D-016: no SMTP is the default). An invite or activation
// that is not mailed because delivery is not configured is the expected path
// — the admin hands the link over — so it logs at Info, "not mailed: delivery
// not configured". A configured transport that FAILS still logs Warn.
func TestUnmailedInviteAndActivation_InfoWhenNotConfigured_WarnWhenDeliveryFails(t *testing.T) {
	orgID := uuid.New()
	id, err := uuid.NewV7()
	require.NoError(t, err)
	user := &domain.User{ID: id, OrganizationID: orgID, Email: "unmailed@acme.test", Role: domain.RoleOrgAdmin, AuthSource: domain.AuthSourceLocal}
	org := &domain.Organization{ID: orgID, Name: "Acme", Domain: "acme.test", OrgSlug: "acme"}

	send := func(t *testing.T, n interface {
		SendUserInviteEmail(context.Context, *domain.User, string, time.Time) error
		SendActivationEmail(context.Context, *domain.User, string, time.Time) error
	}) *observer.ObservedLogs {
		t.Helper()
		core, logs := observer.New(zapcore.DebugLevel)
		lg := zap.New(core)
		fixed := func() time.Time { return seamEpoch }
		(&UserService{}).WithInvite(UserInviteConfig{Notifier: n, Logger: lg, Now: fixed}).
			mailInvite(context.Background(), user, "raw", seamEpoch.Add(time.Hour))
		orgs := newFakeOrgRepo(org)
		svc := NewOrganizationActivationService(OrganizationActivationServiceConfig{
			Users: newFakeUserRepo(user), Orgs: orgs, OrgsAdmin: orgs,
			Audit: audit.NoopService{}, Notifier: n.(OrganizationActivationNotifier), Logger: lg, Now: fixed,
		})
		_, _, err := svc.IssueActivationToken(context.Background(), user)
		require.NoError(t, err)
		return logs
	}

	logs := send(t, UnconfiguredEmailNotifier{})
	require.Equal(t, 2, logs.Len(), "one line each for the invite and the activation")
	for _, e := range logs.All() {
		require.Equal(t, zapcore.InfoLevel, e.Level, "not configured is the default mode: %q", e.Message)
		require.Contains(t, e.Message, "not mailed: delivery not configured")
	}

	logs = send(t, failingNotifier{})
	require.Equal(t, 2, logs.Len())
	for _, e := range logs.All() {
		require.Equal(t, zapcore.WarnLevel, e.Level, "a failed delivery stays a warning: %q", e.Message)
		require.Contains(t, e.Message, "send email failed")
	}
}
