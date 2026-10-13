package service

import (
	"context"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// R6 (owner, v0.9.14; acceptance V8-007 and V8-008): a re-sent invitation and
// an organization activation mail said "You have been invited" and "Activate
// your Organization" without the organization's name, because the user they
// were given came from a write that does not read the name back. Both mails
// now name the organization in the subject and in the body. The tests read
// the message the real notifier hands to an SMTP server; they never print it,
// because it carries a one-time link.

func mailOrgNameNotifier(t *testing.T) (*SMTPNotifier, <-chan fakeSMTPSession) {
	t.Helper()
	addr, sessions := startFakeSMTPServer(t)
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal("fake SMTP address")
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatal("fake SMTP port")
	}
	return NewSMTPNotifier(SMTPNotifierConfig{
		Host:          host,
		Port:          port,
		From:          "no-reply@idp.test",
		LinkBaseURL:   "https://ui.example.com",
		AllowInsecure: true,
	}), sessions
}

// mailOrgNameCheck asserts the subject line and the body of one delivered
// message name the organization.
func mailOrgNameCheck(t *testing.T, sessions <-chan fakeSMTPSession, wantSubject, org string) {
	t.Helper()
	sess := recvSession(t, sessions, 5*time.Second)
	if sess.err != nil {
		t.Fatal("fake SMTP session failed")
	}
	// The fake server stores each line without its CRLF, ending in "\n".
	head, body, ok := strings.Cut(sess.data, "\n\n")
	if !ok {
		t.Fatal("the message has no header/body separator")
	}
	if !strings.Contains(head+"\n", "Subject: "+wantSubject+"\n") {
		t.Errorf("the subject is not %q", wantSubject)
	}
	if !strings.Contains(body, org) {
		t.Errorf("the body does not name the organization %q", org)
	}
}

// RULE: MAIL-ORG-NAME-1
func TestMail_NamesTheOrganization(t *testing.T) {
	ctx := context.Background()

	t.Run("re-sent invitation", func(t *testing.T) {
		notifier, sessions := mailOrgNameNotifier(t)
		org := &domain.Organization{ID: uuid.New(), Name: "Acme", Domain: "acme.test", OrgSlug: "acme", Active: true}
		repo := newUserRepo()
		fixed := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
		svc := NewUserService(nil, verifiedCountRepo{repo}).WithInvite(UserInviteConfig{
			Orgs:     newFakeOrgRepo(org),
			Notifier: notifier,
			Now:      func() time.Time { return fixed },
		})
		pending := uuid.New()
		seedRow(repo, pending, org.ID, domain.RoleOrgAdmin)
		hash := "pending-invite-hash"
		repo.rows[pending].ActivationTokenHash = &hash
		if _, _, _, err := svc.ReissueInviteForActor(ctx, siteAdminActor(), pending); err != nil {
			t.Fatalf("re-issue: %v", err)
		}
		mailOrgNameCheck(t, sessions, "You have been invited to Acme", "Acme")
	})

	t.Run("organization activation", func(t *testing.T) {
		notifier, sessions := mailOrgNameNotifier(t)
		_, users, orgs, _, user, _ := newActivationFixture(t)
		fixed := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
		svc := NewOrganizationActivationService(OrganizationActivationServiceConfig{
			Users:     users,
			Orgs:      orgs,
			OrgsAdmin: orgs,
			Notifier:  notifier,
			Audit:     audit.NoopService{},
			Now:       func() time.Time { return fixed },
		})
		if _, _, err := svc.IssueActivationToken(ctx, user); err != nil {
			t.Fatalf("issue: %v", err)
		}
		mailOrgNameCheck(t, sessions, "Activate your Organization: Acme", "Acme")
	})
}
