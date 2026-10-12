package domain

import "testing"

// OSS-0912-C2 (owner Q1 (a), Q2 (b)): only a verification email, the
// sign-in provider, or a row verified before the upgrade proves the mailbox.
// An administrator's link, an administrator's setting and setup do not, and
// NULL is never proven. The activation flag plays no part.
func TestUser_MailboxProven(t *testing.T) {
	for _, c := range []struct {
		via  *string
		want bool
	}{
		{nil, false},
		{ptrVia(EmailVerifiedViaEmailLink), true},
		{ptrVia(EmailVerifiedViaUpstreamIDP), true},
		{ptrVia(EmailVerifiedViaLegacy), true},
		{ptrVia(EmailVerifiedViaAdminLink), false},
		{ptrVia(EmailVerifiedViaAdminSet), false},
		{ptrVia(EmailVerifiedViaSetup), false},
		{ptrVia("unknown"), false},
	} {
		for _, activated := range []bool{true, false} {
			u := &User{EmailVerified: activated, EmailVerifiedVia: c.via}
			if got := u.MailboxProven(); got != c.want {
				t.Errorf("via %v, activated %v: MailboxProven = %v; want %v", deref(c.via), activated, got, c.want)
			}
		}
	}
	var nilUser *User
	if nilUser.MailboxProven() {
		t.Errorf("a nil user is proven")
	}
}

func ptrVia(s string) *string { return &s }

func deref(s *string) string {
	if s == nil {
		return "<nil>"
	}
	return *s
}
