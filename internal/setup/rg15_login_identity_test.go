package setup

import (
	"strings"
	"testing"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// Rg15 / Rg9 — the site_admin's LOGIN is pinned; the operator's address is
// contact detail (compliance-audit gaps G15 and G9).
//
// AdminPermissionsModel.md states two things that setup was collapsing into
// one field:
//
//	"site_admin's user id (login) is site_admin@system.local"
//	"site_admin has a separate contact-email field set by the installing user"
//
// OSS wrote the operator's typed address as the LOGIN, so the identity of the
// single most privileged account in the installation depended on who happened
// to run the installer. identuum-idp-ce already pinned the canonical login —
// which made this a parity violation too, and the model's first rule is that
// the rules are the same in both products.
//
// The typed address is not thrown away: it goes to users.contact_email, the
// column migration 0026 added and which had no writer at all until now (G9).
//
// This is a UNIT test on the field mapping rather than a live-setup test
// because the mapping is the whole of the change and it can be stated here
// without standing up a database; the end-to-end path is covered by the
// existing setup integration suite.
func TestRg15_SiteAdminLoginIsCanonicalNotTheOperatorsAddress(t *testing.T) {
	const operator = "ops.person@customer.example"

	login, contact := siteAdminIdentity(operator)

	if login != domain.SiteAdminEmail {
		t.Errorf("login = %q, want the pinned %q — the account's identity must not depend on "+
			"who ran the installer", login, domain.SiteAdminEmail)
	}
	if contact != operator {
		t.Errorf("contact = %q, want the operator's typed address %q — it is not discarded, "+
			"it is demoted to contact detail", contact, operator)
	}
	if login == operator {
		t.Errorf("the operator's address became the login again")
	}
}

func TestRg15_ContactIsTrimmedAndOptional(t *testing.T) {
	if _, contact := siteAdminIdentity("  spaced@example.com \n"); contact != "spaced@example.com" {
		t.Errorf("contact = %q, want it trimmed", contact)
	}
	// An installer that supplies nothing still gets a working login; the model
	// requires the login, not the contact address.
	login, contact := siteAdminIdentity("")
	if login != domain.SiteAdminEmail {
		t.Errorf("login = %q, want %q even with no operator address", login, domain.SiteAdminEmail)
	}
	if strings.TrimSpace(contact) != "" {
		t.Errorf("contact = %q, want empty", contact)
	}
}
