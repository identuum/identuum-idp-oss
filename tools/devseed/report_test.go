package main

import (
	"strings"
	"testing"
)

// OSS-DEVSEED-LIVE: the text report told the reader the seeded org_user would
// be asked to enrol TOTP on its first login. OSS demands TOTP of site_admin and
// org_admin only, and of an org_user only when the organization's mfa_policy
// is "required" (internal/service.IsMFARequiredForUser); devseed's organization
// sets none, and `make devseed-live` measured the org_user signing in with its
// password alone (200 with a bearer). The report says what is true.
func TestReport_OrgUserLineSaysPasswordAlone(t *testing.T) {
	var out strings.Builder
	if err := report(&out, false, seeded{OrgUserUser: "u@example.test", OrgUserPass: "p"}); err != nil {
		t.Fatal(err)
	}
	text := out.String()
	if strings.Contains(text, "enrolled on this account's first login") {
		t.Errorf("the report promises a first-login TOTP enrolment the product does not ask of an org_user:\n%s", text)
	}
	if !strings.Contains(text, "signs in with the password alone") {
		t.Errorf("the report must say the org_user signs in with the password alone:\n%s", text)
	}
}
