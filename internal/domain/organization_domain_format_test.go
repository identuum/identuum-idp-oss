package domain

import (
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// THE-UNVALIDATED-DOMAIN (2026-08-31): the entire domain check on an
// organization was `== ""`, so "lexus" — no dot, no TLD — was accepted and
// persisted. The grammar now lives in ONE place (ValidateDomainFormat) and
// both Organization.Validate and OrganizationDomain.Validate run it.
//
// This test asserts the GRAMMAR and its WIRING. It dies when the validator or
// either call site is removed — not when a comment changes.
//
// RULE: ORG-DOMAIN-FORMAT-1
func TestOrganizationDomainFormat_GrammarAndWiring(t *testing.T) {
	accepted := []struct{ in, why string }{
		{"system.local", "the system organization's own domain must stay valid"},
		{"saab.se", "ordinary two-label domain"},
		{"a.co", "shortest valid form: 1-char label, 2-char TLD"},
		{"e2e-abc123.test", "the harness's fixture shape (hyphens, digits, .test)"},
		{"deep.sub.domain.example.com", "arbitrary label depth"},
		{"Example.COM", "case is normalized, not rejected"},
		{"  example.com  ", "surrounding whitespace is trimmed"},
		{"example.com.", "one trailing FQDN dot is stripped"},
		{"xn--80ak6aa92e.com", "punycode A-label"},
		{"example.xn--p1ai", "punycode TLD"},
		{strings.Repeat("a", 63) + ".com", "label exactly at the 63 limit"},
	}
	for _, c := range accepted {
		if err := ValidateDomainFormat(c.in); err != nil {
			t.Errorf("ValidateDomainFormat(%q) rejected, want accepted (%s): %v", c.in, c.why, err)
		}
	}

	rejected := []struct{ in, why string }{
		{"lexus", "THE REPORTED DEFECT: single label, no dot, no TLD"},
		{"localhost", "single label, however familiar"},
		{"", "empty"},
		{"   ", "whitespace only"},
		{".com", "leading dot ⇒ empty first label"},
		{"example.", "trailing dot beyond the single FQDN dot ⇒ empty label"},
		{"exa..mple.com", "consecutive dots ⇒ empty label"},
		{"-bad.com", "label starts with a hyphen"},
		{"bad-.com", "label ends with a hyphen"},
		{"example.c", "one-character TLD"},
		{"example.123", "numeric TLD"},
		{"192.168.1.1", "IPv4 literal — numeric final label"},
		{"exam ple.com", "space inside a label"},
		{"under_score.com", "underscore is not a hostname character"},
		{"münchen.de", "non-ASCII: submit punycode instead"},
		{strings.Repeat("a", 64) + ".com", "label one over the 63 limit"},
		{strings.Repeat("a.", 130) + "com", "total length over 253"},
	}
	for _, c := range rejected {
		if err := ValidateDomainFormat(c.in); err == nil {
			t.Errorf("ValidateDomainFormat(%q) accepted, want rejected (%s)", c.in, c.why)
		}
	}

	// WIRING 1 — Organization.Validate runs the grammar. A valid org that
	// differs ONLY in its domain must flip on the domain alone.
	org := func(d string) *Organization {
		return &Organization{
			Name:               "Test Org",
			Domain:             d,
			MaxSessionsPerUser: 5,
			MFAPolicy:          "optional",
		}
	}
	if err := org("example.com").Validate(); err != nil {
		t.Fatalf("Organization.Validate rejected a well-formed domain: %v", err)
	}
	err := org("lexus").Validate()
	if err == nil {
		t.Fatal("Organization.Validate ACCEPTED \"lexus\" — the reported defect is back")
	}
	if !errors.Is(err, ErrOrganizationDomainInvalid) {
		t.Fatalf("Organization.Validate error does not wrap ErrOrganizationDomainInvalid: %v", err)
	}

	// WIRING 2 — OrganizationDomain.Validate runs the SAME grammar, so the
	// two tables cannot drift apart.
	od := &OrganizationDomain{OrganizationID: uuid.New(), Domain: "lexus"}
	if err := od.Validate(); err == nil {
		t.Fatal("OrganizationDomain.Validate ACCEPTED \"lexus\"")
	}
	odOK := &OrganizationDomain{OrganizationID: uuid.New(), Domain: "example.com"}
	if err := odOK.Validate(); err != nil {
		t.Fatalf("OrganizationDomain.Validate rejected a well-formed domain: %v", err)
	}

	// EVERY OTHER FIELD (owner ruling: not only domain). Each case differs
	// from the valid baseline in exactly ONE field, so a failure names the
	// field that stopped being guarded.
	baseline := func(mut func(*Organization)) *Organization {
		o := &Organization{
			Name:               "Test Org",
			Domain:             "example.com",
			MaxSessionsPerUser: 5,
			MFAPolicy:          "optional",
		}
		mut(o)
		return o
	}
	if err := baseline(func(*Organization) {}).Validate(); err != nil {
		t.Fatalf("the baseline organization must be valid: %v", err)
	}

	fieldCases := []struct {
		field string
		mut   func(*Organization)
	}{
		{"Name: whitespace only was accepted by the old `== \"\"` check", func(o *Organization) { o.Name = "   " }},
		{"Name: over the 255 column width", func(o *Organization) { o.Name = strings.Repeat("n", 256) }},
		{"OrgSlug: uppercase", func(o *Organization) { o.OrgSlug = "Acme" }},
		{"OrgSlug: space", func(o *Organization) { o.OrgSlug = "acme corp" }},
		{"OrgSlug: leading hyphen", func(o *Organization) { o.OrgSlug = "-acme" }},
		{"OrgSlug: trailing hyphen", func(o *Organization) { o.OrgSlug = "acme-" }},
		{"OrgSlug: over the 255 column width", func(o *Organization) { o.OrgSlug = strings.Repeat("s", 256) }},
		{"Tier: outside the enum", func(o *Organization) { o.Tier = Tier(99) }},
		{"M2MAnomalyLimit: negative", func(o *Organization) { o.M2MAnomalyLimit = -1 }},
		{"M2MAnomalyWindowSeconds: negative", func(o *Organization) { o.M2MAnomalyWindowSeconds = -1 }},
		{"MaxSessionsPerUser: below 1", func(o *Organization) { o.MaxSessionsPerUser = 0 }},
		{"MaxSessionsPerUser: above 100", func(o *Organization) { o.MaxSessionsPerUser = 101 }},
		{"MFAPolicy: unknown value", func(o *Organization) { o.MFAPolicy = "sometimes" }},
		{"ServiceAccountExpiryDays: negative", func(o *Organization) { o.ServiceAccountExpiryDays = -1 }},
		{"AuthPolicy: unknown value", func(o *Organization) { o.AuthPolicy = "whenever" }},
		{"ApiAuthorizationPolicy: unknown value", func(o *Organization) { o.ApiAuthorizationPolicy = "LOOSE" }},
	}
	for _, c := range fieldCases {
		if err := baseline(c.mut).Validate(); err == nil {
			t.Errorf("Organization.Validate accepted an invalid field — %s", c.field)
		}
	}

	// Values the live rows actually carry must stay valid, so this guard can
	// never reject the system organization or an existing tenant.
	for _, ok := range []struct {
		why string
		mut func(*Organization)
	}{
		{"the system organization's slug", func(o *Organization) { o.OrgSlug = "system-local"; o.Domain = "system.local" }},
		{"a plain tenant slug", func(o *Organization) { o.OrgSlug = "saab"; o.Domain = "saab.se" }},
		{"no slug at all (optional)", func(o *Organization) { o.OrgSlug = "" }},
		{"zero m2m thresholds = disabled", func(o *Organization) { o.M2MAnomalyLimit = 0; o.M2MAnomalyWindowSeconds = 0 }},
		{"the live m2m thresholds", func(o *Organization) { o.M2MAnomalyLimit = 100; o.M2MAnomalyWindowSeconds = 60 }},
	} {
		if err := baseline(ok.mut).Validate(); err != nil {
			t.Errorf("Organization.Validate rejected a value in live use (%s): %v", ok.why, err)
		}
	}
}
