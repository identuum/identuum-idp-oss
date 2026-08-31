package domain

import (
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// THE-SILENT-DROP (2026-08-31): both of these validators spelled the
// required-field rule as `== ""`, which a whitespace-only value passes. The
// census MEASURED the consequence on two live routes:
//
//	PUT /api/v1/scope-templates/:id  {"name":"   "} -> 200, STORED "   "
//	PUT /api/v1/api-resources/:id    {"name":"   "} -> 200, STORED "   "
//
// while {"name":""} on the same routes was either refused or dropped. So the
// same field had three different answers depending only on how much
// whitespace the caller typed. Required means required after trimming, and
// because these are the shared validators, the create path gains the rule at
// the same time as the update path.
//
// RULE: REQUIRED-NAME-NOT-WHITESPACE-1
func TestRequiredNameIsNotSatisfiedByWhitespace(t *testing.T) {
	blanks := []struct {
		why   string
		value string
	}{
		{"a single space", " "},
		{"several spaces", "   "},
		{"a tab", "\t"},
		{"a newline", "\n"},
		{"mixed whitespace", " \t\r\n "},
	}

	// ── APIResource.Name and .Audience ──
	for _, b := range blanks {
		bad := &APIResource{
			ID: uuid.New(), OrganizationID: uuid.New(),
			Name: b.value, Audience: "https://api.example.test", TokenTTLSecs: 3600,
			CreatedAt: time.Now(), UpdatedAt: time.Now(),
		}
		if err := bad.Validate(); err == nil {
			t.Errorf("APIResource.Validate ACCEPTED a name that is %s — a required field satisfied by whitespace", b.why)
		}
		bad = &APIResource{
			ID: uuid.New(), OrganizationID: uuid.New(),
			Name: "Billing API", Audience: b.value, TokenTTLSecs: 3600,
			CreatedAt: time.Now(), UpdatedAt: time.Now(),
		}
		if err := bad.Validate(); err == nil {
			t.Errorf("APIResource.Validate ACCEPTED an audience that is %s", b.why)
		}
	}

	// ── ScopeTemplate.Name ──
	for _, b := range blanks {
		bad := &ScopeTemplate{
			ID: uuid.New(), OrganizationID: uuid.New(),
			Name: b.value, Scopes: []string{"read:things"},
		}
		if err := bad.Validate(); err == nil {
			t.Errorf("ScopeTemplate.Validate ACCEPTED a name that is %s", b.why)
		}
	}

	// ── CONTROLS: real values still pass, and the length bounds still bite,
	// so a validator that refused everything would not satisfy this test ──
	ok := &APIResource{
		ID: uuid.New(), OrganizationID: uuid.New(),
		Name: "Billing API", Audience: "https://api.example.test", TokenTTLSecs: 3600,
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	if err := ok.Validate(); err != nil {
		t.Errorf("APIResource.Validate rejected a legitimate resource: %v", err)
	}
	okTpl := &ScopeTemplate{
		ID: uuid.New(), OrganizationID: uuid.New(),
		Name: "Reader", Scopes: []string{"read:things"},
	}
	if err := okTpl.Validate(); err != nil {
		t.Errorf("ScopeTemplate.Validate rejected a legitimate template: %v", err)
	}
	// A padded-but-real name is still accepted — the rule refuses blankness,
	// it does not silently rewrite the caller's value.
	padded := &ScopeTemplate{
		ID: uuid.New(), OrganizationID: uuid.New(),
		Name: "  Reader  ", Scopes: []string{"read:things"},
	}
	if err := padded.Validate(); err != nil {
		t.Errorf("ScopeTemplate.Validate rejected a padded but non-blank name: %v", err)
	}
	tooLong := &ScopeTemplate{
		ID: uuid.New(), OrganizationID: uuid.New(),
		Name: strings.Repeat("n", 101), Scopes: []string{"read:things"},
	}
	if err := tooLong.Validate(); err == nil {
		t.Error("ScopeTemplate.Validate accepted a name over its 100-character bound")
	}
}
