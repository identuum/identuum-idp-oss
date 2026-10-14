package domain

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// minExpectedAuditEventTypes is a lower-bound regression guard.
// Fail if AllAuditEventTypeGroups shrinks below this number (mass-deletion catch).
// Update upward when new constants are added; never lower this threshold.
// 141 = the names the server records (OSS-0913-C, the drift test pins them);
// 142 with site_admin_credentials_reset (OSS-0914-RECOVER-AUDIT).
const minExpectedAuditEventTypes = 142

func TestAllAuditEventTypeGroups_NoDuplicates(t *testing.T) {
	seen := make(map[AuditEventType]string)
	for _, g := range AllAuditEventTypeGroups {
		for _, et := range g.Types {
			if prev, ok := seen[et]; ok {
				t.Errorf("duplicate event type %q: appears in group %q and group %q",
					et, prev, g.Label)
			}
			seen[et] = g.Label
		}
	}
}

func TestAllAuditEventTypeGroups_AllValuesNonEmpty(t *testing.T) {
	for _, g := range AllAuditEventTypeGroups {
		require.NotEmpty(t, g.Label, "group label must not be empty")
		require.NotEmpty(t, g.Types, "group %q must have at least one type", g.Label)
		for i, et := range g.Types {
			assert.NotEmpty(t, string(et),
				"group %q index %d has an empty event type value", g.Label, i)
		}
	}
}

func TestAllAuditEventTypeGroups_MinimumCount(t *testing.T) {
	total := 0
	for _, g := range AllAuditEventTypeGroups {
		total += len(g.Types)
	}
	assert.GreaterOrEqual(t, total, minExpectedAuditEventTypes,
		fmt.Sprintf("AllAuditEventTypeGroups has %d event types; expected at least %d. "+
			"If a group was accidentally removed, restore it. "+
			"If new constants were added, increase minExpectedAuditEventTypes.", total, minExpectedAuditEventTypes))
}

// The catalog lists recorded names only (OSS-0913-C): the key names below are
// the ones the server writes for sign-in, users, organizations and tokens.
func TestAllAuditEventTypeGroups_KeyValuesPresent(t *testing.T) {
	required := []AuditEventType{
		"user_session.login.success",
		"user_session.login.failure",
		"user.created",
		AuditUserCreated,
		"organization.created",
		AuditPasswordChanged,
		AuditSessionRevoked,
		"user_session.logout",
		"scope.denied",
		"feature.denied",
		AuditOAuthTokenRevoked,
	}

	all := make(map[AuditEventType]bool)
	for _, g := range AllAuditEventTypeGroups {
		for _, et := range g.Types {
			all[et] = true
		}
	}

	for _, et := range required {
		assert.True(t, all[et],
			"required event type %q is missing from AllAuditEventTypeGroups", et)
	}
}

// TestAuditOAuthTokenRevoked_StringValueIsStable pins the wire
// value of the typed constant to the historical literal so future
// renames cannot silently break external log consumers that filter
// on "oauth_token.revoked". The dot form is intentional and must
// not be normalized to underscore form.
func TestAuditOAuthTokenRevoked_StringValueIsStable(t *testing.T) {
	assert.Equal(t, "oauth_token.revoked", string(AuditOAuthTokenRevoked),
		"AuditOAuthTokenRevoked string value must remain 'oauth_token.revoked' for downstream log filters")
}

// TestAuditOAuthTokenRevoked_RegisteredInTokensGroup asserts the
// typed constant lives in the "Tokens and consent" group rather than
// getting orphaned outside the registered set. The discovery test guards
// against drift between the typed constants and the documented
// group catalogue.
func TestAuditOAuthTokenRevoked_RegisteredInTokensGroup(t *testing.T) {
	for _, g := range AllAuditEventTypeGroups {
		if g.Label != "Tokens and consent" {
			continue
		}
		for _, et := range g.Types {
			if et == AuditOAuthTokenRevoked {
				return
			}
		}
		t.Fatalf("AuditOAuthTokenRevoked not present in the Tokens and consent group: %v", g.Types)
	}
	t.Fatalf("AllAuditEventTypeGroups has no Tokens and consent group; registration check cannot run")
}

// Labels come from one function: plain words, first letter upper case, the
// abbreviations spelled out, and every catalog entry gets a non-empty one.
func TestAuditEventTypeLabel(t *testing.T) {
	cases := map[AuditEventType]string{
		"user_session.login.mfa_verified": "User session login MFA verified",
		"organization.created":            "Organization created",
		"oauth_token.revoked":             "OAuth token revoked",
		"dcr.iat_issued":                  "Dynamic registration initial access token issued",
		"org.identity_provider_created":   "Organization identity provider created",
		"webauthn_credential_registered":  "Passkey credential registered",
	}
	for in, want := range cases {
		assert.Equal(t, want, AuditEventTypeLabel(in), "label of %q", in)
	}
	for _, g := range AllAuditEventTypeGroups {
		for _, et := range g.Types {
			assert.NotEmpty(t, AuditEventTypeLabel(et), "label of %q", et)
		}
	}
}
