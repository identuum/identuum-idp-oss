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
const minExpectedAuditEventTypes = 120

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

func TestAllAuditEventTypeGroups_KeyValuesPresent(t *testing.T) {
	required := []AuditEventType{
		AuditDataAccessed,
		AuditAuthSuccess,
		AuditAuthFailure,
		AuditUserCreated,
		AuditOrgCreated,
		AuditPasswordChanged,
		AuditSessionCreated,
		AuditSessionRevoked,
		AuditPermissionDenied,
		AuditSecurityViolation,
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
// typed constant lives in the "Tokens" group rather than getting
// orphaned outside the registered set. The discovery test guards
// against drift between the typed constants and the documented
// group catalogue.
func TestAuditOAuthTokenRevoked_RegisteredInTokensGroup(t *testing.T) {
	for _, g := range AllAuditEventTypeGroups {
		if g.Label != "Tokens" {
			continue
		}
		for _, et := range g.Types {
			if et == AuditOAuthTokenRevoked {
				return
			}
		}
		t.Fatalf("AuditOAuthTokenRevoked not present in the Tokens group: %v", g.Types)
	}
	t.Fatalf("AllAuditEventTypeGroups has no Tokens group; registration check cannot run")
}
