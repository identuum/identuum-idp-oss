package migrations_test

import (
	"strings"
	"testing"

	"github.com/identuum/identuum-idp-oss/migrations"
)

// TestMigration0039AgentCommunicationTokens is a content-level guard over
// the AYGHU-4 issued-token table: jti-keyed, bound to the authorization
// with cascade, expiry-indexed for the sweeper.
func TestMigration0039AgentCommunicationTokens(t *testing.T) {
	data, err := migrations.EmbedFS.ReadFile("0039_agent_communication_tokens.sql")
	if err != nil {
		t.Fatalf("failed to read 0039: %v", err)
	}
	body := string(data)
	for _, needle := range []string{
		`CREATE TABLE agent_communication_tokens`,
		`jti               TEXT        PRIMARY KEY`,
		`REFERENCES agent_communication_authorizations(id) ON DELETE CASCADE`,
		`idx_act_authorization_id`,
		`idx_act_expires_at`,
	} {
		if !strings.Contains(body, needle) {
			t.Errorf("0039_agent_communication_tokens.sql missing required substring %q", needle)
		}
	}
}
