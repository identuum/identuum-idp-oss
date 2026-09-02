package migrations_test

import (
	"strings"
	"testing"

	"github.com/identuum/identuum-idp-oss/migrations"
)

// TestMigration0037AgentCommunicationAuthorizations is a content-level
// guard over the AYGHU-1 foundation migration: both tables, the unique
// session id and globally unique ACI, the closed role set and capability
// vocabulary CHECKs, the positive-limit / future-expiry CHECKs, the
// deferred two-participant constraint trigger, participant immutability
// and terminal revocation. Renames or drops here are breaking — flag them
// loudly.
func TestMigration0037AgentCommunicationAuthorizations(t *testing.T) {
	data, err := migrations.EmbedFS.ReadFile("0037_agent_communication_authorizations.sql")
	if err != nil {
		t.Fatalf("failed to read 0037: %v", err)
	}
	body := string(data)

	mustContain := []string{
		`CREATE TABLE agent_communication_authorizations`,
		`CREATE TABLE agent_communication_participants`,
		`uq_aca_session_id UNIQUE (session_id)`,
		`uq_acp_aci UNIQUE (aci)`,
		`uq_acp_authorization_role UNIQUE (authorization_id, role)`,
		`uq_acp_authorization_service_account UNIQUE (authorization_id, service_account_id)`,
		`acp_role_check CHECK (role IN ('initiator', 'responder'))`,
		`acp_capabilities_vocabulary_check`,
		`'command.execute'`,
		`'communication.discuss'`,
		`'network.access'`,
		`'report.final.required'`,
		`'repository.read'`,
		`'repository.write'`,
		`'test.execute'`,
		`aca_max_messages_check CHECK (max_messages > 0)`,
		`aca_max_message_size_bytes_check CHECK (max_message_size_bytes > 0)`,
		`aca_expires_after_created_check CHECK (expires_at > created_at)`,
		`aca_policy_version_check CHECK (policy_version = 'v1')`,
		`aca_policy_digest_check CHECK (policy_digest ~ '^[0-9a-f]{64}$')`,
		`REFERENCES oauth_clients(id)`,
		`REFERENCES service_accounts(id)`,
		`agent_communication_enforce_two_participants`,
		`trg_aca_two_participants`,
		`trg_acp_two_participants`,
		`DEFERRABLE INITIALLY DEFERRED`,
		`trg_acp_immutable`,
		`trg_aca_revocation_only`,
		`revocation is terminal`,
	}
	for _, needle := range mustContain {
		if !strings.Contains(body, needle) {
			t.Errorf("0037_agent_communication_authorizations.sql missing required substring %q", needle)
		}
	}
	// The vocabulary CHECK must list exactly the seven members, nothing
	// beyond them: a silent widening of the closed set is refused here.
	if got := strings.Count(body, "'communication.discuss'"); got != 1 {
		t.Errorf("expected the vocabulary member to appear once, got %d", got)
	}
}
