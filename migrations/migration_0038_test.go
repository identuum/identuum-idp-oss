package migrations_test

import (
	"strings"
	"testing"

	"github.com/identuum/identuum-idp-oss/migrations"
)

// TestMigration0038DPoPProofReplays is a content-level guard over the
// AYGHU-3 DPoP replay table: keyed by proof-key thumbprint + sha256(jti),
// separate from the OAuth client-assertion replay table, with an
// expires_at index for the sweeper.
func TestMigration0038DPoPProofReplays(t *testing.T) {
	data, err := migrations.EmbedFS.ReadFile("0038_dpop_proof_replays.sql")
	if err != nil {
		t.Fatalf("failed to read 0038: %v", err)
	}
	body := string(data)
	for _, needle := range []string{
		`CREATE TABLE dpop_proof_replays`,
		`PRIMARY KEY (jkt, jti_hash)`,
		`dpop_proof_replays_jti_hash_check CHECK (jti_hash ~ '^[0-9a-f]{64}$')`,
		`idx_dpop_proof_replays_expires_at`,
	} {
		if !strings.Contains(body, needle) {
			t.Errorf("0038_dpop_proof_replays.sql missing required substring %q", needle)
		}
	}
	if strings.Contains(body, "oauth_client_assertion_replays") && !strings.Contains(body, "SEPARATE table from") {
		t.Errorf("0038 must not touch oauth_client_assertion_replays")
	}
}
