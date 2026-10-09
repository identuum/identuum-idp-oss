package runtime

import (
	"bytes"
	"context"
	"testing"

	"github.com/identuum/identuum-idp-oss/internal/lifecycle"
)

// OSS-MFA-BUDGET-1 (P-103): the runtime's one wrong-code budget counts the
// pending sign-in misses too, so a proof route sees them.
func TestBuildDeps_TheProofBudgetCountsSignInMisses(t *testing.T) {
	dbURL := testDBURL(t)
	migrateTestSchema(t, dbURL)
	t.Setenv("IDENTUUM_IDP_ENCRYPTION_KEY", "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
	rt, err := New(Config{Addr: "127.0.0.1:0", Issuer: "http://localhost", JWKSDBURL: dbURL,
		DataDir: t.TempDir(), Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, pool, _, _, _, _, _, _, _, _, _, _, err := rt.buildDeps(context.Background(), lifecycle.NewStartupReport())
	if err != nil {
		t.Fatalf("buildDeps: %v", err)
	}
	defer pool.Close()
	if rt.proofBudget == nil || !rt.proofBudget.CountsSignInMisses() {
		t.Fatal("the runtime's wrong-code budget does not count the pending sign-in misses")
	}
}
