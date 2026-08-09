package auth

import (
	"testing"

	"github.com/identuum/identuum-idp-oss/internal/lifecycle"
)

// TestNewRepositoryVerifier_NilRepoRecordsFatalFault proves the P-018
// class-C conversion: NewRepositoryVerifier no longer panics on a nil
// KeyRepository — it records a fatal StartupReport fault naming the
// component, so buildDeps surfaces it (NOT-SERVING) rather than crashing.
// (Scenario (a) — valid deps → the verifier works — is covered by the
// existing TestVerifyBearerToken_* happy-path suite.)
func TestNewRepositoryVerifier_NilRepoRecordsFatalFault(t *testing.T) {
	rep := lifecycle.NewStartupReport()

	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("NewRepositoryVerifier(nil repo) panicked: %v", r)
			}
		}()
		_ = NewRepositoryVerifier(rep, nil, VerifierOptions{})
	}()

	if !rep.HasFatal() {
		t.Fatalf("nil KeyRepository must record a fatal fault")
	}
	named := false
	for _, f := range rep.Faults() {
		if f.Component == "NewRepositoryVerifier" && f.Severity == lifecycle.SeverityFatal {
			named = true
		}
	}
	if !named {
		t.Errorf("fault must name NewRepositoryVerifier; got %+v", rep.Faults())
	}
	t.Logf("EVIDENCE NewRepositoryVerifier nil-repo: no panic; faults=%+v", rep.Faults())
}
