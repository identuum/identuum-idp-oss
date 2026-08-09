package service

import (
	"testing"

	"github.com/identuum/identuum-idp-oss/internal/lifecycle"
)

// TestNewUserSessionService_NilRepoRecordsFatalFault proves the P-018
// class-C conversion: NewUserSessionService no longer panics on a nil
// SessionRepository — it records a fatal StartupReport fault naming the
// component, so buildDeps surfaces it (NOT-SERVING) rather than crashing.
// (Scenario (a) — valid deps → the service works — is covered by the
// existing TestCreateUserSession_* / TestRotate_* suite.)
func TestNewUserSessionService_NilRepoRecordsFatalFault(t *testing.T) {
	rep := lifecycle.NewStartupReport()

	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("NewUserSessionService(nil repo) panicked: %v", r)
			}
		}()
		_ = NewUserSessionService(rep, nil, UserSessionServiceOptions{})
	}()

	if !rep.HasFatal() {
		t.Fatalf("nil SessionRepository must record a fatal fault")
	}
	named := false
	for _, f := range rep.Faults() {
		if f.Component == "NewUserSessionService" && f.Severity == lifecycle.SeverityFatal {
			named = true
		}
	}
	if !named {
		t.Errorf("fault must name NewUserSessionService; got %+v", rep.Faults())
	}
	t.Logf("EVIDENCE NewUserSessionService nil-repo: no panic; faults=%+v", rep.Faults())
}
