package api

import (
	"context"
	"testing"

	"github.com/identuum/identuum-idp-oss/internal/audit"
)

// stubAuditService is a non-Noop audit.Service — stands in for the runtime's
// PersistentAuditService (which lives in internal/service and would create an
// import cycle if referenced here).
type stubAuditService struct{}

func (stubAuditService) Record(context.Context, audit.Event) error { return nil }

// L-2: once the runtime sets Deps.Audit to a real (persistent) service,
// resolvedDeps must LEAVE IT IN PLACE — it only substitutes NoopService for a
// nil Audit. This is the "Deps.Audit is no longer Noop once wired" guarantee
// at the composition boundary. Before L-2 nothing set Deps.Audit, so every
// deploy got Noop; the regression this guards is resolvedDeps clobbering a
// wired service back to Noop.
func TestResolvedDeps_PreservesWiredAudit(t *testing.T) {
	wired := stubAuditService{}
	got := resolvedDeps(OSSRouterDeps{Audit: wired})
	if _, isNoop := got.Audit.(audit.NoopService); isNoop {
		t.Fatal("resolvedDeps overwrote a wired Audit service back to NoopService")
	}
	if got.Audit == nil {
		t.Fatal("Audit became nil")
	}
}

// Control: a nil Audit is still normalised to NoopService (the OSS default for
// deploys that do not wire a persistent log).
func TestResolvedDeps_NilAuditBecomesNoop(t *testing.T) {
	got := resolvedDeps(OSSRouterDeps{})
	if _, isNoop := got.Audit.(audit.NoopService); !isNoop {
		t.Fatalf("nil Audit should default to NoopService, got %T", got.Audit)
	}
}
