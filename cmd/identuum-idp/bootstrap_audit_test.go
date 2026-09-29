package main

import (
	"bytes"
	"context"
	"testing"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

type fakeBootstrapRecorder struct{ admins []*domain.User }

func (f *fakeBootstrapRecorder) SetupCompleted(_ context.Context, admin *domain.User) {
	f.admins = append(f.admins, admin)
}

// OSS-FIN-3 item 4: `identuum-idp bootstrap` that creates the site_admin
// records the setup (the rows' shape: service TestBootstrapAuditor_*); a
// re-run that finds the admin creates nothing and records nothing.
func TestBootstrapCore_AuditsTheSetupOnce(t *testing.T) {
	t.Parallel()

	rec := &fakeBootstrapRecorder{}
	deps := bootstrapDeps{Keys: &memKeyRepo{}, Users: &memUserRepo{}, Setup: &fakeSetupCompleter{}, Audit: rec}
	var stdout, stderr bytes.Buffer
	if rc := bootstrapCore(context.Background(), deps, newTestOpts(), &stdout, &stderr); rc != 0 {
		t.Fatalf("expected rc=0, got %d (stderr=%s)", rc, stderr.String())
	}
	if len(rec.admins) != 1 || rec.admins[0].ID.String() != domain.SiteAdminID || rec.admins[0].Role != domain.RoleSiteAdmin {
		t.Fatalf("bootstrap recorded %d setup(s); want one, for the created site_admin", len(rec.admins))
	}
	if rc := bootstrapCore(context.Background(), deps, newTestOpts(), &stdout, &stderr); rc != 0 {
		t.Fatalf("re-run rc=%d", rc)
	}
	if len(rec.admins) != 1 {
		t.Errorf("a re-run that created nothing recorded again (%d total); want 1", len(rec.admins))
	}
}
