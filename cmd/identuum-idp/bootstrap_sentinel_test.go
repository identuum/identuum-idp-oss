package main

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// pkCollidingUserRepo models what Postgres actually enforces: `id` is the
// PRIMARY KEY, so a Create whose ID is already taken fails EVEN IF the email
// differs. memUserRepo collides only on (email, organization_id), which is
// weaker than the database — and that gap is exactly why the false-success
// below shipped unnoticed.
type pkCollidingUserRepo struct {
	memUserRepo
}

func (m *pkCollidingUserRepo) Create(ctx context.Context, u *domain.User) (*domain.User, error) {
	for _, existing := range m.users {
		if existing.ID == u.ID {
			return nil, domain.ErrUserAlreadyExists
		}
	}
	return m.memUserRepo.Create(ctx, u)
}

// TestBootstrapCore_SentinelHeldByAnotherEmail_DoesNotClaimSuccess pins the
// P0 found while standing the dev stack up by hand.
//
// bootstrap writes site_admin at a FIXED sentinel ID (domain.SiteAdminID). A
// stack bootstrapped earlier under some other address — dev stacks routinely
// are, via IDENTUUM_IDP_BOOTSTRAP_EMAIL — already holds that ID. The Create
// then fails with ErrUserAlreadyExists, which bootstrap read as "a concurrent
// bootstrap created MY row" and reported as success.
//
// It had not. Nothing was created, and the operator was told otherwise: the
// next step (login, or recover-site-admin) fails with "site_admin@system.local
// does not exist — run 'identuum-idp bootstrap' first", pointing back at the
// command that just claimed to have done it. That loop is a boot-to-login
// blocker, and a false success is worse than a failure because it sends the
// operator looking in the wrong place.
func TestBootstrapCore_SentinelHeldByAnotherEmail_DoesNotClaimSuccess(t *testing.T) {
	t.Parallel()

	repo := &pkCollidingUserRepo{}
	// The pre-existing occupant: same sentinel ID, DIFFERENT email — precisely
	// the dev-stack shape.
	sentinel := uuid.MustParse(domain.SiteAdminID)
	systemOrg := uuid.MustParse(domain.SystemOrgID)
	if _, err := repo.memUserRepo.Create(context.Background(), &domain.User{
		ID:             sentinel,
		OrganizationID: systemOrg,
		Email:          "owner@acme.example",
		Role:           domain.RoleSiteAdmin,
	}); err != nil {
		t.Fatalf("seeding the occupant row failed: %v", err)
	}

	deps := bootstrapDeps{Keys: &memKeyRepo{}, Users: repo}
	var stdout, stderr bytes.Buffer
	rc := bootstrapCore(context.Background(), deps, newTestOpts(), &stdout, &stderr)

	// CONTROL: the requested row genuinely is not there. Without this the
	// assertion below could pass for the wrong reason.
	if _, err := repo.GetByEmailAndOrgID(context.Background(), systemOrg, newTestOpts().Email); err == nil {
		t.Fatalf("CONTROL FAILED: %s exists, so this test is not exercising the collision at all",
			newTestOpts().Email)
	}

	if rc == 0 {
		t.Fatalf("bootstrap returned SUCCESS (rc=0) while %s does not exist — the operator is told "+
			"the row was created and then hits 'does not exist' at the very next step.\nstdout=%q",
			newTestOpts().Email, stdout.String())
	}
	if !strings.Contains(stderr.String(), "sentinel") {
		t.Fatalf("the failure must NAME the cause (the sentinel ID is held by another row), "+
			"or the operator cannot act on it; got stderr=%q", stderr.String())
	}
}
