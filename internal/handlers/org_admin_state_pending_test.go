package handlers

import (
	"context"
	"testing"

	"github.com/google/uuid"
)

// pendingAwareCounter reports the three counts the site-admin admin state
// needs: live org_admins, verified ones, and recovery-blocking ones
// (verified, or pending with an unexpired activation).
type pendingAwareCounter struct {
	admins, verified, blocking int
}

func (f pendingAwareCounter) CountOrgAdminsByOrganizations(_ context.Context, ids []uuid.UUID) (map[uuid.UUID]int, error) {
	return map[uuid.UUID]int{ids[0]: f.admins}, nil
}
func (f pendingAwareCounter) CountVerifiedOrgAdminsByOrganizations(_ context.Context, ids []uuid.UUID) (map[uuid.UUID]int, error) {
	return map[uuid.UUID]int{ids[0]: f.verified}, nil
}
func (f pendingAwareCounter) CountRecoveryBlockingOrgAdminsByOrganizations(_ context.Context, ids []uuid.UUID) (map[uuid.UUID]int, error) {
	return map[uuid.UUID]int{ids[0]: f.blocking}, nil
}

// OSS-RC: minutes after an organization was created with an admin email, the
// site-admin list read "Invitation expired". can_assign_admin was
// has_admin && no verified admin, so a VALID pending activation counted as
// an expired one. The UI contract (ADMIN_STATE_COPY "expired-pending") and
// its e2e fixture ("valid-pending" → can_assign_admin=false) both say a live
// activation blocks recovery; only an expired one opens it.
func TestAdminState_ValidPendingActivationBlocksRecovery(t *testing.T) {
	id := uuid.New()
	for _, tt := range []struct {
		name          string
		c             pendingAwareCounter
		wantCanAssign bool
	}{
		{"valid pending activation", pendingAwareCounter{admins: 1, verified: 0, blocking: 1}, false},
		{"expired pending activation", pendingAwareCounter{admins: 1, verified: 0, blocking: 0}, true},
		{"active admin", pendingAwareCounter{admins: 1, verified: 1, blocking: 1}, false},
		{"no admin", pendingAwareCounter{}, false},
	} {
		st := adminStateForOrgs(context.Background(), tt.c, []uuid.UUID{id})[id]
		if st.canAssign != tt.wantCanAssign {
			t.Errorf("%s: can_assign_admin = %v, want %v", tt.name, st.canAssign, tt.wantCanAssign)
		}
	}
}
