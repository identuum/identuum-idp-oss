package service

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCreateForActor_CreatingOrgAdminIsTheOwner pins the AYGHU-2 ruling:
// a service account created through the admin API is owned by the org_admin
// who created it. Measured live before the fix: owner_user_id existed since
// migration 0001 but nothing ever wrote it, so every service account was
// ownerless and the agent-communication same-owner rule refused all of them.
func TestCreateForActor_CreatingOrgAdminIsTheOwner(t *testing.T) {
	svc, _ := newAdminSAService()
	org := uuid.New()
	actor := newOrgAdmin(org)

	sa, err := svc.CreateForActor(context.Background(), actor, org, ServiceAccountAdminInput{Name: "agent-a1"})
	require.NoError(t, err)
	require.NotNil(t, sa)
	require.NotNil(t, sa.OwnerUserID, "a service account created by an org_admin must carry an owner")
	assert.Equal(t, actor.UserID, *sa.OwnerUserID, "the owner is the creating org_admin")
	assert.NotEqual(t, uuid.Nil, *sa.OwnerUserID)
}
