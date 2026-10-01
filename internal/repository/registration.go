package repository

import (
	"context"

	"github.com/google/uuid"
	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// RegistrationRepository holds the self-registration state of migration 0043
// (D-021): the instance switch, each organization's policy, and a
// self-registrant's state. It reads and writes those columns directly; the
// organization and user rows are otherwise read through their own
// repositories.
type RegistrationRepository interface {
	InstanceEnabled(ctx context.Context) (bool, error)
	SetInstanceEnabled(ctx context.Context, enabled bool) error

	OrgSettings(ctx context.Context, orgID uuid.UUID) (*domain.OrgRegistrationSettings, error)
	UpdateOrgSettings(ctx context.Context, orgID uuid.UUID, s domain.OrgRegistrationSettings) error

	// SetUserState records a self-registrant's state.
	SetUserState(ctx context.Context, userID uuid.UUID, state string) error
	// UserState returns a user's registration state ("" when it is not a
	// self-registrant) and whether its organization requires a verified email.
	UserState(ctx context.Context, userID uuid.UUID) (state string, verifyEmail bool, err error)
	// ListPending returns the organization's self-registrants held for approval.
	ListPending(ctx context.Context, orgID uuid.UUID) ([]domain.PendingRegistration, error)
}
