package service

import (
	"context"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// BootstrapAuditor records a CLI bootstrap the way the setup wizard records
// its completion (OSS-FIN-3; internal/api recordSetupCompleted):
// setup.completed and the first admin's user_created, by the system actor.
// No row carries the password.
type BootstrapAuditor struct {
	svc audit.Service
}

// NewBootstrapAuditor writes through the persistent audit log.
func NewBootstrapAuditor(repo auditInserter) *BootstrapAuditor {
	return &BootstrapAuditor{svc: NewPersistentAuditService(repo)}
}

// SetupCompleted records the two rows for the site_admin bootstrap created.
func (b *BootstrapAuditor) SetupCompleted(ctx context.Context, admin *domain.User) {
	if b == nil || b.svc == nil || admin == nil {
		return
	}
	systemOrgID, _ := uuid.Parse(domain.SystemOrgID)
	base := audit.Event{Outcome: "success", ActorType: audit.ActorTypeSystem, OrganizationID: systemOrgID}
	done := base
	done.Action = "setup.completed"
	done.Metadata = map[string]any{"organization_id": systemOrgID.String(), "via": "bootstrap"}
	_ = b.svc.Record(ctx, done)
	created := base
	created.Action = string(domain.AuditUserCreated)
	created.SubjectID = admin.ID
	created.SubjectType = "user"
	created.SubjectEmail = admin.Email
	created.Metadata = map[string]any{"role": string(domain.RoleSiteAdmin), "first_admin": true, "via": "bootstrap"}
	_ = b.svc.Record(ctx, created)
}
