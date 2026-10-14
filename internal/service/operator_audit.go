package service

import (
	"context"
	"errors"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// OperatorAuditor records a host-only operator command by the system actor
// (via=cli), the way BootstrapAuditor records a CLI bootstrap, so the command
// layer never builds an audit event itself. No row carries a credential.
type OperatorAuditor struct {
	svc audit.Service
}

// NewOperatorAuditor writes through the persistent audit log.
func NewOperatorAuditor(repo auditInserter) *OperatorAuditor {
	return &OperatorAuditor{svc: NewPersistentAuditService(repo)}
}

// OrgAdminMFAReset records reset-org-admin-mfa: the org_admin whose second
// factor and passkeys were removed, whether its sessions were revoked, and
// how many refresh tokens were (nil when that revocation failed).
func (o *OperatorAuditor) OrgAdminMFAReset(ctx context.Context, admin *domain.User, sessionsRevoked bool, refreshRevoked *int64) {
	if o == nil || o.svc == nil || admin == nil {
		return
	}
	meta := map[string]any{"via": "cli", "user_id": admin.ID, "organization_id": admin.OrganizationID, "sessions_revoked": sessionsRevoked}
	if refreshRevoked != nil {
		meta["refresh_tokens_revoked_count"] = *refreshRevoked
	}
	_ = o.svc.Record(ctx, audit.Event{
		Action:         string(domain.AuditOrgAdminMFAReset),
		Outcome:        "success",
		ActorType:      audit.ActorTypeSystem,
		OrganizationID: admin.OrganizationID,
		SubjectID:      admin.ID,
		SubjectType:    "user",
		SubjectEmail:   admin.Email,
		Metadata:       meta,
	})
}

// SiteAdminCredentialsReset records recover-site-admin in the shape OrgAdminMFAReset
// uses: the site_admin whose password and MFA were reset, whether its
// sessions were revoked, and how many refresh tokens were (nil when that
// revocation failed or did not run). The outcome is "success" only when both
// revocations completed. Unlike OrgAdminMFAReset it returns the write's
// error: the command exits non-zero when its only record is lost.
func (o *OperatorAuditor) SiteAdminCredentialsReset(ctx context.Context, admin *domain.User, sessionsRevoked bool, refreshRevoked *int64) error {
	if o == nil || o.svc == nil || admin == nil {
		return errors.New("operator auditor: no audit sink or no administrator")
	}
	meta := map[string]any{"via": "cli", "user_id": admin.ID, "organization_id": admin.OrganizationID, "sessions_revoked": sessionsRevoked}
	outcome := "failure"
	if refreshRevoked != nil {
		meta["refresh_tokens_revoked_count"] = *refreshRevoked
		if sessionsRevoked {
			outcome = "success"
		}
	}
	return o.svc.Record(ctx, audit.Event{
		Action:         string(domain.AuditSiteAdminCredentialsReset),
		Outcome:        outcome,
		ActorType:      audit.ActorTypeSystem,
		OrganizationID: admin.OrganizationID,
		SubjectID:      admin.ID,
		SubjectType:    "user",
		SubjectEmail:   admin.Email,
		Metadata:       meta,
	})
}
