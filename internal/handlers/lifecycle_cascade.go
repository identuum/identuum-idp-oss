package handlers

import (
	"context"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/repository"
	"github.com/identuum/identuum-idp-oss/internal/service"
	"github.com/identuum/identuum-idp-oss/logger"
)

// OrgSessionRevoker is the narrow seam for org-scoped session revocation.
// *repository.SessionRepository (the Pgx implementation's
// RevokeByOrganizationID, previously dead-wired) satisfies it.
type OrgSessionRevoker interface {
	RevokeByOrganizationID(ctx context.Context, orgID uuid.UUID, reason string) error
}

// OrgMemberLister enumerates an organization's users so the per-member
// refresh-token revoke can fan out, reusing the existing RevokeAllForUser
// primitive (no org-scoped refresh primitive exists). *service.UserService
// satisfies it.
type OrgMemberLister interface {
	ListByOrganization(ctx context.Context, orgID uuid.UUID, opts repository.ListUserOptions) ([]*domain.User, int, error)
}

// cascadeMemberPageSize bounds the per-member refresh fan-out on an org
// lifecycle change. OSS organizations are small; this is a best-effort
// single page. Members beyond the cap still have their SESSIONS revoked by
// RevokeByOrganizationID (which also blocks refresh rotation via the
// session-validity gate) — only the standalone OAuth-refresh sweep is
// page-bounded.
const cascadeMemberPageSize = 10000

// cascadeRevokeUser best-effort revokes a single user's sessions + refresh
// tokens AFTER a lifecycle change (ban / delete) has persisted. It is the
// enforcement the Stage-1 bearer session check then honors.
//
// P-018 / best-effort contract: this never returns an error and never
// panics. A revoke sub-step failure is logged at ERROR and ignored — the
// lifecycle change is the source of truth; revocation is the enforcement.
// Nil seams are no-ops (scaffold deployments without a session store).
func cascadeRevokeUser(ctx context.Context, sessions service.SessionRevoker, refresh service.UserRefreshTokenRevoker, userID uuid.UUID, reason string) {
	if sessions != nil {
		if err := sessions.RevokeUserSessions(ctx, userID, reason, nil); err != nil {
			logger.ErrorContext(ctx, "lifecycle cascade: user session revoke failed",
				zap.String("reason", reason), zap.Stringer("user_id", userID), zap.Error(err))
		}
	}
	if refresh != nil {
		if _, err := refresh.RevokeAllForUser(ctx, userID); err != nil {
			logger.ErrorContext(ctx, "lifecycle cascade: user refresh-token revoke failed",
				zap.String("reason", reason), zap.Stringer("user_id", userID), zap.Error(err))
		}
	}
}

// cascadeRevokeOrg best-effort revokes ALL member sessions (via the
// org-scoped session primitive RevokeByOrganizationID) and refresh tokens
// (per-member fan-out reusing RevokeAllForUser) AFTER an org lifecycle
// change (deactivate / delete) has persisted.
//
// Same P-018 / best-effort contract as cascadeRevokeUser: never returns,
// never panics; sub-step failures are logged at ERROR and ignored.
func cascadeRevokeOrg(ctx context.Context, sessions OrgSessionRevoker, refresh service.UserRefreshTokenRevoker, members OrgMemberLister, orgID uuid.UUID, reason string) {
	if sessions != nil {
		if err := sessions.RevokeByOrganizationID(ctx, orgID, reason); err != nil {
			logger.ErrorContext(ctx, "lifecycle cascade: org session revoke failed",
				zap.String("reason", reason), zap.Stringer("org_id", orgID), zap.Error(err))
		}
	}
	if refresh == nil || members == nil {
		return
	}
	users, _, err := members.ListByOrganization(ctx, orgID, repository.ListUserOptions{
		Pagination: repository.Pagination{Page: 1, PageSize: cascadeMemberPageSize},
	})
	if err != nil {
		logger.ErrorContext(ctx, "lifecycle cascade: org member list failed (refresh sweep skipped)",
			zap.Stringer("org_id", orgID), zap.Error(err))
		return
	}
	for _, u := range users {
		if u == nil {
			continue
		}
		if _, err := refresh.RevokeAllForUser(ctx, u.ID); err != nil {
			logger.ErrorContext(ctx, "lifecycle cascade: org member refresh-token revoke failed",
				zap.String("reason", reason), zap.Stringer("org_id", orgID), zap.Stringer("user_id", u.ID), zap.Error(err))
		}
	}
}
