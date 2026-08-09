package handlers

import (
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/mw"
)

// enrichActor stamps the acting principal's identity onto an audit event —
// ActorID / ActorType / ActorEmail / ActorRole — leaving any caller-set field
// untouched. It deliberately does NOT set OrganizationID: the tenant scope of
// a resource event is the RESOURCE'S organization (the trail it belongs to),
// which the call site supplies explicitly. For an org_admin actor the two are
// identical; for a site_admin acting on a tenant's resource the resource org
// keeps the event visible in that tenant's audit view (the repository clamp
// filters on actor_organization_id), which is the transparency the tenant is
// owed (v0.3.2 gap B2 — without actor/org enrichment the clamp hid every
// resource lifecycle event from the org_admin who performed it).
func enrichActor(c *gin.Context, ev audit.Event) audit.Event {
	p, ok := mw.PrincipalFromContext(c)
	if !ok || p == nil {
		return ev
	}
	if ev.ActorID == uuid.Nil {
		ev.ActorID = p.UserID
	}
	if ev.ActorType == "" {
		ev.ActorType = "user"
	}
	if ev.ActorEmail == "" {
		ev.ActorEmail = p.Email
	}
	if ev.ActorRole == "" {
		ev.ActorRole = string(p.Role)
	}
	return ev
}

// orgOf dereferences a nullable resource organization id for audit emission;
// a nil pointer (an org-less/global resource) contributes the zero UUID,
// which the persistence layer stores as NULL (site_admin-only visibility).
func orgOf(p *uuid.UUID) uuid.UUID {
	if p == nil {
		return uuid.Nil
	}
	return *p
}
