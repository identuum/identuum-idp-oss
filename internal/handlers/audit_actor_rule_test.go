package handlers

import (
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/mw"
)

// enrichActor stamps the acting principal (id, type=user, email, role) onto an
// audit event whose actor fields are unset, and NEVER overwrites actor fields
// the caller already set.
// RULE: AUDIT-ACTOR-1
func TestEnrichActor_StampsPrincipalWithoutOverwriting(t *testing.T) {
	gin.SetMode(gin.ReleaseMode)
	uid := uuid.New()
	ctxWithPrincipal := func() *gin.Context {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		mw.SetPrincipal(c, &domain.Principal{UserID: uid, Email: "p@example.test", Role: domain.RoleOrgAdmin})
		return c
	}

	// Empty actor fields are stamped from the principal.
	got := enrichActor(ctxWithPrincipal(), audit.Event{})
	if got.ActorID != uid || got.ActorType != "user" || got.ActorEmail != "p@example.test" || got.ActorRole != string(domain.RoleOrgAdmin) {
		t.Errorf("enrichActor must stamp the principal onto an empty actor, got %+v", got)
	}

	// Explicitly-set actor fields are NOT overwritten.
	other := uuid.New()
	got2 := enrichActor(ctxWithPrincipal(), audit.Event{
		ActorID: other, ActorType: "service_account", ActorEmail: "svc@example.test", ActorRole: "site_admin",
	})
	if got2.ActorID != other || got2.ActorType != "service_account" || got2.ActorEmail != "svc@example.test" || got2.ActorRole != "site_admin" {
		t.Errorf("enrichActor must not overwrite set actor fields, got %+v", got2)
	}
}
