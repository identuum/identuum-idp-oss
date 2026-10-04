package handlers

import (
	"context"
	"net/http"
	"testing"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// OSS-POLISH item 5 (audit F4): disable and enable were recorded as a generic
// "user.updated" whose metadata was only user_id, with no actor. A PUT that
// only toggles active now records user_deactivated / user_activated, and every
// row this handler writes names its actor.
func TestHandleUpdateUser_LifecycleIsAuditedWithTheActor(t *testing.T) {
	org := uuid.New()
	actor := tenantAdminOf(org)
	for _, tt := range []struct {
		name, body, want string
		initial          bool
	}{
		{"disable", `{"active":false}`, string(domain.AuditUserDeactivated), false},
		{"enable", `{"active":true}`, string(domain.AuditUserActivated), true},
		{"a field change stays user.updated", `{"name":"Renamed"}`, "user.updated", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			user := &domain.User{ID: uuid.New(), OrganizationID: org, Role: domain.RoleOrgUser,
				Email: "lifecycle-audit@example.test", Banned: tt.initial}
			repo := newMemUserRepo()
			if _, err := repo.Create(context.Background(), user); err != nil {
				t.Fatal(err)
			}
			rec := &audit.Recorder{}
			deps := UsersHandlerDeps{
				Audit:               rec,
				UserService:         service.NewUserService(nil, repo),
				SessionRevoker:      service.NoopSessionRevoker{},
				RefreshTokenRevoker: service.NoopRefreshTokenRevoker{},
			}
			if code := runHandlerActing(t, actor, http.MethodPut, "/u/:id", "/u/"+user.ID.String(), tt.body, HandleUpdateUser(deps)); code != http.StatusOK {
				t.Fatalf("status = %d, want 200", code)
			}
			events := rec.Events()
			if len(events) != 1 {
				t.Fatalf("events = %+v, want exactly one %q", events, tt.want)
			}
			ev := events[0]
			if ev.Action != tt.want {
				t.Fatalf("action = %q, want %q", ev.Action, tt.want)
			}
			// The actor is injected, so its id is checked exactly.
			if ev.ActorID != actor.UserID || ev.ActorType != "user" || ev.ActorRole != string(actor.Role) {
				t.Fatalf("actor = (%v, %q, %q), want (%v, user, %q)", ev.ActorID, ev.ActorType, ev.ActorRole, actor.UserID, actor.Role)
			}
			if ev.Metadata["user_id"] != user.ID {
				t.Fatalf("metadata user_id = %v, want %v", ev.Metadata["user_id"], user.ID)
			}
		})
	}
}
