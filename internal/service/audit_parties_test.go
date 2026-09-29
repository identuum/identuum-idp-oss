package service

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
)

// OSS-FIN-3: resolveAuditParties fills the actor and the organization acted
// upon centrally, and never overwrites what the call site set.
func TestResolveAuditParties(t *testing.T) {
	orgA, orgB := uuid.New(), uuid.New()
	user := uuid.New()
	sysOrg := uuid.MustParse(domain.SystemOrgID)
	orgAdmin := audit.Actor{Type: "user", ID: user, Email: "a@example.test", Role: "org_admin", OrganizationID: orgA}
	siteAdmin := audit.Actor{Type: "user", ID: uuid.New(), Email: "s@example.test", Role: "site_admin", OrganizationID: sysOrg}
	client := audit.Actor{Type: "client", ClientID: "cid-1", OrganizationID: orgA}
	req := audit.WithRequest(context.Background())

	for _, c := range []struct {
		name                          string
		ctx                           context.Context
		ev                            audit.Event
		wantType, wantEmail           string
		wantID, wantTarget, wantActor uuid.UUID
	}{
		{"org_admin, no org on the event: its own", audit.WithActor(req, orgAdmin), audit.Event{Action: "user.updated"},
			"user", "a@example.test", user, orgA, orgA},
		{"site_admin, org in metadata: the org acted upon", audit.WithActor(req, siteAdmin),
			audit.Event{Action: "organization.updated", Metadata: map[string]any{"organization_id": orgB}},
			"user", "s@example.test", siteAdmin.ID, orgB, sysOrg},
		{"site_admin, nothing stated: platform-wide", audit.WithActor(req, siteAdmin), audit.Event{Action: "keys.rotated"},
			"user", "s@example.test", siteAdmin.ID, uuid.Nil, sysOrg},
		{"the event's organization wins", audit.WithActor(req, orgAdmin), audit.Event{Action: "x", OrganizationID: orgB},
			"user", "a@example.test", user, orgB, orgA},
		{"explicit actor type is kept and not mixed", audit.WithActor(req, orgAdmin), audit.Event{Action: "x", ActorType: "setup_token"},
			"setup_token", "", uuid.Nil, orgA, orgA},
		{"a client", audit.WithActor(req, client), audit.Event{Action: "x"},
			"client", "", uuid.Nil, orgA, orgA},
		{"a request with no principal: anonymous", req, audit.Event{Action: "user_session.login.failure"},
			"anonymous", "", uuid.Nil, uuid.Nil, uuid.Nil},
		{"no request: system", context.Background(), audit.Event{Action: "retention.sweep"},
			"system", "", uuid.Nil, uuid.Nil, uuid.Nil},
		{"string metadata org", req, audit.Event{Action: "x", Metadata: map[string]any{"organization_id": orgA.String()}},
			"anonymous", "", uuid.Nil, orgA, uuid.Nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			ev, target, actorOrg := resolveAuditParties(c.ctx, c.ev)
			if ev.ActorType != c.wantType || ev.ActorID != c.wantID || ev.ActorEmail != c.wantEmail || target != c.wantTarget || actorOrg != c.wantActor {
				t.Errorf("got type %q id %s email %q target %s actorOrg %s; want %q %s %q %s %s",
					ev.ActorType, ev.ActorID, ev.ActorEmail, target, actorOrg, c.wantType, c.wantID, c.wantEmail, c.wantTarget, c.wantActor)
			}
		})
	}

	// A client's id rides in metadata, without mutating the caller's map.
	md := map[string]any{"k": "v"}
	ev, _, _ := resolveAuditParties(audit.WithActor(req, client), audit.Event{Action: "x", Metadata: md})
	if ev.Metadata["actor_client_id"] != "cid-1" || len(md) != 1 {
		t.Errorf("client metadata %v (caller's map %v); want actor_client_id added to a copy", ev.Metadata, md)
	}
	// The call site's explicit actor is never overwritten.
	set := uuid.New()
	ev, _, _ = resolveAuditParties(audit.WithActor(req, orgAdmin), audit.Event{Action: "x", ActorType: "user", ActorID: set, ActorEmail: "own@example.test"})
	if ev.ActorID != set || ev.ActorEmail != "own@example.test" {
		t.Errorf("explicit actor overwritten: %s %q", ev.ActorID, ev.ActorEmail)
	}
}
