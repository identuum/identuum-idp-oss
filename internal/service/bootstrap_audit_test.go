package service

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
)

type rowsInserter struct{ rows []domain.AuditEvent }

func (c *rowsInserter) Insert(_ context.Context, e domain.AuditEvent) error {
	c.rows = append(c.rows, e)
	return nil
}

// OSS-FIN-3 item 4: the bootstrap's two rows match the wizard's, by the
// system actor, on the system organization, without the password.
func TestBootstrapAuditor_RecordsLikeTheWizard(t *testing.T) {
	ins := &rowsInserter{}
	admin := &domain.User{ID: uuid.MustParse(domain.SiteAdminID), Email: domain.SiteAdminEmail, PasswordHash: "never-in-a-row-1!"}
	NewBootstrapAuditor(ins).SetupCompleted(context.Background(), admin)
	if len(ins.rows) != 2 || ins.rows[0].EventType != "setup.completed" || ins.rows[1].EventType != domain.AuditUserCreated {
		t.Fatalf("bootstrap recorded %d row(s); want setup.completed then user_created", len(ins.rows))
	}
	for _, r := range ins.rows {
		if r.ActorType != "system" || r.OrganizationID == nil || r.OrganizationID.String() != domain.SystemOrgID || r.Outcome == nil || *r.Outcome != "success" {
			t.Errorf("%s: actor_type %q organization %v; want system on the system organization, success", r.EventType, r.ActorType, r.OrganizationID)
		}
		for k, v := range r.Metadata {
			if v == "never-in-a-row-1!" {
				t.Errorf("%s metadata %q carries the password", r.EventType, k)
			}
		}
	}
	u := ins.rows[1]
	if u.SubjectID == nil || u.SubjectID.String() != domain.SiteAdminID || u.Metadata["first_admin"] != true || u.Metadata["via"] != "bootstrap" {
		t.Errorf("user_created: subject %v metadata %v; want the site_admin sentinel, first_admin true, via bootstrap", u.SubjectID, u.Metadata)
	}
}
