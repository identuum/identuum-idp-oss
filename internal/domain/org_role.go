package domain

import (
	"time"

	"github.com/google/uuid"
)

// OrgRole is a custom role defined by an org admin. It bundles a set of
// API Resource scopes that can be assigned to users within the organization.
type OrgRole struct {
	ID          uuid.UUID
	OrgID       uuid.UUID
	Name        string
	Description string
	Scopes      []string // populated by JOIN query (scope_name strings from org_role_scopes)
	CreatedAt   time.Time
	UpdatedAt   time.Time
}
