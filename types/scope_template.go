package types

import (
	"time"

	"github.com/google/uuid"
)

// ScopeTemplateResponse is the public API DTO for a scope template.
type ScopeTemplateResponse struct {
	ID          uuid.UUID `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Scopes      []string  `json:"scopes"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// CreateScopeTemplateRequest is the DTO for creating a scope template.
//
// No `binding:` tags. The handler binds via StrictBindJSON, which decodes
// through encoding/json directly and never invokes Gin's validator —
// validation tags here would be silently ignored. The authoritative
// per-field rules live in `domain.ScopeTemplate.Validate` (name length,
// scope-list non-empty, per-scope non-empty + whitespace + reserved-prefix
// bounds). Tag annotations here would mislead readers into assuming
// handler-edge validation exists.
type CreateScopeTemplateRequest struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Scopes      []string `json:"scopes"`
}

// UpdateScopeTemplateRequest is the DTO for updating a scope template.
// See CreateScopeTemplateRequest for the validation-source note.
type UpdateScopeTemplateRequest struct {
	Name        *string  `json:"name,omitempty"`
	Description *string  `json:"description,omitempty"`
	Scopes      []string `json:"scopes,omitempty"`
}
