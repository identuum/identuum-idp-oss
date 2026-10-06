package types

import (
	"time"

	"github.com/google/uuid"
)

type APIScopeDTO struct {
	ID          uuid.UUID `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
}

type APIResourceResponse struct {
	ID             uuid.UUID     `json:"id"`
	OrganizationID uuid.UUID     `json:"organization_id"`
	Name           string        `json:"name"`
	Audience       string        `json:"audience"`
	Active         bool          `json:"active"`
	Scopes         []APIScopeDTO `json:"scopes"`
	CreatedAt      time.Time     `json:"created_at"`
	UpdatedAt      time.Time     `json:"updated_at"`
}

// The API resource requests carry no token lifetime: OSS has one access-token
// lifetime, 1 hour, and refuses token_ttl_secs with 400 (owner rulings l and
// m, 2026-10-06). The 60-86400 fields these types once declared were never
// bound by the mounted handlers and are removed.
type CreateAPIResourceRequest struct {
	Name     string        `json:"name" binding:"required,min=2,max=255"`
	Audience string        `json:"audience" binding:"required,min=2,max=255"`
	Scopes   []APIScopeDTO `json:"scopes" binding:"omitempty,dive"`
}

type UpdateAPIResourceRequest struct {
	Name   *string       `json:"name,omitempty" binding:"omitempty,min=2,max=255"`
	Active *bool         `json:"active,omitempty"`
	Scopes []APIScopeDTO `json:"scopes,omitempty" binding:"omitempty,dive"`
}

type RegenerateAPIResourceSecretResponse struct {
	ID     uuid.UUID `json:"id"`
	Secret string    `json:"secret"`
}
