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
	TokenTTLSecs   int           `json:"token_ttl_secs"`
	Scopes         []APIScopeDTO `json:"scopes"`
	CreatedAt      time.Time     `json:"created_at"`
	UpdatedAt      time.Time     `json:"updated_at"`
}

type CreateAPIResourceRequest struct {
	Name         string        `json:"name" binding:"required,min=2,max=255"`
	Audience     string        `json:"audience" binding:"required,min=2,max=255"`
	TokenTTLSecs *int          `json:"token_ttl_secs,omitempty" binding:"omitempty,min=60,max=86400"`
	Scopes       []APIScopeDTO `json:"scopes" binding:"omitempty,dive"`
}

type UpdateAPIResourceRequest struct {
	Name         *string       `json:"name,omitempty" binding:"omitempty,min=2,max=255"`
	Active       *bool         `json:"active,omitempty"`
	TokenTTLSecs *int          `json:"token_ttl_secs,omitempty" binding:"omitempty,min=60,max=86400"`
	Scopes       []APIScopeDTO `json:"scopes,omitempty" binding:"omitempty,dive"`
}

type RegenerateAPIResourceSecretResponse struct {
	ID     uuid.UUID `json:"id"`
	Secret string    `json:"secret"`
}
