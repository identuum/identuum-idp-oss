package types

import (
	"time"

	"github.com/google/uuid"
)

// WebhookEndpoint represents a customer-defined HTTPS endpoint DTO
type WebhookEndpoint struct {
	CreatedAt      time.Time `json:"created_at"`
	URL            string    `json:"url"`
	Secret         string    `json:"secret"`
	EventFilters   []string  `json:"event_filters"`
	ID             uuid.UUID `json:"id"`
	OrganizationID uuid.UUID `json:"organization_id"`
	Enabled        bool      `json:"enabled"`
}

// WebhookPayload represents the actual JSON body sent to the webhook endpoint
// Moved from domain to types as it is an external wire contract
type WebhookPayload struct {
	Timestamp      time.Time `json:"timestamp"`
	Data           any       `json:"data"`
	Type           string    `json:"type"`
	ID             uuid.UUID `json:"id"`
	OrganizationID uuid.UUID `json:"organization_id"`
}
