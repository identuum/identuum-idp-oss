package domain

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// Webhook Event Types
const (
	// User Events
	EventUserCreated  = "user.created"
	EventUserUpdated  = "user.updated"
	EventUserDisabled = "user.disabled"
	EventUserDeleted  = "user.deleted"

	// Admin Events
	EventAdminAdded       = "admin.added"
	EventAdminRoleChanged = "admin.role_changed"

	// Organization Events
	EventOrgUpdated   = "org.updated"
	EventOrgDeleted   = "org.deleted"
	EventOrgCreated   = "org.created"
	EventOrgSuspended = "org.suspended"

	// Authentication Events
	EventLoginSuccess           = "login.success"
	EventLoginFailure           = "login.failure"
	EventMFAChallenge           = "mfa.challenge"
	EventMFAFailure             = "mfa.failure"
	EventMFAEnabled             = "mfa.enabled"
	EventMFADisabled            = "mfa.disabled"
	EventPasswordChanged        = "password.changed"
	EventAdminPasswordReset     = "admin.password_reset" // For site admin password resets
	EventPasswordResetRequested = "user.password_reset_requested"

	// Session Events
	EventSessionCreated        = "session.created"
	EventSessionRevoked        = "session.revoked"
	EventSessionMassRevocation = "session.mass_revocation"

	// Error Events
	EventSAMLAssertionFailure = "saml.assertion.failure"
	EventPolicyViolation      = "policy.violation"

	// Agentic Intervention Events
	// EventAgentInterventionRequested is fired when an agent submits a
	// mid-session intervention request. The payload is delivered to the
	// session's integration_webhook_url via the Outbox delivery engine.
	EventAgentInterventionRequested = "agent.intervention.requested"
)

// EventAgentInterventionDecided was removed in CBAA Phase F (RFC-0001) — the
// HMAC webhook delivery channel for HITL decisions is gone; providers retrieve
// decisions via the GET /api/v1/agent/feedback/:intervention_id/decision poll
// endpoint. Constant deletion is intentional: any remaining caller with
// hard-coded "agent.intervention.decided" must now switch to the poll model.

// WebhookEndpoint represents a customer-defined HTTPS endpoint
type WebhookEndpoint struct {
	CreatedAt      time.Time
	URL            string
	Secret         string
	EventFilters   []string
	ID             uuid.UUID
	OrganizationID uuid.UUID
	Enabled        bool
}

// WebhookOutboxEntry represents an event waiting to be delivered to a
// registered WebhookEndpoint.
type WebhookOutboxEntry struct {
	NextAttemptAt  time.Time
	CreatedAt      time.Time
	DeliveredAt    *time.Time
	LastError      *string
	EventType      string
	Payload        json.RawMessage
	Attempts       int
	ID             uuid.UUID
	OrganizationID uuid.UUID
	EndpointID     uuid.UUID
}
