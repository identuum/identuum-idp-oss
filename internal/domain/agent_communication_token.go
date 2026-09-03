package domain

import (
	"time"

	"github.com/google/uuid"
)

// AgentCommunicationToken records one issued participant token (AYGHU-4):
// the token's jti bound to its authorization and participant, so that
// revoking the authorization can revoke every still-live token immediately
// (introspection turns inactive now, not at expiry). Only the jti is
// stored — never the token.
type AgentCommunicationToken struct {
	JTI             string
	AuthorizationID uuid.UUID
	ACI             uuid.UUID
	ExpiresAt       time.Time
	IssuedAt        time.Time
}
