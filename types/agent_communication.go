package types

import (
	"time"

	"github.com/google/uuid"
)

// AgentCommunicationParticipant is the wire projection of one participant
// of an agent communication authorization (AYGHU-2). It carries the
// participant's opaque ACI (an address, never a credential), the service
// account and OAuth client it binds, its role, the proof-key THUMBPRINT
// (never a key) and its canonical capability set.
type AgentCommunicationParticipant struct {
	ID                 uuid.UUID `json:"id"`
	ACI                uuid.UUID `json:"aci"`
	ServiceAccountID   uuid.UUID `json:"service_account_id"`
	OAuthClientID      uuid.UUID `json:"oauth_client_id"`
	Role               string    `json:"role"`
	ProofKeyThumbprint string    `json:"proof_key_thumbprint"`
	Capabilities       []string  `json:"capabilities"`
}

// AgentCommunicationAuthorization is the wire projection of an
// authorization: safe metadata only — no secrets, keys, tokens or proofs
// exist on the aggregate to begin with. Status is derived at response time
// (active / revoked / expired); PolicyDigest is the server-computed
// canonical digest (client-supplied digests are ignored).
type AgentCommunicationAuthorization struct {
	ID                  uuid.UUID                       `json:"id"`
	OrganizationID      uuid.UUID                       `json:"organization_id"`
	OwnerID             uuid.UUID                       `json:"owner_id"`
	SessionID           uuid.UUID                       `json:"session_id"`
	RelayAudience       string                          `json:"relay_audience"`
	MaxMessages         int                             `json:"max_messages"`
	MaxMessageSizeBytes int64                           `json:"max_message_size_bytes"`
	ExpiresAt           time.Time                       `json:"expires_at"`
	CreatedAt           time.Time                       `json:"created_at"`
	Status              string                          `json:"status"`
	RevokedAt           *time.Time                      `json:"revoked_at,omitempty"`
	RevokedBy           *uuid.UUID                      `json:"revoked_by,omitempty"`
	RevocationReason    *string                         `json:"revocation_reason,omitempty"`
	PolicyVersion       string                          `json:"policy_version"`
	PolicyDigest        string                          `json:"policy_digest"`
	Participants        []AgentCommunicationParticipant `json:"participants"`
}

// AgentCommunicationAuthorizationList is the list envelope: the caller's
// organization's authorizations, newest first, any status.
type AgentCommunicationAuthorizationList struct {
	Authorizations []AgentCommunicationAuthorization `json:"authorizations"`
	Count          int                               `json:"count"`
}
