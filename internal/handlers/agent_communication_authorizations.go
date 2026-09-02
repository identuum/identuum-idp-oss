package handlers

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/mw"
	"github.com/identuum/identuum-idp-oss/internal/service"
	"github.com/identuum/identuum-idp-oss/types"
)

// AgentCommunicationAuthorizationsHandlerDeps wires the AYGHU-2 admin
// surface /api/v1/agent-communication-authorizations.
type AgentCommunicationAuthorizationsHandlerDeps struct {
	Service *service.AgentCommunicationAuthorizationService
	Audit   audit.Service
}

// Audit actions of the agent-communication admin surface. Metadata is
// SAFE ONLY (spec): authorization / session / organization / acting owner
// ids, participant ACI + role + service-account + client ids, outcome and a
// stable bounded result code. Never a thumbprint, a free-text reason, an
// audience, a token, a proof or a key.
const (
	AuditActionAgentCommunicationAuthorizationCreated = "agent_communication_authorization.created"
	AuditActionAgentCommunicationAuthorizationRevoked = "agent_communication_authorization.revoked"
)

// RegisterAgentCommunicationAuthorizationRoutes mounts:
//
//	POST /api/v1/agent-communication-authorizations
//	GET  /api/v1/agent-communication-authorizations
//	GET  /api/v1/agent-communication-authorizations/:id
//	POST /api/v1/agent-communication-authorizations/:id/revoke
//
// Every route requires authentication; the service enforces the tenant
// authority model (org_admin OWN organization only — site_admin and
// org_user are refused 403 uniformly, so the refusal depends on the caller,
// never on the target). No PUT/PATCH exists: an authorization is never
// edited or widened. Routes register ONLY when Service is non-nil.
func RegisterAgentCommunicationAuthorizationRoutes(router gin.IRouter, deps AgentCommunicationAuthorizationsHandlerDeps) {
	if deps.Service == nil {
		return
	}
	if deps.Audit == nil {
		deps.Audit = audit.NoopService{}
	}

	g := router.Group("/api/v1/agent-communication-authorizations")
	g.Use(mw.RequireAuthenticated())

	// docgen:endpoint
	// docgen:surface=agent-communication-authorizations
	// docgen:method=POST
	// docgen:path=/api/v1/agent-communication-authorizations
	// docgen:summary=Create an agent communication authorization: exactly two participant service accounts of the acting org_admin (initiator + responder), each installed as a private_key_jwt OAuth client; the server allocates the authorization id, session id, participant ACIs and the canonical policy digest.
	// docgen:tier=oss
	// docgen:auth=org_admin
	// docgen:response=oss.types.AgentCommunicationAuthorization
	// docgen:notes=org_admin OWN-ORG only; the owner is always the actor; site_admin and org_user are refused 403 uniformly; an explicit organization_id that is not the actor's answers 403. Client-supplied ids, session ids, ACIs and policy digests are ignored, never trusted. Refusals: 400 invalid_request with a stable reason (participant_count, unknown_capability, duplicate_role, relay_audience_required, expiry_not_future, limit_not_positive, participant_service_account_not_found, participant_client_not_found, client_not_bound, client_auth_not_asymmetric, …), 403 forbidden with reason ownerless_participant / owner_mismatch (same-owner rule), 409 conflict participant_not_usable (inactive or expired service account). A store error answers 503 temporarily_unavailable with a correlation id (AUTH-503), never a verdict. Emits agent_communication_authorization.created with safe metadata only.
	// docgen:status=201
	g.POST("", HandleCreateAgentCommunicationAuthorization(deps))

	// docgen:endpoint
	// docgen:surface=agent-communication-authorizations
	// docgen:method=GET
	// docgen:path=/api/v1/agent-communication-authorizations
	// docgen:summary=List the acting org_admin's organization's agent communication authorizations (any status, newest first) with their participants' ACIs and derived status.
	// docgen:tier=oss
	// docgen:auth=org_admin
	// docgen:response=oss.types.AgentCommunicationAuthorizationList
	// docgen:notes=org_admin OWN-ORG only; site_admin and org_user are refused 403. Results are scoped to the actor's organization; no cross-organization row is ever listed. Store error → 503 with correlation id (AUTH-503).
	g.GET("", HandleListAgentCommunicationAuthorizations(deps))

	// docgen:endpoint
	// docgen:surface=agent-communication-authorizations
	// docgen:method=GET
	// docgen:path=/api/v1/agent-communication-authorizations/:id
	// docgen:summary=Read one agent communication authorization of the acting org_admin's organization, with participants (ACI, role, service account, client, proof-key thumbprint, capabilities) and derived status.
	// docgen:tier=oss
	// docgen:auth=org_admin
	// docgen:response=oss.types.AgentCommunicationAuthorization
	// docgen:notes=org_admin OWN-ORG only; site_admin and org_user are refused 403. A foreign organization's id and an absent id answer 404 identically — no cross-organization existence oracle. Store error → 503 with correlation id (AUTH-503).
	g.GET("/:id", HandleGetAgentCommunicationAuthorization(deps))

	// docgen:endpoint
	// docgen:surface=agent-communication-authorizations
	// docgen:method=POST
	// docgen:path=/api/v1/agent-communication-authorizations/:id/revoke
	// docgen:summary=Revoke an agent communication authorization (terminal): records the acting org_admin, the timestamp and an optional bounded reason; a repeated revocation is idempotent and returns the first stamp unchanged.
	// docgen:tier=oss
	// docgen:auth=org_admin
	// docgen:response=oss.types.AgentCommunicationAuthorization
	// docgen:notes=org_admin OWN-ORG only (same-organization emergency revocation by any org_admin is allowed and audited); site_admin and org_user are refused 403. Body {"reason"} is optional, trimmed, at most 256 bytes (400 revocation_reason_too_long). A foreign organization's id and an absent id answer 404 identically. Store error → 503 with correlation id (AUTH-503). Emits agent_communication_authorization.revoked (result revoked / already_revoked) with safe metadata only — the free-text reason never enters the audit.
	g.POST("/:id/revoke", HandleRevokeAgentCommunicationAuthorization(deps))
}

type agentCommunicationParticipantRequest struct {
	ServiceAccountID   string   `json:"service_account_id"`
	ClientID           string   `json:"client_id"`
	Role               string   `json:"role"`
	ProofKeyThumbprint string   `json:"proof_key_thumbprint"`
	Capabilities       []string `json:"capabilities"`
}

// agentCommunicationCreateRequest is the creation body. Fields the SERVER
// generates (id, session_id, participant ids, ACIs, policy_digest,
// created_at) are deliberately absent: a client that sends them is ignored,
// never trusted.
type agentCommunicationCreateRequest struct {
	OrganizationID      string                                 `json:"organization_id"`
	RelayAudience       string                                 `json:"relay_audience"`
	ExpiresAt           time.Time                              `json:"expires_at"`
	MaxMessages         int                                    `json:"max_messages"`
	MaxMessageSizeBytes int64                                  `json:"max_message_size_bytes"`
	Participants        []agentCommunicationParticipantRequest `json:"participants"`
}

type agentCommunicationRevokeRequest struct {
	Reason string `json:"reason"`
}

func respondAgentCommunicationInvalid(c *gin.Context, reason string) {
	c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "reason": reason})
}

// parseAgentCommunicationID parses the :id path parameter. A malformed id
// is a 400 (it cannot name anything); an absent or foreign id is the
// service's 404.
func parseAgentCommunicationID(c *gin.Context) (uuid.UUID, bool) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		respondAgentCommunicationInvalid(c, "invalid_authorization_id")
		return uuid.Nil, false
	}
	return id, true
}

// HandleCreateAgentCommunicationAuthorization — POST "".
func HandleCreateAgentCommunicationAuthorization(deps AgentCommunicationAuthorizationsHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		actor, _ := mw.PrincipalFromContext(c)
		var req agentCommunicationCreateRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
			return
		}
		in := service.CreateAgentCommunicationAuthorizationInput{
			RelayAudience:       req.RelayAudience,
			ExpiresAt:           req.ExpiresAt,
			MaxMessages:         req.MaxMessages,
			MaxMessageSizeBytes: req.MaxMessageSizeBytes,
		}
		if s := strings.TrimSpace(req.OrganizationID); s != "" {
			org, err := uuid.Parse(s)
			if err != nil {
				respondAgentCommunicationInvalid(c, "invalid_organization_id")
				return
			}
			in.OrganizationID = org
		}
		for _, p := range req.Participants {
			saID, err := uuid.Parse(strings.TrimSpace(p.ServiceAccountID))
			if err != nil {
				respondAgentCommunicationInvalid(c, "invalid_service_account_id")
				return
			}
			in.Participants = append(in.Participants, service.AgentCommunicationParticipantInput{
				ServiceAccountID:   saID,
				ClientID:           p.ClientID,
				Role:               domain.AgentCommunicationParticipantRole(p.Role),
				ProofKeyThumbprint: p.ProofKeyThumbprint,
				Capabilities:       p.Capabilities,
			})
		}
		a, err := deps.Service.CreateForActor(c.Request.Context(), actor, in)
		if err != nil {
			respondAgentCommunicationError(c, "agent_communication.create", err)
			return
		}
		participants := make([]map[string]any, 0, len(a.Participants))
		for _, p := range a.Participants {
			participants = append(participants, map[string]any{
				"aci":                p.ACI.String(),
				"role":               string(p.Role),
				"service_account_id": p.ServiceAccountID.String(),
				"oauth_client_id":    p.OAuthClientID.String(),
			})
		}
		_ = deps.Audit.Record(c.Request.Context(), enrichActor(c, audit.Event{
			Action:         AuditActionAgentCommunicationAuthorizationCreated,
			Outcome:        "success",
			SubjectID:      a.ID,
			SubjectType:    "agent_communication_authorization",
			OrganizationID: a.OrganizationID,
			CorrelationID:  mw.CorrelationID(c),
			IPAddress:      c.ClientIP(),
			UserAgent:      c.Request.UserAgent(),
			Metadata: map[string]any{
				"authorization_id": a.ID.String(),
				"session_id":       a.SessionID.String(),
				"organization_id":  a.OrganizationID.String(),
				"owner_id":         a.OwnerID.String(),
				"participants":     participants,
			},
		}))
		c.JSON(http.StatusCreated, toAgentCommunicationAuthorizationDTO(a, deps.Service.Now()))
	}
}

// HandleListAgentCommunicationAuthorizations — GET "".
func HandleListAgentCommunicationAuthorizations(deps AgentCommunicationAuthorizationsHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		actor, _ := mw.PrincipalFromContext(c)
		list, err := deps.Service.ListForActor(c.Request.Context(), actor)
		if err != nil {
			respondAgentCommunicationError(c, "agent_communication.list", err)
			return
		}
		now := deps.Service.Now()
		out := types.AgentCommunicationAuthorizationList{
			Authorizations: make([]types.AgentCommunicationAuthorization, 0, len(list)),
			Count:          len(list),
		}
		for _, a := range list {
			out.Authorizations = append(out.Authorizations, toAgentCommunicationAuthorizationDTO(a, now))
		}
		c.JSON(http.StatusOK, out)
	}
}

// HandleGetAgentCommunicationAuthorization — GET "/:id".
func HandleGetAgentCommunicationAuthorization(deps AgentCommunicationAuthorizationsHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		actor, _ := mw.PrincipalFromContext(c)
		id, ok := parseAgentCommunicationID(c)
		if !ok {
			return
		}
		a, err := deps.Service.GetForActor(c.Request.Context(), actor, id)
		if err != nil {
			respondAgentCommunicationError(c, "agent_communication.get", err)
			return
		}
		c.JSON(http.StatusOK, toAgentCommunicationAuthorizationDTO(a, deps.Service.Now()))
	}
}

// HandleRevokeAgentCommunicationAuthorization — POST "/:id/revoke".
func HandleRevokeAgentCommunicationAuthorization(deps AgentCommunicationAuthorizationsHandlerDeps) gin.HandlerFunc {
	return func(c *gin.Context) {
		actor, _ := mw.PrincipalFromContext(c)
		id, ok := parseAgentCommunicationID(c)
		if !ok {
			return
		}
		var req agentCommunicationRevokeRequest
		if c.Request.Body != nil && c.Request.ContentLength != 0 {
			if err := c.ShouldBindJSON(&req); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
				return
			}
		}
		a, revokedNow, err := deps.Service.RevokeForActor(c.Request.Context(), actor, id, req.Reason)
		if err != nil {
			respondAgentCommunicationError(c, "agent_communication.revoke", err)
			return
		}
		result := "already_revoked"
		if revokedNow {
			result = "revoked"
		}
		meta := map[string]any{
			"authorization_id": a.ID.String(),
			"session_id":       a.SessionID.String(),
			"organization_id":  a.OrganizationID.String(),
			"result":           result,
		}
		if a.RevokedBy != nil {
			meta["revoked_by"] = a.RevokedBy.String()
		}
		_ = deps.Audit.Record(c.Request.Context(), enrichActor(c, audit.Event{
			Action:         AuditActionAgentCommunicationAuthorizationRevoked,
			Outcome:        "success",
			SubjectID:      a.ID,
			SubjectType:    "agent_communication_authorization",
			OrganizationID: a.OrganizationID,
			CorrelationID:  mw.CorrelationID(c),
			IPAddress:      c.ClientIP(),
			UserAgent:      c.Request.UserAgent(),
			Metadata:       meta,
		}))
		c.JSON(http.StatusOK, toAgentCommunicationAuthorizationDTO(a, deps.Service.Now()))
	}
}

// agentCommunicationInvalidReasons maps the aggregate's input refusals to
// stable bounded reason codes (400 invalid_request).
var agentCommunicationInvalidReasons = []struct {
	err    error
	reason string
}{
	{domain.ErrAgentCommunicationParticipantCount, "participant_count"},
	{domain.ErrAgentCommunicationDuplicateACI, "duplicate_aci"},
	{domain.ErrAgentCommunicationDuplicateServiceAccount, "duplicate_service_account"},
	{domain.ErrAgentCommunicationDuplicateRole, "duplicate_role"},
	{domain.ErrAgentCommunicationDuplicateClient, "duplicate_client"},
	{domain.ErrAgentCommunicationInvalidRole, "invalid_role"},
	{domain.ErrAgentCommunicationUnknownCapability, "unknown_capability"},
	{domain.ErrAgentCommunicationCapabilitiesNotCanonical, "capabilities_not_canonical"},
	{domain.ErrAgentCommunicationIdentifierNotV7, "identifier_not_v7"},
	{domain.ErrAgentCommunicationIdentifierRequired, "identifier_required"},
	{domain.ErrAgentCommunicationRelayAudienceRequired, "relay_audience_required"},
	{domain.ErrAgentCommunicationRelayAudienceInvalid, "relay_audience_invalid"},
	{domain.ErrAgentCommunicationExpiryNotFuture, "expiry_not_future"},
	{domain.ErrAgentCommunicationLimitNotPositive, "limit_not_positive"},
	{domain.ErrAgentCommunicationProofKeyThumbprintInvalid, "proof_key_thumbprint_invalid"},
	{domain.ErrAgentCommunicationPolicyVersionUnsupported, "policy_version_unsupported"},
	{domain.ErrAgentCommunicationPolicyDigestMismatch, "policy_digest_mismatch"},
	{domain.ErrAgentCommunicationClientNotBound, "client_not_bound"},
	{domain.ErrAgentCommunicationClientAuthNotAsymmetric, "client_auth_not_asymmetric"},
	{domain.ErrAgentCommunicationRevocationReasonTooLong, "revocation_reason_too_long"},
	{domain.ErrServiceAccountNotFound, "participant_service_account_not_found"},
	{domain.ErrClientNotFound, "participant_client_not_found"},
}

// respondAgentCommunicationError maps service/domain errors to honest
// statuses. Order matters: the store class is checked FIRST so a wrapped
// unavailability can never be read as a verdict (AUTH-503).
func respondAgentCommunicationError(c *gin.Context, where string, err error) {
	switch {
	case domain.IsAuthStoreUnavailable(err):
		respondAuthStoreUnavailable(c, where, err)
		return
	case errors.Is(err, service.ErrAgentCommunicationForbidden):
		c.JSON(http.StatusForbidden, gin.H{"error": "forbidden"})
		return
	case errors.Is(err, domain.ErrAgentCommunicationAuthorizationNotFound):
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	case errors.Is(err, domain.ErrAgentCommunicationOwnerlessParticipant):
		c.JSON(http.StatusForbidden, gin.H{"error": "forbidden", "reason": "ownerless_participant"})
		return
	case errors.Is(err, domain.ErrAgentCommunicationOwnerMismatch):
		c.JSON(http.StatusForbidden, gin.H{"error": "forbidden", "reason": "owner_mismatch"})
		return
	case errors.Is(err, domain.ErrAgentCommunicationParticipantNotUsable):
		c.JSON(http.StatusConflict, gin.H{"error": "conflict", "reason": "participant_not_usable"})
		return
	}
	for _, m := range agentCommunicationInvalidReasons {
		if errors.Is(err, m.err) {
			respondAgentCommunicationInvalid(c, m.reason)
			return
		}
	}
	c.JSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
}

// toAgentCommunicationAuthorizationDTO projects the aggregate onto the wire
// type. Nothing secret exists on the aggregate; the projection still copies
// field by field so a future column never leaks by accident.
func toAgentCommunicationAuthorizationDTO(a *domain.AgentCommunicationAuthorization, now time.Time) types.AgentCommunicationAuthorization {
	if a == nil {
		return types.AgentCommunicationAuthorization{}
	}
	out := types.AgentCommunicationAuthorization{
		ID:                  a.ID,
		OrganizationID:      a.OrganizationID,
		OwnerID:             a.OwnerID,
		SessionID:           a.SessionID,
		RelayAudience:       a.RelayAudience,
		MaxMessages:         a.MaxMessages,
		MaxMessageSizeBytes: a.MaxMessageSizeBytes,
		ExpiresAt:           a.ExpiresAt,
		CreatedAt:           a.CreatedAt,
		Status:              string(a.Status(now)),
		RevokedAt:           a.RevokedAt,
		RevokedBy:           a.RevokedBy,
		RevocationReason:    a.RevocationReason,
		PolicyVersion:       a.PolicyVersion,
		PolicyDigest:        a.PolicyDigest,
		Participants:        make([]types.AgentCommunicationParticipant, 0, len(a.Participants)),
	}
	for _, p := range a.Participants {
		caps := make([]string, 0, len(p.Capabilities))
		for _, cp := range p.Capabilities {
			caps = append(caps, string(cp))
		}
		out.Participants = append(out.Participants, types.AgentCommunicationParticipant{
			ID:                 p.ID,
			ACI:                p.ACI,
			ServiceAccountID:   p.ServiceAccountID,
			OAuthClientID:      p.OAuthClientID,
			Role:               string(p.Role),
			ProofKeyThumbprint: p.ProofKeyThumbprint,
			Capabilities:       caps,
		})
	}
	return out
}
