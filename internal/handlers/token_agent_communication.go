package handlers

import (
	"github.com/gin-gonic/gin"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/mw"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// Audit actions of participant-token issuance (AYGHU-3). Metadata is safe
// only: identifiers, role, client_id, reason code, expiry — never a token,
// a proof or a key.
const (
	AuditActionAgentCommunicationTokenIssued  = "agent_communication.token.issued"
	AuditActionAgentCommunicationTokenRefused = "agent_communication.token.refused"
)

// handleAgentCommunicationGrant is the token endpoint's branch for a request
// carrying authorization_details. It is taken ONLY when that parameter is
// present, so every other client_credentials request is untouched.
func handleAgentCommunicationGrant(c *gin.Context, deps TokenHandlerDeps, client *service.AuthenticatedClient, grantType string) (*service.TokenResponse, error) {
	req := service.AgentCommunicationTokenRequest{
		GrantType:            grantType,
		RequestedScope:       c.PostForm("scope"),
		RequestedAudience:    c.PostForm("audience"),
		AuthorizationDetails: c.PostForm("authorization_details"),
		DPoPProof:            c.GetHeader("DPoP"),
		HTTPMethod:           c.Request.Method,
	}
	resp, rec, err := deps.TokenService.IssueAgentCommunication(c.Request.Context(), client, req)
	if err != nil {
		// A store outage is not a verdict: no refusal is recorded for it.
		if reason := service.AgentCommunicationRefusalReason(err); reason != "" && !domain.IsAuthStoreUnavailable(err) {
			_ = deps.Audit.Record(c.Request.Context(), audit.Event{
				Action:        AuditActionAgentCommunicationTokenRefused,
				Outcome:       "refused",
				CorrelationID: mw.CorrelationID(c),
				IPAddress:     c.ClientIP(),
				UserAgent:     c.Request.UserAgent(),
				Metadata: map[string]any{
					"client_id": client.ClientID,
					"reason":    reason,
				},
			})
		}
		return nil, err
	}
	_ = deps.Audit.Record(c.Request.Context(), audit.Event{
		Action:         AuditActionAgentCommunicationTokenIssued,
		Outcome:        "success",
		SubjectID:      rec.AuthorizationID,
		SubjectType:    "agent_communication_authorization",
		OrganizationID: rec.OrganizationID,
		CorrelationID:  mw.CorrelationID(c),
		IPAddress:      c.ClientIP(),
		UserAgent:      c.Request.UserAgent(),
		Metadata: map[string]any{
			"authorization_id":   rec.AuthorizationID.String(),
			"session_id":         rec.SessionID.String(),
			"aci":                rec.ACI.String(),
			"role":               rec.Role,
			"service_account_id": rec.ServiceAccountID.String(),
			"client_id":          rec.ClientID,
			"token_type":         resp.TokenType,
			"expires_at":         rec.ExpiresAt.UTC().Format("2006-01-02T15:04:05Z07:00"),
		},
	})
	return resp, nil
}
