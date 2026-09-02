package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/repository"
	"github.com/identuum/identuum-idp-oss/pkg/oidc"
)

// AYGHU-3 ISSUANCE: the agent-communication participant token.
//
// The existing client_credentials path is extended, never forked: when a
// token request carries RFC 9396-style authorization_details of the ONE
// closed type "agent_communication", the request is sender-constrained
// (RFC 9449 DPoP, required — a Bearer agent token never exists), bound to
// exactly one participant of one active authorization, and answered with a
// short-lived token (default 5 min, hard max 15 min, never past the
// authorization's expiry) that carries no refresh token. Requests without
// authorization_details are untouched.

const (
	// AgentCommunicationAuthorizationDetailsType is the only
	// authorization_details type this server implements.
	AgentCommunicationAuthorizationDetailsType = "agent_communication"
	// AgentCommunicationScope is the narrow scope of a participant token.
	AgentCommunicationScope = "agent_communication"
	// DefaultAgentCommunicationTokenTTL / MaxAgentCommunicationTokenTTL
	// bound the participant token lifetime (spec: 5 min default, 15 max).
	DefaultAgentCommunicationTokenTTL = 5 * time.Minute
	MaxAgentCommunicationTokenTTL     = 15 * time.Minute
)

var (
	// ErrTokenServiceInvalidAuthorizationDetails — the authorization_details
	// parameter is malformed, of an unknown type, carries unknown or missing
	// fields, or names more than one agent-communication detail (RFC 9396
	// invalid_authorization_details).
	ErrTokenServiceInvalidAuthorizationDetails = errors.New("service: authorization_details invalid")
	// ErrAgentCommunicationGrantInvalid — the named authorization does not
	// permit this token for this client: absent (or another
	// organization's), revoked, expired, ACI not in it, client not that
	// participant's installation, participant not usable, binding broken.
	// One sentinel for all of them: no existence oracle.
	ErrAgentCommunicationGrantInvalid = errors.New("service: agent communication grant invalid")
)

// AgentCommunicationRefusal carries a stable bounded reason code for the
// audit trail beside the wire sentinel it unwraps to.
type AgentCommunicationRefusal struct {
	Reason string
	Err    error
}

func (r *AgentCommunicationRefusal) Error() string { return r.Err.Error() + " (" + r.Reason + ")" }
func (r *AgentCommunicationRefusal) Unwrap() error { return r.Err }

func refuseAgentCommunication(reason string, err error) error {
	return &AgentCommunicationRefusal{Reason: reason, Err: err}
}

// AgentCommunicationRefusalReason extracts the reason code of a refusal
// ("" when err is not a refusal, e.g. a store error).
func AgentCommunicationRefusalReason(err error) string {
	var r *AgentCommunicationRefusal
	if errors.As(err, &r) {
		return r.Reason
	}
	return ""
}

// AgentCommunicationIssuanceDeps is what the issuer needs beside the
// TokenService's own signer, clock and jti allocator.
type AgentCommunicationIssuanceDeps struct {
	Authorizations  repository.AgentCommunicationAuthorizationRepository
	ServiceAccounts AgentCommunicationServiceAccountLookup
	Clients         AgentCommunicationClientLookup
	Replays         DPoPProofReplayMarker
	// TokenEndpointURL is the advertised token endpoint (issuer +
	// /api/v1/oauth/token): the DPoP proof's htu must name it.
	TokenEndpointURL string
	// TTL is the configured participant-token lifetime; 0 → default,
	// anything above the hard maximum is clamped to it.
	TTL time.Duration
}

type agentCommunicationIssuance struct {
	deps AgentCommunicationIssuanceDeps
	ttl  time.Duration
}

// WithAgentCommunication enables participant-token issuance. A missing
// dependency leaves the feature OFF (requests with authorization_details
// then answer invalid_authorization_details) — never a partial issuer.
func (s *TokenService) WithAgentCommunication(deps AgentCommunicationIssuanceDeps) *TokenService {
	if deps.Authorizations == nil || deps.ServiceAccounts == nil || deps.Clients == nil || deps.Replays == nil || strings.TrimSpace(deps.TokenEndpointURL) == "" {
		s.agentComm = nil
		return s
	}
	ttl := deps.TTL
	if ttl <= 0 {
		ttl = DefaultAgentCommunicationTokenTTL
	}
	if ttl > MaxAgentCommunicationTokenTTL {
		ttl = MaxAgentCommunicationTokenTTL
	}
	s.agentComm = &agentCommunicationIssuance{deps: deps, ttl: ttl}
	return s
}

// HasAgentCommunication reports whether participant-token issuance is wired.
func (s *TokenService) HasAgentCommunication() bool { return s.agentComm != nil }

// AgentCommunicationTokenTTL is the effective configured lifetime.
func (s *TokenService) AgentCommunicationTokenTTL() time.Duration {
	if s.agentComm == nil {
		return 0
	}
	return s.agentComm.ttl
}

// AgentCommunicationAuthorizationDetail is the closed detail object.
type AgentCommunicationAuthorizationDetail struct {
	Type            string `json:"type"`
	AuthorizationID string `json:"authorization_id"`
	ACI             string `json:"aci"`
}

// ParseAgentCommunicationAuthorizationDetails parses the
// authorization_details form parameter: a JSON array with EXACTLY one
// object whose members are EXACTLY type, authorization_id and aci, type
// "agent_communication", both identifiers UUIDv7. Everything else fails
// closed.
func ParseAgentCommunicationAuthorizationDetails(raw string) (uuid.UUID, uuid.UUID, AgentCommunicationAuthorizationDetail, error) {
	var zero AgentCommunicationAuthorizationDetail
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > 2048 {
		return uuid.Nil, uuid.Nil, zero, fmt.Errorf("%w: empty or oversized", ErrTokenServiceInvalidAuthorizationDetails)
	}
	var items []map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &items); err != nil {
		return uuid.Nil, uuid.Nil, zero, fmt.Errorf("%w: not a JSON array of objects", ErrTokenServiceInvalidAuthorizationDetails)
	}
	if len(items) != 1 {
		return uuid.Nil, uuid.Nil, zero, fmt.Errorf("%w: exactly one detail required, got %d", ErrTokenServiceInvalidAuthorizationDetails, len(items))
	}
	item := items[0]
	if len(item) != 3 {
		return uuid.Nil, uuid.Nil, zero, fmt.Errorf("%w: unknown or missing fields", ErrTokenServiceInvalidAuthorizationDetails)
	}
	str := func(k string) (string, error) {
		rawV, ok := item[k]
		if !ok {
			return "", fmt.Errorf("%w: %s missing", ErrTokenServiceInvalidAuthorizationDetails, k)
		}
		var v string
		if err := json.Unmarshal(rawV, &v); err != nil || v == "" {
			return "", fmt.Errorf("%w: %s must be a non-empty string", ErrTokenServiceInvalidAuthorizationDetails, k)
		}
		return v, nil
	}
	typ, err := str("type")
	if err != nil {
		return uuid.Nil, uuid.Nil, zero, err
	}
	if typ != AgentCommunicationAuthorizationDetailsType {
		return uuid.Nil, uuid.Nil, zero, fmt.Errorf("%w: type %q not supported", ErrTokenServiceInvalidAuthorizationDetails, typ)
	}
	authRaw, err := str("authorization_id")
	if err != nil {
		return uuid.Nil, uuid.Nil, zero, err
	}
	aciRaw, err := str("aci")
	if err != nil {
		return uuid.Nil, uuid.Nil, zero, err
	}
	authID, err := uuid.Parse(authRaw)
	if err != nil || authID.Version() != 7 {
		return uuid.Nil, uuid.Nil, zero, fmt.Errorf("%w: authorization_id is not a UUIDv7", ErrTokenServiceInvalidAuthorizationDetails)
	}
	aci, err := uuid.Parse(aciRaw)
	if err != nil || aci.Version() != 7 {
		return uuid.Nil, uuid.Nil, zero, fmt.Errorf("%w: aci is not a UUIDv7", ErrTokenServiceInvalidAuthorizationDetails)
	}
	return authID, aci, AgentCommunicationAuthorizationDetail{
		Type:            AgentCommunicationAuthorizationDetailsType,
		AuthorizationID: authID.String(),
		ACI:             aci.String(),
	}, nil
}

// AgentCommunicationTokenRequest is the token-endpoint request as the
// handler saw it.
type AgentCommunicationTokenRequest struct {
	GrantType            string
	RequestedScope       string
	RequestedAudience    string
	AuthorizationDetails string
	DPoPProof            string
	HTTPMethod           string
}

// AgentCommunicationIssuanceRecord is the safe record of a success for the
// audit trail: identifiers only, never the token or the proof.
type AgentCommunicationIssuanceRecord struct {
	AuthorizationID  uuid.UUID
	SessionID        uuid.UUID
	ACI              uuid.UUID
	ServiceAccountID uuid.UUID
	OrganizationID   uuid.UUID
	Role             string
	ClientID         string
	ExpiresAt        time.Time
}

// IssueAgentCommunication verifies every spec condition and mints one
// participant token. Errors: an *AgentCommunicationRefusal wrapping the
// wire sentinel (unsupported_grant_type / invalid_authorization_details /
// invalid_dpop_proof / unauthorized_client / invalid_grant / invalid_target
// / invalid_scope), or domain.AuthStoreUnavailable for a store failure.
func (s *TokenService) IssueAgentCommunication(ctx context.Context, client *AuthenticatedClient, req AgentCommunicationTokenRequest) (*TokenResponse, *AgentCommunicationIssuanceRecord, error) {
	if s.agentComm == nil {
		return nil, nil, refuseAgentCommunication("not_available", ErrTokenServiceInvalidAuthorizationDetails)
	}
	d := s.agentComm.deps
	if client == nil {
		return nil, nil, refuseAgentCommunication("client_missing", ErrTokenServiceUnauthorizedClient)
	}
	if req.GrantType != "client_credentials" {
		return nil, nil, refuseAgentCommunication("unsupported_grant", ErrTokenServiceUnsupportedGrant)
	}
	authID, aci, detail, err := ParseAgentCommunicationAuthorizationDetails(req.AuthorizationDetails)
	if err != nil {
		return nil, nil, refuseAgentCommunication("invalid_authorization_details", err)
	}

	// Sender constraint first: no proof → no token, ever.
	now := s.now().UTC()
	proof, err := VerifyDPoPTokenEndpointProof(req.DPoPProof, req.HTTPMethod, d.TokenEndpointURL, now)
	if err != nil {
		if errors.Is(err, ErrDPoPProofRequired) {
			return nil, nil, refuseAgentCommunication("dpop_missing", err)
		}
		return nil, nil, refuseAgentCommunication("dpop_invalid", err)
	}

	// The caller must be an OAuth client authenticated with private_key_jwt
	// (the registered method is the enforced method).
	if client.Kind != AuthenticatedClientKindOAuth || client.IsPublic {
		return nil, nil, refuseAgentCommunication("client_kind", ErrTokenServiceUnauthorizedClient)
	}
	dc, err := d.Clients.GetClientByClientID(ctx, client.ClientID)
	if err != nil {
		if errors.Is(err, domain.ErrClientNotFound) {
			return nil, nil, refuseAgentCommunication("client_not_found", ErrTokenServiceUnauthorizedClient)
		}
		return nil, nil, domain.AuthStoreUnavailable("agent_communication.issue.client", err)
	}
	if dc == nil || dc.OrganizationID == nil || *dc.OrganizationID == uuid.Nil {
		return nil, nil, refuseAgentCommunication("client_not_found", ErrTokenServiceUnauthorizedClient)
	}
	if dc.IsPublic || dc.EffectiveAuthMethod() != "private_key_jwt" {
		return nil, nil, refuseAgentCommunication("client_auth_not_asymmetric", ErrTokenServiceUnauthorizedClient)
	}

	// The authorization, scoped to the client's organization: another
	// organization's id reads exactly like an absent one.
	a, err := d.Authorizations.GetByID(ctx, *dc.OrganizationID, authID)
	if err != nil {
		if errors.Is(err, domain.ErrAgentCommunicationAuthorizationNotFound) {
			return nil, nil, refuseAgentCommunication("authorization_not_found", ErrAgentCommunicationGrantInvalid)
		}
		return nil, nil, domain.AuthStoreUnavailable("agent_communication.issue.authorization", err)
	}
	switch a.Status(now) {
	case domain.AgentCommunicationStatusRevoked:
		return nil, nil, refuseAgentCommunication("authorization_revoked", ErrAgentCommunicationGrantInvalid)
	case domain.AgentCommunicationStatusExpired:
		return nil, nil, refuseAgentCommunication("authorization_expired", ErrAgentCommunicationGrantInvalid)
	}

	// The participant named by the ACI, and it must be THIS client's.
	var participant *domain.AgentCommunicationParticipant
	for i := range a.Participants {
		if a.Participants[i].ACI == aci {
			participant = &a.Participants[i]
			break
		}
	}
	if participant == nil {
		return nil, nil, refuseAgentCommunication("aci_not_in_authorization", ErrAgentCommunicationGrantInvalid)
	}
	if participant.OAuthClientID != dc.ID {
		return nil, nil, refuseAgentCommunication("client_not_participant", ErrAgentCommunicationGrantInvalid)
	}

	// The participant's service account: live, in the organization, and
	// still the account this client is bound to.
	sa, err := d.ServiceAccounts.GetByID(ctx, participant.ServiceAccountID)
	if err != nil {
		if errors.Is(err, domain.ErrServiceAccountNotFound) {
			return nil, nil, refuseAgentCommunication("participant_service_account_missing", ErrAgentCommunicationGrantInvalid)
		}
		return nil, nil, domain.AuthStoreUnavailable("agent_communication.issue.service_account", err)
	}
	if sa == nil || sa.OrganizationID != a.OrganizationID {
		return nil, nil, refuseAgentCommunication("participant_service_account_missing", ErrAgentCommunicationGrantInvalid)
	}
	if !sa.Active || (sa.ExpiresAt != nil && !sa.ExpiresAt.After(now)) {
		return nil, nil, refuseAgentCommunication("participant_not_usable", ErrAgentCommunicationGrantInvalid)
	}
	if err := domain.CheckAgentCommunicationParticipantClient(sa, dc); err != nil {
		return nil, nil, refuseAgentCommunication("participant_binding_invalid", ErrAgentCommunicationGrantInvalid)
	}

	// Exact relay audience (normalized form), narrow scope.
	audience, err := domain.NormalizeAgentCommunicationRelayAudience(req.RequestedAudience)
	if err != nil || audience != a.RelayAudience {
		return nil, nil, refuseAgentCommunication("audience_mismatch", ErrTokenServiceInvalidTarget)
	}
	if sc := strings.TrimSpace(req.RequestedScope); sc != "" && sc != AgentCommunicationScope {
		return nil, nil, refuseAgentCommunication("scope_invalid", ErrTokenServiceInvalidScope)
	}

	// Proof key = enrolled key; then the proof is single-use.
	if !DPoPThumbprintMatches(proof.JKT, participant.ProofKeyThumbprint) {
		return nil, nil, refuseAgentCommunication("thumbprint_mismatch", ErrDPoPProofInvalid)
	}
	firstUse, err := d.Replays.Mark(ctx, proof.JKT, proof.JTI)
	if err != nil {
		return nil, nil, domain.AuthStoreUnavailable("agent_communication.issue.dpop_replay", err)
	}
	if !firstUse {
		return nil, nil, refuseAgentCommunication("dpop_replay", ErrDPoPProofReplayed)
	}

	// Lifetime: configured TTL, never past the authorization's expiry.
	exp := now.Add(s.agentComm.ttl)
	if a.ExpiresAt.Before(exp) {
		exp = a.ExpiresAt
	}
	if !exp.After(now) {
		return nil, nil, refuseAgentCommunication("authorization_expired", ErrAgentCommunicationGrantInvalid)
	}
	jti, err := s.newJTI()
	if err != nil {
		return nil, nil, ErrTokenServiceSigningFailed
	}
	extra := map[string]any{
		"nbf":                   now.Unix(),
		"org_id":                a.OrganizationID.String(),
		"cnf":                   map[string]any{"jkt": proof.JKT},
		"authorization_details": []AgentCommunicationAuthorizationDetail{detail},
		"agent_communication": map[string]any{
			"authorization_id":         a.ID.String(),
			"session_id":               a.SessionID.String(),
			"aci":                      participant.ACI.String(),
			"role":                     string(participant.Role),
			"policy_version":           a.PolicyVersion,
			"policy_digest":            a.PolicyDigest,
			"max_messages":             a.MaxMessages,
			"max_message_size_bytes":   a.MaxMessageSizeBytes,
			"authorization_expires_at": a.ExpiresAt.Unix(),
		},
	}
	wireToken, _, err := s.minter.Mint(ctx, oidc.TokenClaims{
		Issuer:    s.issuer,
		Subject:   sa.ID.String(),
		ClientID:  client.ClientID,
		Audience:  a.RelayAudience,
		Scope:     AgentCommunicationScope,
		IssuedAt:  now,
		ExpiresAt: exp,
		JTI:       jti,
		ActorType: ActorTypeServiceAccount,
		Extra:     extra,
	})
	if err != nil {
		return nil, nil, err
	}
	return &TokenResponse{
		AccessToken: wireToken,
		TokenType:   "DPoP",
		ExpiresIn:   int64(exp.Sub(now).Seconds()),
		Scope:       AgentCommunicationScope,
	}, &AgentCommunicationIssuanceRecord{
		AuthorizationID:  a.ID,
		SessionID:        a.SessionID,
		ACI:              participant.ACI,
		ServiceAccountID: sa.ID,
		OrganizationID:   a.OrganizationID,
		Role:             string(participant.Role),
		ClientID:         client.ClientID,
		ExpiresAt:        exp,
	}, nil
}
