package service

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/lifecycle"
	"github.com/identuum/identuum-idp-oss/internal/repository"
)

// IntrospectionClaims is the OSS-owned struct that a
// TokenClaimsVerifier hands back to the IntrospectionService.
//
// The struct deliberately mirrors RFC 7662 §2.2 token fields plus
// the OSS principal extras (UserID, OrgID, Role) that the
// monolith's MapTokenIntrospection projects via its
// types.IntrospectResponse. A verifier implementation is expected
// to populate as many fields as the underlying token actually
// carries; absent fields are left zero-valued and the response
// omits them via omitempty.
type IntrospectionClaims struct {
	Sub      string
	UserID   uuid.UUID
	Email    string
	ClientID string
	Scope    string
	// UserInfoClaims are the OIDC §5.5 claim names the token's client was
	// consented (and the role permitted) to receive at userinfo, from the
	// access token's `userinfo_claims` claim (THE-CLAIMS-PARAMETER). Nil
	// when the token carries none.
	UserInfoClaims []string
	Iss            string
	Aud            []string
	Exp            int64
	Iat            int64
	Nbf            int64
	Jti            string
	Role           string
	OrgID          uuid.UUID
	ActorType      string

	// SessionID is the user session the token was minted under, zero for
	// tokens that carry none (client-credentials / service-account — M2M).
	// It exists so a caller can apply the SAME use-time liveness verdict the
	// bearer middleware applies, instead of inventing a second one: the
	// pkg/oidc.SubjectResolver seam keys on it (CONF-10). Never rendered in
	// an introspection response.
	SessionID uuid.UUID

	// Extra carries the non-standard claims introspection needs to judge
	// beyond the registered set (AYGHU-4: cnf, agent_communication,
	// authorization_details). Populated by the verifier from the SIGNED
	// claim set; never from unverified input.
	Extra map[string]any
}

// TokenClaimsVerifier is the seam between the IntrospectionService
// and any concrete JWT verifier. The OSS auth.RepositoryVerifier
// satisfies it via a small adapter that lives in internal/auth.
//
// IntrospectToken is expected to do EVERYTHING VerifyBearerToken
// already does (signature verification, alg whitelist, issuer /
// audience claim checks, expiry) AND additionally surface the
// RFC 7662 standard claims so the service can build a faithful
// introspection response. Any verification failure (signature,
// alg, expiry, issuer, audience, malformed) MUST return a non-nil
// error so the service can map it to `{"active":false}` — the
// service NEVER distinguishes failure modes to the caller.
type TokenClaimsVerifier interface {
	IntrospectToken(ctx context.Context, rawToken string) (*IntrospectionClaims, error)
}

// IntrospectionResponse mirrors the monolith's
// types.IntrospectResponse projection (Active, Scope, ClientID,
// Username, TokenType, Exp, Iat, Nbf, Sub, Aud, Iss, Jti) so the
// OSS shape is wire-compatible at the field level. Agentic
// fields, Consumed, capability-specific fields, ADC chain
// fields, and budget fields from the auth-service variant are
// intentionally omitted — they are commercial-tier extensions
// that have no OSS-side mapping.
//
// The Username field is populated from claims.Email when
// available so an operator-facing UI can render a recognizable
// identifier; an OSS deployment that wants stricter privacy can
// wrap this service.
type IntrospectionResponse struct {
	Active    bool     `json:"active"`
	Scope     string   `json:"scope,omitempty"`
	ClientID  string   `json:"client_id,omitempty"`
	Username  string   `json:"username,omitempty"`
	TokenType string   `json:"token_type,omitempty"`
	Exp       int64    `json:"exp,omitempty"`
	Iat       int64    `json:"iat,omitempty"`
	Nbf       int64    `json:"nbf,omitempty"`
	Sub       string   `json:"sub,omitempty"`
	Aud       []string `json:"aud,omitempty"`
	Iss       string   `json:"iss,omitempty"`
	Jti       string   `json:"jti,omitempty"`

	// AYGHU-4 participant tokens: the confirmation key thumbprint ONLY
	// (RFC 9449 §6.1 `cnf.jkt`, never the JWK), the accepted
	// authorization_details, and the safe communication projection.
	Cnf                  map[string]any                   `json:"cnf,omitempty"`
	AuthorizationDetails any                              `json:"authorization_details,omitempty"`
	AgentCommunication   *IntrospectionAgentCommunication `json:"agent_communication,omitempty"`
}

// TokenRevocationChecker is the seam the IntrospectionService
// consults to translate a verified jti into a
// `{"active":false}` response when the token has been previously
// revoked via /api/v1/oauth/revoke. The production
// implementation is *TokenRevocationService; tests use an
// in-memory fake.
//
// IsRevoked must return (false, nil) for unknown jtis. A non-nil
// error is treated as `{"active":false}` by the service so a
// transient revocation-store outage cannot silently let a
// revoked token through.
type TokenRevocationChecker interface {
	IsRevoked(ctx context.Context, jti string) (bool, error)
}

// IntrospectionService is the OSS-narrow RFC 7662 introspection
// service. It takes a TokenClaimsVerifier (required), an
// optional UserScopeService that — when supplied — overrides the
// token's scope claim with the live RBAC-derived effective scope
// set, and an optional TokenRevocationChecker that — when
// supplied — flips `active` to false for any jti that has been
// persisted in the revocation store.
type IntrospectionService struct {
	verifier TokenClaimsVerifier
	scopeSvc *UserScopeService
	revoker  TokenRevocationChecker

	// AYGHU-4: participant-token introspection re-validates the token's
	// authorization and participant binding against the store.
	authorizations repository.AgentCommunicationAuthorizationRepository
	clients        AgentCommunicationClientLookup
	now            func() time.Time
}

// WithAgentCommunication enables participant-token introspection: a token
// carrying the agent_communication claim is judged against its
// authorization (must exist, be active) and its participant binding (ACI,
// service account, client, role, policy digest). Without it, a
// participant token is judged like any other token (signature, expiry,
// jti) — never MORE active than the store allows once wired.
func (s *IntrospectionService) WithAgentCommunication(authorizations repository.AgentCommunicationAuthorizationRepository, clients AgentCommunicationClientLookup) *IntrospectionService {
	if authorizations == nil || clients == nil {
		s.authorizations, s.clients = nil, nil
		return s
	}
	s.authorizations, s.clients = authorizations, clients
	return s
}

// HasAgentCommunication reports whether participant-token introspection is wired.
func (s *IntrospectionService) HasAgentCommunication() bool {
	return s.authorizations != nil && s.clients != nil
}

// IntrospectionAgentCommunication is the safe communication projection of
// an active participant token (RFC 7662 extension fields).
type IntrospectionAgentCommunication struct {
	AuthorizationID        string `json:"authorization_id"`
	SessionID              string `json:"session_id"`
	ACI                    string `json:"aci"`
	Role                   string `json:"role"`
	PolicyVersion          string `json:"policy_version"`
	PolicyDigest           string `json:"policy_digest"`
	MaxMessages            int    `json:"max_messages"`
	MaxMessageSizeBytes    int64  `json:"max_message_size_bytes"`
	AuthorizationExpiresAt int64  `json:"authorization_expires_at"`
}

// agentCommunicationVerdict judges a participant token's binding. It
// returns (nil, nil) for a token without the agent_communication claim,
// (nil, ErrAgentCommunicationTokenInactive) when the token must read
// inactive, a store error (unavailability) when the store could not answer,
// and the projection when the token is live.
func (s *IntrospectionService) agentCommunicationVerdict(ctx context.Context, claims *IntrospectionClaims) (*IntrospectionAgentCommunication, error) {
	raw, ok := claims.Extra["agent_communication"].(map[string]any)
	if !ok {
		return nil, nil
	}
	if !s.HasAgentCommunication() {
		return nil, ErrAgentCommunicationTokenInactive
	}
	str := func(k string) string { v, _ := raw[k].(string); return v }
	authID, err := uuid.Parse(str("authorization_id"))
	if err != nil {
		return nil, ErrAgentCommunicationTokenInactive
	}
	aci, err := uuid.Parse(str("aci"))
	if err != nil {
		return nil, ErrAgentCommunicationTokenInactive
	}
	if claims.OrgID == uuid.Nil {
		return nil, ErrAgentCommunicationTokenInactive
	}
	a, err := s.authorizations.GetByID(ctx, claims.OrgID, authID)
	if err != nil {
		if errors.Is(err, domain.ErrAgentCommunicationAuthorizationNotFound) {
			return nil, ErrAgentCommunicationTokenInactive
		}
		return nil, domain.AuthStoreUnavailable("introspection.agent_communication.authorization", err)
	}
	// The token's audience must be the authorization's relay audience: the
	// verifier defers this judgement to the store for participant tokens.
	audienceOK := false
	for _, aud := range claims.Aud {
		if aud == a.RelayAudience {
			audienceOK = true
			break
		}
	}
	if !audienceOK {
		return nil, ErrAgentCommunicationTokenInactive
	}
	now := time.Now
	if s.now != nil {
		now = s.now
	}
	if a.Status(now().UTC()) != domain.AgentCommunicationStatusActive {
		return nil, ErrAgentCommunicationTokenInactive
	}
	var p *domain.AgentCommunicationParticipant
	for i := range a.Participants {
		if a.Participants[i].ACI == aci {
			p = &a.Participants[i]
			break
		}
	}
	if p == nil {
		return nil, ErrAgentCommunicationTokenInactive
	}
	if p.ServiceAccountID.String() != claims.Sub || string(p.Role) != str("role") {
		return nil, ErrAgentCommunicationTokenInactive
	}
	if str("policy_digest") != a.PolicyDigest || str("session_id") != a.SessionID.String() {
		return nil, ErrAgentCommunicationTokenInactive
	}
	if claims.ClientID == "" {
		return nil, ErrAgentCommunicationTokenInactive
	}
	dc, err := s.clients.GetClientByClientID(ctx, claims.ClientID)
	if err != nil {
		if errors.Is(err, domain.ErrClientNotFound) {
			return nil, ErrAgentCommunicationTokenInactive
		}
		return nil, domain.AuthStoreUnavailable("introspection.agent_communication.client", err)
	}
	if dc == nil || dc.ID != p.OAuthClientID || dc.ServiceAccountID == nil || *dc.ServiceAccountID != p.ServiceAccountID {
		return nil, ErrAgentCommunicationTokenInactive
	}
	return &IntrospectionAgentCommunication{
		AuthorizationID:        a.ID.String(),
		SessionID:              a.SessionID.String(),
		ACI:                    p.ACI.String(),
		Role:                   string(p.Role),
		PolicyVersion:          a.PolicyVersion,
		PolicyDigest:           a.PolicyDigest,
		MaxMessages:            a.MaxMessages,
		MaxMessageSizeBytes:    a.MaxMessageSizeBytes,
		AuthorizationExpiresAt: a.ExpiresAt.Unix(),
	}, nil
}

// ErrAgentCommunicationTokenInactive — the participant token's binding no
// longer validates (a verdict, not a store failure).
var ErrAgentCommunicationTokenInactive = errors.New("service: agent communication token inactive")

// NewIntrospectionService constructs the service. verifier must
// be non-nil — passing nil is a programmer error and panics so a
// misconfigured deployment cannot silently issue
// `{"active":true}` for arbitrary tokens.
func NewIntrospectionService(report *lifecycle.StartupReport, verifier TokenClaimsVerifier, scopeSvc *UserScopeService) *IntrospectionService {
	if verifier == nil {
		report.Fatal("NewIntrospectionService", "service: NewIntrospectionService requires a non-nil TokenClaimsVerifier")
	}
	return &IntrospectionService{verifier: verifier, scopeSvc: scopeSvc, now: time.Now}
}

// WithRevocationChecker installs a TokenRevocationChecker so the
// service consults the revocation store on every verified token.
// Returns the receiver so the call composes with construction.
// A nil checker resets the seam — callers can use that to detach
// a previously wired store.
func (s *IntrospectionService) WithRevocationChecker(c TokenRevocationChecker) *IntrospectionService {
	s.revoker = c
	return s
}

// Introspect runs the supplied rawToken through the verifier and
// returns an IntrospectionResponse. The response is ALWAYS safe
// to serialize:
//
//   - active=false for empty input, verifier error (any reason),
//     or claims-without-subject. The remaining fields are zero
//     and are omitted via JSON omitempty.
//   - active=true for a fully-verified token whose claims include
//     at least a subject identifier. The response carries the
//     RFC 7662 standard fields populated from the claims, with
//     scope optionally overridden by UserScopeService.
//
// The raw token is NEVER echoed in the response and NEVER written
// to any field on the response. Callers that pass nil rawToken
// receive {"active":false}.
func (s *IntrospectionService) Introspect(ctx context.Context, rawToken string) IntrospectionResponse {
	resp, _ := s.IntrospectVerdict(ctx, rawToken)
	return resp
}

// IntrospectVerdict is Introspect with the AUTH-503 distinction surfaced:
// the returned error is non-nil ONLY when a store / infrastructure failure
// (the signing-key store, the revocation store) prevented a verdict — the
// response is then {"active":false} exactly as before (fail closed), but
// the caller can answer 503 with an ERROR log instead of presenting an
// unjudged token as inactive. A nil error means the response IS the
// verdict. Introspect keeps its old signature for existing callers.
func (s *IntrospectionService) IntrospectVerdict(ctx context.Context, rawToken string) (IntrospectionResponse, error) {
	if strings.TrimSpace(rawToken) == "" {
		return IntrospectionResponse{Active: false}, nil
	}
	claims, err := s.verifier.IntrospectToken(ctx, rawToken)
	if err != nil || claims == nil {
		if domain.IsAuthStoreUnavailable(err) {
			return IntrospectionResponse{Active: false}, err
		}
		return IntrospectionResponse{Active: false}, nil
	}
	if claims.Sub == "" && claims.UserID == uuid.Nil && claims.ClientID == "" {
		// A "verified" token with no subject identifier is not a
		// usable bearer — treat it as inactive so a misconfigured
		// claim set cannot poison downstream authorization.
		return IntrospectionResponse{Active: false}, nil
	}
	// Revocation check: if the token carries a jti AND a revocation
	// checker is wired, consult the store. A revoked jti — or a
	// repo error — flips the response to `{"active":false}`. The
	// fail-CLOSED-on-error policy is deliberate: a transient
	// outage of the revocation store must not leak a revoked
	// token as active. Discovery of the policy lives in
	// docs/open-core/PHASE2_IDP_PHYSICAL_RELOCATION.md.
	// AUTH-503: the repo-error branch additionally REPORTS the store
	// class so the wire answer can be 503, not a silent "inactive".
	if s.revoker != nil && claims.Jti != "" {
		revoked, revErr := s.revoker.IsRevoked(ctx, claims.Jti)
		if revErr != nil {
			return IntrospectionResponse{Active: false}, domain.AuthStoreUnavailable("revocation", revErr)
		}
		if revoked {
			return IntrospectionResponse{Active: false}, nil
		}
	}
	resp := IntrospectionResponse{
		Active:    true,
		Sub:       claims.Sub,
		ClientID:  claims.ClientID,
		Username:  claims.Email,
		TokenType: "Bearer",
		Exp:       claims.Exp,
		Iat:       claims.Iat,
		Nbf:       claims.Nbf,
		Aud:       claims.Aud,
		Iss:       claims.Iss,
		Jti:       claims.Jti,
		Scope:     claims.Scope,
	}
	if resp.Sub == "" && claims.UserID != uuid.Nil {
		resp.Sub = claims.UserID.String()
	}
	// Effective-scope override: when UserScopeService is wired,
	// the live RBAC binding set replaces the token's possibly
	// stale scope claim. This catches the common case of a
	// just-revoked role whose token has not yet expired. If the
	// scope lookup fails, the token's own scope claim is the
	// safe fallback (active stays true; the operator just sees
	// the token's view of its scopes).
	//
	// TOKEN-SCOPE-INTERSECTION-1: a CLIENT-BOUND user token (one the
	// authorization_code grant minted, marked by its client_id claim)
	// carries consented ∩ role-permitted. The live set may still narrow
	// it — a revoked role disappears — but must never widen it back to
	// the role set the user did not consent to hand this client. Login
	// session tokens carry no client_id and keep the replace semantics.
	// AYGHU-4: a participant token is judged against its authorization and
	// binding; inactive on any mismatch, 503 (never active:false) when the
	// store could not answer.
	ac, acErr := s.agentCommunicationVerdict(ctx, claims)
	if acErr != nil {
		if errors.Is(acErr, ErrAgentCommunicationTokenInactive) {
			return IntrospectionResponse{Active: false}, nil
		}
		return IntrospectionResponse{Active: false}, acErr
	}
	if ac != nil {
		resp.TokenType = "DPoP"
		resp.AgentCommunication = ac
		if cnf, ok := claims.Extra["cnf"].(map[string]any); ok {
			if jkt, ok := cnf["jkt"].(string); ok && jkt != "" {
				resp.Cnf = map[string]any{"jkt": jkt}
			}
		}
		if resp.Cnf == nil {
			// A participant token without a confirmation key is not one
			// this server issued.
			return IntrospectionResponse{Active: false}, nil
		}
		resp.AuthorizationDetails = claims.Extra["authorization_details"]
	}
	if s.scopeSvc != nil && claims.UserID != uuid.Nil {
		eff, scopeErr := s.scopeSvc.GetScopesForUser(ctx, claims.UserID, nil)
		if scopeErr == nil {
			if claims.ClientID != "" {
				resp.Scope = domain.NarrowScopeToLive(claims.Scope, eff)
			} else {
				resp.Scope = strings.Join(eff, " ")
			}
		}
	}
	return resp, nil
}

// ErrIntrospectionVerifierMissing is returned by future callers
// that want to detect a no-verifier wiring without panicking. The
// service itself panics at construction; this sentinel exists for
// completeness if a CE composer wants to programmatically detect
// the misconfiguration.
var ErrIntrospectionVerifierMissing = errors.New("service: introspection verifier missing")

// IntrospectActiveClaims returns the verified-and-revocation-checked
// claims object for callers that need richer projection than the
// wire-shaped IntrospectionResponse (notably the userinfo handler,
// which needs OrgID and Role beyond what RFC 7662 strictly carries).
//
// Returns (claims, true) only when:
//
//   - the verifier accepted the token,
//   - the claims carry at least one subject identifier,
//   - and either no revocation checker is wired OR the token's jti
//     is NOT marked revoked AND the checker did not error.
//
// Returns (nil, false) for every other case — the caller MUST map
// false to 401 with no additional detail.
//
// The raw token string is consumed once by the verifier and never
// retained.
func (s *IntrospectionService) IntrospectActiveClaims(ctx context.Context, rawToken string) (*IntrospectionClaims, bool) {
	claims, ok, _ := s.IntrospectActiveClaimsVerdict(ctx, rawToken)
	return claims, ok
}

// IntrospectActiveClaimsVerdict is IntrospectActiveClaims with the
// AUTH-503 distinction: (nil, false, err) when a store / infrastructure
// failure prevented a verdict (the caller answers 503 + ERROR log);
// (nil, false, nil) for a genuine negative verdict; (claims, true, nil)
// for an active token.
func (s *IntrospectionService) IntrospectActiveClaimsVerdict(ctx context.Context, rawToken string) (*IntrospectionClaims, bool, error) {
	if strings.TrimSpace(rawToken) == "" {
		return nil, false, nil
	}
	claims, err := s.verifier.IntrospectToken(ctx, rawToken)
	if err != nil || claims == nil {
		if domain.IsAuthStoreUnavailable(err) {
			return nil, false, err
		}
		return nil, false, nil
	}
	if claims.Sub == "" && claims.UserID == uuid.Nil && claims.ClientID == "" {
		return nil, false, nil
	}
	// AYGHU-4: a participant token is addressed to a relay, never to this
	// server's user-facing endpoints (userinfo) — refuse it here regardless
	// of what the store would say about it.
	if _, isParticipant := claims.Extra["agent_communication"]; isParticipant {
		return nil, false, nil
	}
	if s.revoker != nil && claims.Jti != "" {
		revoked, revErr := s.revoker.IsRevoked(ctx, claims.Jti)
		if revErr != nil {
			return nil, false, domain.AuthStoreUnavailable("revocation", revErr)
		}
		if revoked {
			return nil, false, nil
		}
	}
	return claims, true, nil
}
