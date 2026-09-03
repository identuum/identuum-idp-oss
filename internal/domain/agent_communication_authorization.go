package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
)

// AgentCommunicationAuthorization — AYGHU-1 FOUNDATION.
//
// An owner (the human authority of the organization) authorizes exactly two of
// their own agent identities (service accounts, each installed as a
// private_key_jwt OAuth client) to communicate through a relay for one
// bounded session. The IdP allocates every identifier: the authorization
// id, the session id, and one opaque Agent Communication Identifier (ACI)
// per participant. An ACI is an ADDRESS, never a credential, a key or a
// token — it carries no secret and proves nothing on its own.
//
// This file is the aggregate, its closed vocabularies, its structural
// invariants and the canonical capability-policy digest. Owner/participant
// resolution against the store (same-owner rule, client binding) lives in
// the service; the store reinforces the structural invariants with
// constraints (migration 0037). No HTTP surface, no token issuance and no
// DPoP exist yet — those are later AYGHU slices.

// AgentCommunicationCapability is one member of the CLOSED capability
// vocabulary. Values are exact strings: no case folding, no trimming, no
// implication between members (repository.write does NOT imply
// repository.read). Unknown values fail closed.
type AgentCommunicationCapability string

const (
	AgentCapabilityCommunicationDiscuss AgentCommunicationCapability = "communication.discuss"
	AgentCapabilityRepositoryRead       AgentCommunicationCapability = "repository.read"
	AgentCapabilityRepositoryWrite      AgentCommunicationCapability = "repository.write"
	AgentCapabilityCommandExecute       AgentCommunicationCapability = "command.execute"
	AgentCapabilityTestExecute          AgentCommunicationCapability = "test.execute"
	AgentCapabilityNetworkAccess        AgentCommunicationCapability = "network.access"
	AgentCapabilityReportFinalRequired  AgentCommunicationCapability = "report.final.required"
)

var agentCommunicationCapabilityVocabulary = map[AgentCommunicationCapability]struct{}{
	AgentCapabilityCommunicationDiscuss: {},
	AgentCapabilityRepositoryRead:       {},
	AgentCapabilityRepositoryWrite:      {},
	AgentCapabilityCommandExecute:       {},
	AgentCapabilityTestExecute:          {},
	AgentCapabilityNetworkAccess:        {},
	AgentCapabilityReportFinalRequired:  {},
}

// AgentCommunicationCapabilities returns the closed vocabulary in
// canonical (byte-sorted) order. The returned slice is a fresh copy.
func AgentCommunicationCapabilities() []AgentCommunicationCapability {
	out := make([]AgentCommunicationCapability, 0, len(agentCommunicationCapabilityVocabulary))
	for c := range agentCommunicationCapabilityVocabulary {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// ParseAgentCommunicationCapability accepts exactly one vocabulary member
// and refuses everything else with ErrAgentCommunicationUnknownCapability.
func ParseAgentCommunicationCapability(raw string) (AgentCommunicationCapability, error) {
	c := AgentCommunicationCapability(raw)
	if _, ok := agentCommunicationCapabilityVocabulary[c]; !ok {
		return "", fmt.Errorf("%w: %q", ErrAgentCommunicationUnknownCapability, raw)
	}
	return c, nil
}

// CanonicalizeAgentCommunicationCapabilities validates every member
// against the closed vocabulary, drops duplicates and returns the set in
// canonical (byte-sorted) order. An empty input canonicalizes to an empty
// (non-nil) set — "communication only". The input is not mutated.
func CanonicalizeAgentCommunicationCapabilities(in []AgentCommunicationCapability) ([]AgentCommunicationCapability, error) {
	seen := make(map[AgentCommunicationCapability]struct{}, len(in))
	out := make([]AgentCommunicationCapability, 0, len(in))
	for _, raw := range in {
		c, err := ParseAgentCommunicationCapability(string(raw))
		if err != nil {
			return nil, err
		}
		if _, dup := seen[c]; dup {
			continue
		}
		seen[c] = struct{}{}
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out, nil
}

// AgentCommunicationParticipantRole is the closed role set of a v1
// authorization: exactly one initiator and exactly one responder.
type AgentCommunicationParticipantRole string

const (
	AgentCommunicationRoleInitiator AgentCommunicationParticipantRole = "initiator"
	AgentCommunicationRoleResponder AgentCommunicationParticipantRole = "responder"
)

// Valid reports whether r is a member of the closed role set.
func (r AgentCommunicationParticipantRole) Valid() bool {
	return r == AgentCommunicationRoleInitiator || r == AgentCommunicationRoleResponder
}

// AgentCommunicationPolicyVersion is the only policy version this
// foundation writes and accepts. A future version changes the canonical
// form and therefore the digest; it is part of the digest input.
const AgentCommunicationPolicyVersion = "v1"

// AgentCommunicationRelayAudienceMaxLen bounds the normalized audience.
const AgentCommunicationRelayAudienceMaxLen = 512

// AgentCommunicationRevocationReasonMaxLen bounds a stored reason.
const AgentCommunicationRevocationReasonMaxLen = 256

// AgentCommunicationAuthorizationStatus is the derived lifecycle state.
// Revocation is terminal and wins over expiry; expiry is derived at use
// time from ExpiresAt and is never stored.
type AgentCommunicationAuthorizationStatus string

const (
	AgentCommunicationStatusActive  AgentCommunicationAuthorizationStatus = "active"
	AgentCommunicationStatusRevoked AgentCommunicationAuthorizationStatus = "revoked"
	AgentCommunicationStatusExpired AgentCommunicationAuthorizationStatus = "expired"
)

// Typed domain errors. Every refusal a caller can trigger has its own
// sentinel so the (later) wire layer answers honestly without string
// matching; none of them is an auth-store error (see AuthStoreUnavailable).
var (
	ErrAgentCommunicationAuthorizationNotFound     = errors.New("agent communication authorization not found")
	ErrAgentCommunicationParticipantCount          = errors.New("agent communication authorization requires exactly two participants")
	ErrAgentCommunicationDuplicateACI              = errors.New("agent communication participants must carry distinct ACIs")
	ErrAgentCommunicationDuplicateServiceAccount   = errors.New("agent communication participants must be distinct service accounts")
	ErrAgentCommunicationDuplicateRole             = errors.New("agent communication participants must hold distinct roles")
	ErrAgentCommunicationInvalidRole               = errors.New("agent communication participant role is not initiator or responder")
	ErrAgentCommunicationUnknownCapability         = errors.New("agent communication capability is not in the vocabulary")
	ErrAgentCommunicationCapabilitiesNotCanonical  = errors.New("agent communication capabilities are not in canonical form")
	ErrAgentCommunicationIdentifierNotV7           = errors.New("agent communication identifier is not a UUIDv7")
	ErrAgentCommunicationIdentifierRequired        = errors.New("agent communication identifier is required")
	ErrAgentCommunicationRelayAudienceRequired     = errors.New("agent communication relay audience is required")
	ErrAgentCommunicationRelayAudienceInvalid      = errors.New("agent communication relay audience is invalid")
	ErrAgentCommunicationExpiryNotFuture           = errors.New("agent communication authorization must expire in the future")
	ErrAgentCommunicationLimitNotPositive          = errors.New("agent communication session limits must be positive")
	ErrAgentCommunicationProofKeyThumbprintInvalid = errors.New("agent communication proof key thumbprint is invalid")
	ErrAgentCommunicationPolicyVersionUnsupported  = errors.New("agent communication policy version is not supported")
	ErrAgentCommunicationPolicyDigestMismatch      = errors.New("agent communication policy digest does not match the policy")
	ErrAgentCommunicationOwnerlessParticipant      = errors.New("agent communication participant service account has no owner")
	ErrAgentCommunicationOwnerMismatch             = errors.New("agent communication participants must be owned by the creating owner")
	ErrAgentCommunicationParticipantNotUsable      = errors.New("agent communication participant service account is inactive or expired")
	ErrAgentCommunicationClientNotBound            = errors.New("agent communication participant client is not bound to the participant service account")
	ErrAgentCommunicationClientAuthNotAsymmetric   = errors.New("agent communication participant client must authenticate with private_key_jwt and registered keys")
	ErrAgentCommunicationDuplicateClient           = errors.New("agent communication participants must use distinct clients")
	ErrAgentCommunicationRevocationReasonTooLong   = errors.New("agent communication revocation reason is too long")

	// ErrServiceAccountNotFound is the typed verdict the service-account
	// store returns for "no such (live) row". AYGHU-1 introduced it so an
	// agent-communication caller can tell a verdict from a store error
	// (AUTH-503): any OTHER error from the store is the unavailable class.
	ErrServiceAccountNotFound = errors.New("service account not found")
)

// AgentCommunicationParticipant is one side of an authorization. ACI is the
// opaque address the relay and the (later) tokens refer to; it is unique
// across ALL authorizations. Capabilities are stored canonical (sorted,
// deduplicated, vocabulary members only).
type AgentCommunicationParticipant struct {
	ID                 uuid.UUID
	AuthorizationID    uuid.UUID
	ACI                uuid.UUID
	ServiceAccountID   uuid.UUID
	OAuthClientID      uuid.UUID
	Role               AgentCommunicationParticipantRole
	ProofKeyThumbprint string
	Capabilities       []AgentCommunicationCapability
	CreatedAt          time.Time
}

// AgentCommunicationAuthorization is the aggregate root. Participants
// holds exactly two rows; PolicyDigest is the canonical digest of Policy().
type AgentCommunicationAuthorization struct {
	ID                  uuid.UUID
	OrganizationID      uuid.UUID
	OwnerID             uuid.UUID
	SessionID           uuid.UUID
	RelayAudience       string
	MaxMessages         int
	MaxMessageSizeBytes int64
	ExpiresAt           time.Time
	CreatedAt           time.Time
	RevokedAt           *time.Time
	RevokedBy           *uuid.UUID
	RevocationReason    *string
	PolicyVersion       string
	PolicyDigest        string
	Participants        []AgentCommunicationParticipant
}

// Status derives the lifecycle state at `now`. Revoked is terminal and
// reported even after ExpiresAt has passed.
func (a *AgentCommunicationAuthorization) Status(now time.Time) AgentCommunicationAuthorizationStatus {
	if a.RevokedAt != nil {
		return AgentCommunicationStatusRevoked
	}
	if !now.Before(a.ExpiresAt) {
		return AgentCommunicationStatusExpired
	}
	return AgentCommunicationStatusActive
}

// Participant returns the participant holding role, or nil.
func (a *AgentCommunicationAuthorization) Participant(role AgentCommunicationParticipantRole) *AgentCommunicationParticipant {
	for i := range a.Participants {
		if a.Participants[i].Role == role {
			return &a.Participants[i]
		}
	}
	return nil
}

// AgentCommunicationParticipantPolicy is the per-role slice of the
// capability policy: the role and its canonical capability set. It carries
// no ACI, no key material and no timestamp on purpose — the digest binds
// WHAT was authorized, not WHO or WHEN.
type AgentCommunicationParticipantPolicy struct {
	Role         string   `json:"role"`
	Capabilities []string `json:"capabilities"`
}

// AgentCommunicationPolicy is the typed canonical form the digest is
// computed over. Field order is fixed by this declaration (encoding/json
// emits struct fields in declaration order with no whitespace); members are
// normalized by Canonical(): capabilities byte-sorted and deduplicated,
// participants sorted by role. Row order in the store never influences it.
type AgentCommunicationPolicy struct {
	PolicyVersion       string                                `json:"policy_version"`
	MaxMessages         int                                   `json:"max_messages"`
	MaxMessageSizeBytes int64                                 `json:"max_message_size_bytes"`
	Participants        []AgentCommunicationParticipantPolicy `json:"participants"`
}

// Policy projects the aggregate onto its capability policy.
func (a *AgentCommunicationAuthorization) Policy() AgentCommunicationPolicy {
	p := AgentCommunicationPolicy{
		PolicyVersion:       a.PolicyVersion,
		MaxMessages:         a.MaxMessages,
		MaxMessageSizeBytes: a.MaxMessageSizeBytes,
		Participants:        make([]AgentCommunicationParticipantPolicy, 0, len(a.Participants)),
	}
	for _, part := range a.Participants {
		caps := make([]string, 0, len(part.Capabilities))
		for _, c := range part.Capabilities {
			caps = append(caps, string(c))
		}
		p.Participants = append(p.Participants, AgentCommunicationParticipantPolicy{
			Role:         string(part.Role),
			Capabilities: caps,
		})
	}
	return p
}

// Canonical returns the deterministic byte form of the policy: a copy
// with every capability list byte-sorted and deduplicated and the
// participants sorted by role, JSON-encoded without whitespace. Two
// policies that authorize the same thing in a different order produce the
// same bytes.
func (p AgentCommunicationPolicy) Canonical() ([]byte, error) {
	c := AgentCommunicationPolicy{
		PolicyVersion:       p.PolicyVersion,
		MaxMessages:         p.MaxMessages,
		MaxMessageSizeBytes: p.MaxMessageSizeBytes,
		Participants:        make([]AgentCommunicationParticipantPolicy, 0, len(p.Participants)),
	}
	for _, part := range p.Participants {
		caps := append([]string(nil), part.Capabilities...)
		sort.Strings(caps)
		dedup := caps[:0]
		for i, v := range caps {
			if i > 0 && v == caps[i-1] {
				continue
			}
			dedup = append(dedup, v)
		}
		if dedup == nil {
			dedup = []string{}
		}
		c.Participants = append(c.Participants, AgentCommunicationParticipantPolicy{
			Role:         part.Role,
			Capabilities: dedup,
		})
	}
	sort.SliceStable(c.Participants, func(i, j int) bool {
		return c.Participants[i].Role < c.Participants[j].Role
	})
	return json.Marshal(c)
}

// Digest is the lowercase hex SHA-256 of Canonical().
func (p AgentCommunicationPolicy) Digest() (string, error) {
	b, err := p.Canonical()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// ComputePolicyDigest recomputes the aggregate's canonical policy digest.
func (a *AgentCommunicationAuthorization) ComputePolicyDigest() (string, error) {
	return a.Policy().Digest()
}

// NormalizeAgentCommunicationRelayAudience trims the audience and, when
// it is an absolute URL, lowercases its scheme and host. It refuses an
// empty value, whitespace or control characters inside the value, a
// fragment or userinfo in a URL form, and anything longer than
// AgentCommunicationRelayAudienceMaxLen. A non-URL audience (e.g. a URN or
// a bare identifier) is kept byte-exact after trimming.
func NormalizeAgentCommunicationRelayAudience(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", ErrAgentCommunicationRelayAudienceRequired
	}
	if len(s) > AgentCommunicationRelayAudienceMaxLen {
		return "", fmt.Errorf("%w: longer than %d bytes", ErrAgentCommunicationRelayAudienceInvalid, AgentCommunicationRelayAudienceMaxLen)
	}
	for _, r := range s {
		if r <= 0x20 || r == 0x7f {
			return "", fmt.Errorf("%w: contains whitespace or a control character", ErrAgentCommunicationRelayAudienceInvalid)
		}
	}
	u, err := url.Parse(s)
	if err != nil || u.Scheme == "" || u.Host == "" {
		// Not a URL form: keep byte-exact.
		return s, nil
	}
	if u.Fragment != "" || u.RawFragment != "" || strings.Contains(s, "#") {
		return "", fmt.Errorf("%w: must not contain a fragment", ErrAgentCommunicationRelayAudienceInvalid)
	}
	if u.User != nil {
		return "", fmt.Errorf("%w: must not contain userinfo", ErrAgentCommunicationRelayAudienceInvalid)
	}
	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = strings.ToLower(u.Host)
	return u.String(), nil
}

// ValidateAgentCommunicationProofKeyThumbprint accepts a non-empty
// base64url (unpadded) JWK thumbprint (RFC 7638) of bounded length. The
// binding to an actual key is a later slice's concern (DPoP, AYGHU-3).
func ValidateAgentCommunicationProofKeyThumbprint(s string) error {
	if s == "" {
		return fmt.Errorf("%w: empty", ErrAgentCommunicationProofKeyThumbprintInvalid)
	}
	if len(s) > 128 {
		return fmt.Errorf("%w: longer than 128 bytes", ErrAgentCommunicationProofKeyThumbprintInvalid)
	}
	for _, r := range s {
		switch {
		case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_':
		default:
			return fmt.Errorf("%w: not base64url", ErrAgentCommunicationProofKeyThumbprintInvalid)
		}
	}
	return nil
}

// CheckAgentCommunicationSameOwner is the v1 same-owner rule: every
// participant service account MUST carry an owner and that owner MUST be
// the creating owner. An ownerless participant is refused; a participant
// owned by anyone else is refused (cross-owner authorization is deferred,
// not built).
func CheckAgentCommunicationSameOwner(owner uuid.UUID, participants ...*ServiceAccount) error {
	if owner == uuid.Nil {
		return fmt.Errorf("%w: owner", ErrAgentCommunicationIdentifierRequired)
	}
	for _, sa := range participants {
		if sa == nil {
			return fmt.Errorf("%w: participant service account", ErrAgentCommunicationIdentifierRequired)
		}
		if sa.OwnerUserID == nil || *sa.OwnerUserID == uuid.Nil {
			return fmt.Errorf("%w: %s", ErrAgentCommunicationOwnerlessParticipant, sa.ID)
		}
		if *sa.OwnerUserID != owner {
			return fmt.Errorf("%w: %s", ErrAgentCommunicationOwnerMismatch, sa.ID)
		}
	}
	return nil
}

// CheckAgentCommunicationParticipantClient verifies that client is the
// installation of sa: bound to it by ServiceAccountID, in the same
// organization, confidential, and authenticating with private_key_jwt
// backed by registered key material (inline jwks or jwks_uri).
func CheckAgentCommunicationParticipantClient(sa *ServiceAccount, client *Client) error {
	if sa == nil || client == nil {
		return fmt.Errorf("%w: participant client", ErrAgentCommunicationIdentifierRequired)
	}
	if client.ServiceAccountID == nil || *client.ServiceAccountID != sa.ID {
		return fmt.Errorf("%w: %s", ErrAgentCommunicationClientNotBound, client.ClientID)
	}
	if client.OrganizationID == nil || *client.OrganizationID != sa.OrganizationID {
		return fmt.Errorf("%w: %s", ErrAgentCommunicationClientNotBound, client.ClientID)
	}
	if client.IsPublic || client.EffectiveAuthMethod() != "private_key_jwt" {
		return fmt.Errorf("%w: %s", ErrAgentCommunicationClientAuthNotAsymmetric, client.ClientID)
	}
	if strings.TrimSpace(client.JWKS) == "" && strings.TrimSpace(client.JWKSUri) == "" {
		return fmt.Errorf("%w: %s has no registered keys", ErrAgentCommunicationClientAuthNotAsymmetric, client.ClientID)
	}
	return nil
}

func requireV7(what string, id uuid.UUID) error {
	if id == uuid.Nil {
		return fmt.Errorf("%w: %s", ErrAgentCommunicationIdentifierRequired, what)
	}
	if id.Version() != 7 {
		return fmt.Errorf("%w: %s", ErrAgentCommunicationIdentifierNotV7, what)
	}
	return nil
}

// Validate checks every structural invariant of a fully built aggregate
// at `now` (creation time): identifier shape, the closed role and
// capability sets in canonical form, exactly two distinct participants,
// normalized audience, positive limits, future expiry, supported policy
// version and a PolicyDigest that matches the canonical policy. It does
// not consult the store — ownership and client binding are checked by the
// service with the loaded rows (CheckAgentCommunicationSameOwner,
// CheckAgentCommunicationParticipantClient).
func (a *AgentCommunicationAuthorization) Validate(now time.Time) error {
	if a == nil {
		return fmt.Errorf("%w: authorization", ErrAgentCommunicationIdentifierRequired)
	}
	if err := requireV7("authorization id", a.ID); err != nil {
		return err
	}
	if err := requireV7("session id", a.SessionID); err != nil {
		return err
	}
	if a.OrganizationID == uuid.Nil {
		return fmt.Errorf("%w: organization", ErrAgentCommunicationIdentifierRequired)
	}
	if a.OwnerID == uuid.Nil {
		return fmt.Errorf("%w: owner", ErrAgentCommunicationIdentifierRequired)
	}
	normalized, err := NormalizeAgentCommunicationRelayAudience(a.RelayAudience)
	if err != nil {
		return err
	}
	if normalized != a.RelayAudience {
		return fmt.Errorf("%w: not normalized", ErrAgentCommunicationRelayAudienceInvalid)
	}
	if a.MaxMessages <= 0 || a.MaxMessageSizeBytes <= 0 {
		return ErrAgentCommunicationLimitNotPositive
	}
	if !a.ExpiresAt.After(now) {
		return ErrAgentCommunicationExpiryNotFuture
	}
	if a.PolicyVersion != AgentCommunicationPolicyVersion {
		return fmt.Errorf("%w: %q", ErrAgentCommunicationPolicyVersionUnsupported, a.PolicyVersion)
	}
	if len(a.Participants) != 2 {
		return fmt.Errorf("%w: got %d", ErrAgentCommunicationParticipantCount, len(a.Participants))
	}
	if a.RevokedAt != nil {
		// A freshly built aggregate is never revoked; the reason bound is
		// checked here for completeness of loaded rows too.
		if a.RevocationReason != nil && len(*a.RevocationReason) > AgentCommunicationRevocationReasonMaxLen {
			return ErrAgentCommunicationRevocationReasonTooLong
		}
	}
	acis := make(map[uuid.UUID]struct{}, 2)
	sas := make(map[uuid.UUID]struct{}, 2)
	clients := make(map[uuid.UUID]struct{}, 2)
	roles := make(map[AgentCommunicationParticipantRole]struct{}, 2)
	ids := make(map[uuid.UUID]struct{}, 2)
	for i := range a.Participants {
		p := &a.Participants[i]
		if err := requireV7("participant id", p.ID); err != nil {
			return err
		}
		if err := requireV7("participant aci", p.ACI); err != nil {
			return err
		}
		if p.AuthorizationID != a.ID {
			return fmt.Errorf("%w: participant authorization id", ErrAgentCommunicationIdentifierRequired)
		}
		if p.ServiceAccountID == uuid.Nil {
			return fmt.Errorf("%w: participant service account", ErrAgentCommunicationIdentifierRequired)
		}
		if p.OAuthClientID == uuid.Nil {
			return fmt.Errorf("%w: participant client", ErrAgentCommunicationIdentifierRequired)
		}
		if !p.Role.Valid() {
			return fmt.Errorf("%w: %q", ErrAgentCommunicationInvalidRole, p.Role)
		}
		if err := ValidateAgentCommunicationProofKeyThumbprint(p.ProofKeyThumbprint); err != nil {
			return err
		}
		canonical, err := CanonicalizeAgentCommunicationCapabilities(p.Capabilities)
		if err != nil {
			return err
		}
		if len(canonical) != len(p.Capabilities) {
			return ErrAgentCommunicationCapabilitiesNotCanonical
		}
		for j := range canonical {
			if canonical[j] != p.Capabilities[j] {
				return ErrAgentCommunicationCapabilitiesNotCanonical
			}
		}
		if _, dup := ids[p.ID]; dup {
			return fmt.Errorf("%w: participant id", ErrAgentCommunicationDuplicateACI)
		}
		ids[p.ID] = struct{}{}
		if _, dup := acis[p.ACI]; dup {
			return ErrAgentCommunicationDuplicateACI
		}
		acis[p.ACI] = struct{}{}
		if _, dup := sas[p.ServiceAccountID]; dup {
			return ErrAgentCommunicationDuplicateServiceAccount
		}
		sas[p.ServiceAccountID] = struct{}{}
		if _, dup := clients[p.OAuthClientID]; dup {
			return ErrAgentCommunicationDuplicateClient
		}
		clients[p.OAuthClientID] = struct{}{}
		if _, dup := roles[p.Role]; dup {
			return ErrAgentCommunicationDuplicateRole
		}
		roles[p.Role] = struct{}{}
	}
	digest, err := a.ComputePolicyDigest()
	if err != nil {
		return err
	}
	if digest != a.PolicyDigest {
		return ErrAgentCommunicationPolicyDigestMismatch
	}
	return nil
}
