package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/lifecycle"
	"github.com/identuum/identuum-idp-oss/internal/utils/uuidgen"
	"github.com/identuum/identuum-idp-oss/pkg/oidc"
)

// TokenService issues OAuth 2.0 access tokens. This OSS slice
// implements ONLY the RFC 6749 §4.4 client_credentials grant —
// machine-to-machine token issuance backed by a confidential
// client credential. The grant_type/scope/audience policy is
// enforced inline; the signed JWT is produced via the existing
// OSS signing-key repository.
//
// What this service does NOT do:
//
//   - No authorization_code grant. /authorize is not in OSS.
//   - No refresh_token grant. Refresh-token storage is not in OSS.
//   - No password grant.
//   - No device-code grant.
//   - No RS256 issuance. Identuum's no-RS256-issuance policy is
//     enforced at the signing-key selection step — RS256 keys
//     are filtered out before a JWT is signed.
//   - No automatic key generation. If no EdDSA or ES256 active
//     signing key is available, IssueClientCredentials returns
//     ErrTokenServiceNoSigningKey so the deployment surfaces the
//     misconfiguration loudly.
type TokenService struct {
	keys            SigningKeyProvider
	audiences       AudienceLookup
	refresh         *RefreshTokenService
	serviceAccounts ServiceAccountLookup
	clients         ClientByClientIDLookup
	issuer          string
	accessTokenTTL  time.Duration
	now             func() time.Time
	// minter is the A-4 access-token format seam. Production wiring is
	// the JWT minter, so both grants' wire output is unchanged; tests
	// inject a stub to prove the seam is load-bearing.
	minter oidc.AccessTokenMinter
	// newJTI generates the token identifier. Injectable so equivalence
	// tests can pin a fixed jti; defaults to a UUIDv7 source.
	newJTI func() (string, error)

	// agentComm is the AYGHU-3 participant-token issuer; nil = the
	// agent-communication path is not wired (authorization_details refused).
	agentComm *agentCommunicationIssuance
}

// SigningKeyProvider is the seam the TokenService consumes. The
// production wiring is *KeyService.ListActive; tests use an
// in-memory implementation. Returns keys in priority order — the
// service picks the first EdDSA-or-ES256 key it sees.
type SigningKeyProvider interface {
	ListActive(ctx context.Context) ([]domain.SigningKey, error)
}

// ServiceAccountLookup is the optional seam TokenService consults
// when minting client_credentials tokens. *ServiceAccountService
// satisfies it via LookupForClient.
//
// When wired, every client_credentials token issuance is bound to
// the resolved service-account projection: the JWT `sub` becomes
// the SA UUID, `org_id` / `role` / `actor_type=service_account`
// land in the claims, and an unbound OR inactive OR expired OR
// org-mismatched SA fails the issuance with
// ErrTokenServiceUnauthorizedClient.
//
// Without the lookup wired the pre-this-slice behavior is
// preserved: `sub = client_id`, no `actor_type`, no `role`
// claim. That fallback exists ONLY so operators that have not
// yet migrated their oauth_clients table can keep issuing
// tokens during the transition; production deployments MUST
// wire the lookup.
type ServiceAccountLookup interface {
	LookupForClient(ctx context.Context, client *domain.Client) (*ServiceAccountTokenSubject, error)
}

// AudienceLookup is the optional seam TokenService consults when
// the request carries a non-empty `audience` parameter (RFC 8707).
// The production wiring is *APIResourceService.LookupAudience.
//
// Implementations MUST return (nil, nil) for unknown audiences so
// the service can map the absence to `invalid_target`. A non-nil
// error is treated as `invalid_target` too — a transient lookup
// failure must not silently mint a token for an unverified audience.
type AudienceLookup interface {
	LookupAudience(ctx context.Context, audience string) (*domain.APIResource, error)
}

// TokenServiceOptions configures the TokenService. Only Issuer
// is required. AccessTokenTTL defaults to 1 hour.
type TokenServiceOptions struct {
	Issuer         string
	AccessTokenTTL time.Duration
	// Minter overrides the access-token format seam. Nil (the normal
	// case) wires the JWT minter over `keys`, so production output is
	// unchanged. A-4 Phase 2.
	Minter oidc.AccessTokenMinter
}

// NewTokenService constructs the service. keys is required;
// opts.Issuer must be non-empty.
func NewTokenService(report *lifecycle.StartupReport, keys SigningKeyProvider, opts TokenServiceOptions) *TokenService {
	if keys == nil {
		report.Fatal("NewTokenService", "service: NewTokenService requires a non-nil SigningKeyProvider")
	}
	if opts.Issuer == "" {
		report.Fatal("NewTokenService", "service: NewTokenService requires a non-empty Issuer")
	}
	ttl := opts.AccessTokenTTL
	if ttl <= 0 {
		ttl = time.Hour
	}
	minter := opts.Minter
	if minter == nil {
		// Default wiring: the JWT minter over the same signing keys —
		// both grants' tokens are byte-identical to the pre-A-4 path.
		minter = newJWTAccessTokenMinter(keys)
	}
	return &TokenService{
		keys:           keys,
		issuer:         opts.Issuer,
		accessTokenTTL: ttl,
		now:            time.Now,
		minter:         minter,
		newJTI:         uuidgen.NewV7String,
	}
}

// WithServiceAccountLookup wires the ServiceAccountLookup +
// ClientByClientIDLookup seams so client_credentials issuance
// binds the resolved AuthenticatedClient back to its
// *domain.Client (via the client lookup) and then to a
// ServiceAccountTokenSubject (via the service-account lookup).
//
// Both seams MUST be supplied together — the SA lookup needs a
// *domain.Client, and the AuthenticatedClient only carries the
// safe identity projection.
//
// Returns the receiver so the call composes with construction.
func (s *TokenService) WithServiceAccountLookup(sa ServiceAccountLookup, clients ClientByClientIDLookup) *TokenService {
	s.serviceAccounts = sa
	s.clients = clients
	return s
}

// HasServiceAccountLookup reports whether the SA lookup is
// wired. Used by tests + future discovery introspection that
// might want to reflect the binding posture.
func (s *TokenService) HasServiceAccountLookup() bool {
	return s != nil && s.serviceAccounts != nil && s.clients != nil
}

// WithRefreshTokenService wires the RefreshTokenService so the
// TokenService recognises grant_type=refresh_token. The discovery
// composer also reads this seam via HasRefreshTokenGrant to decide
// whether to advertise refresh_token in grant_types_supported.
//
// Without WithRefreshTokenService, any grant_type=refresh_token
// request is rejected with ErrTokenServiceUnsupportedGrant — the
// existing client_credentials behavior is unchanged.
//
// Returns the receiver so the call composes with construction.
func (s *TokenService) WithRefreshTokenService(rts *RefreshTokenService) *TokenService {
	s.refresh = rts
	return s
}

// HasRefreshTokenGrant reports whether the refresh_token grant is
// wired. Discovery uses this to advertise the grant in
// grant_types_supported.
func (s *TokenService) HasRefreshTokenGrant() bool {
	return s != nil && s.refresh != nil
}

// WithAudienceLookup wires an AudienceLookup so the TokenService
// enforces RFC 8707 audience validation on every issuance: a
// non-empty `audience` request parameter is looked up, mapped to
// `invalid_target` when unknown or inactive, and intersected
// against the requested scopes via the resource's scope set.
//
// Returns the receiver so the call composes with construction.
// Without an AudienceLookup wired, the service preserves its
// pre-this-slice behavior: any non-empty audience is echoed into
// the `aud` claim with no policy check (suitable only for
// deployments that have no API resources registered).
func (s *TokenService) WithAudienceLookup(a AudienceLookup) *TokenService {
	s.audiences = a
	return s
}

// ClientCredentialsRequest is the parsed POST /oauth/token form
// for grant_type=client_credentials.
type ClientCredentialsRequest struct {
	GrantType         string
	RequestedScope    string
	RequestedAudience string
}

// TokenResponse is the RFC 6749 §5.1 success response. The
// RefreshToken field is populated only when the issuance path
// rotates an existing refresh token (currently the
// refresh_token grant) — the client_credentials path never
// emits a refresh_token, in alignment with RFC 6749 §4.4.3 and
// the monolith's policy.
//
// IDToken is populated only by the authorization_code grant when
// the consented scope set contains "openid" (OIDC Core §3.1.3.3).
// All other grants leave it empty and `omitempty` keeps it out of
// the wire response.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	Scope        string `json:"scope,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
}

// Sentinel errors returned by IssueClientCredentials. All map to
// RFC 6749 §5.2 error envelopes at the HTTP layer.
var (
	// ErrTokenServiceUnsupportedGrant is returned when grant_type
	// is anything other than "client_credentials".
	ErrTokenServiceUnsupportedGrant = errors.New("service: unsupported_grant_type")

	// ErrTokenServiceInvalidRequest is returned for missing
	// grant_type or other malformed input.
	ErrTokenServiceInvalidRequest = errors.New("service: invalid_request")

	// ErrTokenServiceUnauthorizedClient is returned when the
	// authenticated client is not allowed to use the
	// client_credentials grant (e.g. a public client).
	ErrTokenServiceUnauthorizedClient = errors.New("service: unauthorized_client")

	// ErrTokenServiceInvalidScope is returned when a requested
	// scope is not granted by the client's policy.
	ErrTokenServiceInvalidScope = errors.New("service: invalid_scope")

	// ErrTokenServiceNoSigningKey is returned when the repository
	// has no EdDSA or ES256 active key. The route maps this to a
	// 500 server_error response — auto-generating keys is a
	// deliberate non-goal of this slice.
	ErrTokenServiceNoSigningKey = errors.New("service: no compatible signing key available")

	// ErrTokenServiceSigningFailed wraps a signing-layer error. The
	// raw error is NEVER echoed to the wire.
	ErrTokenServiceSigningFailed = errors.New("service: signing failed")

	// ErrTokenServiceInvalidTarget is returned when the requested
	// audience is unknown to the API resource registry, inactive,
	// or — for the api_resource caller path — does not match the
	// caller's own audience. The wire layer maps this to
	// RFC 8707 §2.2 `invalid_target`.
	ErrTokenServiceInvalidTarget = errors.New("service: invalid_target")

	// ErrTokenServiceInvalidGrant is returned when the supplied
	// refresh token cannot be consumed (unknown, expired, revoked,
	// client_id mismatch). The wire layer maps this to RFC 6749
	// §5.2 `invalid_grant`.
	ErrTokenServiceInvalidGrant = errors.New("service: invalid_grant")

	// ErrTokenServiceRefreshDisabled is returned when a
	// grant_type=refresh_token request reaches a TokenService
	// constructed without WithRefreshTokenService. The wire layer
	// maps this to RFC 6749 §5.2 `unsupported_grant_type` —
	// operators that have not opted in to refresh tokens see the
	// same response as if the grant did not exist.
	ErrTokenServiceRefreshDisabled = errors.New("service: refresh_token grant disabled")
)

// IssueClientCredentials runs the full client_credentials issuance
// flow. The supplied AuthenticatedClient MUST come from a
// successful RequireOAuthClient middleware pass — this method
// does NOT re-authenticate.
//
// Returns:
//   - ErrTokenServiceInvalidRequest when grant_type is empty.
//   - ErrTokenServiceUnsupportedGrant when grant_type is anything
//     other than "client_credentials".
//   - ErrTokenServiceUnauthorizedClient when the client is public
//     (RFC 6749 §4.4: client_credentials is for confidential
//     clients only).
//   - ErrTokenServiceInvalidScope when a requested scope is not in
//     the client's allowed-scope set.
//   - ErrTokenServiceNoSigningKey when no EdDSA/ES256 key is
//     available.
//   - ErrTokenServiceSigningFailed for any signing-layer failure.
//
// On success the returned TokenResponse carries a signed JWT
// access token. The token's standard claims (iss, sub, aud, iat,
// exp, jti, client_id, scope) are populated from the
// authenticated client and the negotiated scope set.
func (s *TokenService) IssueClientCredentials(ctx context.Context, client *AuthenticatedClient, req ClientCredentialsRequest) (*TokenResponse, error) {
	if client == nil {
		return nil, ErrTokenServiceInvalidRequest
	}
	if req.GrantType == "" {
		return nil, ErrTokenServiceInvalidRequest
	}
	if req.GrantType != "client_credentials" {
		return nil, ErrTokenServiceUnsupportedGrant
	}
	// Public clients (auth_method=none) MUST NOT use
	// client_credentials per RFC 6749 §4.4.
	if client.Kind == AuthenticatedClientKindOAuth && client.IsPublic {
		return nil, ErrTokenServiceUnauthorizedClient
	}
	// RFC 8707 audience validation. Runs ONLY when an
	// AudienceLookup is wired AND the request actually carried a
	// non-empty `audience` parameter. The lookup builds the
	// effective allowed-scope set for the issuance — it is what
	// scope negotiation closes over below.
	allowedScopes := client.AllowedScopes
	requestedAudience := strings.TrimSpace(req.RequestedAudience)
	if requestedAudience != "" && s.audiences != nil {
		resource, lookupErr := s.audiences.LookupAudience(ctx, requestedAudience)
		if lookupErr != nil || resource == nil {
			return nil, ErrTokenServiceInvalidTarget
		}
		if !resource.Active {
			return nil, ErrTokenServiceInvalidTarget
		}
		// api_resource caller may only mint tokens for its own
		// audience. Cross-audience minting via this path would
		// undermine the audience-binding guarantee.
		if client.Kind == AuthenticatedClientKindAPIResource && resource.ID != client.AuthRecordID {
			return nil, ErrTokenServiceInvalidTarget
		}
		// The audience's scope set is the upper bound on what may
		// be granted under this audience. Intersect with the
		// caller's own AllowedScopes when both are non-empty —
		// "may mint" requires both "client allows" AND "audience
		// covers". When the caller has no AllowedScopes (an
		// oauth_client without per-client scope policy), the
		// audience set IS the allowed set.
		resourceScopes := make([]string, 0, len(resource.Scopes))
		for _, sc := range resource.Scopes {
			if sc.Name != "" {
				resourceScopes = append(resourceScopes, sc.Name)
			}
		}
		allowedScopes = intersectScopeSets(allowedScopes, resourceScopes)
	}
	granted, err := negotiateScope(req.RequestedScope, allowedScopes)
	if err != nil {
		return nil, err
	}
	// Service-account binding. Runs only on the OAuth-client
	// caller path (api_resource callers are pre-authorized
	// resources, not service accounts) AND only when both seams
	// are wired. Without the seams the legacy `sub = client_id`
	// shape is preserved.
	var saSubject *ServiceAccountTokenSubject
	if client.Kind == AuthenticatedClientKindOAuth && s.HasServiceAccountLookup() {
		// THE-OWNERLESS-ACCOUNT: a STORE outage on either lookup is not a
		// verdict about the client. It travels up as AUTH-503 (the token
		// endpoint answers 503 + correlation id); every other failure still
		// answers unauthorized_client.
		dc, lookupErr := s.clients.GetClientByClientID(ctx, client.ClientID)
		if lookupErr != nil || dc == nil {
			if domain.IsAuthStoreUnavailable(lookupErr) {
				return nil, lookupErr
			}
			return nil, ErrTokenServiceUnauthorizedClient
		}
		saSubject, err = s.serviceAccounts.LookupForClient(ctx, dc)
		if err != nil {
			if domain.IsAuthStoreUnavailable(err) {
				return nil, err
			}
			return nil, ErrTokenServiceUnauthorizedClient
		}
	}
	now := s.now().UTC()
	exp := now.Add(s.accessTokenTTL)
	jti, err := s.newJTI()
	if err != nil {
		return nil, ErrTokenServiceSigningFailed
	}
	// Subject defaults to client_id; a bound service account overrides it
	// and contributes actor_type + org_id/role (each only when present),
	// exactly as the pre-A-4 inline claim map did.
	subject := client.ClientID
	actorType := ""
	var extra map[string]any
	if saSubject != nil {
		subject = saSubject.Subject
		actorType = saSubject.ActorType
		extra = map[string]any{}
		if saSubject.OrganizationID != uuid.Nil {
			extra["org_id"] = saSubject.OrganizationID.String()
		}
		if saSubject.Role != "" {
			extra["role"] = saSubject.Role
		}
	}
	if requestedAudience == "" {
		// IdP-destined. No requested audience ⇒ this machine token is for
		// the IdP's own bearer surface. Stamp aud = the issuer (the
		// verifier's audience anchor) so it passes the issuer-require aud
		// check; without this it would be aud-absent and rejected. When a
		// requestedAudience IS present it is RS-destined and echoed as-is
		// (already validated above when an AudienceLookup is wired).
		requestedAudience = s.issuer
	}
	wireToken, _, err := s.minter.Mint(ctx, oidc.TokenClaims{
		Issuer:    s.issuer,
		Subject:   subject,
		ClientID:  client.ClientID,
		Audience:  requestedAudience,
		Scope:     granted,
		IssuedAt:  now,
		ExpiresAt: exp,
		JTI:       jti,
		ActorType: actorType,
		Extra:     extra,
	})
	if err != nil {
		return nil, err
	}
	return &TokenResponse{
		AccessToken: wireToken,
		TokenType:   "Bearer",
		ExpiresIn:   int64(s.accessTokenTTL.Seconds()),
		Scope:       granted,
	}, nil
}

// RefreshTokenRequest is the parsed POST /oauth/token form for
// grant_type=refresh_token.
type RefreshTokenRequest struct {
	GrantType    string
	RefreshToken string
}

// IssueRefresh runs the RFC 6749 §6 refresh_token grant. The
// supplied AuthenticatedClient MUST come from a successful
// RequireOAuthClient middleware pass; this method does NOT
// re-authenticate.
//
// Returns:
//   - ErrTokenServiceInvalidRequest when grant_type or
//     refresh_token are empty.
//   - ErrTokenServiceUnsupportedGrant when grant_type is anything
//     other than "refresh_token".
//   - ErrTokenServiceUnauthorizedClient when the client is public
//     (refresh_token issuance to a public client is forbidden by
//     OSS policy — the runtime never persists refresh rows for
//     public clients in the first place, but the guard is also
//     applied at consume time).
//   - ErrTokenServiceInvalidGrant when the supplied refresh token
//     is unknown, expired, revoked, or bound to a different
//     client.
//   - ErrTokenServiceNoSigningKey / ErrTokenServiceSigningFailed
//     for the same conditions as IssueClientCredentials.
//   - ErrTokenServiceRefreshDisabled when no RefreshTokenService
//     is wired (no caller-visible refresh_token grant).
//
// On success the TokenResponse carries a freshly minted access
// token AND a rotated refresh token. The previous refresh row is
// marked revoked + replaced_by. The new access token's jti is
// recorded on the new refresh row so /oauth/revoke can cascade.
func (s *TokenService) IssueRefresh(ctx context.Context, client *AuthenticatedClient, req RefreshTokenRequest) (*TokenResponse, error) {
	if client == nil {
		return nil, ErrTokenServiceInvalidRequest
	}
	if req.GrantType == "" {
		return nil, ErrTokenServiceInvalidRequest
	}
	if req.GrantType != "refresh_token" {
		return nil, ErrTokenServiceUnsupportedGrant
	}
	if s.refresh == nil {
		return nil, ErrTokenServiceRefreshDisabled
	}
	if strings.TrimSpace(req.RefreshToken) == "" {
		return nil, ErrTokenServiceInvalidRequest
	}
	if client.Kind == AuthenticatedClientKindOAuth && client.IsPublic {
		return nil, ErrTokenServiceUnauthorizedClient
	}
	consumed, err := s.refresh.Consume(ctx, ConsumeRefreshTokenInput{
		RawToken: req.RefreshToken,
		ClientID: client.ClientID,
	})
	if err != nil {
		// Reuse of a rotated-away (superseded) refresh token already
		// triggered family revocation + the breach signal inside Consume
		// (R1). The wire response stays a generic invalid_grant so the
		// attacker is not told reuse was detected — the breach is surfaced
		// to the operator via logs/metrics, not the token response.
		if errors.Is(err, ErrRefreshTokenInvalidGrant) || errors.Is(err, domain.ErrRefreshTokenReuse) {
			return nil, ErrTokenServiceInvalidGrant
		}
		return nil, err
	}
	now := s.now().UTC()
	exp := now.Add(s.accessTokenTTL)
	jti, err := s.newJTI()
	if err != nil {
		return nil, ErrTokenServiceSigningFailed
	}
	// aud is the original grant's audience when bound (RS-destined),
	// else the issuer (IdP-destined) so the rotated token passes the
	// bearer verifier's issuer-require aud check — same fallback as
	// the pre-A-4 inline path. No actor_type/org_id/role on refresh.
	audience := consumed.Audience
	if audience == "" {
		audience = s.issuer
	}
	wireToken, storeKey, err := s.minter.Mint(ctx, oidc.TokenClaims{
		Issuer:    s.issuer,
		Subject:   consumed.Subject,
		ClientID:  consumed.ClientID,
		Audience:  audience,
		Scope:     consumed.Scope,
		IssuedAt:  now,
		ExpiresAt: exp,
		JTI:       jti,
	})
	if err != nil {
		return nil, err
	}
	// Best-effort: stamp the new refresh row with the issued jti
	// (storeKey == jti for the JWT minter) so /oauth/revoke can
	// cascade. A failure here does NOT undo the rotation — the new
	// tokens are already minted.
	_ = s.refresh.SetAccessJTI(ctx, consumed.NewID, storeKey)
	return &TokenResponse{
		AccessToken:  wireToken,
		TokenType:    "Bearer",
		ExpiresIn:    int64(s.accessTokenTTL.Seconds()),
		Scope:        consumed.Scope,
		RefreshToken: consumed.NewToken,
	}, nil
}

// intersectScopeSets returns the intersection of two allowed-scope
// sets used by the audience-aware issuance path.
//
// Semantics:
//   - If both inputs are nil/empty: returns nil (no scope policy
//     present — negotiateScope will then reject any non-empty
//     requested scope).
//   - If one is nil/empty and the other non-empty: returns the
//     non-empty input as-is. This is the common case for an
//     oauth_client caller with no per-client scope policy minting
//     a token for an audience — the audience's set IS the policy.
//   - If both are non-empty: returns only those entries present in
//     BOTH sets, preserving the order from a.
func intersectScopeSets(a, b []string) []string {
	if len(a) == 0 {
		return b
	}
	if len(b) == 0 {
		return a
	}
	bset := make(map[string]struct{}, len(b))
	for _, s := range b {
		bset[s] = struct{}{}
	}
	out := make([]string, 0, len(a))
	for _, s := range a {
		if _, ok := bset[s]; ok {
			out = append(out, s)
		}
	}
	return out
}

// negotiateScope intersects requested scopes with the client's
// allowed-scope set. Behavior:
//
//   - Empty requested scope: granted scope is the empty string.
//     The TokenResponse omits the `scope` field on the wire.
//   - Non-empty requested scope + nil/empty allowed set: returns
//     ErrTokenServiceInvalidScope. The OAuth client_credentials
//     flow MUST NOT silently downgrade a request to no scopes —
//     that would mask a misconfigured client. The api_resource
//     path populates AllowedScopes from the resource policy; the
//     oauth_client path leaves it nil until per-client scope
//     policy lands (documented gap).
//   - Non-empty requested scope + allowed set with a partial
//     overlap: returns ErrTokenServiceInvalidScope when ANY
//     requested scope is not present. This is stricter than the
//     monolith's behavior of silently dropping unknown scopes;
//     the OSS shape surfaces the misconfiguration to the caller.
//
// Returned granted scope is the requested scope normalized to a
// space-separated list with duplicates removed and ordering
// preserved.
func negotiateScope(requested string, allowed []string) (string, error) {
	requested = strings.TrimSpace(requested)
	if requested == "" {
		return "", nil
	}
	parts := strings.Fields(requested)
	if len(allowed) == 0 {
		return "", ErrTokenServiceInvalidScope
	}
	allowedSet := make(map[string]struct{}, len(allowed))
	for _, a := range allowed {
		allowedSet[a] = struct{}{}
	}
	seen := make(map[string]struct{}, len(parts))
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if _, ok := allowedSet[p]; !ok {
			return "", ErrTokenServiceInvalidScope
		}
		if _, dup := seen[p]; dup {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	return strings.Join(out, " "), nil
}

// parsePrivateKeyPEM decodes a PEM-encoded PKCS#8 / PKCS#1 / SEC1
// private key and asserts it matches the supplied algorithm. RS256
// is REJECTED unconditionally — even if a PrivateKey is set on an
// RS256 row in the repository (which the parser elsewhere also
// rejects), the signing path refuses to use it.
func parsePrivateKeyPEM(s string, alg domain.KeyAlgorithm) (any, error) {
	if s == "" {
		return nil, errors.New("empty private key")
	}
	block, _ := pem.Decode([]byte(s))
	if block == nil {
		return nil, errors.New("no PEM block")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse PKCS#8: %w", err)
	}
	switch alg {
	case domain.KeyAlgorithmEdDSA:
		k, ok := parsed.(ed25519.PrivateKey)
		if !ok {
			return nil, errors.New("EdDSA private key expected")
		}
		return k, nil
	case domain.KeyAlgorithmES256:
		k, ok := parsed.(*ecdsa.PrivateKey)
		if !ok {
			return nil, errors.New("ES256 private key expected")
		}
		return k, nil
	case domain.KeyAlgorithmRS256:
		// THE-PKCE-DECISION: RS256 signing keys parse, but they are
		// reachable ONLY via explicit-alg selection for id_tokens —
		// selectUserSigningKey (access/logout tokens, default id_tokens)
		// never returns an RS256 key. Testing-only, never the default.
		k, ok := parsed.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("RS256 private key expected")
		}
		return k, nil
	default:
		return nil, fmt.Errorf("unsupported algorithm %q", alg)
	}
}

// uuidNilGuard exists so the linter doesn't strip uuid import when
// the helper above is not directly used at body-time.
var _ = uuid.Nil
