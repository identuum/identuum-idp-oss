package service

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/identuum/identuum-idp-oss/auth"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/jwtpolicy"
	"github.com/identuum/identuum-idp-oss/internal/lifecycle"
	"github.com/identuum/identuum-idp-oss/internal/repository"
	"github.com/identuum/identuum-idp-oss/internal/utils/safehttp"
	"github.com/identuum/identuum-idp-oss/internal/utils/uuidgen"
)

// OIDCCallbackService completes the RP callback for OSS basic single-provider
// upstream OIDC login (docs/design/oss-basic-oidc-login.md). It consumes the
// one-time OIDCState, exchanges the code for tokens at the discovered token
// endpoint, STRICTLY validates the upstream ID token (Slice 5), applies the
// claim mapping + email_domains allow-list gate and JIT-provisions/matches the
// local user (Slice 6), then MINTS a local session and returns the material the
// handler needs to set the session cookie and redirect to the stored, already-
// sanitized ReturnURL (Slice 7). It manages the ONE provider named by the state
// — never a list (multi-IdP is CE).
//
// The session mint REUSES UserSessionService.CreateUserSession — the SAME path
// password/browser login uses (same refresh-family / max-session / hash
// semantics; no parallel session store). The session ACR rung is derived from
// the upstream `acr` claim by auth.MapUpstreamACRToLadder.
//
// ID-token validation reuses the auth.VerifyBearerToken policy (golang-jwt v5,
// alg allowlist, reject alg=none + alg-confusion, kid → key, iss/aud/exp/nbf)
// but sources keys from the PROVIDER JWKS via the shared discovery/JWKS path
// (OIDCDiscoveryService.ResolveSigningKey → ClientJWKSFetcherService). Because
// upstream providers (Google, Microsoft/Entra) sign with RS256, the upstream
// allowlist is {RS256, ES256, EdDSA} (asymmetric only) — none/HS* are rejected
// by WithValidMethods + the keyFunc. All outbound HTTP is via
// safehttp.NewSafeClient (SSRF-guarded). No secret/token/code is ever logged.
type OIDCCallbackService struct {
	providers repository.IdentityProviderRepository
	discovery *OIDCDiscoveryService
	states    repository.OIDCStateRepository
	cipher    SecretCipher
	users     repository.UserRepository
	sessions  *UserSessionService
	orgs      OrgLiveLookup

	httpClient        *http.Client
	responseBodyLimit int64
	now               func() time.Time
}

// OIDCCallbackServiceDeps are the required collaborators.
type OIDCCallbackServiceDeps struct {
	Providers repository.IdentityProviderRepository
	Discovery *OIDCDiscoveryService
	States    repository.OIDCStateRepository
	Cipher    SecretCipher
	Users     repository.UserRepository
	// Organizations gates the callback on tenant liveness (P0-4): the
	// callback refuses to JIT-create OR match a user, and mints no session,
	// when the provider's organization is not operational (IsOperational).
	Organizations OrgLiveLookup
	// Sessions mints the local session on a completed login — the SAME
	// UserSessionService password/browser login uses (no parallel path).
	Sessions *UserSessionService
}

// OIDCCallbackResult is the completed-login material the handler needs to set
// the session cookie and redirect. It mirrors the browser-login tail
// (LocalLoginService.LoginResult → CookieSessionService.Issue): the handler
// sets ONE cookie from RefreshToken (or swaps it for a browser-session token)
// with the session's ExpiresAt, then redirects to the STORED, already-sanitized
// ReturnURL (empty ⇒ the handler defaults to a safe landing).
type OIDCCallbackResult struct {
	User         *domain.User
	Session      *domain.Session
	RefreshToken string
	ReturnURL    string
}

// OIDCCallbackServiceOptions parameterises the token-exchange transport.
type OIDCCallbackServiceOptions struct {
	// HTTPClient is used for the token-endpoint POST. nil ⇒
	// safehttp.NewSafeClient with the configured timeout.
	HTTPClient *http.Client
	// Timeout bounds the token exchange. Defaults to 5 s.
	Timeout time.Duration
	// ResponseBodyLimit caps the token response. Defaults to 64 KiB.
	ResponseBodyLimit int64
}

const (
	defaultCallbackTimeout           = 5 * time.Second
	defaultCallbackResponseBodyLimit = int64(64 * 1024)
)

// upstreamAllowedAlgs is the ID-token signature allowlist for UPSTREAM
// providers. Unlike the OSS issuer policy (EdDSA/ES256 only), it includes
// RS256 because Google + Microsoft/Entra sign ID tokens with RS256. It is
// asymmetric-only; none and HS* are excluded (blocked by WithValidMethods and
// the keyFunc) to defeat alg-confusion.
var upstreamAllowedAlgs = []string{"RS256", "ES256", "EdDSA"}

// ErrCallbackStateInvalid is returned when the state is missing, expired,
// already consumed, or bound to a different provider — or when the state's
// provider is gone/non-oidc/inactive. A handler maps it to 400.
var ErrCallbackStateInvalid = errors.New("service: OIDC callback state invalid")

// ErrCallbackDiscoveryFailed is returned when the provider discovery fetch
// fails during callback. A handler maps it to a 502-class error.
var ErrCallbackDiscoveryFailed = errors.New("service: OIDC callback discovery failed")

// ErrCallbackExchangeFailed is returned when the code→token exchange fails
// (transport, non-2xx, malformed, missing id_token, or secret decrypt). A
// handler maps it to a 502-class error. No token/secret/code is attached.
var ErrCallbackExchangeFailed = errors.New("service: OIDC callback token exchange failed")

// ErrCallbackValidationFailed is returned when the ID token fails strict
// validation (signature / alg / iss / aud / exp / nbf / nonce). A handler maps
// it to 401. The failure reason is never leaked.
var ErrCallbackValidationFailed = errors.New("service: OIDC callback ID token validation failed")

// ErrCallbackForbidden is returned when the validated identity is refused
// provisioning: an unverified email, an email whose domain is not in the org's
// allow-list (and AllowExternalDomains is off), or an email that belongs to a
// local account already bound to a DIFFERENT external identity (no takeover).
// A handler maps it to 403. No user is created.
var ErrCallbackForbidden = errors.New("service: OIDC callback identity not permitted")

// ErrCallbackProvisionFailed is returned when the local-user lookup or JIT
// create fails. A handler maps it to 500. No session is minted.
var ErrCallbackProvisionFailed = errors.New("service: OIDC callback provisioning failed")

// ErrCallbackSessionFailed is returned when the local session mint fails after
// the user was resolved. A handler maps it to 500 and sets NO cookie and does
// NOT redirect. No token/secret is attached.
var ErrCallbackSessionFailed = errors.New("service: OIDC callback session mint failed")

// NewOIDCCallbackService constructs the service. All collaborators are
// REQUIRED; a nil dependency records a fatal startup fault (P-018) rather than
// panicking.
func NewOIDCCallbackService(report *lifecycle.StartupReport, deps OIDCCallbackServiceDeps, opts OIDCCallbackServiceOptions) *OIDCCallbackService {
	if deps.Providers == nil {
		report.Fatal("NewOIDCCallbackService", "service: NewOIDCCallbackService requires a non-nil IdentityProviderRepository")
	}
	if deps.Discovery == nil {
		report.Fatal("NewOIDCCallbackService", "service: NewOIDCCallbackService requires a non-nil OIDCDiscoveryService")
	}
	if deps.States == nil {
		report.Fatal("NewOIDCCallbackService", "service: NewOIDCCallbackService requires a non-nil OIDCStateRepository")
	}
	if deps.Cipher == nil {
		report.Fatal("NewOIDCCallbackService", "service: NewOIDCCallbackService requires a non-nil SecretCipher")
	}
	if deps.Users == nil {
		report.Fatal("NewOIDCCallbackService", "service: NewOIDCCallbackService requires a non-nil UserRepository")
	}
	if deps.Organizations == nil {
		report.Fatal("NewOIDCCallbackService", "service: NewOIDCCallbackService requires a non-nil organization lookup")
	}
	if deps.Sessions == nil {
		report.Fatal("NewOIDCCallbackService", "service: NewOIDCCallbackService requires a non-nil UserSessionService")
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = defaultCallbackTimeout
	}
	hc := opts.HTTPClient
	if hc == nil {
		hc = safehttp.NewSafeClient()
		hc.Timeout = timeout
	}
	bodyLimit := opts.ResponseBodyLimit
	if bodyLimit <= 0 {
		bodyLimit = defaultCallbackResponseBodyLimit
	}
	return &OIDCCallbackService{
		providers:         deps.Providers,
		discovery:         deps.Discovery,
		states:            deps.States,
		cipher:            deps.Cipher,
		users:             deps.Users,
		sessions:          deps.Sessions,
		orgs:              deps.Organizations,
		httpClient:        hc,
		responseBodyLimit: bodyLimit,
		now:               time.Now,
	}
}

// HandleCallback runs the full callback flow and COMPLETES login: consume
// state, exchange code, strictly validate the ID token, apply the claim mapping
// + email_domains allow-list gate, match-or-JIT-provision the local user, then
// MINT a local session (stamping the ACR rung derived from the upstream acr).
// It returns the material the handler needs to set the session cookie and
// redirect to the STORED, already-sanitized ReturnURL. ip/ua are recorded on
// the session (same as password/browser login); both may be empty.
func (s *OIDCCallbackService) HandleCallback(ctx context.Context, providerID uuid.UUID, state, code, ipAddress, userAgent string) (*OIDCCallbackResult, error) {
	if state == "" || code == "" {
		return nil, ErrCallbackStateInvalid
	}

	// 1. Consume the state atomically ONCE: ConsumeByState is a single
	// DELETE … RETURNING — the row is returned only to the caller whose
	// DELETE removed it. A concurrent caller or a replay gets a nil row (or
	// a DB error); either way we reject with no session and no token
	// exchange. No separate lock/delete, no ignorable error.
	st, err := s.states.ConsumeByState(ctx, state)
	if err != nil || st == nil {
		return nil, ErrCallbackStateInvalid
	}
	// Expiry + provider-match still enforced on the consumed row.
	if s.now().After(st.ExpiresAt) || st.ProviderID != providerID {
		return nil, ErrCallbackStateInvalid
	}

	// 2. Resolve the provider named by the state + its discovery metadata.
	provider, err := s.providers.GetByID(ctx, st.ProviderID)
	if err != nil || provider == nil || provider.Type != domain.IDPTypeOIDC || !provider.Active {
		return nil, ErrCallbackStateInvalid
	}
	// P0-4: tenant deletion is an authentication boundary. Refuse to
	// JIT-create OR match a user — and mint no session — when the
	// provider's organization is not operational (deleted or deactivated).
	// The provider lookup already enforces this in SQL; this explicit gate
	// is defense in depth, independent of provider-lookup caching. Same
	// predicate as the token-exchange fix (IsOperational).
	if org, orgErr := s.orgs.GetByID(ctx, provider.OrganizationID); orgErr != nil || org == nil || !org.IsOperational() {
		return nil, ErrCallbackStateInvalid
	}
	doc, err := s.discovery.Discover(ctx, provider.Config.IssuerURL)
	if err != nil {
		return nil, ErrCallbackDiscoveryFailed
	}

	// 3. Decrypt the PKCE verifier + the client_secret (in memory only).
	verifier, err := s.cipher.Decrypt(st.PKCEVerifierEncrypted)
	if err != nil {
		return nil, ErrCallbackExchangeFailed
	}
	clientSecret := ""
	if provider.Config.ClientSecretEncrypted != "" {
		clientSecret, err = s.cipher.Decrypt(provider.Config.ClientSecretEncrypted)
		if err != nil {
			return nil, ErrCallbackExchangeFailed
		}
	}

	// 4. Exchange code → tokens at the discovered token endpoint.
	idToken, err := s.exchangeCode(ctx, doc.TokenEndpoint, provider.Config.ClientID, clientSecret, st.RedirectURI, code, verifier)
	if err != nil {
		return nil, ErrCallbackExchangeFailed
	}

	// 5. STRICTLY validate the ID token against the PROVIDER JWKS.
	claims, err := s.validateIDToken(ctx, doc, idToken, provider.Config.ClientID, st.Nonce)
	if err != nil {
		return nil, ErrCallbackValidationFailed
	}

	// 6. Map the validated claims to an ExternalUser (the email is a VALIDATED,
	// signature-covered claim), apply the org's claim mapping, then run the
	// email_domains gate + JIT to resolve the LOCAL user.
	eu, err := externalUserFromClaims(claims, provider.OrganizationID)
	if err != nil {
		return nil, err
	}
	applyClaimMapping(eu, claims, provider.Config.ClaimMapping)
	user, err := s.resolveLocalUser(ctx, provider, eu)
	if err != nil {
		return nil, err
	}

	// 7. MINT the local session (REUSE UserSessionService — the SAME path
	// password/browser login uses; no parallel session store), stamping the
	// ACR rung derived from the upstream acr claim. Return the material the
	// handler needs for the cookie + redirect; the redirect target is the
	// STORED, already-sanitized ReturnURL (never re-derived from the provider).
	issued, err := s.mintSession(ctx, user, eu.UpstreamACR, ipAddress, userAgent)
	if err != nil {
		return nil, ErrCallbackSessionFailed
	}
	return &OIDCCallbackResult{
		User:         user,
		Session:      issued.Session,
		RefreshToken: issued.RefreshToken,
		ReturnURL:    st.ReturnURL,
	}, nil
}

// mintSession issues a local session for the resolved user via the shared
// UserSessionService — the SAME issuance path password/browser login uses (same
// refresh-family / max-session / hash semantics; no parallel session store).
// The session ACR rung is derived from the upstream acr claim by
// auth.MapUpstreamACRToLadder (its first production caller); an empty upstream
// acr maps to the ladder's assumed default. The per-org max-sessions cap +
// admin exemption are enforced inside CreateUserSession.
func (s *OIDCCallbackService) mintSession(ctx context.Context, user *domain.User, upstreamACR, ip, ua string) (*IssuedUserSession, error) {
	// THE-ACR-AMR-TRUTH: an ASSUMED rung is not a performed one, and this
	// call site used to throw the distinction away (`rung, _ :=`). When the
	// upstream IdP sends no acr at all, MapUpstreamACRToLadder answers
	// (ACRMFA, assumedDefault=true) — a floor for the mapper's own callers,
	// not a measurement. Stamping it on the session made the id_token say
	// `acr: urn:identuum:loa:mfa` to a relying party that reads acr to decide
	// whether to trust the session, on the evidence of silence.
	//
	// So an assumed rung stamps NO acr. IDTokenService.Issue omits the claim
	// entirely when the session carries none, which is the honest statement:
	// this user authenticated upstream and we do not know how. It also fails
	// CLOSED — acrLadder[""] is 0, so ACRMeetsFloor refuses every non-empty
	// floor, and an RP that requires a rung gets step-up or
	// unmet_authentication_requirements instead of a false assurance.
	//
	// The mapper is unchanged; its assumed default still serves callers that
	// want a floor. What changes is that this one stops laundering it.
	rung, assumed := auth.MapUpstreamACRToLadder(upstreamACR)
	if assumed {
		rung = ""
	}
	var ipPtr, uaPtr *string
	if ip != "" {
		ipPtr = &ip
	}
	if ua != "" {
		uaPtr = &ua
	}
	maxSessions := 0
	if user.OrgMaxSessionsPerUser != nil {
		maxSessions = *user.OrgMaxSessionsPerUser
	}
	return s.sessions.CreateUserSession(ctx, CreateUserSessionInput{
		UserID:             user.ID,
		IPAddress:          ipPtr,
		UserAgent:          uaPtr,
		Acr:                rung,
		MaxSessionsPerUser: maxSessions,
		OrganizationID:     user.OrganizationID,
		Role:               string(user.Role),
	})
}

// resolveLocalUser enforces the email_domains allow-list gate on the VALIDATED
// email (post-validation, BEFORE any user creation), then resolves the local
// user: match by stable ExternalID FIRST (the no-email-takeover rule), else by
// verified email within the org (linking the external identity), else
// JIT-create a passwordless federated user. Reuses the existing UserRepository
// — no parallel user store.
func (s *OIDCCallbackService) resolveLocalUser(ctx context.Context, provider *domain.IdentityProvider, eu *domain.ExternalUser) (*domain.User, error) {
	// Gate: the provider must have asserted a verified email whose domain is
	// allow-listed (unless AllowExternalDomains). Unverified or off-list ⇒ no
	// provisioning. This is the JIT-abuse gate.
	if !eu.EmailVerified || strings.TrimSpace(eu.Email) == "" {
		return nil, ErrCallbackForbidden
	}
	if !emailDomainAllowed(eu.Email, provider.Config.EmailDomains, provider.Config.AllowExternalDomains) {
		return nil, ErrCallbackForbidden
	}
	orgID := provider.OrganizationID

	// 1. ExternalID FIRST — a returning user is bound to their stable
	// issuer|sub, so a provider-side email change cannot hijack another
	// account.
	if u, err := s.users.GetByExternalID(ctx, orgID, eu.ExternalID); err == nil && u != nil {
		return u, nil
	} else if err != nil && !errors.Is(err, domain.ErrUserNotFound) {
		return nil, ErrCallbackProvisionFailed
	}

	// 2. Verified-email match within the org. Never hijack a local account
	// already bound to a DIFFERENT external identity. Otherwise link this
	// identity so the next login matches by ExternalID.
	if u, err := s.users.GetByEmailAndOrgID(ctx, orgID, eu.Email); err == nil && u != nil {
		if u.ExternalID != nil && *u.ExternalID != "" && *u.ExternalID != eu.ExternalID {
			return nil, ErrCallbackForbidden
		}
		extID := eu.ExternalID
		iss := eu.Issuer
		linked := true
		src := domain.AuthSourceIDJag
		updated, uerr := s.users.Update(ctx, u.ID, orgID, repository.UpdateUserOptions{
			ExternalID: &extID,
			OIDCIssuer: &iss,
			OIDCLinked: &linked,
			AuthSource: &src,
		})
		if uerr != nil {
			return nil, ErrCallbackProvisionFailed
		}
		return updated, nil
	} else if err != nil && !errors.Is(err, domain.ErrUserNotFound) {
		return nil, ErrCallbackProvisionFailed
	}

	// 3. JIT-create a passwordless federated user, stamping ExternalID/Issuer.
	id, err := uuidgen.NewV7()
	if err != nil {
		return nil, ErrCallbackProvisionFailed
	}
	extID := eu.ExternalID
	iss := eu.Issuer
	newUser := &domain.User{
		ID:             id,
		OrganizationID: orgID,
		Email:          eu.Email,
		PasswordHash:   domain.NoPasswordSentinel, // no local password — federated
		Role:           domain.RoleOrgUser,
		AuthSource:     domain.AuthSourceIDJag,
		EmailVerified:  true, // provider-verified (gate enforced above)
		ExternalID:     &extID,
		OIDCIssuer:     &iss,
		OIDCLinked:     true,
	}
	if eu.Name != "" {
		n := eu.Name
		newUser.Name = &n
	}
	created, err := s.users.Create(ctx, newUser)
	if err != nil {
		return nil, ErrCallbackProvisionFailed
	}
	return created, nil
}

// emailDomainAllowed reports whether email's domain is permitted: allow-listed
// (case-insensitive) or AllowExternalDomains. Fail-closed: an empty allow-list
// with AllowExternalDomains off permits nothing.
func emailDomainAllowed(email string, allowed []string, allowExternal bool) bool {
	if allowExternal {
		return true
	}
	at := strings.LastIndex(email, "@")
	if at < 0 || at == len(email)-1 {
		return false
	}
	dom := strings.ToLower(strings.TrimSpace(email[at+1:]))
	for _, d := range allowed {
		if strings.ToLower(strings.TrimSpace(d)) == dom {
			return true
		}
	}
	return false
}

// applyClaimMapping lets an org remap which VALIDATED ID-token claim supplies
// email/name (e.g. {"email":"mail"}). Every source is a claim from the already
// signature-validated ID token, so the value stays trusted. AttributeMapping
// is an LDAP-directory concept and is not consulted on the OIDC path.
//
// P1-3: EmailVerified is bound to the EXACT identifier used for linking. The
// standard email_verified claim attests the STANDARD email claim; when the org
// remaps email to a DIFFERENT claim, that attestation does NOT transfer. So on
// a successful email remap we re-derive verification from the mapped
// identifier's OWN verification source (mapping["email_verified"], if the org
// configured one) and otherwise mark the remapped email UNVERIFIED — the JIT
// gate (resolveLocalUser) then refuses it. This prevents a user-controlled
// mapped claim being treated as verified on the strength of an unrelated
// standard email.
func applyClaimMapping(eu *domain.ExternalUser, claims jwt.MapClaims, mapping map[string]string) {
	if len(mapping) == 0 {
		return
	}
	if src := strings.TrimSpace(mapping["email"]); src != "" {
		if v, _ := claims[src].(string); strings.TrimSpace(v) != "" {
			eu.Email = v
			// The remapped email is a different identifier than the standard
			// email claim; its verification must come from its own source.
			if vsrc := strings.TrimSpace(mapping["email_verified"]); vsrc != "" {
				eu.EmailVerified = claimBool(claims[vsrc])
			} else {
				eu.EmailVerified = false
			}
		}
	}
	if src := strings.TrimSpace(mapping["name"]); src != "" {
		if v, _ := claims[src].(string); strings.TrimSpace(v) != "" {
			eu.Name = v
		}
	}
}

// exchangeCode POSTs the authorization_code grant to the token endpoint over
// the SSRF-guarded client and returns the id_token. client_secret_post auth.
func (s *OIDCCallbackService) exchangeCode(ctx context.Context, tokenEndpoint, clientID, clientSecret, redirectURI, code, verifier string) (string, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", redirectURI)
	form.Set("client_id", clientID)
	if clientSecret != "" {
		form.Set("client_secret", clientSecret)
	}
	form.Set("code_verifier", verifier)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", ErrCallbackExchangeFailed
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return "", ErrCallbackExchangeFailed
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", ErrCallbackExchangeFailed
	}
	limited := http.MaxBytesReader(nil, resp.Body, s.responseBodyLimit)
	body, readErr := io.ReadAll(limited)
	if readErr != nil {
		return "", ErrCallbackExchangeFailed
	}
	var tr struct {
		IDToken string `json:"id_token"`
	}
	if err := json.Unmarshal(body, &tr); err != nil || tr.IDToken == "" {
		return "", ErrCallbackExchangeFailed
	}
	return tr.IDToken, nil
}

// validateIDToken strictly validates the ID token (signature via the provider
// JWKS by kid; alg allowlist rejecting none/HS*/alg-confusion; iss == provider
// issuer; aud contains client_id; exp/nbf via the parser; nonce == stored).
func (s *OIDCCallbackService) validateIDToken(ctx context.Context, doc *OIDCDiscoveryDocument, rawIDToken, expectedAudience, expectedNonce string) (jwt.MapClaims, error) {
	// Shared parse policy (parser options + alg=none/empty + non-allowlisted-alg
	// + kid rejection), parameterized with the UPSTREAM asymmetric-only allowlist
	// {RS256, ES256, EdDSA} and provider-JWKS key resolution. The remaining
	// iss/aud/nonce checks are upstream-specific and stay here.
	claims, err := jwtpolicy.Parse(
		rawIDToken,
		upstreamAllowedAlgs,
		upstreamAlgAllowed,
		func(kid, _ string) (any, error) {
			// Provider JWKS by kid — the shared discovery/JWKS path (HTTPS-only,
			// SSRF-guarded, size-capped, negative-cached). Returning the specific
			// key type binds alg↔key so alg-confusion (e.g. ES256 header on an RSA
			// kid) fails at signature verification.
			return s.discovery.ResolveSigningKey(ctx, doc, kid)
		},
		// P1-1: the UPSTREAM token is third-party and attacker-influenceable, so
		// REQUIRE exp (else it never expires) and a non-empty sub (else it has no
		// subject — and would collapse to a colliding "issuer|" identity below).
		jwtpolicy.Required{Expiration: true, Subject: true},
	)
	if err != nil {
		return nil, ErrCallbackValidationFailed
	}
	if iss, _ := claims["iss"].(string); iss != doc.Issuer {
		return nil, ErrCallbackValidationFailed
	}
	if !audienceContainsValue(claims["aud"], expectedAudience) {
		return nil, ErrCallbackValidationFailed
	}
	if n, _ := claims["nonce"].(string); n != expectedNonce {
		return nil, ErrCallbackValidationFailed
	}
	return claims, nil
}

// upstreamAlgAllowed bans none/HS*/RS-PS-not-listed and allows the asymmetric
// upstream set.
func upstreamAlgAllowed(alg string) bool {
	switch alg {
	case "none", "", "HS256", "HS384", "HS512":
		return false
	}
	for _, a := range upstreamAllowedAlgs {
		if a == alg {
			return true
		}
	}
	return false
}

// audienceContainsValue reports whether the aud claim (string or array)
// contains want.
func audienceContainsValue(audClaim any, want string) bool {
	switch v := audClaim.(type) {
	case string:
		return v == want
	case []any:
		for _, e := range v {
			if s, ok := e.(string); ok && s == want {
				return true
			}
		}
	case []string:
		for _, s := range v {
			if s == want {
				return true
			}
		}
	}
	return false
}

// externalUserFromClaims projects validated ID-token claims onto the domain
// ExternalUser. ExternalID is the stable issuer|sub. No secret is involved.
//
// P1-2: an empty (or whitespace-only) sub is REFUSED rather than folded into a
// colliding "issuer|" ExternalID onto which every subject-less login from a
// malformed provider would collapse. This is defense-in-depth behind the
// parser's Subject requirement (validateIDToken) — the parser rejects an
// absent/empty sub, and this guard additionally rejects a whitespace-only sub
// and protects the identity construction if the parser policy ever loosens.
func externalUserFromClaims(claims jwt.MapClaims, orgID uuid.UUID) (*domain.ExternalUser, error) {
	iss, _ := claims["iss"].(string)
	sub, _ := claims["sub"].(string)
	if strings.TrimSpace(sub) == "" {
		return nil, ErrCallbackValidationFailed
	}
	email, _ := claims["email"].(string)
	name, _ := claims["name"].(string)
	acr, _ := claims["acr"].(string)
	return &domain.ExternalUser{
		Email:          email,
		Name:           name,
		ExternalID:     iss + "|" + sub,
		Issuer:         iss,
		OrganizationID: orgID,
		EmailVerified:  claimBool(claims["email_verified"]),
		UpstreamACR:    acr,
	}, nil
}

// claimBool coerces an email_verified claim that may arrive as a JSON bool or
// as the string "true"/"false".
func claimBool(v any) bool {
	switch b := v.(type) {
	case bool:
		return b
	case string:
		return strings.EqualFold(b, "true")
	default:
		return false
	}
}
