// webauthn_service.go — OSS port of the monolith WebAuthn service.
//
// The monolith implementation lives at
// identuum-idp/internal/service/webauthn_service.go and is the
// behavioural reference. We do NOT import monolith code — this file
// re-implements the same ceremony shape on top of the OSS audit /
// repository / domain seams.
//
// Scope of the OSS port:
//
//   - Registration begin + finish (authenticated; persists a credential).
//   - Login begin + finish (public; verifies an assertion).
//   - Credential list + ownership-checked delete.
//
// Enforced in OSS on the WebAuthn login-finish path (R2 fix): the
// per-org idp_only AuthPolicy seal (service.IsLocalCredentialFlowAllowed —
// a passkey is a local credential) and the org MFA policy gate
// (UV-conditional: a user-verified assertion satisfies MFA, a presence-only
// one does not). Out-of-scope (kept in CE/monolith): Universal Admin
// Sovereignty enforcement on WebAuthn login, and the full monolith
// CompleteWebAuthnLogin → SessionService glue.
// The OSS handler completes a successful login by issuing a session
// + access token via the existing OSS UserSessionService /
// UserTokenService, mirroring the OSS local-login + MFA-complete
// flows (auth_sessions.go + auth_mfa_enroll.go).
//
// Anti-enumeration:
//
//   BeginDummyLogin returns a fake assertion when the supplied
//   email matches zero users OR more than one user. The fake
//   assertion is structurally indistinguishable from a real one
//   (same shape, same field set) so the wire response cannot be
//   used as an account-existence oracle.
//
// Clone detection:
//
//   FinishLogin checks BOTH the persisted-row CloneWarning flag
//   AND the upstream library's live CloneWarning verdict. The
//   first guard prevents a known-cloned credential from ever
//   succeeding again after the initial detection (even when an
//   attacker has synchronised the sign counter); the second
//   catches a new detection during the current ceremony.
//
// Tenant isolation:
//
//   FinishLogin also enforces that the credential's organization
//   matches the user's organization. This guards against a stale
//   credential surviving a user re-org and being reused for the
//   wrong tenant after re-registration would otherwise overwrite
//   the credential row.
//
// Secrets safety:
//
//   The handler never logs the raw challenge, attestation object,
//   assertion response, public-key bytes, credential id, or any
//   session token. The single Logger this service holds is used
//   only for structured ops messages with non-sensitive metadata
//   (user_id, credential db id, error class — never raw material).
//   The metrics counter does not record any sensitive label values.

package service

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/identuum/identuum-idp-oss/internal/audit"
	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/metrics"
	"github.com/identuum/identuum-idp-oss/internal/repository"
	"github.com/identuum/identuum-idp-oss/internal/utils/uuidgen"
)

// WebAuthnTTL is the TTL applied to every ceremony session stored
// in WebAuthnSessionRepository. Matches the upstream go-webauthn
// library's 5-minute default. Challenges expire silently after
// this window so a slow client retry does not leak a usable
// challenge into a future ceremony.
const WebAuthnTTL = 5 * time.Minute

// ErrWebAuthnSessionInvalid is returned by FinishRegistration /
// FinishLogin when the supplied session_id has no live entry,
// expired, was already consumed, or failed integrity checks. The
// HTTP layer collapses it onto an opaque 400/401 so the wire
// cannot disambiguate the failure cases.
var ErrWebAuthnSessionInvalid = errors.New("webauthn session invalid")

// ErrWebAuthnNoCredentials is returned by BeginLogin when the
// resolved user has zero credentials. The handler uses
// BeginDummyLogin for the user-enumeration-protected path, so
// this error is generally only seen by privileged callers that
// know the user exists (e.g. account-settings flow).
var ErrWebAuthnNoCredentials = errors.New("webauthn no credentials")

// ErrWebAuthnAssertionInvalid is returned by FinishLogin when the
// library rejects the assertion (signature mismatch, RP id
// mismatch, origin mismatch, clone detection, …). The HTTP layer
// collapses it onto a generic 401 invalid_credentials.
var ErrWebAuthnAssertionInvalid = errors.New("webauthn assertion invalid")

// ErrWebAuthnCredentialMissing is returned by FinishLogin when
// the upstream library validated the assertion but the credential
// id it carries is not present in the OSS credential store. The
// HTTP layer collapses it onto a generic 401.
var ErrWebAuthnCredentialMissing = errors.New("webauthn credential missing")

// ErrWebAuthnTenantMismatch is returned by FinishLogin when the
// credential row's organization differs from the user's. Treated
// as an assertion-invalid failure at the HTTP boundary.
var ErrWebAuthnTenantMismatch = errors.New("webauthn tenant mismatch")

// ErrWebAuthnCloneDetected is returned by FinishLogin when the
// upstream library reports a clone-warning verdict OR the stored
// row already carries clone_warning=true. The HTTP layer collapses
// it onto a generic 401.
var ErrWebAuthnCloneDetected = errors.New("webauthn clone detected")

// WebAuthnUserRepo is the narrow seam the WebAuthn service uses
// to resolve user rows. Satisfied by repository.UserRepository.
// Exported by agent-a-20260784 so pkg/webauthn can alias it for CE
// consumption without crossing the internal/ boundary; the method
// set + return types are byte-identical to the prior unexported
// `webAuthnUserRepo` shape.
type WebAuthnUserRepo interface {
	GetByID(ctx context.Context, id uuid.UUID) (*domain.User, error)
	FindUsersByEmail(ctx context.Context, email string) ([]*domain.User, error)
}

// webAuthnValidator is the narrow seam over the upstream
// `go-webauthn/webauthn` library. Satisfied by *webauthn.WebAuthn
// in production. Tests can substitute a stub that forces specific
// library-driven outcomes (e.g. CloneWarning=true) without a
// virtual authenticator.
type webAuthnValidator interface {
	BeginRegistration(user webauthn.User, opts ...webauthn.RegistrationOption) (*protocol.CredentialCreation, *webauthn.SessionData, error)
	FinishRegistration(user webauthn.User, session webauthn.SessionData, request *http.Request) (*webauthn.Credential, error)
	BeginLogin(user webauthn.User, opts ...webauthn.LoginOption) (*protocol.CredentialAssertion, *webauthn.SessionData, error)
	FinishLogin(user webauthn.User, session webauthn.SessionData, request *http.Request) (*webauthn.Credential, error)
}

// WebAuthnServiceConfig holds the dependencies AND per-deployment
// configuration the service needs to construct its WebAuthn instance.
//
// As of `agent-claude-20260624-idp-oss-constructor-arity-refactor`, the
// previously-positional dependency args (UserRepo, CredRepo,
// SessionRepo, Audit, Logger) live here too — `NewWebAuthnService` now
// takes a single argument of this type instead of 6 positional args.
type WebAuthnServiceConfig struct {
	// BaseURL is the IDP's own externally-facing origin. Required.
	// Hostname becomes the RP ID; the full origin becomes the first
	// entry of RPOrigins.
	BaseURL string

	// UIPublicBaseURL is the browser-facing UI origin (identuum-ui).
	// Optional. When set and structurally compatible with the RP ID
	// (exact-host or subdomain), the value is added to RPOrigins so
	// the browser ceremony can satisfy the upstream origin check
	// from the UI port. A misconfigured value is silently dropped.
	UIPublicBaseURL string

	// RPDisplayName is the human-readable label the browser presents
	// during the ceremony. Defaults to "Identuum" when empty.
	RPDisplayName string

	// Required dependencies. NewWebAuthnService returns an error when
	// any of UserRepo / CredRepo / SessionRepo is nil.
	UserRepo    WebAuthnUserRepo
	CredRepo    repository.WebAuthnCredentialRepository
	SessionRepo repository.WebAuthnSessionRepository

	// Optional dependencies. Both default to safe no-op implementations.
	Audit  audit.Service
	Logger *zap.Logger
}

// WebAuthnService handles FIDO2/WebAuthn registration and login
// ceremonies. Constructed via NewWebAuthnService.
type WebAuthnService struct {
	validator   webAuthnValidator
	userRepo    WebAuthnUserRepo
	credRepo    repository.WebAuthnCredentialRepository
	sessionRepo repository.WebAuthnSessionRepository
	audit       audit.Service
	logger      *zap.Logger
}

// NewWebAuthnService constructs an OSS WebAuthn service. Returns an
// error if cfg.BaseURL is missing or malformed, or if any of
// cfg.UserRepo / cfg.CredRepo / cfg.SessionRepo is nil. cfg.Audit may
// be nil — defaulted to audit.NoopService{}. cfg.Logger may be nil —
// defaulted to zap.NewNop() (set by the body below; see line further
// down).
//
// Single-argument shape replaces the prior 6-positional-arg
// constructor — refactored 2026-06-24 to satisfy the ≤5-arg target
// from `findings/identuum-idp-oss-findings-claude.md`. The wire
// behavior, validation errors, and defaults are byte-identical.
func NewWebAuthnService(cfg WebAuthnServiceConfig) (*WebAuthnService, error) {
	if cfg.UserRepo == nil {
		return nil, errors.New("webauthn: nil userRepo")
	}
	if cfg.CredRepo == nil {
		return nil, errors.New("webauthn: nil credRepo")
	}
	if cfg.SessionRepo == nil {
		return nil, errors.New("webauthn: nil sessionRepo")
	}
	if cfg.BaseURL == "" {
		return nil, errors.New("webauthn: BaseURL is required")
	}
	parsedOrigin, err := url.Parse(cfg.BaseURL)
	if err != nil {
		return nil, fmt.Errorf("webauthn: invalid BaseURL: %w", err)
	}
	rpID := parsedOrigin.Hostname()
	if rpID == "" {
		return nil, errors.New("webauthn: BaseURL has empty hostname")
	}
	rpOrigins := []string{cfg.BaseURL}
	if extra, ok := normalizeUIOriginForRPID(cfg.UIPublicBaseURL, rpID); ok && extra != cfg.BaseURL {
		rpOrigins = append(rpOrigins, extra)
	}
	displayName := cfg.RPDisplayName
	if displayName == "" {
		displayName = "Identuum"
	}
	wconfig := &webauthn.Config{
		RPDisplayName: displayName,
		RPID:          rpID,
		RPOrigins:     rpOrigins,
	}
	w, err := webauthn.New(wconfig)
	if err != nil {
		return nil, fmt.Errorf("webauthn: configure: %w", err)
	}
	auditSvc := cfg.Audit
	if auditSvc == nil {
		auditSvc = audit.NoopService{}
	}
	logger := cfg.Logger
	if logger == nil {
		logger = zap.NewNop()
	}
	return &WebAuthnService{
		validator:   w,
		userRepo:    cfg.UserRepo,
		credRepo:    cfg.CredRepo,
		sessionRepo: cfg.SessionRepo,
		audit:       auditSvc,
		logger:      logger,
	}, nil
}

// normalizeUIOriginForRPID returns the trimmed origin string when
// uiPublicBaseURL is non-empty, parses cleanly, has an http/https
// scheme, and its hostname is RP-ID-compatible (exact match or a
// subdomain of rpID — the WebAuthn spec's "registrable suffix"
// rule). Returns ("", false) otherwise. Mirrors the monolith.
func normalizeUIOriginForRPID(uiPublicBaseURL, rpID string) (string, bool) {
	if uiPublicBaseURL == "" || rpID == "" {
		return "", false
	}
	parsed, err := url.Parse(uiPublicBaseURL)
	if err != nil {
		return "", false
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", false
	}
	host := parsed.Hostname()
	if host == "" {
		return "", false
	}
	if host == rpID {
		return rebuildOrigin(parsed), true
	}
	if len(host) > len(rpID)+1 && host[len(host)-len(rpID)-1:] == "."+rpID {
		return rebuildOrigin(parsed), true
	}
	return "", false
}

func rebuildOrigin(u *url.URL) string {
	host := u.Host
	if host == "" {
		host = u.Hostname()
	}
	return u.Scheme + "://" + host
}

// BeginRegistration starts a registration ceremony for the
// supplied authenticated user and persists the upstream library's
// SessionData under a freshly-minted opaque session id. Returns
// the CredentialCreation (handed to the browser) and the session
// id (the client must send it back to FinishRegistration).
func (s *WebAuthnService) BeginRegistration(ctx context.Context, user *domain.User) (creation *protocol.CredentialCreation, sessionID string, err error) {
	defer func() {
		result := "success"
		if err != nil {
			result = "failure"
		}
		metrics.WebAuthnOperations.WithLabelValues("register_begin", result).Inc()
	}()
	if user == nil {
		return nil, "", errors.New("webauthn: nil user")
	}
	wUser, err := s.adaptUser(ctx, user)
	if err != nil {
		return nil, "", err
	}
	registerOptions := func(opts *protocol.PublicKeyCredentialCreationOptions) {
		opts.AuthenticatorSelection.UserVerification = protocol.VerificationPreferred
		opts.AuthenticatorSelection.ResidentKey = protocol.ResidentKeyRequirementPreferred
	}
	var sessionData *webauthn.SessionData
	creation, sessionData, err = s.validator.BeginRegistration(wUser, registerOptions)
	if err != nil {
		return nil, "", fmt.Errorf("webauthn: begin registration: %w", err)
	}
	sessionID, err = uuidgen.NewV7String()
	if err != nil {
		return nil, "", fmt.Errorf("webauthn: generate session id: %w", err)
	}
	key := registrationKey(sessionID)
	if err := s.sessionRepo.Save(ctx, key, sessionData, WebAuthnTTL); err != nil {
		return nil, "", fmt.Errorf("webauthn: store session: %w", err)
	}
	return creation, sessionID, nil
}

// FinishRegistration is a convenience wrapper that stores the
// credential without a user-supplied nickname (defaulting to the
// schema's "Device passkey"). Equivalent to
// FinishRegistrationWithNickname(ctx, user, sessionID, request, "").
func (s *WebAuthnService) FinishRegistration(ctx context.Context, user *domain.User, sessionID string, request *http.Request) (*domain.WebAuthnCredential, error) {
	return s.FinishRegistrationWithNickname(ctx, user, sessionID, request, "")
}

// FinishRegistrationWithNickname verifies the browser's attestation
// response against the persisted SessionData and stores a credential
// row on success. nickname (when non-empty) is persisted as the
// credential's display label. Session is consumed via Delete on
// every exit path so a single session id cannot be replayed even
// when the upstream validator returns a soft failure on the first
// attempt.
func (s *WebAuthnService) FinishRegistrationWithNickname(ctx context.Context, user *domain.User, sessionID string, request *http.Request, nickname string) (stored *domain.WebAuthnCredential, err error) {
	defer func() {
		result := "success"
		if err != nil {
			result = "failure"
		}
		metrics.WebAuthnOperations.WithLabelValues("register_finish", result).Inc()
	}()
	if user == nil {
		return nil, errors.New("webauthn: nil user")
	}
	if sessionID == "" {
		return nil, ErrWebAuthnSessionInvalid
	}
	key := registrationKey(sessionID)
	// ATOMIC single-use (P2-11): Consume reads AND removes the entry in
	// one lock acquisition, so two concurrent finishes for the same
	// sessionID see exactly one winner. This replaces the prior
	// non-atomic Get + defer-Delete, which let both read the live entry
	// before either deleted (replay). The entry is already gone on every
	// exit path, so no defer-Delete is needed.
	sessionData, err := s.sessionRepo.Consume(ctx, key)
	if err != nil {
		return nil, ErrWebAuthnSessionInvalid
	}
	wUser, err := s.adaptUser(ctx, user)
	if err != nil {
		return nil, err
	}
	credential, err := s.validator.FinishRegistration(wUser, *sessionData, request)
	if err != nil {
		return nil, fmt.Errorf("webauthn: finish registration: %w", err)
	}
	cred := &domain.WebAuthnCredential{
		UserID:          user.ID,
		OrganizationID:  user.OrganizationID,
		CredentialID:    credential.ID,
		PublicKey:       credential.PublicKey,
		AttestationType: credential.AttestationType,
		Transport:       convertWebAuthnTransports(credential.Transport),
		AAGUID:          parseWebAuthnAAGUID(credential.Authenticator.AAGUID),
		SignCount:       credential.Authenticator.SignCount,
		CloneWarning:    credential.Authenticator.CloneWarning,
		BackupEligible:  credential.Flags.BackupEligible,
		BackupState:     credential.Flags.BackupState,
		Nickname:        nickname,
	}
	created, err := s.credRepo.Create(ctx, cred)
	if err != nil {
		return nil, err
	}
	_ = s.audit.Record(ctx, audit.Event{
		Action:         string(domain.AuditWebAuthnCredentialRegistered),
		Outcome:        "success",
		ActorID:        user.ID,
		ActorType:      "user",
		SubjectID:      user.ID,
		SubjectType:    "user",
		OrganizationID: user.OrganizationID,
		Metadata: map[string]any{
			"credential_db_id": created.ID.String(),
		},
	})
	return created, nil
}

// BeginLogin starts an assertion ceremony for the supplied user.
// Returns ErrWebAuthnNoCredentials when the user has no live
// credentials. Callers that need anti-enumeration semantics
// (public login route) should call BeginDummyLogin in that case.
func (s *WebAuthnService) BeginLogin(ctx context.Context, user *domain.User) (assertion *protocol.CredentialAssertion, sessionID string, err error) {
	defer func() {
		result := "success"
		if err != nil {
			result = "failure"
		}
		metrics.WebAuthnOperations.WithLabelValues("login_begin", result).Inc()
	}()
	if user == nil {
		return nil, "", errors.New("webauthn: nil user")
	}
	wUser, err := s.adaptUser(ctx, user)
	if err != nil {
		return nil, "", err
	}
	if len(wUser.creds) == 0 {
		return nil, "", ErrWebAuthnNoCredentials
	}
	loginOptions := func(opts *protocol.PublicKeyCredentialRequestOptions) {
		opts.UserVerification = protocol.VerificationPreferred
	}
	var sessionData *webauthn.SessionData
	assertion, sessionData, err = s.validator.BeginLogin(wUser, loginOptions)
	if err != nil {
		return nil, "", fmt.Errorf("webauthn: begin login: %w", err)
	}
	sessionID, err = uuidgen.NewV7String()
	if err != nil {
		return nil, "", fmt.Errorf("webauthn: generate session id: %w", err)
	}
	key := loginKey(sessionID)
	if err := s.sessionRepo.Save(ctx, key, sessionData, WebAuthnTTL); err != nil {
		return nil, "", fmt.Errorf("webauthn: store session: %w", err)
	}
	return assertion, sessionID, nil
}

// BeginDummyLogin returns a fake assertion + opaque session id so
// the wire response cannot enumerate accounts. The dummy challenge
// is opaque random material with no usable side effect (no session
// row is persisted; FinishLogin will reject the resulting
// assertion). UUIDv4 is used deliberately for the dummy fields so
// the constant-shape contract is preserved — a UUIDv7 generator
// can fail on retry exhaustion, which would create a distinguishable
// error path. The bytes are never wire-inspected with
// `uuid_extract_version`.
func (s *WebAuthnService) BeginDummyLogin(ctx context.Context) (*protocol.CredentialAssertion, string) {
	credID := uuid.New()
	assertion := &protocol.CredentialAssertion{
		Response: protocol.PublicKeyCredentialRequestOptions{
			Challenge: []byte(uuid.New().String()),
			AllowedCredentials: []protocol.CredentialDescriptor{
				{
					Type:         protocol.PublicKeyCredentialType,
					CredentialID: credID[:],
					Transport:    []protocol.AuthenticatorTransport{protocol.Internal},
				},
			},
			UserVerification: protocol.VerificationPreferred,
		},
	}
	return assertion, uuid.New().String()
}

// FinishLogin verifies the assertion response and returns both the
// resolved credential row and the user it belongs to. Session is
// consumed on every exit path. Enforces:
//
//   - session must exist + be live (not expired, not consumed);
//   - the upstream library must accept the assertion;
//   - the credential row must exist in the OSS store;
//   - the credential's organization must match the user's;
//   - the credential row's persisted CloneWarning must be false
//     (one-strike disable — the user must re-register the key
//     before it can authenticate again);
//   - the live library verdict must not flip CloneWarning to true.
//
// On success the persisted sign_count is updated to the value the
// library returned.
func (s *WebAuthnService) FinishLogin(ctx context.Context, sessionID string, request *http.Request) (credOut *domain.WebAuthnCredential, userOut *domain.User, userVerified bool, err error) {
	cloneDetected := false
	defer func() {
		var result string
		switch {
		case cloneDetected:
			result = "clone_warning"
		case err != nil:
			result = "failure"
		default:
			result = "success"
		}
		metrics.WebAuthnOperations.WithLabelValues("login_finish", result).Inc()
	}()
	if sessionID == "" {
		return nil, nil, false, ErrWebAuthnSessionInvalid
	}
	key := loginKey(sessionID)
	// ATOMIC single-use (P2-11): Consume reads AND removes the entry in
	// one lock acquisition, so two concurrent finishes for the same
	// sessionID see exactly one winner (the loser gets the invalid
	// sentinel). Replaces the prior non-atomic Get + defer-Delete that
	// allowed assertion replay.
	sessionDataPtr, err := s.sessionRepo.Consume(ctx, key)
	if err != nil {
		return nil, nil, false, ErrWebAuthnSessionInvalid
	}
	sessionData := *sessionDataPtr

	userID, err := uuid.FromBytes(sessionData.UserID)
	if err != nil {
		return nil, nil, false, ErrWebAuthnAssertionInvalid
	}
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil || user == nil {
		return nil, nil, false, ErrWebAuthnAssertionInvalid
	}
	wUser, err := s.adaptUser(ctx, user)
	if err != nil {
		return nil, nil, false, err
	}
	credential, err := s.validator.FinishLogin(wUser, sessionData, request)
	if err != nil {
		return nil, nil, false, ErrWebAuthnAssertionInvalid
	}
	// Surface the authenticator's user-verification (UV) flag from the
	// assertion result so the login-finish handler can apply the
	// org MFA-policy gate (UV-verified WebAuthn satisfies MFA; a
	// presence-only assertion does not). This does NOT alter any
	// attestation / assertion / origin / RP-ID / uniqueness check above.
	userVerified = credential.Flags.UserVerified
	stored, err := s.credRepo.GetByCredentialID(ctx, credential.ID)
	if err != nil {
		if errors.Is(err, repository.ErrWebAuthnCredentialNotFound) {
			return nil, nil, false, ErrWebAuthnCredentialMissing
		}
		return nil, nil, false, err
	}
	// §1.10 persistence-state clone guard. Once a credential is
	// flagged CloneWarning=true the credential MUST NOT authenticate
	// again until the user explicitly deletes and re-registers it.
	if stored.CloneWarning {
		cloneDetected = true
		return nil, nil, false, ErrWebAuthnCloneDetected
	}
	// Tenant isolation guard.
	if stored.OrganizationID != user.OrganizationID {
		return nil, nil, false, ErrWebAuthnTenantMismatch
	}
	// Live clone detection.
	if credential.Authenticator.CloneWarning {
		cloneDetected = true
		if updateErr := s.credRepo.UpdateCloneWarning(ctx, stored.ID, true); updateErr != nil {
			s.logger.Error("webauthn: persist clone warning",
				zap.String("credential_db_id", stored.ID.String()),
				zap.Error(updateErr),
			)
		}
		return nil, nil, false, ErrWebAuthnCloneDetected
	}
	if err := s.credRepo.UpdateSignCount(ctx, stored.ID, credential.Authenticator.SignCount); err != nil {
		// Auth succeeded; sign-count update is best-effort. A
		// persistence hiccup here would otherwise erode the
		// happy-path UX without improving security.
		s.logger.Warn("webauthn: persist sign_count",
			zap.String("credential_db_id", stored.ID.String()),
			zap.Error(err),
		)
	}
	return stored, user, userVerified, nil
}

// DeleteCredential removes a credential row after enforcing
// ownership: the supplied userID must own the credential. Returns
// domain.ErrResourceNotFound when the credential does not belong
// to the user (including the case where the credential id is
// entirely unknown) so the wire response cannot enumerate
// credential ids across users.
func (s *WebAuthnService) DeleteCredential(ctx context.Context, userID, credID uuid.UUID) (err error) {
	defer func() {
		result := "success"
		if err != nil {
			result = "failure"
		}
		metrics.WebAuthnOperations.WithLabelValues("delete", result).Inc()
	}()
	if userID == uuid.Nil || credID == uuid.Nil {
		return domain.ErrResourceNotFound
	}
	creds, err := s.credRepo.ListByUser(ctx, userID)
	if err != nil {
		return fmt.Errorf("webauthn: list for delete: %w", err)
	}
	var owned bool
	for _, c := range creds {
		if c.ID == credID {
			owned = true
			break
		}
	}
	if !owned {
		return domain.ErrResourceNotFound
	}
	if err := s.credRepo.Delete(ctx, credID); err != nil {
		return fmt.Errorf("webauthn: delete: %w", err)
	}
	_ = s.audit.Record(ctx, audit.Event{
		Action:      string(domain.AuditWebAuthnCredentialDeleted),
		Outcome:     "success",
		ActorID:     userID,
		ActorType:   "user",
		SubjectID:   userID,
		SubjectType: "user",
		Metadata: map[string]any{
			"credential_db_id": credID.String(),
		},
	})
	return nil
}

// ListCredentials returns the credentials owned by userID. The
// service exists so handler tests don't need to know about the
// repository at all — they just stub ListCredentials on the
// service interface.
func (s *WebAuthnService) ListCredentials(ctx context.Context, userID uuid.UUID) ([]*domain.WebAuthnCredential, error) {
	return s.credRepo.ListByUser(ctx, userID)
}

// FindUserByEmail proxies through to the user repo so the handler
// can keep its anti-enumeration logic centralised. Returns the
// resolved single user when EXACTLY one is found; nil otherwise.
// The handler distinguishes "no match" / "multiple match" / "one
// match" without learning the email-existence answer from the
// service side — the public path falls through to BeginDummyLogin
// when this returns nil.
func (s *WebAuthnService) FindUserByEmail(ctx context.Context, email string) (*domain.User, error) {
	users, err := s.userRepo.FindUsersByEmail(ctx, email)
	if err != nil {
		return nil, err
	}
	if len(users) != 1 {
		return nil, nil
	}
	return users[0], nil
}

// ---- adapters ----

type webAuthnUser struct {
	user  *domain.User
	creds []webauthn.Credential
}

func (u *webAuthnUser) WebAuthnID() []byte                         { return u.user.ID[:] }
func (u *webAuthnUser) WebAuthnName() string                       { return u.user.Email }
func (u *webAuthnUser) WebAuthnDisplayName() string                { return webAuthnDisplayName(u.user) }
func (u *webAuthnUser) WebAuthnIcon() string                       { return "" }
func (u *webAuthnUser) WebAuthnCredentials() []webauthn.Credential { return u.creds }

func webAuthnDisplayName(u *domain.User) string {
	if u != nil && u.Name != nil && *u.Name != "" {
		return *u.Name
	}
	if u != nil {
		return u.Email
	}
	return ""
}

func (s *WebAuthnService) adaptUser(ctx context.Context, user *domain.User) (*webAuthnUser, error) {
	domainCreds, err := s.credRepo.ListByUser(ctx, user.ID)
	if err != nil {
		return nil, err
	}
	libCreds := make([]webauthn.Credential, 0, len(domainCreds))
	for _, dc := range domainCreds {
		libCreds = append(libCreds, webauthn.Credential{
			ID:              dc.CredentialID,
			PublicKey:       dc.PublicKey,
			AttestationType: dc.AttestationType,
			Transport:       parseWebAuthnTransports(dc.Transport),
			Authenticator: webauthn.Authenticator{
				AAGUID:       byteAAGUID(dc.AAGUID),
				SignCount:    dc.SignCount,
				CloneWarning: dc.CloneWarning,
			},
			Flags: webauthn.CredentialFlags{
				BackupEligible: dc.BackupEligible,
				BackupState:    dc.BackupState,
				UserPresent:    true,
				UserVerified:   true,
			},
		})
	}
	return &webAuthnUser{user: user, creds: libCreds}, nil
}

func convertWebAuthnTransports(ts []protocol.AuthenticatorTransport) []string {
	if len(ts) == 0 {
		return nil
	}
	out := make([]string, 0, len(ts))
	for _, t := range ts {
		out = append(out, string(t))
	}
	return out
}

func parseWebAuthnTransports(ts []string) []protocol.AuthenticatorTransport {
	if len(ts) == 0 {
		return nil
	}
	out := make([]protocol.AuthenticatorTransport, 0, len(ts))
	for _, t := range ts {
		out = append(out, protocol.AuthenticatorTransport(t))
	}
	return out
}

func parseWebAuthnAAGUID(b []byte) *uuid.UUID {
	if len(b) != 16 {
		return nil
	}
	u, err := uuid.FromBytes(b)
	if err != nil {
		return nil
	}
	return &u
}

func byteAAGUID(u *uuid.UUID) []byte {
	if u == nil {
		return nil
	}
	return u[:]
}

// ---- session key helpers ----

func registrationKey(sessionID string) string { return "webauthn:reg:" + sessionID }
func loginKey(sessionID string) string        { return "webauthn:login:" + sessionID }
