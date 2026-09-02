package postgres

import (
	"time"

	"github.com/identuum/identuum-idp-oss/internal/infra/cache"
	"github.com/identuum/identuum-idp-oss/internal/repository"
)

// Repositories is the OSS-only aggregate of repository implementations
// constructed from a single DBTX. It deliberately excludes commercial
// repository fields (trusted-assertion issuer, anomaly, dynamic client
// registration, audit, compliance, SPIFFE, webhook, org backup) that
// belong in the commercial edition.
type Repositories struct {
	User                         repository.UserRepository
	AdminUser                    repository.AdminUserRepository
	Organization                 repository.OrganizationRepository
	Session                      repository.SessionRepository
	AuthCode                     repository.AuthCodeRepository
	Client                       repository.ClientRepository
	Key                          repository.KeyRepository
	PasswordReset                repository.PasswordResetRepository
	IdentityProvider             repository.IdentityProviderRepository
	OIDCState                    repository.OIDCStateRepository
	Claim                        repository.ClaimRepository
	APIResource                  repository.APIResourceRepository
	OrgRole                      repository.OrgRoleRepository
	OrganizationDomain           repository.OrganizationDomainRepository
	OrganizationProtocolSettings repository.OrganizationProtocolSettingsRepository
	ScopeTemplate                repository.ScopeTemplateRepository
	ServiceAccount               repository.ServiceAccountRepository
	TokenRevocation              repository.TokenRevocationRepository
	RefreshToken                 repository.RefreshTokenRepository
	ClientAssertionReplay        repository.ClientAssertionReplayRepository
	OAuthAuthorizationCode       repository.OAuthAuthorizationCodeRepository
	OAuthConsent                 repository.OAuthConsentRepository
	LoginAttempt                 repository.LoginAttemptRepository
	BrowserSessionToken          repository.BrowserSessionTokenRepository
	BackchannelLogoutDelivery    repository.BackchannelLogoutDeliveryRepository
	MFAPendingLoginSession       repository.MFAPendingLoginSessionRepository
	WebAuthnCredential           repository.WebAuthnCredentialRepository
	EmailVerification            repository.EmailVerificationRepository
	// UserProfile is the optional OIDC profile row store (THE-PROFILE-CLAIMS).
	UserProfile repository.UserProfileRepository
	// AgentCommunicationAuthorization is the AYGHU-1 aggregate store
	// (agent_communication_authorizations + _participants, migration 0037).
	AgentCommunicationAuthorization repository.AgentCommunicationAuthorizationRepository
	// DPoPProofReplay is the AYGHU-3 token-endpoint DPoP replay store
	// (dpop_proof_replays, migration 0038) — separate from ClientAssertionReplay.
	DPoPProofReplay repository.DPoPProofReplayRepository
	// Audit is the OSS plain persistent audit log store (L-2). Concrete
	// type (not an interface) so the runtime can SetRetention on it after
	// resolving the env override; it satisfies both the persistent
	// audit.Service's inserter seam and service.ExpiredRowSweeper.
	Audit *PgxAuditRepository
}

// NewPgxRepositories constructs the OSS aggregate of pgx-backed
// repository implementations. The User instance is reused for the
// AdminUser field because PgxUserRepository satisfies both
// repository.UserRepository and repository.AdminUserRepository.
//
// keyCipher (P3-5) encrypts signing_keys.private_key at rest. Callers that
// create or read signing keys (the serving runtime, bootstrap) MUST pass a
// real cipher; cipher-free one-shot diagnostics (db-check, recover) pass nil
// — the key repository is nil-tolerant + fail-closed (see NewPgxKeyRepository)
// and can never silently write plaintext.
func NewPgxRepositories(db DBTX, keyCipher PrivateKeyCipher) *Repositories {
	userRepo := NewPgxUserRepository(db)
	return &Repositories{
		User:                            userRepo,
		AdminUser:                       userRepo,
		Organization:                    NewPgxOrganizationRepository(db),
		Session:                         NewPgxSessionRepository(db),
		AuthCode:                        NewPgxAuthCodeRepository(db),
		Client:                          NewPgxClientRepository(db),
		Key:                             NewPgxKeyRepository(db, keyCipher),
		PasswordReset:                   NewPgxPasswordResetRepository(db),
		IdentityProvider:                NewPgxIdentityProviderRepository(db),
		OIDCState:                       NewPgxOIDCStateRepository(db),
		Claim:                           NewPgClaimRepository(db),
		APIResource:                     NewPgxAPIResourceRepository(db),
		OrgRole:                         NewPgxOrgRoleRepository(db),
		OrganizationDomain:              NewPgxOrganizationDomainRepository(db),
		OrganizationProtocolSettings:    NewPgxOrganizationProtocolSettingsRepository(db),
		ScopeTemplate:                   NewPgxScopeTemplateRepository(db),
		ServiceAccount:                  NewPgxServiceAccountRepository(db),
		TokenRevocation:                 NewPgxTokenRevocationRepository(db),
		RefreshToken:                    NewPgxRefreshTokenRepository(db),
		ClientAssertionReplay:           NewPgxClientAssertionReplayRepository(db),
		OAuthAuthorizationCode:          NewPgxOAuthAuthorizationCodeRepository(db),
		OAuthConsent:                    NewPgxOAuthConsentRepository(db),
		LoginAttempt:                    NewPgxLoginAttemptRepository(db),
		BrowserSessionToken:             NewPgxBrowserSessionTokenRepository(db),
		BackchannelLogoutDelivery:       NewPgxBackchannelLogoutDeliveryRepository(db),
		MFAPendingLoginSession:          NewPgxMFAPendingLoginSessionRepository(db),
		WebAuthnCredential:              NewPgxWebAuthnCredentialRepository(db),
		EmailVerification:               NewPgxEmailVerificationRepository(db),
		UserProfile:                     NewPgxUserProfileRepository(db),
		AgentCommunicationAuthorization: NewPgxAgentCommunicationAuthorizationRepository(db),
		DPoPProofReplay:                 NewPgxDPoPProofReplayRepository(db),
		Audit:                           NewPgxAuditRepository(db, DefaultAuditRetention),
	}
}

// ApplyCachedWrappers swaps in Redis-backed cached decorators on the
// repository fields whose cached wrapper has been PROVED unable to serve a
// dead tenant on a cache hit. It is a no-op when redisClient is nil so
// callers can invoke it unconditionally during bootstrap.
//
// P3-11 (2026-07-25): the applied set is EMPTY. All six cached wrappers were
// measured against their pgx delegates' SQL, and every one caches at least
// one read whose delegate carries a tenant/liveness predicate a cache hit
// would bypass — reopening the P0-3/4/5 tenant boundary for up to the TTL if
// ever wired. Each wrapper file is kept (the caching logic is sound as
// machinery); a wrapper may be RE-ADDED here only together with a liveness
// verdict for every cached read AND an update to
// TestApplyCachedWrappers_AppliedSetIsPinned, which fails on any silent
// addition. The predicate a cache hit would bypass, per wrapper:
//
//   - User: `banned = false AND deleted_at IS NULL`
//     (user_repository_pgx.go:338 GetByID, :391 GetByEmailAndOrgID,
//     :434 GetByExternalID; :1148 CountByOrganization filters
//     `deleted_at IS NULL`; :746 GetByIDWithOrg caches org policy fields
//     with no filter at all). The P0-3b org-delete cascade soft-deletes
//     users by raw SQL inside the org tx
//     (organization_repository_pgx.go Delete) and never touches these keys.
//   - Organization: `active = true AND deleted_at IS NULL`
//     (organization_repository_pgx.go:243 GetByID; :267 GetByDomain and
//     :286 GetBySlug filter `deleted_at IS NULL`) — the org-liveness
//     predicate itself; a cache-aside race can repopulate a stale entry
//     for the full TTL even though this wrapper invalidates on its own
//     mutations.
//   - Session: session_repository_pgx.go:177 GetSessionWithUserAndOrgStatus
//     RETURNS the user/org status flags the bearer path's CanBeUsedForAuth
//     verdict is computed from — caching it caches the P0-4/5 combined
//     check for 60s, and the P0-3b org-delete revocation runs as raw SQL
//     inside the org tx, never invalidating these keys (the wrapper's own
//     RevokeByOrganizationID invalidation is fail-open by its own comment).
//   - Client: org-liveness EXISTS subquery
//     `oc.deleted_at IS NULL AND (... o.deleted_at IS NULL AND o.active)`
//     (client_repository_pgx.go:194 GetClientByClientID) — org lifecycle
//     never invalidates client keys.
//   - IdentityProvider: `ip.deleted_at IS NULL AND EXISTS (... o.deleted_at
//     IS NULL AND o.active)` (identity_provider_repository_pgx.go:70
//     GetByID) — same class.
//   - ServiceAccount: `deleted_at IS NULL`
//     (service_account_repository_pgx.go:58 GetByID) — the org-delete
//     cascade soft-deletes service accounts by raw SQL inside the org tx,
//     never touching these keys.
func ApplyCachedWrappers(repos *Repositories, redisClient *cache.RedisClient, cacheTTL time.Duration) {
	if repos == nil || redisClient == nil {
		return
	}
	// P3-11: no wrapper is currently proved safe to apply. See the list
	// above before re-adding any line of the form:
	//   repos.X = repository.NewCachedXRepository(repos.X, redisClient, cacheTTL)
	_ = cacheTTL
}
