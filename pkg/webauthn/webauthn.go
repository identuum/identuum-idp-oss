// Package webauthn is the public OSS seam for the identuum-idp-oss
// WebAuthn / passkey backend. It re-exports the minimum surface
// downstream callers — including the future identuum-idp-ce overlay —
// need to wire WebAuthn credential storage + ceremony session storage
// without crossing the OSS `internal/` boundary.
//
// Implementation note: this file is a thin shim over the existing
// `internal/repository` + `internal/domain` packages. Every named
// type below is a Go type alias of the corresponding internal type,
// so a struct or interface value built at either path is the same
// value at every Go compile site. The internal package remains the
// single source of truth for behaviour; this public package is the
// stable import surface CE will pin against.
//
// Scope of this seam (what is and is NOT re-exported):
//   - In scope (re-exported here):
//   - `Credential`, `CredentialRepository` — the credential storage
//     seam CE implements against its own Postgres pool.
//   - `SessionRepository`, `InMemorySessionRepository`,
//     `NewInMemorySessionRepository` — the ceremony storage seam
//     (5-minute TTL, single-use). In-memory is sufficient for
//     single-instance deployments; CE may later supply a Redis-
//     backed implementation behind the same interface.
//   - `RoutePaths` — the canonical OSS WebAuthn route literals so
//     CE contract tests can pin both surfaces against one place.
//   - `TTL` — the ceremony TTL constant (re-exported from the
//     service layer for callers that want to mirror it).
//   - `Err*` — the service-level error sentinels CE handler shims
//     may surface to operators.
//   - Added by agent-a-20260784 (v0.1.2 seam extension):
//   - `Service` + `ServiceConfig` + `NewService(cfg)` factory — CE
//     can now construct the shared OSS WebAuthn service without
//     importing `internal/*`. The internal `webAuthnUserRepo` was
//     promoted to the exported `service.WebAuthnUserRepo` in the
//     same slice so `UserRepo` can alias it.
//   - `User` type alias of `internal/domain.User` — required by
//     every Service method (BeginRegistration, FinishRegistration,
//     …) on the User parameter.
//   - `UserRepo` interface alias — the seam CE's user-lookup
//     adapter implements.
//   - 6 service-level error sentinels (`ErrSessionInvalid`,
//     `ErrNoCredentials`, `ErrAssertionInvalid`,
//     `ErrCredentialMissing`, `ErrTenantMismatch`,
//     `ErrCloneDetected`) — CE handler shims map these onto HTTP
//     status codes consistently with the OSS reference.
//   - NOT exposed here (deferred to the CE-side capability flip
//     slice; remains owner-gated):
//   - `RegisterWebAuthnRoutes` handler factory — coupled to
//     `gin.IRouter`; CE uses `net/http.ServeMux` so the routing-
//     model bridge is a CE-side design decision that lands
//     alongside the capability flip.
//
// SECURITY contract:
//   - This package depends only on the OSS `internal/repository`
//     and `internal/domain` packages (which depend on no secret
//     material). It carries no license envelope, no signing key,
//     no DB handle, no secret material, and no network surface
//     of its own.
//   - The OSS module must never import identuum-idp-ce.
//   - CE adapters implementing `CredentialRepository` MUST NOT
//     log raw credential bytes, public key bytes, attestation
//     blobs, or session ids. The shared safety contract from
//     `internal/handlers/webauthn.go` applies to every consumer.
package webauthn

import (
	"time"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	"github.com/identuum/identuum-idp-oss/internal/repository"
	"github.com/identuum/identuum-idp-oss/internal/service"
)

// ── Credential storage seam ────────────────────────────────────────────────

// Credential is a passkey row as stored by the OSS WebAuthn service.
// Type-alias re-export of `internal/domain.WebAuthnCredential` —
// values are interchangeable at every Go compile site, so a CE-side
// adapter satisfying `CredentialRepository` returns the same `*Credential`
// the OSS service consumes.
type Credential = domain.WebAuthnCredential

// CredentialRepository defines storage for WebAuthn credentials.
// Type-alias re-export of `internal/repository.WebAuthnCredentialRepository`
// so CE may implement this interface directly with its own Postgres
// pool — no OSS-internal import required.
type CredentialRepository = repository.WebAuthnCredentialRepository

// ErrCredentialNotFound is returned by CredentialRepository.GetByCredentialID
// when the supplied raw credential id has no live row. Type-alias re-export
// of `internal/repository.ErrWebAuthnCredentialNotFound`.
var ErrCredentialNotFound = repository.ErrWebAuthnCredentialNotFound

// ── Ceremony session storage seam ──────────────────────────────────────────

// SessionRepository defines storage for ephemeral WebAuthn ceremony
// sessions. Type-alias re-export of
// `internal/repository.WebAuthnSessionRepository`.
type SessionRepository = repository.WebAuthnSessionRepository

// InMemorySessionRepository is a process-local SessionRepository
// suitable for single-instance deployments. Type-alias re-export of
// `internal/repository.InMemoryWebAuthnSessionRepository`.
type InMemorySessionRepository = repository.InMemoryWebAuthnSessionRepository

// NewInMemorySessionRepository constructs a SessionRepository backed
// by a process-local map. Thin wrapper over
// `internal/repository.NewInMemoryWebAuthnSessionRepository`.
func NewInMemorySessionRepository() *InMemorySessionRepository {
	return repository.NewInMemoryWebAuthnSessionRepository()
}

// ── Constants ──────────────────────────────────────────────────────────────

// TTL is the ceremony TTL applied to every entry stored in
// `SessionRepository`. Matches the upstream go-webauthn library's
// 5-minute default. Re-exported so callers that mirror the timeout
// (e.g. CE handler shims) reference the same value as the OSS
// service does internally.
const TTL = 5 * time.Minute

// RoutePathRegisterBegin is the canonical OSS path for the
// authenticated `POST /api/v1/webauthn/register/begin` route.
const RoutePathRegisterBegin = "/api/v1/webauthn/register/begin"

// RoutePathRegisterFinish is the canonical OSS path for the
// authenticated `POST /api/v1/webauthn/register/finish` route.
const RoutePathRegisterFinish = "/api/v1/webauthn/register/finish"

// RoutePathCredentialsList is the canonical OSS path for the
// authenticated `GET /api/v1/webauthn/credentials` route.
const RoutePathCredentialsList = "/api/v1/webauthn/credentials"

// RoutePathCredentialDelete is the canonical OSS path template for
// the authenticated `DELETE /api/v1/webauthn/credentials/:id` route.
const RoutePathCredentialDelete = "/api/v1/webauthn/credentials/:id"

// RoutePathLoginBegin is the canonical OSS path for the public
// `POST /api/v1/auth/login/webauthn/begin` route.
const RoutePathLoginBegin = "/api/v1/auth/login/webauthn/begin"

// RoutePathLoginFinish is the canonical OSS path for the public
// `POST /api/v1/auth/login/webauthn/finish` route.
const RoutePathLoginFinish = "/api/v1/auth/login/webauthn/finish"

// ── Service seam (agent-a-20260784 v0.1.2 extension) ──────────────────────

// User is the user object the WebAuthn service operates on. Type-alias
// re-export of `internal/domain.User`. CE adapters constructing a
// `pkgwebauthn.User` for the service produce the same value at every
// Go compile site.
type User = domain.User

// UserRepo is the narrow seam the WebAuthn service uses to resolve
// user rows. Type-alias re-export of `internal/service.WebAuthnUserRepo`
// (promoted from unexported `webAuthnUserRepo` in the same slice).
// CE implements this interface against `local_users` so the OSS
// service can resolve users without crossing the internal/ boundary.
type UserRepo = service.WebAuthnUserRepo

// ServiceConfig is the WebAuthn service configuration bundle. Type-
// alias re-export of `internal/service.WebAuthnServiceConfig`.
// Required dependencies: `BaseURL` (origin → RPID), `UserRepo`,
// `CredRepo`, `SessionRepo`. Optional: `UIPublicBaseURL`,
// `RPDisplayName`, `Audit`, `Logger`.
type ServiceConfig = service.WebAuthnServiceConfig

// Service is the WebAuthn service receiver. Type-alias re-export of
// `internal/service.WebAuthnService`. CE handler shims call methods
// (BeginRegistration / FinishRegistration / FinishRegistrationWithNickname
// / BeginLogin / BeginDummyLogin / FinishLogin / ListCredentials /
// DeleteCredential) directly on the alias.
type Service = service.WebAuthnService

// NewService constructs a `*Service` from the supplied configuration.
// Thin wrapper over `internal/service.NewWebAuthnService` — preserves
// the same nil-dependency validation + URL parsing + RPID derivation
// behavior. Returns an error if any of `cfg.BaseURL` / `cfg.UserRepo`
// / `cfg.CredRepo` / `cfg.SessionRepo` is missing or invalid.
func NewService(cfg ServiceConfig) (*Service, error) {
	return service.NewWebAuthnService(cfg)
}

// ── Service error sentinels (agent-a-20260784) ─────────────────────────────

// ErrSessionInvalid is returned by FinishRegistration / FinishLogin
// when the supplied session_id has no live entry, expired, was
// already consumed, or failed integrity checks. Type-alias re-export
// of `internal/service.ErrWebAuthnSessionInvalid`. CE handlers
// collapse this onto an opaque 400/401 response so the wire cannot
// disambiguate the failure cases.
var ErrSessionInvalid = service.ErrWebAuthnSessionInvalid

// ErrNoCredentials is returned by BeginLogin when the resolved user
// has zero credentials. Type-alias re-export of
// `internal/service.ErrWebAuthnNoCredentials`. CE handlers route
// public callers through BeginDummyLogin (anti-enumeration) so this
// error is generally only seen by privileged callers that know the
// user exists.
var ErrNoCredentials = service.ErrWebAuthnNoCredentials

// ErrAssertionInvalid is returned by FinishLogin when the library
// rejects the assertion (signature mismatch, RP id mismatch, origin
// mismatch, clone detection, …). Type-alias re-export of
// `internal/service.ErrWebAuthnAssertionInvalid`. CE handlers
// collapse this onto a generic 401 invalid_credentials.
var ErrAssertionInvalid = service.ErrWebAuthnAssertionInvalid

// ErrCredentialMissing is returned by FinishLogin when the upstream
// library validated the assertion but the credential id it carries
// is not present in the OSS credential store. Type-alias re-export
// of `internal/service.ErrWebAuthnCredentialMissing`. CE handlers
// collapse this onto a generic 401.
var ErrCredentialMissing = service.ErrWebAuthnCredentialMissing

// ErrTenantMismatch is returned by FinishLogin when the credential
// row's organization differs from the user's. Type-alias re-export
// of `internal/service.ErrWebAuthnTenantMismatch`. CE handlers treat
// it as an assertion-invalid failure at the HTTP boundary.
var ErrTenantMismatch = service.ErrWebAuthnTenantMismatch

// ErrCloneDetected is returned by FinishLogin when the upstream
// library reports a clone-warning verdict OR the stored row already
// carries `clone_warning=true`. Type-alias re-export of
// `internal/service.ErrWebAuthnCloneDetected`. CE handlers collapse
// it onto a generic 401.
var ErrCloneDetected = service.ErrWebAuthnCloneDetected

// ── Route path helpers ────────────────────────────────────────────────────

// RoutePaths returns the canonical OSS WebAuthn route paths in a
// stable, addressable map. Callers (in particular CE contract tests)
// MAY use the keys as identifiers when emitting failure messages.
// The map is constructed fresh on every call so callers may freely
// mutate the returned value.
func RoutePaths() map[string]string {
	return map[string]string{
		"register_begin":    RoutePathRegisterBegin,
		"register_finish":   RoutePathRegisterFinish,
		"credentials_list":  RoutePathCredentialsList,
		"credential_delete": RoutePathCredentialDelete,
		"login_begin":       RoutePathLoginBegin,
		"login_finish":      RoutePathLoginFinish,
	}
}
