// Package server is the public OSS seam for the identuum-idp-oss HTTP
// server wrapper, JWKS publication primitives, and static OIDC
// discovery payload.
//
// It is the canonical import path for downstream callers — including
// the future identuum-idp-ce overlay — that need the OSS server
// lifecycle wrapper or the JWKS / discovery surface without crossing
// the internal/ boundary.
//
// Implementation note: this file is a thin shim over the existing
// internal/server package. Every named type below is a Go type alias
// of the corresponding internal/server type, so a struct literal or
// value built at either path is the same value at every Go compile
// site. NewSmokeHandler / NewSmokeHandlerWithJWKS /
// ResolveDiscoveryConfig / DiscoveryDocument / PublicKeyToJWK / New
// are pass-through wrappers around the corresponding internal/server
// functions. The internal package remains the single source of truth
// for behavior; this public package is the stable import surface CE
// will pin against.
//
// Scope of this seam (what is and is NOT re-exported):
//   - In scope (re-exported here): JWK + JWKS types, JWKSProvider
//     interface, EmptyJWKSProvider, RepositoryJWKSProvider,
//     PublicKeyToJWK, OIDCDiscoveryConfig, ResolveDiscoveryConfig,
//     DiscoveryDocument, NewSmokeHandler / NewSmokeHandlerWithJWKS /
//     NewSmokeHandlerWithDiscovery, SetSmokeVersion.
//   - NOT in scope: the HTTP server lifecycle wrapper (retired in
//     v0.2.0 — it was unused in OSS and unconsumed by CE; the OSS
//     runtime owns serving directly, and future in-process TLS will be
//     added to internal/runtime, not here), TLS / Vault cert sources,
//     and the TLS hot-reload loader.
//
// SECURITY contract:
//   - This package depends only on the OSS internal/server package
//     (which transitively depends on internal/domain and
//     internal/repository for the JWKS primitives). It carries no
//     license envelope, no private signing key, no DB handle, no
//     secret material, and no network surface of its own. The JWKS
//     publication path filters out private key material at the
//     internal/server layer; this seam does not relax that filter.
//   - The OSS module must never import identuum-idp-ce.
package server

import (
	"net/http"

	"github.com/identuum/identuum-idp-oss/internal/domain"
	internalserver "github.com/identuum/identuum-idp-oss/internal/server"
)

// JWK is the RFC 7517 JSON Web Key shape narrowed to the algorithms
// Identuum issues with. Aliased from internal/server.JWK.
type JWK = internalserver.JWK

// JWKS is the RFC 7517 §5 JSON Web Key Set wrapper. Aliased from
// internal/server.JWKS.
type JWKS = internalserver.JWKS

// JWKSProvider yields the current public JWKS. Aliased from
// internal/server.JWKSProvider so an implementation written against
// either name satisfies both.
type JWKSProvider = internalserver.JWKSProvider

// EmptyJWKSProvider always returns an empty JWKS. Aliased from
// internal/server.EmptyJWKSProvider.
type EmptyJWKSProvider = internalserver.EmptyJWKSProvider

// RepositoryJWKSProvider adapts a KeyRepository to JWKSProvider.
// Aliased from internal/server.RepositoryJWKSProvider. The Repo
// field's type (repository.KeyRepository) remains the internal
// package's interface; callers wiring this provider through the
// public seam must still hold a repository handle obtained from the
// OSS postgres factory.
type RepositoryJWKSProvider = internalserver.RepositoryJWKSProvider

// OIDCDiscoveryConfig drives the static OIDC discovery document.
// Aliased from internal/server.OIDCDiscoveryConfig so a literal such
// as `server.OIDCDiscoveryConfig{Issuer: "x"}` constructed at either
// path is the same value.
type OIDCDiscoveryConfig = internalserver.OIDCDiscoveryConfig

// SetSmokeVersion overrides the build-time identifier surfaced in
// the smoke /healthz and /livez JSON. Pass-through wrapper around
// internal/server.SetSmokeVersion.
func SetSmokeVersion(v string) {
	internalserver.SetSmokeVersion(v)
}

// NewSmokeHandler returns the minimal HTTP smoke surface with safe
// localhost defaults and an EmptyJWKSProvider. Pass-through wrapper
// around internal/server.NewSmokeHandler.
func NewSmokeHandler() http.Handler {
	return internalserver.NewSmokeHandler()
}

// NewSmokeHandlerWithDiscovery returns the smoke surface keyed off
// the supplied discovery config. Pass-through wrapper around
// internal/server.NewSmokeHandlerWithDiscovery.
func NewSmokeHandlerWithDiscovery(cfg OIDCDiscoveryConfig) http.Handler {
	return internalserver.NewSmokeHandlerWithDiscovery(cfg)
}

// NewSmokeHandlerWithJWKS returns the smoke surface plus a static
// /.well-known/openid-configuration document derived from cfg and a
// /.well-known/jwks.json endpoint backed by jwks. Pass-through
// wrapper around internal/server.NewSmokeHandlerWithJWKS.
func NewSmokeHandlerWithJWKS(cfg OIDCDiscoveryConfig, jwks JWKSProvider) http.Handler {
	return internalserver.NewSmokeHandlerWithJWKS(cfg, jwks)
}

// ResolveDiscoveryConfig fills in safe localhost defaults for any
// empty fields in cfg and returns the resolved value. Pass-through
// wrapper around internal/server.ResolveDiscoveryConfig.
func ResolveDiscoveryConfig(cfg OIDCDiscoveryConfig) OIDCDiscoveryConfig {
	return internalserver.ResolveDiscoveryConfig(cfg)
}

// DiscoveryDocument returns the static OIDC discovery payload keyed
// off cfg. Pass-through wrapper around
// internal/server.DiscoveryDocument; the OSS no-RS256-issuance
// policy (EdDSA + ES256 only) is single-sourced at the internal
// layer.
func DiscoveryDocument(cfg OIDCDiscoveryConfig) map[string]any {
	return internalserver.DiscoveryDocument(cfg)
}

// PublicKeyToJWK converts a single OSS signing-key row to its
// public-only JWK form. Pass-through wrapper around
// internal/server.PublicKeyToJWK. The alg parameter retains the
// internal/domain.KeyAlgorithm shape so the public seam single-
// sources the algorithm policy with the internal authority; callers
// composing through the seam typically obtain the value from a
// JWKSProvider result rather than constructing it directly.
func PublicKeyToJWK(kid string, alg domain.KeyAlgorithm, publicKeyPEM string) (JWK, error) {
	return internalserver.PublicKeyToJWK(kid, alg, publicKeyPEM)
}
