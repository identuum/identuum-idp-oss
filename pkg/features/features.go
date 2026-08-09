// Package features is the public OSS seam for feature-key constants
// and the runtime feature-decision primitives consumed by route
// gates and the OSS/CE license-provider model.
//
// It is the canonical import path for downstream callers — including
// the identuum-idp-ce overlay — that need access to OSS feature
// constants without crossing the internal/ boundary.
//
// Implementation note: this file is a thin shim over the existing
// internal/features package. Every symbol here is a Go type alias,
// constant re-declaration, or variable re-binding pointing at the
// internal/features authority. The internal package remains the
// single source of truth for behavior; the public package is the
// stable import surface CE will pin against.
//
// Why aliases (and not a full physical relocation):
//   - Type aliases share the same underlying type identity, so a
//     value of pkg/features.StarterFeatureGate is identical to a
//     value of internal/features.StarterFeatureGate at every Go
//     compile site. Existing internal callers keep working unchanged.
//   - Constants are re-declared with `const X = internalfeatures.X`
//     so the public package emits identical compile-time values.
//   - The two map/slice re-exports (StarterFeatures, StarterLimits)
//     are var-aliased to the same underlying memory so they cannot
//     drift between the two paths.
//
// SECURITY contract:
//   - This package depends only on the OSS internal/features
//     package and the standard library. It carries no secret
//     material, no license envelope, no signing key, no DB handle,
//     and no network surface.
//   - The OSS module must never import identuum-idp-ce.
package features

import (
	internalfeatures "github.com/identuum/identuum-idp-oss/internal/features"
)

// ---------------------------------------------------------------
// Feature-key constants
//
// The exact set, ordering, and string values mirror the canonical
// declaration in internal/features/constants.go. Adding or removing
// a key here without matching the internal authority is a build
// error because the public symbol is defined as `const X =
// internalfeatures.X`.
// ---------------------------------------------------------------

const (
	Core               = internalfeatures.Core
	PublicRegistration = internalfeatures.PublicRegistration

	MFA             = internalfeatures.MFA
	SSO             = internalfeatures.SSO
	AppendOnlyAudit = internalfeatures.AppendOnlyAudit
	FailClosedAudit = internalfeatures.FailClosedAudit
	StaticVault     = internalfeatures.StaticVault
	DynamicVault    = internalfeatures.DynamicVault

	PAR                 = internalfeatures.PAR
	WhiteLabel          = internalfeatures.WhiteLabel
	OIDCFederation      = internalfeatures.OIDCFederation
	Webhooks            = internalfeatures.Webhooks
	WebAuthn            = internalfeatures.WebAuthn
	AuthorizationServer = internalfeatures.AuthorizationServer
	AuditExport         = internalfeatures.AuditExport

	DynamicClientRegistration = internalfeatures.DynamicClientRegistration
	LDAP                      = internalfeatures.LDAP
	SCIM                      = internalfeatures.SCIM
	AnomalyDetection          = internalfeatures.AnomalyDetection
	MCPServer                 = internalfeatures.MCPServer
	DatabaseBackups           = internalfeatures.DatabaseBackups
	SPIFFEFederation          = internalfeatures.SPIFFEFederation

	FIPS            = internalfeatures.FIPS
	HardwareBinding = internalfeatures.HardwareBinding

	LimitUserSessions          = internalfeatures.LimitUserSessions
	LimitM2MSessions           = internalfeatures.LimitM2MSessions
	LimitTenants               = internalfeatures.LimitTenants
	LimitUsers                 = internalfeatures.LimitUsers
	LimitSPIFFEPeers           = internalfeatures.LimitSPIFFEPeers
	LimitSPIFFEBundleSizeBytes = internalfeatures.LimitSPIFFEBundleSizeBytes
)

// ---------------------------------------------------------------
// Seam interfaces and Starter / test gate implementations
// ---------------------------------------------------------------

// FeatureGate is the runtime feature-availability seam consumed by
// route gates (mw.RequireFeature) and service-layer entitlement
// checks. The OSS Starter gate and the CE license-backed gate both
// satisfy this interface.
type FeatureGate = internalfeatures.FeatureGate

// FeatureLimits is the runtime per-metric limit seam consumed by
// service-layer enforcement (tenant counts, M2M session counts,
// SPIFFE peer counts).
type FeatureLimits = internalfeatures.FeatureLimits

// LicenseInfoProvider is the runtime license-info seam consumed by
// the IDP component-discovery and health surfaces. Returns a
// runtime-safe scalar map — never carries license envelope or
// signature material.
type LicenseInfoProvider = internalfeatures.LicenseInfoProvider

// StarterFeatureGate is the OSS-side FeatureGate. It returns
// true for the Starter-tier feature set and false for every
// commercial feature.
type StarterFeatureGate = internalfeatures.StarterFeatureGate

// StarterFeatureLimits is the OSS-side FeatureLimits.
type StarterFeatureLimits = internalfeatures.StarterFeatureLimits

// OpenGate is the always-allow FeatureGate. It is the documented
// OSS default for routes that do not yet have a tier-aware gate
// wired in.
type OpenGate = internalfeatures.OpenGate

// ClosedGate is the always-deny FeatureGate. Intended for tests
// that confirm a gated route fails closed.
type ClosedGate = internalfeatures.ClosedGate

// StaticGate is a map-backed FeatureGate. Features whose key is
// present and true return true; everything else is denied.
type StaticGate = internalfeatures.StaticGate

// NewStaticGate constructs a StaticGate whose enabled set is a
// defensive copy of the supplied map.
func NewStaticGate(enabled map[string]bool) StaticGate {
	return internalfeatures.NewStaticGate(enabled)
}

// ---------------------------------------------------------------
// Starter tier data
//
// StarterFeatures and StarterLimits are re-bound to the same
// underlying slice/map declared in internal/features. Callers that
// mutate either of these globals are mis-using the API — both the
// internal and public packages treat them as immutable definitions.
// ---------------------------------------------------------------

// StarterFeatures is the canonical list of feature keys enabled at
// the Starter tier per the current product definition.
var StarterFeatures = internalfeatures.StarterFeatures

// StarterLimits is the canonical map of per-metric Starter-tier
// limit values.
var StarterLimits = internalfeatures.StarterLimits
