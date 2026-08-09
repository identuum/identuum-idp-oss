package features

// FeatureGate is the core-owned interface for runtime
// feature-availability checks. Both the identuum-idp-oss Starter
// implementation (StarterFeatureGate, below) and the
// identuum-idp-ce license-backed implementation
// (*internal/license.Service in the commercial module) satisfy
// this interface.
//
// Introduced in Phase 1 of the open-core split
// (identuum-idp-open-core-phase1-feature-gate-interface). Relocated
// into identuum-idp-oss in Phase 2 by slice
// identuum-idp-open-core-phase2-starter-provider-into-oss (copy;
// the monolith retains its own copy as the current source of truth
// until Phase 2 completes).
//
// The variadic `roles` parameter mirrors the existing
// (*license.Service).IsFeatureEnabled signature so that the
// interface remains backward-compatible with every current caller.
// Callers that have no role context (the common case) simply omit
// it.
type FeatureGate interface {
	IsFeatureEnabled(feature string, roles ...string) bool
}

// StarterFeatures is the canonical list of feature keys the OSS
// core ACTUALLY SERVES — one entry per tier-classified
// capability whose implementation ships in identuum-idp-oss and is
// mounted on a serving path. It is the DOCUMENTED OSS capability set.
//
// STRUCTURAL BOUNDARY (read before editing): the OSS/CE boundary is
// enforced STRUCTURALLY, not by this list at runtime — a feature is OSS
// iff its code lives in identuum-idp-oss; CE-only features (PAR,
// managed/multi-IdP OIDC federation, audit, webhooks, SCIM, LDAP,
// anomaly, backups, SPIFFE, dynamic vault, MCP, white-label, …) live in
// identuum-idp-ce and simply
// have no handler here to reach. StarterFeatures is NOT a runtime
// enforcement point today: the production route gates run with an
// OpenGate (allow-all) — see mw.RequireFeatureWithAudit and the
// StarterFeatureGate note below.
//
// ADD-ONLY RULE: add a key here iff OSS actually serves that capability
// (its routes are mounted). Never add a CE-only or removed feature
// (e.g. scim was removed in docs/audit/changelog/scim-oss-leak-removal.md
// — it is absent here by design). Keeping this list == "what OSS serves"
// is a safety invariant (audit C2/F2): if a future slice ever flips the
// production gate from the allow-all OpenGate to an enforce-listed-only
// gate (StarterFeatureGate / StaticGate), a COMPLETE list guarantees no
// OSS-served capability is wrongly 403'd. Whether the gate becomes such
// an enforcing backstop is a DEFERRED post-release decision; this
// definition only documents the capability set — it does NOT enforce.
//
// NOTE: this list is intentionally NOT a verbatim mirror of the CE
// internal/license.TierFeatures[TierStarter] map. authorization_server
// and dynamic_client_registration are OSS-baseline-ungated capabilities
// (owner decisions 2026-06-04/05: DCR Foundation + the Authorization
// Server = RBAC / API resources / scope templates ship in OSS) that CE's
// tier map classifies Professional+; OSS serves them, so they belong here.
//
// StarterFeatures intentionally lives in OSS (internal/features) because
// the StarterFeatureGate must not import internal/license.
var StarterFeatures = []string{
	Core,
	PublicRegistration,
	MFA,
	SSO,
	StaticVault,
	WebAuthn,
	// OSS-baseline-ungated capabilities OSS genuinely serves. Added to
	// complete the list (audit C2/F2 trap defuse). NO behavior change:
	// no production route enforces these keys today (the gate is
	// allow-all), so listing them only future-proofs an enforce switch.
	AuthorizationServer,       // RBAC + API resources + scope templates (rbac.go / api_resources.go / scope_templates.go)
	DynamicClientRegistration, // DCR RFC 7591 + 7592 + IATs (dcr.go / dcr_management.go / dcr_initial_access_tokens.go)
}

// starterFeatureSet is a constant-time lookup table built once
// from StarterFeatures so per-request IsFeatureEnabled calls do
// not iterate the slice.
var starterFeatureSet = func() map[string]struct{} {
	m := make(map[string]struct{}, len(StarterFeatures))
	for _, f := range StarterFeatures {
		m[f] = struct{}{}
	}
	return m
}()

// StarterFeatureGate is the Starter-tier FeatureGate implementation.
// It returns true for the exact set of features enabled at the
// Starter tier (see StarterFeatures) and false for everything
// else.
//
// Behaviour (kept aligned with (*license.Service).IsFeatureEnabled
// so swap-in is risk-free):
//   - The Core feature is always enabled (base authentication
//     contract).
//   - The MFA feature is always enabled at Starter; additionally,
//     a site_admin role is honoured as a hard always-on so the
//     "site_admin MUST have MFA" security invariant from
//     license.Service is preserved when StarterFeatureGate is the
//     active gate.
//   - The remaining Starter features (PublicRegistration, SSO,
//     StaticVault, WebAuthn, AuthorizationServer,
//     DynamicClientRegistration) return true — i.e. every capability
//     OSS actually serves (see StarterFeatures).
//   - Every CE-only (Professional / Enterprise) feature returns false.
//   - Unknown features return false.
//
// POSTURE: StarterFeatureGate is NOT the active production gate today.
// Production route gates run with an OpenGate (allow-all); the OSS/CE
// boundary is structural (CE-only handlers simply do not exist in this
// module). This gate is the documented OSS capability gate and a
// candidate enforce-listed-only backstop whose activation is a DEFERRED
// post-release decision (audit C2/F2). Because StarterFeatures now lists
// every OSS-served capability, activating it would NOT 403 any of them.
//
// StarterFeatureGate has no state, no license parsing, no crypto,
// and no import of internal/license. It is safe to construct and
// use in any code path that can reference internal/features.
type StarterFeatureGate struct{}

// IsFeatureEnabled answers Starter-tier feature checks. See
// StarterFeatureGate for the contract.
func (StarterFeatureGate) IsFeatureEnabled(feature string, roles ...string) bool {
	// 1. Security invariant: site_admin always has MFA. Matches
	//    the early-return in (*license.Service).IsFeatureEnabled
	//    so swapping the gate does not weaken the invariant.
	if feature == MFA {
		for _, r := range roles {
			if r == "site_admin" {
				return true
			}
		}
	}
	// 2. Constant-time membership check against the Starter set.
	_, ok := starterFeatureSet[feature]
	return ok
}

// Compile-time assertion that StarterFeatureGate satisfies the
// FeatureGate interface. If the interface shape changes and the
// Starter implementation no longer conforms, the build fails
// here.
var _ FeatureGate = StarterFeatureGate{}
