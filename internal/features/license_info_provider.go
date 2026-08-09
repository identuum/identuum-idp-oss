package features

// LicenseInfoProvider is the core-owned interface for runtime
// license-info reads consumed by the IDP component-discovery and
// health surfaces. The commercial *internal/license.Service (in
// identuum-idp-ce) satisfies this interface; the OSS
// licenseprovider.StarterProvider also satisfies it; tests can stub.
//
// Introduced in Phase 1 of the open-core split
// (identuum-idp-open-core-phase1-license-info-provider). Relocated
// into identuum-idp-oss in Phase 2 by slice
// identuum-idp-open-core-phase2-starter-provider-into-oss (copy;
// the monolith retains its own copy as the current source of truth
// until Phase 2 completes).
//
// Return-type design (binding): the interface returns the same
// untyped `map[string]any` shape that (*license.Service).GetLicenseInfo
// already returns. The handlers (handler_component.go +
// handler_health.go) already project this map onto typed DTOs
// (IDPComponentLicenseInfo / the health-response inline shape) at
// the call site, so the map-based contract is a faithful
// preservation of the existing surface — NO new DTO was introduced
// in the Phase 1 slice. A future slice may narrow the contract to
// a typed LicenseInfo struct once the field-set has stabilised.
//
// Safety contract:
//   - The returned map MUST NOT carry license envelope, signature,
//     verifier output, raw entitlement claims, or any commercial-only
//     internal. The Starter implementation returns only runtime-safe
//     scalar keys (status / tier / license_type / deployment_mode);
//     the commercial implementation may carry additional fields,
//     but the handlers intentionally drop customer-bearing fields
//     (licensee, features list, issued_at) when projecting onto the
//     wire DTO. The interface itself does not enforce that — the
//     projection lives in the handlers per the existing design.
type LicenseInfoProvider interface {
	GetLicenseInfo() map[string]any
}
