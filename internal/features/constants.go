package features

const (
	// Core bundle - implicitly enabled if license is valid, or in Demo Mode
	Core               = "core"
	PublicRegistration = "public_registration" // Org-scoped self-service registration

	// Optional Modules
	MFA             = "mfa"
	SSO             = "sso"
	AppendOnlyAudit = "audit_append_only"
	FailClosedAudit = "audit_fail_closed"
	StaticVault     = "vault_static"
	DynamicVault    = "vault_dynamic"

	// Professional Features
	PAR                 = "par"
	WhiteLabel          = "white_label"
	OIDCFederation      = "oidc_federation"
	Webhooks            = "webhooks"
	WebAuthn            = "webauthn"
	AuthorizationServer = "authorization_server"
	AuditExport         = "audit_export" // Paginated GET export endpoint for SIEM pull-model integrations

	// Enterprise Features
	//
	// DynamicClientRegistration is the canonical feature key used in
	// `// docgen:feature_gate=dynamic_client_registration` annotations
	// AND in the wiki tier matrix. The key has TWO concrete meanings
	// depending on which build consumes it:
	//
	//   - **OSS (this module)** — the key gates a **DCR foundation**:
	//     RFC 7591 `POST /api/v1/oauth/register` (site_admin OR Bearer
	//     IAT), the RFC 7591 §2.1 IAT lifecycle, and the RFC 7592
	//     management surface (GET/PUT/DELETE under :client_id). Owner
	//     decision (2026-06-04): the DCR FOUNDATION stays in OSS. The
	//     key is listed in StarterFeatures (audit C2/F2 trap defuse) so
	//     the OSS `StarterFeatureGate` ALLOWS it, but NO production route
	//     feature-gates DCR — it is reachable via a site_admin or a valid
	//     IAT regardless (the production gate is allow-all today). The
	//     `docgen:feature_gate` annotation surfaces the key to the
	//     docs site so an operator can see which routes belong to the
	//     DCR family.
	//   - **CE (identuum-idp-ce)** — the same key is the runtime
	//     entitlement check for advanced DCR features that are NOT in
	//     OSS: signed `software_statement` verification, public
	//     anonymous DCR with tenant-policy templates, per-tenant DCR
	//     approval workflows, RFC 7591 §5 client-management
	//     access-token rotation policies, public-registration rate
	//     limiting, and DCR audit reconciliation. The CE provider
	//     returns true only for Enterprise tier.
	//
	// The split is documented in
	// `identuum-idp/docs/open-core/IDP_DCR_SCIM_OPEN_CORE_SPLIT_DECISION.md`
	// and in `wiki/protocols/dcr.md` §"OSS foundation".
	DynamicClientRegistration = "dynamic_client_registration"
	LDAP                      = "ldap"
	// SCIM is the canonical feature key used in
	// `// docgen:feature_gate=scim` annotations AND in the wiki tier
	// matrix. The key has TWO concrete meanings depending on which
	// build consumes it:
	//
	//   - **OSS (this module)** — the key gates a **SCIM v2 read +
	//     conservative-write foundation**: discovery (ServiceProvider
	//     Config / Schemas / ResourceTypes), Users list + get, Users
	//     create / replace / replace-only PATCH / soft-delete. Owner
	//     decision (2026-06-04): the SCIM FOUNDATION stays in OSS.
	//     The OSS `StarterFeatureGate` does NOT enforce this key —
	//     SCIM is reachable when site_admin or org_admin with the
	//     appropriate users:* scope is presented. The
	//     `docgen:feature_gate` annotation surfaces the key to the
	//     docs site.
	//   - **CE (identuum-idp-ce)** — the same key is the runtime
	//     entitlement check for advanced SCIM features that are NOT in
	//     OSS: SCIM Groups, SCIM Bulk, SCIM filter / sortBy /
	//     attributes / excludedAttributes, the SCIM Enterprise User
	//     extension, full PATCH (add / remove / move ops), ETag /
	//     versioned-resource concurrency, SCIM password +
	//     changePassword, SCIM provisioning-drift reconciliation
	//     reports. The CE provider returns true only for Enterprise
	//     tier.
	//
	// The split is documented in
	// `identuum-idp/docs/open-core/IDP_DCR_SCIM_OPEN_CORE_SPLIT_DECISION.md`
	// and in `wiki/protocols/scim.md` §"OSS foundation".
	SCIM             = "scim"
	AnomalyDetection = "anomaly_detection"
	MCPServer        = "mcp_server"
	DatabaseBackups  = "database_backups"
	// SPIFFEFederation gates the SPIFFE Workload Identity Federation surface
	// (admin CRUD over peers / bundles / mapping rules + the JWT-SVID
	// branch of the RFC 8693 token-exchange endpoint). Enterprise-only per
	// docs/ImplementationPlan-SPIFFEFederation.md §9.
	SPIFFEFederation = "spiffe_federation"

	// FIPS is a declarative tier entitlement marker — it signals that the deployment
	// is operating in a FIPS 140-3 context. The primary FIPS artifact is produced by
	// `make build-fips` and runs against the native Go Cryptographic Module
	// (GOFIPS140=v1.0.0, MIP-listed as of the current Go toolchain). Runtime
	// enforcement is the operator gate AUTH_SERVICE_REQUIRE_FIPS, verified at startup
	// against debug.BuildInfo; see startup.VerifyFIPSBuildOrFail.
	// This flag is NOT checked via IsFeatureEnabled() at runtime; it is a commercial
	// tier signal that the deployment is entitled to the FIPS-locked artifact.
	FIPS = "fips"

	// HardwareBinding is a declarative tier entitlement marker — it signals that the
	// license was issued with a hardware identity constraint (License.HardwareID != "").
	// Enforcement happens at license Verify() time in internal/license/verifier.go, not
	// via an IsFeatureEnabled() gate — it applies regardless of whether this constant is
	// checked, because verification is unconditional when HardwareID is present.
	HardwareBinding = "hardware_binding"

	// Usage Limits Keys
	// LimitUserSessions is reserved for future per-tier concurrent session enforcement.
	// It is NOT currently present in TierLimits — no runtime cap is active.
	// Do not read this key expecting an enforced limit until wired into SessionService.
	LimitUserSessions = "user_sessions"
	LimitM2MSessions  = "m2m_sessions" // Used for both sessions and clients count
	LimitTenants      = "limit_tenants"
	LimitUsers        = "limit_users"
	// LimitSPIFFEPeers is the per-org soft cap on
	// spiffe_federation_peers rows. Enforced at the service layer in
	// SPIFFEFederationAdminService.Create.
	LimitSPIFFEPeers = "limit_spiffe_peers"
	// LimitSPIFFEBundleSizeBytes caps the maximum bundle blob size for
	// both pull and operator-upload. Mirrored at the HTTP layer with a
	// request-body byte cap.
	LimitSPIFFEBundleSizeBytes = "limit_spiffe_bundle_size_bytes"
)
