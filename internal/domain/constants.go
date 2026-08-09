package domain

const (
	// MFA Constants
	DefaultMFARecoveryCodesCount = 10
	DefaultMFARecoveryCodeLength = 16

	// ── Bootstrap sentinel UUIDs ──────────────────────────────────────────────
	//
	// SystemOrgID and SiteAdminID are reserved, manually-assigned UUIDv7-zero
	// sentinel identifiers for the two bootstrap rows every IDP installation
	// requires. They are NOT randomly generated and must not be changed without
	// a coordinated database migration across every installed instance.
	//
	// Both values sit in the reserved UUIDv7-zero range:
	//   00000000-0000-7000-0000-000000000000  (version=7, all other bits zero)
	//   00000000-0000-7000-0000-000000000001  (version=7, last bit incremented)
	//
	// Why UUIDv7-zero? UUIDv7 encodes a millisecond timestamp in the high bits;
	// an all-zero timestamp is the Unix epoch (1970), so these values are
	// identifiably synthetic, cannot collide with any genuinely generated UUIDv7,
	// and are trivially distinguishable from the all-zero non-versioned UUID
	// (00000000-0000-0000-0000-000000000000, which is uuid.Nil in Go).
	//
	// Ordinary tenant orgs and users continue to use generated UUIDv7 IDs.
	// The sentinel values are valid UUIDs in the database but carry special
	// semantics: they must never be deleted or reused for other purposes.
	//
	// See migrations/0016_bootstrap_v7_sentinel_ids.sql for the upgrade path
	// from the legacy non-UUIDv7 sentinel (00000000-0000-0000-0000-000000000001).
	// See LegacySystemOrgID below for the old value still needed for backup/restore
	// compatibility with backup files written before migration 0016.

	// SystemOrgID is the reserved UUIDv7-zero sentinel for the bootstrap
	// system organization (domain: system.local). All site_admin users belong
	// to this organization. Do not use for tenant organizations.
	SystemOrgID = "00000000-0000-7000-0000-000000000000"

	// SiteAdminID is the reserved UUIDv7-zero+1 sentinel for the bootstrap
	// site_admin user (email: site_admin@system.local). createSiteAdmin uses
	// this as the fixed primary key so the row is locatable by UUID without
	// an email lookup. Do not use for ordinary operator or org_admin users.
	SiteAdminID = "00000000-0000-7000-0000-000000000001"

	// SiteAdminEmail is the canonical email of the bootstrap site_admin user.
	// cli.RunSetup hardcodes this when calling EnsureSiteAdmin; backup-service
	// row exclusion, cleanup-service compliance fallback, and the
	// IsSystemConfigured lookup all reference it via this constant. Treat it
	// as a wire-format constant — changing the literal requires updating
	// every install's admin row.
	SiteAdminEmail = "site_admin@system.local"

	// LegacySystemOrgID is the pre-migration system org UUID that was used before
	// migrations/0016_bootstrap_v7_sentinel_ids.sql changed it to SystemOrgID.
	// This value must NOT be used as a primary identifier in new code or new rows.
	// It exists solely for backward-compatibility in backup/restore filtering:
	// backup files written before migration 0016 contain this UUID as the system
	// org row identifier, and the restore exclusion logic must recognise both the
	// old and new values to avoid accidentally importing the deprecated bootstrap row.
	//
	// Do not add new references to LegacySystemOrgID outside backup/restore paths.
	LegacySystemOrgID = "00000000-0000-0000-0000-000000000001"

	SystemOrgName = "System Organization"
	// SystemOrgSlug is pinned VERBATIM by AdminPermissionsModel.md:
	// 'System Organization name is "System Organization", slug is: system-local'.
	// OSS previously had no slug constant at all (the System org came back with
	// slug=null over the API) while CE pinned "system-org" — neither matched the
	// model, and they disagreed with each other, which rule one makes a
	// divergence on its own.
	SystemOrgSlug   = "system-local"
	SystemOrgDomain = "system.local"

	// Argon2id Constants
	Argon2Memory  uint32 = 64 * 1024 // 65536 KiB (64 MiB)
	Argon2Time    uint32 = 3         // Iterations
	Argon2Threads uint8  = 4         // Parallelism
	Argon2KeyLen  uint32 = 32
	Argon2SaltLen uint32 = 16

	// MinPasswordLength is the minimum character length enforced for all passwords
	// in the claim/bootstrap flow (and any context where no org policy is available yet).
	MinPasswordLength = 8

	// ClaimMaxPasswordAttempts is the maximum number of failed password submissions
	// allowed before a claim link is permanently burned (deleted from the DB).
	ClaimMaxPasswordAttempts = 3

	// Context Keys
	CtxKeyClaims           = "claims"
	CtxKeyPrincipal        = "principal"
	CtxKeyUserID           = "user_id"
	CtxKeyUserEmail        = "user_email"
	CtxKeyUserRole         = "user_role"
	CtxKeyRole             = "role" // Used historically in test seeding
	CtxKeyOrganizationID   = "organization_id"
	CtxKeyIsServiceAccount = "is_service_account"
	CtxKeyServiceAccountID = "service_account_id"
	CtxKeyRequestID        = "request_id"
	CtxKeyCorrelationID    = "correlation_id"
	CtxKeyScopesChecked    = "scopes_checked"
	CtxKeyDomain           = "domain"
)
