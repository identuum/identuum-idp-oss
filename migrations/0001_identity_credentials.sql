-- Identuum IdP OSS — Identity & Credentials
-- Clean consolidated open-core migration. Authored fresh (NOT a copy of any
-- single monolith migration). Folds in final-state effects from monolith
-- 0001, 0012 (claim target_email), 0013 (claim email_bound), 0014 (webauthn
-- nickname), 0015 (sessions device metadata), and 0018 (organizations
-- e2e_fixture_marker).
--
-- Final-state omissions vs. monolith 0001:
--   users.allow_agent_issuance        (dropped in monolith 0007)
--   users.foreign_idp_issuer          (dropped in monolith 0006)
--   idx_users_org_foreign_idp_external_id
--   ux_users_org_foreign_idp_external_id
--   service_accounts.can_issue_agent_tokens (dropped in monolith 0007)
--   service_accounts.origin_peer_id    (SPIFFE; CE overlay)
--   service_accounts.origin_spiffe_id  (SPIFFE; CE overlay)
--   service_accounts_origin_pair_chk   (SPIFFE; CE overlay)
--   ix_service_accounts_org_spiffe_id  (SPIFFE; CE overlay)
--
-- System Organization is inserted with the v7 sentinel UUID directly
-- (00000000-0000-7000-0000-000000000000), so this OSS history does not need
-- the temp-row dance from monolith 0016 + 0017.
--
-- Targets: organizations, users, sessions, webauthn_credentials,
-- password_resets, service_accounts, organization_claims.
-- PG18+ uuidv7() built-in is required.

-- +goose Up

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TYPE user_role AS ENUM ('org_user', 'org_admin', 'site_admin');

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION set_organizations_updated_at()
    RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

-- ============================================================================
-- ORGANIZATIONS
-- ============================================================================
-- CE-feature columns (tier, m2m_anomaly_limit, m2m_anomaly_window_seconds,
-- last_scim_sync_at, compliance_contact_email, require_strict_reauth,
-- local_admin_only) are retained on the OSS table so OSS and CE share an
-- identical row shape during the open-core split. OSS code does not read
-- these columns; they sit at default values on every OSS row.
CREATE TABLE organizations (
    id UUID PRIMARY KEY DEFAULT uuidv7(),
    name VARCHAR(255) NOT NULL,
    domain VARCHAR(255) NOT NULL UNIQUE,
    org_slug VARCHAR(255) NOT NULL UNIQUE,
    active BOOLEAN NOT NULL DEFAULT true,
    deleted_at TIMESTAMPTZ,
    max_sessions_per_user INTEGER NOT NULL DEFAULT 5,
    mfa_policy VARCHAR(20) NOT NULL DEFAULT 'optional',
    auth_policy VARCHAR(50) NOT NULL DEFAULT 'mixed',
    api_authorization_policy VARCHAR(50) NOT NULL DEFAULT 'strict',
    service_account_expiry_days INTEGER NOT NULL DEFAULT 365,
    allow_public_registration BOOLEAN NOT NULL DEFAULT false,
    require_registration_approval BOOLEAN NOT NULL DEFAULT false,
    m2m_anomaly_limit INTEGER NOT NULL DEFAULT 100,
    m2m_anomaly_window_seconds INTEGER NOT NULL DEFAULT 60,
    require_strict_reauth BOOLEAN NOT NULL DEFAULT false,
    tier VARCHAR(50) NOT NULL DEFAULT 'TierBase',
    local_admin_only BOOLEAN NOT NULL DEFAULT true,
    password_complexity_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    compliance_contact_email VARCHAR(255),
    last_scim_sync_at TIMESTAMPTZ,
    -- Folded from monolith 0018: marker column populated only by the
    -- local --e2e-create-org-admin-fixture CLI for hard-delete-safe
    -- identification of fixture rows. NULL on every production org.
    e2e_fixture_marker TEXT DEFAULT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_organization_name_not_empty CHECK (length(trim(name)) > 0),
    CONSTRAINT chk_organization_domain_not_empty CHECK (length(trim(domain)) > 0),
    CONSTRAINT chk_organization_org_slug_not_empty CHECK (length(trim(org_slug)) > 0),
    CONSTRAINT chk_max_sessions_positive CHECK (max_sessions_per_user > 0),
    CONSTRAINT organizations_mfa_policy_check CHECK (mfa_policy IN ('optional', 'required')),
    CONSTRAINT check_service_account_expiry_days CHECK (service_account_expiry_days >= 0 AND service_account_expiry_days <= 3650)
);

CREATE INDEX idx_organizations_active ON organizations(active);
CREATE INDEX idx_organizations_deleted_at ON organizations(deleted_at) WHERE deleted_at IS NULL;
CREATE INDEX idx_organizations_domain ON organizations(domain);
CREATE INDEX idx_organizations_org_slug ON organizations(org_slug);
CREATE INDEX idx_organizations_created_at ON organizations(created_at);
CREATE INDEX idx_organizations_updated_at ON organizations(updated_at DESC);
-- Folded from monolith 0018: partial index supporting fast e2e-fixture purge.
CREATE INDEX idx_organizations_e2e_fixture_marker
    ON organizations(e2e_fixture_marker)
    WHERE e2e_fixture_marker IS NOT NULL;

CREATE TRIGGER trg_organizations_updated_at
    BEFORE UPDATE ON organizations
    FOR EACH ROW EXECUTE FUNCTION set_organizations_updated_at();

-- System Organization. OSS uses the v7 sentinel UUID
-- (00000000-0000-7000-0000-000000000000 = domain.SystemOrgID) from the
-- start, so the monolith 0016 + 0017 sentinel-migration dance is unneeded.
-- Seed defaults (mfa_policy='required', max_sessions_per_user=20) match
-- the monolith conventions. site_admin@system.local is bootstrapped at
-- first boot by cli.RunSetup with the v7 sentinel domain.SiteAdminID.
INSERT INTO organizations (id, name, domain, org_slug, active, max_sessions_per_user, mfa_policy)
VALUES ('00000000-0000-7000-0000-000000000000', 'System Organization', 'system.local', 'system-local', true, 20, 'required');

-- ============================================================================
-- USERS
-- ============================================================================
-- Final-state shape: agentic columns (allow_agent_issuance, foreign_idp_issuer)
-- and their indexes are deliberately omitted (dropped in monolith 0006 + 0007).
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuidv7(),
    email VARCHAR(255) NOT NULL,
    name VARCHAR(255),
    password_hash VARCHAR(255) NOT NULL,
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE ON UPDATE CASCADE,
    role user_role NOT NULL DEFAULT 'org_user',
    banned BOOLEAN NOT NULL DEFAULT false,
    email_verified BOOLEAN NOT NULL DEFAULT false,
    deleted_at TIMESTAMPTZ,
    mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    mfa_secret TEXT,
    mfa_recovery_codes JSONB,
    auth_source VARCHAR(50) NOT NULL DEFAULT 'local',
    external_id TEXT,
    requires_password_change BOOLEAN NOT NULL DEFAULT false,
    oidc_linked BOOLEAN NOT NULL DEFAULT false,
    oidc_issuer VARCHAR(255),
    activation_token_expires_at TIMESTAMPTZ,
    activation_token_hash VARCHAR(64),
    verification_token_hash VARCHAR(64),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_login_at TIMESTAMPTZ,

    CONSTRAINT chk_user_email_format CHECK (email ~* '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$'),
    CONSTRAINT chk_user_password_hash_not_empty CHECK (length(trim(password_hash)) > 0),
    CONSTRAINT chk_users_org_id_not_null CHECK (role = 'site_admin' OR organization_id IS NOT NULL)
);

CREATE INDEX idx_users_name ON users(name);
CREATE INDEX idx_users_organization_id ON users(organization_id);
CREATE INDEX idx_users_role ON users(role);
CREATE INDEX idx_users_banned ON users(banned);
CREATE INDEX idx_users_deleted_at ON users(deleted_at) WHERE deleted_at IS NULL;
CREATE INDEX idx_users_created_at ON users(created_at);
CREATE INDEX idx_users_last_login ON users(last_login_at) WHERE last_login_at IS NOT NULL;
CREATE INDEX idx_users_active_not_deleted ON users(banned, deleted_at) WHERE banned = false AND deleted_at IS NULL;
CREATE INDEX idx_users_org_role ON users(organization_id, role);
CREATE INDEX idx_users_activation_token_hash ON users(activation_token_hash) WHERE activation_token_hash IS NOT NULL;
CREATE INDEX idx_users_verification_token_hash ON users(verification_token_hash) WHERE verification_token_hash IS NOT NULL;

CREATE UNIQUE INDEX users_organization_id_email_key_undeleted
    ON users(organization_id, email) WHERE deleted_at IS NULL;
CREATE UNIQUE INDEX idx_users_org_auth_external_id
    ON users(organization_id, auth_source, external_id) WHERE external_id IS NOT NULL AND deleted_at IS NULL;
CREATE UNIQUE INDEX idx_single_site_admin ON users(role) WHERE role = 'site_admin';

-- ============================================================================
-- SERVICE_ACCOUNTS
-- ============================================================================
-- Final-state shape: can_issue_agent_tokens (dropped in monolith 0007) and
-- the SPIFFE columns (origin_peer_id, origin_spiffe_id) are deliberately
-- omitted from the OSS schema. The OSS domain.ServiceAccount Go struct
-- currently still carries the SPIFFE field pointers (deferred Go cleanup;
-- see open-core notes); SELECT/INSERT statements that reference those
-- columns will not function against this OSS-only schema until either
-- (a) the OSS Go code is trimmed to omit them, or (b) the CE overlay
-- migration adds them via ALTER TABLE. This is the documented runtime
-- gap for the open-core split.
CREATE TABLE service_accounts (
    id UUID PRIMARY KEY DEFAULT uuidv7(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    active BOOLEAN NOT NULL DEFAULT true,
    deleted_at TIMESTAMPTZ,
    role VARCHAR(32) NOT NULL DEFAULT 'org_admin',
    owner_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,

    CONSTRAINT chk_sa_name_not_empty CHECK (length(trim(name)) > 0)
);

CREATE INDEX idx_sa_organization_id ON service_accounts(organization_id);
CREATE INDEX idx_sa_active ON service_accounts(active);
CREATE INDEX idx_sa_deleted_at ON service_accounts(deleted_at) WHERE deleted_at IS NULL;
CREATE INDEX idx_sa_owner_user_id ON service_accounts(owner_user_id) WHERE owner_user_id IS NOT NULL;

-- ============================================================================
-- SESSIONS  (oauth_clients FK is wired in 0002 after oauth_clients exists)
-- ============================================================================
-- Final-state shape: includes ip_address + user_agent device-metadata
-- columns folded from monolith 0015.
CREATE TABLE sessions (
    id UUID PRIMARY KEY DEFAULT uuidv7(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_selector UUID NOT NULL,
    token_validator_hash VARCHAR(255) NOT NULL,
    client_id VARCHAR(255),
    acr VARCHAR(50) DEFAULT '0',
    amr TEXT DEFAULT 'pwd',
    last_acr_uplift_at TIMESTAMPTZ,
    last_acr_uplift_value TEXT,
    remember_me BOOLEAN NOT NULL DEFAULT false,
    is_valid BOOLEAN NOT NULL DEFAULT true,
    revoked_at TIMESTAMPTZ,
    revoked_reason VARCHAR(100),
    -- Folded from monolith 0015. Nullable: not populated for sessions
    -- created in paths without request context.
    ip_address TEXT,
    user_agent TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMPTZ NOT NULL,
    last_used_at TIMESTAMPTZ,

    CONSTRAINT chk_expires_after_created CHECK (expires_at > created_at),
    CONSTRAINT chk_last_used_after_created CHECK (last_used_at IS NULL OR last_used_at >= created_at),
    CONSTRAINT chk_revoked_after_created CHECK (revoked_at IS NULL OR revoked_at >= created_at),
    CONSTRAINT chk_token_validator_hash_not_empty CHECK (token_validator_hash IS NOT NULL AND length(token_validator_hash) > 0),
    CONSTRAINT chk_sessions_acr_uplift_paired CHECK (
        (last_acr_uplift_at IS NULL AND last_acr_uplift_value IS NULL)
        OR (last_acr_uplift_at IS NOT NULL AND last_acr_uplift_value IS NOT NULL)
    )
);

CREATE INDEX idx_sessions_cleanup_composite ON sessions(expires_at, revoked_at);
CREATE INDEX idx_sessions_created_at ON sessions(created_at);
CREATE INDEX idx_sessions_expires_at ON sessions(expires_at);
CREATE INDEX idx_sessions_revoked ON sessions(revoked_at) WHERE revoked_at IS NOT NULL;
CREATE INDEX idx_sessions_user_id ON sessions(user_id);
CREATE INDEX idx_sessions_client_id ON sessions(client_id) WHERE client_id IS NOT NULL;

-- ============================================================================
-- WEBAUTHN_CREDENTIALS
-- ============================================================================
-- Final-state shape: includes nickname column folded from monolith 0014.
CREATE TABLE webauthn_credentials (
    id UUID PRIMARY KEY DEFAULT uuidv7(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    credential_id BYTEA NOT NULL,
    public_key BYTEA NOT NULL,
    attestation_type VARCHAR(50) NOT NULL,
    transport VARCHAR[],
    aaguid UUID,
    sign_count INTEGER NOT NULL DEFAULT 0,
    clone_warning BOOLEAN NOT NULL DEFAULT false,
    backup_eligible BOOLEAN NOT NULL DEFAULT false,
    backup_state BOOLEAN NOT NULL DEFAULT false,
    -- Folded from monolith 0014. User-editable display label so users can
    -- distinguish multiple enrolled keys.
    nickname VARCHAR(80) NOT NULL DEFAULT 'Device passkey',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at TIMESTAMPTZ,
    deleted_at TIMESTAMPTZ
);

CREATE UNIQUE INDEX idx_webauthn_credential_id_active ON webauthn_credentials(credential_id) WHERE deleted_at IS NULL;
CREATE INDEX idx_webauthn_org_id ON webauthn_credentials(organization_id);
CREATE INDEX idx_webauthn_user_id ON webauthn_credentials(user_id);

-- ============================================================================
-- PASSWORD_RESETS
-- ============================================================================
CREATE TABLE password_resets (
    token_hash VARCHAR(255) PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    used_at TIMESTAMPTZ
);

CREATE INDEX idx_password_resets_user_id ON password_resets(user_id);
CREATE INDEX idx_password_resets_expires_at ON password_resets(expires_at);

-- ============================================================================
-- ORGANIZATION_CLAIMS  (invitation / auto-claim tokens)
-- ============================================================================
-- Final-state shape: includes target_email (folded from monolith 0012) and
-- email_bound (folded from monolith 0013). email_bound defaults to TRUE so
-- the historical behavior is preserved; no-email tokens set it to FALSE.
CREATE TABLE organization_claims (
    id UUID PRIMARY KEY DEFAULT uuidv7(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    token_hash VARCHAR(255) NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    attempt_count INT NOT NULL DEFAULT 0,
    -- Folded from monolith 0012. Binds each delegation URL to exactly one
    -- intended recipient. Nullable so the no-email token shape (with
    -- email_bound=FALSE below) still applies.
    target_email TEXT,
    -- Folded from monolith 0013. TRUE on pre-existing rows preserves the
    -- historical email-bound behavior; the service layer sets it FALSE
    -- when issuing a no-email token.
    email_bound BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT chk_claim_expires_after_created CHECK (expires_at > created_at)
);

CREATE INDEX idx_organization_claims_org_id ON organization_claims(organization_id);
CREATE INDEX idx_organization_claims_expires_at ON organization_claims(expires_at);

-- +goose Down
DROP TABLE IF EXISTS organization_claims CASCADE;
DROP TABLE IF EXISTS password_resets CASCADE;
DROP TABLE IF EXISTS webauthn_credentials CASCADE;
DROP TABLE IF EXISTS sessions CASCADE;
DROP TABLE IF EXISTS service_accounts CASCADE;
DROP TABLE IF EXISTS users CASCADE;
DROP TRIGGER IF EXISTS trg_organizations_updated_at ON organizations;
DROP INDEX IF EXISTS idx_organizations_e2e_fixture_marker;
DROP TABLE IF EXISTS organizations CASCADE;
DROP FUNCTION IF EXISTS set_organizations_updated_at();
DROP TYPE IF EXISTS user_role;
DROP EXTENSION IF EXISTS "uuid-ossp";
