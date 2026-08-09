-- Identuum IdP OSS — Identity Providers & RBAC
-- Clean consolidated open-core migration. Authored fresh from the core
-- portion of monolith 0003. Deliberately omits the SPIFFE federation
-- subsystem (spiffe_federation_peers, spiffe_trust_bundles,
-- spiffe_mapping_rules and the deferred service_accounts.origin_peer_id
-- FK) — those belong to the CE overlay (CE 0003).
--
-- Targets: identity_providers, org_roles, org_role_scopes, user_roles.
-- Wires the deferred oidc_states → identity_providers FK from 0002.

-- +goose Up

-- ============================================================================
-- IDENTITY_PROVIDERS
-- ============================================================================
CREATE TABLE identity_providers (
    id UUID PRIMARY KEY DEFAULT uuidv7(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    type VARCHAR NOT NULL,
    priority INTEGER NOT NULL DEFAULT 0,
    name VARCHAR NOT NULL,
    slug VARCHAR NOT NULL,
    active BOOLEAN NOT NULL DEFAULT true,
    config JSONB NOT NULL DEFAULT '{}'::jsonb,
    deleted_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT identity_providers_org_slug_key UNIQUE (organization_id, slug),
    CONSTRAINT identity_providers_org_type_priority_key UNIQUE (organization_id, type, priority)
);

CREATE INDEX idx_identity_providers_org_active ON identity_providers(organization_id, active);
CREATE INDEX idx_identity_providers_deleted_at ON identity_providers(deleted_at) WHERE deleted_at IS NULL;

-- Wire deferred FK from oidc_states(provider_id) → identity_providers(id).
ALTER TABLE oidc_states
    ADD CONSTRAINT oidc_states_provider_id_fkey
    FOREIGN KEY (provider_id) REFERENCES identity_providers(id) ON DELETE CASCADE;

-- ============================================================================
-- ORG_ROLES + ORG_ROLE_SCOPES + USER_ROLES
-- ============================================================================
CREATE TABLE org_roles (
    id UUID PRIMARY KEY DEFAULT uuidv7(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_org_role_name UNIQUE (org_id, name)
);

CREATE INDEX idx_org_roles_org ON org_roles(org_id);

CREATE TABLE org_role_scopes (
    id UUID PRIMARY KEY DEFAULT uuidv7(),
    role_id UUID NOT NULL REFERENCES org_roles(id) ON DELETE CASCADE,
    resource_id UUID NOT NULL REFERENCES api_resources(id) ON DELETE CASCADE,
    scope_name VARCHAR(255) NOT NULL,
    CONSTRAINT uq_role_scope UNIQUE (role_id, scope_name)
);

CREATE INDEX idx_org_role_scopes_role ON org_role_scopes(role_id);

CREATE TABLE user_roles (
    id UUID PRIMARY KEY DEFAULT uuidv7(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id UUID NOT NULL REFERENCES org_roles(id) ON DELETE CASCADE,
    assigned_by UUID REFERENCES users(id) ON DELETE SET NULL,
    assigned_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_user_role UNIQUE (user_id, role_id)
);

CREATE INDEX idx_user_roles_user ON user_roles(user_id);

-- +goose Down
DROP TABLE IF EXISTS user_roles CASCADE;
DROP TABLE IF EXISTS org_role_scopes CASCADE;
DROP TABLE IF EXISTS org_roles CASCADE;
ALTER TABLE oidc_states DROP CONSTRAINT IF EXISTS oidc_states_provider_id_fkey;
DROP TABLE IF EXISTS identity_providers CASCADE;
