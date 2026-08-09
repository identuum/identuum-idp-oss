-- Identuum IdP OSS — OAuth & OIDC
-- Clean consolidated open-core migration. Authored fresh. Folds in
-- final-state effects from monolith 0002, 0009 (private_key_jwt client
-- authentication columns), and 0010 (broadened signing-alg constraint).
--
-- Targets: oauth_clients (with private_key_jwt columns inline),
-- api_resources (+ scopes), oauth2_consents, auth_codes,
-- oauth_par_requests, oidc_states, scope_templates. Wires the deferred
-- sessions → oauth_clients FK from 0001.

-- +goose Up

-- ============================================================================
-- OAUTH_CLIENTS
-- ============================================================================
-- Final-state shape: monolith 0009 added 4 private_key_jwt columns +
-- 3 constraints; 0010 replaced the signing_alg constraint with the broader
-- 9-algorithm allowlist. Both are inlined here so the OSS CREATE TABLE
-- emits the final shape in one statement.
CREATE TABLE oauth_clients (
    id UUID PRIMARY KEY DEFAULT uuidv7(),
    client_id VARCHAR(255) NOT NULL UNIQUE,
    client_secret_hash VARCHAR(255) NOT NULL,
    name VARCHAR(255) NOT NULL,
    redirect_uris TEXT[] NOT NULL,
    scope TEXT NOT NULL,
    is_public BOOLEAN NOT NULL DEFAULT false,
    service_account_id UUID REFERENCES service_accounts(id) ON DELETE CASCADE,
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    allowed_audiences TEXT[],
    post_logout_redirect_uris TEXT[] DEFAULT '{}'::text[],
    skip_consent BOOLEAN NOT NULL DEFAULT false,
    token_ttl_secs INTEGER,
    -- Folded from monolith 0009 (private_key_jwt support).
    token_endpoint_auth_method TEXT NOT NULL DEFAULT 'client_secret_basic',
    jwks_uri TEXT,
    jwks TEXT,
    -- token_endpoint_auth_signing_alg uses the broadened 9-algorithm
    -- allowlist from monolith 0010 (constraint defined below).
    token_endpoint_auth_signing_alg TEXT NOT NULL DEFAULT 'EdDSA',
    deleted_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- Folded from monolith 0009.
    CONSTRAINT oauth_clients_auth_method_check
        CHECK (token_endpoint_auth_method IN (
            'client_secret_basic',
            'client_secret_post',
            'none',
            'private_key_jwt'
        )),
    -- Folded from monolith 0009. Exactly one key source for private_key_jwt
    -- clients; both columns NULL otherwise.
    CONSTRAINT oauth_clients_pkj_key_source_check
        CHECK (
            CASE token_endpoint_auth_method
                WHEN 'private_key_jwt' THEN
                    (jwks_uri IS NOT NULL) != (jwks IS NOT NULL)
                ELSE
                    jwks_uri IS NULL AND jwks IS NULL
            END
        ),
    -- Final-state from monolith 0010 (9-algorithm allowlist).
    CONSTRAINT oauth_clients_signing_alg_check
        CHECK (token_endpoint_auth_signing_alg IN (
            'EdDSA',
            'ES256',
            'ES384',
            'RS256',
            'RS384',
            'RS512',
            'PS256',
            'PS384',
            'PS512'
        ))
);

CREATE INDEX idx_oauth_clients_client_id ON oauth_clients(client_id);
CREATE INDEX idx_oauth_clients_organization_id ON oauth_clients(organization_id);
CREATE INDEX idx_oauth_clients_service_account_id ON oauth_clients(service_account_id);
CREATE INDEX idx_oauth_clients_deleted_at ON oauth_clients(deleted_at) WHERE deleted_at IS NULL;

-- Wire deferred FK from sessions(client_id) → oauth_clients(client_id).
ALTER TABLE sessions
    ADD CONSTRAINT sessions_client_id_fkey
    FOREIGN KEY (client_id) REFERENCES oauth_clients(client_id) ON DELETE SET NULL;

-- ============================================================================
-- API_RESOURCES + API_RESOURCE_SCOPES
-- ============================================================================
CREATE TABLE api_resources (
    id UUID PRIMARY KEY DEFAULT uuidv7(),
    org_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    audience VARCHAR(255) NOT NULL,
    active BOOLEAN DEFAULT true,
    token_ttl_secs INTEGER NOT NULL DEFAULT 3600,
    resource_secret_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT unique_org_audience UNIQUE (org_id, audience)
);

CREATE INDEX idx_api_resources_audience ON api_resources(audience);

CREATE TABLE api_resource_scopes (
    id UUID PRIMARY KEY DEFAULT uuidv7(),
    resource_id UUID REFERENCES api_resources(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    CONSTRAINT unique_resource_scope_name UNIQUE (resource_id, name)
);

-- ============================================================================
-- OAUTH2_CONSENTS  (per-user consent records)
-- ============================================================================
CREATE TABLE oauth2_consents (
    id UUID PRIMARY KEY DEFAULT uuidv7(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_id UUID NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
    api_resource_id UUID REFERENCES api_resources(id) ON DELETE CASCADE,
    scope TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT oauth2_consents_user_id_client_id_key
        UNIQUE NULLS NOT DISTINCT (user_id, client_id, api_resource_id)
);

-- ============================================================================
-- AUTH_CODES
-- ============================================================================
CREATE TABLE auth_codes (
    code VARCHAR(255) PRIMARY KEY,
    client_id VARCHAR(255) NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    scope TEXT NOT NULL,
    redirect_uri TEXT NOT NULL,
    nonce TEXT,
    code_challenge VARCHAR(255),
    code_challenge_method VARCHAR(10) DEFAULT 'plain',
    audience VARCHAR(255),
    session_id TEXT,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT chk_auth_code_not_empty CHECK (length(trim(code)) > 0)
);

CREATE INDEX idx_auth_codes_expires_at ON auth_codes(expires_at);
CREATE INDEX idx_auth_codes_session_id ON auth_codes(session_id);

-- ============================================================================
-- OAUTH_PAR_REQUESTS  (RFC 9126 pushed authorization requests)
-- ============================================================================
CREATE TABLE oauth_par_requests (
    request_uri VARCHAR(255) PRIMARY KEY,
    client_id VARCHAR(255) NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
    request_object JSONB NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_oauth_par_expires_at ON oauth_par_requests(expires_at);

-- ============================================================================
-- OIDC_STATES  (provider_id FK to identity_providers wired in 0003)
-- ============================================================================
CREATE TABLE oidc_states (
    state TEXT PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    provider_id UUID NOT NULL,
    nonce TEXT NOT NULL,
    pkce_verifier_encrypted TEXT NOT NULL,
    redirect_uri TEXT NOT NULL,
    code_challenge_method VARCHAR DEFAULT 'S256' NOT NULL,
    return_url TEXT NOT NULL DEFAULT '',
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_oidc_states_expires_at ON oidc_states(expires_at);

-- ============================================================================
-- SCOPE_TEMPLATES
-- ============================================================================
CREATE TABLE scope_templates (
    id UUID PRIMARY KEY DEFAULT uuidv7(),
    org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    scopes TEXT[] NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT unique_org_template_name UNIQUE (org_id, name)
);

CREATE INDEX idx_scope_templates_org ON scope_templates(org_id);

-- +goose Down
DROP TABLE IF EXISTS scope_templates CASCADE;
DROP TABLE IF EXISTS oidc_states CASCADE;
DROP TABLE IF EXISTS oauth_par_requests CASCADE;
DROP TABLE IF EXISTS auth_codes CASCADE;
DROP TABLE IF EXISTS oauth2_consents CASCADE;
DROP TABLE IF EXISTS api_resource_scopes CASCADE;
DROP TABLE IF EXISTS api_resources CASCADE;
ALTER TABLE sessions DROP CONSTRAINT IF EXISTS sessions_client_id_fkey;
DROP TABLE IF EXISTS oauth_clients CASCADE;
