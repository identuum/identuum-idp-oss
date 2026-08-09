-- +goose Up
-- +goose StatementBegin

-- dcr_initial_access_tokens persists per-tenant DCR initial
-- access tokens (RFC 7591 §3 IATs). The raw token bytes are
-- NEVER stored — only a SHA-256 hash (token_hash) used for
-- constant-time lookup. The raw token is returned to the
-- operator exactly once at issuance time.
--
-- Use-counting is in-row: max_uses = 0 means unlimited; any
-- positive value caps the number of successful DCR
-- registrations the token can authorise. uses_count is
-- incremented atomically during consume; consume rejects when
-- uses_count >= max_uses (max_uses > 0).
--
-- Optional constraints:
--   organization_id (nullable)             — when set, the
--     registered client's organization_id MUST equal this value.
--   allowed_grant_types (text[], empty=any) — when non-empty,
--     the DCR request's grant_types MUST be a subset.
--   allowed_token_endpoint_auth_methods    — when non-empty,
--     the DCR request's token_endpoint_auth_method MUST be a
--     member (empty value is treated as the IDP default
--     client_secret_basic for the comparison).
--
-- Lifecycle:
--   expires_at  — past = automatic invalidation.
--   revoked_at  — non-null = manually revoked (highest priority).
--   uses_count  — incremented on each consume.
--
-- IDs are UUIDv7 per Identuum convention. created_by_user_id
-- captures the site_admin actor who issued the IAT for audit
-- correlation.
CREATE TABLE dcr_initial_access_tokens (
    id                                     UUID PRIMARY KEY,
    token_hash                             TEXT NOT NULL UNIQUE,
    organization_id                        UUID,
    allowed_grant_types                    TEXT[] NOT NULL DEFAULT '{}',
    allowed_token_endpoint_auth_methods    TEXT[] NOT NULL DEFAULT '{}',
    expires_at                             TIMESTAMPTZ NOT NULL,
    max_uses                               INTEGER NOT NULL DEFAULT 1,
    uses_count                             INTEGER NOT NULL DEFAULT 0,
    revoked_at                             TIMESTAMPTZ,
    created_by_user_id                     UUID,
    description                            TEXT NOT NULL DEFAULT '',
    created_at                             TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at                             TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT dcr_iat_max_uses_nonneg     CHECK (max_uses >= 0),
    CONSTRAINT dcr_iat_uses_count_nonneg   CHECK (uses_count >= 0)
);

CREATE INDEX idx_dcr_initial_access_tokens_expires_at
    ON dcr_initial_access_tokens(expires_at);
CREATE INDEX idx_dcr_initial_access_tokens_organization_id
    ON dcr_initial_access_tokens(organization_id)
    WHERE organization_id IS NOT NULL;
CREATE INDEX idx_dcr_initial_access_tokens_revoked_at
    ON dcr_initial_access_tokens(revoked_at)
    WHERE revoked_at IS NOT NULL;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS dcr_initial_access_tokens;
-- +goose StatementEnd
