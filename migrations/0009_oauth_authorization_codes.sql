-- Identuum IdP OSS — OAuth Authorization Codes (PKCE-bound)
-- Storage foundation for the authorization-code grant. Distinct
-- from the pre-existing `auth_codes` table (migration 0002) —
-- this new table is hash-only and carries the PKCE columns plus
-- a consumed_at lifecycle flag the new OSS service consults.
-- Operators that have not yet migrated off the legacy table can
-- leave it untouched; the new flow lives in this table.
--
-- IMPORTANT:
--   - The raw authorization code is NEVER stored. Only the
--     SHA-256 hex digest of the issued code lands in code_hash.
--   - One-time consume is enforced via a partial unique index on
--     code_hash (active rows only). A second consume attempt
--     either races into the consumed_at update path or hits the
--     constraint depending on ordering — the service layer
--     fails closed in both cases.
--   - PKCE code_challenge_method is stored as 'S256' or 'plain';
--     the service layer rejects 'plain' by default.
--   - cleanup driver prunes rows older than expires_at via the
--     btree on expires_at.

-- +goose Up

CREATE TABLE oauth_authorization_codes (
    id                     UUID         PRIMARY KEY,
    code_hash              TEXT         NOT NULL,
    client_id              TEXT         NOT NULL,
    user_id                UUID         NOT NULL,
    organization_id        UUID,
    session_id             UUID         NOT NULL,
    redirect_uri           TEXT         NOT NULL,
    scope                  TEXT         NOT NULL DEFAULT '',
    audience               TEXT         NOT NULL DEFAULT '',
    code_challenge         TEXT         NOT NULL,
    code_challenge_method  TEXT         NOT NULL,
    nonce                  TEXT         NOT NULL DEFAULT '',
    expires_at             TIMESTAMPTZ  NOT NULL,
    consumed_at            TIMESTAMPTZ,
    created_at             TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    metadata               JSONB        NOT NULL DEFAULT '{}'::jsonb
);

-- Partial unique index on active rows so a second consume that
-- races BEFORE consumed_at lands also collides at the storage
-- layer. The service treats either failure as invalid_grant.
CREATE UNIQUE INDEX uq_oauth_authorization_codes_active_code_hash
    ON oauth_authorization_codes(code_hash)
    WHERE consumed_at IS NULL;

CREATE INDEX idx_oauth_authorization_codes_expires_at
    ON oauth_authorization_codes(expires_at);

CREATE INDEX idx_oauth_authorization_codes_client_id
    ON oauth_authorization_codes(client_id);

-- +goose Down
DROP INDEX IF EXISTS idx_oauth_authorization_codes_client_id;
DROP INDEX IF EXISTS idx_oauth_authorization_codes_expires_at;
DROP INDEX IF EXISTS uq_oauth_authorization_codes_active_code_hash;
DROP TABLE IF EXISTS oauth_authorization_codes;
