-- Identuum IdP OSS — OAuth Token Revocations
-- Persistent jti-based revocation store for OSS-issued
-- client_credentials access tokens. Lands the database side of the
-- RFC 7009 §2.2 revocation contract: POST /api/v1/oauth/revoke now
-- writes a row keyed by the token's jti, and POST
-- /api/v1/oauth/introspection consults the same row before
-- returning active:true. Rows expire naturally at the token's exp;
-- a cleanup pass driven by the service layer removes expired
-- entries.
--
-- The table is intentionally narrow: no token text, no client_secret,
-- no signing material, no audience leak. The metadata column is a
-- bounded JSONB blob for safe operator-facing fields (client_id,
-- client_kind); the service layer enforces what may land there.

-- +goose Up

CREATE TABLE oauth_token_revocations (
    jti         TEXT        PRIMARY KEY,
    expires_at  TIMESTAMPTZ NOT NULL,
    reason      TEXT        NOT NULL,
    metadata    JSONB       NOT NULL DEFAULT '{}'::jsonb,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Cleanup driver index: the service layer prunes rows whose
-- expires_at is already in the past, so the column needs a btree
-- for range-deletes.
CREATE INDEX idx_oauth_token_revocations_expires_at
    ON oauth_token_revocations(expires_at);

-- +goose Down
DROP INDEX IF EXISTS idx_oauth_token_revocations_expires_at;
DROP TABLE IF EXISTS oauth_token_revocations;
