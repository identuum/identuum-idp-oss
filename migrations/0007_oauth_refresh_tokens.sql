-- Identuum IdP OSS — OAuth Refresh Tokens
-- Storage foundation for OAuth refresh tokens. Lands the table that
-- backs the OSS refresh_token grant on POST /api/v1/oauth/token plus
-- the refresh-aware path on POST /api/v1/oauth/revoke.
--
-- Wire format on the caller side is `<selector>.<base64url(validator)>`
-- — the same selector / validator split the OSS tools package
-- already exposes via domain.SecureRefreshToken. The selector
-- (UUID) is the primary lookup key; the validator's SHA-256 hex
-- digest is constant-time-compared during consume. The raw
-- validator NEVER lands in the DB.
--
-- IMPORTANT: this slice does NOT cause client_credentials issuance
-- to emit a refresh token. RFC 6749 §4.4.3 forbids it and the
-- monolith does not emit one either. The grant exists so future
-- slices (and tests) can drive it via RefreshTokenService.Issue.

-- +goose Up

CREATE TABLE oauth_refresh_tokens (
    id              UUID         PRIMARY KEY,
    validator_hash  TEXT         NOT NULL,
    client_id       TEXT         NOT NULL,
    client_kind     TEXT         NOT NULL,
    subject         TEXT         NOT NULL,
    scope           TEXT         NOT NULL DEFAULT '',
    audience        TEXT         NOT NULL DEFAULT '',
    expires_at      TIMESTAMPTZ  NOT NULL,
    revoked_at      TIMESTAMPTZ,
    replaced_by     UUID         REFERENCES oauth_refresh_tokens(id) ON DELETE SET NULL,
    access_jti      TEXT,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    last_used_at    TIMESTAMPTZ,
    metadata        JSONB        NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX idx_oauth_refresh_tokens_client_id
    ON oauth_refresh_tokens(client_id);

CREATE INDEX idx_oauth_refresh_tokens_expires_at
    ON oauth_refresh_tokens(expires_at);

CREATE INDEX idx_oauth_refresh_tokens_access_jti
    ON oauth_refresh_tokens(access_jti)
    WHERE access_jti IS NOT NULL;

-- +goose Down
DROP INDEX IF EXISTS idx_oauth_refresh_tokens_access_jti;
DROP INDEX IF EXISTS idx_oauth_refresh_tokens_expires_at;
DROP INDEX IF EXISTS idx_oauth_refresh_tokens_client_id;
DROP TABLE IF EXISTS oauth_refresh_tokens;
