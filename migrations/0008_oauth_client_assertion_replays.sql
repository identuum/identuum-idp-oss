-- Identuum IdP OSS — Client Assertion Replay Protection
-- Persistent replay store for RFC 7523 / OIDC Core §9 private_key_jwt
-- client assertions. Closes the deferred replay-defense gap from the
-- prior JWT-client-auth slice.
--
-- Wire contract: ClientAssertionValidator computes
--   jti_hash = sha256_hex(jti)
-- and atomically inserts (client_id, jti_hash) with the assertion's exp
-- as the row's expires_at. The primary key collision IS the replay
-- detection — the service treats a no-op insert as ErrClientAssertionInvalid.
--
-- Notes:
--   - The raw jti value is NEVER stored. Only the SHA-256 hex digest.
--   - client_id is namespaced into the PK so two distinct clients minting
--     assertions with the same jti DO NOT collide.
--   - A separate index on expires_at drives the cleanup sweep.

-- +goose Up

CREATE TABLE oauth_client_assertion_replays (
    client_id    TEXT        NOT NULL,
    jti_hash     TEXT        NOT NULL,
    expires_at   TIMESTAMPTZ NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (client_id, jti_hash)
);

CREATE INDEX idx_oauth_client_assertion_replays_expires_at
    ON oauth_client_assertion_replays(expires_at);

-- +goose Down
DROP INDEX IF EXISTS idx_oauth_client_assertion_replays_expires_at;
DROP TABLE IF EXISTS oauth_client_assertion_replays;
