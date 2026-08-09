-- +goose Up
-- +goose StatementBegin

-- browser_session_tokens is the OSS cookie-indirection table. The
-- browser cookie value is a high-entropy opaque token; only its
-- SHA-256 hex digest is stored in `token_hash`. Resolution maps a
-- presented cookie back to a `sessions.id` row. A leak of the
-- table contents does NOT yield the refresh token — the indirection
-- breaks the prior "cookie value == refresh token wire shape"
-- coupling.
CREATE TABLE browser_session_tokens (
    id              UUID PRIMARY KEY,
    session_id      UUID NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    user_id         UUID NOT NULL,
    organization_id UUID,
    token_hash      TEXT NOT NULL UNIQUE,
    user_agent      TEXT NOT NULL DEFAULT '',
    ip_address      TEXT NOT NULL DEFAULT '',
    expires_at      TIMESTAMPTZ NOT NULL,
    revoked_at      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at    TIMESTAMPTZ
);

CREATE INDEX idx_browser_session_tokens_session_id
    ON browser_session_tokens(session_id);
CREATE INDEX idx_browser_session_tokens_user_id
    ON browser_session_tokens(user_id);
CREATE INDEX idx_browser_session_tokens_expires_at
    ON browser_session_tokens(expires_at);

-- Per-client logout metadata. OIDC Front-Channel Logout 1.0 +
-- Back-Channel Logout 1.0 require the RP to register its logout
-- URIs with the OP; OSS adds the four columns here and lets the
-- admin DTOs surface them. NULL means "this client does NOT
-- participate in that logout channel".
ALTER TABLE oauth_clients
    ADD COLUMN IF NOT EXISTS frontchannel_logout_uri TEXT,
    ADD COLUMN IF NOT EXISTS frontchannel_logout_session_required BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS backchannel_logout_uri TEXT,
    ADD COLUMN IF NOT EXISTS backchannel_logout_session_required BOOLEAN NOT NULL DEFAULT FALSE;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE oauth_clients
    DROP COLUMN IF EXISTS frontchannel_logout_uri,
    DROP COLUMN IF EXISTS frontchannel_logout_session_required,
    DROP COLUMN IF EXISTS backchannel_logout_uri,
    DROP COLUMN IF EXISTS backchannel_logout_session_required;

DROP TABLE IF EXISTS browser_session_tokens;
-- +goose StatementEnd
