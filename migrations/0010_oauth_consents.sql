-- +goose Up
-- +goose StatementBegin

-- oauth_consents persists remembered OIDC consent grants per
-- (user, client, audience). Granted scope is stored as a
-- space-separated string; the subset-check at /authorize time
-- compares membership token-by-token.
--
-- Rows are immutable in spirit — revoke is a soft delete via
-- revoked_at; re-granting flips revoked_at back to NULL and
-- updates the scope set via UPSERT.
CREATE TABLE oauth_consents (
    id              UUID PRIMARY KEY,
    user_id         UUID NOT NULL,
    organization_id UUID,
    client_id       TEXT NOT NULL,
    audience        TEXT NOT NULL DEFAULT '',
    scope           TEXT NOT NULL DEFAULT '',
    granted_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- One active consent row per (user, client, audience). UPSERT
-- uses this constraint to flip a revoked row back active.
CREATE UNIQUE INDEX uq_oauth_consents_user_client_aud
    ON oauth_consents(user_id, client_id, audience);

-- /api/v1/oauth/authorize lookup path: scoped to a user across all
-- known clients (rare; mostly client-scoped). Kept narrow.
CREATE INDEX idx_oauth_consents_user_id ON oauth_consents(user_id);
CREATE INDEX idx_oauth_consents_client_id ON oauth_consents(client_id);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS oauth_consents;
-- +goose StatementEnd
