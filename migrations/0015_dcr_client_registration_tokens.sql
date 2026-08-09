-- +goose Up
-- +goose StatementBegin

-- dcr_client_registration_tokens stores the RFC 7592
-- registration_access_token (RAT) issued to a client at the time
-- of dynamic registration. The raw RAT bytes are NEVER stored —
-- only a SHA-256 hash. The raw RAT is returned to the registering
-- client exactly once in the DCR response, alongside the
-- registration_client_uri.
--
-- The presence of a row in this table is also the marker that
-- distinguishes a DCR-created client from a site-admin-created
-- client. Site-admin-created clients have no RAT row and cannot
-- be managed through the /api/v1/oauth/register/:client_id
-- surface — they are managed only through /api/v1/clients.
--
-- One row per client. The primary key is client_id (the
-- oauth_clients.id UUIDv7) so a single client carries at most one
-- active RAT at a time. Rotation is implemented as
-- DELETE + INSERT inside a single transaction.
--
-- ON DELETE CASCADE removes the RAT row automatically when the
-- underlying client is deleted, so a stale RAT row cannot
-- outlive its client.
CREATE TABLE dcr_client_registration_tokens (
    client_id    UUID PRIMARY KEY REFERENCES oauth_clients(id) ON DELETE CASCADE,
    token_hash   TEXT NOT NULL UNIQUE,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS dcr_client_registration_tokens;
-- +goose StatementEnd
