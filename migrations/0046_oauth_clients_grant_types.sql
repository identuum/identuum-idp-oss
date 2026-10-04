-- identuum-idp-oss — the grant types a client registered are stored and enforced.
--
-- oauth_clients.grant_types holds the RFC 7591 grant_types an app registered
-- through POST /api/v1/oauth/register (authorization_code when it asked for
-- nothing). The token endpoint refuses a grant outside the set with
-- unauthorized_client.
--
-- NULL means unrestricted: an app created in the console, and every app
-- registered before this column existed, keeps using whatever grant it already
-- used. Nothing is backfilled, because the grant types an earlier registration
-- asked for were never stored.

-- +goose Up

ALTER TABLE oauth_clients
    ADD COLUMN grant_types TEXT[];

ALTER TABLE oauth_clients
    ADD CONSTRAINT oauth_clients_grant_types_known
    CHECK (grant_types IS NULL OR grant_types <@ ARRAY['authorization_code', 'refresh_token', 'client_credentials']::text[]);

-- +goose Down

ALTER TABLE oauth_clients DROP CONSTRAINT IF EXISTS oauth_clients_grant_types_known;
ALTER TABLE oauth_clients DROP COLUMN IF EXISTS grant_types;
