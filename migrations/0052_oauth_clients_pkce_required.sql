-- identuum-idp-oss — PKCE is required per client, on by default
-- (OSS-PUBLIC-CLIENT-PKCE-OPTION, owner decision 2026-10-10).
--
-- oauth_clients.pkce_required is true for every client, existing and new.
-- An org_admin may turn it off for one PUBLIC client through the client admin
-- API, so that a test client (the OpenID conformance public-client plan sends
-- no PKCE) can sign in without a code challenge. It is never turned off for a
-- confidential client, never through dynamic registration, and there is no
-- server-wide switch. A challenge that is sent is still S256-only and is
-- still verified at the token endpoint.

-- +goose Up

ALTER TABLE oauth_clients
    ADD COLUMN pkce_required BOOLEAN NOT NULL DEFAULT true;

ALTER TABLE oauth_clients
    ADD CONSTRAINT oauth_clients_pkce_opt_out_public_only
    CHECK (pkce_required OR is_public);

-- +goose Down

ALTER TABLE oauth_clients DROP CONSTRAINT IF EXISTS oauth_clients_pkce_opt_out_public_only;
ALTER TABLE oauth_clients DROP COLUMN IF EXISTS pkce_required;
