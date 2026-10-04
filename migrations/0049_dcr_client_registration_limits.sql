-- identuum-idp-oss — the limits an initial access token set on the client it
-- registered.
--
-- An initial access token can limit the grant types and the token-endpoint
-- auth methods of the client registered with it (RFC 7591 §3). Nothing kept
-- those limits with the client, so an RFC 7592 update could add what the
-- registration could not. The registration now records them here, one row per
-- client registered with a limiting token, and the update is judged against
-- them. A NULL list means the token set no limit of that kind. The row goes
-- with its client (ON DELETE CASCADE); the registration access token's own row
-- is rotated by delete-and-insert, so the limits live apart from it.

-- +goose Up

CREATE TABLE dcr_client_registration_limits (
    client_id                           UUID        PRIMARY KEY REFERENCES oauth_clients(id) ON DELETE CASCADE,
    allowed_grant_types                 TEXT[],
    allowed_token_endpoint_auth_methods TEXT[],
    created_at                          TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- +goose Down

DROP TABLE IF EXISTS dcr_client_registration_limits;
