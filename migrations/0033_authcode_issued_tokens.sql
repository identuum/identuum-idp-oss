-- identuum-idp-oss — record what an authorization_code exchange minted
-- (THE-CODE-REUSE-REVOKER).
--
-- RFC 6749 §4.1.2: "If an authorization code is used more than once, the
-- authorization server MUST deny the request and SHOULD revoke (when
-- possible) all tokens previously issued based on that authorization code."
-- The consume path already detects the replay (P0-1b) and fires the
-- AuthCodeReuseRevoker seam, but the code row recorded NOTHING about what
-- the first exchange minted, so there was nothing to revoke. These three
-- nullable columns are written once, by the token endpoint, right after the
-- access token (and, with offline_access, the refresh token) are minted:
--
--   issued_access_jti         the access token's jti — revoked through the
--                             EXISTING oauth_token_revocations path
--   issued_access_expires_at  the access token's exp, so the revocation row
--                             can be pruned with the token it fences
--   issued_refresh_token_id   the refresh token's selector (oauth_refresh_tokens.id)
--                             — its whole rotation family is revoked
--
-- NULL means "nothing recorded" (legacy rows, or an exchange that failed
-- after consume); the revoker treats NULL as nothing to revoke.
--
-- +goose Up
-- +goose StatementBegin
ALTER TABLE oauth_authorization_codes
    ADD COLUMN IF NOT EXISTS issued_access_jti        TEXT,
    ADD COLUMN IF NOT EXISTS issued_access_expires_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS issued_refresh_token_id  UUID;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE oauth_authorization_codes
    DROP COLUMN IF EXISTS issued_refresh_token_id,
    DROP COLUMN IF EXISTS issued_access_expires_at,
    DROP COLUMN IF EXISTS issued_access_jti;
-- +goose StatementEnd
