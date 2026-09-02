-- identuum-idp-oss — OIDC Core §5.5 `claims` request parameter
-- (THE-CLAIMS-PARAMETER).
--
-- A client may ask for individual identity claims (name, email,
-- email_verified) for the userinfo response and/or the id_token. Consent
-- must cover them and they are released only when consented AND the role
-- permits (TOKEN-SCOPE-INTERSECTION-1 semantics extended to claims).
--
--   oauth_authorization_codes.requested_claims  the parsed, emittable
--       request persisted with the code: {"userinfo":[...],"id_token":[...]}
--       (NULL = none requested); the exchange reads it to stamp the
--       userinfo claim names on the access token and to mint id_token claims.
--   oauth_consents.claims  the consented claim tokens, space-separated and
--       sorted ("id_token:email userinfo:name"); '' = none. A returning
--       client asking for a claim not in this set is sent to consent again.
--
-- +goose Up
-- +goose StatementBegin
ALTER TABLE oauth_authorization_codes
    ADD COLUMN IF NOT EXISTS requested_claims JSONB;
ALTER TABLE oauth_consents
    ADD COLUMN IF NOT EXISTS claims TEXT NOT NULL DEFAULT '';
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE oauth_consents
    DROP COLUMN IF EXISTS claims;
ALTER TABLE oauth_authorization_codes
    DROP COLUMN IF EXISTS requested_claims;
-- +goose StatementEnd
