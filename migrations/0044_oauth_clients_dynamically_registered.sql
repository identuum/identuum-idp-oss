-- identuum-idp-oss — an app created through dynamic client registration never
-- skips the consent screen (D-026).
--
-- oauth_clients.dynamically_registered is set once, when the app is created
-- through POST /api/v1/oauth/register, and never written again.
--
-- An app that already holds a registration access token was created that way,
-- so it is marked here, and one that had been given skip_consent through the
-- console loses it. An app registered before this column existed that holds no
-- registration access token cannot be told apart and is left as it is. The
-- sign-in rule (identity scopes only, confidential apps only) still applies to it.

-- +goose Up

ALTER TABLE oauth_clients
    ADD COLUMN dynamically_registered BOOLEAN NOT NULL DEFAULT false;

UPDATE oauth_clients
   SET dynamically_registered = true
 WHERE id IN (SELECT client_id FROM dcr_client_registration_tokens);

UPDATE oauth_clients
   SET skip_consent = false
 WHERE dynamically_registered AND skip_consent;

-- +goose Down

ALTER TABLE oauth_clients DROP COLUMN IF EXISTS dynamically_registered;
