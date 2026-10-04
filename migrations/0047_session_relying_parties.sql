-- identuum-idp-oss — which relying parties hold an ID token for a session.
--
-- When the token endpoint issues an ID token for a session it records the
-- (session, client) pair here, so that ending the session can notify every
-- relying party that registered a back-channel logout endpoint, not only the one
-- that asked for the logout (OIDC Back-Channel Logout 1.0 §2).
--
-- A pair is recorded once. The rows go with their session (ON DELETE CASCADE).
-- client_id is the public client_id string, with no foreign key: a client that is
-- deleted later simply no longer resolves when the logout looks it up.

-- +goose Up

CREATE TABLE session_relying_parties (
    session_id      UUID        NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    client_id       TEXT        NOT NULL,
    first_issued_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (session_id, client_id)
);

-- +goose Down

DROP TABLE IF EXISTS session_relying_parties;
