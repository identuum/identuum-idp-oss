-- identuum-idp-oss — issued participant tokens (AYGHU-4, revocation propagation).
--
-- Every participant token issued for an agent-communication authorization is
-- recorded here by its jti, bound to the authorization and the participant
-- ACI, with its expiry. Revoking the authorization reads the still-live jtis
-- and writes them to oauth_token_revocations, so introspection (and every
-- other jti-revocation consumer) turns the tokens inactive IMMEDIATELY — not
-- at their expiry. Only the jti is stored, never the token. Rows are swept
-- once expired; the authorization's cascade removes them with the
-- authorization.

-- +goose Up

CREATE TABLE agent_communication_tokens (
    jti               TEXT        PRIMARY KEY,
    authorization_id  UUID        NOT NULL REFERENCES agent_communication_authorizations(id) ON DELETE CASCADE,
    aci               UUID        NOT NULL,
    expires_at        TIMESTAMPTZ NOT NULL,
    issued_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT act_jti_check CHECK (length(jti) BETWEEN 1 AND 256),
    CONSTRAINT act_expires_after_issued_check CHECK (expires_at > issued_at)
);

CREATE INDEX idx_act_authorization_id ON agent_communication_tokens (authorization_id, expires_at);
CREATE INDEX idx_act_expires_at ON agent_communication_tokens (expires_at);

-- +goose Down

DROP INDEX IF EXISTS idx_act_expires_at;
DROP INDEX IF EXISTS idx_act_authorization_id;
DROP TABLE IF EXISTS agent_communication_tokens;
