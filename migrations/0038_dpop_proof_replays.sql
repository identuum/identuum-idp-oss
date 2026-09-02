-- identuum-idp-oss — DPoP proof replay protection (AYGHU-3, RFC 9449 §11.1).
--
-- Every DPoP proof presented to the token endpoint for an agent-communication
-- token is single-use: (proof-key thumbprint, sha256(jti)) is recorded here
-- with ON CONFLICT DO NOTHING; the affected-row count is the verdict. The raw
-- jti is never stored. This is deliberately a SEPARATE table from
-- oauth_client_assertion_replays (0008): OAuth client-assertion identifiers
-- and DPoP proof identifiers are two identifier spaces and are never
-- conflated. Rows expire shortly after the proof's acceptance window and are
-- swept by the revocation cleanup ticker.

-- +goose Up

CREATE TABLE dpop_proof_replays (
    jkt          TEXT        NOT NULL,
    jti_hash     TEXT        NOT NULL,
    expires_at   TIMESTAMPTZ NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (jkt, jti_hash),
    CONSTRAINT dpop_proof_replays_jkt_check CHECK (length(jkt) BETWEEN 1 AND 128),
    CONSTRAINT dpop_proof_replays_jti_hash_check CHECK (jti_hash ~ '^[0-9a-f]{64}$')
);

CREATE INDEX idx_dpop_proof_replays_expires_at ON dpop_proof_replays (expires_at);

-- +goose Down

DROP INDEX IF EXISTS idx_dpop_proof_replays_expires_at;
DROP TABLE IF EXISTS dpop_proof_replays;
