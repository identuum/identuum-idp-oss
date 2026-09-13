-- identuum-idp-oss — TOTP single-use guard (THE-CODE-THAT-WORKS-TWICE,
-- 2026-09-13; RFC 6238 §5.2).
--
-- A time-based one-time password was matched against its skew window and
-- nothing else, so a captured code was accepted again for as long as that
-- window lasted. Every TOTP proof the appliance accepts now claims the
-- (user_id, step) it matched here with INSERT … ON CONFLICT DO NOTHING; the
-- affected-row count is the verdict, exactly as dpop_proof_replays (0038)
-- decides a DPoP proof. A second presentation of the same step for the same
-- user finds the row and is refused as a wrong code. Only the step number is
-- stored, never the code or the seed. Rows expire once the step can no
-- longer be accepted (its validity window plus one period of margin) and are
-- swept by the revocation cleanup ticker, so the table is bounded to a
-- handful of rows per user and expiry can never resurrect a live code.

-- +goose Up

CREATE TABLE totp_used_steps (
    user_id      UUID        NOT NULL,
    step         BIGINT      NOT NULL,
    expires_at   TIMESTAMPTZ NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id, step),
    CONSTRAINT totp_used_steps_step_check CHECK (step >= 0)
);

CREATE INDEX idx_totp_used_steps_expires_at ON totp_used_steps (expires_at);

-- +goose Down

DROP INDEX IF EXISTS idx_totp_used_steps_expires_at;
DROP TABLE IF EXISTS totp_used_steps;
