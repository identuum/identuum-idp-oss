-- identuum-idp-oss — wrong second-factor codes on the proof routes, per user.
--
-- Step-up, self-service MFA disable, recovery-code regeneration and turning
-- skip consent on share one per-user budget of wrong codes (TOTPFailureBudget).
-- It was kept in process memory, so a restart reset it and each replica counted
-- its own. One row per wrong code: the budget counts a user's rows inside its
-- window, and the cleanup sweep drops the rows that have left it. The rows go
-- with their user (ON DELETE CASCADE).

-- +goose Up

CREATE TABLE mfa_proof_failures (
    id        UUID        PRIMARY KEY,
    user_id   UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    failed_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX idx_mfa_proof_failures_user_time ON mfa_proof_failures (user_id, failed_at);
CREATE INDEX idx_mfa_proof_failures_time ON mfa_proof_failures (failed_at);

-- +goose Down

DROP TABLE IF EXISTS mfa_proof_failures;
