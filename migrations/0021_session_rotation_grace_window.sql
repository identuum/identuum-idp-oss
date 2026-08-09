-- Identuum IdP OSS — Session Rotation Grace Window (P0-12b)
--
-- P0-12 (migration-adjacent commit 133b853) closed the WRITE race on
-- refresh-token rotation with a compare-and-set: two concurrent
-- rotations of the same session can no longer both succeed. It did
-- NOT close the READ race: RotateRefreshToken's validator compare
-- happens at read time, before the CAS. A benign concurrent racer
-- (a double-click, a client retry) that reads the session AFTER a
-- sibling has already committed its rotation sees the NEW hash,
-- fails the compare against its own (now just-superseded) validator,
-- and is executed as a thief — RevokeByUserID tears down the user's
-- whole session family for what was, in reality, a harmless race.
--
-- The schema could not distinguish "the immediate predecessor,
-- superseded microseconds ago by a sibling" from "an old validator
-- replayed by an attacker who stole it days ago" — both are simply
-- "not the current hash". This migration adds the state needed to
-- make that distinction: the single prior validator hash, and the
-- instant it stopped being current.
--
-- prev_validator_hash / prev_rotated_at are written by the SAME
-- UPDATE statement that performs the rotation CAS (see
-- PgxSessionRepository.RotateToken) — the outgoing validator hash
-- moves into prev_validator_hash and prev_rotated_at is stamped from
-- the DB clock (now()), never the host clock, per the P2-21 clock
-- discipline. RotateRefreshToken then classifies a validator
-- mismatch three ways: current hash → rotate; prev hash presented
-- within a short grace window → benign racer, accept without
-- rotating or revoking; anything else (unknown hash, or a
-- predecessor older than the grace window) → genuine reuse, revoke
-- the family exactly as before. Nullable: existing sessions and
-- freshly-created ones have never rotated, so both columns start as
-- NULL — the paired CHECK constraint keeps that consistent.

-- +goose Up
-- +goose StatementBegin
ALTER TABLE sessions
    ADD COLUMN prev_validator_hash VARCHAR(255),
    ADD COLUMN prev_rotated_at TIMESTAMPTZ;

ALTER TABLE sessions
    ADD CONSTRAINT chk_sessions_prev_validator_paired CHECK (
        (prev_validator_hash IS NULL AND prev_rotated_at IS NULL)
        OR (prev_validator_hash IS NOT NULL AND prev_rotated_at IS NOT NULL)
    );
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE sessions DROP CONSTRAINT IF EXISTS chk_sessions_prev_validator_paired;
ALTER TABLE sessions DROP COLUMN IF EXISTS prev_rotated_at;
ALTER TABLE sessions DROP COLUMN IF EXISTS prev_validator_hash;
-- +goose StatementEnd
