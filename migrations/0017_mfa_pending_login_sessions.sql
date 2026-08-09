-- +goose Up
-- +goose StatementBegin

-- mfa_pending_login_sessions stores the short-lived pending-MFA login
-- state created when a correct-password login lands on a path that
-- cannot yet issue a full session — i.e. the user must complete TOTP
-- enrolment (kind='enroll') or supply a TOTP code (kind='verify')
-- before access_token / refresh_token cookies can be emitted.
--
-- Why a DB-backed pending table rather than a JWT-carried handle:
--
--   - The TOTP candidate secret + recovery-code allowlist for the
--     enrolment kind MUST NOT round-trip through the client. Putting
--     them in the response is acceptable for one-time display; putting
--     them in the pending handle the client retransmits is not.
--
--   - DB-backed makes single-use enforcement trivial (UPDATE ... SET
--     consumed_at=NOW() WHERE consumed_at IS NULL RETURNING ...).
--
--   - Background sweep is a clean expire-by-time-bound DELETE. No
--     dependency on JWT clock-skew handling.
--
-- Rows are intentionally short-lived (5 minutes by default; enforced
-- in the service layer via expires_at). The sweeper deletes rows past
-- expires_at after a grace window.
--
-- Security invariants:
--   - id is the OPAQUE handle returned to the client. It is a
--     freshly-generated UUIDv7. Never reused; never derived from the
--     user_id or email.
--   - kind controls which finalisation path applies. 'enroll' rows
--     additionally carry the candidate secret + recovery codes
--     between /initiate and /complete. 'verify' rows carry no secret
--     material (the user's persisted MFASecret is consulted at verify
--     time).
--   - consumed_at IS NULL gates the single-use property. Once set,
--     the row cannot be redeemed again.
--   - ON DELETE CASCADE removes pending rows when the user is hard-
--     deleted, so no orphan handles survive.
CREATE TABLE mfa_pending_login_sessions (
    id              UUID PRIMARY KEY,
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    kind            TEXT NOT NULL,
    secret          TEXT,
    recovery_codes  JSONB,
    remember_me     BOOLEAN NOT NULL DEFAULT FALSE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at      TIMESTAMPTZ NOT NULL,
    consumed_at     TIMESTAMPTZ,
    CONSTRAINT mfa_pending_login_sessions_kind_check
        CHECK (kind IN ('enroll', 'verify'))
);

CREATE INDEX mfa_pending_login_sessions_expires_at_idx
    ON mfa_pending_login_sessions (expires_at);

CREATE INDEX mfa_pending_login_sessions_user_id_idx
    ON mfa_pending_login_sessions (user_id);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS mfa_pending_login_sessions;
-- +goose StatementEnd
