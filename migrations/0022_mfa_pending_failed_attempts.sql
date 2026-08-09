-- Identuum IdP OSS — MFA pending-login failed-attempt counter (P0-13)
--
-- The MFA verification endpoint (POST /api/v1/auth/login/mfa) had NO
-- brute-force protection: a wrong TOTP or recovery code returned before
-- the pending handle was consumed, so the handle survived every failed
-- guess for its full ~5-minute lifetime. An attacker who already holds
-- the password (and therefore a valid verify-kind pending handle) could
-- guess six-digit codes without limit, throttle, count, or lockout — a
-- live MFA bypass, since MFA is precisely the control that must survive
-- password compromise.
--
-- failed_attempts is a DURABLE, SHARED per-handle guess counter. It is
-- incremented atomically on each failed verify (same statement that, at
-- the threshold, sets consumed_at to invalidate the handle), so one
-- handle can never yield more than a bounded number of guesses
-- regardless of client IP, which replica served the request, or a
-- process restart — properties the process-local IP rate limiter
-- (internal/mw/rate_limit.go, per-process map) cannot provide. Chosen
-- over riding login_attempts because that path is fail-OPEN and is keyed
-- per-account/IP-window rather than bound to the specific handle, so it
-- can neither fail closed nor invalidate the handle.
--
-- NOT NULL DEFAULT 0: every existing and every freshly-created row starts
-- at zero failed guesses. Backfill is implicit via the default. The
-- successful-redemption path (MarkConsumed) is unchanged and never reads
-- or writes this column.

-- +goose Up
-- +goose StatementBegin
ALTER TABLE mfa_pending_login_sessions
    ADD COLUMN failed_attempts INTEGER NOT NULL DEFAULT 0;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE mfa_pending_login_sessions DROP COLUMN IF EXISTS failed_attempts;
-- +goose StatementEnd
