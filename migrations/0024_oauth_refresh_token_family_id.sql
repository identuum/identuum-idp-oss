-- Identuum IdP OSS — OAuth Refresh Token family lineage
--
-- Converges the OSS automated refresh-token reuse response onto
-- family-lineage revocation (RFC 9700 §4.13.2), matching the CE overlay
-- (CE-SEC-4). family_id groups a refresh token with its entire rotation
-- lineage: the initial grant (RefreshTokenService.Issue) generates a new
-- UUIDv7 family, and each rotation (Consume) inherits the consumed
-- parent's family_id. When an already-rotated (superseded) token is
-- replayed — the reuse signal — only that lineage is revoked instead of
-- the subject's every session/device/client.
--
-- Nullable for legacy (pre-migration) rows: a NULL-family token cannot
-- identify its lineage, so reuse detection falls back to the prior
-- subject-wide revocation for those rows (no regression window; such
-- tokens expire within the ~30-day refresh lifetime). New tokens are
-- family-scoped.
--
-- The DELIBERATE subject-wide paths (RevokeAllForUser: password reset,
-- admin MFA reset, account takeover) are unchanged — strong-evidence
-- account events still cut everything.

-- +goose Up
ALTER TABLE oauth_refresh_tokens
    ADD COLUMN family_id UUID;

CREATE INDEX idx_oauth_refresh_tokens_family_id
    ON oauth_refresh_tokens(family_id)
    WHERE family_id IS NOT NULL;

-- +goose Down
DROP INDEX IF EXISTS idx_oauth_refresh_tokens_family_id;
ALTER TABLE oauth_refresh_tokens
    DROP COLUMN family_id;
