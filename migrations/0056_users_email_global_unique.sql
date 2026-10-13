-- identuum-idp-oss — one live email address is one account across the whole
-- server (OSS-0914-STAGE-2, owner decision EMAIL-SCOPE (a), 2026-10-13).
--
-- Sign-in asks only for the address, so two live accounts with one address
-- (in two organizations, or in one organization in two cases) lost password
-- and passkey-by-email sign-in. Until now the unique index was per
-- organization and case-sensitive (0001, users_organization_id_email_key_undeleted).
-- This index holds every live account (deleted_at IS NULL, the predicate of
-- that index) to one address in any case.
--
-- If the database already holds such a duplicate, the migration refuses with
-- SQLSTATE IDM01 (postgres.MigrationRefusedSQLState) and changes nothing: the
-- transaction rolls back, the database stays at 55, and a server of this
-- version stays NOT-SERVING until an operator resolves the duplicates
-- (docs/OPERATOR-GUIDE.md, "Before upgrading to v0.9.14"). The refusal names
-- how many addresses, never an address.

-- +goose Up

-- +goose StatementBegin
DO $$
DECLARE
    duplicates bigint;
BEGIN
    SELECT count(*) INTO duplicates FROM (
        SELECT lower(email) FROM users WHERE deleted_at IS NULL
        GROUP BY lower(email) HAVING count(*) > 1
    ) d;
    IF duplicates > 0 THEN
        RAISE EXCEPTION USING
            ERRCODE = 'IDM01',
            MESSAGE = format('migration 0056 refused: %s email address(es) belong to more than one live account (any case, any organization); nothing was changed', duplicates),
            HINT = 'Give each account its own address or delete the extra accounts, then run identuum-idp migrate again. See the operator guide, "Before upgrading to v0.9.14".';
    END IF;
END
$$;
-- +goose StatementEnd

CREATE UNIQUE INDEX users_email_lower_key_undeleted
    ON users (lower(email)) WHERE deleted_at IS NULL;

-- +goose Down

DROP INDEX IF EXISTS users_email_lower_key_undeleted;
