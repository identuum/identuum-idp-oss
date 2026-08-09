-- identuum-idp-oss — service-account name uniqueness PER ORGANIZATION
-- (THE-V032-ALL-GREEN gap E).
--
-- The UI's rename flow maps a duplicate name to an inline 409 error, but the
-- backend accepted duplicates (measured: renaming an SA to a sibling's name
-- returned 200), so that error path was unreachable and operators could end
-- up with same-named machine identities in one org. The uniqueness is scoped
-- to LIVE rows: a soft-deleted SA releases its name.
--
-- REFUSAL, NEVER DEDUP. If a deployment already carries live duplicates the
-- index cannot be created safely; renaming or deleting rows is an operator
-- decision. The migration REFUSES with named counts (duplicate groups and
-- the total rows involved) and the operator resolves them by hand, then
-- re-runs.
--
-- +goose Up
-- +goose StatementBegin
DO $$
DECLARE
    duplicate_groups INTEGER;
    duplicate_rows   INTEGER;
BEGIN
    SELECT COUNT(*), COALESCE(SUM(cnt), 0) INTO duplicate_groups, duplicate_rows
    FROM (
        SELECT COUNT(*) AS cnt
        FROM service_accounts
        WHERE deleted_at IS NULL
        GROUP BY organization_id, name
        HAVING COUNT(*) > 1
    ) d;

    IF duplicate_groups > 0 THEN
        RAISE EXCEPTION
            'service-account name-uniqueness REFUSED: % (organization, name) group(s) hold % live duplicate row(s). Rename or delete the duplicates by hand — this migration never dedups — then re-run.',
            duplicate_groups, duplicate_rows;
    END IF;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE UNIQUE INDEX IF NOT EXISTS uq_service_accounts_org_name_live
    ON service_accounts (organization_id, name)
    WHERE deleted_at IS NULL;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS uq_service_accounts_org_name_live;
-- +goose StatementEnd
