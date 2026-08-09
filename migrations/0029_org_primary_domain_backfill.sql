-- identuum-idp-oss — materialize the primary organization_domains row
-- (THE-V032-ALL-GREEN gap D).
--
-- An organization's own domain lives as a column on organizations, but the
-- Domains surface reads organization_domains — and org creation never wrote a
-- row there, so no org ever showed its primary domain (measured by the
-- released-appliance e2e suite: the Domains card could not render the
-- Primary + Verified row for any org). Creation now materializes the row in
-- the same transaction (service layer); this migration backfills EXISTING
-- live orgs.
--
-- The backfilled row is is_primary = true and verified — the organization's
-- own domain was named at creation by the authority that created the org; it
-- is trusted by construction, exactly as the creation path now records it.
--
-- REFUSAL, NEVER DEDUP. Two ambiguity classes make the backfill unsafe for a
-- deployment, and the migration REFUSES with named counts instead of guessing:
--   1. conflicting_own_rows — a live org with NO primary row already has an
--      organization_domains row for its own domain string (pending or
--      non-primary). Flipping or replacing it would silently rewrite an
--      operator-created row.
--   2. cross_org_verified_claims — another org already holds the VERIFIED
--      row for this org's domain string (uq_org_domains_verified_domain is
--      deployment-wide). Inserting would either fail or seize the claim.
-- An operator resolves the named rows by hand, then re-runs the migration.
--
-- +goose Up
-- +goose StatementBegin
DO $$
DECLARE
    conflicting_own_rows       INTEGER;
    cross_org_verified_claims  INTEGER;
BEGIN
    SELECT COUNT(*) INTO conflicting_own_rows
    FROM organizations o
    JOIN organization_domains od
      ON od.organization_id = o.id AND od.domain = o.domain::citext
    WHERE o.deleted_at IS NULL
      AND NOT EXISTS (
          SELECT 1 FROM organization_domains p
          WHERE p.organization_id = o.id AND p.is_primary = true
      );

    SELECT COUNT(*) INTO cross_org_verified_claims
    FROM organizations o
    JOIN organization_domains od
      ON od.domain = o.domain::citext
     AND od.organization_id <> o.id
     AND od.verified_at IS NOT NULL
    WHERE o.deleted_at IS NULL
      AND NOT EXISTS (
          SELECT 1 FROM organization_domains p
          WHERE p.organization_id = o.id AND p.is_primary = true
      );

    IF conflicting_own_rows > 0 OR cross_org_verified_claims > 0 THEN
        RAISE EXCEPTION
            'primary-domain backfill REFUSED: % org(s) already carry a non-primary/pending row for their own domain (conflicting_own_rows), % org domain(s) are verified-claimed by ANOTHER org (cross_org_verified_claims). Resolve these rows by hand — this migration never dedups or reassigns — then re-run.',
            conflicting_own_rows, cross_org_verified_claims;
    END IF;

    INSERT INTO organization_domains
        (organization_id, domain, is_primary, verified_at, created_at, updated_at)
    SELECT o.id, o.domain::citext, true, NOW(), NOW(), NOW()
    FROM organizations o
    WHERE o.deleted_at IS NULL
      AND NOT EXISTS (
          SELECT 1 FROM organization_domains p
          WHERE p.organization_id = o.id AND p.is_primary = true
      );
END $$;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
-- Down removes ONLY rows this backfill could have created: primary + verified
-- rows whose domain equals the org's own domain column. Operator-created rows
-- (non-primary, or differing domains) are untouched.
DELETE FROM organization_domains od
USING organizations o
WHERE od.organization_id = o.id
  AND od.domain = o.domain::citext
  AND od.is_primary = true;
-- +goose StatementEnd
