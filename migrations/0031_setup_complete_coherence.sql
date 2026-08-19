-- identuum-idp-oss — setup-state / site_admin COHERENCE tooth
-- (WIZARD-SPLIT-BRAIN-1).
--
-- The setup wizard flipped system_setup_state to 'setup_complete' while, in
-- the split-brain case, having stored NOTHING — a site_admin from devseed
-- already held the single-site_admin slot, the wizard silently discarded the
-- operator's credentials, and the next login said "Invalid credentials". The
-- service layer now refuses to complete without adopting the operator's
-- credentials (Complete/ensureSiteAdmin adopt-and-reset), and bootstrap marks
-- setup complete so a bootstrapped database is coherent. This migration adds
-- the DB tooth behind those service invariants: the state and the site_admin's
-- existence may never disagree.
--
-- The tooth: system_setup_state can be marked 'setup_complete' ONLY when a
-- live site_admin exists. Setup completion and bootstrap both create the
-- site_admin BEFORE flipping the state, so this never blocks a real completion;
-- it blocks the incoherent "complete with no admin" state at the database, past
-- every service guard (a support script, a restore, a psql session).
--
-- +goose Up
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION model_setup_complete_requires_site_admin() RETURNS trigger AS $$
BEGIN
    IF NEW.status = 'setup_complete' AND NEW.status IS DISTINCT FROM OLD.status THEN
        IF NOT EXISTS (
            SELECT 1 FROM users
            WHERE role = 'site_admin' AND deleted_at IS NULL
        ) THEN
            RAISE EXCEPTION 'setup cannot be marked complete without a live site_admin (WIZARD-SPLIT-BRAIN-1): setup-state and site_admin existence must agree';
        END IF;
    END IF;
    RETURN NEW;
END $$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_setup_complete_requires_site_admin ON system_setup_state;
CREATE TRIGGER trg_setup_complete_requires_site_admin
    BEFORE UPDATE ON system_setup_state
    FOR EACH ROW
    EXECUTE FUNCTION model_setup_complete_requires_site_admin();
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TRIGGER IF EXISTS trg_setup_complete_requires_site_admin ON system_setup_state;
DROP FUNCTION IF EXISTS model_setup_complete_requires_site_admin();
-- +goose StatementEnd
