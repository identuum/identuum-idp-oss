-- identuum-idp-oss — a new organization starts with no default service-account
-- expiry.
--
-- Owner rulings 2026-10-06 (OSS-SA-EXPIRY-2): service_account_expiry_days is
-- each organization's own setting; a new organization starts at 0 (no default
-- expiry) unless its create request names a value, and its org_admin turns it
-- on. Migration 0001 declared DEFAULT 365, while the create path always wrote
-- the requested value (0 when none was named); the column default now says the
-- same. No existing organization row changes.

-- +goose Up

ALTER TABLE organizations ALTER COLUMN service_account_expiry_days SET DEFAULT 0;

-- +goose Down

ALTER TABLE organizations ALTER COLUMN service_account_expiry_days SET DEFAULT 365;
