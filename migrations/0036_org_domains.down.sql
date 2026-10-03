-- 0036 down: drop organisation domains and SSO settings.

DROP TABLE IF EXISTS org_sso_settings;
DROP INDEX IF EXISTS idx_org_domains_verified;
DROP TABLE IF EXISTS org_domains;
