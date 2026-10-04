-- 0034 down: drop the provider registry. Identities keep their provider ids;
-- with no rows the server falls back to no configured sign-in providers.

DROP INDEX IF EXISTS idx_auth_providers_org;
DROP TABLE IF EXISTS auth_providers;
