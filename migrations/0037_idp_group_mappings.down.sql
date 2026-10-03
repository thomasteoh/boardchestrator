-- 0037 down: drop IdP group mappings and memberships.source.

DROP INDEX IF EXISTS idx_idp_group_mappings_key;
DROP TABLE IF EXISTS idp_group_mappings;
ALTER TABLE memberships DROP COLUMN source;
