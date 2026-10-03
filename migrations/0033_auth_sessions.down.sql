-- 0033 down: drop the WU-601 session provenance and identity login columns.

DROP INDEX IF EXISTS idx_sessions_provider_subject;
DROP INDEX IF EXISTS idx_sessions_provider_sid;

ALTER TABLE sessions DROP COLUMN id_token_enc;
ALTER TABLE sessions DROP COLUMN idp_subject;
ALTER TABLE sessions DROP COLUMN idp_sid;
ALTER TABLE sessions DROP COLUMN auth_method;
ALTER TABLE sessions DROP COLUMN provider_id;

ALTER TABLE identities DROP COLUMN last_login_at;
