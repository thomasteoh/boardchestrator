-- 0040 down: drop passkeys and the users columns they added.

DROP TABLE IF EXISTS webauthn_credentials;
DROP INDEX IF EXISTS idx_users_webauthn_handle;

ALTER TABLE users DROP COLUMN email_verified;
ALTER TABLE users DROP COLUMN webauthn_handle;
