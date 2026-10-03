-- 0038: per-provider "sign out of the identity provider too" (WU-609, SPEC
-- s7.6). When on (the default) and the provider's discovery document has an
-- end_session_endpoint, POST /auth/logout sends the browser there after the
-- local session is revoked. GitHub has no IdP logout, so its rows start off.
-- The (provider_id, idp_sid) and (provider_id, idp_subject) session indexes
-- that back-channel logout uses were created in 0033.
ALTER TABLE auth_providers ADD COLUMN idp_logout INTEGER NOT NULL DEFAULT 1;

UPDATE auth_providers SET idp_logout = 0 WHERE kind = 'github';
