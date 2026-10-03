-- 0033: login resolution + session provenance (WU-601, SPEC §5, §7.3, §7.10).
--
-- identities.last_login_at records each successful sign-in through that
-- identity. The session columns record how a session was established so later
-- WUs can enforce org SSO (provider_id), perform RP-initiated logout
-- (id_token_enc as the id_token_hint) and back-channel logout (idp_sid /
-- idp_subject). Pre-existing sessions carry empty values.

ALTER TABLE identities ADD COLUMN last_login_at TEXT;

ALTER TABLE sessions ADD COLUMN provider_id  TEXT NOT NULL DEFAULT '';
ALTER TABLE sessions ADD COLUMN auth_method  TEXT NOT NULL DEFAULT '';
ALTER TABLE sessions ADD COLUMN idp_sid      TEXT NOT NULL DEFAULT '';
ALTER TABLE sessions ADD COLUMN idp_subject  TEXT NOT NULL DEFAULT '';
ALTER TABLE sessions ADD COLUMN id_token_enc TEXT NOT NULL DEFAULT '';

CREATE INDEX idx_sessions_provider_sid ON sessions (provider_id, idp_sid);
CREATE INDEX idx_sessions_provider_subject ON sessions (provider_id, idp_subject);

-- The pre-WU-601 GitHub callback linked identities as provider 'google' with
-- subject 'gh-<id>'. Normalise them to provider 'github', subject '<id>' so
-- (provider, subject) lookup finds them. Skipped where the target row already
-- exists. Deliberately not reverted by the down migration: the old shape was
-- a bug, not a schema.
UPDATE identities
SET provider = 'github', subject = substr(subject, 4)
WHERE provider = 'google'
  AND subject LIKE 'gh-%'
  AND NOT EXISTS (
      SELECT 1 FROM identities i2
      WHERE i2.provider = 'github' AND i2.subject = substr(identities.subject, 4)
  );
