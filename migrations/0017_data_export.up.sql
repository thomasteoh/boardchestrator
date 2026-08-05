-- 0017: data export & deletion support
-- Sentinel "Former member" user for re-attribution of authored content.
INSERT INTO users (id, email, name, avatar_url)
VALUES ('ffffffffffffffffffffffffffffffff', 'former-member@local', 'Former member', '')
ON CONFLICT DO NOTHING;

-- Add deleted_by column to comments for re-attribution tracking.
ALTER TABLE comments ADD COLUMN deleted_by TEXT DEFAULT '';

-- Add deleted_by column to task_activity.
ALTER TABLE task_activity ADD COLUMN deleted_by TEXT DEFAULT '';
