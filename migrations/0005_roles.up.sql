-- Seed system roles (SPEC §6, copy-on-edit).
-- Create the platform sentinel org first so FK constraints on roles are satisfied.
INSERT INTO orgs (id, name, slug, context, visibility)
VALUES ('00000000000000000000000000000000', 'Platform', '_platform', '', 'internal')
ON CONFLICT DO NOTHING;

INSERT INTO roles (id, org_id, name, is_system, grants_json) VALUES
    ('00000000000000000000000000000000', '00000000000000000000000000000000', 'Org Owner', 1, '["*"]'),
    ('11111111111111111111111111111111', '00000000000000000000000000000000', 'Team Admin', 1, '["org.read","team.*","project.*","board.*","sprint.*","task.*","comment.*","wiki.*","report.view"]'),
    ('22222222222222222222222222222222', '00000000000000000000000000000000', 'Member', 1, '["org.read","project.read","task.*","comment.*","sprint.read","board.read","wiki.read"]'),
    ('33333333333333333333333333333333', '00000000000000000000000000000000', 'Viewer', 1, '["org.read","project.read","task.read","comment.read","sprint.read","board.read","wiki.read"]'),
    ('44444444444444444444444444444444', '00000000000000000000000000000000', 'Guest', 1, '["project.read","task.read","comment.read"]')
ON CONFLICT DO NOTHING;
