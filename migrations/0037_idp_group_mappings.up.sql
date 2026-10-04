-- 0037: membership provenance and IdP group -> role mappings (WU-608, SPEC s5,
-- s7.5).
--
-- memberships.source records how a membership was granted: manual (an admin
-- or org creation), invite (invite acceptance), jit (org JIT provisioning),
-- idp (group mapping sync at sign-in) or scim (WU-611). Group sync only ever
-- inserts, updates or deletes rows with source = 'idp'.
ALTER TABLE memberships ADD COLUMN source TEXT NOT NULL DEFAULT 'manual'
    CHECK (source IN ('manual', 'invite', 'jit', 'idp', 'scim'));

-- Best-effort backfill: a user membership exactly matching an accepted invite
-- for that user's email (same org and resource) came from the invite.
UPDATE memberships SET source = 'invite'
WHERE actor_type = 'user'
  AND EXISTS (
    SELECT 1 FROM invites i JOIN users u ON lower(u.email) = lower(i.email)
    WHERE i.accepted_at IS NOT NULL
      AND u.id = memberships.actor_id
      AND i.org_id = memberships.org_id
      AND i.resource_type = memberships.resource_type
      AND i.resource_id = memberships.resource_id
  );

-- idp_group_mappings: an IdP group value maps to a role at org, team or
-- project scope in the owning org. provider_id NULL applies the mapping to
-- every provider of the org. One mapping per (provider, group, resource):
-- the unique index treats NULL provider as its own value.
CREATE TABLE idp_group_mappings (
    id            TEXT PRIMARY KEY,
    org_id        TEXT NOT NULL REFERENCES orgs (id) ON DELETE CASCADE,
    provider_id   TEXT REFERENCES auth_providers (id) ON DELETE CASCADE,
    group_value   TEXT NOT NULL,
    role_id       TEXT NOT NULL REFERENCES roles (id) ON DELETE CASCADE,
    resource_type TEXT NOT NULL CHECK (resource_type IN ('org', 'team', 'project')),
    resource_id   TEXT NOT NULL,
    created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE UNIQUE INDEX idx_idp_group_mappings_key
    ON idp_group_mappings (org_id, COALESCE(provider_id, ''), group_value, resource_type, resource_id);
