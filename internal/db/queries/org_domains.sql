-- Organisation email domains (WU-606, SPEC s7.4). Every query binds org_id
-- except FindVerifiedDomainOrg, which is the home-realm discovery lookup: it
-- maps a verified domain to the one org that owns it and returns that org_id.

-- name: CreateOrgDomain :one
INSERT INTO org_domains (id, org_id, domain, verify_token, created_at)
VALUES (?, ?, ?, ?, ?)
RETURNING *;

-- name: ListOrgDomains :many
-- taken is 1 when another org has verified the same domain, so this org's
-- pending claim can never verify.
SELECT d.id, d.org_id, d.domain, d.verify_token, d.verified_at, d.created_at,
       CAST(EXISTS (
           SELECT 1 FROM org_domains o
           WHERE o.domain = d.domain AND o.org_id <> d.org_id AND o.verified_at IS NOT NULL
       ) AS INTEGER) AS taken
FROM org_domains d
WHERE d.org_id = ?
ORDER BY d.domain;

-- name: GetOrgDomain :one
SELECT * FROM org_domains
WHERE id = ? AND org_id = ?;

-- name: CountOrgDomains :one
SELECT count(*) FROM org_domains
WHERE org_id = ?;

-- name: DomainVerifiedByOtherOrg :one
SELECT CAST(EXISTS (
    SELECT 1 FROM org_domains
    WHERE domain = ? AND org_id <> ? AND verified_at IS NOT NULL
) AS INTEGER);

-- name: MarkOrgDomainVerified :execrows
-- Conditional on the token the caller checked in DNS, so a concurrent
-- remove-and-re-add cannot be verified with the old token.
UPDATE org_domains SET verified_at = ?
WHERE id = ? AND org_id = ? AND verify_token = ? AND verified_at IS NULL;

-- name: DeleteOrgDomain :execrows
DELETE FROM org_domains
WHERE id = ? AND org_id = ?;

-- name: FindVerifiedDomainOrg :one
SELECT org_id FROM org_domains
WHERE domain = ? AND verified_at IS NOT NULL;
