-- 0036: organisation email domains and SSO settings (WU-606, SPEC s5, s7.4).
--
-- org_domains: a domain an org claims for home-realm discovery, org-owned
-- email trust (WU-607) and JIT (WU-608). An org adds a domain (pending, with
-- a random verify_token), publishes the TXT record
-- _boardchestrator-challenge.<domain> = bc-verify=<token>, and verifies it.
-- Uniqueness: SPEC s5 says domain UNIQUE, but a plain UNIQUE would let any
-- org park an unverified claim on someone else's domain forever. Instead a
-- domain is unique per org, and unique across orgs only once verified (the
-- partial index): many orgs may hold pending claims, exactly one may verify.
-- domain is stored normalised (lower-case ASCII, IDNA A-labels, no trailing
-- dot).
CREATE TABLE org_domains (
    id           TEXT PRIMARY KEY,
    org_id       TEXT NOT NULL REFERENCES orgs (id) ON DELETE CASCADE,
    domain       TEXT NOT NULL,
    verify_token TEXT NOT NULL,
    verified_at  TEXT,
    created_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    UNIQUE (org_id, domain)
);

CREATE UNIQUE INDEX idx_org_domains_verified ON org_domains (domain) WHERE verified_at IS NOT NULL;

-- org_sso_settings: per-org SSO policy (SPEC s7.4/s7.5). Created here so the
-- SSO settings page has one home; WU-607 (enforce_sso) and WU-608 (JIT,
-- group mapping) add the queries and actions. No row = all off.
CREATE TABLE org_sso_settings (
    org_id              TEXT PRIMARY KEY REFERENCES orgs (id) ON DELETE CASCADE,
    enforce_sso         INTEGER NOT NULL DEFAULT 0,
    jit_enabled         INTEGER NOT NULL DEFAULT 0,
    jit_default_role_id TEXT REFERENCES roles (id) ON DELETE SET NULL,
    group_claim         TEXT NOT NULL DEFAULT '',
    group_sync          INTEGER NOT NULL DEFAULT 0,
    updated_at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
