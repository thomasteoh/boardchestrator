-- 0002: action-dispatch infrastructure (SPEC §5 — idempotency_keys,
-- audit_log). These are deliberately NOT tenant-scoped in the usual way:
-- idempotency_keys carries no org_id (keyed globally by the idempotency
-- key), and audit_log.org_id is nullable (platform-level actions and some
-- pre-org events have no org). check-scope.sh is updated to reflect this.

CREATE TABLE idempotency_keys (
    key         TEXT PRIMARY KEY,
    actor       TEXT NOT NULL,
    action      TEXT NOT NULL,
    result_json TEXT NOT NULL,
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE TABLE audit_log (
    id          TEXT PRIMARY KEY,
    org_id      TEXT,
    actor_type  TEXT NOT NULL,
    actor_id    TEXT NOT NULL,
    action      TEXT NOT NULL,
    subject     TEXT NOT NULL DEFAULT '',
    detail_json TEXT NOT NULL DEFAULT '{}',
    ip          TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX idx_audit_log_org_id ON audit_log (org_id);
CREATE INDEX idx_audit_log_created_at ON audit_log (created_at);
