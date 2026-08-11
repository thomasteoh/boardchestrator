-- 0026: cost controls + usage (WU-310)
--
-- model_pricing: platform-global price table per provider+model, editable by
-- platform admin (no org_id — pricing is not tenant-scoped). input/output
-- cost per 1M tokens (MTok), USD.
--
-- orgs gain monthly_cap_usd + cap_alert_pct: the org's monthly spend ceiling.
-- cap_alert_pct is the % of the cap that triggers a threshold alert; 0 disables
-- the alert. monthly_cap_usd 0 = unlimited (no hard stop).

CREATE TABLE IF NOT EXISTS model_pricing (
    id            TEXT PRIMARY KEY,
    provider_id   TEXT NOT NULL REFERENCES providers(id) ON DELETE CASCADE,
    model         TEXT NOT NULL,
    input_per_mtok  REAL NOT NULL DEFAULT 0,
    output_per_mtok REAL NOT NULL DEFAULT 0,
    created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%S.000Z', 'now')),
    updated_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%S.000Z', 'now')),
    UNIQUE(provider_id, model)
);

CREATE INDEX IF NOT EXISTS idx_model_pricing_provider ON model_pricing(provider_id);

ALTER TABLE orgs ADD COLUMN monthly_cap_usd REAL NOT NULL DEFAULT 0;
ALTER TABLE orgs ADD COLUMN cap_alert_pct REAL NOT NULL DEFAULT 80;

-- org_cap_alerts: one row per org per threshold crossing (WU-310). The alert
-- fires once per crossing; the engine tracks fired orgs in memory so it doesn't
-- re-alert on every run.
CREATE TABLE IF NOT EXISTS org_cap_alerts (
    id         TEXT PRIMARY KEY,
    org_id     TEXT NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    spend_usd  REAL NOT NULL,
    cap_usd    REAL NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%S.000Z', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_org_cap_alerts_org ON org_cap_alerts(org_id);
