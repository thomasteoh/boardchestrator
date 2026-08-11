-- 0026 down: cost controls + usage (WU-310)
DROP TABLE IF EXISTS model_pricing;
-- SQLite cannot drop columns; the ALTERs on orgs are effectively irreversible.
-- Keep the (defaulted) columns; drop only the pricing table.
