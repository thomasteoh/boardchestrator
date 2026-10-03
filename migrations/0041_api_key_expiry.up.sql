-- 0041: optional API key expiry (SPEC s7.10, WU-613). NULL = never expires.
ALTER TABLE api_keys ADD COLUMN expires_at TEXT;
