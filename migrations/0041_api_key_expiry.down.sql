-- 0041 down: drop the API key expiry column.
ALTER TABLE api_keys DROP COLUMN expires_at;
