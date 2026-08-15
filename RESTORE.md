# Restore

This document covers restoring a `bc backup` snapshot. Backups are produced by
`bc backup` (WU-507) via `VACUUM INTO` and are fully self-contained SQLite
databases. No external tooling is required to restore them.

## Prerequisites

- The `bc` binary built from this repo (`make build` or `go build ./cmd/bc`).
- A backup file produced by `bc backup` (default: `./data/backups/boardchestrator-<timestamp>.db`).

## Restore procedure

1. Stop the server so no writes race the restore:
   ```sh
   systemctl stop boardchestrator   # or kill the bc serve process
   ```

2. (Recommended) back up the current DB first:
   ```sh
   cp "$BC_DB_PATH" "$BC_DB_PATH.pre-restore"
   ```

3. Replace the live DB with the backup snapshot:
   ```sh
   cp data/backups/boardchestrator-20260815T010459Z.db "$BC_DB_PATH"
   ```

4. Restart the server. On startup it applies migrations automatically
   (`db.MigrateUp` is idempotent), so a backup taken before a schema change
   upgrades cleanly:
   ```sh
   systemctl start boardchestrator
   ```

5. Verify readiness and data:
   ```sh
   curl -s http://localhost:8080/readyz | jq .status   # → "ok"
   ```

## Verification

A restored database is verified by opening it directly with the sqlite driver
and querying a known row (see `cmd/bc/backup_test.go` for the automated
round-trip test). The round-trip test creates a live DB, inserts a marker row,
runs `bc backup`, then opens the backup file and asserts the marker is present.

## Notes

- `bc backup` prunes to the newest 5 backups by default (configurable via the
  `backupKeep` constant). Old snapshots are removed oldest-first.
- Backups are written to `<BC_DATA_DIR>/backups/`. Mount this directory onto
  durable storage in production so snapshots survive container restarts.
