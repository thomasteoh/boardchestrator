# Deploy

This document covers deploying boardchestrator in a container (docker
compose) and the runtime environment reference.

## Compose example

`compose.yaml` (docker compose v2):

```yaml
services:
  bc:
    image: boardchestrator:latest
    build: .
    ports:
      - "8080:8080"
    environment:
      BC_DB_PATH: /data/bc.db
      BC_DATA_DIR: /data
      BC_BASE_URL: https://bc.example.com
      BC_BIND: 0.0.0.0:8080
      BC_SECRET_KEY: ${BC_SECRET_KEY}
      BC_SESSION_SECRET: ${BC_SESSION_SECRET}
      BC_GOOGLE_CLIENT_ID: ${BC_GOOGLE_CLIENT_ID}
      BC_GOOGLE_CLIENT_SECRET: ${BC_GOOGLE_CLIENT_SECRET}
      BC_AGENT_WORKERS: "4"
      BC_SCHED_POLL_INTERVAL: "60"
    volumes:
      - bc-data:/data
    healthcheck:
      test: ["CMD", "wget", "-qO-", "http://localhost:8080/readyz"]
      interval: 30s
      timeout: 3s
      retries: 3
      start_period: 5s

volumes:
  bc-data:
```

## Volume layout

The single volume `bc-data` mounts `<BC_DATA_DIR>`. Inside it:

```
/data
├── bc.db              # SQLite database (BC_DB_PATH)
├── backups/           # bc backup snapshots (pruned to newest 5)
│   └── boardchestrator-<timestamp>.db
├── attachments/       # local attachment store (org/<task>/<id>_<name>)
└── wiki/              # wiki checkout cache
```

Mount `bc-data` onto durable storage. In production put `backups/` on a
separate persistent volume if you need snapshot history beyond the container.

## Environment reference

Generated from the `internal/config.Config` struct (`config.EnvReference`).
Every variable is `BC_`-prefixed.

| Env | Type | Default | Notes |
|-----|------|---------|-------|
| `BC_DB_PATH` | string | `bc.db` | SQLite database path |
| `BC_DATA_DIR` | string | `./data` | data root (backups, attachments, wiki) |
| `BC_BASE_URL` | string | `http://localhost:8080` | external base URL (OAuth redirects) |
| `BC_BIND` | string | `0.0.0.0:8080` | listen address |
| `BC_LOG_LEVEL` | string | `info` | debug/info/warn/error |
| `BC_SECRET_KEY` | string | required | encryption key for secrets at rest |
| `BC_SESSION_SECRET` | string | required | session HMAC secret (≥32 chars) |
| `BC_BOOTSTRAP_TOKEN` | string | `` | first-run bootstrap token |
| `BC_ADMIN_EMAILS` | string | `` | comma-separated admin emails |
| `BC_GOOGLE_CLIENT_ID` | string | required | Google OAuth client id |
| `BC_GOOGLE_CLIENT_SECRET` | string | required | Google OAuth client secret |
| `BC_GITHUB_CLIENT_ID` | string | `` | GitHub OAuth client id |
| `BC_GITHUB_CLIENT_SECRET` | string | `` | GitHub OAuth client secret |
| `BC_AGENT_WORKERS` | int | `4` | worker pool size |
| `BC_SCHED_POLL_INTERVAL` | int | `60` | scheduler poll seconds |

Secrets (`BC_SECRET_KEY`, `BC_SESSION_SECRET`, OAuth secrets) should come from
a secret store, never committed. Use `${VAR}` interpolation in compose or a
`.env` file excluded from git.

## Readiness

`GET /readyz` reports `200 {"status":"ok"}` when the server is up **and** the
DB is reachable **and** the queue is healthy (depth + oldest queued age).
Any degraded component returns `503` with the failing check named. Wire this
to your orchestrator's healthcheck (see compose above).

## Commands

- `bc serve` — run the server.
- `bc backup` — `VACUUM INTO` snapshot to `backups/`, prunes to newest 5.
- `bc storage migrate <org-id>` — migrate an org's attachments local→S3.
