---
title: Deployment
desc: Docker, environment reference, and operations for running Boardchestrator in production.
order: 3
---

Boardchestrator ships as a single Go binary. The official container image is published to `ghcr.io/thomasteoh/boardchestrator` on every version tag.

## Docker Compose

```yaml
services:
  bc:
    image: ghcr.io/thomasteoh/boardchestrator:latest
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

Secrets come from a `.env` file or your secret store — never commit them.

## Data layout

The single `bc-data` volume maps to `BC_DATA_DIR`:

```
/data
├── bc.db              # SQLite database
├── backups/           # snapshots (pruned to newest 5)
├── attachments/       # org/task file attachments
└── wiki/              # wiki checkout cache
```

Mount `bc-data` on durable storage. Put `backups/` on a separate persistent volume if you need snapshot history beyond the container.

## Environment reference

| Env | Type | Default | Notes |
|-----|------|---------|-------|
| `BC_DB_PATH` | string | `bc.db` | SQLite database path |
| `BC_DATA_DIR` | string | `./data` | data root |
| `BC_BASE_URL` | string | `http://localhost:8080` | external URL (OAuth redirects) |
| `BC_BIND` | string | `0.0.0.0:8080` | listen address |
| `BC_LOG_LEVEL` | string | `info` | debug/info/warn/error |
| `BC_SECRET_KEY` | string | required | encryption key for secrets |
| `BC_SESSION_SECRET` | string | required | session HMAC secret (≥32 chars) |
| `BC_BOOTSTRAP_TOKEN` | string | `` | first-run bootstrap token |
| `BC_ADMIN_EMAILS` | string | `` | comma-separated admin emails |
| `BC_GOOGLE_CLIENT_ID` | string | required | Google OAuth client id |
| `BC_GOOGLE_CLIENT_SECRET` | string | required | Google OAuth client secret |
| `BC_GITHUB_CLIENT_ID` | string | `` | GitHub OAuth client id |
| `BC_GITHUB_CLIENT_SECRET` | string | `` | GitHub OAuth client secret |
| `BC_AGENT_WORKERS` | int | `4` | worker pool size |
| `BC_SCHED_POLL_INTERVAL` | int | `60` | scheduler poll seconds |

## Operations

- `bc serve` — run the server.
- `bc backup` — online SQLite snapshot via `VACUUM INTO`, pruned to the newest 5.
- `bc storage migrate <org-id>` — migrate an org's attachments from local to S3.

`GET /readyz` returns `200 {"status":"ok"}` when the server is up, the DB is reachable, and the queue is healthy. Wire it to your orchestrator's healthcheck (see the compose example).
