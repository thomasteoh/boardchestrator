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
| `BC_GOOGLE_CLIENT_ID` | string | `` | Google OAuth client id (seeds sign-in provider `google`) |
| `BC_GOOGLE_CLIENT_SECRET` | string | `` | Google OAuth client secret |
| `BC_GITHUB_CLIENT_ID` | string | `` | GitHub OAuth client id (seeds sign-in provider `github`) |
| `BC_GITHUB_CLIENT_SECRET` | string | `` | GitHub OAuth client secret |
| `BC_OIDC_<NAME>_ISSUER` | string | preset default | OIDC issuer URL for provider `<name>` (lower-cased, `_` becomes `-`) |
| `BC_OIDC_<NAME>_CLIENT_ID` | string | required per provider | OIDC client id |
| `BC_OIDC_<NAME>_CLIENT_SECRET` | string | `` | OIDC client secret |
| `BC_OIDC_<NAME>_PRESET` | string | `generic` | google, microsoft, gitlab, okta, auth0, keycloak, zitadel, authentik, generic |
| `BC_OIDC_<NAME>_DISPLAY_NAME` | string | preset name | label on the sign-in button |
| `BC_OIDC_<NAME>_TRUST_EMAIL` | bool | preset default | link to existing users by verified email |
| `BC_OIDC_<NAME>_ALLOW_SIGNUP` | bool | `true` | let new users sign up through this provider |
| `BC_OIDC_<NAME>_SCOPES` | string | preset default | space- or comma-separated scopes |
| `BC_OIDC_<NAME>_GROUPS_CLAIM` | string | preset default | claim (or dotted path) holding the user's groups |
| `BC_AGENT_WORKERS` | int | `4` | worker pool size |
| `BC_SCHED_POLL_INTERVAL` | int | `60` | scheduler poll seconds |

At least one sign-in provider should be configured; the server starts
without one but logs a warning, because nobody can sign in. Env-configured
providers are written to the `auth_providers` table at startup; removing a
provider's variables disables it on the next start (its users' identities are
kept).

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
