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
| `BC_DATA_DIR` | string | `./data` | data root (backups, attachments, wiki) |
| `BC_BASE_URL` | string | `http://localhost:8080` | external base URL (OAuth redirects) |
| `BC_BIND` | string | `0.0.0.0:8080` | listen address |
| `BC_LOG_LEVEL` | string | `info` | debug/info/warn/error |
| `BC_SECRET_KEY` | string | required | encryption key for secrets at rest |
| `BC_SESSION_SECRET` | string | required | session HMAC secret (≥32 chars) |
| `BC_BOOTSTRAP_TOKEN` | string | `` (generated) | token that claims an unclaimed instance at `/setup?token=`; see "Claiming a new instance" |
| `BC_ADMIN_EMAILS` | string | `` | comma-separated admin emails; while the instance is unclaimed their first sign-in (verified email) claims it, and they always hold platform admin |
| `BC_TRUSTED_PROXIES` | string | `` | comma-separated CIDRs or addresses of reverse proxies whose `X-Forwarded-For` is believed for the client IP (sign-in rate limits, audit rows, sessions). Empty: the TCP peer is the client and `X-Forwarded-For` is ignored. Set it to your proxy's address, otherwise every client behind the proxy shares one rate-limit bucket |
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
| `BC_OIDC_<NAME>_ALLOW_SIGNUP` | bool | `BC_ALLOW_SIGNUP` | let new users sign up through this provider |
| `BC_OIDC_<NAME>_SCOPES` | string | preset default | space- or comma-separated scopes |
| `BC_OIDC_<NAME>_GROUPS_CLAIM` | string | preset default | claim (or dotted path) holding the user's groups |
| `BC_ALLOW_SIGNUP` | bool | `true` | open sign-up on the env-configured providers (`google`, `github`, and `BC_OIDC_<NAME>_*` without their own `_ALLOW_SIGNUP`); `false` makes them invite-only. Providers added in the admin UI are invite-only unless the admin ticks "Let anyone who signs in through this provider create an account". Invite links and the bootstrap admin can always sign up |
| `BC_ORG_IDP_ALLOW_PRIVATE` | bool | `false` | let organisation-owned identity providers (and org owners' "Test discovery") reach private and loopback addresses; off, only public addresses are dialled for them (QUESTIONS Q11) |
| `BC_AGENT_WORKERS` | int | `4` | worker pool size |
| `BC_SCHED_POLL_INTERVAL` | int | `60` | scheduler poll seconds |

`BC_OIDC_<NAME>_*` configures one OpenID Connect provider per `<NAME>`: the provider ID is `<NAME>` lower-cased with `_` becoming `-`, so `BC_OIDC_CORP_SSO_CLIENT_ID` sets up provider `corp-sso` with callback `<BC_BASE_URL>/auth/corp-sso/callback`. See [Sign-in and identity](/sign-in/) for every provider, the URLs to register, organisation SSO and passkeys.

## Operations

- `bc serve` — run the server.
- `bc backup` — online SQLite snapshot via `VACUUM INTO`, pruned to the newest 5.
- `bc storage migrate <org-id>` — migrate an org's attachments from local to S3.

`GET /readyz` returns `200 {"status":"ok"}` when the server is up, the DB is reachable, and the queue is healthy. Wire it to your orchestrator's healthcheck (see the compose example).
