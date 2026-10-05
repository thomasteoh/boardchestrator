---
title: Getting started
desc: Install, configure, and run Boardchestrator locally or in production.
order: 2
---

## Requirements

- Go 1.25+ (or a prebuilt binary / Docker image)
- A `BC_SESSION_SECRET` of at least 32 characters
- A sign-in method: any OpenID Connect provider (Google, Entra, Okta, Keycloak, authentik, ...), GitHub, SAML 2.0, or passkeys

## Run it

```sh
# build the server
go build -o bc ./cmd/bc

# run with the required secrets
BC_SESSION_SECRET="$(openssl rand -hex 32)" \
BC_GOOGLE_CLIENT_ID="..." \
BC_GOOGLE_CLIENT_SECRET="..." \
BC_SECRET_KEY="$(openssl rand -hex 32)" \
./bc serve
```

The server listens on `0.0.0.0:8080` by default. Open `http://localhost:8080` and sign in with Google.

## First run

While nobody has claimed the instance, the server logs a claim URL at every start: `<BC_BASE_URL>/setup?token=…`. Open it and sign in; the first person to finish becomes platform owner. Set `BC_BOOTSTRAP_TOKEN` to choose the token, or `BC_ADMIN_EMAILS` to let listed addresses claim it by signing in. See [Sign-in and identity](/sign-in/).

## Configuration

Every setting is an environment variable prefixed with `BC_`. See the [deployment reference](/deployment/) for the full table. The two non-negotiable secrets:

- `BC_SESSION_SECRET` — HMAC key for session CSRF tokens. **Required, ≥32 chars.**
- `BC_SECRET_KEY` — encryption key for secrets at rest. **Required.**

## What you get

- A real-time kanban **board** with drag-and-drop, WIP limits, and swimlanes
- An **agent chat** that can assign, label, and decompose tasks
- A versioned **wiki** with autolinking and semantic search
- **MCP** tool servers plugged into the agent runtime
