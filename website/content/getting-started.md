---
title: Getting started
desc: Install, configure, and run Boardchestrator locally or in production.
order: 2
---

## Requirements

- Go 1.25+ (or a prebuilt binary / Docker image)
- A `BC_SESSION_SECRET` of at least 32 characters
- One OAuth provider: Google (recommended) or GitHub

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

On first boot, if you set `BC_BOOTSTRAP_TOKEN`, a bootstrap endpoint lets you create the first org without a provider. Otherwise sign in through the configured OAuth provider — the first user to sign in becomes an owner.

## Configuration

Every setting is an environment variable prefixed with `BC_`. See the [deployment reference](/docs/deployment/) for the full table. The two non-negotiable secrets:

- `BC_SESSION_SECRET` — HMAC key for session CSRF tokens. **Required, ≥32 chars.**
- `BC_SECRET_KEY` — encryption key for secrets at rest. **Required.**

## What you get

- A real-time kanban **board** with drag-and-drop, WIP limits, and swimlanes
- An **agent chat** that can assign, label, and decompose tasks
- A versioned **wiki** with autolinking and semantic search
- **MCP** tool servers plugged into the agent runtime
