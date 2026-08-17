# Boardchestrator

**The operating system for your agents.** A self-hosted agent workspace with a real-time kanban board, autonomous agents, a versioned wiki, and MCP tool integration — one Go binary, one SQLite file.

[Website](https://thomasteoh.github.io/boardchestrator/) · [Documentation](/website) · [GitHub](https://github.com/thomasteoh/boardchestrator)

## What it is

Boardchestrator brings a kanban board, agent chat, a versioned wiki, and Model Context Protocol tool servers together behind a single real-time web UI. Agents operate inside your orgs/projects/teams — assigning, labelling, and decomposing work with your approval.

- **Board** — visual task management with drag-and-drop, WIP limits, swimlanes, and live updates over SSE (no refresh).
- **Agents** — autonomous tool-use with multi-step execution and a streaming chat interface. Slash commands map to board actions (`/assign`, `/label`, `/decompose`).
- **Wiki** — versioned project knowledge base with autolinking and semantic search.
- **MCP** — plug any Model Context Protocol tool server into the agent runtime.

## Quickstart

```sh
go build -o bc ./cmd/bc

BC_SESSION_SECRET="$(openssl rand -hex 32)" \
BC_GOOGLE_CLIENT_ID="..." \
BC_GOOGLE_CLIENT_SECRET="..." \
BC_SECRET_KEY="$(openssl rand -hex 32)" \
./bc serve
```

Open `http://localhost:8080` and sign in with Google. See [Getting started](/website/content/getting-started.md) and [Deployment](/website/content/deployment.md) for the full guide.

## Documentation

Full docs live in the [public website](/website/content/):

- [Getting started](/website/content/getting-started.md)
- [Deployment](/website/content/deployment.md) — Docker, environment reference, operations
- [Concepts](/website/content/concepts.md) — boards, agents, wiki, MCP

Project-internal docs: [PRD.md](PRD.md), [SPEC.md](SPEC.md), [DEPLOY.md](DEPLOY.md), [BACKLOG.md](BACKLOG.md), [PROCESS-WORKFLOW.md](PROCESS-WORKFLOW.md), [PROCESS-RETRO.md](PROCESS-RETRO.md).

## Repository layout

```
cmd/bc/        server binary
internal/      packages (web, action, agentrt, auth, db, config, ...)
migrations/    SQLite schema migrations
website/       public website generator (Go static site → GitHub Pages)
public/        app favicon
scripts/       smoke tests, dev tooling
```

## License

Open source. See [LICENSE](LICENSE).
