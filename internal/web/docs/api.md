# API & actions

Every mutation in Boardchestrator flows through the action dispatch pipeline: `POST /api/action/<name>` with a JSON or form body. The same pipeline backs the UI (htmx), MCP, and agent tool calls.

## Authentication

- **Browser sessions** — cookie-authenticated. State-changing requests must carry a per-session CSRF token in the `X-CSRF-Token` header (HTMX sends it automatically) or the `csrf_token` form field. The token is `HMAC-SHA256(BC_SESSION_SECRET, session.token_hash)` — bound to the session, stateless, constant-time compared.
- **API keys** — `Authorization: Bearer <token>`. A key is `<8-char prefix><64-hex-secret>`. The secret is hashed at rest; the prefix looks it up and the secret verifies it. Keys scope which actions are visible (omission, not denial).
- **MCP** — `POST /mcp` accepts the same Bearer API key; the key's scope filters which tools appear.

## Scoping

A request is scoped by `X-Org-Id`, `X-Project-Id`, and `X-Team-Id` headers. When those are absent, scope ids are read from the input JSON's `org_id` / `project_id` / `team_id` fields. Headers win; input only fills gaps.

## Dry-run

Send `X-Dry-Run: true` to run validation + permission + scope and get a **preview** without mutating anything. The UI's propose→approve flow uses this.

## Idempotency

Pass an `idem` key in the input to make the call idempotent: a repeat with the same key returns the stored result without re-executing.

## Pipeline

`resolve actor → validate input → verify scope → permission → approval gate (agents) → idempotency → execute in a tx → emit event → audit`. High-impact and every agent action are always audited.

## Action index

Common actions (the full set is exposed in the [OpenAPI spec](/api/v1/openapi.json)):

- **Tasks** — `task.create`, `task.update`, `task.move`, `task.assign`, `task.label`, `task.archive`, `task.unarchive`, `task.relate`, `task.list`
- **Board** — `board.column.create`, `board.column.update`, `board.column.delete`, `board.column.reorder`
- **Backlog/sprints** — `backlog`, `sprint.create`, `sprint.update`, `sprint.close`
- **Agents/chat** — `chat.send`, `chat.session.create`, `chat.history`, `agent.create`, `agent.update`, `agent.delete`, `agent.list`
- **Org/team/project** — `org.create`, `org.update`, `team.create`, `team.update`, `project.create`, `project.update`, `project.archive`, `project.unarchive`
- **People/permissions** — `member.invite`, `member.remove`, `role.create`, `role.update`, `role.list`, `invite.accept`
- **Wiki** — `wiki.edit`, `wiki.rename`, `wiki.delete`, `wiki.history`, `wiki.read`, `wiki.tree`
- **Webhooks/triggers** — `webhook.create`, `webhook.update`, `webhook.delete`, `trigger.create`, `trigger.update`, `trigger.delete`
- **Reports/usage** — `report.burndown`, `report.flow`, `report.csv`, `usage.read`
- **Storage/API keys** — `org.storage.configure`, `apikey.create`, `apikey.revoke`
