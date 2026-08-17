# MCP integration

Boardchestrator is itself an MCP server, and it can plug other MCP servers into its agents.

## Using Boardchestrator's MCP endpoint

Boardchestrator speaks **MCP over Streamable HTTP** at `POST /mcp` — JSON-RPC 2.0. Point any MCP client at it with an API key:

- `initialize` — reports the protocol version and server capabilities.
- `tools/list` — lists the available tools. Tool names are the action names with dots → underscores (e.g. `task.create` → `task_create`). **Scope-aware**: a key only sees the tools its scope allows (omission, not denial).
- `tools/call` — invokes a tool, running the full action pipeline.
- `resources/list`, `resources/read` — expose project/org resources.
- `prompts/list`, `prompts/get` — prompt templates.

Auth: `Authorization: Bearer <api-key>` (create one under **API Keys** in the org).

## Wiring external MCP servers into agents

Agents can use tools from any MCP server you plug in. Configure the server endpoint + credentials under **Skills** — credentials are encrypted at rest with the org secret key. Once wired, the agent runtime discovers the server's tools and can call them as part of a run.
