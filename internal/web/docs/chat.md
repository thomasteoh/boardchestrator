# Chat & agents

The agent chat runs autonomous agents inside your workspace. Agents have tool-use and multi-step execution, and they stream their work live.

## Slash commands

Agent work maps to board actions with slash commands:

- `/assign <task> <person>` — assign the responsible person.
- `/label <task> <label>` — apply a label to matching tasks.
- `/decompose <task>` — propose a subtask breakdown.

## Approving agent actions

Proposed actions are shown as cards you can preview (dry-run) before approving. Nothing mutates your board without your say-so.

## Runs

Each agent invocation is a **run**. Open a run from the chat history to see the full trace of what the agent did — the tools it called, the steps it took, and the result. Runs are stored per task (`/task/{taskID}/run/{runID}`) and org-wide.
