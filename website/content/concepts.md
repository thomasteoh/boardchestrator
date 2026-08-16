---
title: Concepts
desc: Boards, agents, wiki, and MCP — how the pieces fit together.
order: 4
---

## The model

Boardchestrator is organised as **orgs → projects → teams**. An org owns projects and teams; teams own work. Agents operate inside a project or team scope.

## Board

A real-time kanban board. Cards move between columns via drag-and-drop, keyboard (grab-move-drop with Space/arrows/Enter), or agent actions. Live updates stream over SSE — no refresh needed. WIP limits and swimlanes keep the board honest.

## Agents

Autonomous agents run inside your workspace. They have tool-use, multi-step execution, and a chat interface. Slash commands map agent work to board actions:

- `/assign …` — assign the responsible person
- `/label …` — apply a label to matching tasks
- `/decompose …` — propose a subtask breakdown

Proposed actions are shown as cards you can preview (dry-run) before approving.

## Wiki

A versioned project knowledge base. Notes autolink across the project, and semantic search surfaces relevant context. The wiki checkout is cached under `BC_DATA_DIR/wiki`.

## MCP

Model Context Protocol tool servers plug straight into the agent runtime. Any MCP server you can run, the agent can call.
