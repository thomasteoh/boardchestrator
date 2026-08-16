# Board

The board is a real-time kanban view of a project's work.

## Columns

Each column is a workflow state (e.g. To do, In progress, Done). Cards move between columns as work progresses.

- **Drag-and-drop** — pick up a card and move it to another column.
- **Keyboard** — grab with `Space`, move with `↑`/`↓`, drop with `Enter`, cancel with `Esc`.
- **Mobile focus mode** — on a narrow screen the board shows one column at a time; use `→`/`←` to step between columns.

## WIP limits

Set a work-in-progress limit on a column so it never overflows. When a column is at its limit, the board shows the constraint so you can see where work is piling up.

## Swimlanes

Swimlanes group cards horizontally (e.g. by assignee or type) so you can see the shape of the work across columns at a glance.

## Live updates

The board streams changes over SSE. Create, move, and label operations from any session appear immediately, without a refresh.
