// Package agentrt implements the agent run engine (SPEC §10): run lifecycle,
// labelled-cascade context assembly, the registry-derived tool loop filtered
// by the agent's effective permission set, step caps, cancellation, and
// retry→notify failure handling.
package agentrt

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"strings"

	"github.com/thomasteoh/boardchestrator/internal/db/sqlc"
)

// assembleContext builds the model prompt context per SPEC §10, in fixed
// order: platform → org → team → project → agent → skill instructions → trigger
// payload. Each block is labelled with its source; absent scopes are skipped.
// For a task-triggered run the trigger payload is a task snapshot (fields,
// comments, relations, labels, attachment names); for chat it is the chat
// history (WU-308) — WU-305 only handles the task snapshot form.
func assembleContext(ctx context.Context, q *sqlc.Queries, agent sqlc.Agent, orgID, taskID, projectID string, trigger string) (string, error) {
	var b strings.Builder
	write := func(label string, body string) {
		if body == "" {
			return
		}
		if b.Len() > 0 {
			b.WriteByte('\n')
		}
		fmt.Fprintf(&b, "[%s]\n%s\n[/%s]", label, body, label)
	}

	// Platform context: none carried in the agent row for now (agent template
	// context is org-customised); the agent row's Context field is the org
	// agent's configured system context (see below).

	// Org context.
	if orgID != "" {
		org, err := q.FindOrgByID(ctx, orgID)
		if err == nil {
			write("org-context", org.Context)
		}
	}

	// Team + project context (SPEC §10 order: team before project).
	if projectID != "" {
		p, err := q.FindProjectByID(ctx, sqlc.FindProjectByIDParams{ID: projectID, OrgID: orgID})
		if err == nil {
			if p.TeamID.Valid && p.TeamID.String != "" {
				team, err := q.FindTeamByID(ctx, sqlc.FindTeamByIDParams{ID: p.TeamID.String, OrgID: orgID})
				if err == nil {
					write("team-context", team.Context)
				}
			}
			write("project-context", p.Context)
		}
	}

	// Agent context.
	write("agent-context", agent.Context)

	// Skill instructions (each attached skill), labelled by skill name.
	skills, err := q.ListAgentSkillsWithActions(ctx, sqlc.ListAgentSkillsWithActionsParams{
		AgentID: agent.ID,
		OrgID:   sql.NullString{String: orgID, Valid: orgID != ""},
	})
	if err != nil {
		return "", fmt.Errorf("assemble: list agent skills: %w", err)
	}
	for _, s := range skills {
		write("skill-"+s.Name, s.Instructions)
	}

	// Trigger payload — task snapshot.
	if taskID != "" && projectID != "" {
		snap, err := taskSnapshot(ctx, q, taskID, projectID, orgID)
		if err != nil {
			return "", err
		}
		write("task", snap)
	}

	// Trigger line (mention text / column prompt / schedule prompt).
	if trigger != "" {
		write("trigger", trigger)
	}

	return b.String(), nil
}

// assembleChatContext builds the model prompt for a chat run (WU-308). It
// mirrors assembleContext but, in place of the task snapshot, threads the chat
// session's transcript ([chat] block) so the agent sees prior turns. The
// chatID/orgID scope the history read; the run's project is the session's
// project (assembleContext already loads project/team context from orgID —
// here we pass the session's projectID explicitly).
func assembleChatContext(ctx context.Context, q *sqlc.Queries, agent sqlc.Agent, orgID, projectID, chatID string, instruction string) (string, error) {
	var b strings.Builder
	write := func(label string, body string) {
		if body == "" {
			return
		}
		if b.Len() > 0 {
			b.WriteByte('\n')
		}
		fmt.Fprintf(&b, "[%s]\n%s\n[/%s]", label, body, label)
	}

	// Org context.
	if orgID != "" {
		org, err := q.FindOrgByID(ctx, orgID)
		if err == nil {
			write("org-context", org.Context)
		}
	}

	// Team + project context.
	if projectID != "" {
		p, err := q.FindProjectByID(ctx, sqlc.FindProjectByIDParams{ID: projectID, OrgID: orgID})
		if err == nil {
			if p.TeamID.Valid && p.TeamID.String != "" {
				team, err := q.FindTeamByID(ctx, sqlc.FindTeamByIDParams{ID: p.TeamID.String, OrgID: orgID})
				if err == nil {
					write("team-context", team.Context)
				}
			}
			write("project-context", p.Context)
		}
	}

	// Agent context.
	write("agent-context", agent.Context)

	// Skill instructions.
	skills, err := q.ListAgentSkillsWithActions(ctx, sqlc.ListAgentSkillsWithActionsParams{
		AgentID: agent.ID,
		OrgID:   sql.NullString{String: orgID, Valid: orgID != ""},
	})
	if err != nil {
		return "", fmt.Errorf("assemble chat: list agent skills: %w", err)
	}
	for _, s := range skills {
		write("skill-"+s.Name, s.Instructions)
	}

	// Chat transcript. The history read is scoped through the parent session
	// (chat_messages JOIN chat_sessions on org_id), so a cross-org chatID
	// yields an empty transcript.
	if chatID != "" {
		msgs, err := q.ListChatMessages(ctx, sqlc.ListChatMessagesParams{ChatID: chatID, OrgID: orgID})
		if err != nil {
			return "", fmt.Errorf("assemble chat: list history: %w", err)
		}
		var tb strings.Builder
		for _, m := range msgs {
			fmt.Fprintf(&tb, "%s: %s\n", m.Role, m.Content)
		}
		write("chat", tb.String())
	}

	// Trigger line (the user's latest instruction).
	if instruction != "" {
		write("trigger", instruction)
	}

	return b.String(), nil
}

// taskSnapshot renders the labelled task context block: the task fields, its
// labels, comments, relations, and attachment names (SPEC §10).
func taskSnapshot(ctx context.Context, q *sqlc.Queries, taskID, projectID, orgID string) (string, error) {
	task, err := q.FindTaskByID(ctx, sqlc.FindTaskByIDParams{ID: taskID, ProjectID: projectID})
	if err != nil {
		return "", fmt.Errorf("assemble: find task: %w", err)
	}

	var b strings.Builder
	fmt.Fprintf(&b, "task: %s (%s)\n", task.Title, task.Key)
	if task.Description != "" {
		fmt.Fprintf(&b, "description: %s\n", task.Description)
	}
	if task.Points > 0 {
		fmt.Fprintf(&b, "points: %d\n", task.Points)
	}
	if task.Priority > 0 {
		fmt.Fprintf(&b, "priority: %d\n", task.Priority)
	}
	if task.DueAt != "" {
		fmt.Fprintf(&b, "due: %s\n", task.DueAt)
	}
	fmt.Fprintf(&b, "status: %s\n", task.Status)

	// Labels.
	labels, err := q.GetTaskLabels(ctx, sqlc.GetTaskLabelsParams{OrgID: orgID, TaskID: taskID, ProjectID: projectID})
	if err != nil {
		return "", fmt.Errorf("assemble: task labels: %w", err)
	}
	if len(labels) > 0 {
		var names []string
		for _, l := range labels {
			names = append(names, l.Name)
		}
		fmt.Fprintf(&b, "labels: %s\n", strings.Join(names, ", "))
	}

	// Relations (parent/child/dependency).
	rels, err := q.ListTaskRelations(ctx, sqlc.ListTaskRelationsParams{TaskID: taskID, RelatedTaskID: taskID, ProjectID: projectID})
	if err != nil {
		return "", fmt.Errorf("assemble: task relations: %w", err)
	}
	if len(rels) > 0 {
		var lines []string
		for _, r := range rels {
			other := r.TaskID
			if r.TaskID == taskID {
				other = r.RelatedTaskID
			}
			lines = append(lines, fmt.Sprintf("%s %s", other, r.RelationType))
		}
		sort.Strings(lines)
		fmt.Fprintf(&b, "relations: %s\n", strings.Join(lines, ", "))
	}

	// Comments.
	comments, err := q.ListCommentsByTask(ctx, sqlc.ListCommentsByTaskParams{TaskID: taskID, ProjectID: projectID})
	if err != nil {
		return "", fmt.Errorf("assemble: task comments: %w", err)
	}
	if len(comments) > 0 {
		for _, c := range comments {
			fmt.Fprintf(&b, "comment: %s\n", c.Body)
		}
	}

	// Attachment names.
	atts, err := q.ListAttachmentsByTask(ctx, taskID)
	if err != nil {
		return "", fmt.Errorf("assemble: task attachments: %w", err)
	}
	if len(atts) > 0 {
		var names []string
		for _, a := range atts {
			names = append(names, a.Filename)
		}
		fmt.Fprintf(&b, "attachments: %s\n", strings.Join(names, ", "))
	}

	return b.String(), nil
}
