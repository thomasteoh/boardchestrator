package action

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/thomasteoh/boardchestrator/internal/db/sqlc"
)

// chatSessionCreateInput is the input to chat.session.create.
type chatSessionCreateInput struct {
	OrgID     string `json:"org_id"`
	ProjectID string `json:"project_id,omitempty"`
	TeamID    string `json:"team_id,omitempty"`
	AgentID   string `json:"agent_id"`
	Name      string `json:"name,omitempty"`
}

// handleChatSessionCreate creates a chat_sessions row (WU-308). Scope is the
// project by default, or team/org for permitted users. The scope ids are
// resolved via the action's ScopeProject so the ScopeResolver verifies the
// project belongs to the org.
func handleChatSessionCreate(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	var input chatSessionCreateInput
	if err := json.Unmarshal(in, &input); err != nil {
		return nil, fmt.Errorf("chat.session.create: %w", err)
	}
	if input.AgentID == "" {
		return nil, fmt.Errorf("chat.session.create: agent_id is required")
	}
	if ac.Proj == "" {
		return nil, fmt.Errorf("chat.session.create: missing project scope")
	}

	id := newID()
	created, err := ac.Tx.CreateChatSession(ctx, sqlc.CreateChatSessionParams{
		ID:        id,
		OrgID:     ac.Org,
		ProjectID: sql.NullString{String: input.ProjectID, Valid: input.ProjectID != ""},
		TeamID:    sql.NullString{String: input.TeamID, Valid: input.TeamID != ""},
		AgentID:   input.AgentID,
		Name:      input.Name,
		CreatedBy: ac.Actor.ref(),
	})
	if err != nil {
		return nil, fmt.Errorf("chat.session.create: %w", err)
	}
	return map[string]string{"id": created.ID}, nil
}

// chatSendInput is the input to chat.send.
type chatSendInput struct {
	ChatID string `json:"chat_id"`
	Text   string `json:"text"`
}

// handleChatSend writes the user's message and emits chat.sent (WU-308). The
// dispatch pipeline emits chat.sent (event name == action name); a server-side
// chatLoop subscriber reads the chat session (agent + scope) from the DB and
// enqueues the run job via EnqueueRun. The engine's Handler detects the run's
// chat_session_id and runs the streaming chat loop, writing the assistant reply
// + action cards back to chat_messages.
func handleChatSend(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	var input chatSendInput
	if err := json.Unmarshal(in, &input); err != nil {
		return nil, fmt.Errorf("chat.send: %w", err)
	}
	if input.ChatID == "" || input.Text == "" {
		return nil, fmt.Errorf("chat.send: chat_id and text are required")
	}

	// The chat_sessions row is verified to belong to the org by CreateChatMessage
	// (child-scoping EXISTS clause) below; scope resolution already verified the
	// project. Write the user message first.
	userMsgID := newID()
	err := ac.Tx.CreateChatMessage(ctx, sqlc.CreateChatMessageParams{
		ID:          userMsgID,
		ChatID:      input.ChatID,
		Role:        "user",
		Content:     input.Text,
		RunID:       sql.NullString{},
		ActionName:  "",
		ActionInput: "",
		ID_2:        input.ChatID, // EXISTS scope: chat_id
		OrgID:       ac.Org,
	})
	if err != nil {
		return nil, fmt.Errorf("chat.send: user message: %w", err)
	}

	// The event payload carries everything the server chatLoop needs to enqueue
	// the run job and stream deltas to the initiating user.
	return map[string]string{
		"chat_id": input.ChatID,
		"text":    input.Text,
	}, nil
}

// chatHistoryInput is the input to chat.history.
type chatHistoryInput struct {
	ChatID string `json:"chat_id"`
}

// handleChatHistory lists the transcript for a chat session (WU-308). The
// query joins chat_messages to chat_sessions so a cross-org session returns
// no rows (scoped through the parent).
func handleChatHistory(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	var input chatHistoryInput
	if err := json.Unmarshal(in, &input); err != nil {
		return nil, fmt.Errorf("chat.history: %w", err)
	}
	msgs, err := ac.Tx.ListChatMessages(ctx, sqlc.ListChatMessagesParams{
		ChatID: input.ChatID,
		OrgID:  ac.Org,
	})
	if err != nil {
		return nil, fmt.Errorf("chat.history: %w", err)
	}
	return msgs, nil
}

// chatSessionListInput is the input to chat.session.list.
type chatSessionListInput struct {
	Limit int64 `json:"limit,omitempty"`
}

// handleChatSessionList lists sessions for the current scope (project default;
// team/org for permitted users — the caller sets ac.Proj/ac.Team accordingly).
func handleChatSessionList(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) {
	limit := int64(50)
	if ac.Proj != "" {
		sessions, err := ac.Tx.ListChatSessionsByProject(ctx, sqlc.ListChatSessionsByProjectParams{
			OrgID:     ac.Org,
			ProjectID: sql.NullString{String: ac.Proj, Valid: true},
			Limit:     limit,
		})
		if err != nil {
			return nil, fmt.Errorf("chat.session.list: %w", err)
		}
		return sessions, nil
	}
	sessions, err := ac.Tx.ListChatSessionsByOrg(ctx, sqlc.ListChatSessionsByOrgParams{
		OrgID: ac.Org,
		Limit: limit,
	})
	if err != nil {
		return nil, fmt.Errorf("chat.session.list: %w", err)
	}
	return sessions, nil
}

func init() {
	Register(Definition{
		Name:       "chat.session.create",
		Impact:     ImpactLow,
		Permission: "chat.session.create",
		Scope:      ScopeProject,
		Input: ObjectSchema{Fields: []Field{
			{Name: "org_id", Kind: KindString, Required: true},
			{Name: "project_id", Kind: KindString, Required: false},
			{Name: "team_id", Kind: KindString, Required: false},
			{Name: "agent_id", Kind: KindString, Required: true},
			{Name: "name", Kind: KindString, Required: false},
		}},
		Handle: handleChatSessionCreate,
	})
	Register(Definition{
		Name:       "chat.send",
		Impact:     ImpactLow,
		Permission: "chat.send",
		Scope:      ScopeProject,
		Input: ObjectSchema{Fields: []Field{
			{Name: "chat_id", Kind: KindString, Required: true},
			{Name: "text", Kind: KindString, Required: true},
		}},
		Handle: handleChatSend,
	})
	Register(Definition{
		Name:       "chat.history",
		Impact:     ImpactRead,
		Permission: "chat.history",
		Scope:      ScopeProject,
		Input: ObjectSchema{Fields: []Field{
			{Name: "chat_id", Kind: KindString, Required: true},
		}},
		Handle: handleChatHistory,
	})
	Register(Definition{
		Name:       "chat.session.list",
		Impact:     ImpactRead,
		Permission: "chat.session.list",
		Scope:      ScopeProject,
		Input:      nil,
		Handle:     handleChatSessionList,
	})
}
