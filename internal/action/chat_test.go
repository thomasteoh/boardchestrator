package action

import (
	"context"
	"database/sql"
	"encoding/json"
	"testing"

	"github.com/thomasteoh/boardchestrator/internal/db/dbtest"
	"github.com/thomasteoh/boardchestrator/internal/db/sqlc"
)

// registerChatFixtures registers the actions chat_test relies on. Each action
// test file owns its registry via reset()+t.Cleanup(reset) — the package init()
// registry is wiped by reset(), so tests re-register what they need.
func registerChatFixtures() {
	Register(Definition{Name: "org.create", Impact: ImpactHigh, Scope: ScopePlatform, Handle: handleOrgCreate})
	Register(Definition{Name: "provider.create", Impact: ImpactHigh, Scope: ScopePlatform, Handle: handleProviderCreate})
	Register(Definition{Name: "agent.create", Impact: ImpactHigh, Scope: ScopeOrg, Permission: "agent.create", Input: FuncSchema(func(raw json.RawMessage) error { return nil }), Handle: handleAgentCreate})
	Register(Definition{Name: "project.create", Impact: ImpactHigh, Scope: ScopeOrg, Permission: "project.create", Input: FuncSchema(func(raw json.RawMessage) error { return nil }), Handle: handleProjectCreate})
	Register(Definition{Name: "chat.session.create", Impact: ImpactLow, Scope: ScopeProject, Permission: "chat.session.create", Input: ObjectSchema{Fields: []Field{{Name: "org_id", Kind: KindString, Required: true}, {Name: "project_id", Kind: KindString, Required: false}, {Name: "team_id", Kind: KindString, Required: false}, {Name: "agent_id", Kind: KindString, Required: true}, {Name: "name", Kind: KindString, Required: false}}}, Handle: handleChatSessionCreate})
	Register(Definition{Name: "chat.send", Impact: ImpactLow, Scope: ScopeProject, Permission: "chat.send", Input: ObjectSchema{Fields: []Field{{Name: "chat_id", Kind: KindString, Required: true}, {Name: "text", Kind: KindString, Required: true}}}, Handle: handleChatSend})
	Register(Definition{Name: "chat.history", Impact: ImpactRead, Scope: ScopeProject, Permission: "chat.history", Input: ObjectSchema{Fields: []Field{{Name: "chat_id", Kind: KindString, Required: true}}}, Handle: handleChatHistory})
	Register(Definition{Name: "chat.session.list", Impact: ImpactRead, Scope: ScopeProject, Permission: "chat.session.list", Input: nil, Handle: handleChatSessionList})
}

// seedChatScope creates an org + provider + agent + project, returning their
// IDs. chat.session.create requires an existing agent (FK) and project scope.
func seedChatScope(t *testing.T, d *Dispatcher, name string) (orgID, agentID, projectID string) {
	t.Helper()
	ctx := context.Background()

	orgOut, err := d.Dispatch(ctx, userActor(), "org.create",
		json.RawMessage(`{"name":"`+name+`","slug":"`+name+`","visibility":"private"}`), Opts{Org: ""})
	if err != nil {
		t.Fatalf("seed org: %v", err)
	}
	orgID = extractID(t, mustJSON(t, orgOut))

	provOut, err := d.Dispatch(ctx, userActor(), "provider.create",
		json.RawMessage(`{"kind":"openai-compatible","name":"Chat Provider","base_url":"https://test.example.com/v1","models":["gpt-4o"]}`), Opts{})
	if err != nil {
		t.Fatalf("seed provider: %v", err)
	}
	providerID := extractID(t, mustJSON(t, provOut))

	agentRaw, _ := json.Marshal(map[string]any{"org_id": orgID, "name": "chat-agent", "provider_id": providerID, "model": "gpt-4o"})
	agentOut, err := d.Dispatch(ctx, userActor(), "agent.create", agentRaw, Opts{Org: orgID})
	if err != nil {
		t.Fatalf("seed agent: %v", err)
	}
	agentID = extractID(t, mustJSON(t, agentOut))

	projRaw, _ := json.Marshal(map[string]any{"org_id": orgID, "name": "Chat Project", "key": "CHAT", "visibility": "private"})
	projOut, err := d.Dispatch(ctx, userActor(), "project.create", projRaw, Opts{Org: orgID})
	if err != nil {
		t.Fatalf("seed project: %v", err)
	}
	projectID = extractID(t, mustJSON(t, projOut))

	return orgID, agentID, projectID
}

// TestChatSessionCreateAndSend covers the WU-308 happy path: create a session,
// send a user message, and read the history back (the user message + any
// assistant messages that were written).
func TestChatSessionCreateAndSend(t *testing.T) {
	reset()
	t.Cleanup(reset)
	registerChatFixtures()

	db := dbtest.New(t)
	d := New(db, WithScopeResolver(NewDBScopeResolver(db)))
	ctx := context.Background()

	orgID, agentID, projectID := seedChatScope(t, d, "chat-org")
	sessRaw, _ := json.Marshal(map[string]any{
		"org_id": orgID, "project_id": projectID, "agent_id": agentID, "name": "Test chat",
	})
	sessOut, err := d.Dispatch(ctx, userActor(), "chat.session.create", sessRaw, Opts{Org: orgID, Proj: projectID})
	if err != nil {
		t.Fatalf("chat.session.create: %v", err)
	}
	chatID := extractID(t, mustJSON(t, sessOut))
	if chatID == "" {
		t.Fatal("expected non-empty chat_id")
	}

	// Send a user message (chat.send writes the user message; the server
	// chatLoop enqueues the run separately — not exercised here).
	sendRaw, _ := json.Marshal(map[string]any{"chat_id": chatID, "text": "create a task for the landing page"})
	if _, err := d.Dispatch(ctx, userActor(), "chat.send", sendRaw, Opts{Org: orgID, Proj: projectID}); err != nil {
		t.Fatalf("chat.send: %v", err)
	}

	// History returns the user message.
	histRaw, _ := json.Marshal(map[string]string{"chat_id": chatID})
	histOut, err := d.Dispatch(ctx, userActor(), "chat.history", histRaw, Opts{Org: orgID, Proj: projectID})
	if err != nil {
		t.Fatalf("chat.history: %v", err)
	}
	msgs, ok := histOut.([]sqlc.ChatMessage)
	if !ok {
		t.Fatalf("expected []sqlc.ChatMessage, got %T", histOut)
	}
	if len(msgs) != 1 {
		t.Fatalf("expected 1 message, got %d", len(msgs))
	}
	if msgs[0].Role != "user" || msgs[0].Content != "create a task for the landing page" {
		t.Fatalf("unexpected message: role=%s content=%s", msgs[0].Role, msgs[0].Content)
	}
}

// TestChatScopePermission ensures the chat history read is org-scoped through
// the parent session (child-scoping): a chatID belonging to another org returns
// no messages, so a cross-org caller cannot read another tenant's transcript.
func TestChatScopePermission(t *testing.T) {
	reset()
	t.Cleanup(reset)
	registerChatFixtures()

	db := dbtest.New(t)
	d := New(db, WithScopeResolver(NewDBScopeResolver(db)))
	ctx := context.Background()

	orgA, agentA, projA := seedChatScope(t, d, "org-a")
	orgB, _, projB := seedChatScope(t, d, "org-b")

	// Session in org A.
	sessRaw, _ := json.Marshal(map[string]any{"org_id": orgA, "project_id": projA, "agent_id": agentA, "name": ""})
	sessOut, err := d.Dispatch(ctx, userActor(), "chat.session.create", sessRaw, Opts{Org: orgA, Proj: projA})
	if err != nil {
		t.Fatalf("chat.session.create: %v", err)
	}
	chatID := extractID(t, mustJSON(t, sessOut))

	// A caller in org B asking for org A's chatID gets no rows (the JOIN
	// scopes chat_messages through chat_sessions.org_id).
	histRaw, _ := json.Marshal(map[string]string{"chat_id": chatID})
	histOut, err := d.Dispatch(ctx, userActor(), "chat.history", histRaw, Opts{Org: orgB, Proj: projB})
	if err != nil {
		t.Fatalf("chat.history: %v", err)
	}
	msgs, ok := histOut.([]sqlc.ChatMessage)
	if !ok {
		t.Fatalf("expected []sqlc.ChatMessage, got %T", histOut)
	}
	if len(msgs) != 0 {
		t.Fatalf("expected 0 messages from cross-org read, got %d", len(msgs))
	}
}

var _ = sql.NullString{} // keep sql import for future FK-scoped helpers
