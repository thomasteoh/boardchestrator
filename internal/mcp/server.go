package mcp

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/thomasteoh/boardchestrator/internal/action"
	"github.com/thomasteoh/boardchestrator/internal/auth"
	"github.com/thomasteoh/boardchestrator/internal/db/sqlc"
	"github.com/thomasteoh/boardchestrator/internal/wiki"
)

// randBytes returns n cryptographically random bytes.
func randBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return b
	}
	return b
}

// WU-403 MCP server (SPEC §12): a minimal in-repo JSON-RPC implementation of
// the Model Context Protocol over Streamable HTTP at /mcp.
//
// Decision (recorded in BACKLOG WU-403 notes): in-repo implementation rather
// than modelcontextprotocol/go-sdk — the protocol surface we need here
// (initialize, tools/list, tools/call, resources/list, resources/read,
// prompts/list, prompts/get) is small, and the repo already owns the auth
// (bearer API key) + dispatch seams; the SDK would add a heavy dependency for
// little gain. Streamable HTTP responses are returned as a single JSON-RPC
// body (no SSE stream) per the spec's non-streaming mode.

// protocol version we speak.
const protocolVersion = "2024-11-05"

// Dispatcher is the action dispatch seam the MCP server calls.
type Dispatcher interface {
	Dispatch(ctx context.Context, actor action.Actor, name string, input json.RawMessage, opts action.Opts) (any, error)
}

// Server handles MCP JSON-RPC requests over Streamable HTTP.
type Server struct {
	db         *sql.DB
	dispatcher Dispatcher
	wikiStore  *wiki.Store
}

// New builds an MCP server over db (per-key scope + resource lookups) and the
// action dispatcher (tool calls).
func New(db *sql.DB, dispatcher Dispatcher) *Server {
	return &Server{db: db, dispatcher: dispatcher}
}

// WithWikiStore sets the wiki backend for the bc://wiki resource (WU-501).
func (s *Server) WithWikiStore(st *wiki.Store) *Server {
	s.wikiStore = st
	return s
}

// Handle is the /mcp HTTP entry point. Auth is expected to have run first
// (APIKeyAuthMiddleware) so the actor is in context.
func (s *Server) Handle(w http.ResponseWriter, r *http.Request) {
	actor, ok := auth.APIKeyActorFrom(r.Context())
	if !ok {
		writeError(w, nil, -32001, "unauthorized", "Bearer API key required")
		return
	}
	// Read the key's granted scope (scope_json = permission list) for filtering.
	key, err := sqlc.New(s.db).FindAPIKeyByID(r.Context(), actor.ID)
	if err != nil {
		writeError(w, nil, -32001, "unauthorized", "API key not found")
		return
	}
	var scope []string
	_ = json.Unmarshal([]byte(key.ScopeJson), &scope)

	var req jsonrpcRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, nil, -32700, "parse error", err.Error())
		return
	}
	res := s.dispatch(r.Context(), actor, key.OrgID, scope, req)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(res)
}

type jsonrpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

type jsonrpcResult struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *jsonrpcError   `json:"error,omitempty"`
}

type jsonrpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// dispatch routes one JSON-RPC method to its handler.
func (s *Server) dispatch(ctx context.Context, actor action.Actor, orgID string, scope []string, req jsonrpcRequest) jsonrpcResult {
	switch req.Method {
	case "initialize":
		return s.handleInitialize(req)
	case "tools/list":
		return s.handleToolsList(scope, req)
	case "tools/call":
		return s.handleToolCall(ctx, actor, scope, req)
	case "resources/list":
		return s.handleResourcesList(req)
	case "resources/read":
		return s.handleResourceRead(ctx, actor, orgID, req)
	case "prompts/list":
		return s.handlePromptsList(req)
	case "prompts/get":
		return s.handlePromptGet(ctx, actor, req)
	default:
		return jsonrpcResult{JSONRPC: "2.0", ID: req.ID, Error: &jsonrpcError{Code: -32601, Message: "method not found"}}
	}
}

// handleInitialize returns the protocol + server capabilities (client-sim AC).
func (s *Server) handleInitialize(req jsonrpcRequest) jsonrpcResult {
	return jsonrpcResult{JSONRPC: "2.0", ID: req.ID, Result: map[string]any{
		"protocolVersion": protocolVersion,
		"capabilities": map[string]any{
			"tools":     map[string]any{},
			"resources": map[string]any{},
			"prompts":   map[string]any{},
		},
		"serverInfo": map[string]any{"name": "boardchestrator", "version": "1.0.0"},
	}}
}

// toolName converts an action name to an MCP tool name (dots→underscores).
func toolName(name string) string { return strings.ReplaceAll(name, ".", "_") }

// keyAllows reports whether the key's scope grants this action's permission.
// Omission not denial: an action whose permission is empty or present in the
// key scope is included.
func keyAllows(scope []string, def action.Definition) bool {
	if def.Permission == "" {
		return true
	}
	for _, p := range scope {
		if p == def.Permission {
			return true
		}
	}
	return false
}

// handleToolsList lists registry actions filtered to the key scope (WU-403:
// omission not denial; unauthorized tools are absent, not denied).
func (s *Server) handleToolsList(scope []string, req jsonrpcRequest) jsonrpcResult {
	tools := []map[string]any{}
	for _, def := range action.All() {
		if !keyAllows(scope, def) {
			continue
		}
		tools = append(tools, map[string]any{
			"name":        toolName(def.Name),
			"description": def.Name,
			"inputSchema": map[string]any{"type": "object", "properties": map[string]any{}},
		})
	}
	return jsonrpcResult{JSONRPC: "2.0", ID: req.ID, Result: map[string]any{"tools": tools}}
}

// handleToolCall runs a gated dispatch for an action. High-impact calls by an
// API key return approval_pending without executing (SPEC §12).
func (s *Server) handleToolCall(ctx context.Context, actor action.Actor, scope []string, req jsonrpcRequest) jsonrpcResult {
	var params struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return jsonrpcResult{JSONRPC: "2.0", ID: req.ID, Error: &jsonrpcError{Code: -32602, Message: "invalid params"}}
	}
	def, ok := action.Lookup(actionName(params.Name))
	if !ok {
		return jsonrpcResult{JSONRPC: "2.0", ID: req.ID, Error: &jsonrpcError{Code: -32602, Message: "unknown tool"}}
	}
	if !keyAllows(scope, def) {
		return jsonrpcResult{JSONRPC: "2.0", ID: req.ID, Error: &jsonrpcError{Code: -32602, Message: "tool not authorized"}}
	}
	// Approval gate for API-key actors (SPEC §12): high-impact → pending.
	if def.Impact == action.ImpactHigh {
		return jsonrpcResult{JSONRPC: "2.0", ID: req.ID, Result: map[string]any{
			"content":           []map[string]any{{"type": "text", "text": "approval pending"}},
			"isError":           false,
			"structuredContent": map[string]any{"status": "approval_pending", "approval_id": approvalID()},
		}}
	}
	if params.Arguments == nil {
		params.Arguments = json.RawMessage("{}")
	}
	out, err := s.dispatcher.Dispatch(ctx, actor, actionName(params.Name), params.Arguments, action.Opts{})
	if err != nil {
		return jsonrpcResult{JSONRPC: "2.0", ID: req.ID, Error: &jsonrpcError{Code: -32603, Message: err.Error()}}
	}
	b, _ := json.Marshal(out)
	return jsonrpcResult{JSONRPC: "2.0", ID: req.ID, Result: map[string]any{
		"content":           []map[string]any{{"type": "text", "text": string(b)}},
		"isError":           false,
		"structuredContent": out,
	}}
}

// actionName converts an MCP tool name back to an action name.
func actionName(tool string) string { return strings.ReplaceAll(tool, "_", ".") }

// handleResourcesList lists scoped resources (bc:// URIs).
func (s *Server) handleResourcesList(req jsonrpcRequest) jsonrpcResult {
	// Placeholder resource list; concrete project/task resources are
	// resolved on read. Kept minimal per WU-403 scope.
	return jsonrpcResult{JSONRPC: "2.0", ID: req.ID, Result: map[string]any{
		"resources": []map[string]any{
			{"uri": "bc://project/{key}", "name": "Project", "mimeType": "application/json"},
			{"uri": "bc://task/{key}-{n}", "name": "Task", "mimeType": "application/json"},
		},
	}}
}

// handleResourceRead resolves a bc:// resource from the DB.
func (s *Server) handleResourceRead(ctx context.Context, actor action.Actor, orgID string, req jsonrpcRequest) jsonrpcResult {
	var params struct {
		URI string `json:"uri"`
	}
	if err := json.Unmarshal(req.Params, &params); err != nil || params.URI == "" {
		return jsonrpcResult{JSONRPC: "2.0", ID: req.ID, Error: &jsonrpcError{Code: -32602, Message: "invalid params"}}
	}
	text := s.resolveResource(ctx, orgID, params.URI)
	if text == "" {
		return jsonrpcResult{JSONRPC: "2.0", ID: req.ID, Error: &jsonrpcError{Code: -32002, Message: "resource not found"}}
	}
	return jsonrpcResult{JSONRPC: "2.0", ID: req.ID, Result: map[string]any{
		"contents": []map[string]any{{"uri": params.URI, "mimeType": "application/json", "text": text}},
	}}
}

// resolveResource returns the JSON body for a bc:// URI ("" = not found).
func (s *Server) resolveResource(ctx context.Context, orgID, uri string) string {
	// Only bc://project/{key} + bc://task/{key}-{n} are supported in WU-403;
	// wiki + assembled-context resources land with the wiki package (WU-501).
	switch {
	case strings.HasPrefix(uri, "bc://project/"):
		key := strings.TrimPrefix(uri, "bc://project/")
		proj, err := sqlc.New(s.db).FindProjectByKey(ctx, sqlc.FindProjectByKeyParams{OrgID: orgID, Key: key})
		if err != nil {
			return ""
		}
		b, _ := json.Marshal(map[string]any{
			"id": proj.ID, "key": proj.Key, "name": proj.Name,
			"visibility": proj.Visibility, "archived": proj.Archived,
		})
		return string(b)
	case strings.HasPrefix(uri, "bc://task/"):
		rest := strings.TrimPrefix(uri, "bc://task/")
		// {key}-{n}
		idx := strings.LastIndex(rest, "-")
		if idx <= 0 {
			return ""
		}
		key, numS := rest[:idx], rest[idx+1:]
		n, err := strconv.Atoi(numS)
		if err != nil {
			return ""
		}
		proj, err := sqlc.New(s.db).FindProjectByKey(ctx, sqlc.FindProjectByKeyParams{OrgID: orgID, Key: key})
		if err != nil {
			return ""
		}
		task, err := sqlc.New(s.db).FindTaskByKey(ctx, sqlc.FindTaskByKeyParams{ProjectID: proj.ID, Key: key, KeyNum: int64(n)})
		if err != nil {
			return ""
		}
		b, _ := json.Marshal(map[string]any{
			"id": task.ID, "key": task.Key, "title": task.Title,
			"status": task.Status, "points": task.Points,
		})
		return string(b)
	case strings.HasPrefix(uri, "bc://wiki/"):
		// WU-501: render a wiki page. bc://wiki/{page-path} → rendered HTML.
		if s.wikiStore == nil {
			return ""
		}
		pagePath := strings.TrimPrefix(uri, "bc://wiki/")
		page, err := s.wikiStore.ReadPage(ctx, orgID, pagePath)
		if err != nil {
			return ""
		}
		b, _ := json.Marshal(map[string]any{
			"path": page.Path, "name": page.Name,
			"markdown": page.Markdown, "html": page.HTML,
		})
		return string(b)
	default:
		return ""
	}
}

// approvalID returns a fresh opaque approval id for a pending tool call.
func approvalID() string {
	return "ap_" + strings.ToLower(hex.EncodeToString(randBytes(8)))
}

// handlePromptsList lists the registered prompts (WU-403).
func (s *Server) handlePromptsList(req jsonrpcRequest) jsonrpcResult {
	return jsonrpcResult{JSONRPC: "2.0", ID: req.ID, Result: map[string]any{
		"prompts": []map[string]any{
			{"name": "decompose_task", "description": "Break a task into subtasks"},
			{"name": "summarise_sprint", "description": "Summarise a sprint"},
			{"name": "triage_backlog", "description": "Triage a project backlog"},
		},
	}}
}

// handlePromptGet returns the prompt template for a named prompt.
func (s *Server) handlePromptGet(ctx context.Context, actor action.Actor, req jsonrpcRequest) jsonrpcResult {
	var params struct {
		Name string `json:"name"`
	}
	_ = json.Unmarshal(req.Params, &params)
	var messages []map[string]any
	switch params.Name {
	case "decompose_task":
		messages = []map[string]any{{"role": "user", "content": map[string]any{"type": "text", "text": "Break task into subtasks."}}}
	case "summarise_sprint":
		messages = []map[string]any{{"role": "user", "content": map[string]any{"type": "text", "text": "Summarise the sprint."}}}
	case "triage_backlog":
		messages = []map[string]any{{"role": "user", "content": map[string]any{"type": "text", "text": "Triage the backlog."}}}
	default:
		return jsonrpcResult{JSONRPC: "2.0", ID: req.ID, Error: &jsonrpcError{Code: -32602, Message: "unknown prompt"}}
	}
	return jsonrpcResult{JSONRPC: "2.0", ID: req.ID, Result: map[string]any{
		"description": params.Name,
		"messages":    messages,
	}}
}

// writeError writes a JSON-RPC error response.
func writeError(w http.ResponseWriter, id json.RawMessage, code int, msg string, data string) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(jsonrpcResult{
		JSONRPC: "2.0", ID: id,
		Error: &jsonrpcError{Code: code, Message: msg},
	})
}
