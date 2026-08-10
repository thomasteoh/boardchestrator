package agentrt

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/thomasteoh/boardchestrator/internal/action"
	"github.com/thomasteoh/boardchestrator/internal/client"
	"github.com/thomasteoh/boardchestrator/internal/db/sqlc"
)

// MaxStepsPerRun is the default cap on tool-loop iterations per run (SPEC §10).
const MaxStepsPerRun = 25

// toolFor derives a provider ToolDef from a registry action definition. The
// parameters schema is built from the action's ObjectSchema when available;
// otherwise it is a permissive object schema. External MCP tools from skills
// are added in WU-403; WU-305 exposes registry actions only.
func toolFor(def action.Definition) client.ToolDef {
	params := map[string]any{"type": "object", "properties": map[string]any{}, "required": []string{}}
	if os, ok := def.Input.(action.ObjectSchema); ok {
		props := map[string]any{}
		var required []string
		for _, f := range os.Fields {
			props[f.Name] = map[string]any{"type": jsonKind(f.Kind)}
			if f.Required {
				required = append(required, f.Name)
			}
		}
		params["properties"] = props
		if len(required) > 0 {
			params["required"] = required
		}
	}
	return client.ToolDef{
		Type: "function",
		Function: struct {
			Name        string `json:"name"`
			Description string `json:"description"`
			Parameters  any    `json:"parameters"`
		}{
			Name:        def.Name,
			Description: actionDescription(def),
			Parameters:  params,
		},
	}
}

func jsonKind(k action.FieldKind) string {
	switch k {
	case action.KindString:
		return "string"
	case action.KindNumber:
		return "number"
	case action.KindBool:
		return "boolean"
	default:
		return "string"
	}
}

func actionDescription(def action.Definition) string {
	return fmt.Sprintf("%s (impact %s)", def.Name, def.Impact.String())
}

// toolsForAgent returns the registry actions the agent may perform, as
// provider tool definitions. It filters All() by the agent's effective
// permission set (SPEC §6: role grants ∩ skills). Reads are always included
// for actions whose Permission is empty or a read grant.
func toolsForAgent(ctx context.Context, q *sqlc.Queries, agent sqlc.Agent, eff map[string]bool) ([]client.ToolDef, error) {
	var out []client.ToolDef
	for _, def := range action.All() {
		// Skip platform-scope actions (agent.list-templates etc.) unless
		// explicitly granted — they are not part of an org agent's tool set.
		if def.Scope == action.ScopePlatform {
			continue
		}
		if def.Permission == "" || grantAllows(def.Permission, eff) {
			out = append(out, toolFor(def))
		}
	}
	return out, nil
}

// toolResult is a single executed tool call's outcome, returned to the model
// as an assistant tool message.
type toolResult struct {
	Name    string
	CallID  string
	Content string // JSON-encoded action output
	Error   string // set on dispatch failure (e.g. forbidden)
}

// runToolLoop drives the chat-completions tool loop (SPEC §10):
//
//	assemble context → send with tools → if tool_calls, execute each via
//	Dispatch as the agent actor, append results, repeat; else finish.
//
// It caps iterations at MaxStepsPerRun, checks a cancellation flag between
// steps, records every model call + tool execution as a run_steps row, and
// accumulates token usage. Approval-pending calls (ErrApprovalPending, WU-306)
// return a sentinel so the engine can persist awaiting_approval state.
func runToolLoop(ctx context.Context, eng *Engine, run sqlc.Run, agent sqlc.Agent, prompt string, cancel *cancelFlag) (*loopOutcome, error) {
	q := eng.q
	messages := []client.Message{
		{Role: "system", Content: systemPrompt(agent)},
		{Role: "user", Content: prompt},
	}
	eff, err := EffectivePerms(ctx, q, agent)
	if err != nil {
		return nil, fmt.Errorf("run: resolve effective perms: %w", err)
	}
	tools, err := toolsForAgent(ctx, q, agent, eff)
	if err != nil {
		return nil, err
	}

	steps := 0
	var promptTokens, completionTokens int64
	cl, err := eng.clientFor(ctx, agent)
	if err != nil {
		return nil, err
	}
	for {
		if cancel != nil && cancel.isSet() {
			return &loopOutcome{cancelled: true}, nil
		}
		if steps >= MaxStepsPerRun {
			return &loopOutcome{stepCapped: true}, nil
		}
		steps++

		req := client.CompletionRequest{
			Model:    cl.Model(),
			Messages: messages,
			Tools:    tools,
		}
		resp, err := cl.ChatCompletion(ctx, req)
		if err != nil {
			return nil, err
		}
		promptTokens += int64(resp.Usage.PromptTokens)
		completionTokens += int64(resp.Usage.CompletionTokens)
		_ = eng.recordStep(ctx, run, steps, "model", req, resp, resp.Usage.PromptTokens+resp.Usage.CompletionTokens)

		if len(resp.Choices) == 0 {
			return &loopOutcome{promptTokens: promptTokens, completionTokens: completionTokens}, nil
		}
		choice := resp.Choices[0]
		messages = append(messages, client.Message{
			Role:    choice.Message.Role,
			Content: choice.Message.Content,
		})
		if len(choice.ToolCalls) == 0 {
			return &loopOutcome{promptTokens: promptTokens, completionTokens: completionTokens}, nil
		}

		// Execute each tool call and feed results back.
		var results []client.Message
		approvalPending := false
		for _, tc := range choice.ToolCalls {
			name := tc.Function.Name
			args := json.RawMessage(tc.Function.Arguments)
			res, err := eng.dispatchTool(ctx, run, agent, name, args)
			if err != nil {
				if errors.Is(err, action.ErrApprovalPending{}) {
					approvalPending = true
					break
				}
				results = append(results, client.Message{
					Role:    "tool",
					Content: fmt.Sprintf(`{"tool":"%s","error":%q}`, name, err.Error()),
				})
				continue
			}
			results = append(results, client.Message{
				Role:    "tool",
				Content: res.Content,
			})
		}
		if approvalPending {
			return &loopOutcome{approvalPending: true, promptTokens: promptTokens, completionTokens: completionTokens}, nil
		}
		messages = append(messages, results...)
	}
}
