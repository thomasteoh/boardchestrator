package agentrt

import (
	"context"
	"testing"

	"github.com/thomasteoh/boardchestrator/internal/action"
	"github.com/thomasteoh/boardchestrator/internal/db/sqlc"
)

// WU-603a: platform- and self-scope actions are never an agent's tools, and
// the engine's permission checker refuses them even with a "*" grant.
func TestAgentNeverGetsPlatformOrSelfActions(t *testing.T) {
	ctx := context.Background()
	tools, err := toolsForAgent(ctx, nil, sqlc.Agent{}, map[string]bool{"*": true})
	if err != nil {
		t.Fatal(err)
	}
	offered := map[string]bool{}
	for _, tl := range tools {
		offered[tl.Function.Name] = true
	}
	checker := agentPermChecker{}
	n := 0
	for _, def := range action.All() {
		if def.Scope != action.ScopePlatform && def.Scope != action.ScopeSelf {
			continue
		}
		n++
		if offered[toolFor(def).Function.Name] {
			t.Errorf("%s (%s scope) offered as an agent tool", def.Name, def.Scope)
		}
		ok, err := checker.Allow(ctx, action.ActionCtx{Actor: action.Actor{Type: action.ActorAgent, ID: "a1"}, Org: "o1"}, def)
		if err != nil || ok {
			t.Errorf("%s: agentPermChecker.Allow = %v, %v; want false", def.Name, ok, err)
		}
	}
	if n == 0 {
		t.Fatal("no platform/self actions registered")
	}
}
