package idp

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/thomasteoh/boardchestrator/internal/action"
)

// TestPlatformOnlyGuard calls each registered idp.* handler directly with a
// tenant id, bypassing Dispatch (which refuses that first since WU-603a), so
// the handler-level defence in depth stays covered.
func TestPlatformOnlyGuard(t *testing.T) {
	names := []string{ActionList, ActionGet, ActionCreate, ActionUpdate, ActionDelete,
		ActionEnable, ActionDisable, ActionDiscover}
	scopes := []action.ActionCtx{
		{Org: "org-own"},
		{Team: "team-1"},
		{Proj: "proj-1"},
	}
	for _, name := range names {
		def, ok := action.Lookup(name)
		if !ok {
			t.Fatalf("%s not registered", name)
		}
		for _, ac := range scopes {
			ac.Actor = action.Actor{Type: action.ActorUser, ID: "u-orgowner"}
			_, err := def.Handle(context.Background(), ac, json.RawMessage(`{}`))
			if !errors.Is(err, action.ErrForbidden) || !strings.Contains(err.Error(), "organisation") {
				t.Errorf("%s with scope %+v: err = %v, want the platform guard's ErrForbidden", name, ac, err)
			}
		}
	}
}
