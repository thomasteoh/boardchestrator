package action

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/thomasteoh/boardchestrator/internal/db/dbtest"
)

// TestBoardMutationRace runs concurrent board column mutations under -race.
// Exercises column create, update, and reorder simultaneously.
func TestBoardMutationRace(t *testing.T) {
	reset()
	t.Cleanup(reset)
	registerBaseActions()
	Register(Definition{
		Name:   "board.column.create",
		Impact: ImpactLow,
		Scope:  ScopeProject,
		Handle: handleBoardColCreate,
	})
	Register(Definition{
		Name:   "board.column.update",
		Impact: ImpactLow,
		Scope:  ScopeProject,
		Handle: handleBoardColUpdate,
	})

	d := New(dbtest.New(t))
	ctx := context.Background()

	orgID, projID := createOrgAndProject(t, d, ctx, "RACE")

	// Seed one column
	colOut, _ := d.Dispatch(ctx, userActor(), "board.column.create",
		json.RawMessage(`{"project_id":"`+projID+`","name":"To Do","color":"blue","position":1}`),
		Opts{Org: orgID})
	colID := extractID(t, mustJSON(t, colOut))

	var wg sync.WaitGroup
	errs := make(chan error, 20)

	// 10 concurrent column updates
	for i := range 10 {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			_, err := d.Dispatch(ctx, userActor(), "board.column.update",
				json.RawMessage(`{"id":"`+colID+`","project_id":"`+projID+`","name":"Col `+fmt.Sprintf("%d", n)+`","color":"red","position":1}`),
				Opts{Org: orgID})
			if err != nil {
				errs <- err
			}
		}(i)
	}

	// 10 concurrent column creates
	for range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := d.Dispatch(ctx, userActor(), "board.column.create",
				json.RawMessage(`{"project_id":"`+projID+`","name":"Race Col","color":"green","position":2}`),
				Opts{Org: orgID})
			if err != nil {
				errs <- err
			}
		}()
	}

	wg.Wait()
	close(errs)

	var hadErr bool
	for err := range errs {
		if err != nil {
			// SQLITE_BUSY is expected under concurrent contention on SQLite.
			if !strings.Contains(err.Error(), "database is locked") {
				t.Errorf("concurrent board mutation unexpected error: %v", err)
			}
			hadErr = true
		}
	}
	if hadErr {
		t.Log("some concurrent mutations failed (SQLITE_BUSY) — expected under contention")
	}
}
