package action

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/thomasteoh/boardchestrator/internal/db/dbtest"
)

// TestToolArgValidationFuzz covers WU-311 AC: a corpus of malformed/wrong-type
// tool-argument payloads is rejected by schema validation (ErrInvalidInput)
// rather than crashing or executing. Uses a strict-input action with required
// string + number fields and an optional number field.
func TestToolArgValidationFuzz(t *testing.T) {
	reset()
	t.Cleanup(reset)
	Register(Definition{
		Name:   "test.strict",
		Impact: ImpactHigh,
		Scope:  ScopeOrg,
		Input: ObjectSchema{Fields: []Field{
			{Name: "name", Kind: KindString, Required: true},
			{Name: "amount", Kind: KindNumber, Required: true},
			{Name: "note", Kind: KindString, Required: false},
		}},
		Handle: func(ctx context.Context, ac ActionCtx, in json.RawMessage) (any, error) { return nil, nil },
	})
	d := New(dbtest.New(t))

	corpus := []struct {
		in  string
		ok  bool // valid input should execute
		bad bool // malformed input must be rejected
	}{
		{`{"name":"a","amount":1}`, true, false},            // valid
		{``, false, true},                                   // empty
		{`{`, false, true},                                  // truncated
		{`[]`, false, true},                                 // wrong top-level type
		{`"str"`, false, true},                              // scalar
		{`{"name":"a","amount":"x"}`, false, true},          // wrong kind
		{`{"name":42,"amount":1}`, false, true},             // wrong kind
		{`{"name":"a"}`, false, true},                       // missing required amount
		{`{"amount":1}`, false, true},                       // missing required name
		{`{"name":"a","amount":1,"bogus":2}`, false, true},  // unknown field
		{`null`, false, true},                               // null body
		{`{"name":"a","amount":1,"note":null}`, false, true}, // null optional
	}
	for i, c := range corpus {
		_, err := d.Dispatch(context.Background(), userActor(), "test.strict",
			json.RawMessage(c.in), Opts{Org: "org1"})
		if c.ok && err != nil {
			t.Fatalf("corpus[%d] %q rejected unexpectedly: %v", i, c.in, err)
		}
		if c.bad && err == nil {
			t.Fatalf("corpus[%d] %q accepted (expected validation error)", i, c.in)
		}
		if c.bad && err != nil {
			msg := err.Error()
			if !strings.Contains(msg, "invalid") && !strings.Contains(msg, "unknown") {
				t.Fatalf("corpus[%d] %q unexpected error type: %v", i, c.in, err)
			}
		}
	}
}
