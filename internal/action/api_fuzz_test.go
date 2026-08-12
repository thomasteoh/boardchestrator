package action

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/thomasteoh/boardchestrator/internal/db/dbtest"
)

// fuzzCorpusEntry is one committed malformed payload shape (WU-407 AC: fuzz
// corpora committed). Each shape is *unconditionally* invalid JSON for an
// object-schema input (wrong top-level type, truncated, malformed types), so
// every ObjectSchema-driven action must reject it with ErrInvalidInput.
type fuzzCorpusEntry struct {
	Name    string `json:"name"`
	Payload string `json:"payload"`
}

// TestSchemaDrivenAPIFuzz covers WU-407 AC: every registered action whose
// input is an ObjectSchema rejects (a) the committed malformed corpus and
// (b) per-schema generated malformed inputs (missing required fields, wrong
// field types) — with ErrInvalidInput, never executing the handler — while a
// valid input built from the schema's fields is accepted. The corpus is
// committed at fuzz_corpus.json so the fuzz surface is reproducible.
func TestSchemaDrivenAPIFuzz(t *testing.T) {
	corpus := loadCorpus(t)
	db := dbtest.New(t)

	// Walk every registered action once (init-registered).
	for _, def := range All() {
		os, ok := def.Input.(ObjectSchema)
		if !ok {
			continue // FuncSchema actions are validated by their own handler
		}

		d := New(db)
		ctx := context.Background()

		// A valid input built from the schema must not be rejected as invalid.
		valid := validInputFromSchema(os)
		if len(valid) > 0 {
			if _, err := d.Dispatch(ctx, userActor(), def.Name, json.RawMessage(valid), Opts{}); errors.Is(err, ErrInvalidInput) {
				t.Fatalf("%s: valid input %s rejected as invalid", def.Name, valid)
			}
		}

		// (a) Committed always-invalid corpus: reject, never execute.
		for _, c := range corpus {
			_, err := d.Dispatch(ctx, userActor(), def.Name, json.RawMessage(c.Payload), Opts{})
			if err == nil {
				t.Fatalf("%s: corpus[%s] %s accepted — expected validation rejection", def.Name, c.Name, c.Payload)
			}
			if !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("%s: corpus[%s] %s returned %v — expected ErrInvalidInput", def.Name, c.Name, c.Payload, err)
			}
		}

		// (b) Schema-driven malformed inputs.
		gen := schemaMalformed(os)
		for _, g := range gen {
			_, err := d.Dispatch(ctx, userActor(), def.Name, json.RawMessage(g), Opts{})
			if err == nil {
				t.Fatalf("%s: malformed %s accepted — expected validation rejection", def.Name, g)
			}
			if !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("%s: malformed %s returned %v — expected ErrInvalidInput", def.Name, g, err)
			}
		}

		// Empty input must be rejected (ObjectSchema always requires an object).
		if _, err := d.Dispatch(ctx, userActor(), def.Name, json.RawMessage(""), Opts{}); err == nil || !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("%s: empty input accepted or wrong error %v — want ErrInvalidInput", def.Name, err)
		}
	}
}

// validInputFromSchema builds a minimal valid JSON object for an ObjectSchema,
// or "" when the schema has no fields (no valid input is possible).
func validInputFromSchema(s ObjectSchema) string {
	if len(s.Fields) == 0 {
		return ""
	}
	parts := make([]string, 0, len(s.Fields))
	for _, f := range s.Fields {
		parts = append(parts, `"`+f.Name+`":`+exampleKind(f.Kind))
	}
	return "{" + joinComma(parts) + "}"
}

// schemaMalformed generates per-schema malformed inputs: one missing each
// required field, and one wrong-typed value per field.
func schemaMalformed(s ObjectSchema) []string {
	out := make([]string, 0, len(s.Fields)*2)
	for _, f := range s.Fields {
		if f.Required {
			// Missing required field: drop it from a valid skeleton.
			var parts []string
			for _, g := range s.Fields {
				if g.Name == f.Name {
					continue
				}
				parts = append(parts, `"`+g.Name+`":`+exampleKind(g.Kind))
			}
			out = append(out, "{"+joinComma(parts)+"}")
		}
		// Wrong type for this field.
		parts := make([]string, 0, len(s.Fields))
		for _, g := range s.Fields {
			v := exampleKind(g.Kind)
			if g.Name == f.Name {
				v = wrongKind(g.Kind)
			}
			parts = append(parts, `"`+g.Name+`":`+v)
		}
		out = append(out, "{"+joinComma(parts)+"}")
	}
	return out
}

func wrongKind(k FieldKind) string {
	switch k {
	case KindString:
		return `1`
	case KindNumber:
		return `"x"`
	case KindBool:
		return `"true"`
	case KindObject:
		return `[]`
	case KindArray:
		return `{}`
	default:
		return `null`
	}
}

func exampleKind(k FieldKind) string {
	switch k {
	case KindString:
		return `"x"`
	case KindNumber:
		return `1`
	case KindBool:
		return `true`
	case KindObject:
		return `{}`
	case KindArray:
		return `[]`
	default:
		return `null`
	}
}

func joinComma(ss []string) string {
	out := ""
	for i, s := range ss {
		if i > 0 {
			out += ","
		}
		out += s
	}
	return out
}

func loadCorpus(t *testing.T) []fuzzCorpusEntry {
	t.Helper()
	b, err := os.ReadFile("fuzz_corpus.json")
	if err != nil {
		t.Fatalf("read fuzz_corpus.json: %v", err)
	}
	var corpus []fuzzCorpusEntry
	if err := json.Unmarshal(b, &corpus); err != nil {
		t.Fatalf("parse fuzz_corpus.json: %v", err)
	}
	return corpus
}
