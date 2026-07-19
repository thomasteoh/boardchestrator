package action

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// Schema validates an action's input (and documents its output). SPEC §4
// calls for a "JSON schema (compiled once)". Rather than pull in a full JSON
// Schema dependency now — which would add a runtime dep and buys little while
// only the dispatch spine exists — we express validation behind this small
// interface. A definition compiles its schema once (at registration) and
// Dispatch calls Validate on the raw input.
//
// This keeps the dependency footprint at std-lib only for Phase 0. When richer
// validation is needed (e.g. WU-401 fuzzing action inputs from schemas, or an
// OpenAPI document in WU-402), a JSON-Schema-backed implementation can be
// added behind this same interface without touching Dispatch. The choice is
// recorded in BACKLOG WU-006 notes.
type Schema interface {
	// Validate reports whether raw is acceptable input. It returns a non-nil
	// error describing the first problem otherwise. Implementations must treat
	// nil/empty raw per their own semantics.
	Validate(raw json.RawMessage) error
}

// FuncSchema adapts a plain function into a Schema. Handy for tests and for
// bespoke validation that does not fit a declarative shape.
type FuncSchema func(raw json.RawMessage) error

// Validate implements Schema.
func (f FuncSchema) Validate(raw json.RawMessage) error { return f(raw) }

// FieldKind is the coarse JSON type an ObjectSchema field expects.
type FieldKind int

const (
	// KindString expects a JSON string.
	KindString FieldKind = iota
	// KindNumber expects a JSON number.
	KindNumber
	// KindBool expects a JSON boolean.
	KindBool
	// KindObject expects a JSON object.
	KindObject
	// KindArray expects a JSON array.
	KindArray
	// KindAny accepts any JSON value (still must be valid JSON).
	KindAny
)

// Field declares one property of an ObjectSchema.
type Field struct {
	Name     string
	Kind     FieldKind
	Required bool
}

// ObjectSchema is a lightweight, declarative object validator: it checks that
// input is a JSON object, that required fields are present, and that present
// declared fields have the expected coarse type. It intentionally does not do
// deep validation — that is future work behind the Schema interface. Unknown
// fields are rejected to keep inputs tight (defence in depth).
type ObjectSchema struct {
	Fields []Field
}

// Validate implements Schema.
func (s ObjectSchema) Validate(raw json.RawMessage) error {
	if len(raw) == 0 {
		return fmt.Errorf("%w: empty input, object expected", ErrInvalidInput)
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return fmt.Errorf("%w: not a JSON object: %v", ErrInvalidInput, err)
	}

	declared := make(map[string]Field, len(s.Fields))
	for _, f := range s.Fields {
		declared[f.Name] = f
	}

	// Reject unknown fields, deterministically ordered for stable messages.
	var unknown []string
	for name := range obj {
		if _, ok := declared[name]; !ok {
			unknown = append(unknown, name)
		}
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		return fmt.Errorf("%w: unknown field %q", ErrInvalidInput, unknown[0])
	}

	for _, f := range s.Fields {
		val, present := obj[f.Name]
		if !present {
			if f.Required {
				return fmt.Errorf("%w: missing required field %q", ErrInvalidInput, f.Name)
			}
			continue
		}
		if err := checkKind(f, val); err != nil {
			return err
		}
	}
	return nil
}

func checkKind(f Field, val json.RawMessage) error {
	trimmed := strings.TrimSpace(string(val))
	if trimmed == "" {
		return fmt.Errorf("%w: field %q is empty", ErrInvalidInput, f.Name)
	}
	// A JSON null never satisfies a typed field.
	if trimmed == "null" {
		if f.Kind == KindAny {
			return nil
		}
		return fmt.Errorf("%w: field %q must not be null", ErrInvalidInput, f.Name)
	}

	var v any
	if err := json.Unmarshal(val, &v); err != nil {
		return fmt.Errorf("%w: field %q is not valid JSON: %v", ErrInvalidInput, f.Name, err)
	}

	ok := false
	switch f.Kind {
	case KindString:
		_, ok = v.(string)
	case KindNumber:
		_, ok = v.(float64)
	case KindBool:
		_, ok = v.(bool)
	case KindObject:
		_, ok = v.(map[string]any)
	case KindArray:
		_, ok = v.([]any)
	case KindAny:
		ok = true
	}
	if !ok {
		return fmt.Errorf("%w: field %q has wrong type (want %s)", ErrInvalidInput, f.Name, f.Kind)
	}
	return nil
}

// String renders a FieldKind for error messages.
func (k FieldKind) String() string {
	switch k {
	case KindString:
		return "string"
	case KindNumber:
		return "number"
	case KindBool:
		return "bool"
	case KindObject:
		return "object"
	case KindArray:
		return "array"
	case KindAny:
		return "any"
	default:
		return "unknown"
	}
}
