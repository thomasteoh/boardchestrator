package action

import (
	"encoding/json"
	"errors"
	"testing"
)

func TestObjectSchemaValidate(t *testing.T) {
	s := ObjectSchema{Fields: []Field{
		{Name: "title", Kind: KindString, Required: true},
		{Name: "points", Kind: KindNumber, Required: false},
		{Name: "done", Kind: KindBool, Required: false},
		{Name: "meta", Kind: KindObject, Required: false},
		{Name: "tags", Kind: KindArray, Required: false},
		{Name: "anything", Kind: KindAny, Required: false},
	}}

	valid := []string{
		`{"title":"x"}`,
		`{"title":"x","points":3}`,
		`{"title":"x","done":true}`,
		`{"title":"x","meta":{"a":1}}`,
		`{"title":"x","tags":["a","b"]}`,
		`{"title":"x","anything":null}`,
		`{"title":"x","anything":123}`,
	}
	for _, in := range valid {
		if err := s.Validate(json.RawMessage(in)); err != nil {
			t.Errorf("Validate(%s) = %v, want nil", in, err)
		}
	}

	invalid := []string{
		``,                            // empty
		`[]`,                          // not object
		`{}`,                          // missing required
		`{"title":1}`,                 // wrong type
		`{"title":"x","points":"3"}`,  // number as string
		`{"title":"x","done":"true"}`, // bool as string
		`{"title":"x","meta":[]}`,     // array not object
		`{"title":"x","tags":{}}`,     // object not array
		`{"title":"x","unknown":1}`,   // unknown field
		`{"title":null}`,              // null on typed required
	}
	for _, in := range invalid {
		if err := s.Validate(json.RawMessage(in)); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("Validate(%s) = %v, want ErrInvalidInput", in, err)
		}
	}
}

func TestFuncSchema(t *testing.T) {
	s := FuncSchema(func(raw json.RawMessage) error {
		if string(raw) == `"bad"` {
			return ErrInvalidInput
		}
		return nil
	})
	if err := s.Validate(json.RawMessage(`"ok"`)); err != nil {
		t.Fatalf("want nil, got %v", err)
	}
	if err := s.Validate(json.RawMessage(`"bad"`)); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("want ErrInvalidInput, got %v", err)
	}
}
