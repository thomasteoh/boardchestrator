package config

import (
	"reflect"
	"strings"
)

// EnvRefEntry describes one environment variable in the generated reference.
type EnvRefEntry struct {
	Env   string // e.g. BC_DB_PATH
	Field string // struct field name
	Type  string // field type
}

// EnvReference generates the BC_* environment variable reference from the
// Config struct by reflection (WU-507: env reference generated from config
// struct). Field names map to upper-snake: DBPath → BC_DB_PATH.
func EnvReference() []EnvRefEntry {
	t := reflect.TypeOf(Config{})
	out := make([]EnvRefEntry, 0, t.NumField())
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		env := "BC_" + toUpperSnake(f.Name)
		out = append(out, EnvRefEntry{Env: env, Field: f.Name, Type: f.Type.String()})
	}
	return out
}

// toUpperSnake converts a CamelCase field name to UPPER_SNAKE_CASE.
// DBPath → BC_DB_PATH; SchedPollInterval → BC_SCHED_POLL_INTERVAL.
func toUpperSnake(name string) string {
	var b strings.Builder
	runes := []rune(name)
	for i, r := range runes {
		if i > 0 && r >= 'A' && r <= 'Z' {
			prev := runes[i-1]
			// Insert separator between a lower/digit and an upper, or between
			// an upper and an upper that is followed by a lower (acronym rule).
			if (prev >= 'a' && prev <= 'z') || (prev >= '0' && prev <= '9') ||
				(i+1 < len(runes) && runes[i+1] >= 'a' && runes[i+1] <= 'z') {
				b.WriteByte('_')
			}
		}
		b.WriteRune(r)
	}
	return strings.ToUpper(b.String())
}
