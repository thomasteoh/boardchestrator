// Package schedule provides cron parsing and next-at computation for
// recurring task rules (WU-209). Uses robfig/cron for standard cron
// expression parsing with optional seconds field.
package schedule

import (
	"fmt"
	"time"

	"github.com/robfig/cron/v3"
)

// NextAt parses a cron expression and computes the next activation time
// after the given reference time. Returns RFC3339 string.
func NextAt(expr string, after time.Time) (string, error) {
	parser := cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow | cron.Descriptor)
	sched, err := parser.Parse(expr)
	if err != nil {
		return "", fmt.Errorf("parse cron %q: %w", expr, err)
	}

	next := sched.Next(after)
	return next.UTC().Format(time.RFC3339), nil
}
