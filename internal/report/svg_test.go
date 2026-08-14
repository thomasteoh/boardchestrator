package report

import (
	"encoding/xml"
	"strings"
	"testing"
)

// svgIsWellFormed reports whether s parses as well-formed XML (SVG output must
// be parseable; WU-504 AC3).
func svgIsWellFormed(s string) bool {
	type anyXML struct{}
	dec := xml.NewDecoder(strings.NewReader(s))
	dec.Strict = true
	if err := dec.Decode(&anyXML{}); err != nil {
		return false
	}
	return true
}

func TestSVGBurndownWellFormed(t *testing.T) {
	b := Burndown{SprintID: "s1", ProjectID: "p1",
		Days:      []Day{"2026-08-10", "2026-08-11", "2026-08-12"},
		Remaining: []int64{10, 7, 4}, Done: []int64{0, 3, 6}, Ideal: []int64{10, 5, 0}, Total: 10}
	svg := SVGBurndown(b)
	if !strings.Contains(svg, "<svg") {
		t.Errorf("SVG missing <svg>: %q", svg)
	}
	if !svgIsWellFormed(svg) {
		t.Errorf("SVG not well-formed: %q", svg)
	}
	if !strings.Contains(svg, "polyline") {
		t.Errorf("SVG missing series polyline: %q", svg)
	}
}

func TestSVGDistributionsWellFormed(t *testing.T) {
	dists := []Distribution{{Project: "a", TaskCount: 5, TotalPts: 12, DoneCount: 2}, {Project: "b", TaskCount: 2, TotalPts: 4, DoneCount: 1}}
	svg := SVGDistributions(dists)
	if !strings.Contains(svg, "<svg") || !svgIsWellFormed(svg) {
		t.Errorf("SVG not well-formed: %q", svg)
	}
	if !strings.Contains(svg, "<rect") {
		t.Errorf("SVG missing bars: %q", svg)
	}
	// Empty distribution set must still render a well-formed chart.
	if empty := SVGDistributions(nil); !svgIsWellFormed(empty) {
		t.Errorf("empty SVG not well-formed: %q", empty)
	}
}
