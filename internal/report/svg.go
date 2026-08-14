package report

import (
	"bytes"
	"fmt"
)

// svg renders a simple, dependency-free SVG chart. All output is
// integer-based and escaped; charts are parse-testable (well-formed XML).
// Charts use a fixed viewBox so they scale responsively.

const (
	chartW  = 640
	chartH  = 300
	padL    = 40
	padR    = 16
	padT    = 16
	padB    = 28
	plotW   = chartW - padL - padR
	plotH   = chartH - padT - padB
	gridRow = 4
)

// SVGBurndown renders a burndown chart: ideal line (dashed), done line
// (solid), remaining line (solid). Returns the <svg> element markup.
func SVGBurndown(b Burndown) string {
	var buf bytes.Buffer
	fmt.Fprintf(&buf, `<svg viewBox="0 0 %d %d" xmlns="http://www.w3.org/2000/svg" class="bc-chart" role="img" aria-label="burndown">`, chartW, chartH)
	buf.WriteString(`<rect x="0" y="0" width="640" height="300" fill="#fafafa"/>`)

	maxV := b.Total
	if maxV == 0 {
		maxV = 1
	}
	n := len(b.Days)
	x := func(i int) float64 { return padL + plotW*float64(i)/float64(max(1, n-1)) }
	y := func(v int64) float64 {
		if v < 0 {
			v = 0
		}
		if v > maxV {
			v = maxV
		}
		return padT + plotH*(1-float64(v)/float64(maxV))
	}
	grid := func(v int64) float64 { return padT + plotH*(1-float64(v)/float64(maxV)) }

	// Grid + axis.
	for r := 0; r <= gridRow; r++ {
		gy := grid(int64(maxV) * int64(r) / gridRow)
		fmt.Fprintf(&buf, `<line x1="%d" y1="%.1f" x2="%d" y2="%.1f" stroke="#e0e0e0" stroke-width="1"/>`, padL, gy, chartW-padR, gy)
		label := int64(maxV) * int64(gridRow-r) / gridRow
		fmt.Fprintf(&buf, `<text x="%d" y="%.1f" font-size="11" fill="#666">%d</text>`, padL-6, gy+4, label)
	}
	buf.WriteString(`<line x1="40" y1="16" x2="40" y2="272" stroke="#999" stroke-width="1"/>`)

	series := func(vals []int64, color, dash string) {
		if len(vals) == 0 {
			return
		}
		buf.WriteString(`<polyline points="`)
		for i, v := range vals {
			fmt.Fprintf(&buf, "%.1f,%.1f ", x(i), y(v))
		}
		buf.WriteString(`" fill="none" stroke="` + color + `" stroke-width="2"`)
		if dash != "" {
			buf.WriteString(` stroke-dasharray="` + dash + `"`)
		}
		buf.WriteString(`/>`)
	}
	series(b.Ideal, "#90a4ae", "4,3")
	series(b.Done, "#4caf50", "")
	series(b.Remaining, "#f44336", "")

	// X labels (first/last day).
	if n > 0 {
		fmt.Fprintf(&buf, `<text x="%.1f" y="%d" font-size="11" fill="#666">%s</text>`, x(0), chartH-8, string(b.Days[0]))
		fmt.Fprintf(&buf, `<text x="%.1f" y="%d" font-size="11" fill="#666">%s</text>`, x(n-1), chartH-8, string(b.Days[n-1]))
	}
	buf.WriteString(`</svg>`)
	return buf.String()
}

// SVGDistributions renders horizontal bars per project (task count).
func SVGDistributions(dists []Distribution) string {
	var buf bytes.Buffer
	fmt.Fprintf(&buf, `<svg viewBox="0 0 %d %d" xmlns="http://www.w3.org/2000/svg" class="bc-chart" role="img" aria-label="project distribution">`, chartW, chartH)
	buf.WriteString(`<rect x="0" y="0" width="640" height="300" fill="#fafafa"/>`)
	if len(dists) == 0 {
		buf.WriteString(`<text x="200" y="150" font-size="14" fill="#888">No tasks</text></svg>`)
		return buf.String()
	}
	maxC := int64(1)
	for _, d := range dists {
		if d.TaskCount > maxC {
			maxC = d.TaskCount
		}
	}
	barW := plotH / int64(len(dists)) * 6 / 7
	if barW < 10 {
		barW = 10
	}
	gap := int64(6)
	for i, d := range dists {
		by := int64(padT) + int64(i)*(barW+gap)
		barLen := plotW * d.TaskCount / maxC
		fmt.Fprintf(&buf, `<text x="%d" y="%d" font-size="11" fill="#333">%s</text>`, padL-4, by+barW/2+4, d.Project)
		fmt.Fprintf(&buf, `<rect x="%d" y="%d" width="%d" height="%d" fill="#42a5f5"/>`, padL, by, barLen, barW)
		fmt.Fprintf(&buf, `<text x="%d" y="%d" font-size="11" fill="#333">%d</text>`, padL+barLen+4, by+barW/2+4, d.TaskCount)
	}
	buf.WriteString(`</svg>`)
	return buf.String()
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
