package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"

	"ijiya/internal/report"
	"ijiya/internal/scan"
	"ijiya/internal/version"
)

// ---------------------------------------------------------------------------
// Design system
//
// The interface is deliberately close to a printed instrument report: a fixed
// left margin, one rule under the masthead and one above the key hints, sharp
// edges, and colour reserved for meaning (severity and state) rather than
// decoration.
//
// The base text uses the terminal's own foreground and background so the tool
// looks native in any theme, light or dark. Only semantic accents are set as
// fixed colours, and they are chosen from the bright half of the 256-colour
// cube so they stay legible on either.
// ---------------------------------------------------------------------------

const (
	// margin is the single left inset used by every block on every screen.
	margin = 2
	// gutter separates a row's columns.
	gutter = "  "
)

// Type scale. Bold marks the level above; dim the level below.
var (
	stMark  = lipgloss.NewStyle().Bold(true)                                                                                                        // masthead, values that matter
	stBody  = lipgloss.NewStyle()                                                                                                                   // default copy
	stSub   = lipgloss.NewStyle().Faint(true)                                                                                                       // labels, secondary copy
	stRule  = lipgloss.NewStyle().Faint(true)                                                                                                       // hairline rules
	stField = lipgloss.NewStyle().Border(lipgloss.NormalBorder(), false, false, false, true).BorderForeground(lipgloss.Color("241")).PaddingLeft(1) // focused input
	stKey   = lipgloss.NewStyle().Bold(true)                                                                                                        // key hints
	stWarn  = lipgloss.NewStyle().Foreground(lipgloss.Color("203"))                                                                                 // errors and failures
	stGood  = lipgloss.NewStyle().Foreground(lipgloss.Color("78"))                                                                                  // success
)

// Severity ink. Critical is the only severity that inverts, because it is the
// only one that should stop the eye from anywhere on the screen.
var (
	stCritical = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("231")).Background(lipgloss.Color("160"))
	stHigh     = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("203"))
	stMedium   = lipgloss.NewStyle().Foreground(lipgloss.Color("215"))
	stLow      = lipgloss.NewStyle().Foreground(lipgloss.Color("109"))
	stInfo     = lipgloss.NewStyle().Faint(true)
)

// sevStyle returns the ink for a severity.
func sevStyle(s scan.Severity) lipgloss.Style {
	switch s {
	case scan.SeverityCritical:
		return stCritical
	case scan.SeverityHigh:
		return stHigh
	case scan.SeverityMedium:
		return stMedium
	case scan.SeverityLow:
		return stLow
	default:
		return stInfo
	}
}

// sevTag renders a fixed-width severity label so labels align in a column.
func sevTag(s scan.Severity) string {
	return sevStyle(s).Render(fmt.Sprintf("%-8s", s.Label()))
}

// gradeInk colours the letter grade by how bad the risk score is.
func gradeInk(g string) lipgloss.Style {
	switch g {
	case "A+", "A":
		return stGood
	case "B":
		return lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("114"))
	case "C":
		return lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("215"))
	case "D":
		return lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("209"))
	default:
		return stHigh
	}
}

// ---------------------------------------------------------------------------
// Frame pieces
// ---------------------------------------------------------------------------

// masthead is the one-line brand mark: name at the left, context at the right.
func masthead(width int, right string) string {
	left := stMark.Render(version.Name)
	tail := stSub.Render(" " + version.Version)
	if right != "" {
		gap := width - 2*margin - lipgloss.Width(left) - lipgloss.Width(tail) - lipgloss.Width(right)
		if gap < 1 {
			return margin2(left + tail)
		}
		return margin2(left + tail + strings.Repeat(" ", gap) + stSub.Render(right))
	}
	return margin2(left + tail)
}

// keyHints is the interactive chrome pinned to the last screen row.
func keyHints(width int, status string, pairs ...[2]string) string {
	keys := make([]string, 0, len(pairs))
	for _, p := range pairs {
		keys = append(keys, stKey.Render(p[0])+stSub.Render(" "+p[1]))
	}
	left := strings.Join(keys, stSub.Render(gutter))
	if status != "" {
		gap := width - 2*margin - lipgloss.Width(left) - lipgloss.Width(status)
		if gap >= 1 {
			return margin2(left + strings.Repeat(" ", gap) + stSub.Render(status))
		}
	}
	return margin2(left)
}

// margin2 indents a rendered block by the screen margin.
func margin2(s string) string {
	if s == "" {
		return ""
	}
	pad := strings.Repeat(" ", margin)
	parts := strings.Split(s, "\n")
	for i := range parts {
		// Rules are drawn full width and must not be shifted.
		if strings.HasPrefix(parts[i], "\x1b") && strings.HasSuffix(parts[i], "\x1b[0m") && strings.Contains(parts[i], "─") {
			continue
		}
		parts[i] = pad + parts[i]
	}
	return strings.Join(parts, "\n")
}

// rule draws the full-width hairline that separates the three bands of the
// layout. The terminal's own foreground is used, so it is a subtle line in
// either theme rather than a colour of its own.
func rule(width int) string {
	if width < 1 {
		width = 1
	}
	return stRule.Render(strings.Repeat("─", width))
}

// ruleLeft draws a hairline with an inline label, e.g. "── CHECKS ───────".
func ruleLeft(width int, label string) string {
	if label == "" {
		return rule(width)
	}
	head := stSub.Render("── " + strings.ToUpper(label) + " ")
	rest := width - lipgloss.Width(head)
	if rest < 1 {
		return head
	}
	return head + stRule.Render(strings.Repeat("─", rest))
}

// bar renders a progress bar. The filled portion is a solid block, which is
// visually distinct at a glance; the track is a plain ASCII dot, because the
// lighter block and box-drawing shades vary too much between fonts to read as
// a track at small sizes.
func bar(done, total, width int) string {
	if total <= 0 || width < 2 {
		return ""
	}
	if done > total {
		done = total
	}
	filled := done * width / total
	return stMark.Render(strings.Repeat("█", filled)) + stRule.Render(strings.Repeat(".", width-filled))
}

// ---------------------------------------------------------------------------
// Screen
// ---------------------------------------------------------------------------

// View renders the active screen. bubbletea calls it after every update.
func (m model) View() string {
	height := m.viewportHeight
	if height <= 0 {
		height = 24
	}
	width := m.width
	if width <= 0 {
		width = 80
	}

	var lines []string
	switch m.phase {
	case phaseInput:
		lines = m.viewInput(width)
	case phaseScanning:
		lines = m.viewScanning(width)
	case phaseResults:
		lines = m.viewResults(width)
	}
	return strings.Join(padTo(lines, height), "\n")
}

// ---------------------------------------------------------------------------
// Input screen
// ---------------------------------------------------------------------------

func (m model) viewInput(width int) []string {
	inner := width - 2*margin
	if inner < 20 {
		inner = 20
	}

	lines := []string{
		masthead(width, version.Description),
		rule(width),
		"",
	}

	// Target field.
	lines = append(lines, margin2(stSub.Render("TARGET URL")))
	if m.focus == focusURL {
		lines = append(lines, stField.Width(inner-1).Render(m.url.View()))
	} else {
		value := m.url.Value()
		if value == "" {
			value = stSub.Render(m.url.Placeholder)
		}
		lines = append(lines, margin2(value))
	}
	if m.inputErr != "" {
		lines = append(lines, margin2(stWarn.Render("! "+m.inputErr)))
	}
	lines = append(lines, "")

	// Check list. Rows are drawn in two columns when the width allows it, so
	// the whole set fits without scrolling on a normal terminal.
	on := 0
	for _, r := range m.rows {
		if r.selected {
			on++
		}
	}
	lines = append(lines, ruleLeft(width, fmt.Sprintf("checks  %d/%d", on, len(m.rows))))

	if m.width >= 76 {
		lines = append(lines, m.checkGrid(width)...)
	} else {
		lines = append(lines, m.checkColumn(width)...)
	}

	lines = append(lines, "")
	lines = append(lines, margin2(deepRow(m.deep)))
	lines = append(lines, "")

	// Fill the space above the key hints so the footer stays pinned to the
	// bottom of the screen rather than floating under the content.
	lines = append(lines, "")
	lines = append(lines, rule(width))
	lines = append(lines, keyHints(width, "",
		[2]string{"enter", "start scan"},
		[2]string{"tab", "switch field"},
		[2]string{"space", "toggle check"},
		[2]string{"a", "all / none"},
		[2]string{"d", "deep mode"},
		[2]string{"q", "quit"},
	))
	return lines
}

// checkGrid lays the checks out in two columns.
func (m model) checkGrid(width int) []string {
	col := (width - 2*margin - 4) / 2
	if col < 24 {
		col = 24
	}
	var out []string
	for i := 0; i < len(m.rows); i += 2 {
		left := m.checkCell(m.rows[i], i, col)
		right := ""
		if i+1 < len(m.rows) {
			right = m.checkCell(m.rows[i+1], i+1, col)
		}
		out = append(out, margin2(padRight(left, col)+gutter+right))
	}
	return out
}

// checkColumn lays the checks out in a single column for narrow terminals.
func (m model) checkColumn(width int) []string {
	var out []string
	for i, r := range m.rows {
		out = append(out, margin2(m.checkCell(r, i, width-2*margin)))
	}
	return out
}

// checkCell renders one check as a single aligned row.
//
// Columns are cursor · box · id · name, and the cursor bar spans the whole
// cell in reverse video, so the active row is unmistakable in any theme
// without relying on a highlight colour. The box marker is plain ASCII on
// purpose: a box glyph renders at the same width in every font and terminal,
// whereas a filled circle varies in width and skews the column.
func (m model) checkCell(r checkRow, index, width int) string {
	box := "[ ]"
	if r.selected {
		box = "[x]"
	}
	underCursor := index == m.cursor && m.focus == focusChecks

	cursor, lead := "  ", "  "
	if underCursor {
		cursor, lead = "› ", "  "
	}
	body := cursor + box + " " + fmt.Sprintf("%-12s", r.id) + " " + r.name

	switch {
	case underCursor:
		return lipgloss.NewStyle().Reverse(true).Render(padRight(truncate(body, width), width))
	case r.selected:
		return lead + stGood.Render(box) + stBody.Render(body[len(cursor)+len(box):])
	default:
		return lead + stSub.Render(box) + stSub.Render(body[len(cursor)+len(box):])
	}
}

// deepRow renders the deep-scan switch as a check row, so it reads as part of
// the same set of options rather than a footnote.
func deepRow(deep bool) string {
	const label = "deep probes"
	const detail = "blind SQLi and POST form fields, slower"
	if deep {
		return "  " + stGood.Render("[x]") + stBody.Render(" "+label) +
			stSub.Render("  "+detail)
	}
	return "  " + stSub.Render("[ ]") + stSub.Render(" "+label+"  "+detail)
}

// ---------------------------------------------------------------------------
// Scanning screen
// ---------------------------------------------------------------------------

func (m model) viewScanning(width int) []string {
	done, total, issues := m.progress()

	head := stSub.Render("TARGET")
	if gaps := width - 2*margin - lipgloss.Width(head) - lipgloss.Width(m.targetURL()); gaps > 0 && m.targetURL() != "" {
		head = head + strings.Repeat(" ", gaps) + stBody.Render(m.targetURL())
	}
	lines := []string{
		masthead(width, "scanning"),
		rule(width),
		margin2(head),
	}

	// Progress band: a bar, the request count and the elapsed time.
	barWidth := width - 2*margin - 30
	if barWidth < 10 {
		barWidth = 10
	}
	if barWidth > 40 {
		barWidth = 40
	}
	pct := 0
	if total > 0 {
		pct = done * 100 / total
	}
	lines = append(lines, margin2(fmt.Sprintf("%s %s %s",
		bar(done, total, barWidth),
		stMark.Render(fmt.Sprintf("%3d%%", pct)),
		stSub.Render(fmt.Sprintf("%d/%d checks · %d requests · %s",
			done, total, m.requestCount(), timeSince(m.started))))))
	lines = append(lines, "")

	// The selected checks, in selection order.
	lines = append(lines, ruleLeft(width, "checks"))
	for _, r := range m.rows {
		if !r.selected {
			continue
		}
		lines = append(lines, margin2(m.checkStatusRow(r, width)))
	}

	// Live findings, newest first, using whatever room is left.
	lines = append(lines, "")
	lines = append(lines, ruleLeft(width, fmt.Sprintf("live findings  %d", issues)))

	fixed := len(lines) + 3 // blank, rule, key hints
	budget := m.viewportHeight - fixed
	if budget < 1 {
		budget = 1
	}
	feed := m.feedLines(width, budget)
	if len(feed) == 0 {
		lines = append(lines, margin2(stSub.Render("waiting for the first result…")))
	} else {
		lines = append(lines, feed...)
	}

	lines = append(lines, "")
	lines = append(lines, rule(width))
	lines = append(lines, keyHints(width, "esc cancel",
		[2]string{"q", "quit"},
	))
	return lines
}

// checkStatusRow renders one check's live state. The state marks are ASCII for
// the same reason the check boxes are: identical width in every font.
func (m model) checkStatusRow(r checkRow, width int) string {
	res, finished := m.results[r.id]
	switch {
	case finished && res.Failed():
		return stWarn.Render("! ") + stMark.Render(fmt.Sprintf("%-12s", r.id)) +
			stWarn.Render("failed  "+truncate(res.Error, width-30))
	case finished:
		n := len(res.Findings)
		state := stGood.Render("done")
		detail := stSub.Render("no issues")
		if n > 0 {
			state = stBody.Render("done")
			detail = sevStyle(highest(res.Findings)).Render(fmt.Sprintf("%d issue(s)", n))
		}
		return stGood.Render("+ ") + stMark.Render(fmt.Sprintf("%-12s", r.id)) +
			state + stSub.Render(gutter) + detail
	case m.running[r.id]:
		return stHigh.Render("> ") + stMark.Render(fmt.Sprintf("%-12s", r.id)) +
			stSub.Render("running…")
	default:
		return stSub.Render("· " + fmt.Sprintf("%-12s", r.id) + "queued")
	}
}

// feedLines renders the live findings feed in the space available, newest
// first, so the most recent discovery is always on screen.
func (m model) feedLines(width, budget int) []string {
	if budget < 1 || len(m.feed) == 0 {
		return nil
	}
	start := len(m.feed) - budget
	if start < 0 {
		start = 0
	}
	recent := m.feed[start:]
	out := make([]string, 0, len(recent))
	// Walk backwards so the newest sits directly under the section rule,
	// where the eye already is while the scan runs.
	for i := len(recent) - 1; i >= 0; i-- {
		f := recent[i]
		text := fmt.Sprintf("%s %s %s", sevTag(f.Severity), stSub.Render(fmt.Sprintf("%-11s", f.CheckID)), f.Title)
		out = append(out, margin2(truncate(text, width-margin)))
	}
	return out
}

// highest returns the most severe finding in a set.
func highest(findings []scan.Finding) scan.Severity {
	var max scan.Severity
	for i, f := range findings {
		if i == 0 || f.Severity > max {
			max = f.Severity
		}
	}
	return max
}

// progress counts finished checks, selected checks and findings so far.
func (m model) progress() (done, total, issues int) {
	for _, r := range m.rows {
		if !r.selected {
			continue
		}
		total++
		if res, ok := m.results[r.id]; ok {
			done++
			issues += len(res.Findings)
		}
	}
	return done, total, issues
}

// ---------------------------------------------------------------------------
// Results screen
// ---------------------------------------------------------------------------

func (m model) viewResults(width int) []string {
	s := m.report.Summary

	head := stSub.Render("TARGET")
	if gaps := width - 2*margin - lipgloss.Width(head) - lipgloss.Width(m.report.Target); gaps > 0 {
		head = head + strings.Repeat(" ", gaps) + stBody.Render(m.report.Target)
	}
	lines := []string{
		masthead(width, "results"),
		rule(width),
		margin2(head),
	}

	// Verdict band: the outcome, the counts that matter, the grade, and the
	// cost. A clean scan says so explicitly rather than showing a zero.
	var parts []string
	if s.Total == 0 {
		parts = append(parts, stGood.Render("PASS")+stBody.Render(" no issues found"))
	} else {
		parts = append(parts, stMark.Render(fmt.Sprintf("%d issue(s)", s.Total)))
		for _, v := range []string{
			sevCount(s.Critical, scan.SeverityCritical),
			sevCount(s.High, scan.SeverityHigh),
			sevCount(s.Medium, scan.SeverityMedium),
			sevCount(s.Low, scan.SeverityLow),
			sevCount(s.Info, scan.SeverityInfo),
		} {
			if v != "" {
				parts = append(parts, v)
			}
		}
	}
	line := strings.Join(parts, stSub.Render(gutter))
	line += stSub.Render(gutter+"RISK ") + stMark.Render(fmt.Sprintf("%d", m.report.RiskScore)) +
		stSub.Render("/100"+gutter+"GRADE ") + gradeInk(m.report.Grade).Render(m.report.Grade)
	if s.Errors > 0 {
		line += stWarn.Render(fmt.Sprintf("%s%d failed", gutter, s.Errors))
	}
	lines = append(lines, margin2(line))
	if m.report.Suppressed > 0 {
		lines = append(lines, margin2(stSub.Render(fmt.Sprintf("%d known finding(s) suppressed by the baseline", m.report.Suppressed))))
	}
	lines = append(lines, "")

	// The full report scrolls in the viewport below the verdict. The viewport
	// pads its output to its full height with blank rows; those are dropped so
	// the frame is assembled from real content only.
	vp := ""
	if m.ready {
		vp = strings.TrimRight(m.viewport.View(), "\n ")
	}
	if vp != "" {
		lines = append(lines, strings.Split(vp, "\n")...)
	}

	lines = append(lines, "")
	lines = append(lines, rule(width))
	status := fmt.Sprintf("%s · %d requests", formatClock(m.report.DurationMS), m.report.Requests)
	if m.toast != "" {
		status = m.toast
	}
	lines = append(lines, keyHints(width, status,
		[2]string{"↑↓", "scroll"},
		[2]string{"pgup/pgdn", "page"},
		[2]string{"s", "save report"},
		[2]string{"r", "new scan"},
		[2]string{"q", "quit"},
	))
	return lines
}

// sevCount renders one severity count, omitted when it is zero so the band
// shows only what is actually present.
func sevCount(n int, s scan.Severity) string {
	if n == 0 {
		return ""
	}
	return sevStyle(s).Render(fmt.Sprintf("%d %s", n, strings.ToLower(s.Label())))
}

// ---------------------------------------------------------------------------
// Shared formatting
// ---------------------------------------------------------------------------

// targetURL is the URL currently being scanned, if any.
func (m model) targetURL() string {
	if m.target == nil {
		return ""
	}
	return m.target.URL.String()
}

// requestCount is how many HTTP requests the current scan has issued.
func (m model) requestCount() int64 {
	if m.target == nil {
		return 0
	}
	return m.target.Requests()
}

// timeSince formats an elapsed duration for the status line.
func timeSince(t time.Time) string {
	if t.IsZero() {
		return "0.0s"
	}
	d := time.Since(t)
	if d < time.Second {
		return fmt.Sprintf("%dms", d.Milliseconds())
	}
	return fmt.Sprintf("%.1fs", d.Seconds())
}

// formatClock renders a millisecond duration for the results footer. Negative
// or absurd inputs are clamped, so a zeroed or skewed report cannot print a
// nonsensical elapsed time.
func formatClock(ms int64) string {
	if ms < 0 {
		ms = 0
	}
	if ms > 24*60*60*1000 {
		return "24h+"
	}
	d := time.Duration(ms) * time.Millisecond
	switch {
	case d < time.Second:
		return fmt.Sprintf("%dms", ms)
	case d < time.Minute:
		return fmt.Sprintf("%.1fs", d.Seconds())
	default:
		return fmt.Sprintf("%dm%ds", int(d.Minutes()), int(d.Seconds())%60)
	}
}

// padRight pads a possibly styled string to a visible width.
func padRight(s string, width int) string {
	w := lipgloss.Width(s)
	if w >= width {
		return s
	}
	return s + strings.Repeat(" ", width-w)
}

// padTo grows (or trims) lines to exactly height rows so each frame covers
// the whole screen and leaves no stale output behind. Elements containing
// embedded newlines (which is how lipgloss returns multi-line blocks) are
// flattened first, otherwise the count would not match what is displayed.
//
// The top and bottom bands are always preserved. When the assembled frame is
// too tall - a long verdict line plus a full viewport, say - the surplus is
// taken from the end of the body, never from the front, so the masthead, the
// verdict and the key hints cannot be pushed off screen by content.
func padTo(lines []string, height int) []string {
	flat := make([]string, 0, len(lines))
	for _, l := range lines {
		flat = append(flat, strings.Split(l, "\n")...)
	}
	lines = flat

	if height < 1 {
		height = 1
	}
	if len(lines) <= height {
		for len(lines) < height {
			lines = append(lines, "")
		}
		return lines
	}

	const (
		keepTop    = 4 // masthead, rule, target, verdict
		keepBottom = 3 // blank, rule, key hints
	)
	if keepTop+keepBottom >= height {
		return lines[:height]
	}
	room := height - keepTop - keepBottom
	head := lines[:keepTop]
	tail := lines[len(lines)-keepBottom:]
	body := lines[keepTop : len(lines)-keepBottom]
	if len(body) > room {
		body = body[:room]
	}

	out := make([]string, 0, height)
	out = append(out, head...)
	out = append(out, body...)
	out = append(out, tail...)
	for len(out) < height {
		out = append(out, "")
	}
	return out
}

// truncate shortens s to at most width visible cells, appending an ellipsis.
func truncate(s string, width int) string {
	if width <= 0 {
		return s
	}
	if lipgloss.Width(s) <= width {
		return s
	}
	// Style-free text only: callers compose styles after truncating.
	r := []rune(s)
	if len(r) <= width {
		return s
	}
	if width <= 1 {
		return string(r[:width])
	}
	return string(r[:width-1]) + "…"
}

// renderReport turns a finished report into the body shown in the viewport.
//
// Only the findings are rendered: the target, timing, request count and the
// verdict are already in the chrome above, and the report's own header and
// SUMMARY blocks would state them a second time.
//
// The body itself is rendered without colour, because the interface adapts to
// the terminal's theme and the report renderer's palette assumes a dark
// background. Severity ink is re-applied to the leading label of each finding
// instead, which keeps the colour meaning without the legibility risk.
func renderReport(rep report.Report, width int, min scan.Severity) string {
	if len(rep.Checks) == 0 {
		return ""
	}
	var b strings.Builder
	rep.Banner = false
	_ = report.WriteText(&b, rep, report.TextOptions{
		Color:       false,
		Verbose:     false,
		Min:         min,
		Width:       width,
		HideHeader:  true,
		HideSummary: true,
	})
	return inkSeverityLabels(strings.TrimLeft(b.String(), "\n"))
}

// sevLabels maps a rendered severity label onto its severity.
var sevLabels = []struct {
	label string
	sev   scan.Severity
}{
	{"CRITICAL", scan.SeverityCritical},
	{"HIGH", scan.SeverityHigh},
	{"MEDIUM", scan.SeverityMedium},
	{"LOW", scan.SeverityLow},
	{"INFO", scan.SeverityInfo},
}

// inkSeverityLabels colours the leading severity label of each finding line.
// The report body is rendered uncoloured so it stays legible in any terminal
// theme; this puts the ink back only where it carries meaning.
func inkSeverityLabels(body string) string {
	lines := strings.Split(body, "\n")
	for i, line := range lines {
		trimmed := strings.TrimLeft(line, " ")
		for _, sl := range sevLabels {
			if !strings.HasPrefix(trimmed, sl.label) {
				continue
			}
			indent := line[:len(line)-len(trimmed)]
			rest := trimmed[len(sl.label):]
			// Only the label is tinted; the title must not inherit it.
			lines[i] = indent + sevStyle(sl.sev).Render(sl.label) + rest
			break
		}
	}
	return strings.Join(lines, "\n")
}
