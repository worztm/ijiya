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

// Palette. Colours are chosen to stay readable on both light and dark
// terminals.
var (
	stTitle   = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("81"))
	stDim     = lipgloss.NewStyle().Foreground(lipgloss.Color("244"))
	stError   = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("196"))
	stOK      = lipgloss.NewStyle().Foreground(lipgloss.Color("78"))
	stSelect  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("232")).Background(lipgloss.Color("81"))
	stCursor  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("81"))
	stFooter  = lipgloss.NewStyle().Foreground(lipgloss.Color("241"))
	stKey     = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("252"))
	stBox     = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(lipgloss.Color("63"))
	stSection = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("252"))

	stCritical = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("232")).Background(lipgloss.Color("196"))
	stHigh     = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("196"))
	stMedium   = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("220"))
	stLow      = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("51"))
	stInfo     = lipgloss.NewStyle().Foreground(lipgloss.Color("245"))
)

// sevStyle returns the style used for a severity label.
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

// sevTag renders a fixed-width severity label.
func sevTag(s scan.Severity) string {
	return sevStyle(s).Render(fmt.Sprintf("%-8s", s.Label()))
}

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
		return "0s"
	}
	d := time.Since(t)
	if d < time.Second {
		return fmt.Sprintf("%dms", d.Milliseconds())
	}
	return fmt.Sprintf("%.1fs", d.Seconds())
}

// View renders the active screen. bubbletea calls it after every update.
func (m model) View() string {
	height := m.viewportHeight
	if height <= 0 {
		height = 24
	}

	var lines []string
	switch m.phase {
	case phaseInput:
		lines = m.viewInput()
	case phaseScanning:
		lines = m.viewScanning()
	case phaseResults:
		lines = m.viewResults()
	}
	return strings.Join(padTo(lines, height), "\n")
}

// ---------------------------------------------------------------------------
// Input screen
// ---------------------------------------------------------------------------

func (m model) viewInput() []string {
	lines := []string{
		stTitle.Render(bannerLine()),
		stDim.Render(version.Notice),
		"",
	}

	inner := m.width - 6
	if inner < 30 {
		inner = 30
	}

	var body []string
	body = append(body, "  "+label("Target URL", m.focus == focusURL))
	if m.focus == focusURL {
		body = append(body, "  "+m.url.View())
	} else {
		value := m.url.Value()
		if value == "" {
			value = stDim.Render(m.url.Placeholder)
		}
		body = append(body, "  "+value)
	}
	body = append(body, "")

	body = append(body, "  "+label("Checks", m.focus == focusChecks)+
		"  "+stDim.Render("tab switches · space toggles · a all/none · d deep"))
	for i, r := range m.rows {
		selected := "○"
		if r.selected {
			selected = "●"
		}
		if i == m.cursor && m.focus == focusChecks {
			body = append(body, stSelect.Render(fmt.Sprintf(" › %s  %-12s %s", selected, r.id, r.name)))
			continue
		}
		mark := stDim.Render("○")
		if r.selected {
			mark = stOK.Render("●")
		}
		row := "   " + mark + "  " + fmt.Sprintf("%-12s %s", r.id, r.name)
		if r.id == "sqli" && m.deep {
			row += stDim.Render("  (deep: blind SQLi + POST forms)")
		}
		body = append(body, row)
	}

	body = append(body, "")
	deepMark := "○ deep scan"
	if m.deep {
		deepMark = "● deep scan (blind SQLi + POST forms)"
	}
	body = append(body, "  "+stDim.Render(deepMark))

	if m.inputErr != "" {
		body = append(body, "")
		body = append(body, "  "+stError.Render("✗ "+m.inputErr))
	}

	lines = append(lines, indentLines(stBox.Width(inner).Render(strings.Join(body, "\n")), "  "), "")

	lines = append(lines, footer(
		keyHint("enter", "start"),
		keyHint("tab", "switch"),
		keyHint("space", "toggle"),
		keyHint("a", "all/none"),
		keyHint("d", "deep"),
		keyHint("q", "quit"),
	))
	return lines
}

// label renders a field label, highlighted when its field has focus.
func label(text string, focused bool) string {
	if focused {
		return stSelect.Render(text)
	}
	return stSection.Render(text)
}

// ---------------------------------------------------------------------------
// Scanning screen
// ---------------------------------------------------------------------------

func (m model) viewScanning() []string {
	lines := []string{
		stTitle.Render(bannerLine()),
		stDim.Render(version.Notice),
		"",
	}
	lines = append(lines, fmt.Sprintf("  %s %s",
		stTitle.Render("Scanning"), m.targetURL()))

	if m.toast != "" {
		lines = append(lines, "  "+stOK.Render(m.toast))
	}
	lines = append(lines, "")

	// One row per selected check.
	lines = append(lines, "  "+stSection.Render("Checks"))
	done, total := 0, 0
	for _, r := range m.rows {
		if !r.selected {
			continue
		}
		total++
		switch res, finished := m.results[r.id]; {
		case finished:
			done++
			issues := fmt.Sprintf("%d issue(s)", len(res.Findings))
			style := stOK
			if res.Failed() {
				style = stError
				issues = "error: " + res.Error
			} else if len(res.Findings) > 0 {
				style = stDim
			}
			lines = append(lines, fmt.Sprintf("   %s %-12s %-24s %s",
				stOK.Render("✔"), r.id, r.name, style.Render(issues)))
		case m.running[r.id]:
			lines = append(lines, fmt.Sprintf("   %s %-12s %-24s %s",
				stCursor.Render(strings.TrimSpace(m.spinner.View())), r.id, r.name,
				stDim.Render("running…")))
		default:
			lines = append(lines, fmt.Sprintf("   %s %-12s %-24s %s",
				stDim.Render("·"), r.id, r.name, stDim.Render("queued")))
		}
	}

	// Live findings feed, newest last, trimmed to whatever room is left.
	lines = append(lines, "")
	lines = append(lines, "  "+stSection.Render(fmt.Sprintf("Live findings (%d)", len(m.feed))))

	fixed := len(lines) + 2 // footer + its leading blank
	budget := m.viewportHeight - fixed
	if budget < 1 {
		budget = 1
	}
	feed := feedLines(m.feed, m.width)
	if len(feed) > budget {
		feed = feed[len(feed)-budget:]
	}
	if len(feed) == 0 {
		lines = append(lines, "  "+stDim.Render("waiting for the first result…"))
	} else {
		lines = append(lines, feed...)
	}

	lines = append(lines, "")
	lines = append(lines, footer(
		hint(fmt.Sprintf("%d/%d checks", done, total)),
		hint(fmt.Sprintf("%d requests", int(m.requestCount()))),
		hint(timeSince(m.started)),
		keyHint("esc", "cancel"),
	))
	return lines
}

// feedLines renders the live findings list.
func feedLines(feed []scan.Finding, width int) []string {
	out := make([]string, 0, len(feed))
	for _, f := range feed {
		text := fmt.Sprintf("  %s %s  %s", sevTag(f.Severity), f.CheckID, f.Title)
		out = append(out, truncate(text, width-1))
	}
	return out
}

// ---------------------------------------------------------------------------
// Results screen
// ---------------------------------------------------------------------------

func (m model) viewResults() []string {
	s := m.report.Summary

	lines := []string{
		stTitle.Render(bannerLine()),
		stDim.Render(version.Notice),
		fmt.Sprintf("  %s  %s", stSection.Render("Target"), m.report.Target),
		"",
	}

	// Severity chips.
	chips := make([]string, 0, 6)
	add := func(n int, sev scan.Severity) {
		if n > 0 {
			chips = append(chips, sevStyle(sev).Render(fmt.Sprintf("%d %s", n, sev.Label())))
		}
	}
	add(s.Critical, scan.SeverityCritical)
	add(s.High, scan.SeverityHigh)
	add(s.Medium, scan.SeverityMedium)
	add(s.Low, scan.SeverityLow)
	add(s.Info, scan.SeverityInfo)

	summary := stSection.Render(fmt.Sprintf("  %d issue(s)", s.Total))
	if len(chips) > 0 {
		summary += "   " + strings.Join(chips, stDim.Render(" · "))
	}
	summary += stDim.Render(fmt.Sprintf("   risk %d/100 · grade ", m.report.RiskScore)) +
		gradeStyle(m.report.Grade).Render(m.report.Grade)
	lines = append(lines, summary)
	lines = append(lines, "")

	// Reserved height for the viewport (headerLines counts the six lines
	// above: banner, notice, target, blank, summary, blank).
	vp := ""
	if m.ready {
		vp = m.viewport.View()
	}
	lines = append(lines, vp)

	lines = append(lines, "")
	footerItems := footer(
		keyHint("↑↓", "scroll"),
		keyHint("pgup/pgdn", "page"),
		keyHint("s", "save"),
		keyHint("esc", "new scan"),
		keyHint("q", "quit"),
	)
	if m.toast != "" {
		lines = append(lines, stOK.Render("  "+m.toast))
	} else {
		lines = append(lines, footerItems)
	}
	return lines
}

// gradeStyle colours the letter grade by how bad the risk score is.
func gradeStyle(g string) lipgloss.Style {
	switch g {
	case "A+", "A":
		return lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("78"))
	case "B":
		return lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("114"))
	case "C":
		return lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("220"))
	case "D":
		return lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("208"))
	default:
		return lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("196"))
	}
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

// footer renders a status line from pre-rendered segments. Segments are
// styled individually rather than the whole line, so a bold key does not
// reset the colour of everything that follows it.
func footer(items ...string) string {
	return "  " + strings.Join(items, stFooter.Render(" · "))
}

// keyHint styles a "key action" pair for the footer.
func keyHint(key, action string) string {
	return stKey.Render(key) + " " + stDim.Render(action)
}

// hint styles a plain status value for the footer.
func hint(s string) string {
	return stDim.Render(s)
}

// padTo grows (or trims) lines to exactly height rows so each frame covers
// the whole screen and leaves no stale output behind. Elements containing
// embedded newlines (which is how lipgloss returns multi-line blocks) are
// flattened first, otherwise the count would not match what is displayed.
func padTo(lines []string, height int) []string {
	flat := make([]string, 0, len(lines))
	for _, l := range lines {
		flat = append(flat, strings.Split(l, "\n")...)
	}
	lines = flat

	if height < 1 {
		height = 1
	}
	if len(lines) > height {
		// Keep the header and the footer; drop from the middle.
		keepTop := 4
		keepBottom := 2
		if keepTop+keepBottom > height {
			return lines[:height]
		}
		head := lines[:keepTop]
		tail := lines[len(lines)-keepBottom:]
		middle := lines[keepTop : len(lines)-keepBottom]
		room := height - keepTop - keepBottom
		if room < len(middle) {
			middle = middle[:room]
		}
		out := append([]string{}, head...)
		out = append(out, middle...)
		out = append(out, tail...)
		return out
	}
	for len(lines) < height {
		lines = append(lines, "")
	}
	return lines
}

// truncate shortens s to at most width runes, appending an ellipsis.
func truncate(s string, width int) string {
	if width <= 0 {
		return s
	}
	r := []rune(s)
	if len(r) <= width {
		return s
	}
	if width <= 1 {
		return string(r[:width])
	}
	return string(r[:width-1]) + "…"
}

// indentLines prefixes every line of a possibly multi-line block, which a
// plain string concatenation would not do.
func indentLines(s, prefix string) string {
	if prefix == "" || s == "" {
		return s
	}
	parts := strings.Split(s, "\n")
	for i := range parts {
		parts[i] = prefix + parts[i]
	}
	return strings.Join(parts, "\n")
}

// renderReport turns a finished report into the text shown in the viewport.
func renderReport(rep report.Report, width int, min scan.Severity) string {
	if len(rep.Checks) == 0 {
		return ""
	}
	var b strings.Builder
	_ = report.WriteText(&b, rep, report.TextOptions{
		Color:   true,
		Verbose: false,
		Min:     min,
		Width:   width,
		Banner:  false, // the TUI supplies its own header
	})
	return b.String()
}
