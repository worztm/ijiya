package tui

import (
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/worztm/ijiya/internal/report"
	"github.com/worztm/ijiya/internal/scan"
)

// The interface is a design contract as much as a behaviour one: these tests
// pin the structural rules that make the screens readable, so a later change
// cannot quietly pull the header, the verdict or the key hints off screen, or
// reintroduce duplicated information.

// TestLayoutAlwaysFillsTheScreen guards the frame arithmetic. Every screen must
// be exactly the terminal height; a short frame leaves stale rows behind and a
// tall one scrolls the terminal.
func TestLayoutAlwaysFillsTheScreen(t *testing.T) {
	sizes := []struct{ w, h int }{
		{40, 12}, {60, 20}, {80, 24}, {100, 40}, {120, 50}, {200, 60},
	}
	for _, size := range sizes {
		m := newModel(testOptions())
		m = upd(m, tea.WindowSizeMsg{Width: size.w, Height: size.h})
		m.url.SetValue("https://shop.example.com")

		if got := len(strings.Split(m.View(), "\n")); got != size.h {
			t.Errorf("%dx%d input view has %d lines, want %d", size.w, size.h, got, size.h)
		}

		// Scanning screen.
		m.phase = phaseScanning
		m.running = map[string]bool{"xss": true}
		m.results = map[string]scan.CheckResult{
			"headers": {ID: "headers", Name: "Security headers", Findings: []scan.Finding{{Severity: scan.SeverityHigh, Title: "t"}}},
		}
		for i := 0; i < 30; i++ {
			m.addFeed(scan.Finding{CheckID: "headers", Severity: scan.SeverityLow, Title: "finding"})
		}
		if got := len(strings.Split(m.View(), "\n")); got != size.h {
			t.Errorf("%dx%d scanning view has %d lines, want %d", size.w, size.h, got, size.h)
		}

		// Results screen, including the overflowing case where the report is
		// far taller than the viewport.
		m.phase = phaseResults
		m.report = sampleReport()
		m.syncViewport()
		if got := len(strings.Split(m.View(), "\n")); got != size.h {
			t.Errorf("%dx%d results view has %d lines, want %d", size.w, size.h, got, size.h)
		}
	}
}

// showcaseReport is a report with a spread of severities and enough findings
// to fill a viewport, used by the screen dump and the size tests.
func showcaseReport() report.Report {
	rep := report.Build("https://shop.example.com", time.Now(), []scan.CheckResult{
		{
			ID: "headers", Name: "Security headers", Category: scan.CategoryHeaders,
			Findings: []scan.Finding{
				{CheckID: "headers", Category: scan.CategoryHeaders, Severity: scan.SeverityMedium,
					Title: "Content-Security-Policy (CSP) header missing",
					URL:   "https://shop.example.com/",
					Evidence: "The browser will load scripts, styles, images and frames from anywhere, " +
						"so a single injected tag becomes a full XSS.",
					Remediation: "Start with `Content-Security-Policy: default-src 'self'; object-src 'none'`."},
				{CheckID: "headers", Category: scan.CategoryHeaders, Severity: scan.SeverityLow,
					Title:       "Referrer-Policy header missing",
					URL:         "https://shop.example.com/",
					Evidence:    "Full URLs may leak to third-party origins via the Referer header.",
					Remediation: "Send `Referrer-Policy: strict-origin-when-cross-origin`."},
			},
		},
		{
			ID: "cookies", Name: "Cookie security", Category: scan.CategoryCookies,
			Findings: []scan.Finding{
				{CheckID: "cookies", Category: scan.CategoryCookies, Severity: scan.SeverityHigh,
					Title:       `Cookie "session_id" is missing the HttpOnly flag`,
					URL:         "https://shop.example.com/",
					Evidence:    "Set-Cookie: session_id=[redacted]; path=/",
					Remediation: "Add `HttpOnly` so injected JavaScript cannot read the cookie."},
			},
		},
		{
			ID: "cors", Name: "CORS configuration", Category: scan.CategoryCORS,
			Findings: []scan.Finding{
				{CheckID: "cors", Category: scan.CategoryCORS, Severity: scan.SeverityCritical,
					Title: "CORS allows any origin to read credentialed responses",
					URL:   "https://shop.example.com/api/item",
					Evidence: "Request with Origin: https://ijiya-cors-probe.invalid -> " +
						"Access-Control-Allow-Origin: https://ijiya-cors-probe.invalid, " +
						"Access-Control-Allow-Credentials: true",
					Remediation: "Never reflect arbitrary origins alongside Access-Control-Allow-Credentials: true."},
			},
		},
	}, report.BuildOptions{Requests: 34})
	return rep
}

// sampleTime is a fixed instant so dumps are comparable between runs.
func sampleTime() time.Time {
	return time.Date(2026, 3, 14, 9, 41, 7, 0, time.UTC)
}

// reportWithManyFindings builds a report whose body is far taller than any
// viewport, to exercise the frame's overflow handling.
func reportWithManyFindings(n int) report.Report {
	return report.Build("https://example.com", time.Now(), []scan.CheckResult{{
		ID: "headers", Name: "Security headers", Category: scan.CategoryHeaders,
		Findings: manyFindings(n),
	}}, report.BuildOptions{Requests: 9})
}

// TestLongReportCannotPushChromeOffScreen is the regression test for a frame
// that overflowed: the surplus used to be taken from the front of the body, so
// a report longer than the viewport silently removed the target and verdict
// lines directly under the masthead.
func TestLongReportCannotPushChromeOffScreen(t *testing.T) {
	m := newModel(testOptions())
	m = upd(m, tea.WindowSizeMsg{Width: 100, Height: 24})
	m.report = reportWithManyFindings(80)
	m.phase = phaseResults
	m.syncViewport()

	view := m.View()
	for _, want := range []string{"ijiya", "TARGET", "RISK", "GRADE", "quit"} {
		if !strings.Contains(view, want) {
			t.Errorf("a long report pushed %q off screen:\n%s", want, view)
		}
	}
	if got := len(strings.Split(view, "\n")); got != 24 {
		t.Errorf("view has %d lines, want 24", got)
	}
}

// TestInputCursorMarkedWithoutColour checks the selection cursor is drawn with
// a glyph as well as reverse video, so it survives a terminal or font that
// does not render the highlight.
func TestInputCursorMarkedWithoutColour(t *testing.T) {
	m := newModel(testOptions())
	m = upd(m, tea.WindowSizeMsg{Width: 100, Height: 40})
	m.focus = focusChecks
	m.cursor = 2

	view := stripANSI(m.View())
	if !strings.Contains(view, "›") {
		t.Errorf("no cursor marker in the check list:\n%s", view)
	}
	// The marker must be on the cursor's row, not just anywhere.
	var cursorRow string
	for _, line := range strings.Split(view, "\n") {
		if strings.Contains(line, "›") {
			cursorRow = line
		}
	}
	if !strings.Contains(cursorRow, "tls") {
		t.Errorf("cursor is on the wrong row: %q", cursorRow)
	}

	// With the URL focused there is no check-list cursor at all.
	m.focus = focusURL
	if strings.Contains(stripANSI(m.View()), "›") {
		t.Error("the check-list cursor should not be drawn while the URL field has focus")
	}
}

// TestCheckMarkersAreASCII keeps the state markers in the plain ASCII range,
// where every font and terminal gives them the same width.
func TestCheckMarkersAreASCII(t *testing.T) {
	m := newModel(testOptions())
	m = upd(m, tea.WindowSizeMsg{Width: 100, Height: 40})
	m.focus = focusChecks

	for _, line := range strings.Split(stripANSI(m.View()), "\n") {
		if !strings.Contains(line, "[x]") && !strings.Contains(line, "[ ]") {
			continue
		}
		for _, r := range line {
			if r > 127 && r != '›' && r != '—' {
				t.Errorf("non-ASCII glyph %q in a check row: %q", r, line)
			}
		}
	}
}

// TestResultsDoNotRepeatTheSummary catches the duplication that made the
// results screen noisy: the report body used to restate the target, timing and
// severity summary that the chrome above already shows.
func TestResultsDoNotRepeatTheSummary(t *testing.T) {
	m := newModel(testOptions())
	m = upd(m, tea.WindowSizeMsg{Width: 110, Height: 40})
	m.report = sampleReport()
	m.phase = phaseResults
	m.syncViewport()

	view := stripANSI(m.View())
	if n := strings.Count(view, "SUMMARY"); n != 0 {
		t.Errorf("results screen contains %d SUMMARY block(s), want none:\n%s", n, view)
	}
	if n := strings.Count(view, "example.com"); n != 1 {
		t.Errorf("target is printed %d times, want once:\n%s", n, view)
	}
	// The body must still carry the findings.
	for _, want := range []string{"CRITICAL", "crit"} {
		if !strings.Contains(view, want) {
			t.Errorf("results body is missing %q:\n%s", want, view)
		}
	}
}

// TestResultsStateEverySeverityPresent checks the verdict names each severity
// that has findings, which is the number the user actually acts on.
func TestResultsStateEverySeverityPresent(t *testing.T) {
	m := newModel(testOptions())
	m = upd(m, tea.WindowSizeMsg{Width: 110, Height: 40})
	m.report = sampleReport() // one critical, one high
	m.phase = phaseResults
	m.syncViewport()

	view := stripANSI(m.View())
	for _, want := range []string{"1 critical", "1 high", "2 issue(s)"} {
		if !strings.Contains(view, want) {
			t.Errorf("verdict line is missing %q:\n%s", want, view)
		}
	}
}

// TestQuitMidScanNeedsConfirmation stops a stray q from throwing away a run
// that may already have taken a minute.
func TestQuitMidScanNeedsConfirmation(t *testing.T) {
	m := newModel(testOptions())
	m.phase = phaseScanning

	next, cmd := m.handleKey(runes("q"))
	m = next.(model)
	if cmd == nil {
		t.Error("the first q should schedule the toast to clear")
	}
	if !m.confirmQuit {
		t.Fatal("the first q should arm the confirmation, not quit")
	}
	if m.toast == "" {
		t.Error("the first q should explain what the second one will do")
	}

	// Any other key disarms it again.
	next, _ = m.handleKey(runes("j"))
	m = next.(model)
	if m.confirmQuit {
		t.Error("an unrelated key should disarm the pending quit")
	}
}

// TestScanningFeedShowsNewestFirst checks the live feed is ordered so the most
// recent discovery is the first thing under the section rule.
func TestScanningFeedShowsNewestFirst(t *testing.T) {
	m := newModel(testOptions())
	m = upd(m, tea.WindowSizeMsg{Width: 100, Height: 40})
	m.phase = phaseScanning
	for _, title := range []string{"oldest", "middle", "newest"} {
		m.addFeed(scan.Finding{CheckID: "headers", Severity: scan.SeverityLow, Title: title})
	}

	view := stripANSI(m.View())
	newest := strings.Index(view, "newest")
	oldest := strings.Index(view, "oldest")
	if newest < 0 || oldest < 0 {
		t.Fatalf("feed is missing entries:\n%s", view)
	}
	if newest > oldest {
		t.Errorf("feed is oldest-first (newest at %d, oldest at %d):\n%s", newest, oldest, view)
	}
}

// TestFeedIsBounded keeps the model small during a long deep scan: the feed
// slice and its dedupe set must not grow without limit.
func TestFeedIsBounded(t *testing.T) {
	m := newModel(testOptions())
	for i := 0; i < maxFeed*3; i++ {
		m.addFeed(scan.Finding{
			CheckID:  "headers",
			Severity: scan.SeverityLow,
			Title:    "finding " + string(rune('a'+i%26)) + strings.Repeat("x", i%7),
			URL:      string(rune('0' + i%10)),
		})
	}
	if len(m.feed) > maxFeed {
		t.Errorf("feed holds %d findings, want at most %d", len(m.feed), maxFeed)
	}
	if len(m.feedKeys) > maxFeed {
		t.Errorf("dedupe set holds %d keys, want at most %d", len(m.feedKeys), maxFeed)
	}
}

// TestProgressBarReflectsCompletedChecks checks the bar and the percentage are
// derived from finished checks, not from findings.
func TestProgressBarReflectsCompletedChecks(t *testing.T) {
	m := newModel(testOptions())
	m.results = map[string]scan.CheckResult{}
	for _, id := range []string{"headers", "cookies", "tls", "cors"} {
		m.results[id] = scan.CheckResult{ID: id}
	}
	done, total, _ := m.progress()
	if done != 4 || total != len(m.rows) {
		t.Errorf("progress = %d/%d, want 4/%d", done, total, len(m.rows))
	}
	if b := bar(done, total, 20); strings.Count(b, "█") != 10 {
		t.Errorf("bar filled %d of 20 cells at 50%%, want 10", strings.Count(b, "█"))
	}
	if b := bar(0, 8, 16); strings.Count(b, "█") != 0 {
		t.Errorf("bar should be empty at 0%%, got %q", b)
	}
	if b := bar(8, 8, 16); strings.Count(b, "█") != 16 {
		t.Errorf("bar should be full at 100%%, got %q", b)
	}
}

// TestCleanScanSaysSo checks a scan with no findings reports a pass rather
// than a bare zero, and that a zeroed report cannot print a nonsense duration.
func TestCleanScanSaysSo(t *testing.T) {
	m := newModel(testOptions())
	m = upd(m, tea.WindowSizeMsg{Width: 100, Height: 30})
	m.report = report.Build("https://shop.example.com", time.Now(), []scan.CheckResult{
		{ID: "headers", Name: "Security headers"},
	}, report.BuildOptions{Requests: 12})
	m.phase = phaseResults
	m.syncViewport()

	view := stripANSI(m.View())
	for _, want := range []string{"PASS", "no issues found", "GRADE A+"} {
		if !strings.Contains(view, want) {
			t.Errorf("clean results are missing %q:\n%s", want, view)
		}
	}
	if strings.Contains(view, "0 issue(s)") {
		t.Errorf("a clean scan should not report zero issues:\n%s", view)
	}

	// A report with no start time must not produce a negative clock.
	if got := formatClock(-5000); got != "0ms" {
		t.Errorf("formatClock(-5000) = %q, want 0ms", got)
	}
	if got := formatClock(60 * 60 * 24 * 1000 * 400); got != "24h+" {
		t.Errorf("formatClock(huge) = %q, want 24h+", got)
	}
}

// stripANSI removes SGR sequences so assertions can look at the visible text.
func stripANSI(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		if s[i] == 0x1b && i+1 < len(s) && s[i+1] == '[' {
			j := i + 2
			for j < len(s) && s[j] != 'm' {
				j++
			}
			i = j + 1
			continue
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}
