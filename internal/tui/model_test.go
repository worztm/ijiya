package tui

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"ijiya/internal/report"
	"ijiya/internal/scan"
)

// upd runs one update cycle and returns the resulting model.
func upd(m model, msg tea.Msg) model {
	next, _ := m.Update(msg)
	return next.(model)
}

func enterKey() tea.KeyMsg { return tea.KeyMsg{Type: tea.KeyEnter} }
func tabKey() tea.KeyMsg   { return tea.KeyMsg{Type: tea.KeyTab} }
func escKey() tea.KeyMsg   { return tea.KeyMsg{Type: tea.KeyEsc} }
func downKey() tea.KeyMsg  { return tea.KeyMsg{Type: tea.KeyDown} }
func upKey() tea.KeyMsg    { return tea.KeyMsg{Type: tea.KeyUp} }
func spaceKey() tea.KeyMsg { return tea.KeyMsg{Type: tea.KeySpace} }
func runes(s string) tea.KeyMsg {
	return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s)}
}

func testOptions() Options {
	return Options{
		Timeout:     3 * time.Second,
		Threads:     4,
		MinSeverity: scan.SeverityInfo,
		FailOn:      scan.SeverityCritical,
	}
}

// ---------------------------------------------------------------------------
// Input screen
// ---------------------------------------------------------------------------

func TestInputScreenListsEveryCheck(t *testing.T) {
	m := newModel(testOptions())
	m = upd(m, tea.WindowSizeMsg{Width: 100, Height: 40})

	view := m.View()
	for _, want := range []string{"Target URL", "headers", "cookies", "tls", "cors", "xss", "sqli", "disclosure", "redirect"} {
		if !strings.Contains(view, want) {
			t.Errorf("input screen is missing %q", want)
		}
	}
	if m.phase != phaseInput {
		t.Errorf("phase = %v, want phaseInput", m.phase)
	}
}

func TestTabMovesFocusAndSpaceToggles(t *testing.T) {
	m := newModel(testOptions())

	// Starts focused on the URL field.
	if m.focus != focusURL {
		t.Fatalf("initial focus = %d, want focusURL", m.focus)
	}

	// Typing reaches the URL field, not the check list.
	m = upd(m, runes("https://example.com"))
	if !strings.HasPrefix(m.url.Value(), "https://example.com") {
		t.Fatalf("typing did not reach the URL field: %q", m.url.Value())
	}
	if m.cursor != 0 {
		t.Errorf("cursor moved while typing: %d", m.cursor)
	}

	m = upd(m, tabKey())
	if m.focus != focusChecks {
		t.Fatalf("focus after tab = %d, want focusChecks", m.focus)
	}

	m = upd(m, downKey())
	if m.cursor != 1 {
		t.Errorf("cursor after down = %d, want 1", m.cursor)
	}

	// Space toggles whichever row the cursor is on.
	if !m.rows[1].selected {
		t.Fatal("row 1 should start selected")
	}
	m = upd(m, spaceKey())
	if m.rows[1].selected {
		t.Error("space should have deselected row 1")
	}

	// Tab returns to the URL field.
	m = upd(m, tabKey())
	if m.focus != focusURL {
		t.Errorf("focus after second tab = %d, want focusURL", m.focus)
	}
}

func TestEmptyURLRefusesToStart(t *testing.T) {
	m := newModel(testOptions())
	m = upd(m, enterKey())

	if m.phase != phaseInput {
		t.Errorf("phase = %v, want phaseInput", m.phase)
	}
	if m.inputErr == "" {
		t.Error("expected an error when starting with an empty URL")
	}
}

func TestInvalidURLReportsError(t *testing.T) {
	m := newModel(testOptions())
	m.url.SetValue("ftp://example.com")
	m = upd(m, enterKey())

	if m.phase != phaseInput {
		t.Errorf("phase = %v, want phaseInput", m.phase)
	}
	if !strings.Contains(m.inputErr, "scheme") {
		t.Errorf("inputErr = %q, want a scheme error", m.inputErr)
	}
}

func TestUncheckingEveryCheckRefusesToStart(t *testing.T) {
	m := newModel(testOptions())
	m.url.SetValue("http://127.0.0.1:1/")
	m = upd(m, tabKey())
	m = upd(m, runes("a")) // deselect all
	if n := len(selectedIDs(m.rows)); n != 0 {
		t.Fatalf("expected no checks selected, got %d", n)
	}
	m = upd(m, enterKey())

	if m.phase != phaseInput {
		t.Errorf("phase = %v, want phaseInput", m.phase)
	}
	if !strings.Contains(m.inputErr, "check") {
		t.Errorf("inputErr = %q, want a check-selection error", m.inputErr)
	}
}

func TestDeepToggle(t *testing.T) {
	m := newModel(testOptions())
	if m.deep {
		t.Fatal("deep should start off")
	}
	m = upd(m, tabKey())
	m = upd(m, runes("d"))
	if !m.deep {
		t.Error("d should have enabled deep mode")
	}
	m = upd(m, runes("d"))
	if m.deep {
		t.Error("d should have disabled deep mode again")
	}
}

// ---------------------------------------------------------------------------
// Live scan
// ---------------------------------------------------------------------------

// insecureServer is a tiny app with none of the protections ijiya looks for.
func insecureServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Add("Set-Cookie", "session_id=demo-token; Path=/")
		fmt.Fprint(w, `<!doctype html><html><body>
<h1>demo</h1>
<form method="get" action="/search"><input name="q" value=""></form>
</body></html>`)
	}))
}

// drain runs the scan's message pump until the report arrives, mirroring
// what bubbletea does at runtime.
func drain(t *testing.T, m model) model {
	t.Helper()
	for i := 0; i < 500; i++ {
		if m.phase == phaseResults {
			return m
		}
		if m.pump == nil {
			t.Fatal("no scan channel")
		}
		msg := waitFor(m.pump)()
		m = upd(m, msg)
	}
	t.Fatal("scan never reached the results phase")
	return m
}

func TestLiveScanStreamsFindingsBeforeCompletion(t *testing.T) {
	srv := insecureServer()
	defer srv.Close()

	m := newModel(testOptions())
	m = upd(m, tea.WindowSizeMsg{Width: 110, Height: 45})
	m.url.SetValue(srv.URL)
	m = upd(m, enterKey())

	if m.phase != phaseScanning {
		t.Fatalf("phase = %v, want phaseScanning", m.phase)
	}
	if m.pump == nil {
		t.Fatal("scan channel was not created")
	}
	if m.target == nil || m.targetURL() != srv.URL {
		t.Errorf("target = %v, want %s", m.target, srv.URL)
	}

	// Consume the pump one message at a time and confirm findings arrive
	// as their own messages, before the scan is finished.
	sawStart, sawFinding, sawDone := false, false, false
	for i := 0; i < 500 && m.phase == phaseScanning; i++ {
		msg := waitFor(m.pump)()
		switch msg.(type) {
		case checkStartedMsg:
			sawStart = true
		case findingMsg:
			sawFinding = true
		case scanDoneMsg:
			sawDone = true
		}
		m = upd(m, msg)
	}

	if !sawStart {
		t.Error("never saw a check start")
	}
	if !sawFinding {
		t.Error("never saw a live finding message")
	}
	if !sawDone {
		t.Error("never saw the scan completion message")
	}
	if m.phase != phaseResults {
		t.Errorf("phase = %v, want phaseResults", m.phase)
	}
	if len(m.feed) == 0 {
		t.Error("the live feed is empty")
	}
	if len(m.report.Checks) == 0 {
		t.Error("the report has no checks")
	}
	// The feed is deduplicated, so it must match the authoritative count
	// exactly: every finding is emitted once and counted once.
	if got, want := len(m.feed), m.report.Summary.Total; got != want {
		t.Errorf("feed has %d findings, report has %d", got, want)
	}
}

func TestScanResultsShowIssueCounts(t *testing.T) {
	srv := insecureServer()
	defer srv.Close()

	m := newModel(testOptions())
	m = upd(m, tea.WindowSizeMsg{Width: 110, Height: 45})
	m.url.SetValue(srv.URL)
	m = upd(m, enterKey())
	m = drain(t, m)

	view := m.View()
	for _, want := range []string{"Target", "issue", "risk", "grade"} {
		if !strings.Contains(view, want) {
			t.Errorf("results view is missing %q\nview:\n%s", want, view)
		}
	}
	if m.report.Summary.Total == 0 {
		t.Error("expected findings against the insecure demo server")
	}
	if m.report.Summary.High == 0 && m.report.Summary.Medium == 0 {
		t.Error("expected at least a high or medium finding (insecure cookie)")
	}
}

func TestAbortReturnsToInput(t *testing.T) {
	srv := insecureServer()
	defer srv.Close()

	m := newModel(testOptions())
	m = upd(m, tea.WindowSizeMsg{Width: 110, Height: 45})
	m.url.SetValue(srv.URL)
	m = upd(m, enterKey())
	if m.phase != phaseScanning {
		t.Fatalf("phase = %v, want phaseScanning", m.phase)
	}
	if m.cancel == nil {
		t.Fatal("no cancel function installed")
	}

	m = upd(m, escKey())
	if m.phase != phaseInput {
		t.Errorf("phase = %v, want phaseInput after cancel", m.phase)
	}
	if m.cancel != nil {
		t.Error("cancel should have been cleared")
	}
	if !strings.Contains(m.toast, "cancelled") {
		t.Errorf("toast = %q, want a cancellation notice", m.toast)
	}
}

// ---------------------------------------------------------------------------
// Results screen
// ---------------------------------------------------------------------------

func sampleReport() report.Report {
	return report.Build("https://example.com", time.Now(), []scan.CheckResult{
		{
			ID:   "headers",
			Name: "Security headers",
			Findings: []scan.Finding{
				{Severity: scan.SeverityCritical, Title: "crit"},
				{Severity: scan.SeverityHigh, Title: "high"},
			},
		},
	}, 12)
}

func TestResultsViewRendersSummary(t *testing.T) {
	m := newModel(testOptions())
	m = upd(m, tea.WindowSizeMsg{Width: 100, Height: 40})
	m.report = sampleReport()
	m.phase = phaseResults
	m.syncViewport()

	view := m.View()
	for _, want := range []string{"example.com", "2 issue", "risk", "CRITICAL"} {
		if !strings.Contains(view, want) {
			t.Errorf("results view is missing %q\nview:\n%s", want, view)
		}
	}
}

func TestResultsKeysScroll(t *testing.T) {
	m := newModel(testOptions())
	m = upd(m, tea.WindowSizeMsg{Width: 100, Height: 40})
	m.report = sampleReport()
	m.phase = phaseResults
	m.syncViewport()

	if m.viewport.YOffset != 0 {
		t.Fatalf("YOffset = %d, want 0", m.viewport.YOffset)
	}

	// Make the content taller than the viewport so scrolling is possible.
	long := report.Build("https://example.com", time.Now(), []scan.CheckResult{{
		ID: "headers", Name: "Security headers",
		Findings: manyFindings(60),
	}}, 12)
	m.report = long
	m.syncViewport()

	m = upd(m, downKey())
	if m.viewport.YOffset != 1 {
		t.Errorf("YOffset after down = %d, want 1", m.viewport.YOffset)
	}
	m = upd(m, downKey())
	m = upd(m, upKey())
	if m.viewport.YOffset != 1 {
		t.Errorf("YOffset after down down up = %d, want 1", m.viewport.YOffset)
	}
	m = upd(m, escKey())
	if m.phase != phaseInput {
		t.Errorf("phase = %v, want phaseInput after esc", m.phase)
	}
}

func TestExitCodeHonoursFailOn(t *testing.T) {
	m := newModel(testOptions())
	if m.exitCode() != exitOK {
		t.Errorf("empty report should exit 0, got %d", m.exitCode())
	}

	m.report = sampleReport() // contains a critical
	if m.exitCode() != exitFindings {
		t.Errorf("critical finding with FailOn=critical should exit 1, got %d", m.exitCode())
	}

	m.opts.FailOn = scan.SeverityCritical
	m.report = report.Build("https://example.com", time.Now(), []scan.CheckResult{{
		ID: "headers", Name: "Security headers",
		Findings: []scan.Finding{{Severity: scan.SeverityLow, Title: "low only"}},
	}}, 5)
	if m.exitCode() != exitOK {
		t.Errorf("low finding with FailOn=critical should exit 0, got %d", m.exitCode())
	}
}

func TestAutostartLaunchesImmediately(t *testing.T) {
	opts := testOptions()
	opts.Autostart = true
	m := newModel(opts)
	m.url.SetValue("http://127.0.0.1:1/")

	cmd := m.Init()
	if cmd == nil {
		t.Fatal("Init should return a command when autostart is set")
	}
	if msg := cmd(); msg == nil {
		t.Error("autostart command should produce a message")
	}
}

func TestPlainInitBlinksCursor(t *testing.T) {
	m := newModel(testOptions())
	if m.Init() == nil {
		t.Error("Init should return the cursor blink command")
	}
}

// TestViewAlwaysFillsTheScreen guards the frame padding: a frame that is
// too short leaves stale output behind, and one that is too long scrolls
// the terminal. Embedded newlines inside a lipgloss block are the classic
// way to get this wrong, because the slice length stops matching the
// number of visual lines.
func TestViewAlwaysFillsTheScreen(t *testing.T) {
	for _, h := range []int{20, 30, 42, 60} {
		for _, w := range []int{60, 100, 160} {
			m := newModel(testOptions())
			m = upd(m, tea.WindowSizeMsg{Width: w, Height: h})

			for _, ph := range []phase{phaseInput, phaseScanning, phaseResults} {
				m.phase = ph
				switch ph {
				case phaseScanning:
					m.running = map[string]bool{"xss": true}
					m.results = map[string]scan.CheckResult{
						"headers": {ID: "headers", Name: "Security headers", Findings: manyFindings(3)},
					}
					m.feed = manyFindings(5)
				case phaseResults:
					m.report = sampleReport()
					m.syncViewport()
				}
				got := len(strings.Split(m.View(), "\n"))
				if got != h {
					t.Errorf("%dx%d phase=%v: View has %d lines, want %d",
						w, h, ph, got, h)
				}
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func manyFindings(n int) []scan.Finding {
	out := make([]scan.Finding, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, scan.Finding{
			Severity: scan.SeverityMedium,
			Title:    fmt.Sprintf("finding number %d", i),
			URL:      "https://example.com/",
		})
	}
	return out
}
