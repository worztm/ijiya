package tui

import (
	"fmt"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/worztm/ijiya/internal/report"
	"github.com/worztm/ijiya/internal/scan"
)

// TestDumpScreens is a development aid: run with
//
//	go test ./internal/tui -run TestDumpScreens -v
//
// to print the screens so the layout can be eyeballed. Nothing here launches a
// scan, so the dump never touches the network.
func TestDumpScreens(t *testing.T) {
	// --- input, with the cursor in the check list -------------------------
	m := newModel(testOptions())
	m = upd(m, tea.WindowSizeMsg{Width: 100, Height: 30})
	m.url.SetValue("https://shop.example.com")
	m.focus = focusChecks
	m.cursor = 4
	m.url.Blur()
	emit(t, "INPUT", m.View())

	// --- input on a narrow terminal --------------------------------------
	narrow := newModel(testOptions())
	narrow = upd(narrow, tea.WindowSizeMsg{Width: 64, Height: 24})
	narrow.url.SetValue("https://shop.example.com")
	narrow.focus = focusChecks
	narrow.cursor = 1
	narrow.url.Blur()
	emit(t, "INPUT-NARROW", narrow.View())

	// --- scanning, mid-run ------------------------------------------------
	s := newModel(testOptions())
	s = upd(s, tea.WindowSizeMsg{Width: 100, Height: 30})
	s.url.SetValue("https://shop.example.com")
	if tgt, err := scan.NewTarget("https://shop.example.com", scan.Options{Timeout: 3 * time.Second, Concurrency: 4}); err == nil {
		s.target = tgt
	}
	s.phase = phaseScanning
	s.running = map[string]bool{"xss": true, "sqli": true}
	s.results = map[string]scan.CheckResult{
		"headers": {ID: "headers", Name: "Security headers", Findings: manyFindings(6)},
		"cookies": {ID: "cookies", Name: "Cookie security", Findings: manyFindings(3)},
		"tls":     {ID: "tls", Name: "TLS and HTTPS"},
		"cors":    {ID: "cors", Name: "CORS configuration", Findings: manyFindings(2)},
	}
	// Realistic findings, so the feed shows what it will really show.
	for _, f := range []scan.Finding{
		{CheckID: "headers", Severity: scan.SeverityMedium, Title: "Content-Security-Policy (CSP) header missing"},
		{CheckID: "cookies", Severity: scan.SeverityHigh, Title: `Cookie "session_id" is missing the HttpOnly flag`},
		{CheckID: "cors", Severity: scan.SeverityCritical, Title: "CORS allows any origin to read credentialed responses"},
		{CheckID: "headers", Severity: scan.SeverityLow, Title: "Referrer-Policy header missing"},
		{CheckID: "disclosure", Severity: scan.SeverityHigh, Title: "Server banner discloses Apache/2.4.49"},
	} {
		s.addFeed(f)
	}
	// Pretend the scan has been running for a few seconds.
	s.started = time.Now().Add(-3200 * time.Millisecond)
	emit(t, "SCANNING", m2v(s))

	// --- results with findings -------------------------------------------
	r := newModel(testOptions())
	r = upd(r, tea.WindowSizeMsg{Width: 100, Height: 30})
	r.report = showcaseReport()
	r.phase = phaseResults
	r.syncViewport()
	emit(t, "RESULTS", r.View())

	// --- results, clean scan ---------------------------------------------
	c := newModel(testOptions())
	c = upd(c, tea.WindowSizeMsg{Width: 100, Height: 30})
	c.report = report.Build("https://shop.example.com", sampleTime(), []scan.CheckResult{
		{ID: "headers", Name: "Security headers", Category: scan.CategoryHeaders},
		{ID: "cookies", Name: "Cookie security", Category: scan.CategoryCookies},
	}, report.BuildOptions{Requests: 21})
	c.report.Grade = "A+"
	c.phase = phaseResults
	c.syncViewport()
	emit(t, "RESULTS-CLEAN", c.View())
}

// m2v renders the scanning screen of a model.
func m2v(m model) string { return strings.Join(padTo(m.viewScanning(m.width), m.viewportHeight), "\n") }

// emit prints one screen between markers the dump script can split on.
func emit(t *testing.T, name, view string) {
	t.Helper()
	fmt.Printf("=========== %s ===========\n", name)
	for i, line := range strings.Split(view, "\n") {
		fmt.Printf("%2d|%s\n", i, line)
	}
}
