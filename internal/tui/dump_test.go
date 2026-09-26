package tui

import (
	"fmt"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"ijiya/internal/scan"
)

// defaultTimeout is used by the screen dump when building a target.
const defaultTimeout = 3 * time.Second

// TestDumpScreens is a development aid: run with
//
//	go test ./internal/tui -run TestDumpScreens -v
//
// to print the three screens so the layout can be eyeballed.
func TestDumpScreens(t *testing.T) {
	m := newModel(testOptions())
	m = upd(m, tea.WindowSizeMsg{Width: 100, Height: 42})
	m.url.SetValue("https://shop.example.com")

	fmt.Println("=========== INPUT ===========")
	dump(m.View())

	// Scanning screen: fake some progress so the layout is representative.
	// Nothing is launched here, so the dump never touches the network.
	m.phase = phaseScanning
	if tgt, err := scan.NewTarget("https://shop.example.com", scan.Options{Timeout: defaultTimeout, Concurrency: 4}); err == nil {
		m.target = tgt
	}
	m.running = map[string]bool{"sqli": true, "xss": true}
	m.results = map[string]scan.CheckResult{
		"headers": {ID: "headers", Name: "Security headers", Findings: make([]scan.Finding, 6)},
		"cookies": {ID: "cookies", Name: "Cookie security", Findings: make([]scan.Finding, 3)},
		"tls":     {ID: "tls", Name: "TLS and HTTPS"},
		"cors":    {ID: "cors", Name: "CORS configuration"},
	}
	for i := 0; i < 4; i++ {
		m.addFeed(scan.Finding{
			CheckID:  "headers",
			Severity: scan.Severity(i % 3),
			Title:    fmt.Sprintf("example finding %d for the live feed", i),
			URL:      "https://shop.example.com/",
		})
	}
	fmt.Println("=========== SCANNING ===========")
	dump(m.viewScanningPadded())

	// Results screen from a real report.
	m.phase = phaseResults
	m.report = sampleReport()
	m.syncViewport()
	fmt.Println("=========== RESULTS ===========")
	dump(m.View())
}

func dump(view string) {
	for i, line := range strings.Split(view, "\n") {
		fmt.Printf("%2d|%s\n", i, line)
	}
}

// viewScanningPadded renders the scanning screen at the current size.
func (m model) viewScanningPadded() string {
	return strings.Join(padTo(m.viewScanning(), 42), "\n")
}
