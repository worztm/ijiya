// Package tui implements the interactive terminal interface: type a URL,
// watch the scan run, and browse findings as they are discovered.
package tui

import (
	"fmt"
	"os"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"ijiya/internal/report"
	"ijiya/internal/scan"
)

// Options carries the CLI flags that configure an interactive scan.
type Options struct {
	// Target, when set, pre-fills the URL field. Combined with Autostart
	// it begins scanning immediately.
	Target      string
	Timeout     time.Duration
	UserAgent   string
	Deep        bool
	Insecure    bool
	Threads     int
	MinSeverity scan.Severity
	FailOn      scan.Severity
	// OutFile, when set, is the default destination for the save action.
	OutFile string
	// JSON saves the report as JSON rather than text.
	JSON bool
	// Autostart begins scanning as soon as the TUI opens.
	Autostart bool
}

// Exit codes, mirrored from the CLI so the shell sees the same contract.
const (
	exitOK       = 0
	exitFindings = 1
	exitError    = 3
)

// Run starts the interactive program and returns a process exit code.
func Run(opts Options) int {
	program := tea.NewProgram(newModel(opts), tea.WithAltScreen())
	final, err := program.Run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return exitError
	}
	m, ok := final.(model)
	if !ok {
		return exitOK
	}
	return m.exitCode()
}

// Messages delivered from the scan goroutine to the update loop.
type (
	// autostartMsg kicks off a scan that was requested before the program
	// was fully running.
	autostartMsg struct{}

	// checkStartedMsg reports that a check has begun.
	checkStartedMsg struct{ id string }

	// findingMsg streams a single finding the moment it is discovered.
	findingMsg struct {
		id string
		f  scan.Finding
	}

	// checkDoneMsg reports a finished check with its full result.
	checkDoneMsg struct{ res scan.CheckResult }

	// scanDoneMsg carries the finished report.
	scanDoneMsg struct{ rep report.Report }

	// scanFinishedMsg means the scan channel was closed.
	scanFinishedMsg struct{}

	// clearToastMsg hides a transient status message.
	clearToastMsg struct{}

	// saveDoneMsg reports the outcome of writing a report to disk.
	saveDoneMsg struct {
		path string
		err  error
	}
)

// waitFor blocks until the next message arrives on the scan channel, which
// is how the UI keeps a live view of a scan running in the background.
func waitFor(ch <-chan tea.Msg) tea.Cmd {
	return func() tea.Msg {
		msg, ok := <-ch
		if !ok {
			return scanFinishedMsg{}
		}
		return msg
	}
}

// clearToastAfter hides a toast once it has been on screen long enough to
// be read.
func clearToastAfter(d time.Duration) tea.Cmd {
	return tea.Tick(d, func(time.Time) tea.Msg { return clearToastMsg{} })
}

// reportFor renders a report into a string suitable for the viewport.
func reportFor(rep report.Report, width int, min scan.Severity) string {
	if width < 40 {
		width = 40
	}
	return renderReport(rep, width, min)
}
