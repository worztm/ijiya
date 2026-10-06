package tui

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"

	"ijiya/internal/report"
	"ijiya/internal/scan"
	"ijiya/internal/version"
)

// phase is which screen the user is looking at.
type phase int

const (
	phaseInput    phase = iota // enter a URL and pick checks
	phaseScanning              // watching a live scan
	phaseResults               // browsing the finished report
)

// Focus targets on the input screen.
const (
	focusURL = iota
	focusChecks
)

// checkRow is one selectable check on the input screen.
type checkRow struct {
	id       string
	name     string
	selected bool
}

// model is the whole TUI state. It follows the bubbletea convention of
// being copied on every update, so anything that must persist across
// updates is returned from Update alongside the next command.
type model struct {
	opts           Options
	phase          phase
	focus          int
	width          int
	viewportHeight int

	// input screen
	url      textinput.Model
	rows     []checkRow
	cursor   int
	deep     bool
	inputErr string

	// scanning screen
	spinner  spinner.Model
	pump     chan tea.Msg
	cancel   context.CancelFunc
	target   *scan.Target
	started  time.Time
	running  map[string]bool
	results  map[string]scan.CheckResult
	feed     []scan.Finding
	feedKeys map[string]bool

	// results screen
	report   report.Report
	viewport viewport.Model
	ready    bool
	toast    string
	saved    string
}

// newModel builds the initial state.
func newModel(opts Options) model {
	url := textinput.New()
	url.Placeholder = "https://example.com"
	url.Prompt = "> "
	url.CharLimit = 2048
	url.Width = 64
	url.Focus()
	if opts.Target != "" {
		url.SetValue(opts.Target)
	}

	rows := make([]checkRow, 0, 8)
	for _, c := range scan.Available() {
		rows = append(rows, checkRow{id: c.ID(), name: c.Name(), selected: true})
	}

	return model{
		opts:     opts,
		phase:    phaseInput,
		focus:    focusURL,
		width:    80,
		url:      url,
		rows:     rows,
		deep:     opts.Deep,
		spinner:  spinner.New(spinner.WithSpinner(spinner.Dot)),
		running:  map[string]bool{},
		results:  map[string]scan.CheckResult{},
		feedKeys: map[string]bool{},
	}
}

// Init is called once when the program starts.
func (m model) Init() tea.Cmd {
	if m.opts.Autostart && strings.TrimSpace(m.url.Value()) != "" {
		return func() tea.Msg { return autostartMsg{} }
	}
	return textinput.Blink
}

// Update handles one message. It is the only place state changes.
func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.viewportHeight = msg.Height
		m.syncViewport()
		return m, nil

	case autostartMsg:
		return m.startScan()

	case spinner.TickMsg:
		s, cmd := m.spinner.Update(msg)
		m.spinner = s
		if m.phase == phaseScanning {
			return m, cmd
		}
		return m, nil

	case checkStartedMsg:
		m.ensure()
		m.running[msg.id] = true
		return m, m.next()

	case findingMsg:
		m.addFeed(msg.f)
		return m, m.next()

	case checkDoneMsg:
		m.ensure()
		m.running[msg.res.ID] = false
		m.results[msg.res.ID] = msg.res
		for _, f := range msg.res.Findings {
			m.addFeed(f)
		}
		return m, m.next()

	case scanDoneMsg:
		m.report = msg.rep
		m.phase = phaseResults
		m.cancel = nil
		m.syncViewport()
		m.viewport.GotoTop()
		return m, m.next()

	case scanFinishedMsg:
		return m, nil

	case clearToastMsg:
		m.toast = ""
		return m, nil

	case saveDoneMsg:
		if msg.err != nil {
			m.toast = "save failed: " + msg.err.Error()
		} else {
			m.toast = "report written to " + msg.path
			m.saved = msg.path
		}
		return m, clearToastAfter(4 * time.Second)

	case tea.KeyMsg:
		return m.handleKey(msg)
	}
	return m, nil
}

// handleKey dispatches a key press to the active screen.
func (m model) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	key := msg.String()

	if key == "ctrl+c" {
		m.stopScan()
		return m, tea.Quit
	}

	switch m.phase {
	case phaseInput:
		return m.inputKey(key, msg)
	case phaseScanning:
		return m.scanningKey(key)
	case phaseResults:
		return m.resultsKey(key)
	}
	return m, nil
}

// inputKey drives the URL field and the check list.
func (m model) inputKey(key string, msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if m.focus == focusURL {
		switch key {
		case "tab", "shift+tab":
			m.focus = focusChecks
			m.url.Blur()
			return m, nil
		case "esc":
			m.focus = focusChecks
			m.url.Blur()
			return m, nil
		case "enter":
			return m.startScan()
		default:
			var cmd tea.Cmd
			m.url, cmd = m.url.Update(msg)
			return m, cmd
		}
	}

	switch key {
	case "tab", "shift+tab":
		m.focus = focusURL
		return m, m.url.Focus()
	case "enter":
		return m.startScan()
	case "up", "k":
		if m.cursor > 0 {
			m.cursor--
		}
	case "down", "j":
		if m.cursor < len(m.rows)-1 {
			m.cursor++
		}
	case " ":
		if len(m.rows) > 0 {
			m.rows[m.cursor].selected = !m.rows[m.cursor].selected
		}
	case "a":
		allOn := true
		for _, r := range m.rows {
			if !r.selected {
				allOn = false
				break
			}
		}
		for i := range m.rows {
			m.rows[i].selected = !allOn
		}
	case "d":
		m.deep = !m.deep
	case "esc":
		return m, tea.Quit
	}
	return m, nil
}

// scanningKey lets the user abandon a run in progress.
func (m model) scanningKey(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "q", "esc":
		m.stopScan()
		m.phase = phaseInput
		m.focus = focusURL
		m.url.Focus()
		m.toast = "scan cancelled"
		return m, clearToastAfter(3 * time.Second)
	}
	return m, nil
}

// resultsKey scrolls the report and offers save/rescan.
func (m model) resultsKey(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "q":
		return m, tea.Quit
	case "esc", "r":
		m.phase = phaseInput
		m.focus = focusURL
		m.url.Focus()
		return m, textinput.Blink
	case "up", "k":
		m.viewport.SetYOffset(m.viewport.YOffset - 1)
	case "down", "j":
		m.viewport.SetYOffset(m.viewport.YOffset + 1)
	case "pgup", "b":
		m.viewport.SetYOffset(m.viewport.YOffset - m.viewport.Height)
	case "pgdn", "f", " ":
		m.viewport.SetYOffset(m.viewport.YOffset + m.viewport.Height)
	case "home", "g":
		m.viewport.GotoTop()
	case "end", "G":
		m.viewport.GotoBottom()
	case "s":
		return m, m.saveReport()
	}
	return m, nil
}

// startScan validates the form and launches a background scan.
func (m model) startScan() (model, tea.Cmd) {
	raw := strings.TrimSpace(m.url.Value())
	if raw == "" {
		m.inputErr = "enter a URL to scan"
		m.focus = focusURL
		m.url.Focus()
		return m, textinput.Blink
	}

	selected := selectedIDs(m.rows)
	if len(selected) == 0 {
		m.inputErr = "select at least one check"
		return m, nil
	}
	checks, err := scan.Select(strings.Join(selected, ","))
	if err != nil {
		m.inputErr = err.Error()
		return m, nil
	}
	target, err := scan.NewTarget(raw, scan.Options{
		Timeout:     m.opts.Timeout,
		UserAgent:   m.opts.UserAgent,
		Deep:        m.deep,
		Insecure:    m.opts.Insecure,
		Concurrency: m.opts.Threads,
		Headers:     m.opts.Headers,
		RateLimit:   m.opts.RateLimit,
	})
	if err != nil {
		m.inputErr = err.Error()
		m.focus = focusURL
		m.url.Focus()
		return m, textinput.Blink
	}

	m.inputErr = ""
	m.ensure()
	for id := range m.running {
		delete(m.running, id)
	}
	for id := range m.results {
		delete(m.results, id)
	}
	m.feed = nil
	for k := range m.feedKeys {
		delete(m.feedKeys, k)
	}
	m.toast = ""
	m.saved = ""

	ctx, cancel := context.WithCancel(context.Background())
	ch := make(chan tea.Msg, 64)

	m.cancel = cancel
	m.pump = ch
	m.target = target
	m.started = time.Now()
	m.phase = phaseScanning

	go m.runScan(ctx, ch, target, checks)

	return m, tea.Batch(waitFor(ch), m.spinner.Tick)
}

// runScan executes the engine in the background and streams its progress
// back to the update loop over ch.
func (m model) runScan(ctx context.Context, ch chan tea.Msg, target *scan.Target, checks []scan.Check) {
	defer close(ch)

	// Blocking on a cancelled context would leak this goroutine when the
	// user aborts, so every send gives up as soon as the scan is stopped.
	send := func(msg tea.Msg) bool {
		select {
		case ch <- msg:
			return true
		case <-ctx.Done():
			return false
		}
	}

	engine := &scan.Engine{
		Checks:      checks,
		Concurrency: m.opts.Threads,
		OnCheckStart: func(id string) {
			send(checkStartedMsg{id: id})
		},
		OnFinding: func(id string, f scan.Finding) {
			send(findingMsg{id: id, f: f})
		},
		OnResult: func(res scan.CheckResult) {
			send(checkDoneMsg{res: res})
		},
	}

	results := engine.Run(ctx, target)
	if ctx.Err() != nil {
		return
	}
	send(scanDoneMsg{rep: report.Build(target.URL.String(), m.started, results, report.BuildOptions{
		Requests: target.Requests(),
		// The TUI draws its own header, so the text report does not repeat
		// the ASCII banner inside the viewport.
		Banner: false,
	})})
}

// stopScan cancels a scan that is still running.
func (m *model) stopScan() {
	if m.cancel != nil {
		m.cancel()
		m.cancel = nil
	}
}

// saveReport writes the current report to disk.
func (m model) saveReport() tea.Cmd {
	path := m.opts.OutFile
	if path == "" {
		if m.opts.JSON {
			path = "ijiya-report.json"
		} else {
			path = "ijiya-report.txt"
		}
	}
	// Snapshot the pieces the closure needs so it does not reference the
	// model after Update has returned.
	rep := m.report
	asJSON := m.opts.JSON
	min := m.opts.MinSeverity

	return func() tea.Msg {
		f, err := os.Create(path)
		if err != nil {
			return saveDoneMsg{path: path, err: err}
		}
		defer func() { _ = f.Close() }()
		if asJSON {
			err = report.WriteJSON(f, rep)
		} else {
			saved := rep
			saved.Banner = true
			err = report.WriteText(f, saved, report.TextOptions{
				Verbose: false,
				Min:     min,
				Width:   100,
			})
		}
		return saveDoneMsg{path: path, err: err}
	}
}

// next returns the command that awaits the following scan message.
func (m model) next() tea.Cmd {
	if m.pump == nil {
		return nil
	}
	return waitFor(m.pump)
}

// ensure lazily initialises the maps so partially constructed models (in
// tests, for example) never panic on assignment.
func (m *model) ensure() {
	if m.running == nil {
		m.running = map[string]bool{}
	}
	if m.results == nil {
		m.results = map[string]scan.CheckResult{}
	}
	if m.feedKeys == nil {
		m.feedKeys = map[string]bool{}
	}
}

// addFeed appends a finding to the live feed, ignoring repeats so a
// finding emitted by a check is not shown again when that check finishes.
func (m *model) addFeed(f scan.Finding) {
	m.ensure()
	key := fmt.Sprintf("%s\x00%s\x00%s\x00%s", f.CheckID, f.Severity, f.Title, f.URL)
	if m.feedKeys[key] {
		return
	}
	m.feedKeys[key] = true
	m.feed = append(m.feed, f)
}

// syncViewport resizes the report viewport and re-wraps its content.
func (m *model) syncViewport() {
	vpWidth := m.width - 2
	if vpWidth < 20 {
		vpWidth = 20
	}
	vpHeight := m.viewportHeight - headerLines - footerLines
	if vpHeight < 3 {
		vpHeight = 3
	}

	if !m.ready {
		m.viewport = viewport.New(vpWidth, vpHeight)
		m.ready = true
	} else {
		m.viewport.Width = vpWidth
		m.viewport.Height = vpHeight
	}
	m.viewport.SetContent(reportFor(m.report, vpWidth, m.opts.MinSeverity))
}

// exitCode translates the finished report into the CLI's contract.
func (m model) exitCode() int {
	if len(m.report.Checks) == 0 {
		return exitOK
	}
	max, found := m.report.MaxSeverity()
	if found && max >= m.opts.FailOn {
		return exitFindings
	}
	return exitOK
}

// selectedIDs lists the ticks of the check list in display order.
func selectedIDs(rows []checkRow) []string {
	ids := make([]string, 0, len(rows))
	for _, r := range rows {
		if r.selected {
			ids = append(ids, r.id)
		}
	}
	return ids
}

// headerLines and footerLines are reserved for the fixed chrome around the
// report viewport: banner, notice, target, blank, summary, blank.
const (
	headerLines = 6
	footerLines = 2
)

// banner renders the header shared by every screen.
func bannerLine() string {
	return fmt.Sprintf("%s %s · %s", version.Name, version.Version, version.Description)
}
