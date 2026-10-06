// Package cli parses arguments and drives a scan end to end.
package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"ijiya/internal/report"
	"ijiya/internal/scan"
	"ijiya/internal/tui"
	"ijiya/internal/version"
)

// Exit codes. They are documented in --help so scripts can rely on them.
const (
	exitOK       = 0 // nothing at or above -fail-on
	exitFindings = 1 // findings at or above -fail-on
	exitUsage    = 2 // bad arguments
	exitError    = 3 // the scan itself could not run
)

type config struct {
	target      string
	checks      string
	output      string
	outFile     string
	outFormat   string
	baseline    string
	timeout     time.Duration
	threads     int
	rate        float64
	deep        bool
	verbose     bool
	noColor     bool
	noBanner    bool
	insecure    bool
	userAgent   string
	minSeverity string
	failOn      string
	list        bool
	showVersion bool
	tui         bool
	headers     headerFlags
}

// headerFlags collects every -H occurrence. flag.Value is used rather than a
// single string because a scan of an authenticated area usually needs both a
// session cookie and an API key.
type headerFlags []string

func (h *headerFlags) String() string { return strings.Join(*h, ", ") }

func (h *headerFlags) Set(v string) error {
	*h = append(*h, v)
	return nil
}

// Run executes the CLI and returns a process exit code.
func Run(args []string) int {
	cfg := config{}
	fs := flag.NewFlagSet(version.Name, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() { printUsage(fs) }

	fs.StringVar(&cfg.checks, "c", "all", "alias for -checks")
	fs.StringVar(&cfg.checks, "checks", "all", "comma-separated checks to run (\"all\" for everything)")
	fs.StringVar(&cfg.output, "o", "text", "alias for -output")
	fs.StringVar(&cfg.output, "output", "text", "report format: text, json, sarif or markdown")
	fs.StringVar(&cfg.outFile, "out", "", "also write the report to this file (format follows the extension)")
	fs.StringVar(&cfg.outFormat, "out-format", "", "format for -out: text, json, sarif or markdown (default: from the file extension)")
	fs.StringVar(&cfg.baseline, "baseline", "", "JSON report of known findings to suppress, so CI only fails on new ones")
	fs.Var(&cfg.headers, "H", "extra request header as \"Name: value\" (repeatable; use for auth cookies and tokens)")
	fs.DurationVar(&cfg.timeout, "t", 10*time.Second, "alias for -timeout")
	fs.DurationVar(&cfg.timeout, "timeout", 10*time.Second, "per-request timeout")
	fs.IntVar(&cfg.threads, "threads", 8, "maximum concurrent HTTP requests")
	fs.Float64Var(&cfg.rate, "rate", 0, "cap outbound requests per second (0 = unthrottled)")
	fs.BoolVar(&cfg.deep, "deep", false, "enable slower probes (boolean/time-based SQLi, POST forms)")
	fs.BoolVar(&cfg.verbose, "v", false, "alias for -verbose")
	fs.BoolVar(&cfg.verbose, "verbose", false, "show checks that passed and informational findings")
	fs.BoolVar(&cfg.noColor, "nc", false, "alias for -no-color")
	fs.BoolVar(&cfg.noColor, "no-color", false, "disable ANSI colours")
	fs.BoolVar(&cfg.noBanner, "nb", false, "alias for -no-banner")
	fs.BoolVar(&cfg.noBanner, "no-banner", false, "hide the startup banner")
	fs.BoolVar(&cfg.insecure, "k", false, "alias for -insecure")
	fs.BoolVar(&cfg.insecure, "insecure", false, "skip TLS certificate verification")
	fs.StringVar(&cfg.userAgent, "ua", "", "alias for -user-agent")
	fs.StringVar(&cfg.userAgent, "user-agent", "", "User-Agent header to send")
	fs.StringVar(&cfg.minSeverity, "min", "info", "hide findings below this severity (info|low|medium|high|critical)")
	fs.StringVar(&cfg.failOn, "fail-on", "medium", "exit 1 when a finding reaches this severity")
	fs.BoolVar(&cfg.list, "list", false, "list the available checks and exit")
	fs.BoolVar(&cfg.showVersion, "version", false, "print the version and exit")
	fs.BoolVar(&cfg.tui, "tui", false, "force the interactive interface (auto-scans when a URL is given)")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}

	if cfg.showVersion {
		fmt.Printf("%s %s\n", version.Name, version.Version)
		return exitOK
	}
	if cfg.list {
		printChecks()
		return exitOK
	}

	rest := fs.Args()
	if len(rest) > 1 {
		fmt.Fprintf(os.Stderr, "error: expected a single URL, got %d arguments\n", len(rest))
		return exitUsage
	}
	if len(rest) == 1 {
		cfg.target = rest[0]
	}

	format, err := report.ParseFormat(cfg.output)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return exitUsage
	}
	// The file format defaults to the one selected for stdout, then to the
	// -out extension when that says something more specific.
	fileFormat := format
	if cfg.outFormat != "" {
		fileFormat, err = report.ParseFormat(cfg.outFormat)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: -out-format: %v\n", err)
			return exitUsage
		}
	} else {
		fileFormat = report.FormatForFile(cfg.outFile, format)
	}

	headers, err := scan.ParseHeaders(cfg.headers)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: -H: %v\n", err)
		return exitUsage
	}

	minSev, err := scan.ParseSeverity(cfg.minSeverity)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return exitUsage
	}
	failOn, err := scan.ParseSeverity(cfg.failOn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: -fail-on: %v\n", err)
		return exitUsage
	}
	if cfg.threads < 1 {
		cfg.threads = 1
	}
	if cfg.rate < 0 {
		fmt.Fprintln(os.Stderr, "error: -rate cannot be negative")
		return exitUsage
	}
	if cfg.rate > 0 && cfg.rate < 0.01 {
		fmt.Fprintln(os.Stderr, "error: -rate must be at least 0.01 requests per second")
		return exitUsage
	}

	// Interactive mode: explicitly requested with -tui, or implied when no
	// URL was supplied and there is a terminal to draw on. Argument-less
	// use in a pipe still prints usage rather than hanging on a program
	// nobody can see or type into.
	if cfg.tui || cfg.target == "" {
		if !isTerminal(os.Stdout) {
			if cfg.target == "" {
				fmt.Fprintln(os.Stderr, "error: no target URL given")
				fmt.Fprintln(os.Stderr)
				fs.Usage()
				return exitUsage
			}
			fmt.Fprintln(os.Stderr, "error: -tui needs an interactive terminal; drop -tui to print the report instead")
			return exitUsage
		}
		return tui.Run(tui.Options{
			Target:      cfg.target,
			Timeout:     cfg.timeout,
			UserAgent:   cfg.userAgent,
			Deep:        cfg.deep,
			Insecure:    cfg.insecure,
			Threads:     cfg.threads,
			MinSeverity: minSev,
			FailOn:      failOn,
			Headers:     headers,
			RateLimit:   cfg.rate,
			OutFile:     cfg.outFile,
			JSON:        format == report.FormatJSON,
			Autostart:   cfg.target != "",
		})
	}

	target, err := scan.NewTarget(cfg.target, scan.Options{
		Timeout:     cfg.timeout,
		UserAgent:   cfg.userAgent,
		Deep:        cfg.deep,
		Insecure:    cfg.insecure,
		Concurrency: cfg.threads,
		Headers:     headers,
		RateLimit:   cfg.rate,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return exitUsage
	}

	// Load the baseline before scanning: a broken baseline file should stop
	// the run rather than silently produce a report with no suppression.
	baseline, err := report.LoadBaseline(cfg.baseline)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return exitUsage
	}

	checks, err := scan.Select(cfg.checks)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return exitUsage
	}

	color := wantColor(cfg)
	if color {
		report.EnableANSI()
	}

	// Machine readable formats are consumed by tools, so progress chatter
	// on stderr would only be noise in a CI log.
	quiet := format != report.FormatText

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Pre-flight: make sure the target answers at all before spending
	// requests on individual checks, so an offline host fails fast with a
	// clear message instead of a report full of connection errors.
	if _, err := target.Get(ctx, target.URL.String(), false); err != nil {
		fmt.Fprintf(os.Stderr, "error: cannot reach %s: %v\n", target.URL.String(), err)
		return exitError
	}

	if !quiet {
		fmt.Fprintf(os.Stderr, "  scanning %s with %d checks (%s)\n",
			target.Base(), len(checks), checkNames(checks))
		if len(headers) > 0 || cfg.rate > 0 {
			fmt.Fprintf(os.Stderr, "  %s\n", sessionSummary(headers, cfg.rate))
		}
		if !baseline.Empty() {
			fmt.Fprintf(os.Stderr, "  suppressing %d known finding(s) from %s\n",
				baseline.Len(), cfg.baseline)
		}
	}

	started := time.Now()
	engine := &scan.Engine{
		Checks:      checks,
		Concurrency: cfg.threads,
		OnResult: func(res scan.CheckResult) {
			if quiet {
				return
			}
			switch {
			case res.Failed():
				fmt.Fprintf(os.Stderr, "  \x1b[91merror\x1b[0m  %-12s %s\n", res.ID, res.Error)
			default:
				fmt.Fprintf(os.Stderr, "  done  %-12s %-24s %d issue(s)\n",
					res.ID, res.Name, len(res.Findings))
			}
		},
	}
	results := engine.Run(ctx, target)

	rep := report.Build(target.URL.String(), started, results, report.BuildOptions{
		Requests: target.Requests(),
		Banner:   !cfg.noBanner,
		Baseline: baseline,
	})

	// Render.
	textOpts := report.TextOptions{
		Color:   color,
		Verbose: cfg.verbose,
		Min:     minSev,
		Width:   terminalWidth(),
	}
	if err := report.Write(os.Stdout, rep, format, textOpts); err != nil {
		fmt.Fprintf(os.Stderr, "error: writing report: %v\n", err)
		return exitError
	}

	if cfg.outFile != "" {
		// A file is read later or by someone else, so it never carries
		// terminal colour codes.
		fileOpts := textOpts
		fileOpts.Color = false
		if err := writeReportFile(cfg.outFile, rep, fileFormat, fileOpts); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			return exitError
		}
		if format == report.FormatText {
			fmt.Fprintf(os.Stdout, "\n  report written to %s (%s)\n", cfg.outFile, fileFormat)
		}
	}

	// Decide the exit code.
	if allFailed(results) {
		fmt.Fprintln(os.Stderr, "error: every check failed to run; see the messages above")
		return exitError
	}
	if max, found := rep.MaxSeverity(); found && max >= failOn {
		return exitFindings
	}
	return exitOK
}

// writeReportFile renders rep into name, creating it with the usual
// permissions for a report.
func writeReportFile(name string, rep report.Report, format report.Format, opts report.TextOptions) error {
	f, err := os.Create(name)
	if err != nil {
		return fmt.Errorf("creating %s: %w", name, err)
	}
	defer func() { _ = f.Close() }()
	if err := report.Write(f, rep, format, opts); err != nil {
		return fmt.Errorf("writing %s: %w", name, err)
	}
	return nil
}

// sessionSummary describes the request headers and throttle in use, naming the
// headers without repeating their values so a token never reaches a terminal
// log or a CI transcript.
func sessionSummary(headers []scan.Header, rate float64) string {
	var parts []string
	if len(headers) > 0 {
		parts = append(parts, "sending "+strings.Join(scan.SortedHeaderNames(headers), ", "))
	}
	if rate > 0 {
		parts = append(parts, fmt.Sprintf("throttled to %g request(s)/s", rate))
	}
	return strings.Join(parts, "; ")
}

// isTerminal reports whether f is attached to a character device, i.e. a
// real console rather than a pipe or a file.
func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

// wantColor decides whether ANSI output is appropriate.
func wantColor(cfg config) bool {
	if cfg.noColor || os.Getenv("NO_COLOR") != "" {
		return false
	}
	if os.Getenv("FORCE_COLOR") != "" {
		return true
	}
	return isTerminal(os.Stdout)
}

// terminalWidth reads COLUMNS when present, otherwise returns a sensible
// default that fits most windows.
func terminalWidth() int {
	if v := os.Getenv("COLUMNS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 40 {
			return n
		}
	}
	return 92
}

// allFailed reports whether no check managed to complete.
func allFailed(results []scan.CheckResult) bool {
	if len(results) == 0 {
		return true
	}
	for _, r := range results {
		if !r.Failed() {
			return false
		}
	}
	return true
}

// checkNames renders the selected check IDs for the startup line.
func checkNames(checks []scan.Check) string {
	ids := make([]string, 0, len(checks))
	for _, c := range checks {
		ids = append(ids, c.ID())
	}
	return strings.Join(ids, ", ")
}

// printChecks writes the -list output.
func printChecks() {
	fmt.Printf("%s %s available checks:\n\n", version.Name, version.Version)
	for _, c := range scan.Available() {
		fmt.Printf("  %-12s %-24s %s\n", c.ID(), c.Name(), c.Category())
	}
	fmt.Printf("\nUse them with -checks, e.g. -checks headers,xss\n")
	fmt.Printf("Output formats: %s\n", strings.Join(report.Formats(), ", "))
}

// printUsage writes the full help text.
func printUsage(fs *flag.FlagSet) {
	w := fs.Output()
	fmt.Fprintf(w, "%s %s - %s\n\n", version.Name, version.Version, version.Description)
	fmt.Fprintf(w, "USAGE\n  %s [flags] <url>\n\n", version.Name)

	fmt.Fprintf(w, "DESCRIPTION\n")
	for _, line := range []string{
		"  ijiya probes a web application for the loopholes that most often",
		"  lead to compromise, and tells you how to close each one:",
		"",
		"    headers     missing or weak HSTS, CSP, clickjacking and friends",
		"    cookies     Secure / HttpOnly / SameSite flags",
		"    tls         HTTPS enforcement, certificate expiry, weak keys",
		"    cors        origin reflection and credentialed cross-origin reads",
		"    xss         reflected cross-site scripting in query and form input",
		"    sqli        error-based SQL injection (+ boolean/time with -deep)",
		"    disclosure  server banners, .git/.env leaks, directory listing",
		"    redirect    open redirect parameters",
		"",
		"  " + version.Notice,
		"",
	} {
		fmt.Fprintln(w, line)
	}

	fmt.Fprintf(w, "FLAGS\n")
	fs.SetOutput(w)
	fs.PrintDefaults()

	fmt.Fprintf(w, "\nEXAMPLES\n")
	for _, ex := range []string{
		`  ijiya https://example.com`,
		`  ijiya -checks headers,cookies,tls https://example.com`,
		`  ijiya -deep -o json -out report.json https://app.example.com`,
		`  ijiya -H "Cookie: session=..." -H "X-API-Key: ..." https://app.example.com`,
		`  ijiya -rate 5 -min medium -fail-on high https://example.com`,
		`  ijiya -baseline ijiya.json -o sarif -out results.sarif https://app.example.com`,
		`  ijiya -k -threads 4 http://localhost:8080`,
	} {
		fmt.Fprintln(w, ex)
	}

	fmt.Fprintf(w, "\nEXIT CODES\n")
	fmt.Fprintf(w, "  0  clean (no finding at or above -fail-on)\n")
	fmt.Fprintf(w, "  1  findings at or above -fail-on\n")
	fmt.Fprintf(w, "  2  invalid usage\n")
	fmt.Fprintf(w, "  3  the scan could not run\n")
}
