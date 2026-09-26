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
	timeout     time.Duration
	threads     int
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
	fs.StringVar(&cfg.output, "output", "text", "report format: text or json")
	fs.StringVar(&cfg.outFile, "out", "", "also write the report to this file")
	fs.DurationVar(&cfg.timeout, "t", 10*time.Second, "alias for -timeout")
	fs.DurationVar(&cfg.timeout, "timeout", 10*time.Second, "per-request timeout")
	fs.IntVar(&cfg.threads, "threads", 8, "maximum concurrent HTTP requests")
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

	output := strings.ToLower(strings.TrimSpace(cfg.output))
	if output != "text" && output != "json" {
		fmt.Fprintf(os.Stderr, "error: unknown output format %q (want text or json)\n", cfg.output)
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
			OutFile:     cfg.outFile,
			JSON:        output == "json",
			Autostart:   cfg.target != "",
		})
	}

	target, err := scan.NewTarget(cfg.target, scan.Options{
		Timeout:     cfg.timeout,
		UserAgent:   cfg.userAgent,
		Deep:        cfg.deep,
		Insecure:    cfg.insecure,
		Concurrency: cfg.threads,
	})
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

	jsonMode := output == "json"

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Pre-flight: make sure the target answers at all before spending
	// requests on individual checks, so an offline host fails fast with a
	// clear message instead of a report full of connection errors.
	if _, err := target.Get(ctx, target.URL.String(), false); err != nil {
		fmt.Fprintf(os.Stderr, "error: cannot reach %s: %v\n", target.URL.String(), err)
		return exitError
	}

	if !jsonMode {
		fmt.Fprintf(os.Stderr, "  scanning %s with %d checks (%s)\n",
			target.Base(), len(checks), checkNames(checks))
	}

	started := time.Now()
	engine := &scan.Engine{
		Checks:      checks,
		Concurrency: cfg.threads,
		OnResult: func(res scan.CheckResult) {
			if jsonMode {
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

	rep := report.Build(target.URL.String(), started, results, target.Requests())

	// Render.
	if jsonMode {
		if err := report.WriteJSON(os.Stdout, rep); err != nil {
			fmt.Fprintf(os.Stderr, "error: writing report: %v\n", err)
			return exitError
		}
	} else {
		if err := report.WriteText(os.Stdout, rep, report.TextOptions{
			Color:   color,
			Verbose: cfg.verbose,
			Min:     minSev,
			Width:   terminalWidth(),
			Banner:  !cfg.noBanner,
		}); err != nil {
			fmt.Fprintf(os.Stderr, "error: writing report: %v\n", err)
			return exitError
		}
	}

	if cfg.outFile != "" {
		f, err := os.Create(cfg.outFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: creating %s: %v\n", cfg.outFile, err)
			return exitError
		}
		var werr error
		if jsonMode {
			werr = report.WriteJSON(f, rep)
		} else {
			werr = report.WriteText(f, rep, report.TextOptions{
				Color:   false,
				Verbose: cfg.verbose,
				Min:     minSev,
				Width:   terminalWidth(),
				Banner:  !cfg.noBanner,
			})
		}
		f.Close()
		if werr != nil {
			fmt.Fprintf(os.Stderr, "error: writing %s: %v\n", cfg.outFile, werr)
			return exitError
		}
		if !jsonMode {
			fmt.Fprintf(os.Stdout, "\n  report written to %s\n", cfg.outFile)
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
		`  ijiya -min medium -fail-on high https://example.com`,
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
