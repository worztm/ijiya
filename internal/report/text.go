package report

import (
	"fmt"
	"io"
	"strings"
	"time"

	"ijiya/internal/scan"
	"ijiya/internal/version"
)

// TextOptions controls the human readable renderer.
type TextOptions struct {
	Color   bool
	Verbose bool
	Min     scan.Severity
	Width   int
	Banner  bool
}

// ANSI styling helpers. Every helper returns plain text when colors are off.
const (
	reset = "\x1b[0m"
	dim   = "\x1b[2m"
	bold  = "\x1b[1m"
)

func paint(code, s string, on bool) string {
	if !on || s == "" {
		return s
	}
	return code + s + reset
}

// severityStyle returns the colour code for a severity.
func severityStyle(s scan.Severity) string {
	switch s {
	case scan.SeverityCritical:
		return "\x1b[1;97;41m" // bold white on red
	case scan.SeverityHigh:
		return "\x1b[1;91m" // bold bright red
	case scan.SeverityMedium:
		return "\x1b[1;93m" // bold yellow
	case scan.SeverityLow:
		return "\x1b[1;96m" // bold cyan
	default:
		return "\x1b[90m" // grey
	}
}

// WriteText renders the report for a terminal.
func WriteText(w io.Writer, rep Report, opts TextOptions) error {
	if opts.Width <= 0 {
		opts.Width = 92
	}
	var b strings.Builder

	if opts.Banner {
		b.WriteString(banner(opts.Color))
	}

	fmt.Fprintf(&b, "  %s %s\n", paint(dim, "Target  ", opts.Color), paint(bold, rep.Target, opts.Color))
	fmt.Fprintf(&b, "  %s %s\n", paint(dim, "Started ", opts.Color), rep.StartedAt.Format("2006-01-02 15:04:05 MST"))
	fmt.Fprintf(&b, "  %s %s\n", paint(dim, "Duration", opts.Color), formatDuration(rep.DurationMS))
	fmt.Fprintf(&b, "  %s %d across %d checks\n", paint(dim, "Requests", opts.Color), rep.Requests, len(rep.Checks))
	b.WriteString("  " + rule(opts.Width-2, opts.Color) + "\n")

	shown, hidden := 0, 0

	for _, c := range rep.Checks {
		// Collect the findings that pass the filter.
		var visible []scan.Finding
		for _, f := range c.Findings {
			if f.Severity.AtLeast(opts.Min) {
				visible = append(visible, f)
			} else {
				hidden++
			}
		}

		if len(visible) == 0 {
			if !opts.Verbose {
				continue
			}
			b.WriteString(fmt.Sprintf("\n  %s  %s\n", paint("\x1b[32m", "OK", opts.Color), sectionTitle(c)))
			b.WriteString(fmt.Sprintf("    %s\n", paint(dim, "no issues found", opts.Color)))
			continue
		}
		shown += len(visible)

		// Sort most severe first inside each check.
		for i := 0; i < len(visible); i++ {
			for j := i + 1; j < len(visible); j++ {
				if visible[j].Severity > visible[i].Severity {
					visible[i], visible[j] = visible[j], visible[i]
				}
			}
		}

		b.WriteString("\n  ")
		b.WriteString(paint(bold, c.ID, opts.Color))
		b.WriteString("  ")
		b.WriteString(c.Name)
		b.WriteString("  ")
		b.WriteString(paint(dim, fmt.Sprintf("%s · %d issue(s)", formatDuration(c.DurationMS), len(visible)), opts.Color))
		b.WriteString("\n")

		for _, f := range visible {
			writeFinding(&b, f, opts)
		}
	}

	if c := failedChecks(rep); len(c) > 0 {
		b.WriteString("\n  ")
		b.WriteString(paint(bold, "checks that failed", opts.Color))
		b.WriteString("\n")
		for _, res := range c {
			b.WriteString(fmt.Sprintf("    %s  %s: %s\n",
				paint("\x1b[91m", "ERROR", opts.Color), res.ID, res.Error))
		}
	}

	b.WriteString("  " + rule(opts.Width-2, opts.Color) + "\n")
	writeSummary(&b, rep, opts, shown, hidden)

	_, err := io.WriteString(w, b.String())
	return err
}

// writeFinding renders one finding block.
func writeFinding(b *strings.Builder, f scan.Finding, opts TextOptions) {
	label := fmt.Sprintf("%-8s", f.Severity.Label())
	fmt.Fprintf(b, "    %s  %s\n", paint(severityStyle(f.Severity), label, opts.Color), f.Title)

	indent := strings.Repeat(" ", 14)
	if f.URL != "" {
		wrapInto(b, "url: "+f.URL, opts.Width-14, indent, opts.Color)
	}
	if f.Evidence != "" {
		wrapInto(b, "why: "+f.Evidence, opts.Width-14, indent, opts.Color)
	}
	if f.Remediation != "" {
		wrapInto(b, "fix: "+f.Remediation, opts.Width-14, indent, opts.Color)
	}
}

// wrapInto word-wraps text with a hanging indent, styling the leading
// "url:"/"why:"/"fix:" tag differently from the rest.
func wrapInto(b *strings.Builder, text string, width int, indent string, color bool) {
	if width < 20 {
		width = 20
	}
	lines := wrap(text, width)
	for i, line := range lines {
		b.WriteString(indent)
		if i == 0 {
			if idx := strings.Index(line, ": "); idx > 0 && idx < 6 {
				b.WriteString(paint(dim, line[:idx+2], color))
				b.WriteString(line[idx+2:])
				b.WriteString("\n")
				continue
			}
		}
		b.WriteString(line)
		b.WriteString("\n")
	}
}

// writeSummary prints the severity tally and risk score.
func writeSummary(b *strings.Builder, rep Report, opts TextOptions, shown, hidden int) {
	s := rep.Summary

	if s.Total == 0 {
		fmt.Fprintf(b, "  %s No issues found. Nothing to fix on the tested surface.\n",
			paint("\x1b[1;32m", "PASS", opts.Color))
		return
	}

	b.WriteString("  " + paint(bold, "SUMMARY", opts.Color) + "\n")
	rows := []struct {
		label string
		count int
		style string
	}{
		{"critical", s.Critical, severityStyle(scan.SeverityCritical)},
		{"high", s.High, severityStyle(scan.SeverityHigh)},
		{"medium", s.Medium, severityStyle(scan.SeverityMedium)},
		{"low", s.Low, severityStyle(scan.SeverityLow)},
		{"info", s.Info, severityStyle(scan.SeverityInfo)},
	}
	for _, r := range rows {
		if r.count == 0 && !opts.Verbose {
			continue
		}
		fmt.Fprintf(b, "    %-10s %s\n", r.label, paint(r.style, fmt.Sprintf("%d", r.count), opts.Color))
	}
	if s.Errors > 0 {
		fmt.Fprintf(b, "    %-10s %s\n", "errors", paint("\x1b[1;91m", fmt.Sprintf("%d", s.Errors), opts.Color))
	}

	b.WriteString("    " + paint(dim, strings.Repeat("─", 18), opts.Color) + "\n")
	gradeColor := "\x1b[1;32m"
	if rep.RiskScore > 25 {
		gradeColor = "\x1b[1;93m"
	}
	if rep.RiskScore > 65 {
		gradeColor = "\x1b[1;91m"
	}
	fmt.Fprintf(b, "    %-10s %d issue(s)   risk %d/100   grade %s\n",
		"total", s.Total, rep.RiskScore,
		paint(gradeColor, rep.Grade, opts.Color))

	if hidden > 0 {
		fmt.Fprintf(b, "    %s\n", paint(dim, fmt.Sprintf("(%d finding(s) hidden by the severity filter)", hidden), opts.Color))
	}
}

// failedChecks lists checks that errored rather than reporting findings.
func failedChecks(rep Report) []scan.CheckResult {
	var out []scan.CheckResult
	for _, c := range rep.Checks {
		if c.Failed() {
			out = append(out, c)
		}
	}
	return out
}

// sectionTitle builds the "id  Name" header used in verbose mode.
func sectionTitle(c scan.CheckResult) string {
	return c.ID + "  " + c.Name
}

// formatDuration renders milliseconds as a friendly duration.
func formatDuration(ms int64) string {
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

// rule draws a horizontal line of the requested width.
func rule(width int, color bool) string {
	if width < 10 {
		width = 10
	}
	return paint(dim, strings.Repeat("─", width), color)
}

// wrap splits text into lines no wider than width, honouring existing
// newlines so evidence that already has structure keeps it.
func wrap(text string, width int) []string {
	var out []string
	for _, para := range strings.Split(text, "\n") {
		words := strings.Fields(para)
		if len(words) == 0 {
			out = append(out, "")
			continue
		}
		line := ""
		for _, w := range words {
			switch {
			case line == "":
				line = w
			case len(line)+1+len(w) > width:
				out = append(out, line)
				line = w
			default:
				line += " " + w
			}
		}
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}

// banner returns the ASCII art header.
func banner(color bool) string {
	rows := []string{
		"█████  █████ █████  ██   ██   ███ ",
		"  ██     ██    ██  ██   ██ ██  ██ ",
		"  ██     ██    ██    ███   █████  ",
		"  ██     ██    ██     ██   ██  ██ ",
		"█████   ███   █████    ██   ██  ██ ",
	}
	style := "\x1b[1;96m"
	var b strings.Builder
	b.WriteString("\n")
	for _, r := range rows {
		b.WriteString("  ")
		b.WriteString(paint(style, r, color))
		b.WriteString("\n")
	}
	b.WriteString("  ")
	b.WriteString(paint(dim, "lightweight web vulnerability scanner", color))
	b.WriteString("  ")
	b.WriteString(paint(style, "v"+version.Version, color))
	b.WriteString("\n")
	b.WriteString("  ")
	b.WriteString(paint(dim, version.Notice, color))
	b.WriteString("\n\n")
	return b.String()
}
