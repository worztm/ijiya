package report

import (
	"fmt"
	"io"
	"path/filepath"
	"strings"
)

// Format identifies a report renderer.
type Format string

const (
	// FormatText is the human readable terminal report.
	FormatText Format = "text"
	// FormatJSON is the machine readable report used by CI and as a baseline.
	FormatJSON Format = "json"
	// FormatSARIF is the static analysis format GitHub code scanning ingests.
	FormatSARIF Format = "sarif"
	// FormatMarkdown is a pull-request friendly summary.
	FormatMarkdown Format = "markdown"
)

// Formats lists every accepted -output value, in documentation order.
func Formats() []string {
	return []string{string(FormatText), string(FormatJSON), string(FormatSARIF), string(FormatMarkdown)}
}

// ParseFormat maps the -output flag onto a Format, accepting the aliases
// people reach for (md, markdown, sarif).
func ParseFormat(s string) (Format, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "text", "txt", "console":
		return FormatText, nil
	case "json":
		return FormatJSON, nil
	case "sarif", "sarif.json":
		return FormatSARIF, nil
	case "markdown", "md":
		return FormatMarkdown, nil
	}
	return "", fmt.Errorf("unknown output format %q (want %s)", s, strings.Join(Formats(), ", "))
}

// FormatForFile guesses the report format from a filename extension, so
// `-out report.sarif` writes SARIF without a second flag. Extensions that say
// nothing about the format return the fallback unchanged.
func FormatForFile(name string, fallback Format) Format {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".sarif":
		return FormatSARIF
	case ".json":
		return FormatJSON
	case ".md", ".markdown":
		return FormatMarkdown
	case ".txt", ".text":
		return FormatText
	}
	return fallback
}

// Write renders rep in the requested format.
func Write(w io.Writer, rep Report, format Format, opts TextOptions) error {
	switch format {
	case FormatJSON:
		return WriteJSON(w, rep)
	case FormatSARIF:
		return WriteSARIF(w, rep)
	case FormatMarkdown:
		return WriteMarkdown(w, rep, opts)
	default:
		return WriteText(w, rep, opts)
	}
}
