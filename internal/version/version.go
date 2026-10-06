// Package version holds build information shared by the CLI and the report.
package version

const (
	// Name is the tool name shown in banners and reports.
	Name = "ijiya"
	// Version is the semantic version of this release.
	Version = "0.2.0"
	// Description is a one line summary used in --help output.
	Description = "lightweight web vulnerability scanner"
	// Notice reminds users to scan responsibly.
	Notice = "Only scan systems you own or have explicit permission to test."
)
