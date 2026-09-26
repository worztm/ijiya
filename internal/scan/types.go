package scan

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// Severity ranks how serious a finding is, from informational to critical.
type Severity int

const (
	// SeverityInfo is useful context rather than a vulnerability.
	SeverityInfo Severity = iota
	// SeverityLow is a hardening gap with limited direct impact.
	SeverityLow
	// SeverityMedium is a weakness that is commonly exploitable.
	SeverityMedium
	// SeverityHigh is a likely exploitable vulnerability.
	SeverityHigh
	// SeverityCritical is an immediately dangerous exposure.
	SeverityCritical
)

// ParseSeverity maps a user supplied name onto a Severity.
func ParseSeverity(s string) (Severity, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "info", "informational":
		return SeverityInfo, nil
	case "low":
		return SeverityLow, nil
	case "medium", "med", "moderate":
		return SeverityMedium, nil
	case "high":
		return SeverityHigh, nil
	case "critical", "crit":
		return SeverityCritical, nil
	}
	return SeverityInfo, fmt.Errorf("unknown severity %q (want info|low|medium|high|critical)", s)
}

func (s Severity) String() string {
	switch s {
	case SeverityInfo:
		return "info"
	case SeverityLow:
		return "low"
	case SeverityMedium:
		return "medium"
	case SeverityHigh:
		return "high"
	case SeverityCritical:
		return "critical"
	}
	return "unknown"
}

// Label is the uppercase form used in the text report.
func (s Severity) Label() string {
	switch s {
	case SeverityInfo:
		return "INFO"
	case SeverityLow:
		return "LOW"
	case SeverityMedium:
		return "MEDIUM"
	case SeverityHigh:
		return "HIGH"
	case SeverityCritical:
		return "CRITICAL"
	}
	return "?"
}

// AtLeast reports whether the severity is at or above min.
func (s Severity) AtLeast(min Severity) bool { return s >= min }

// MarshalJSON renders the severity as a lower case string.
func (s Severity) MarshalJSON() ([]byte, error) { return json.Marshal(s.String()) }

// UnmarshalJSON accepts either a severity string or a numeric rank.
func (s *Severity) UnmarshalJSON(b []byte) error {
	var str string
	if err := json.Unmarshal(b, &str); err == nil {
		parsed, perr := ParseSeverity(str)
		if perr != nil {
			return perr
		}
		*s = parsed
		return nil
	}
	var n int
	if err := json.Unmarshal(b, &n); err != nil {
		return err
	}
	*s = Severity(n)
	return nil
}

// Category groups related checks together in the report.
type Category string

const (
	CategoryHeaders    Category = "headers"
	CategoryCookies    Category = "cookies"
	CategoryTLS        Category = "tls"
	CategoryCORS       Category = "cors"
	CategoryXSS        Category = "xss"
	CategorySQLi       Category = "sqli"
	CategoryDisclosure Category = "disclosure"
	CategoryRedirect   Category = "redirect"
)

// Finding is a single security issue discovered by a check.
type Finding struct {
	CheckID     string   `json:"check"`
	Category    Category `json:"category"`
	Severity    Severity `json:"severity"`
	Title       string   `json:"title"`
	URL         string   `json:"url,omitempty"`
	Evidence    string   `json:"evidence,omitempty"`
	Remediation string   `json:"remediation,omitempty"`
}

// CheckResult is the outcome of running one check.
type CheckResult struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	Category   Category  `json:"category"`
	Findings   []Finding `json:"findings"`
	Error      string    `json:"error,omitempty"`
	DurationMS int64     `json:"duration_ms"`
}

// Failed reports whether the check itself blew up rather than reporting issues.
func (r CheckResult) Failed() bool { return r.Error != "" }

// Check is a self contained test that can run against a target.
type Check interface {
	// ID is the machine readable name used with -checks.
	ID() string
	// Name is the human readable label shown in reports.
	Name() string
	// Category groups this check with related ones.
	Category() Category
	// Run performs the check and returns its findings.
	Run(ctx context.Context, t *Target) ([]Finding, error)
}
