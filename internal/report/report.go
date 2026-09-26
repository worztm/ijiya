// Package report turns scan results into text and JSON output.
package report

import (
	"sort"
	"time"

	"ijiya/internal/scan"
	"ijiya/internal/version"
)

// Report is the complete result of one scan, in both rendering forms.
type Report struct {
	Tool       string             `json:"tool"`
	Version    string             `json:"version"`
	Target     string             `json:"target"`
	StartedAt  time.Time          `json:"started_at"`
	DurationMS int64              `json:"duration_ms"`
	Requests   int64              `json:"requests"`
	Checks     []scan.CheckResult `json:"checks"`
	Summary    Summary            `json:"summary"`
	RiskScore  int                `json:"risk_score"`
	Grade      string             `json:"grade"`
}

// Summary counts findings by severity.
type Summary struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
	Total    int `json:"total"`
	Errors   int `json:"errors"`
}

// Build assembles a Report from raw check results.
func Build(target string, started time.Time, results []scan.CheckResult, requests int64) Report {
	rep := Report{
		Tool:       version.Name,
		Version:    version.Version,
		Target:     target,
		StartedAt:  started,
		DurationMS: time.Since(started).Milliseconds(),
		Requests:   requests,
		Checks:     results,
	}

	for _, r := range results {
		if r.Failed() {
			rep.Summary.Errors++
		}
		for _, f := range r.Findings {
			switch f.Severity {
			case scan.SeverityCritical:
				rep.Summary.Critical++
			case scan.SeverityHigh:
				rep.Summary.High++
			case scan.SeverityMedium:
				rep.Summary.Medium++
			case scan.SeverityLow:
				rep.Summary.Low++
			default:
				rep.Summary.Info++
			}
			rep.Summary.Total++
		}
	}

	rep.RiskScore = score(rep.Summary)
	rep.Grade = grade(rep.RiskScore)
	return rep
}

// score weights findings so that one critical issue dominates the result.
func score(s Summary) int {
	raw := s.Critical*25 + s.High*12 + s.Medium*6 + s.Low*3 + s.Info
	if raw > 100 {
		return 100
	}
	return raw
}

// grade maps a risk score onto a letter, where F is the worst outcome.
func grade(risk int) string {
	switch {
	case risk == 0:
		return "A+"
	case risk <= 10:
		return "A"
	case risk <= 25:
		return "B"
	case risk <= 45:
		return "C"
	case risk <= 65:
		return "D"
	default:
		return "F"
	}
}

// Findings returns every finding, most severe first.
func (r Report) Findings() []scan.Finding {
	var all []scan.Finding
	for _, c := range r.Checks {
		all = append(all, c.Findings...)
	}
	sort.SliceStable(all, func(i, j int) bool {
		return all[i].Severity > all[j].Severity
	})
	return all
}

// MaxSeverity returns the most severe finding, or -1 when there are none.
// It is used to decide the process exit code.
func (r Report) MaxSeverity() (scan.Severity, bool) {
	var max scan.Severity = -1
	found := false
	for _, f := range r.Findings() {
		if !found || f.Severity > max {
			max = f.Severity
			found = true
		}
	}
	return max, found
}
