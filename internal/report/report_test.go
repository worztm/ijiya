package report

import (
	"testing"
	"time"

	"ijiya/internal/scan"
)

func find(sev scan.Severity) scan.Finding {
	return scan.Finding{Severity: sev, Title: "x"}
}

func TestBuildCountsAndScores(t *testing.T) {
	results := []scan.CheckResult{
		{
			ID:   "headers",
			Name: "Security headers",
			Findings: []scan.Finding{
				find(scan.SeverityCritical),
				find(scan.SeverityHigh),
				find(scan.SeverityMedium),
			},
		},
		{
			ID:    "cors",
			Name:  "CORS configuration",
			Error: "boom",
			Findings: []scan.Finding{
				find(scan.SeverityLow),
			},
		},
	}

	rep := Build("https://example.com", time.Now(), results, BuildOptions{Requests: 12})

	if rep.Summary.Critical != 1 || rep.Summary.High != 1 ||
		rep.Summary.Medium != 1 || rep.Summary.Low != 1 || rep.Summary.Info != 0 {
		t.Errorf("summary = %+v", rep.Summary)
	}
	if rep.Summary.Total != 4 {
		t.Errorf("total = %d, want 4", rep.Summary.Total)
	}
	if rep.Summary.Errors != 1 {
		t.Errorf("errors = %d, want 1", rep.Summary.Errors)
	}
	// 25 + 12 + 6 + 3 = 46
	if rep.RiskScore != 46 {
		t.Errorf("risk score = %d, want 46", rep.RiskScore)
	}
	if rep.Grade != "D" {
		t.Errorf("grade = %q, want D (risk 46 is just above the C boundary)", rep.Grade)
	}
	if rep.Requests != 12 {
		t.Errorf("requests = %d, want 12", rep.Requests)
	}
}

func TestScoreIsCappedAndGradeExtremes(t *testing.T) {
	if s := score(Summary{}); s != 0 {
		t.Errorf("clean scan should score 0, got %d", s)
	}
	if g := grade(0); g != "A+" {
		t.Errorf("grade(0) = %q, want A+", g)
	}
	if g := grade(100); g != "F" {
		t.Errorf("grade(100) = %q, want F", g)
	}
	huge := score(Summary{Critical: 20, High: 20, Medium: 20})
	if huge != 100 {
		t.Errorf("score must be capped at 100, got %d", huge)
	}
}

func TestMaxSeverity(t *testing.T) {
	rep := Report{Checks: []scan.CheckResult{
		{Findings: []scan.Finding{find(scan.SeverityLow), find(scan.SeverityHigh)}},
	}}
	max, found := rep.MaxSeverity()
	if !found || max != scan.SeverityHigh {
		t.Errorf("MaxSeverity = (%v, %v), want (high, true)", max, found)
	}

	empty := Report{}
	if _, found := empty.MaxSeverity(); found {
		t.Error("an empty report must report no maximum severity")
	}
}

func TestFindingsSortedBySeverity(t *testing.T) {
	rep := Report{Checks: []scan.CheckResult{
		{Findings: []scan.Finding{find(scan.SeverityInfo), find(scan.SeverityCritical)}},
		{Findings: []scan.Finding{find(scan.SeverityMedium)}},
	}}
	all := rep.Findings()
	if len(all) != 3 {
		t.Fatalf("len = %d, want 3", len(all))
	}
	if all[0].Severity != scan.SeverityCritical || all[2].Severity != scan.SeverityInfo {
		t.Errorf("findings are not sorted: %v %v %v", all[0].Severity, all[1].Severity, all[2].Severity)
	}
}

func TestWrapRespectsWidth(t *testing.T) {
	text := "Use parameterised queries for every database access, and map database errors to generic client messages."
	for _, width := range []int{20, 40, 80} {
		for _, line := range wrap(text, width) {
			// A single long word may exceed the width, but nothing else should.
			if len(line) > width && !isSingleWord(line) {
				t.Errorf("width %d: line %q is %d chars", width, line, len(line))
			}
		}
	}
}

func TestWrapKeepsShortInputOnOneLine(t *testing.T) {
	lines := wrap("short text", 80)
	if len(lines) != 1 || lines[0] != "short text" {
		t.Errorf("got %v", lines)
	}
}

func isSingleWord(s string) bool {
	for _, r := range s {
		if r == ' ' {
			return false
		}
	}
	return true
}

func TestFormatDuration(t *testing.T) {
	cases := map[int64]string{
		12:    "12ms",
		1500:  "1.5s",
		65000: "1m5s",
	}
	for ms, want := range cases {
		if got := formatDuration(ms); got != want {
			t.Errorf("formatDuration(%d) = %q, want %q", ms, got, want)
		}
	}
}
