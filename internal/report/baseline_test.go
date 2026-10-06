package report

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"ijiya/internal/scan"
)

// writeBaseline writes rep as JSON and returns the file path.
func writeBaseline(t *testing.T, rep Report) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "baseline.json")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("creating baseline: %v", err)
	}
	if err := WriteJSON(f, rep); err != nil {
		t.Fatalf("writing baseline: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("closing baseline: %v", err)
	}
	return path
}

func finding(check, title, url string, sev scan.Severity) scan.Finding {
	return scan.Finding{CheckID: check, Title: title, URL: url, Severity: sev, Category: scan.Category(check)}
}

// baselineFixture is a scan with two known findings on the headers check.
func baselineFixture() Report {
	return Build("https://staging.example.com", time.Now(), []scan.CheckResult{
		{
			ID: "headers", Name: "Security headers", Category: scan.CategoryHeaders,
			Findings: []scan.Finding{
				finding("headers", "HSTS header missing", "https://staging.example.com/", scan.SeverityMedium),
				finding("headers", "CSP header missing", "https://staging.example.com/", scan.SeverityMedium),
			},
		},
	}, BuildOptions{Requests: 3})
}

func TestLoadBaselineMissingFileIsNotAnError(t *testing.T) {
	b, err := LoadBaseline(filepath.Join(t.TempDir(), "does-not-exist.json"))
	if err != nil {
		t.Fatalf("a missing baseline must not fail the run: %v", err)
	}
	if !b.Empty() {
		t.Errorf("expected an empty baseline, got %d entries", b.Len())
	}
}

func TestLoadBaselineRejectsGarbage(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatalf("writing: %v", err)
	}
	if _, err := LoadBaseline(path); err == nil {
		t.Error("a malformed baseline must be reported rather than ignored")
	}
}

func TestSuppressRemovesKnownFindingsAndRescores(t *testing.T) {
	base := baselineFixture()
	path := writeBaseline(t, base)

	bl, err := LoadBaseline(path)
	if err != nil {
		t.Fatalf("LoadBaseline: %v", err)
	}
	if bl.Len() != 2 {
		t.Fatalf("baseline length = %d, want 2", bl.Len())
	}

	// A new scan of a different host with the same two issues plus one new one.
	rep := Build("https://preview.example.com", time.Now(), []scan.CheckResult{
		{
			ID: "headers", Name: "Security headers", Category: scan.CategoryHeaders,
			Findings: []scan.Finding{
				finding("headers", "HSTS header missing", "https://preview.example.com/", scan.SeverityMedium),
				finding("headers", "CSP header missing", "https://preview.example.com/", scan.SeverityMedium),
				finding("headers", "New: X-Frame-Options missing", "https://preview.example.com/", scan.SeverityHigh),
			},
		},
	}, BuildOptions{Requests: 4, Baseline: bl})

	if rep.Suppressed != 2 {
		t.Errorf("Suppressed = %d, want 2", rep.Suppressed)
	}
	if rep.Summary.Total != 1 {
		t.Errorf("Summary.Total = %d, want only the new finding counted", rep.Summary.Total)
	}
	if rep.Summary.High != 1 || rep.Summary.Medium != 0 {
		t.Errorf("summary = %+v, want one high and no medium", rep.Summary)
	}
	if rep.Summary.Total != rep.Summary.High+rep.Summary.Medium+rep.Summary.Low+rep.Summary.Critical+rep.Summary.Info {
		t.Errorf("summary rows do not add up to the total: %+v", rep.Summary)
	}
	if max, found := rep.MaxSeverity(); !found || max != scan.SeverityHigh {
		t.Errorf("MaxSeverity = (%v, %v), want (high, true)", max, found)
	}
}

func TestSuppressAllFindingsLeavesCleanReport(t *testing.T) {
	path := writeBaseline(t, baselineFixture())
	bl, err := LoadBaseline(path)
	if err != nil {
		t.Fatalf("LoadBaseline: %v", err)
	}

	rep := Build("https://staging.example.com", time.Now(), []scan.CheckResult{
		{
			ID: "headers", Name: "Security headers", Category: scan.CategoryHeaders,
			Findings: []scan.Finding{
				finding("headers", "HSTS header missing", "https://staging.example.com/", scan.SeverityMedium),
			},
		},
	}, BuildOptions{Baseline: bl})

	if rep.Summary.Total != 0 {
		t.Errorf("Total = %d, want 0", rep.Summary.Total)
	}
	if rep.RiskScore != 0 || rep.Grade != "A+" {
		t.Errorf("risk = %d grade = %q, want 0 and A+", rep.RiskScore, rep.Grade)
	}
	if _, found := rep.MaxSeverity(); found {
		t.Error("a fully suppressed report must have no maximum severity, so -fail-on passes")
	}
}

func TestSuppressCountsDuplicatesIndividually(t *testing.T) {
	// Two identical findings in the baseline only excuse two in the new run.
	base := Build("https://example.com", time.Now(), []scan.CheckResult{{
		ID: "headers", Name: "Security headers",
		Findings: []scan.Finding{
			finding("headers", "dup", "https://example.com/", scan.SeverityLow),
			finding("headers", "dup", "https://example.com/", scan.SeverityLow),
		},
	}}, BuildOptions{})

	path := writeBaseline(t, base)
	bl, err := LoadBaseline(path)
	if err != nil {
		t.Fatalf("LoadBaseline: %v", err)
	}

	rep := Build("https://example.com", time.Now(), []scan.CheckResult{{
		ID: "headers", Name: "Security headers",
		Findings: []scan.Finding{
			finding("headers", "dup", "https://example.com/", scan.SeverityLow),
			finding("headers", "dup", "https://example.com/", scan.SeverityLow),
			finding("headers", "dup", "https://example.com/", scan.SeverityLow),
		},
	}}, BuildOptions{Baseline: bl})

	if rep.Suppressed != 2 {
		t.Errorf("Suppressed = %d, want 2", rep.Suppressed)
	}
	if rep.Summary.Total != 1 {
		t.Errorf("Total = %d, want the third duplicate to remain", rep.Summary.Total)
	}
}

func TestFingerprintIgnoresHostAndQueryButNotPath(t *testing.T) {
	a := Fingerprint(finding("headers", "Missing CSP", "https://staging.example.com/app?token=1", scan.SeverityMedium))
	b := Fingerprint(finding("headers", "Missing CSP", "https://preview.example.com/app?other=2", scan.SeverityMedium))
	if a != b {
		t.Error("host and query must not change a fingerprint")
	}

	c := Fingerprint(finding("headers", "Missing CSP", "https://preview.example.com/admin", scan.SeverityMedium))
	if a == c {
		t.Error("a different path must produce a different fingerprint")
	}

	d := Fingerprint(finding("headers", "Missing  CSP", "https://preview.example.com/app", scan.SeverityMedium))
	e := Fingerprint(finding("headers", "missing csp", "https://preview.example.com/app", scan.SeverityLow))
	if d != e {
		t.Error("casing, spacing and severity must not change a fingerprint")
	}
}

func TestFingerprintFallsBackWhenCheckIsFilledByTheEngine(t *testing.T) {
	// The baseline writer stores the check ID inside each finding, but a hand
	// edited or older report may not; LoadBaseline fills it from the check.
	rep := Report{Checks: []scan.CheckResult{{
		ID: "cors", Name: "CORS",
		Findings: []scan.Finding{{Title: "any origin", URL: "https://example.com/"}},
	}}}
	path := filepath.Join(t.TempDir(), "old.json")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("creating: %v", err)
	}
	if err := WriteJSON(f, rep); err != nil {
		t.Fatalf("writing: %v", err)
	}
	f.Close()

	bl, err := LoadBaseline(path)
	if err != nil {
		t.Fatalf("LoadBaseline: %v", err)
	}
	want := Fingerprint(finding("cors", "any origin", "https://example.com/", scan.SeverityInfo))
	if _, ok := bl.known[want]; !ok {
		t.Errorf("baseline entry was not keyed by the parent check ID: %v", bl.known)
	}
}
