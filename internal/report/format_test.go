package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"ijiya/internal/scan"
)

func TestParseFormat(t *testing.T) {
	cases := map[string]Format{
		"":         FormatText,
		"text":     FormatText,
		"TEXT":     FormatText,
		" json ":   FormatJSON,
		"sarif":    FormatSARIF,
		"markdown": FormatMarkdown,
		"md":       FormatMarkdown,
	}
	for in, want := range cases {
		got, err := ParseFormat(in)
		if err != nil {
			t.Errorf("ParseFormat(%q) failed: %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("ParseFormat(%q) = %q, want %q", in, got, want)
		}
	}
	if _, err := ParseFormat("xml"); err == nil {
		t.Error("ParseFormat must reject an unknown format")
	}
}

func TestFormatForFile(t *testing.T) {
	cases := []struct {
		name     string
		fallback Format
		want     Format
	}{
		{"report.sarif", FormatText, FormatSARIF},
		{"report.JSON", FormatText, FormatJSON},
		{"report.md", FormatText, FormatMarkdown},
		{"report.markdown", FormatText, FormatMarkdown},
		{"report.txt", FormatSARIF, FormatText},
		{"report", FormatText, FormatText},
		{"report", FormatJSON, FormatJSON},
		{"report.dat", FormatJSON, FormatJSON},
	}
	for _, c := range cases {
		if got := FormatForFile(c.name, c.fallback); got != c.want {
			t.Errorf("FormatForFile(%q, %q) = %q, want %q", c.name, c.fallback, got, c.want)
		}
	}
}

func sarifFixture() Report {
	return Build("https://example.com", time.Now(), []scan.CheckResult{
		{
			ID: "headers", Name: "Security headers", Category: scan.CategoryHeaders,
			Findings: []scan.Finding{
				finding("headers", "HSTS header missing", "https://example.com/?token=secret", scan.SeverityMedium),
				finding("headers", "CSP header missing", "https://example.com/", scan.SeverityCritical),
			},
		},
		{
			ID: "sqli", Name: "SQL injection", Category: scan.CategorySQLi,
			Findings: []scan.Finding{
				finding("sqli", "SQL injection via query input \"id\"", "https://example.com/item?id=1", scan.SeverityHigh),
			},
		},
	}, BuildOptions{})
}

func TestWriteSARIFStructure(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteSARIF(&buf, sarifFixture()); err != nil {
		t.Fatalf("WriteSARIF: %v", err)
	}
	if !json.Valid(buf.Bytes()) {
		t.Fatalf("SARIF output is not valid JSON:\n%s", buf.String())
	}

	var decoded struct {
		Schema  string `json:"$schema"`
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Name  string `json:"name"`
					Rules []struct {
						ID               string `json:"id"`
						ShortDescription struct {
							Text string `json:"text"`
						} `json:"shortDescription"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID    string `json:"ruleId"`
				RuleIndex int    `json:"ruleIndex"`
				Level     string `json:"level"`
				Message   struct {
					Text string `json:"text"`
				} `json:"message"`
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct {
							URI string `json:"uri"`
						} `json:"artifactLocation"`
					} `json:"physicalLocation"`
				} `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.Version != "2.1.0" {
		t.Errorf("version = %q, want 2.1.0", decoded.Version)
	}
	if !strings.Contains(decoded.Schema, "sarif") {
		t.Errorf("$schema = %q, want a SARIF schema URL", decoded.Schema)
	}
	if len(decoded.Runs) != 1 {
		t.Fatalf("runs = %d, want 1", len(decoded.Runs))
	}
	run := decoded.Runs[0]
	if run.Tool.Driver.Name != "ijiya" {
		t.Errorf("driver name = %q, want ijiya", run.Tool.Driver.Name)
	}
	if len(run.Tool.Driver.Rules) != 2 {
		t.Fatalf("rules = %d, want one per check with findings", len(run.Tool.Driver.Rules))
	}
	if len(run.Results) != 3 {
		t.Fatalf("results = %d, want one per finding", len(run.Results))
	}

	// Rule references must resolve, and the levels must map as documented.
	levels := map[string]string{}
	for _, r := range run.Results {
		if r.RuleIndex < 0 || r.RuleIndex >= len(run.Tool.Driver.Rules) {
			t.Fatalf("result %q has out-of-range ruleIndex %d", r.RuleID, r.RuleIndex)
		}
		if run.Tool.Driver.Rules[r.RuleIndex].ID != r.RuleID {
			t.Errorf("ruleIndex %d points at %q, want %q",
				r.RuleIndex, run.Tool.Driver.Rules[r.RuleIndex].ID, r.RuleID)
		}
		if r.Message.Text == "" {
			t.Errorf("result %q has an empty message", r.RuleID)
		}
		levels[r.Message.Text] = r.Level
	}
	if got := levels["SQL injection via query input \"id\""]; got != "error" {
		t.Errorf("high severity mapped to %q, want error", got)
	}
	found := map[string]bool{}
	for _, r := range run.Results {
		if r.Level == "" {
			t.Error("every result needs an explicit level")
		}
		found[r.Level] = true
	}
	if !found["error"] || !found["warning"] {
		t.Errorf("levels = %v, want both error and warning present", found)
	}

	// The scanned URL is the artifact, and its query string must be stripped.
	for _, r := range run.Results {
		for _, loc := range r.Locations {
			uri := loc.PhysicalLocation.ArtifactLocation.URI
			if uri == "" {
				t.Error("a location with an empty URI is worse than no location")
			}
			if strings.Contains(uri, "token=secret") {
				t.Errorf("query string leaked into the artifact URI: %q", uri)
			}
		}
	}
}

func TestWriteSARIFSkipsRulesWithoutFindings(t *testing.T) {
	rep := Build("https://example.com", time.Now(), []scan.CheckResult{
		{ID: "headers", Name: "Security headers", Findings: nil},
		{ID: "cors", Name: "CORS", Findings: []scan.Finding{
			finding("cors", "wildcard", "https://example.com/", scan.SeverityInfo),
		}},
	}, BuildOptions{})

	var buf bytes.Buffer
	if err := WriteSARIF(&buf, rep); err != nil {
		t.Fatalf("WriteSARIF: %v", err)
	}
	if !strings.Contains(buf.String(), `"rules"`) {
		t.Error("a report with findings must declare rules")
	}
	if strings.Contains(buf.String(), `"id": "headers"`) {
		t.Error("a check without findings must not be declared as a rule")
	}
}

func TestWriteSARIFEmptyReportIsValid(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteSARIF(&buf, Build("https://example.com", time.Now(), nil, BuildOptions{})); err != nil {
		t.Fatalf("WriteSARIF: %v", err)
	}
	if !json.Valid(buf.Bytes()) {
		t.Fatalf("empty SARIF is not valid JSON: %s", buf.String())
	}
	// An empty results array, not null: some ingesters reject null.
	if strings.Contains(buf.String(), `"results": null`) {
		t.Error("results must serialise as an empty array")
	}
}

func TestWriteMarkdown(t *testing.T) {
	rep := sarifFixture()
	rep.Banner = true // the Markdown renderer must ignore the text banner

	var buf bytes.Buffer
	if err := WriteMarkdown(&buf, rep, TextOptions{Min: scan.SeverityInfo}); err != nil {
		t.Fatalf("WriteMarkdown: %v", err)
	}
	out := buf.String()

	for _, want := range []string{"#", "example.com", "CRITICAL", "HIGH", "MEDIUM", "HSTS header missing"} {
		if !strings.Contains(out, want) {
			t.Errorf("markdown is missing %q\n%s", want, out)
		}
	}
	if strings.Contains(out, "█████") {
		t.Error("the ASCII banner must not leak into Markdown")
	}
}

func TestWriteMarkdownHonoursSeverityFilter(t *testing.T) {
	rep := Build("https://example.com", time.Now(), []scan.CheckResult{{
		ID: "headers", Name: "Security headers",
		Findings: []scan.Finding{
			finding("headers", "low thing", "https://example.com/", scan.SeverityLow),
			finding("headers", "high thing", "https://example.com/", scan.SeverityHigh),
		},
	}}, BuildOptions{})

	var buf bytes.Buffer
	if err := WriteMarkdown(&buf, rep, TextOptions{Min: scan.SeverityHigh}); err != nil {
		t.Fatalf("WriteMarkdown: %v", err)
	}
	out := buf.String()
	if strings.Contains(out, "low thing") {
		t.Error("a finding below the filter must not be listed")
	}
	if !strings.Contains(out, "high thing") {
		t.Error("a finding at the filter must be listed")
	}
	if !strings.Contains(out, "below the severity filter") {
		t.Error("the number of hidden findings should be stated")
	}
}

func TestWriteDispatchesEveryFormat(t *testing.T) {
	rep := sarifFixture()
	for _, f := range []Format{FormatText, FormatJSON, FormatSARIF, FormatMarkdown} {
		var buf bytes.Buffer
		if err := Write(&buf, rep, f, TextOptions{Min: scan.SeverityInfo, Width: 80}); err != nil {
			t.Errorf("Write(%s) failed: %v", f, err)
		}
		if buf.Len() == 0 {
			t.Errorf("Write(%s) produced no output", f)
		}
	}
}

// TestSuppressedLineAppearsInText keeps the baseline visible in the human
// report: a silently smaller report would look like the issues were fixed.
func TestSuppressedLineAppearsInText(t *testing.T) {
	rep := sarifFixture()
	rep.Suppressed = 3
	var buf bytes.Buffer
	if err := WriteText(&buf, rep, TextOptions{Min: scan.SeverityInfo, Width: 80}); err != nil {
		t.Fatalf("WriteText: %v", err)
	}
	if !strings.Contains(buf.String(), "3 known finding(s) suppressed") {
		t.Errorf("text report does not mention suppressed findings:\n%s", buf.String())
	}
}
