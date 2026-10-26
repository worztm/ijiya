package report

import (
	"encoding/json"
	"io"
	"net/url"
	"strings"

	"github.com/worztm/ijiya/internal/scan"
)

// SARIF 2.1.0 structures. Only the subset a security scanner needs is modelled
// here; anything left out is simply absent from the JSON rather than emitted as
// a null, which keeps the document valid under the spec's optional fields.
//
// Uploading this file with `github/codeql-action/upload-sarif` turns every
// finding into a code-scanning annotation on the pull request that introduced
// it, which is why the format is worth supporting: findings appear where the
// reviewer already is instead of in a log nobody opens.
type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri,omitempty"`
	Rules          []sarifRule `json:"rules,omitempty"`
}

type sarifRule struct {
	ID               string       `json:"id"`
	Name             string       `json:"name,omitempty"`
	ShortDescription sarifMessage `json:"shortDescription"`
	Help             sarifMessage `json:"help,omitempty"`
	Properties       *sarifProps  `json:"properties,omitempty"`
}

type sarifProps struct {
	Category  string   `json:"category,omitempty"`
	Tags      []string `json:"tags,omitempty"`
	Precision string   `json:"precision,omitempty"`
}

type sarifResult struct {
	RuleID              string            `json:"ruleId"`
	RuleIndex           int               `json:"ruleIndex"`
	Level               string            `json:"level,omitempty"`
	Message             sarifMessage      `json:"message"`
	Locations           []sarifLocation   `json:"locations,omitempty"`
	PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"`
	Properties          *sarifProps       `json:"properties,omitempty"`
}

type sarifMessage struct {
	Text     string `json:"text,omitempty"`
	Markdown string `json:"markdown,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

// sarifSchema is the canonical schema identifier for SARIF 2.1.0.
const sarifSchema = "https://json.schemastore.org/sarif-2.1.0.json"

// WriteSARIF renders the report as SARIF 2.1.0.
//
// Findings become results, one rule is declared per check that produced a
// finding, and the rule index is carried so GitHub can group alerts by check.
func WriteSARIF(w io.Writer, rep Report) error {
	log := sarifLog{
		Schema:  sarifSchema,
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           rep.Tool,
				Version:        rep.Version,
				InformationURI: "https://github.com/worztm/ijiya",
			}},
			Results: []sarifResult{},
		}},
	}

	run := &log.Runs[0]
	index := map[string]int{}

	for _, check := range rep.Checks {
		if len(check.Findings) == 0 {
			continue
		}
		if _, ok := index[check.ID]; !ok {
			index[check.ID] = len(run.Tool.Driver.Rules)
			run.Tool.Driver.Rules = append(run.Tool.Driver.Rules, sarifRule{
				ID:               check.ID,
				Name:             sanitiseRuleName(check.Name),
				ShortDescription: sarifMessage{Text: check.Name},
				Help:             sarifMessage{Markdown: ruleHelp(check)},
				Properties: &sarifProps{
					Category: string(check.Category),
					Tags:     []string{"security", string(check.Category)},
				},
			})
		}
	}

	for _, check := range rep.Checks {
		for _, f := range check.Findings {
			run.Results = append(run.Results, sarifResult{
				RuleID:              check.ID,
				RuleIndex:           index[check.ID],
				Level:               sarifLevel(f.Severity),
				Message:             sarifMessage{Text: resultMessage(f)},
				Locations:           sarifLocations(rep.Target, f),
				PartialFingerprints: map[string]string{"ijiyaFingerprint/v1": Fingerprint(f)},
				Properties: &sarifProps{
					Category: string(f.Category),
					Tags:     []string{"security", string(f.Category), f.Severity.String()},
				},
			})
		}
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(log)
}

// sarifLevel maps a severity onto the SARIF level vocabulary. GitHub only
// renders error/warning/note distinctly, so critical and high both become
// errors: severity detail is preserved in the tags instead.
func sarifLevel(s scan.Severity) string {
	switch s {
	case scan.SeverityCritical, scan.SeverityHigh:
		return "error"
	case scan.SeverityMedium:
		return "warning"
	case scan.SeverityLow:
		return "note"
	default:
		return "note"
	}
}

// resultMessage is the one-line summary shown in the annotation.
func resultMessage(f scan.Finding) string {
	msg := f.Title
	if f.Evidence != "" {
		msg += " - " + f.Evidence
	}
	return msg
}

// sarifLocations points the result at the target under test. A web scanner has
// no source file to blame, so the artifact is the scanned URL and the review
// comment lands on the pull request as a whole rather than on a line.
func sarifLocations(target string, f scan.Finding) []sarifLocation {
	uri := f.URL
	if uri == "" {
		uri = target
	}
	if u, err := url.Parse(uri); err == nil && u.Host != "" {
		// Keep the query string out of the artifact URI: it can carry
		// tokens, and it is not part of the path being flagged.
		u.RawQuery = ""
		u.Fragment = ""
		uri = u.String()
	}
	if uri == "" {
		return nil
	}
	return []sarifLocation{{PhysicalLocation: sarifPhysical{
		ArtifactLocation: sarifArtifact{URI: uri},
	}}}
}

// ruleHelp renders the remediation guidance for a check as Markdown, taking
// the fix from the first finding since every finding of a check shares one.
func ruleHelp(check scan.CheckResult) string {
	var b strings.Builder
	b.WriteString("**" + check.Name + "**\n\n")
	if check.Category != "" {
		b.WriteString("Category: `" + string(check.Category) + "`\n\n")
	}
	seen := map[string]bool{}
	for _, f := range check.Findings {
		if f.Remediation == "" || seen[f.Remediation] {
			continue
		}
		seen[f.Remediation] = true
		b.WriteString("- " + f.Remediation + "\n")
	}
	return strings.TrimSpace(b.String())
}

// sanitiseRuleName turns a human readable check name into the camel-case
// style identifier SARIF suggests for rule names.
func sanitiseRuleName(name string) string {
	fields := strings.FieldsFunc(name, func(r rune) bool {
		return r == ' ' || r == '-' || r == '_' || r == '/'
	})
	if len(fields) == 0 {
		return name
	}
	for i, f := range fields {
		fields[i] = strings.ToUpper(f[:1]) + f[1:]
	}
	return strings.Join(fields, "")
}
