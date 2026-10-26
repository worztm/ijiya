package report

import (
	"strings"
	"testing"
	"time"

	"ijiya/internal/scan"
)

func TestBuildRedactsURLsAndEvidence(t *testing.T) {
	rep := Build("https://example.com/app?token=top-secret", time.Now(), []scan.CheckResult{{
		ID: "redirect",
		Findings: []scan.Finding{{
			CheckID:  "redirect",
			Title:    "redirect",
			URL:      "https://example.com/app?token=top-secret",
			Evidence: "Location: https://example.com/callback?code=top-secret",
		}},
	}}, BuildOptions{Redact: true})

	raw := rep.Target + " " + rep.Checks[0].Findings[0].URL + " " + rep.Checks[0].Findings[0].Evidence
	if strings.Contains(raw, "top-secret") {
		t.Fatalf("report leaked secret: %s", raw)
	}
	if !strings.Contains(raw, "token=REDACTED") || !strings.Contains(raw, "code=REDACTED") {
		t.Fatalf("report did not show redaction: %s", raw)
	}
}
