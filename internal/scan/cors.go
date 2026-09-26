package scan

import (
	"context"
	"fmt"
	"net/http"
	"strings"
)

type corsCheck struct{}

func (corsCheck) ID() string         { return "cors" }
func (corsCheck) Name() string       { return "CORS configuration" }
func (corsCheck) Category() Category { return CategoryCORS }

// probeOrigin is a reserved, non-resolvable origin (RFC 6761 .invalid TLD)
// used to see whether the server reflects arbitrary origins.
const probeOrigin = "https://ijiya-cors-probe.invalid"

func (corsCheck) Run(ctx context.Context, t *Target) ([]Finding, error) {
	var out []Finding
	type probe struct {
		label  string
		origin string
		null   bool
	}
	probes := []probe{
		{"an arbitrary cross-origin site", probeOrigin, false},
		{"the opaque origin \"null\"", "null", true},
	}

	for _, p := range probes {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, t.URL.String(), nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Origin", p.origin)
		resp, err := t.Do(ctx, req, true)
		if err != nil {
			continue
		}

		acao := strings.TrimSpace(resp.Header.Get("Access-Control-Allow-Origin"))
		if acao == "" {
			continue
		}
		allowCreds := strings.EqualFold(strings.TrimSpace(resp.Header.Get("Access-Control-Allow-Credentials")), "true")
		methods := resp.Header.Get("Access-Control-Allow-Methods")

		evidence := fmt.Sprintf("Request with Origin: %s -> Access-Control-Allow-Origin: %s", p.origin, acao)
		if allowCreds {
			evidence += ", Access-Control-Allow-Credentials: true"
		}
		if methods != "" {
			evidence += ", Access-Control-Allow-Methods: " + methods
		}

		add := func(sev Severity, title, fix string) {
			f := Finding{
				Severity:    sev,
				Title:       title,
				URL:         resp.URL,
				Evidence:    evidence,
				Remediation: fix,
			}
			Emit(ctx, f)
			out = append(out, f)
		}

		reflected := strings.EqualFold(acao, p.origin)
		wildcard := acao == "*"

		switch {
		case reflected && p.null && allowCreds:
			add(SeverityCritical,
				"CORS trusts the opaque \"null\" origin with credentials",
				"Restrict Access-Control-Allow-Origin to an explicit allow-list and never combine it with Allow-Credentials: true for null.")
		case reflected && p.null:
			add(SeverityMedium,
				"CORS reflects the opaque \"null\" origin",
				"Sandboxed iframes and local files send Origin: null, so remove null from the allow-list.")
		case reflected && allowCreds:
			add(SeverityCritical,
				"CORS allows any origin to read credentialed responses",
				"Never reflect arbitrary origins alongside Access-Control-Allow-Credentials: true; validate the Origin against an exact allow-list.")
		case reflected:
			add(SeverityHigh,
				"CORS allows any origin to read this response",
				"Reflect only origins you control, or drop Access-Control-Allow-Origin for public resources.")
		case wildcard && allowCreds:
			add(SeverityLow,
				"CORS combines Access-Control-Allow-Origin: * with credentials",
				"Browsers reject this combination, but it signals a misconfiguration; use an explicit origin when credentials are involved.")
		case wildcard:
			add(SeverityInfo,
				"CORS allows every origin via a wildcard",
				"Acceptable only for genuinely public, non-sensitive data. Do not expose user-specific content this way.")
		}
		// Any other value means the server replied with a different origin
		// (an allow-listed one), which is the correct behaviour and needs
		// no finding.
	}

	return out, nil
}
