package scan

import (
	"context"
	"fmt"
	"strings"
	"sync"
)

type xssCheck struct{}

func (xssCheck) ID() string         { return "xss" }
func (xssCheck) Name() string       { return "Reflected XSS" }
func (xssCheck) Category() Category { return CategoryXSS }

// maxVectors bounds how many inputs each injection check probes.
const maxVectors = 10

func (xssCheck) Run(ctx context.Context, t *Target) ([]Finding, error) {
	page, err := t.Get(ctx, t.URL.String(), false)
	if err != nil {
		return nil, err
	}

	if !page.IsHTML() {
		f := Finding{
			Severity:    SeverityInfo,
			Title:       "Response is not HTML, reflected XSS probes skipped",
			URL:         page.URL,
			Evidence:    "Content-Type: " + page.Header.Get("Content-Type"),
			Remediation: "Non-HTML responses are not rendered as documents. Ensure the endpoint still encodes output if it is ever embedded in a page.",
		}
		Emit(ctx, f)
		return []Finding{f}, nil
	}

	vectors := CollectVectors(page, t.Opts.Deep)
	if len(vectors) == 0 {
		f := Finding{
			Severity:    SeverityInfo,
			Title:       "No user input found on this page to probe for XSS",
			URL:         page.URL,
			Evidence:    "No query parameters and no form fields were discovered.",
			Remediation: "If the application accepts input elsewhere (paths, headers, JSON bodies), test those routes individually.",
		}
		Emit(ctx, f)
		return []Finding{f}, nil
	}
	if len(vectors) > maxVectors {
		vectors = vectors[:maxVectors]
	}

	cspPresent := strings.TrimSpace(hv(page.Header, "Content-Security-Policy")) != ""

	var mu sync.Mutex
	var out []Finding
	// record streams the finding to any live listener and stores it. It is
	// only called while mu is held.
	record := func(f Finding) {
		Emit(ctx, f)
		out = append(out, f)
	}

	tasks := make([]func(), 0, len(vectors))
	for _, v := range vectors {
		v := v
		tasks = append(tasks, func() {
			marker := randomToken(6)
			// A quote plus angle brackets: if any of these reach the
			// document unescaped the attacker can close the current tag
			// and open their own element.
			payload := `"><ijiya` + marker

			resp, err := t.sendVector(ctx, v, payload)
			if err != nil {
				return
			}
			body := string(resp.Body)

			mu.Lock()
			defer mu.Unlock()

			switch {
			case strings.Contains(body, payload) && resp.IsHTML():
				offset := strings.Index(body, payload)
				evidence := fmt.Sprintf("%s input %q reflects the payload verbatim at byte offset %d of a %s response.",
					v.Kind, v.Name, offset, resp.Header.Get("Content-Type"))
				fix := fmt.Sprintf("HTML-encode %q on output (or use your framework's automatic escaping). A strong `Content-Security-Policy` with `script-src` nonces limits the impact but does not remove the injection.", v.Name)
				if cspPresent {
					fix += " A CSP is present, which reduces impact, but inline injection should still be fixed at the source."
				}
				record(Finding{
					Severity:    SeverityHigh,
					Title:       fmt.Sprintf("Reflected cross-site scripting via %s input %q", v.Kind, v.Name),
					URL:         resp.URL,
					Evidence:    evidence + " Payload: " + payload,
					Remediation: fix,
				})
			case strings.Contains(body, marker):
				record(Finding{
					Severity:    SeverityInfo,
					Title:       fmt.Sprintf("%s input %q is reflected but appears encoded", v.Kind, v.Name),
					URL:         resp.URL,
					Evidence:    "The marker reached the response only in encoded form, so no XSS was demonstrated.",
					Remediation: "Keep output encoding context-aware (HTML, attribute, JavaScript, URL, CSS) and add regression tests.",
				})
			}
		})
	}
	parallel(t.Opts.Concurrency, tasks)

	return out, nil
}
