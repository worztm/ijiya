package scan

import (
	"context"
	"fmt"
	"net/url"
	"strings"
)

type redirectCheck struct{}

func (redirectCheck) ID() string         { return "redirect" }
func (redirectCheck) Name() string       { return "Open redirect" }
func (redirectCheck) Category() Category { return CategoryRedirect }

// redirectParams are the query keys applications most commonly trust when
// deciding where to send the browser next.
var redirectParams = []string{
	"url", "next", "redirect", "redirect_uri", "return", "return_to",
	"returnurl", "continue", "dest", "destination", "target", "redir",
	"goto", "callback", "redirect_url", "cb",
}

// redirectPaths are conventional endpoints that often honour a redirect
// parameter even when the landing page does not.
var redirectPaths = []string{
	"/redirect", "/login", "/logout", "/out", "/continue", "/return",
}

// probeHost is reserved (RFC 6761) so the payload can never resolve even
// if a browser follows it.
const probeHost = "ijiya-probe.invalid"

// maxRedirectFindings stops the check after enough evidence is collected.
const maxRedirectFindings = 3

func (redirectCheck) Run(ctx context.Context, t *Target) ([]Finding, error) {
	base := t.URL.String()
	probe := "https://" + probeHost + "/ijiya-open-redirect"

	// testOne sends name=probe on the given URL and returns a finding when
	// the application routes the browser to the probe host. Each path/param
	// pair is only tried once so the landing page and the discovery list
	// cannot report the same hit twice.
	testedKeys := map[string]bool{}
	testOne := func(rawurl, name string) *Finding {
		u, err := url.Parse(rawurl)
		if err != nil {
			return nil
		}
		key := u.Path + "\x00" + name
		if testedKeys[key] {
			return nil
		}
		testedKeys[key] = true

		q := u.Query()
		q.Set(name, probe)
		u.RawQuery = q.Encode()

		resp, err := t.Get(ctx, u.String(), true)
		if err != nil {
			return nil
		}

		switch {
		case resp.StatusCode >= 300 && resp.StatusCode < 400 &&
			strings.Contains(resp.Header.Get("Location"), probeHost):
			return &Finding{
				Severity: SeverityHigh,
				Title:    fmt.Sprintf("Open redirect via query parameter %q", name),
				URL:      resp.URL,
				Evidence: fmt.Sprintf("The endpoint answered %d and sent Location: %s", resp.StatusCode, resp.Header.Get("Location")),
				Remediation: "Allow-list redirect targets (same site paths or exact origins) instead of forwarding an arbitrary URL. " +
					"Reject values that do not start with a single '/' or match your allow-list.",
			}
		case resp.StatusCode >= 200 && resp.StatusCode < 300 && isClientSideRedirect(resp.BodyString(), probe):
			return &Finding{
				Severity:    SeverityMedium,
				Title:       fmt.Sprintf("Client-side open redirect via query parameter %q", name),
				URL:         resp.URL,
				Evidence:    fmt.Sprintf("The endpoint answered %d and its body routes the browser to %s.", resp.StatusCode, probeHost),
				Remediation: "Validate redirect targets against an allow-list before embedding them in meta refresh tags or location assignments.",
			}
		}
		return nil
	}

	// Test the parameters the page already uses first: they are far more
	// likely to be honoured than a key we invented.
	var candidates []string
	if q := t.URL.Query(); len(q) > 0 {
		for name := range q {
			if !isProtectedInput(name) {
				candidates = append(candidates, name)
			}
		}
	}
	candidates = append(candidates, redirectParams...)

	seen := map[string]bool{}
	var out []Finding

	for _, name := range candidates {
		if ctx.Err() != nil || len(out) >= maxRedirectFindings {
			break
		}
		if seen[name] {
			continue
		}
		seen[name] = true
		if f := testOne(base, name); f != nil {
			Emit(ctx, *f)
			out = append(out, *f)
		}
	}

	// Nothing on the landing page redirected, so look at the endpoints
	// that normally own redirect handling.
	for _, path := range redirectPaths {
		if ctx.Err() != nil || len(out) >= maxRedirectFindings {
			break
		}
		rawurl := t.Base() + path
		for _, name := range []string{"next", "url"} {
			if len(out) >= maxRedirectFindings {
				break
			}
			if f := testOne(rawurl, name); f != nil {
				Emit(ctx, *f)
				out = append(out, *f)
			}
		}
	}

	if len(out) == 0 {
		f := Finding{
			Severity:    SeverityInfo,
			Title:       "No open redirect detected on the tested inputs",
			URL:         base,
			Evidence:    fmt.Sprintf("Tested %d path/parameter combinations (landing page plus %d conventional redirect paths); probe host %s.", len(testedKeys), len(redirectPaths), probeHost),
			Remediation: "Keep validating redirect targets; new endpoints are the usual place this regresses.",
		}
		Emit(ctx, f)
		out = append(out, f)
	}

	return out, nil
}

// isClientSideRedirect reports whether a 200 response routes the browser to
// the probe host through JavaScript or a meta refresh.
func isClientSideRedirect(body, probe string) bool {
	if !strings.Contains(body, probeHost) {
		return false
	}
	lower := strings.ToLower(body)
	for _, marker := range []string{
		"http-equiv=\"refresh\"",
		"http-equiv='refresh'",
		"location.replace",
		"location.href",
		"window.location",
		"document.location",
	} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}
