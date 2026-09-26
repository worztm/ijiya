package scan

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// recommendedHSTS is Mozilla's recommended max-age in seconds (180 days).
const recommendedHSTS int64 = 15552000

type headersCheck struct{}

func (headersCheck) ID() string         { return "headers" }
func (headersCheck) Name() string       { return "Security headers" }
func (headersCheck) Category() Category { return CategoryHeaders }

func (headersCheck) Run(ctx context.Context, t *Target) ([]Finding, error) {
	resp, err := t.Get(ctx, t.URL.String(), false)
	if err != nil {
		return nil, err
	}
	h := resp.Header

	scheme := t.URL.Scheme
	if u, err := url.Parse(resp.URL); err == nil && u != nil && u.Scheme != "" {
		scheme = u.Scheme
	}

	var out []Finding
	add := func(sev Severity, title, evidence, fix string) {
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

	// --- Strict-Transport-Security -------------------------------------
	hsts := hv(h, "Strict-Transport-Security")
	if hsts == "" {
		evidence := "Browsers are not told to force HTTPS for this host, so a network attacker can downgrade the first request to plain HTTP."
		if scheme != "https" {
			evidence = "This response arrived over plain HTTP (" + scheme + "://) and carries no HSTS header, so nothing pins the connection to HTTPS."
		}
		add(SeverityMedium,
			"Strict-Transport-Security (HSTS) header missing",
			evidence,
			"Serve the site over HTTPS and send `Strict-Transport-Security: max-age=31536000; includeSubDomains` from every HTTPS response.")
	} else {
		lower := strings.ToLower(hsts)
		maxAge, ok := parseMaxAge(lower)
		switch {
		case !ok:
			add(SeverityMedium,
				"HSTS header has no valid max-age directive",
				"Header value: "+hsts+" - browsers ignore HSTS without max-age.",
				"Add `max-age=31536000` to the Strict-Transport-Security header.")
		case maxAge == 0:
			add(SeverityMedium,
				"HSTS max-age is 0, which disables HSTS",
				"Header value: "+hsts,
				"Set max-age to at least 15552000 (180 days), ideally 31536000 (1 year).")
		case maxAge < recommendedHSTS:
			add(SeverityLow,
				fmt.Sprintf("HSTS max-age is only %d days", maxAge/86400),
				fmt.Sprintf("Header value: %s (recommended: %d seconds / 180 days)", hsts, recommendedHSTS),
				"Raise max-age to at least 15552000 seconds.")
		}
		if ok && maxAge >= recommendedHSTS && !strings.Contains(lower, "includesubdomains") {
			add(SeverityLow,
				"HSTS does not apply to subdomains",
				"Header value: "+hsts,
				"Add `includeSubDomains` so every subdomain inherits the HSTS policy.")
		}
	}

	// --- Content-Security-Policy ---------------------------------------
	csp := hv(h, "Content-Security-Policy")
	dirs := map[string][]string{}
	if csp != "" {
		dirs = parseDirectives(csp)
	}
	if csp == "" {
		add(SeverityMedium,
			"Content-Security-Policy (CSP) header missing",
			"The browser will load scripts, styles, images and frames from anywhere, so a single injected tag becomes a full XSS.",
			"Start with `Content-Security-Policy: default-src 'self'; object-src 'none'; base-uri 'self'` and tighten it from report-only mode.")
	} else {
		scriptSrc := dirs["script-src"]
		if len(scriptSrc) == 0 {
			scriptSrc = dirs["default-src"]
		}
		if hasToken(scriptSrc, "'unsafe-inline'") {
			add(SeverityMedium,
				"CSP allows inline scripts ('unsafe-inline')",
				"script-src/default-src: "+strings.Join(scriptSrc, " "),
				"Remove 'unsafe-inline' and move inline code into external files or nonces.")
		}
		if hasToken(scriptSrc, "'unsafe-eval'") {
			add(SeverityMedium,
				"CSP allows eval() ('unsafe-eval')",
				"script-src/default-src: "+strings.Join(scriptSrc, " "),
				"Remove 'unsafe-eval'; it lets injected code execute arbitrary strings.")
		}
		if hasToken(scriptSrc, "*") {
			add(SeverityMedium,
				"CSP script sources use a wildcard",
				"script-src/default-src: "+strings.Join(scriptSrc, " "),
				"Replace `*` with an explicit allow-list of origins.")
		}
		if hasToken(scriptSrc, "data:") {
			add(SeverityLow,
				"CSP allows data: URIs as script sources",
				"script-src/default-src: "+strings.Join(scriptSrc, " "),
				"Drop `data:` from script-src; attackers can smuggle script through data URIs.")
		}
		if _, ok := dirs["default-src"]; !ok {
			add(SeverityLow,
				"CSP has no default-src fallback",
				"Directives present: "+strings.Join(directiveNames(csp), ", "),
				"Add `default-src 'self'` so unlisted resource types are restricted too.")
		}
	}

	// --- X-Content-Type-Options ----------------------------------------
	xcto := strings.TrimSpace(hv(h, "X-Content-Type-Options"))
	switch {
	case xcto == "":
		add(SeverityMedium,
			"X-Content-Type-Options header missing",
			"Browsers may MIME-sniff responses, turning an uploaded file or JSON payload into executable content.",
			"Send `X-Content-Type-Options: nosniff`.")
	case !strings.EqualFold(xcto, "nosniff"):
		add(SeverityLow,
			"X-Content-Type-Options is not set to nosniff",
			"Header value: "+xcto,
			"The only valid value is `nosniff`.")
	}

	// --- Clickjacking: X-Frame-Options / frame-ancestors ----------------
	xfo := strings.TrimSpace(hv(h, "X-Frame-Options"))
	hasFA := len(dirs["frame-ancestors"]) > 0
	switch {
	case xfo == "" && !hasFA:
		add(SeverityMedium,
			"No clickjacking protection (missing X-Frame-Options and frame-ancestors)",
			"The page can be framed by any origin, letting an attacker overlay it with a transparent iframe.",
			"Add `frame-ancestors 'none'` to CSP (or `X-Frame-Options: DENY` for older browsers).")
	case xfo != "":
		v := strings.ToUpper(xfo)
		if v != "DENY" && v != "SAMEORIGIN" && !strings.Contains(v, "ALLOW-FROM") {
			add(SeverityLow,
				"X-Frame-Options has an unrecognised value",
				"Header value: "+xfo,
				"Use `DENY` or `SAMEORIGIN`.")
		}
	}

	// --- Referrer-Policy -----------------------------------------------
	rp := strings.TrimSpace(hv(h, "Referrer-Policy"))
	switch {
	case rp == "":
		add(SeverityLow,
			"Referrer-Policy header missing",
			"Full URLs (including query strings and IDs) may leak to third-party origins via the Referer header.",
			"Send `Referrer-Policy: strict-origin-when-cross-origin`.")
	case strings.EqualFold(rp, "unsafe-url") || strings.EqualFold(rp, "no-referrer-when-downgrade"):
		add(SeverityLow,
			"Referrer-Policy is too permissive",
			"Header value: "+rp,
			"Use `strict-origin-when-cross-origin` instead.")
	}

	// --- Permissions-Policy --------------------------------------------
	if strings.TrimSpace(hv(h, "Permissions-Policy")) == "" && strings.TrimSpace(hv(h, "Feature-Policy")) == "" {
		add(SeverityLow,
			"Permissions-Policy header missing",
			"Embedded content can still use powerful browser features (camera, microphone, geolocation, accelerometer).",
			"Send `Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()`.")
	}

	// --- Legacy XSS filter ---------------------------------------------
	if xss := strings.TrimSpace(hv(h, "X-XSS-Protection")); xss != "" {
		if strings.HasPrefix(xss, "0") {
			add(SeverityInfo,
				"X-XSS-Protection is explicitly disabled",
				"Header value: "+xss,
				"This is the modern recommendation: keep CSP strict instead of relying on the deprecated filter.")
		} else {
			add(SeverityInfo,
				"Legacy X-XSS-Protection header is still sent",
				"Header value: "+xss,
				"The header is deprecated and can introduce its own bugs; prefer CSP and remove it.")
		}
	}

	// --- Cross-origin isolation ----------------------------------------
	if coop := strings.TrimSpace(hv(h, "Cross-Origin-Opener-Policy")); coop == "" {
		add(SeverityInfo,
			"Cross-Origin-Opener-Policy (COOP) header missing",
			"This window can still interact with cross-origin popups, which weakens cross-origin isolation.",
			"Send `Cross-Origin-Opener-Policy: same-origin` if you do not need cross-origin windows.")
	} else if !strings.EqualFold(coop, "same-origin") && !strings.EqualFold(coop, "same-origin-allow-popups") {
		add(SeverityInfo,
			"Cross-Origin-Opener-Policy is not restrictive",
			"Header value: "+coop,
			"Use `same-origin` (or `same-origin-allow-popups` when popups are required).")
	}
	if corp := strings.TrimSpace(hv(h, "Cross-Origin-Resource-Policy")); corp == "" {
		add(SeverityInfo,
			"Cross-Origin-Resource-Policy (CORP) header missing",
			"Responses can be embedded by any cross-origin document, widening the impact of a CORS mistake.",
			"Send `Cross-Origin-Resource-Policy: same-origin` on sensitive responses.")
	}

	return out, nil
}

// parseMaxAge extracts the max-age value from an HSTS header.
func parseMaxAge(v string) (int64, bool) {
	i := strings.Index(v, "max-age=")
	if i < 0 {
		return 0, false
	}
	rest := v[i+len("max-age="):]
	j := 0
	for j < len(rest) && rest[j] >= '0' && rest[j] <= '9' {
		j++
	}
	if j == 0 {
		return 0, false
	}
	n, err := strconv.ParseInt(rest[:j], 10, 64)
	if err != nil {
		return 0, false
	}
	return n, true
}

// parseDirectives turns a CSP header into directive -> value tokens.
func parseDirectives(csp string) map[string][]string {
	out := map[string][]string{}
	for _, part := range strings.Split(csp, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		fields := strings.Fields(part)
		if len(fields) == 0 {
			continue
		}
		name := strings.ToLower(fields[0])
		out[name] = append(out[name], fields[1:]...)
	}
	return out
}

// directiveNames lists CSP directives in the order they appear.
func directiveNames(csp string) []string {
	var names []string
	seen := map[string]bool{}
	for _, part := range strings.Split(csp, ";") {
		fields := strings.Fields(strings.TrimSpace(part))
		if len(fields) == 0 {
			continue
		}
		n := strings.ToLower(fields[0])
		if !seen[n] {
			seen[n] = true
			names = append(names, n)
		}
	}
	return names
}

// hasToken reports whether a source list contains an exact token.
func hasToken(list []string, token string) bool {
	for _, v := range list {
		if v == token {
			return true
		}
	}
	return false
}
