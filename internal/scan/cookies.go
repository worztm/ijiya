package scan

import (
	"context"
	"fmt"
	"strings"
)

type cookiesCheck struct{}

func (cookiesCheck) ID() string         { return "cookies" }
func (cookiesCheck) Name() string       { return "Cookie security" }
func (cookiesCheck) Category() Category { return CategoryCookies }

// sessionHints are cookie names that carry an authenticated session.
var sessionHints = []string{
	"session", "sess", "sid", "auth", "token", "jwt", "user", "login",
	"phpsessid", "jsessionid", "asp.net_sessionid", "connect.sid",
	"_identity", "remember", "access",
}

// cookie is a parsed Set-Cookie header.
type cookie struct {
	Name  string
	Value string
	Attrs map[string]string
	Flags map[string]bool
}

// isSession reports whether the cookie likely holds a session identifier.
func (c cookie) isSession() bool {
	n := strings.ToLower(c.Name)
	for _, h := range sessionHints {
		if strings.Contains(n, h) {
			return true
		}
	}
	return false
}

func (cookiesCheck) Run(ctx context.Context, t *Target) ([]Finding, error) {
	resp, err := t.Get(ctx, t.URL.String(), false)
	if err != nil {
		return nil, err
	}

	raw := resp.Header.Values("Set-Cookie")
	if len(raw) == 0 {
		return nil, nil // no cookies set, nothing to harden here
	}

	var out []Finding
	seen := map[string]bool{}

	for _, line := range raw {
		c := parseSetCookie(line)
		if c.Name == "" || seen[c.Name] {
			continue
		}
		seen[c.Name] = true

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

		quoted := fmt.Sprintf("%q", c.Name)

		if !c.Flags["secure"] {
			sev := SeverityMedium
			if c.isSession() {
				sev = SeverityHigh
			}
			add(sev,
				"Cookie "+quoted+" is missing the Secure flag",
				"Set-Cookie: "+redactCookie(c),
				"Add `Secure` so the cookie is only ever sent over HTTPS.")
		}

		if !c.Flags["httponly"] {
			sev := SeverityMedium
			if c.isSession() {
				sev = SeverityHigh
			}
			add(sev,
				"Cookie "+quoted+" is missing the HttpOnly flag",
				"Set-Cookie: "+redactCookie(c),
				"Add `HttpOnly` so injected JavaScript cannot read the cookie through document.cookie.")
		}

		sameSite := strings.ToLower(c.Attrs["samesite"])
		switch {
		case sameSite == "" && !c.Flags["samesite"]:
			add(SeverityLow,
				"Cookie "+quoted+" has no SameSite attribute",
				"Set-Cookie: "+redactCookie(c),
				"Add `SameSite=Lax` (or `Strict`) to block cross-site request forgery.")
		case sameSite == "none" && !c.Flags["secure"]:
			add(SeverityMedium,
				"Cookie "+quoted+" uses SameSite=None without Secure",
				"Set-Cookie: "+redactCookie(c),
				"Modern browsers reject SameSite=None unless the Secure flag is also set.")
		case sameSite == "none":
			add(SeverityLow,
				"Cookie "+quoted+" allows cross-site sending (SameSite=None)",
				"Set-Cookie: "+redactCookie(c),
				"Prefer SameSite=Lax unless a genuine cross-site flow needs it.")
		}

		if len(c.Attrs) == 0 {
			continue
		}
		if age, ok := c.Attrs["max-age"]; ok && age == "0" {
			add(SeverityInfo,
				"Cookie "+quoted+" is being cleared (Max-Age=0)",
				"Set-Cookie: "+redactCookie(c),
				"This is normal for logout; no action needed.")
		}
	}

	return out, nil
}

// parseSetCookie splits a Set-Cookie header into name, value and attributes.
func parseSetCookie(line string) cookie {
	c := cookie{Attrs: map[string]string{}, Flags: map[string]bool{}}
	parts := strings.Split(line, ";")
	if len(parts) == 0 {
		return c
	}
	if kv := strings.SplitN(parts[0], "=", 2); len(kv) == 2 {
		c.Name = strings.TrimSpace(kv[0])
		c.Value = strings.TrimSpace(kv[1])
	}
	for _, p := range parts[1:] {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if kv := strings.SplitN(p, "=", 2); len(kv) == 2 {
			key := strings.ToLower(strings.TrimSpace(kv[0]))
			c.Attrs[key] = strings.TrimSpace(kv[1])
		} else {
			c.Flags[strings.ToLower(p)] = true
		}
	}
	return c
}

// redactCookie renders a cookie header without its (potentially secret)
// value so reports stay safe to share.
func redactCookie(c cookie) string {
	attrs := make([]string, 0, len(c.Attrs)+len(c.Flags))
	for k, v := range c.Attrs {
		attrs = append(attrs, k+"="+v)
	}
	for k := range c.Flags {
		attrs = append(attrs, k)
	}
	suffix := ""
	if len(attrs) > 0 {
		suffix = "; " + strings.Join(attrs, "; ")
	}
	return c.Name + "=[redacted]" + suffix
}
