package scan

import (
	"testing"
)

func TestParseMaxAge(t *testing.T) {
	cases := []struct {
		in   string
		want int64
		ok   bool
	}{
		{"max-age=31536000", 31536000, true},
		{"max-age=31536000; includesubdomains", 31536000, true},
		{"max-age=0", 0, true},
		{"max-age=15552000; preload", 15552000, true},
		{"includesubdomains", 0, false},
		{"max-age=", 0, false},
		{"max-age=abc", 0, false},
		{"", 0, false},
	}
	for _, c := range cases {
		got, ok := parseMaxAge(c.in)
		if ok != c.ok || (ok && got != c.want) {
			t.Errorf("parseMaxAge(%q) = (%d, %v), want (%d, %v)", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestParseDirectives(t *testing.T) {
	csp := "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.example.com; object-src 'none'"
	dirs := parseDirectives(csp)

	if _, ok := dirs["default-src"]; !ok {
		t.Fatal("default-src missing")
	}
	if !hasToken(dirs["script-src"], "'unsafe-inline'") {
		t.Error("expected 'unsafe-inline' in script-src")
	}
	if hasToken(dirs["script-src"], "'unsafe-eval'") {
		t.Error("did not expect 'unsafe-eval' in script-src")
	}
	if !hasToken(dirs["script-src"], "https://cdn.example.com") {
		t.Error("expected the CDN origin in script-src")
	}
	if !hasToken(dirs["object-src"], "'none'") {
		t.Error("expected 'none' in object-src")
	}

	names := directiveNames(csp)
	if len(names) != 3 {
		t.Errorf("directiveNames = %v, want 3 entries", names)
	}
}

func TestHasTokenIsExact(t *testing.T) {
	list := []string{"'self'", "'unsafe-inline'"}
	if hasToken(list, "unsafe-inline") {
		t.Error("token match must include the quotes")
	}
	if !hasToken(list, "'self'") {
		t.Error("exact token not found")
	}
}

func TestSeverityParsingAndRanking(t *testing.T) {
	for _, name := range []string{"info", "informational", "low", "medium", "high", "critical"} {
		if _, err := ParseSeverity(name); err != nil {
			t.Errorf("ParseSeverity(%q) failed: %v", name, err)
		}
	}
	if _, err := ParseSeverity("purple"); err == nil {
		t.Error("expected an error for an unknown severity")
	}
	if !(SeverityCritical > SeverityHigh && SeverityHigh > SeverityMedium &&
		SeverityMedium > SeverityLow && SeverityLow > SeverityInfo) {
		t.Error("severities must rank critical > high > medium > low > info")
	}
	if !SeverityHigh.AtLeast(SeverityMedium) || SeverityLow.AtLeast(SeverityMedium) {
		t.Error("AtLeast ranking is wrong")
	}
}

func TestRelativeDelta(t *testing.T) {
	if d := relativeDelta(100, 100); d != 0 {
		t.Errorf("identical values should delta to 0, got %v", d)
	}
	if d := relativeDelta(100, 50); d != 0.5 {
		t.Errorf("relativeDelta(100,50) = %v, want 0.5", d)
	}
	if d := relativeDelta(0, 0); d != 0 {
		t.Errorf("relativeDelta(0,0) = %v, want 0", d)
	}
}
