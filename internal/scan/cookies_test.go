package scan

import (
	"testing"
)

func TestParseSetCookie(t *testing.T) {
	c := parseSetCookie("session_id=abc123; Path=/; HttpOnly; Secure; SameSite=Lax")
	if c.Name != "session_id" || c.Value != "abc123" {
		t.Fatalf("got name=%q value=%q", c.Name, c.Value)
	}
	if c.Attrs["path"] != "/" {
		t.Errorf("path attr = %q", c.Attrs["path"])
	}
	if !c.Flags["httponly"] || !c.Flags["secure"] {
		t.Errorf("flags = %v, want httponly and secure", c.Flags)
	}
	if c.Attrs["samesite"] != "Lax" {
		t.Errorf("samesite = %q", c.Attrs["samesite"])
	}
	if !c.isSession() {
		t.Error("session_id should be recognised as a session cookie")
	}
}

func TestParseSetCookieMinimal(t *testing.T) {
	c := parseSetCookie("theme=dark")
	if c.Name != "theme" || c.Value != "dark" {
		t.Fatalf("got name=%q value=%q", c.Name, c.Value)
	}
	if c.Flags["httponly"] || c.Flags["secure"] {
		t.Error("no flags were set, but some were parsed")
	}
	if c.isSession() {
		t.Error("theme should not be treated as a session cookie")
	}
}

func TestRedactCookieHidesValue(t *testing.T) {
	c := parseSetCookie("session_id=super-secret-value; Path=/; HttpOnly")
	out := redactCookie(c)
	if out == "" {
		t.Fatal("empty output")
	}
	for _, banned := range []string{"super-secret-value"} {
		if contains(out, banned) {
			t.Errorf("redacted cookie still contains %q: %s", banned, out)
		}
	}
	if !contains(out, "session_id=[redacted]") {
		t.Errorf("expected a redacted placeholder, got %s", out)
	}
	if !contains(out, "httponly") {
		t.Errorf("attributes should survive redaction, got %s", out)
	}
}

// contains is a tiny local helper so the test does not depend on the
// production package's string helpers.
func contains(hay, needle string) bool {
	return len(needle) == 0 || (len(hay) >= len(needle) && indexOf(hay, needle) >= 0)
}

func indexOf(hay, needle string) int {
	for i := 0; i+len(needle) <= len(hay); i++ {
		if hay[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}
