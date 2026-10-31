package scan

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSeverityJSONRejectsOutOfRangeRank(t *testing.T) {
	for _, raw := range []string{"-1", "5", "99"} {
		t.Run(raw, func(t *testing.T) {
			var got Severity
			if err := json.Unmarshal([]byte(raw), &got); err == nil {
				t.Fatalf("accepted invalid severity rank %s as %v", raw, got)
			}
		})
	}
}

func TestSeverityJSONAcceptsValidRank(t *testing.T) {
	var got Severity
	if err := json.Unmarshal([]byte("3"), &got); err != nil {
		t.Fatalf("decode severity: %v", err)
	}
	if got != SeverityHigh {
		t.Fatalf("severity = %v, want high", got)
	}
}

func TestRedactURLRemovesCredentialLikeValues(t *testing.T) {
	got := RedactURL("https://user:password@example.com/path?keep=yes&access_token=abc123&client-id=public#token")
	for _, leaked := range []string{"password", "abc123", "#token"} {
		if strings.Contains(got, leaked) {
			t.Fatalf("RedactURL leaked %q in %q", leaked, got)
		}
	}
	for _, want := range []string{"user:REDACTED@", "keep=yes", "access_token=REDACTED", "client-id=public", "#REDACTED"} {
		if !strings.Contains(got, want) {
			t.Errorf("RedactURL(%q) = %q, missing %q", "credential URL", got, want)
		}
	}
}

func TestRedactTextURLs(t *testing.T) {
	got := RedactTextURLs("redirected to https://example.com/callback?code=secret123, then continued")
	if strings.Contains(got, "secret123") || !strings.Contains(got, "code=REDACTED") {
		t.Fatalf("RedactTextURLs = %q", got)
	}
}

func TestExternalRedirectsBlockedByDefault(t *testing.T) {
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("destination"))
	}))
	defer destination.Close()

	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, destination.URL, http.StatusFound)
	}))
	defer source.Close()

	blocked, err := NewTarget(source.URL, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := blocked.Get(context.Background(), source.URL, false); err == nil || !strings.Contains(err.Error(), "external redirect blocked") {
		t.Fatalf("default redirect policy error = %v", err)
	}

	allowed, err := NewTarget(source.URL, Options{AllowExternalRedirects: true})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := allowed.Get(context.Background(), source.URL, false)
	if err != nil {
		t.Fatalf("allowed redirect failed: %v", err)
	}
	if string(resp.Body) != "destination" {
		t.Fatalf("allowed redirect body = %q", resp.Body)
	}
}
