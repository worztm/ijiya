package scan

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"
)

func TestParseHeader(t *testing.T) {
	cases := []struct {
		spec      string
		wantName  string
		wantValue string
		wantErr   bool
	}{
		{spec: "Authorization: Bearer abc.def", wantName: "Authorization", wantValue: "Bearer abc.def"},
		{spec: "Cookie: session=1; theme=dark", wantName: "Cookie", wantValue: "session=1; theme=dark"},
		{spec: "  X-Api-Key :  secret  ", wantName: "X-Api-Key", wantValue: "secret"},
		// The value may contain colons: only the first one separates.
		{spec: "X-Forwarded-For: 127.0.0.1:8080", wantName: "X-Forwarded-For", wantValue: "127.0.0.1:8080"},
		{spec: "Referer: https://example.com/a?b=c", wantName: "Referer", wantValue: "https://example.com/a?b=c"},
		{spec: "", wantErr: true},
		{spec: "   ", wantErr: true},
		{spec: "NoColonHere", wantErr: true},
		{spec: ": empty name", wantErr: true},
		{spec: "Bad Name: value", wantErr: true},
		{spec: "X-Test: two\nlines", wantErr: true},
	}
	for _, c := range cases {
		got, err := ParseHeader(c.spec)
		if c.wantErr {
			if err == nil {
				t.Errorf("ParseHeader(%q) succeeded, want an error", c.spec)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseHeader(%q) failed: %v", c.spec, err)
			continue
		}
		if got.Name != c.wantName || got.Value != c.wantValue {
			t.Errorf("ParseHeader(%q) = (%q, %q), want (%q, %q)",
				c.spec, got.Name, got.Value, c.wantName, c.wantValue)
		}
	}
}

func TestParseHeadersDropsDuplicates(t *testing.T) {
	headers, err := ParseHeaders([]string{
		"Cookie: first=1",
		"cookie: second=2", // same name, different case
		"X-Api-Key: k",
	})
	if err != nil {
		t.Fatalf("ParseHeaders failed: %v", err)
	}
	if len(headers) != 2 {
		t.Fatalf("got %d headers, want 2: %+v", len(headers), headers)
	}
	m := headerMap(headers)
	if m["Cookie"] != "first=1" {
		t.Errorf("Cookie = %q, want the first definition to win", m["Cookie"])
	}
}

func TestSortedHeaderNamesOmitsValues(t *testing.T) {
	names := SortedHeaderNames([]Header{
		{Name: "cookie", Value: "session=topsecret"},
		{Name: "X-Api-Key", Value: "topsecret"},
	})
	want := []string{"Cookie", "X-Api-Key"}
	if strings.Join(names, ",") != strings.Join(want, ",") {
		t.Errorf("SortedHeaderNames = %v, want %v", names, want)
	}
	if !sort.StringsAreSorted(names) {
		t.Errorf("names are not sorted: %v", names)
	}
	for _, n := range names {
		if strings.Contains(n, "topsecret") {
			t.Fatalf("header value leaked into the display name %q", n)
		}
	}
}

// TestCustomHeadersAreSent proves the -H plumbing reaches the wire, including
// overriding the built-in User-Agent.
func TestCustomHeadersAreSent(t *testing.T) {
	var got http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><body>ok</body></html>"))
	}))
	defer srv.Close()

	target, err := NewTarget(srv.URL, Options{
		Timeout: 5 * time.Second,
		Headers: []Header{
			{Name: "Cookie", Value: "session=abc"},
			{Name: "X-Api-Key", Value: "k123"},
			{Name: "User-Agent", Value: "custom-agent/9"},
			{Name: "Accept", Value: "application/json"},
		},
	})
	if err != nil {
		t.Fatalf("NewTarget: %v", err)
	}
	if _, err := target.Get(context.Background(), target.URL.String(), false); err != nil {
		t.Fatalf("Get: %v", err)
	}

	for name, want := range map[string]string{
		"Cookie":     "session=abc",
		"X-Api-Key":  "k123",
		"User-Agent": "custom-agent/9",
		"Accept":     "application/json",
	} {
		if got.Get(name) != want {
			t.Errorf("%s = %q, want %q", name, got.Get(name), want)
		}
	}
}

func TestDefaultUserAgentUsesVersion(t *testing.T) {
	target, err := NewTarget("https://example.com", Options{})
	if err != nil {
		t.Fatalf("NewTarget: %v", err)
	}
	if !strings.HasPrefix(target.Opts.UserAgent, "ijiya/") {
		t.Errorf("default User-Agent = %q, want it to start with ijiya/", target.Opts.UserAgent)
	}
}

func TestRateLimiterSpacesRequests(t *testing.T) {
	// 20 requests per second is a 50ms slot: the second reservation must
	// wait for it.
	l := newLimiter(20)
	start := time.Now()
	if !l.wait(context.Background()) {
		t.Fatal("first wait was cancelled")
	}
	if !l.wait(context.Background()) {
		t.Fatal("second wait was cancelled")
	}
	if elapsed := time.Since(start); elapsed < 30*time.Millisecond {
		t.Errorf("two waits took %s, want the second one to be throttled", elapsed)
	}
}

func TestRateLimiterDisabledAndCancelled(t *testing.T) {
	if l := newLimiter(0); l != nil {
		t.Error("rate 0 must disable the limiter")
	}
	if l := newLimiter(-5); l != nil {
		t.Error("a negative rate must disable the limiter")
	}
	// A cancelled context must not leave a scan waiting for a slot.
	l := newLimiter(0.01) // one request every 100 seconds
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if l.wait(ctx) {
		t.Error("wait returned true on a cancelled context")
	}
}
