package scan

import (
	"net/http"
	"testing"
)

func TestIsProtectedInput(t *testing.T) {
	protected := []string{"csrf", "csrf_token", "authenticity_token", "api_token", "nonce", "hmac", "g-recaptcha-response"}
	for _, n := range protected {
		if !isProtectedInput(n) {
			t.Errorf("%q should be treated as a protected input", n)
		}
	}
	ordinary := []string{"q", "search", "term", "id", "redirect", "page"}
	for _, n := range ordinary {
		if isProtectedInput(n) {
			t.Errorf("%q should be testable", n)
		}
	}
}

func testPage(body string) *Response {
	return &Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"text/html; charset=utf-8"}},
		URL:        "https://example.com/search?q=shoes&page=2",
		Body:       []byte(body),
	}
}

const samplePage = `<!doctype html>
<html><body>
<form method="get" action="/find">
  <input type="text" name="term" value="x">
  <input type="hidden" name="csrf_token" value="abc123">
</form>
<form method="post" action="/login">
  <input type="text" name="username" value="">
  <input type="password" name="password" value="">
</form>
</body></html>`

func TestCollectVectorsQueryOnly(t *testing.T) {
	vectors := CollectVectors(testPage(samplePage), false)

	got := map[string]string{}
	for _, v := range vectors {
		got[v.Name] = v.Kind
	}

	for _, want := range []string{"q", "page", "term"} {
		if _, ok := got[want]; !ok {
			t.Errorf("expected vector %q, got %v", want, got)
		}
	}
	if _, ok := got["csrf_token"]; ok {
		t.Error("csrf_token must never be overwritten")
	}
	if _, ok := got["password"]; ok {
		t.Error("POST fields must be excluded unless includeForms is set")
	}
	if _, ok := got["username"]; ok {
		t.Error("POST fields must be excluded unless includeForms is set")
	}
}

func TestCollectVectorsWithPostForms(t *testing.T) {
	vectors := CollectVectors(testPage(samplePage), true)
	got := map[string]bool{}
	for _, v := range vectors {
		got[v.Name] = true
	}
	if !got["username"] || !got["password"] {
		t.Errorf("deep mode should include POST fields, got %v", got)
	}
	if got["csrf_token"] {
		t.Error("csrf_token must never be overwritten")
	}
}

func TestCollectVectorsFormActionResolution(t *testing.T) {
	vectors := CollectVectors(testPage(samplePage), false)
	for _, v := range vectors {
		if v.Kind != "form" {
			continue
		}
		if v.Action != "https://example.com/find" {
			t.Errorf("relative action not resolved: got %q", v.Action)
		}
		if v.Method != "GET" {
			t.Errorf("form method = %q, want GET", v.Method)
		}
	}
}

func TestCollectVectorsSkipsNonHTML(t *testing.T) {
	page := &Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		URL:        "https://example.com/api?x=1",
		Body:       []byte(`{"ok":true}`),
	}
	vectors := CollectVectors(page, true)
	if len(vectors) != 1 || vectors[0].Name != "x" {
		t.Errorf("expected only the query vector, got %+v", vectors)
	}
}
