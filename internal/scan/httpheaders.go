package scan

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
)

// Header is a single extra HTTP header the user asked every request to carry.
// It exists mainly so authenticated areas can be scanned with a session
// cookie or bearer token, which is otherwise the biggest blind spot of a
// scanner that only sees what an anonymous visitor sees.
type Header struct {
	Name  string
	Value string
}

// ParseHeader splits a "Name: value" string as accepted by -H. The value may
// itself contain colons (an Origin or a URL, for example), so only the first
// one separates the name from the value.
func ParseHeader(spec string) (Header, error) {
	raw := strings.TrimSpace(spec)
	if raw == "" {
		return Header{}, fmt.Errorf("empty header (want \"Name: value\")")
	}
	i := strings.IndexByte(raw, ':')
	if i < 0 {
		return Header{}, fmt.Errorf("header %q has no colon (want \"Name: value\")", raw)
	}
	name := strings.TrimSpace(raw[:i])
	value := strings.TrimSpace(raw[i+1:])
	if name == "" {
		return Header{}, fmt.Errorf("header %q has an empty name", raw)
	}
	if !validHeaderName(name) {
		return Header{}, fmt.Errorf("header name %q contains characters that are not allowed in an HTTP field name", name)
	}
	// Values must not contain bare newlines; Go's HTTP client would reject
	// them anyway, but failing here gives a much clearer message.
	if strings.ContainsAny(value, "\r\n") {
		return Header{}, fmt.Errorf("header %q has a value containing a line break", name)
	}
	return Header{Name: name, Value: value}, nil
}

// ParseHeaders parses every -H occurrence, keeping only the first definition
// of a repeated name so an earlier explicit flag is never silently replaced.
func ParseHeaders(specs []string) ([]Header, error) {
	out := make([]Header, 0, len(specs))
	seen := make(map[string]bool, len(specs))
	for _, spec := range specs {
		h, err := ParseHeader(spec)
		if err != nil {
			return nil, err
		}
		key := http.CanonicalHeaderKey(h.Name)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, h)
	}
	return out, nil
}

// validHeaderName reports whether name is a legal HTTP field name (RFC 7230
// token characters). Go's own client is strict about this, but catching it in
// the CLI turns a confusing transport error into a clear usage message.
func validHeaderName(name string) bool {
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0:
		default:
			return false
		}
	}
	return true
}

// headerMap converts a parsed header list into the map the transport applies.
// Later duplicates have already been dropped by ParseHeaders.
func headerMap(headers []Header) map[string]string {
	if len(headers) == 0 {
		return nil
	}
	out := make(map[string]string, len(headers))
	for _, h := range headers {
		out[http.CanonicalHeaderKey(h.Name)] = h.Value
	}
	return out
}

// SortedHeaderNames lists the configured header names for display, without
// their values: a session cookie or API key must never be echoed back into a
// report that may be shared or committed.
func SortedHeaderNames(headers []Header) []string {
	names := make([]string, 0, len(headers))
	for _, h := range headers {
		names = append(names, http.CanonicalHeaderKey(h.Name))
	}
	sort.Strings(names)
	return names
}
