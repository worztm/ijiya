package scan

import (
	"context"
	"net/url"
	"regexp"
	"strings"
)

// Vector is a single user-controllable input discovered on a page.
type Vector struct {
	Name   string     // input name
	Kind   string     // "query" or "form"
	Method string     // "GET" or "POST" for forms
	Action string     // URL the input is submitted to
	Value  string     // original value, kept for reference
	Form   url.Values // complete form payload, nil for query vectors
}

var (
	formRe  = regexp.MustCompile(`(?is)<form\b([^>]*)>(.*?)</form>`)
	inputRe = regexp.MustCompile(`(?is)<input\b([^>]*)>`)
	areaRe  = regexp.MustCompile(`(?is)<textarea\b([^>]*)>(.*?)</textarea>`)
	attrRe  = regexp.MustCompile(`(?i)([\w:.-]+)\s*=\s*("([^"]*)"|'([^']*)'|([^\s>]+))`)
)

// skipNames are anti-CSRF or integrity fields whose values must be left
// untouched, otherwise the request is rejected before our payload lands.
var skipNames = []string{
	"csrf", "xsrf", "_token", "token", "nonce", "authenticity_token",
	"__requestverificationtoken", "antiforgery", "hmac", "signature",
	"captcha", "recaptcha", "g-recaptcha",
}

// isProtectedInput reports whether an input carries an anti-abuse value
// that must not be replaced with a test payload.
func isProtectedInput(name string) bool {
	n := strings.ToLower(name)
	for _, s := range skipNames {
		if strings.Contains(n, s) {
			return true
		}
	}
	return false
}

// tagAttrs parses the attributes of a single HTML tag.
func tagAttrs(tag string) map[string]string {
	out := make(map[string]string, 6)
	for _, m := range attrRe.FindAllStringSubmatch(tag, -1) {
		key := strings.ToLower(m[1])
		val := m[3]
		if val == "" {
			val = m[4]
		}
		if val == "" {
			val = m[5]
		}
		out[key] = val
	}
	return out
}

// CollectVectors gathers the inputs a check should probe: every query
// parameter on the page plus the fields of any HTML forms. When
// includeForms is false only GET based forms are returned (the safe
// default; POST forms are gated behind --deep).
func CollectVectors(page *Response, includeForms bool) []Vector {
	if page == nil {
		return nil
	}
	seen := make(map[string]bool)
	out := make([]Vector, 0, 8)

	pageURL := page.URL
	u, err := url.Parse(pageURL)
	if err == nil {
		for name, vals := range u.Query() {
			if isProtectedInput(name) || seen["q:"+name] {
				continue
			}
			seen["q:"+name] = true
			val := ""
			if len(vals) > 0 {
				val = vals[0]
			}
			out = append(out, Vector{
				Name:   name,
				Kind:   "query",
				Method: "GET",
				Action: pageURL,
				Value:  val,
			})
		}
	}

	if !page.IsHTML() {
		return out
	}

	base, err := url.Parse(pageURL)
	if err != nil {
		return out
	}

	for _, fm := range formRe.FindAllStringSubmatch(string(page.Body), -1) {
		attrs := tagAttrs(fm[1])
		action, _ := attrs["action"]
		method := strings.ToUpper(attrs["method"])
		if method == "" {
			method = "GET"
		}
		if method != "GET" && method != "POST" {
			method = "GET"
		}
		if method == "POST" && !includeForms {
			continue
		}

		actionURL, err := resolveURL(base, action)
		if err != nil {
			continue
		}

		values := url.Values{}
		for _, in := range inputRe.FindAllStringSubmatch(fm[2], -1) {
			ia := tagAttrs(in[1])
			name := ia["name"]
			if name == "" {
				continue
			}
			values.Set(name, ia["value"])
		}
		for _, ta := range areaRe.FindAllStringSubmatch(fm[2], -1) {
			ia := tagAttrs(ta[1])
			name := ia["name"]
			if name == "" {
				continue
			}
			values.Set(name, unescapeEntities(ta[2]))
		}

		for name := range values {
			if isProtectedInput(name) || seen["f:"+actionURL+"?"+name] {
				continue
			}
			seen["f:"+actionURL+"?"+name] = true
			out = append(out, Vector{
				Name:   name,
				Kind:   "form",
				Method: method,
				Action: actionURL,
				Value:  values.Get(name),
				Form:   values,
			})
		}
	}

	return out
}

// resolveURL resolves a possibly relative form action against the page URL.
func resolveURL(base *url.URL, action string) (string, error) {
	action = strings.TrimSpace(action)
	if action == "" {
		return base.String(), nil
	}
	ref, err := url.Parse(action)
	if err != nil {
		return "", err
	}
	return base.ResolveReference(ref).String(), nil
}

// sendVector replays a vector's request with payload in place of its value.
func (t *Target) sendVector(ctx context.Context, v Vector, payload string) (*Response, error) {
	switch {
	case v.Kind == "query":
		u, err := url.Parse(v.Action)
		if err != nil {
			return nil, err
		}
		q := u.Query()
		q.Set(v.Name, payload)
		u.RawQuery = q.Encode()
		return t.Get(ctx, u.String(), false)

	case v.Method == "POST":
		data := url.Values{}
		for k, vs := range v.Form {
			data[k] = append([]string(nil), vs...)
		}
		data.Set(v.Name, payload)
		return t.PostForm(ctx, v.Action, data, false)

	default: // GET form
		u, err := url.Parse(v.Action)
		if err != nil {
			return nil, err
		}
		q := u.Query()
		for k, vs := range v.Form {
			q[k] = append([]string(nil), vs...)
		}
		q.Set(v.Name, payload)
		u.RawQuery = q.Encode()
		return t.Get(ctx, u.String(), false)
	}
}

// unescapeEntities decodes the handful of entities that commonly appear
// inside textarea bodies.
func unescapeEntities(s string) string {
	r := strings.NewReplacer(
		"&lt;", "<",
		"&gt;", ">",
		"&quot;", `"`,
		"&#39;", "'",
		"&amp;", "&",
	)
	return strings.TrimSpace(r.Replace(s))
}
