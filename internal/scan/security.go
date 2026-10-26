package scan

import (
	"net/url"
	"regexp"
	"strings"
)

// sensitiveQueryKeys are common names for credentials that should not be
// copied into a report or a CI log. Query strings are frequently included in
// URLs even when authentication is supplied through a browser redirect.
var sensitiveQueryKeys = map[string]bool{
	"access_token": true, "apikey": true, "api_key": true, "auth": true,
	"authorization": true, "code": true, "credential": true, "credentials": true,
	"id_token": true, "jwt": true, "key": true, "password": true,
	"passwd": true, "pass": true, "refresh_token": true, "secret": true,
	"session": true, "sessionid": true, "sid": true, "sig": true,
	"signature": true, "token": true, "user_token": true,
}

// RedactURL removes credentials from a URL while preserving its useful path
// and non-sensitive query parameters. It is safe to call on an empty or
// malformed URL, which is useful for report data assembled by checks.
func RedactURL(raw string) string {
	if raw == "" {
		return raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	if u.User != nil {
		if _, ok := u.User.Password(); ok {
			u.User = url.UserPassword(u.User.Username(), "REDACTED")
		}
	}
	if u.RawQuery != "" {
		parts := strings.Split(u.RawQuery, "&")
		for i, part := range parts {
			key := part
			if eq := strings.IndexByte(part, '='); eq >= 0 {
				key = part[:eq]
			}
			decoded, err := url.QueryUnescape(key)
			if err != nil {
				decoded = key
			}
			if sensitiveQueryKeys[normaliseQueryKey(decoded)] {
				parts[i] = key + "=REDACTED"
			}
		}
		u.RawQuery = strings.Join(parts, "&")
	}
	// Fragments are not sent in HTTP requests, but they often carry OAuth
	// tokens and are routinely pasted into logs, so do not retain them.
	if u.Fragment != "" {
		u.Fragment = "REDACTED"
	}
	return u.String()
}

func normaliseQueryKey(key string) string {
	return strings.ToLower(strings.ReplaceAll(strings.TrimSpace(key), "-", "_"))
}

var urlTokenRe = regexp.MustCompile(`https?://[^\s"'<>]+`)

// RedactTextURLs applies RedactURL to URLs embedded in evidence strings.
// This closes the less obvious leak where a check mentions a redirect target
// in prose rather than storing it in Finding.URL.
func RedactTextURLs(text string) string {
	return urlTokenRe.ReplaceAllStringFunc(text, func(token string) string {
		trimmed := strings.TrimRight(token, ".,;:!?)]}")
		suffix := token[len(trimmed):]
		return RedactURL(trimmed) + suffix
	})
}
