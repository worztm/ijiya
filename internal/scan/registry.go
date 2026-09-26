package scan

import (
	"fmt"
	"sort"
	"strings"
)

// Available returns every check in report order.
func Available() []Check {
	return []Check{
		headersCheck{},
		cookiesCheck{},
		tlsCheck{},
		corsCheck{},
		xssCheck{},
		sqliCheck{},
		disclosureCheck{},
		redirectCheck{},
	}
}

// aliases maps short and alternate names onto canonical check IDs.
var aliases = map[string]string{
	"header":       "headers",
	"http":         "headers",
	"cookie":       "cookies",
	"ssl":          "tls",
	"https":        "tls",
	"cert":         "tls",
	"certificate":  "tls",
	"cors":         "cors",
	"xss":          "xss",
	"sqli":         "sqli",
	"sql":          "sqli",
	"injection":    "sqli",
	"info":         "disclosure",
	"leak":         "disclosure",
	"leaks":        "disclosure",
	"secret":       "disclosure",
	"secrets":      "disclosure",
	"redirect":     "redirect",
	"openredirect": "redirect",
	"url":          "redirect",
}

// Select resolves a comma separated selection such as "all" or
// "headers,xss" into an ordered list of checks.
func Select(spec string) ([]Check, error) {
	all := Available()
	spec = strings.TrimSpace(spec)
	if spec == "" || strings.EqualFold(spec, "all") {
		return all, nil
	}

	byID := make(map[string]Check, len(all))
	for _, c := range all {
		byID[c.ID()] = c
	}

	seen := make(map[string]bool)
	var chosen []Check
	for _, raw := range strings.Split(spec, ",") {
		name := strings.ToLower(strings.TrimSpace(raw))
		if name == "" || name == "all" {
			continue
		}
		if canon, ok := aliases[name]; ok {
			name = canon
		}
		c, ok := byID[name]
		if !ok {
			return nil, fmt.Errorf("unknown check %q (available: %s)", raw, strings.Join(CheckIDs(), ", "))
		}
		if seen[c.ID()] {
			continue
		}
		seen[c.ID()] = true
		chosen = append(chosen, c)
	}
	if len(chosen) == 0 {
		return nil, fmt.Errorf("no checks selected from %q", spec)
	}
	return chosen, nil
}

// CheckIDs lists the canonical IDs accepted by -checks.
func CheckIDs() []string {
	all := Available()
	ids := make([]string, 0, len(all))
	for _, c := range all {
		ids = append(ids, c.ID())
	}
	sort.Strings(ids)
	return ids
}
