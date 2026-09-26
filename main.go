// Command ijiya is a lightweight, dependency-free CLI scanner that helps
// owners and operators find common loopholes in their own web applications:
// missing security headers, weak cookie flags, reflected XSS, SQL injection,
// TLS problems, CORS misconfiguration, information disclosure and open
// redirects.
//
// Only ever run it against systems you own or have explicit permission to
// test.
package main

import (
	"os"

	"ijiya/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:]))
}
