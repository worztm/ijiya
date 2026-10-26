# ijiya

A lightweight CLI and TUI that checks your own web application for the
loopholes that most often lead to compromise — and tells you how to close each
one.

```console
$ ijiya https://app.example.com

  █████  █████ █████  ██   ██   ███
    ██     ██    ██  ██   ██ ██  ██
    ██     ██    ██    ███   █████
    ██     ██    ██     ██   ██  ██
  █████   ███   █████    ██   ██  ██
  lightweight web vulnerability scanner  v0.3.0
  Only scan systems you own or have explicit permission to test.

  headers  Security headers  8ms · 3 issue(s)
    MEDIUM    Content-Security-Policy (CSP) header missing
              url: https://app.example.com/
              why: The browser will load scripts, styles, images and frames
              from anywhere, so a single injected tag becomes a full XSS.
              fix: Start with `Content-Security-Policy: default-src 'self';
              object-src 'none'; base-uri 'self'` ...
```

The scanner core — every check, the report renderers and the CLI — is built
entirely on the Go standard library. The interactive TUI layers
[bubbletea], [bubbles] and [lipgloss] from the Charm suite on top. Either way
you get a single static binary with nothing to install at runtime.

[bubbletea]: https://github.com/charmbracelet/bubbletea
[bubbles]: https://github.com/charmbracelet/bubbles
[lipgloss]: https://github.com/charmbracelet/lipgloss

## Interactive mode

Running `ijiya` with no arguments opens a full-screen TUI, so nobody has to
remember the flag names:

```console
$ ijiya
```

1. Type the URL you want to check and press **enter**.
2. Pick which checks to run — **tab** switches between the URL field and the
   check list, **space** toggles a check, **a** selects or deselects all, **d**
   turns on the slower deep probes. The header counts how many are selected.
3. Watch results stream in live: a progress bar tracks finished checks, each
   check moves through queued → running → done with its issue count, and the
   newest findings appear at the top of a live feed.
4. Scroll the finished report, then press **s** to save it to a file.

Three screens, one grid: a masthead and hairline rule above, the content in the
middle, and the key hints pinned to the bottom row. Labels are set in small
caps, severity is the only thing that takes colour, and the body text uses your
terminal's own foreground so it stays readable in a light or dark theme.
Checks and their selection are drawn as `[x]` rows, with the cursor as a
reverse-video bar on the active row.

| Key | Action |
| --- | --- |
| `enter` | start the scan |
| `tab` / `shift+tab` | switch between the URL field and the check list |
| `↑` `↓` (or `k` `j`) | move the check cursor |
| `space` / `a` / `d` | toggle a check / all checks / deep mode |
| `↑` `↓` `pgup` `pgdn` `home` `end` | scroll the report on the results screen |
| `s` | save the report to a file |
| `esc` | cancel a running scan and return to the input screen |
| `r` | start a new scan from the results screen |
| `q` | quit (`ctrl+c` always quits; mid-scan `q` asks once more first) |

```console
$ ijiya -tui https://app.example.com   # open the TUI and scan immediately
```

All the usual flags (`-k`, `-t`, `-threads`, `-deep`, `-out`, `-fail-on`, `-H`,
`-rate`, …) apply to the interactive scan, and the exit code follows the same
`-fail-on` contract — so a TUI run can still gate CI. Report URLs are redacted
by default in the TUI as well.

Findings are pushed into the feed the moment a check discovers them rather
than when the whole check finishes, which keeps long `-deep` runs interesting
to watch. The feed holds the most recent 200 findings.

## What it checks

| Check | Catches |
| --- | --- |
| `headers` | Missing/weak **HSTS**, **CSP** (`unsafe-inline`, `unsafe-eval`, wildcards), `X-Content-Type-Options`, clickjacking (`X-Frame-Options` / `frame-ancestors`), `Referrer-Policy`, `Permissions-Policy`, `COOP`, `CORP`, legacy `X-XSS-Protection` |
| `cookies` | Missing `Secure`, `HttpOnly`, `SameSite` (session cookies are escalated to HIGH), `SameSite=None` without `Secure` |
| `tls` | HTTP→HTTPS enforcement, certificate expiry, hostname mismatch, self-signed certs, weak key material, SHA-1 signatures, missing intermediates, obsolete TLS versions |
| `cors` | Origin reflection with credentials, the opaque `null` origin, wildcard + credentials |
| `xss` | **Reflected XSS** in query parameters and HTML form fields (raw unencoded reflection of tag-breaking payloads) |
| `sqli` | **SQL injection** via error-based probing (MySQL, PostgreSQL, MSSQL, Oracle, SQLite, …) plus boolean- and time-based blind detection with `-deep` |
| `disclosure` | Version banners (`Server`, `X-Powered-By`), CMS generator tags, stack traces/debug mode, `.git`, `.env`, `.aws/credentials`, private keys, DB dumps, backup archives, directory listing |
| `redirect` | **Open redirect** on the parameters the page exposes plus conventional `/login`, `/logout`, `/redirect` endpoints |

Every finding carries a severity, the exact evidence, the URL that produced it,
and a concrete remediation.

## Install

```console
$ go build -o ijiya .
```

Or install it straight into `GOBIN`:

```console
$ go install .
```

Requires Go 1.26 or newer. Nothing else.

## Usage

```console
$ ijiya                   # interactive mode (TUI)
$ ijiya [flags] <url>     # one-shot scan, prints a report and exits
```

| Flag | Default | Purpose |
| --- | --- | --- |
| `-checks`, `-c` | `all` | Comma-separated list: `headers,cookies,tls,cors,xss,sqli,disclosure,redirect` (aliases like `ssl`, `sql`, `leaks` also work) |
| `-output`, `-o` | `text` | Report format: `text`, `json`, `sarif` or `markdown` |
| `-out` | – | Also write the report to a file (format follows the extension: `.sarif`, `.json`, `.md`) |
| `-out-format` | from the extension | Override the format used for `-out` |
| `-baseline` | – | A JSON report of known findings to suppress, so CI only fails on new ones |
| `-H` | – | Extra request header as `"Name: value"`, repeatable — use it for auth cookies and tokens |
| `-timeout`, `-t` | `10s` | Per-request timeout |
| `-threads` | `8` | Maximum concurrent HTTP requests |
| `-rate` | off | Cap outbound requests per second (`0.01`–…) so a production host is not hammered |
| `-deep` | off | Enable the slow probes: boolean/time-based SQL injection and POST form fields |
| `-min` | `info` | Hide findings below this severity |
| `-fail-on` | `medium` | Exit `1` when a finding reaches this severity |
| `-verbose`, `-v` | off | Show checks that passed too |
| `-insecure`, `-k` | off | Skip TLS verification (staging boxes, self-signed certs) |
| `-allow-external-redirects` | off | Follow redirects to another host (unsafe; same-host only by default) |
| `-show-secrets` | off | Disable credential redaction in report URLs (unsafe) |
| `-user-agent`, `-ua` | built-in | Override the User-Agent |
| `-no-color`, `-nc` | off | Disable ANSI colour (also honours `NO_COLOR`) |
| `-no-banner`, `-nb` | off | Hide the startup banner |
| `-list` | – | List the available checks and the output formats |
| `-tui` | off | Force the interactive interface (scans immediately when a URL is given) |
| `-version` | – | Print the version |

### Examples

```console
# Full scan
$ ijiya https://app.example.com

# Just the configuration checks, CI-friendly output
$ ijiya -checks headers,cookies,tls,cors -min medium -fail-on high https://app.example.com

# Everything, including blind SQL injection and POST forms, as JSON
$ ijiya -deep -o json -out report.json https://app.example.com

# Scan behind a login: both a session cookie and an API key on every request
$ ijiya -H "Cookie: session=$SESSION" -H "X-API-Key: $KEY" https://app.example.com/account

# Be gentle with a production host: at most five requests per second
$ ijiya -rate 5 https://app.example.com

# Local development box with a self-signed certificate
$ ijiya -k -threads 4 http://localhost:8080

# Explicitly allow a trusted cross-host redirect flow
$ ijiya -allow-external-redirects https://trusted.example.com
```

### Safety defaults

Two guardrails are enabled by default:

- Redirects are restricted to the original host, preventing a page from
  turning `ijiya` into a proxy for another service. Use
  `-allow-external-redirects` only for an explicitly trusted multi-host flow.
- Credential-like query values, URL passwords, fragments and URLs embedded in
  evidence are written as `REDACTED`. Use `-show-secrets` only when the report
  is going to a controlled destination.

Report files are created with owner-only permissions where the platform
supports them.

### Scanning authenticated areas

By default `ijiya` sees exactly what an anonymous visitor sees, which for most
applications means the login page. `-H` puts an arbitrary header on every
request, so the checks run against the pages that actually hold the data:

```console
$ ijiya -H "Cookie: session=$SESSION" https://app.example.com/dashboard
$ ijiya -H "Authorization: Bearer $TOKEN" https://api.example.com/v1/me
```

`-H` may be repeated and the value may contain colons (`Origin`,
`X-Forwarded-For: 10.0.0.1:8080`). Header **names** are printed at startup so
you can confirm what was sent, but values never are — a token must not end up
in a terminal log or a CI transcript. A malformed header is a usage error
(exit `2`) rather than a confusing transport failure later.

Tune the load with `-threads` and `-rate`. `-threads` bounds how many requests
are in flight at once; `-rate` bounds how many go out per second, which is the
better lever against a host you share with real users.

### Output formats

| Format | Use it for |
| --- | --- |
| `text` | Reading in a terminal (the default) |
| `json` | Scripts, dashboards, and as a `-baseline` for later runs |
| `sarif` | Uploading to GitHub code scanning, where findings appear as review annotations |
| `markdown` | Pull-request comments and job summaries |

```console
$ ijiya -o sarif -out results.sarif https://app.example.com   # format from the extension
$ ijiya -o markdown https://app.example.com                   # pipe it into a PR comment
$ ijiya -o json -out latest.json https://app.example.com
```

### Using a baseline in CI

A scan of an application that already has known issues should still fail a
build when the change under review introduces a *new* one. `-baseline` takes a
previous JSON report and suppresses every finding it contains:

```console
# Record today's state once
$ ijiya -o json -out ijiya-baseline.json "$STAGING_URL"

# From now on only new findings are reported, scored and gated on
$ ijiya -baseline ijiya-baseline.json -o sarif -out results.sarif -fail-on high "$STAGING_URL"
```

Matching is by check, title and URL path, so it survives a different host name
(staging vs. preview), query strings and session IDs — while a finding that
moves to a new path is treated as new. Suppressed findings are counted in the
output (`suppressed` in JSON, a line in the text report) rather than silently
dropped, the summary and grade describe the new findings only, and a missing
baseline file is not an error (the first CI run has nothing to compare
against). Regenerate the baseline deliberately, by promoting a reviewed report.

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Clean — no finding at or above `-fail-on` |
| `1` | Findings at or above `-fail-on` |
| `2` | Invalid usage |
| `3` | The scan could not run (unreachable target, etc.) |

This makes it usable as a CI gate:

```yaml
- name: Security gate
  run: |
    ijiya -checks headers,cookies,tls,cors \
          -o json -out ijiya.json \
          -fail-on high "$STAGING_URL"

- name: Upload findings to code scanning
  if: always()
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: ijiya.sarif
```

The JSON report contains `tool`, `target`, `started_at`, `requests`, the full
`checks[]` array with `severity`/`evidence`/`remediation` per finding, plus
`summary`, `risk_score`, `grade` and `suppressed`.

## Testing it against a vulnerable app

The repository ships a deliberately vulnerable local server so you can see what
a real report looks like without touching anything you do not own:

```console
$ go run ./testdata/vulnserver -addr 127.0.0.1:8099
$ ijiya http://127.0.0.1:8099/
```

It binds to loopback only and should never be exposed to a network. Its
`/echo` endpoint prints the request headers it received, which is the quickest
way to confirm that `-H` is doing what you expect:

```console
$ curl -s -H "X-Api-Key: k123" http://127.0.0.1:8099/echo | grep -i api-key
X-Api-Key: k123
```

## How it works

`ijiya` drives every check through one shared HTTP session, so a single
concurrency gate (`-threads`) bounds the total number of in-flight requests no
matter how many checks are running, and an optional `-rate` throttle bounds how
many requests leave per second.

- **Header and cookie checks** parse the response of the target page.
- **XSS** fetches the page, extracts query parameters and HTML form fields
  (skipping CSRF/nonce/hmac inputs), then replays each one with a unique random
  payload containing `"`, `>` and `<`. A finding is raised only when the full
  payload comes back **verbatim** in an HTML response — HTML-encoded or
  URL-encoded reflections are reported as informational, not as XSS.
- **SQL injection** appends quote characters and looks for database error text
  that was *not* present in the baseline response, which removes the usual
  false positives from pages that legitimately talk about SQL. With `-deep` it
  additionally compares response sizes under a true and a false condition, and
  measures round-trip time against `SLEEP()`/`pg_sleep()`/`WAITFOR DELAY`.
- **Disclosure** first asks the server for a path that cannot exist. If that
  returns `200` (a catch-all SPA route), file and directory probes are skipped
  rather than reporting noise, and you are told why.
- **Redirect** uses `ijiya-probe.invalid`, a reserved TLD (RFC 6761) that can
  never resolve, so a detected redirect cannot lead anywhere.

Payloads are limited to the inputs discovered on the page you point it at, the
request budget is bounded, and everything runs in parallel with per-request
timeouts.

## Scope and responsible use

`ijiya` sends crafted payloads (quote characters, tag-breaking sequences,
time-delay functions) to the target. **Only scan systems you own or have
explicit permission to test.** Running it against someone else's site without
authorisation is illegal in most jurisdictions.

Useful boundaries, all of which are already in place:

- It only follows `http` and `https` URLs, one host at a time.
- Probe hosts use the reserved `.invalid` TLD, so nothing can be redirected to
  a real destination.
- Anti-CSRF, nonce, signature and captcha inputs are never overwritten.
- POST form submission is opt-in via `-deep`.
- `Set-Cookie` values are redacted in reports so secrets do not leak into
  shared output.
- Header *values* supplied with `-H` are never echoed into reports or progress
  output — only the header names are.
- `-rate` throttles the whole scan, so a shared or production host is not
  pushed past what it can absorb.

## Limitations

- Only the page you point at is crawled — this is a scanner, not a spider.
  Run it against each route you care about, or pass a URL that already carries
  the parameters you want tested.
- Detection is signature- and heuristic-based. Treat every finding as a lead to
  confirm, and remember that a clean scan never proves the absence of a bug.
- `-H` gets you past a login, but it does not discover or replay a login flow,
  refresh an expired token, or walk a multi-step authenticated journey.
- JSON bodies, HTTP parameter pollution and web-socket traffic are not tested.

## Development

```console
$ go test ./...        # unit tests for the checks, renderers and TUI
$ go vet ./...
$ gofmt -l .           # CI fails on unformatted files
```

CI runs the tests with `-race` on Linux, macOS and Windows, plus
`golangci-lint`; see [`.github/workflows/ci.yml`](.github/workflows/ci.yml).

## License

Use and modify it freely for testing your own applications.
