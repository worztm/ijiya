# ijiya

A small command-line security scanner for web applications you own or are
allowed to test.

`ijiya` checks the response headers, cookies, TLS setup, CORS policy, reflected
XSS, SQL injection, information disclosure, and open redirects. It gives each
finding a severity, evidence, and a practical fix.

> Only scan systems you own or have explicit permission to test.

## Install

### Go users

Go 1.26 or newer can install `ijiya` directly from this repository:

```console
go install github.com/worztm/ijiya@v0.3.0
```

The binary is placed in your Go binary directory. Make sure that directory is
on your `PATH`, then verify the installation:

```console
ijiya -version
```

On Windows, the default location is usually `%USERPROFILE%\go\bin`. On
macOS and Linux, it is usually `$HOME/go/bin`.

### Prebuilt binaries

If you do not have Go installed, download the archive for your operating
system and CPU from the [GitHub Releases page](https://github.com/worztm/ijiya/releases).

Available builds include:

- Windows: `amd64` and `arm64`
- macOS: `amd64` and `arm64`
- Linux: `amd64` and `arm64`

Extract the archive, put the `ijiya` binary somewhere on your `PATH`, and run:

```console
ijiya -version
```

Each release also includes a `SHA256SUMS` file for verifying downloads.

## Quick start

Run a scan:

```console
ijiya https://app.example.com
```

Run the interactive interface instead:

```console
ijiya
```

The project has no runtime dependencies.

## Interactive mode

Running `ijiya` without a URL opens the terminal interface. It is useful when
you want to choose checks and watch a scan as it runs.

1. Enter a URL and press `Enter`.
2. Use `Tab` to move between the URL and the check list.
3. Press `Space` to toggle a check, `a` to select or clear all checks, and `d`
   to enable the slower deep probes.
4. Watch checks move from queued to running to complete.
5. Press `s` on the results screen to save the report.

You can also start the interface with a URL already selected:

```console
ijiya -tui https://app.example.com
```

| Key | Action |
| --- | --- |
| `Enter` | Start a scan |
| `Tab` / `Shift+Tab` | Move between fields |
| `↑` `↓` or `j` `k` | Move through checks or scroll results |
| `Space` | Toggle the selected check |
| `a` | Select or clear all checks |
| `d` | Toggle deep mode |
| `s` | Save the report |
| `r` | Start another scan |
| `Esc` | Cancel a running scan |
| `q` | Quit |

## Checks

| Check | What it looks for |
| --- | --- |
| `headers` | HSTS, CSP, clickjacking protection, MIME sniffing, referrer policy, permissions policy, COOP, and CORP |
| `cookies` | Missing `Secure`, `HttpOnly`, or `SameSite` flags, including unsafe `SameSite=None` cookies |
| `tls` | HTTP-to-HTTPS redirects, certificate validity, hostname mismatches, weak keys, SHA-1 signatures, missing intermediates, and old TLS versions |
| `cors` | Reflected origins, credentialed cross-origin access, the `null` origin, and wildcard configuration |
| `xss` | Reflected payloads in query parameters and HTML form fields |
| `sqli` | Database error responses, plus boolean- and time-based checks with `-deep` |
| `disclosure` | Server banners, debug output, source-control files, environment files, private keys, backups, dumps, and directory listings |
| `redirect` | Open redirects in discovered parameters and common redirect endpoints |

Every finding includes its severity, the URL that produced it, supporting
evidence, and a remediation suggestion.

## Usage

```console
ijiya [flags] <url>
```

With no URL, `ijiya` starts the interactive interface when it is attached to a
terminal. With a URL, it runs a one-shot scan and prints the report.

### Common examples

Scan everything:

```console
ijiya https://app.example.com
```

Run only configuration checks and fail CI on high-severity findings:

```console
ijiya \
  -checks headers,cookies,tls,cors \
  -min medium \
  -fail-on high \
  https://app.example.com
```

Enable the slower SQL injection and POST form checks:

```console
ijiya -deep https://app.example.com
```

Scan an authenticated area. Header values are never printed by the tool:

```console
ijiya \
  -H "Cookie: session=$SESSION" \
  -H "Authorization: Bearer $TOKEN" \
  https://app.example.com/dashboard
```

Limit the load against a shared or production system:

```console
ijiya -threads 4 -rate 5 https://app.example.com
```

Write JSON, SARIF, or Markdown output:

```console
ijiya -o json -out report.json https://app.example.com
ijiya -o sarif -out results.sarif https://app.example.com
ijiya -o markdown https://app.example.com
```

### Flags

| Flag | Default | Description |
| --- | --- | --- |
| `-checks`, `-c` | `all` | Comma-separated checks to run |
| `-output`, `-o` | `text` | Output format: `text`, `json`, `sarif`, or `markdown` |
| `-out` | — | Write a second copy of the report to a file |
| `-out-format` | file extension | Choose the format used for `-out` |
| `-baseline` | — | Suppress findings already present in a JSON report |
| `-H` | — | Add a request header; repeat the flag when needed |
| `-timeout`, `-t` | `10s` | Per-request timeout |
| `-threads` | `8` | Maximum number of concurrent requests |
| `-rate` | `0` | Maximum requests per second; zero means unlimited |
| `-deep` | off | Enable slower SQL injection and POST form probes |
| `-min` | `info` | Hide findings below this severity |
| `-fail-on` | `medium` | Exit with code `1` at this severity or higher |
| `-verbose`, `-v` | off | Include checks that found no issues |
| `-insecure`, `-k` | off | Skip TLS certificate verification |
| `-allow-external-redirects` | off | Follow redirects to another host |
| `-show-secrets` | off | Disable redaction of credential-like URL values |
| `-user-agent`, `-ua` | built-in | Override the User-Agent header |
| `-no-color`, `-nc` | off | Disable ANSI colours; also respects `NO_COLOR` |
| `-no-banner`, `-nb` | off | Hide the text report banner |
| `-list` | — | List available checks |
| `-tui` | off | Force the interactive interface |
| `-version` | — | Print the version |

Use `ijiya -h` for the complete help text.

## Safety defaults

`ijiya` keeps two protections enabled by default.

### Redirects stay on the target host

The scanner does not follow a redirect to another host unless you explicitly
allow it:

```console
ijiya -allow-external-redirects https://trusted.example.com
```

Only use this for a flow you understand and trust. The default prevents a
redirect on the target from making the scanner request an unrelated service.

### Reports redact credentials

Credential-like query parameters, URL passwords, fragments, and URLs embedded
in evidence are written as `REDACTED`. This helps keep tokens out of terminal
logs, JSON files, and CI artifacts.

Use `-show-secrets` only when the output is going to a controlled destination.
Report files are created with owner-only permissions where the platform
supports them.

## Authenticated scans

By default, the scanner sees what an anonymous visitor sees. Use `-H` to send
session or API credentials with every request:

```console
ijiya -H "Cookie: session=$SESSION" https://app.example.com/account
ijiya -H "Authorization: Bearer $TOKEN" https://api.example.com/v1/me
```

The flag can be repeated. Values may contain colons, so URLs and forwarded IP
addresses are valid header values too. Header names may appear in the startup
summary, but header values are never echoed.

`ijiya` does not log in for you, refresh expired tokens, or walk a multi-step
authenticated flow. Provide a valid header or scan the relevant route directly.

## Reports and CI

### Output formats

- **Text** is the default and is designed for terminal output.
- **JSON** is useful for scripts, dashboards, and baselines.
- **SARIF** works with GitHub code scanning.
- **Markdown** is convenient for pull requests and job summaries.

### Baselines

A baseline lets CI ignore findings that are already known while still catching
new ones.

Create a baseline:

```console
ijiya -o json -out ijiya-baseline.json "$STAGING_URL"
```

Use it in a later run:

```console
ijiya \
  -baseline ijiya-baseline.json \
  -o sarif \
  -out results.sarif \
  -fail-on high \
  "$STAGING_URL"
```

Findings are matched by check, title, and URL path. Host names, query strings,
and fragments do not affect the match. Suppressed findings are counted in the
report, and the risk score only covers findings that remain.

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | No finding reached `-fail-on` |
| `1` | At least one finding reached `-fail-on` |
| `2` | Invalid command-line usage |
| `3` | The scan could not run |

Example GitHub Actions step:

```yaml
- name: Scan staging
  run: |
    ijiya -checks headers,cookies,tls,cors \
      -o json -out ijiya.json \
      -fail-on high "$STAGING_URL"

- name: Upload SARIF
  if: always()
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: ijiya.sarif
```

The JSON report includes the tool version, target, timestamps, request count,
check results, severity counts, risk score, grade, and suppressed findings.

## Try it locally

The repository includes a deliberately vulnerable test server. It binds to
loopback only and is safe to use for a local demonstration.

Start the server in one terminal:

```console
go run ./testdata/vulnserver -addr 127.0.0.1:8099
```

Run the scanner in another:

```console
ijiya http://127.0.0.1:8099/
```

The test server also has an `/echo` endpoint for checking request headers:

```console
curl -s \
  -H "X-Api-Key: demo-key" \
  http://127.0.0.1:8099/echo | grep -i api-key
```

Do not expose the vulnerable server to a network.

## How it works

All checks use one shared HTTP session. The `-threads` setting limits the total
number of in-flight requests, while `-rate` limits the number of requests sent
per second. Each request has its own timeout and response bodies are capped in
memory.

The scanner only tests the URL and inputs it can discover from that page. It
is not a crawler. Deep mode adds more expensive SQL injection probes and POST
form checks.

Detection is heuristic. A finding should be confirmed manually, and a clean
scan does not prove that an application is secure.

## Limitations

- Only the page you provide is scanned; linked pages are not crawled.
- Login flows, token refresh, and multi-step authenticated journeys are not
  automated.
- JSON request bodies, HTTP parameter pollution, and WebSocket traffic are not
  tested.
- XSS and SQL injection checks are signature-based and can miss unusual
  application behaviour.
- `-deep` sends additional POST requests, so enable it only when that is safe
  for the target.

## Development

```console
go build -o ijiya .
go test ./...
go vet ./...
gofmt -l .
```

Continuous integration runs tests on Linux, macOS, and Windows, including race
detection and linting.

## License

Use and modify `ijiya` freely for testing applications you own or are
authorised to assess.
