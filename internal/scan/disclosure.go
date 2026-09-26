package scan

import (
	"context"
	"fmt"
	"regexp"
	"strings"
)

type disclosureCheck struct{}

func (disclosureCheck) ID() string         { return "disclosure" }
func (disclosureCheck) Name() string       { return "Information disclosure" }
func (disclosureCheck) Category() Category { return CategoryDisclosure }

// versionRe finds a dotted version number in a banner such as nginx/1.18.0.
var versionRe = regexp.MustCompile(`\b\d+\.\d+(\.\d+)*\b`)

// generatorRe pulls the content of a <meta name="generator"> tag.
var generatorRe = regexp.MustCompile(`(?is)<meta[^>]+name\s*=\s*["']generator["'][^>]+content\s*=\s*["']([^"']+)["']`)

// debugSignatures are lower-case markers of leaked stack traces and
// development mode output.
var debugSignatures = []struct{ sig, title string }{
	{"traceback (most recent call last)", "Python traceback exposed"},
	{"system.nullreferenceexception", ".NET exception exposed"},
	{"system.invalidoperationexception", ".NET exception exposed"},
	{"stack trace:", "Stack trace exposed"},
	{"stacktrace:", "Stack trace exposed"},
	{"actioncontroller::", "Ruby on Rails error page exposed"},
	{"django version:", "Django debug page exposed"},
	{"secret key (change this)", "Django SECRET_KEY present in output"},
	{"werkzeug debugger", "Werkzeug interactive debugger exposed"},
	{"whoops! something went wrong", "Detailed error page exposed"},
	{"debug = true", "Application debug mode enabled"},
	{"ignition.", "Laravel Ignition debug page exposed"},
	{"laravel.log", "Laravel log path exposed"},
	{"php warning:", "PHP warning exposed"},
	{"php parse error:", "PHP parse error exposed"},
	{"fatal error:", "PHP fatal error exposed"},
	{"uncaught exception", "Unhandled exception exposed"},
	{"exception in \"/", "Unhandled exception exposed"},
	{"nativescript", "Framework fingerprint in error output"},
	{"var_dump(", "Debug output (var_dump) present"},
	{"sqlstate[", "Database error surfaced to the client"},
}

// sensitivePath describes a file that should never be web reachable.
type sensitivePath struct {
	Path     string
	Severity Severity
	Title    string
	Validate func(body []byte) bool
}

var has = func(needles ...string) func([]byte) bool {
	return func(b []byte) bool {
		s := strings.ToLower(string(b))
		for _, n := range needles {
			if !strings.Contains(s, n) {
				return false
			}
		}
		return true
	}
}

var sensitivePaths = []sensitivePath{
	{"/.git/HEAD", SeverityHigh, "Git metadata exposed (.git/HEAD)",
		func(b []byte) bool { return strings.HasPrefix(strings.TrimSpace(string(b)), "ref: refs/heads") }},
	{"/.git/config", SeverityHigh, "Git configuration exposed (.git/config)", has("[core]")},
	{"/.env", SeverityCritical, "Environment file exposed (.env)",
		func(b []byte) bool { return len(envKeyLines(b)) >= 3 }},
	{"/.aws/credentials", SeverityCritical, "AWS credentials file exposed", has("[default]")},
	{"/id_rsa", SeverityCritical, "Private key exposed (id_rsa)", has("private key")},
	{"/wp-config.php.bak", SeverityCritical, "WordPress config backup exposed", has("<?php", "db_password")},
	{"/config.php.bak", SeverityHigh, "PHP configuration backup exposed", has("<?php")},
	{"/backup.sql", SeverityCritical, "Database dump exposed",
		func(b []byte) bool { return has("create table", "insert into")(b) }},
	{"/dump.sql", SeverityCritical, "Database dump exposed",
		func(b []byte) bool { return has("create table", "insert into")(b) }},
	{"/backup.zip", SeverityHigh, "Site archive exposed",
		func(b []byte) bool { return strings.HasPrefix(string(b), "PK\x03\x04") }},
	{"/www.zip", SeverityHigh, "Site archive exposed",
		func(b []byte) bool { return strings.HasPrefix(string(b), "PK\x03\x04") }},
	{"/.svn/wc.db", SeverityHigh, "Subversion working copy exposed", has("sqlite format 3")},
	{"/.DS_Store", SeverityMedium, "Directory metadata exposed (.DS_Store)",
		func(b []byte) bool {
			return strings.HasPrefix(string(b), "\x00\x00\x00\x01") || strings.Contains(string(b), "DSDB")
		}},
	{"/.htaccess", SeverityMedium, "Apache .htaccess exposed", has("rewriterule", "rewriteengine")},
	{"/server-status", SeverityMedium, "Apache server-status page exposed", has("apache server status")},
	{"/phpinfo.php", SeverityMedium, "phpinfo() page exposed", has("phpinfo()")},
	{"/web.config", SeverityMedium, "IIS web.config exposed", has("<system.web")},
	{"/composer.json", SeverityLow, "Composer manifest exposed", has(`"require"`)},
	{"/package.json", SeverityLow, "npm manifest exposed", has(`"dependencies"`)},
}

// listingDirs are common directories worth probing for an open index.
var listingDirs = []string{"/static/", "/uploads/", "/images/", "/assets/", "/files/", "/backup/"}

func (disclosureCheck) Run(ctx context.Context, t *Target) ([]Finding, error) {
	page, err := t.Get(ctx, t.URL.String(), false)
	if err != nil {
		return nil, err
	}
	var out []Finding
	add := func(sev Severity, title, evidence, fix string) {
		f := Finding{
			Severity:    sev,
			Title:       title,
			URL:         page.URL,
			Evidence:    evidence,
			Remediation: fix,
		}
		Emit(ctx, f)
		out = append(out, f)
	}

	// --- Server banners -------------------------------------------------
	if v := hv(page.Header, "Server"); v != "" && versionRe.MatchString(v) {
		add(SeverityLow,
			"Server banner discloses software versions",
			"Server: "+v,
			"Strip version numbers (nginx `server_tokens off;`, Apache `ServerTokens Prod`, or a reverse proxy that rewrites the header).")
	}
	for _, h := range []string{"X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version", "X-Runtime", "X-Generator", "X-Backend", "X-Drupal-Cache"} {
		if v := hv(page.Header, h); v != "" {
			add(SeverityLow,
				"Framework fingerprint disclosed in the "+h+" header",
				h+": "+v,
				"Remove the header at the web server or framework level.")
		}
	}
	if m := generatorRe.FindStringSubmatch(page.BodyString()); m != nil {
		val := m[1]
		sev := SeverityLow
		if versionRe.MatchString(val) {
			sev = SeverityMedium
		}
		add(sev,
			"Meta generator tag discloses the CMS and version",
			`<meta name="generator" content="`+val+`">`,
			"Remove the generator meta tag or keep the CMS version current.")
	}

	// --- Debug / stack trace output -------------------------------------
	lowerBody := strings.ToLower(page.BodyString())
	for _, d := range debugSignatures {
		if strings.Contains(lowerBody, d.sig) {
			add(SeverityMedium,
				d.title,
				fmt.Sprintf("Response body contains %q.", d.sig),
				"Disable debug mode in production, return a generic error page and log details server-side only.")
			break // one finding is enough to point at the leak
		}
	}

	// --- Custom 404 detection -------------------------------------------
	// Some applications answer every unknown path with 200 and their normal
	// page. Probing files would then produce nothing but false positives,
	// so establish the baseline first.
	notFoundURL := t.Base() + "/ijiya-" + randomToken(8) + "-definitely-not-here"
	nf, nfErr := t.Get(ctx, notFoundURL, true)
	customOK := nfErr == nil && nf.StatusCode == 200
	if nfErr == nil && nf.StatusCode >= 500 {
		add(SeverityInfo,
			"Unknown paths return a server error instead of 404",
			fmt.Sprintf("GET %s returned %d.", notFoundURL, nf.StatusCode),
			"Return a consistent 404 status for missing resources so scanners and search engines can tell them apart.")
	}

	if customOK {
		add(SeverityInfo,
			"Every unknown path returns HTTP 200, so file disclosure probes were skipped",
			fmt.Sprintf("GET %s returned 200 with the normal page.", notFoundURL),
			"Serving 200 for missing files hides real problems too; return 404 for unknown resources.")
	} else {
		// --- Sensitive files -------------------------------------------
		for _, p := range sensitivePaths {
			target := t.Base() + p.Path
			resp, err := t.Get(ctx, target, true)
			if err != nil || resp.StatusCode != 200 {
				continue
			}
			if p.Validate == nil || !p.Validate(resp.Body) {
				continue
			}
			f := Finding{
				Severity:    p.Severity,
				Title:       p.Title,
				URL:         target,
				Evidence:    fmt.Sprintf("GET %s returned %d and the body matched the expected signature.", p.Path, resp.StatusCode),
				Remediation: "Block access to dotfiles, backups and source control metadata at the web server, and move secrets out of the document root.",
			}
			Emit(ctx, f)
			out = append(out, f)
		}

		// --- Directory listing ----------------------------------------
		for _, d := range listingDirs {
			target := t.Base() + d
			resp, err := t.Get(ctx, target, true)
			if err != nil || resp.StatusCode != 200 {
				continue
			}
			if !isDirectoryListing(resp.Body) {
				continue
			}
			f := Finding{
				Severity:    SeverityMedium,
				Title:       "Directory listing enabled on " + d,
				URL:         target,
				Evidence:    fmt.Sprintf("GET %s returned an auto-generated index.", d),
				Remediation: "Turn off indexing (`Options -Indexes` in Apache, `autoindex off;` in nginx) and serve an explicit index page.",
			}
			Emit(ctx, f)
			out = append(out, f)
		}
	}

	return out, nil
}

// isDirectoryListing recognises the common auto-generated index pages.
func isDirectoryListing(body []byte) bool {
	s := strings.ToLower(string(body))
	return strings.Contains(s, "<title>index of /") ||
		strings.Contains(s, "directory listing for") ||
		strings.Contains(s, "<h1>index of /") ||
		strings.Contains(s, "[to parent directory]") ||
		strings.Contains(s, "<h1>directory listing")
}

// envKeyLines counts lines that look like KEY=value assignments.
func envKeyLines(b []byte) []string {
	var out []string
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if i := strings.IndexByte(line, '='); i > 0 {
			key := line[:i]
			if envKeyRe.MatchString(key) {
				out = append(out, key)
			}
		}
	}
	return out
}

var envKeyRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
