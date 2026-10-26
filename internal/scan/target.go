package scan

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"ijiya/internal/version"
)

// MaxBody caps how much of a response body is read into memory.
const MaxBody = 2 << 20 // 2 MiB

// Options configures how the scanner talks to a target.
type Options struct {
	Timeout     time.Duration
	UserAgent   string
	Deep        bool
	Insecure    bool
	Concurrency int
	// Headers are extra headers added to every request, which is how an
	// authenticated area is scanned (session cookie, bearer token).
	Headers []Header
	// RateLimit caps outbound requests per second across the whole scan.
	// Zero means unthrottled.
	RateLimit float64
	// AllowExternalRedirects opts out of the default same-host redirect
	// boundary. Keeping redirects on the original host prevents a target from
	// turning the scanner into a request proxy for another service.
	AllowExternalRedirects bool
}

// Target is the shared HTTP session every check runs against.
type Target struct {
	Raw  string
	URL  *url.URL
	Opts Options

	client *http.Client  // follows redirects
	direct *http.Client  // stops at the first response
	gate   chan struct{} // global cap on in-flight requests
	limit  *limiter      // optional requests-per-second throttle
	reqs   atomic.Int64
}

// Response is a trimmed down http.Response that is safe to keep around.
type Response struct {
	StatusCode int
	Status     string
	Header     http.Header
	Body       []byte
	URL        string // final URL after any redirects
	Truncated  bool
	Duration   time.Duration
}

// BodyString returns the response body as a string.
func (r *Response) BodyString() string { return string(r.Body) }

// ContentType returns the lower cased media type without parameters.
func (r *Response) ContentType() string {
	v := r.Header.Get("Content-Type")
	if i := strings.IndexByte(v, ';'); i >= 0 {
		v = v[:i]
	}
	return strings.ToLower(strings.TrimSpace(v))
}

// IsHTML reports whether the response looks like an HTML document.
func (r *Response) IsHTML() bool {
	ct := r.ContentType()
	if ct == "" {
		// No content type: sniff the body the way a browser would.
		trim := strings.TrimLeft(string(r.Body), " \t\r\n")
		trim = strings.ToLower(trim)
		return strings.HasPrefix(trim, "<!doctype html") || strings.HasPrefix(trim, "<html") ||
			strings.Contains(trim[:min(len(trim), 512)], "<html")
	}
	return ct == "text/html" || ct == "application/xhtml+xml"
}

// NewTarget normalises a user supplied URL and builds its HTTP session.
func NewTarget(raw string, opts Options) (*Target, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("no target given")
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid url %q: %w", raw, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("unsupported scheme %q (only http and https)", u.Scheme)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("url %q has no host", raw)
	}
	u.Fragment = ""

	if opts.Timeout <= 0 {
		opts.Timeout = 10 * time.Second
	}
	if opts.UserAgent == "" {
		opts.UserAgent = version.Name + "/" + version.Version + " (security scanner)"
	}
	if opts.Concurrency <= 0 {
		opts.Concurrency = 8
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{
		// #nosec G402 -- deliberate: enabled by the user's -k flag for staging
		// environments with self-signed certificates.
		InsecureSkipVerify: opts.Insecure,
		MinVersion:         tls.VersionTLS10,
	}
	transport.MaxIdleConns = 64
	transport.MaxIdleConnsPerHost = 16
	transport.IdleConnTimeout = 30 * time.Second
	transport.DialContext = (&net.Dialer{
		Timeout:   opts.Timeout,
		KeepAlive: 30 * time.Second,
	}).DialContext

	rt := &uaTransport{base: transport, ua: opts.UserAgent, headers: headerMap(opts.Headers)}

	allowedHost := strings.ToLower(u.Host)
	checkRedirect := func(req *http.Request, via []*http.Request) error {
		if len(via) >= 10 {
			return http.ErrUseLastResponse
		}
		if !opts.AllowExternalRedirects && strings.ToLower(req.URL.Host) != allowedHost {
			from := allowedHost
			if len(via) > 0 && via[0].URL != nil {
				from = via[0].URL.Host
			}
			return fmt.Errorf("external redirect blocked: %s -> %s (use -allow-external-redirects to permit it)", from, req.URL.Host)
		}
		return nil
	}

	client := &http.Client{
		Transport:     rt,
		Timeout:       opts.Timeout,
		CheckRedirect: checkRedirect,
	}
	direct := &http.Client{
		Transport: rt,
		Timeout:   opts.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	return &Target{
		Raw:    raw,
		URL:    u,
		Opts:   opts,
		client: client,
		direct: direct,
		gate:   make(chan struct{}, opts.Concurrency),
		limit:  newLimiter(opts.RateLimit),
	}, nil
}

// Requests reports how many HTTP requests have been issued so far.
func (t *Target) Requests() int64 { return t.reqs.Load() }

// Base returns scheme://host for the target.
func (t *Target) Base() string {
	u := *t.URL
	u.Path = ""
	u.RawPath = ""
	u.RawQuery = ""
	u.ForceQuery = false
	u.Fragment = ""
	return u.String()
}

// uaTransport injects the scanner's default headers on every outbound
// request, then layers any user supplied headers on top so an explicit -H can
// override a default (including the User-Agent).
type uaTransport struct {
	base    http.RoundTripper
	ua      string
	headers map[string]string
}

func (u *uaTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	clone := r.Clone(r.Context())
	clone.Header.Set("User-Agent", u.ua)
	if clone.Header.Get("Accept") == "" {
		clone.Header.Set("Accept", "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8")
	}
	if clone.Header.Get("Accept-Language") == "" {
		clone.Header.Set("Accept-Language", "en-US,en;q=0.9")
	}
	for name, value := range u.headers {
		clone.Header.Set(name, value)
	}
	return u.base.RoundTrip(clone)
}

// Get issues a GET request. When direct is true the first response is
// returned instead of following redirects.
func (t *Target) Get(ctx context.Context, rawurl string, direct bool) (*Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawurl, nil)
	if err != nil {
		return nil, err
	}
	return t.Do(ctx, req, direct)
}

// PostForm issues an application/x-www-form-urlencoded POST request.
func (t *Target) PostForm(ctx context.Context, rawurl string, data url.Values, direct bool) (*Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rawurl, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return t.Do(ctx, req, direct)
}

// Do executes a prepared request under the global concurrency gate and, when
// -rate is set, under the shared request throttle as well.
func (t *Target) Do(ctx context.Context, req *http.Request, direct bool) (*Response, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case t.gate <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	defer func() { <-t.gate }()

	// Throttle before spending a connection so a slow scan stays slow
	// instead of queueing up work the target has to absorb at once.
	if !t.limit.wait(ctx) {
		return nil, ctx.Err()
	}

	cli := t.client
	if direct {
		cli = t.direct
	}

	t.reqs.Add(1)
	start := time.Now()
	resp, err := cli.Do(req.WithContext(ctx))
	if err != nil {
		return nil, err
	}
	// The body is fully read below, so a close error carries no information
	// the caller could act on; it still has to be acknowledged explicitly.
	defer func() { _ = resp.Body.Close() }()

	limited := io.LimitReader(resp.Body, int64(MaxBody)+1)
	body, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	truncated := false
	if len(body) > MaxBody {
		body = body[:MaxBody]
		truncated = true
	}

	final := ""
	if resp.Request != nil && resp.Request.URL != nil {
		final = resp.Request.URL.String()
	}

	return &Response{
		StatusCode: resp.StatusCode,
		Status:     resp.Status,
		Header:     resp.Header,
		Body:       body,
		URL:        final,
		Truncated:  truncated,
		Duration:   time.Since(start),
	}, nil
}

// parallel runs tasks with at most limit of them in flight at once and
// waits for every one to finish. Used by checks that probe many inputs.
func parallel(limit int, tasks []func()) {
	if limit < 1 {
		limit = 1
	}
	if len(tasks) == 0 {
		return
	}
	if limit > len(tasks) {
		limit = len(tasks)
	}
	sem := make(chan struct{}, limit)
	done := make(chan struct{}, len(tasks))
	for _, task := range tasks {
		task := task
		go func() {
			sem <- struct{}{}
			defer func() { <-sem; done <- struct{}{} }()
			task()
		}()
	}
	for range len(tasks) {
		<-done
	}
}

// hv returns a header value with all instances joined, so multi-part
// headers such as Content-Security-Policy are handled correctly.
func hv(h http.Header, name string) string {
	return strings.Join(h.Values(name), ", ")
}

// min and max are small helpers kept local to avoid clashing with the
// builtins available in newer Go releases in surprising ways.
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
