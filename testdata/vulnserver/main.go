// Command vulnserver is a deliberately vulnerable local web application
// used to exercise ijiya's checks during development.
//
// It binds to loopback only and must never be exposed to a network.
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strings"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8099", "loopback listen address")
	flag.Parse()

	mux := http.NewServeMux()
	mux.HandleFunc("/", home)
	mux.HandleFunc("/search", search)
	mux.HandleFunc("/api/item", apiItem)
	mux.HandleFunc("/redirect", redirector)
	mux.HandleFunc("/uploads/", uploads)
	mux.HandleFunc("/.env", envFile)
	mux.HandleFunc("/.git/config", gitConfig)
	// /echo shows exactly which request headers arrived, which is how the
	// -H authenticated-scanning flag is verified by hand.
	mux.HandleFunc("/echo", echoHeaders)

	log.Printf("vulnerable demo server on http://%s", *addr)
	log.Fatal(http.ListenAndServe(*addr, mux))
}

// leakHeaders plants the disclosures ijiya looks for.
func leakHeaders(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("Server", "Apache/2.4.49 (Ubuntu)")
	h.Set("X-Powered-By", "PHP/8.1.2")
	h.Set("Content-Type", "text/html; charset=utf-8")
	// Deliberately no CSP, HSTS, X-Frame-Options, nosniff, Referrer-Policy
	// or Permissions-Policy: those absences are the point of the demo.
	// The CORS policy blindly trusts whatever origin shows up.
	if o := r.Header.Get("Origin"); o != "" {
		h.Set("Access-Control-Allow-Origin", o)
		h.Set("Access-Control-Allow-Credentials", "true")
	}
}

func home(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	leakHeaders(w, r)
	w.Header().Add("Set-Cookie", "session_id=demo-session-token; Path=/")

	q := r.URL.Query().Get("q")
	search := r.URL.Query().Get("search")

	fmt.Fprintf(w, `<!doctype html>
<html>
<head>
<meta name="generator" content="WordPress 6.4.2">
<title>Ijiya demo shop</title>
</head>
<body>
<h1>Ijiya demo shop</h1>
<p>You searched for: %s</p>
<p>Results for: %s</p>
<form method="get" action="/search">
  <input type="text" name="term" value="">
  <input type="hidden" name="csrf" value="demo-csrf-token">
  <input type="submit" value="Search">
</form>
<p class="debug">Stack Trace: at com.example.ShopController.index(ShopController.java:42)</p>
</body>
</html>`, q, search)
}

func search(w http.ResponseWriter, r *http.Request) {
	leakHeaders(w, r)
	term := r.URL.Query().Get("term")
	fmt.Fprintf(w, `<!doctype html>
<html><head><title>Search</title></head><body>
<h1>Search</h1>
<p>You searched for: %s</p>
</body></html>`, term)
}

// apiItem answers with a MySQL error whenever a quote reaches the query.
func apiItem(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if strings.ContainsAny(id, `'"`) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, `<b>Warning</b>: You have an error in your SQL syntax;
check the manual that corresponds to your MySQL server version for the
right syntax to use near `+"`'"+id+`' at line 1`)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"id":%q,"name":"widget"}`, id)
}

func redirector(w http.ResponseWriter, r *http.Request) {
	next := r.URL.Query().Get("next")
	if next == "" {
		next = "/"
	}
	http.Redirect(w, r, next, http.StatusFound)
}

func uploads(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/uploads/" {
		http.NotFound(w, r)
		return
	}
	leakHeaders(w, r)
	fmt.Fprint(w, `<!doctype html><html><head><title>Index of /uploads/</title></head>
<body><h1>Index of /uploads/</h1><ul>
<li><a href="a.png">a.png</a></li>
<li><a href="b.zip">b.zip</a></li>
</ul></body></html>`)
}

func envFile(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprint(w, `APP_ENV=local
DB_HOST=127.0.0.1
DB_PASSWORD=super-secret
MAIL_PASSWORD=hunter2
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI
`)
}

func gitConfig(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprint(w, `[core]
	repositoryformatversion = 0
	filemode = true
	bare = false
[remote "origin"]
	url = https://example.invalid/demo.git
`)
}

// echoHeaders reflects the request headers so a -H flag can be confirmed
// against a known endpoint. Values are echoed verbatim: this server is a local
// test fixture and never handles a real credential.
func echoHeaders(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	names := make([]string, 0, len(r.Header))
	for name := range r.Header {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		for _, value := range r.Header.Values(name) {
			fmt.Fprintf(w, "%s: %s\n", name, value)
		}
	}
}
