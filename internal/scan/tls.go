package scan

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"
)

type tlsCheck struct{}

func (tlsCheck) ID() string         { return "tls" }
func (tlsCheck) Name() string       { return "TLS and HTTPS" }
func (tlsCheck) Category() Category { return CategoryTLS }

func (tlsCheck) Run(ctx context.Context, t *Target) ([]Finding, error) {
	var out []Finding
	add := func(sev Severity, title, evidence, fix string) {
		f := Finding{
			Severity:    sev,
			Title:       title,
			Evidence:    evidence,
			Remediation: fix,
		}
		Emit(ctx, f)
		out = append(out, f)
	}

	// --- Does plain HTTP silently continue without upgrading? -----------
	httpURL := *t.URL
	httpURL.Scheme = "http"
	httpURL.Path = "/"
	httpURL.RawPath = ""
	httpURL.RawQuery = ""
	httpURL.ForceQuery = false
	httpURL.Fragment = ""

	httpsOK := probeHTTPS(ctx, t)

	resp, err := t.Get(ctx, httpURL.String(), true)
	if err == nil {
		// Does the first hop point at an HTTPS URL?
		upgraded := false
		if loc := resp.Header.Get("Location"); loc != "" {
			if lu, lerr := url.Parse(loc); lerr == nil && lu != nil {
				abs := lu
				if lu.Scheme == "" {
					abs = httpURL.ResolveReference(lu)
				}
				if abs.Scheme == "https" {
					upgraded = true
				}
			}
		}
		switch {
		case resp.StatusCode >= 300 && resp.StatusCode < 400 && upgraded:
			add(SeverityInfo,
				"HTTP correctly redirects to HTTPS",
				httpURL.String()+" -> "+resp.Header.Get("Location"),
				"No action needed; pair it with a long Strict-Transport-Security max-age.")
		case resp.StatusCode < 300:
			if httpsOK {
				add(SeverityMedium,
					"Plain HTTP is served without redirecting to HTTPS",
					fmt.Sprintf("GET %s returned %d on the final hop rather than a redirect to HTTPS.", httpURL.String(), resp.StatusCode),
					"Redirect every HTTP request to HTTPS (301/308) and only then send HSTS.")
			} else {
				add(SeverityMedium,
					"Site is reachable over plain HTTP and no HTTPS endpoint responded",
					fmt.Sprintf("GET %s returned %d; the HTTPS probe on this host failed.", httpURL.String(), resp.StatusCode),
					"Terminate TLS on this host, redirect HTTP to HTTPS, then enable HSTS.")
			}
		}
	} else if !httpsOK {
		add(SeverityMedium,
			"Neither plain HTTP nor HTTPS could be reached on this host",
			"Probes against "+httpURL.String()+" and its HTTPS counterpart failed: "+err.Error(),
			"Confirm the service is listening and reachable from the network.")
	}

	// --- Inspect the certificate and negotiated protocol ----------------
	host := t.URL.Hostname()
	port := "443"
	if t.URL.Scheme == "https" {
		if p := t.URL.Port(); p != "" {
			port = p
		}
	} else if resp != nil {
		if u, uerr := url.Parse(resp.URL); uerr == nil && u != nil && u.Scheme == "https" && u.Port() != "" {
			port = u.Port()
		}
	}

	cert, proto, err := inspectTLS(ctx, host, port, t.Opts.Timeout)
	if err != nil {
		if err == context.Canceled || err == context.DeadlineExceeded {
			return out, nil
		}
		if !httpsOK {
			return out, nil // already reported above
		}
		add(SeverityMedium,
			"TLS handshake failed against "+net.JoinHostPort(host, port),
			err.Error(),
			"Check the certificate chain, supported protocol versions and any SNI requirements.")
		return out, nil
	}

	// Protocol version.
	switch {
	case proto < tls.VersionTLS12:
		add(SeverityHigh,
			fmt.Sprintf("Obsolete TLS version negotiated (%s)", tlsVersionName(proto)),
			fmt.Sprintf("Handshake with %s negotiated %s, which has known weaknesses.", net.JoinHostPort(host, port), tlsVersionName(proto)),
			"Disable SSLv3/TLS 1.0/TLS 1.1 and require TLS 1.2 or newer (ideally TLS 1.3).")
	case proto == tls.VersionTLS12:
		add(SeverityInfo,
			"TLS 1.2 negotiated (TLS 1.3 not used)",
			"Handshake with "+net.JoinHostPort(host, port)+" selected TLS 1.2.",
			"Enable TLS 1.3 where the platform allows it; keep TLS 1.2 only for compatibility.")
	}

	// Hostname match.
	if err := cert.VerifyHostname(host); err != nil {
		add(SeverityHigh,
			"Certificate does not match the scanned host name",
			fmt.Sprintf("Subject: %s | DNS names: %s | error: %v", cert.Subject.CommonName, strings.Join(cert.DNSNames, ", "), err),
			"Issue a certificate whose SAN list includes "+host+".")
	}

	// Validity window.
	now := time.Now()
	switch {
	case now.After(cert.NotAfter):
		add(SeverityHigh,
			fmt.Sprintf("Certificate expired %d days ago", int(now.Sub(cert.NotAfter).Hours()/24)),
			fmt.Sprintf("NotAfter: %s (issuer: %s)", cert.NotAfter.UTC().Format(time.RFC3339), cert.Issuer.CommonName),
			"Renew the certificate; expired certificates break every browser and invite interception.")
	case now.Before(cert.NotBefore):
		add(SeverityMedium,
			"Certificate is not valid yet",
			fmt.Sprintf("NotBefore: %s", cert.NotBefore.UTC().Format(time.RFC3339)),
			"Check the system clock or wait for the certificate's validity window to start.")
	case cert.NotAfter.Sub(now) < 30*24*time.Hour:
		add(SeverityMedium,
			fmt.Sprintf("Certificate expires in %d days", int(cert.NotAfter.Sub(now).Hours()/24)),
			fmt.Sprintf("NotAfter: %s", cert.NotAfter.UTC().Format(time.RFC3339)),
			"Automate renewal before expiry to avoid an outage.")
	}

	// Trust and issuance.
	if err := cert.CheckSignatureFrom(cert); err == nil {
		add(SeverityHigh,
			"Certificate is self-signed",
			fmt.Sprintf("Subject: %s | Issuer: %s", cert.Subject.CommonName, cert.Issuer.CommonName),
			"Obtain a certificate from a CA the browsers trust (Let's Encrypt is free).")
	}
	if cert.NotAfter.Sub(cert.NotBefore) > 398*24*time.Hour {
		add(SeverityLow,
			fmt.Sprintf("Certificate lifetime is %d days", int(cert.NotAfter.Sub(cert.NotBefore).Hours()/24)),
			fmt.Sprintf("Valid %s -> %s", cert.NotBefore.UTC().Format(time.RFC3339), cert.NotAfter.UTC().Format(time.RFC3339)),
			"Public CAs cap certificates at 398 days; a longer term suggests an internal CA.")
	}

	// Key strength. The floor differs by algorithm: RSA 2048 is the modern
	// minimum while ECDSA P-256 (256 bits) is already equivalent to
	// RSA-3072, so a single bit threshold would raise false positives.
	if algo, bits, floor, known := keyStrength(cert); known && bits < floor {
		add(SeverityHigh,
			fmt.Sprintf("Weak certificate key (%s, %d bits)", algo, bits),
			fmt.Sprintf("Public key algorithm: %s; the recommended floor for this algorithm is %d bits.", cert.PublicKeyAlgorithm, floor),
			"Use RSA >= 2048 bits, ECDSA >= P-256 or Ed25519.")
	}
	if cert.SignatureAlgorithm == x509.SHA1WithRSA {
		add(SeverityMedium,
			"Certificate is signed with SHA-1",
			"SignatureAlgorithm: "+cert.SignatureAlgorithm.String(),
			"Reissue with SHA-256; SHA-1 signatures can be forged.")
	}

	// Chain completeness: browsers need the intermediates too.
	if chain, cerr := inspectChain(ctx, host, port, t.Opts.Timeout); cerr == nil && len(chain) == 1 {
		add(SeverityLow,
			"Server does not send intermediate certificates",
			fmt.Sprintf("Chain length: %d (leaf only).", len(chain)),
			"Serve the full chain (leaf + intermediates) so older clients can validate it.")
	}

	return out, nil
}

// keyStrength reports the certificate's key algorithm, its size in bits
// and the recommended minimum for that algorithm.
func keyStrength(cert *x509.Certificate) (algo string, bits, floor int, known bool) {
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return "RSA", pub.N.BitLen(), 2048, true
	case *ecdsa.PublicKey:
		// Curve is the embedded elliptic.Curve, whose Params() gives the
		// field size; a public key always carries a named curve.
		params := pub.Params()
		if params == nil {
			return "", 0, 0, false
		}
		return "ECDSA", params.BitSize, 256, true
	case ed25519.PublicKey:
		return "Ed25519", len(pub) * 8, 128, true
	}
	return "", 0, 0, false
}

// probeHTTPS reports whether an HTTPS endpoint answers on this host.
func probeHTTPS(ctx context.Context, t *Target) bool {
	u := *t.URL
	u.Scheme = "https"
	u.Path = "/"
	u.RawPath = ""
	u.RawQuery = ""
	u.ForceQuery = false
	u.Fragment = ""
	if t.URL.Scheme == "https" {
		return true
	}
	_, err := t.Get(ctx, u.String(), true)
	return err == nil
}

// inspectTLS performs a handshake to read the leaf certificate and the
// negotiated protocol version.
func inspectTLS(ctx context.Context, host, port string, timeout time.Duration) (*x509.Certificate, uint16, error) {
	dialer := &tls.Dialer{
		Config: &tls.Config{
			// #nosec G402 -- we only want the handshake so we can report on
			// it; hostname and chain verification are done separately and
			// reported as their own findings.
			InsecureSkipVerify: true,
			ServerName:         host,
			MinVersion:         tls.VersionTLS10,
		},
	}
	dctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	conn, err := dialer.DialContext(dctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		return nil, 0, err
	}
	tc, ok := conn.(*tls.Conn)
	if !ok {
		// Closing a connection we are about to discard cannot fail in a way
		// worth reporting, but the error still has to be acknowledged.
		_ = conn.Close()
		return nil, 0, fmt.Errorf("unexpected connection type %T", conn)
	}
	defer func() { _ = tc.Close() }()

	state := tc.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, state.Version, fmt.Errorf("server presented no certificates")
	}
	return state.PeerCertificates[0], state.Version, nil
}

// inspectChain returns every certificate the server sent during a handshake.
func inspectChain(parent context.Context, host, port string, timeout time.Duration) ([]*x509.Certificate, error) {
	dialer := &tls.Dialer{
		Config: &tls.Config{
			InsecureSkipVerify: true, // #nosec G402 -- see inspectTLS
			ServerName:         host,
			MinVersion:         tls.VersionTLS10,
		},
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	tc, ok := conn.(*tls.Conn)
	if !ok {
		return nil, fmt.Errorf("unexpected connection type %T", conn)
	}
	return tc.ConnectionState().PeerCertificates, nil
}

// tlsVersionName renders a TLS version as a human readable string.
func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	case 0x0300:
		return "SSL 3.0"
	}
	return fmt.Sprintf("0x%04x", v)
}
