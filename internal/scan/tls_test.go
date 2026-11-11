package scan

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// certPair is a leaf certificate and the key that signed it.
type certPair struct {
	cert *x509.Certificate
	der  []byte
	key  *ecdsa.PrivateKey
}

// makeCert builds a leaf certificate for 127.0.0.1. When parent is nil the
// certificate signs itself, which is what a staging host usually presents.
func makeCert(t *testing.T, parent *certPair) certPair {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	signer, signerKey := tmpl, key
	if parent != nil {
		signer, signerKey = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signer, &key.PublicKey, signerKey)
	if err != nil {
		t.Fatalf("creating certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing certificate: %v", err)
	}
	return certPair{cert: cert, der: der, key: key}
}

// serveTLS starts a TLS server presenting the given certificate.
func serveTLS(t *testing.T, pair certPair) string {
	t.Helper()
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{{
		Certificate: [][]byte{pair.der},
		PrivateKey:  pair.key,
	}}}
	server.StartTLS()
	t.Cleanup(server.Close)
	return server.URL
}

// findTitle reports whether the findings contain a title.
func findTitle(findings []Finding, title string) bool {
	for _, f := range findings {
		if f.Title == title {
			return true
		}
	}
	return false
}

// TestTLSCheckFlagsSelfSignedLeaf runs the real check against a server whose
// certificate signed itself and is not a CA.
//
// The previous implementation used CheckSignatureFrom, which also enforces
// the RFC 5280 rules for the signing certificate: a self-signed leaf is
// rejected as its own parent, so the finding was never raised. This is the
// exact shape of certificate a staging host serves.
func TestTLSCheckFlagsSelfSignedLeaf(t *testing.T) {
	selfSigned := makeCert(t, nil)
	url := serveTLS(t, selfSigned)

	target, err := NewTarget(url, Options{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("NewTarget: %v", err)
	}
	findings, err := tlsCheck{}.Run(context.Background(), target)
	if err != nil {
		t.Fatalf("tls check: %v", err)
	}
	if !findTitle(findings, "Certificate is self-signed") {
		t.Errorf("a self-signed leaf certificate was not reported; findings: %v", findings)
	}
}

// TestTLSCheckDoesNotFlagCASignedLeaf is the other half: a certificate signed
// by a real CA must not be called self-signed.
func TestTLSCheckDoesNotFlagCASignedLeaf(t *testing.T) {
	ca := makeCert(t, nil)
	ca.cert.IsCA = true
	leaf := makeCert(t, &ca)
	url := serveTLS(t, leaf)

	target, err := NewTarget(url, Options{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("NewTarget: %v", err)
	}
	findings, err := tlsCheck{}.Run(context.Background(), target)
	if err != nil {
		t.Fatalf("tls check: %v", err)
	}
	if findTitle(findings, "Certificate is self-signed") {
		t.Error("a CA-signed certificate must not be reported as self-signed")
	}
}
