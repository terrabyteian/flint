package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// testCert is a self-signed certificate for 127.0.0.1.
type testCert struct {
	certPEM, keyPEM []byte
	cert            *x509.Certificate
}

func newTestCert(t *testing.T, cn string) testCert {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour).Truncate(time.Second),
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return testCert{
		certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		keyPEM:  pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
		cert:    cert,
	}
}

// writeAtomic replaces a file the way a careful tool does: write a
// temporary file, then rename it into place.
func writeAtomic(t *testing.T, path string, b []byte) {
	t.Helper()
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}
}

// servedCert connects to addr and returns the certificate it presents.
func servedCert(t *testing.T, addr string, roots *x509.CertPool) (*x509.Certificate, error) {
	t.Helper()
	conn, err := tls.Dial("tcp", addr, &tls.Config{RootCAs: roots, ServerName: "127.0.0.1"})
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	return conn.ConnectionState().PeerCertificates[0], nil
}

// waitForCert polls until the server presents want.
func waitForCert(t *testing.T, addr string, want testCert) {
	t.Helper()
	roots := x509.NewCertPool()
	roots.AddCert(want.cert)
	deadline := time.Now().Add(5 * time.Second)
	for {
		got, err := servedCert(t, addr, roots)
		if err == nil && got.Equal(want.cert) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("server never presented %s: last %v, %v", want.cert.Subject.CommonName, got, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestTLSHotReload(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	a := newTestCert(t, "cert-a")
	writeAtomic(t, certFile, a.certPEM)
	writeAtomic(t, keyFile, a.keyPEM)

	s, logs := newTestServer(t, Options{
		Addr:              "127.0.0.1:0",
		TLS:               &TLSFiles{CertFile: certFile, KeyFile: keyFile},
		TLSReloadInterval: 10 * time.Millisecond,
	})
	addr, err := s.Listen()
	if err != nil {
		t.Fatal(err)
	}
	served := make(chan error, 1)
	go func() { served <- s.Serve() }()
	defer func() {
		s.Shutdown(t.Context())
		if err := <-served; err != nil {
			t.Errorf("Serve: %v", err)
		}
	}()
	waitForCert(t, addr.String(), a)

	// HTTPS requests work, with HTTP/2.
	roots := x509.NewCertPool()
	roots.AddCert(a.cert)
	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig:   &tls.Config{RootCAs: roots},
		ForceAttemptHTTP2: true,
	}}
	resp, err := client.Get("https://" + addr.String() + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.ProtoMajor != 2 {
		t.Errorf("healthz over TLS: %d %s, want 200 over HTTP/2", resp.StatusCode, resp.Proto)
	}
	client.CloseIdleConnections()

	// Replace the certificate before the key: the mismatched pair is
	// rejected and the old certificate keeps serving.
	b := newTestCert(t, "cert-b")
	writeAtomic(t, certFile, b.certPEM)
	deadline := time.Now().Add(5 * time.Second)
	for logs.find(t, "tls certificate reload failed; still serving the previous certificate", nil) == nil {
		if time.Now().After(deadline) {
			t.Fatal("mismatched pair was not reported")
		}
		time.Sleep(10 * time.Millisecond)
	}
	waitForCert(t, addr.String(), a)

	// Once the key follows, the new certificate is served without a restart.
	writeAtomic(t, keyFile, b.keyPEM)
	waitForCert(t, addr.String(), b)
	if logs.find(t, "tls certificate reloaded", map[string]any{"subject": "CN=cert-b"}) == nil {
		t.Error("reload not logged")
	}

	// Garbage is rejected too, and logged once however many polls see it.
	writeAtomic(t, certFile, []byte("not a certificate"))
	time.Sleep(100 * time.Millisecond)
	waitForCert(t, addr.String(), b)
	failures := 0
	for _, rec := range logs.records(t) {
		if rec["msg"] == "tls certificate reload failed; still serving the previous certificate" {
			failures++
		}
	}
	if failures != 2 {
		t.Errorf("logged %d reload failures, want 2 (one per distinct bad state)", failures)
	}

	out := scrape(t, s.Handler())
	for _, want := range []string{
		`flint_tls_reloads_total{result="success"} 1`,
		`flint_tls_reloads_total{result="failure"} 2`,
		"flint_tls_certificate_expiry_timestamp_seconds " + strconv.FormatFloat(float64(b.cert.NotAfter.Unix()), 'g', -1, 64),
	} {
		if !strings.Contains(out, want+"\n") {
			t.Errorf("metrics missing %q:\n%s", want, out)
		}
	}
}

// TestTLSSymlinkSwap mimics a Kubernetes secret volume, where the files
// are symlinks through a directory link that is swapped atomically.
func TestTLSSymlinkSwap(t *testing.T) {
	dir := t.TempDir()
	install := func(name string, c testCert) {
		d := filepath.Join(dir, name)
		os.Mkdir(d, 0o700)
		writeAtomic(t, filepath.Join(d, "tls.crt"), c.certPEM)
		writeAtomic(t, filepath.Join(d, "tls.key"), c.keyPEM)
		tmp := filepath.Join(dir, "..data_tmp")
		if err := os.Symlink(name, tmp); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(tmp, filepath.Join(dir, "..data")); err != nil {
			t.Fatal(err)
		}
	}
	a, b := newTestCert(t, "a"), newTestCert(t, "b")
	install("v1", a)
	for _, f := range []string{"tls.crt", "tls.key"} {
		if err := os.Symlink(filepath.Join("..data", f), filepath.Join(dir, f)); err != nil {
			t.Fatal(err)
		}
	}
	s, _ := newTestServer(t, Options{
		Addr:              "127.0.0.1:0",
		TLS:               &TLSFiles{CertFile: filepath.Join(dir, "tls.crt"), KeyFile: filepath.Join(dir, "tls.key")},
		TLSReloadInterval: 10 * time.Millisecond,
	})
	addr, err := s.Listen()
	if err != nil {
		t.Fatal(err)
	}
	go s.Serve()
	defer s.Shutdown(t.Context())
	waitForCert(t, addr.String(), a)
	install("v2", b)
	waitForCert(t, addr.String(), b)
}

func TestTLSStartupErrors(t *testing.T) {
	dir := t.TempDir()
	a, b := newTestCert(t, "a"), newTestCert(t, "b")
	certFile, keyFile := filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	writeAtomic(t, certFile, a.certPEM)
	writeAtomic(t, keyFile, b.keyPEM)
	tests := []struct {
		name       string
		cert, key  string
		wantSubstr string
	}{
		{"missing cert", filepath.Join(dir, "nope.crt"), keyFile, "nope.crt"},
		{"missing key", certFile, filepath.Join(dir, "nope.key"), "nope.key"},
		{"mismatched pair", certFile, keyFile, "does not match"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := New(Options{TLS: &TLSFiles{CertFile: tt.cert, KeyFile: tt.key}})
			if err == nil || !strings.Contains(err.Error(), tt.wantSubstr) {
				t.Errorf("New = %v, want an error containing %q", err, tt.wantSubstr)
			}
		})
	}
}

// TestTLSReloadAfterMissingFile checks that a file that disappears and
// comes back unchanged is picked up again rather than ignored.
func TestTLSReloadAfterMissingFile(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	a := newTestCert(t, "a")
	writeAtomic(t, certFile, a.certPEM)
	writeAtomic(t, keyFile, a.keyPEM)
	s, logs := newTestServer(t, Options{TLS: &TLSFiles{CertFile: certFile, KeyFile: keyFile}})
	os.Remove(keyFile)
	s.certs.check()
	if logs.find(t, "tls certificate reload failed; still serving the previous certificate", nil) == nil {
		t.Error("missing key not reported")
	}
	writeAtomic(t, keyFile, a.keyPEM)
	s.certs.check()
	if logs.find(t, "tls certificate reloaded", nil) == nil {
		t.Error("restored files not reloaded")
	}
	if s.certs.err != "" {
		t.Errorf("failure state not cleared: %q", s.certs.err)
	}
}
