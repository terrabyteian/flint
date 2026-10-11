package server

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/terrabyteian/flint/internal/metrics"
)

// certReloader serves a certificate loaded from files and reloads it when
// the files change. The standard library has no file-change notification,
// so it polls: each check reads both files, and when their contents differ
// from the pair last tried, parses and installs them. Comparing contents
// rather than modification times also catches Kubernetes secret updates,
// which swap a symlink. A pair that fails to load, such as a certificate
// replaced before its key, leaves the current certificate in place and is
// retried on the next check once either file changes again.
type certReloader struct {
	certFile, keyFile string
	log               *slog.Logger
	reloads           *metrics.Counter

	cert atomic.Pointer[tls.Certificate]

	mu   sync.Mutex
	last [2][sha256.Size]byte // sums of the pair last tried, loaded or not
	err  string               // why the last pair failed, if it did
}

func newCertReloader(certFile, keyFile string, log *slog.Logger, reg *metrics.Registry) (*certReloader, error) {
	c := &certReloader{certFile: certFile, keyFile: keyFile, log: log}
	if err := c.check(); err != nil {
		return nil, err
	}
	c.reloads = reg.Counter("flint_tls_reloads_total",
		"Certificate reloads after the certificate or key file changed, by result.", "result")
	c.reloads.With("success")
	c.reloads.With("failure")
	reg.GaugeFunc("flint_tls_certificate_expiry_timestamp_seconds",
		"Expiry time of the served TLS certificate, in seconds since the Unix epoch.",
		func() float64 { return float64(leaf(c.cert.Load()).NotAfter.Unix()) })
	return c, nil
}

func (c *certReloader) getCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return c.cert.Load(), nil
}

// run checks the files every interval until ctx is done.
func (c *certReloader) run(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			c.check()
		}
	}
}

// check loads the files if they changed since the last check. It returns
// an error only when no certificate is loaded yet and loading failed.
func (c *certReloader) check() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	initial := c.cert.Load() == nil
	cert, err := c.load(initial)
	switch {
	case initial && err != nil:
		return fmt.Errorf("server: tls: %w", err)
	case err != nil:
		// Log each distinct failure once, not on every poll.
		if err.Error() != c.err {
			c.err = err.Error()
			c.reloads.With("failure").Inc()
			c.log.Error("tls certificate reload failed; still serving the previous certificate", "err", err)
		}
	case cert != nil:
		c.err = ""
		c.cert.Store(cert)
		if !initial {
			l := leaf(cert)
			c.reloads.With("success").Inc()
			c.log.Info("tls certificate reloaded", "subject", l.Subject.String(),
				"not_after", l.NotAfter, "cert_file", c.certFile)
		}
	}
	return nil
}

// load reads both files and, if their contents differ from the pair last
// tried or force is set, parses them. It returns nil, nil if they are
// unchanged.
func (c *certReloader) load(force bool) (*tls.Certificate, error) {
	certPEM, err := os.ReadFile(c.certFile)
	if err != nil {
		c.last = [2][sha256.Size]byte{} // retry once readable, even if unchanged
		return nil, err
	}
	keyPEM, err := os.ReadFile(c.keyFile)
	if err != nil {
		c.last = [2][sha256.Size]byte{}
		return nil, err
	}
	sums := [2][sha256.Size]byte{sha256.Sum256(certPEM), sha256.Sum256(keyPEM)}
	if sums == c.last && !force {
		return nil, nil
	}
	c.last = sums
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("loading certificate %s and key %s: %w", c.certFile, c.keyFile, err)
	}
	return &cert, nil
}

// leaf returns the parsed leaf certificate of cert.
func leaf(cert *tls.Certificate) *x509.Certificate {
	if cert.Leaf != nil {
		return cert.Leaf
	}
	l, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return &x509.Certificate{}
	}
	return l
}
