package main

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/terrabyteian/flint/internal/blob"
	"github.com/terrabyteian/flint/internal/config"
	"github.com/terrabyteian/flint/internal/fsys"
	"github.com/terrabyteian/flint/internal/meta"
)

// runMainEnv makes the test binary act as flint: a child started with it
// set runs run() on its command-line arguments.
const runMainEnv = "FLINT_TEST_RUN_MAIN"

func TestMain(m *testing.M) {
	if os.Getenv(runMainEnv) == "1" {
		os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
	}
	os.Exit(m.Run())
}

// flintProcess is a flint serve child process.
type flintProcess struct {
	cmd  *exec.Cmd
	addr string // set once the server logs that it is listening
	done chan struct{}

	mu   sync.Mutex
	logs []map[string]any
	raw  []string
}

// startFlint starts flint with args and waits until it listens or exits.
func startFlint(t *testing.T, args ...string) *flintProcess {
	t.Helper()
	cmd := exec.Command(os.Args[0], args...)
	cmd.Env = append(os.Environ(), runMainEnv+"=1")
	stderr, err := cmd.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	p := &flintProcess{cmd: cmd, done: make(chan struct{})}
	listening := make(chan string, 1)
	go func() {
		defer close(p.done)
		sc := bufio.NewScanner(stderr)
		for sc.Scan() {
			line := sc.Text()
			var rec map[string]any
			json.Unmarshal([]byte(line), &rec)
			p.mu.Lock()
			p.raw = append(p.raw, line)
			if rec != nil {
				p.logs = append(p.logs, rec)
			}
			p.mu.Unlock()
			if rec["msg"] == "flint listening" {
				listening <- rec["addr"].(string)
			}
		}
		cmd.Wait()
	}()
	t.Cleanup(func() {
		cmd.Process.Kill()
		<-p.done
	})
	select {
	case p.addr = <-listening:
	case <-p.done:
	case <-time.After(30 * time.Second):
		t.Fatalf("flint did not start; output:\n%s", p.output())
	}
	return p
}

// wait waits for the process to exit and returns its exit code.
func (p *flintProcess) wait(t *testing.T) int {
	t.Helper()
	select {
	case <-p.done:
	case <-time.After(30 * time.Second):
		t.Fatalf("flint did not exit; output:\n%s", p.output())
	}
	return p.cmd.ProcessState.ExitCode()
}

func (p *flintProcess) output() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return strings.Join(p.raw, "\n")
}

func (p *flintProcess) hasLog(msg string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, rec := range p.logs {
		if rec["msg"] == msg {
			return true
		}
	}
	return false
}

func writeConfig(t *testing.T, cfg map[string]any) string {
	t.Helper()
	b, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "flint.json")
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func get(t *testing.T, client *http.Client, url string) (int, string) {
	t.Helper()
	resp, err := client.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, string(b)
}

// TestServeSmoke runs flint serve end to end: it starts, serves health,
// readiness, and metrics, locks its data directory against a second
// process, shuts down gracefully on SIGTERM, and starts again on the same
// data directory.
func TestServeSmoke(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "data")
	cfgPath := writeConfig(t, map[string]any{
		"listen":  "127.0.0.1:0",
		"dataDir": dataDir,
		"log":     map[string]any{"level": "debug"},
	})
	p := startFlint(t, "serve", "-config", cfgPath)
	if p.addr == "" {
		t.Fatalf("flint exited at startup:\n%s", p.output())
	}
	base := "http://" + p.addr
	client := http.DefaultClient

	if code, body := get(t, client, base+"/healthz"); code != 200 || body != "ok\n" {
		t.Errorf("/healthz = %d %q", code, body)
	}
	if code, body := get(t, client, base+"/readyz"); code != 200 || body != "ok\n" {
		t.Errorf("/readyz = %d %q", code, body)
	}
	if code, body := get(t, client, base+"/v2/"); code != 200 || body != "{}" {
		t.Errorf("/v2/ = %d %q, want the OCI API base check", code, body)
	}
	if code, _ := get(t, client, base+"/nope"); code != 404 {
		t.Errorf("/nope = %d, want 404", code)
	}
	code, body := get(t, client, base+"/metrics")
	if code != 200 {
		t.Fatalf("/metrics = %d", code)
	}
	for _, want := range []string{
		"flint_meta_store_poisoned 0\n",
		"flint_meta_sequence 0\n",
		`flint_build_info{version="dev",goversion="go`,
		`flint_http_requests_total{method="GET",route="GET /healthz",code="200"} 1` + "\n",
		`flint_http_requests_total{method="GET",route="oci.base",code="200"} 1` + "\n",
		`flint_http_requests_total{method="GET",route="unmatched",code="404"} 1` + "\n",
		"go_goroutines ",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("/metrics missing %q", want)
		}
	}
	for _, path := range []string{"LOCK", "meta", "blobs/sha256/00", "uploads"} {
		if _, err := os.Stat(filepath.Join(dataDir, path)); err != nil {
			t.Errorf("data directory: %v", err)
		}
	}

	// A second process on the same data directory refuses to start.
	p2 := startFlint(t, "serve", "-config", cfgPath)
	if code := p2.wait(t); code != 1 || !strings.Contains(p2.output(), "in use by another flint process") {
		t.Errorf("second flint: exit %d, output:\n%s", code, p2.output())
	}

	if err := p.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	if code := p.wait(t); code != 0 {
		t.Errorf("exit code after SIGTERM = %d, output:\n%s", code, p.output())
	}
	for _, msg := range []string{"shutting down", "shutdown complete"} {
		if !p.hasLog(msg) {
			t.Errorf("no %q log; output:\n%s", msg, p.output())
		}
	}
	for _, line := range strings.Split(p.output(), "\n") {
		if !json.Valid([]byte(line)) {
			t.Errorf("log line is not JSON: %q", line)
		}
	}

	// The lock is released, and the store reopens.
	p3 := startFlint(t, "serve", "-config", cfgPath)
	if p3.addr == "" {
		t.Fatalf("restart failed:\n%s", p3.output())
	}
	p3.cmd.Process.Signal(syscall.SIGINT)
	if code := p3.wait(t); code != 0 {
		t.Errorf("exit code after SIGINT = %d", code)
	}
}

func TestServeTLS(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile, cert := writeTestCert(t, dir)
	cfgPath := writeConfig(t, map[string]any{
		"listen":  "127.0.0.1:0",
		"dataDir": filepath.Join(dir, "data"),
		"tls":     map[string]any{"certFile": certFile, "keyFile": keyFile},
	})
	p := startFlint(t, "serve", "-config", cfgPath)
	if p.addr == "" {
		t.Fatalf("flint exited at startup:\n%s", p.output())
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}}}
	if code, _ := get(t, client, "https://"+p.addr+"/readyz"); code != 200 {
		t.Errorf("/readyz over TLS = %d", code)
	}
	code, body := get(t, client, "https://"+p.addr+"/metrics")
	if code != 200 || !strings.Contains(body, "flint_tls_certificate_expiry_timestamp_seconds ") {
		t.Errorf("/metrics over TLS = %d, missing the certificate expiry", code)
	}
	p.cmd.Process.Signal(syscall.SIGTERM)
	if code := p.wait(t); code != 0 {
		t.Errorf("exit code = %d", code)
	}
}

func TestServeStartupErrors(t *testing.T) {
	dir := t.TempDir()
	tests := []struct {
		name string
		cfg  string
		want string
	}{
		{"invalid config", `{"dataDir": "relative"}`, "dataDir"},
		{"unknown field", `{"dataDir": "/tmp/x", "lisen": ":1"}`, `unknown field "lisen"`},
		{"bad tls files", `{"listen": "127.0.0.1:0", "dataDir": "` + filepath.Join(dir, "d1") +
			`", "tls": {"certFile": "/nonexistent.crt", "keyFile": "/nonexistent.key"}}`, "nonexistent.crt"},
		{"address in use", "", "address already in use"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := tt.cfg
			if cfg == "" {
				ln, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer ln.Close()
				cfg = `{"listen": "` + ln.Addr().String() + `", "dataDir": "` + filepath.Join(dir, "d2") + `"}`
			}
			path := filepath.Join(t.TempDir(), "flint.json")
			os.WriteFile(path, []byte(cfg), 0o644)
			var stderr strings.Builder
			code := serve(context.Background(), []string{"-config", path}, &stderr)
			if code != 1 || !strings.Contains(stderr.String(), tt.want) {
				t.Errorf("serve = %d, stderr %q; want 1 and %q", code, stderr.String(), tt.want)
			}
		})
	}
}

// TestPoisonedStoreStaysReady checks the agreed readiness policy: after a
// failed log fsync poisons the metadata store, flint stays ready, and the
// fault shows in flint_meta_store_poisoned.
func TestPoisonedStoreStaysReady(t *testing.T) {
	m := fsys.NewMem()
	store, err := meta.Open("/data/meta", meta.Options{FS: m, Logger: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	blobs, err := blob.NewFS("/data", blob.Options{FS: m})
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Parse([]byte(`{"dataDir": "/data"}`))
	if err != nil {
		t.Fatal(err)
	}
	srv, _, err := newServer(context.Background(), cfg, slog.New(slog.DiscardHandler), m, store, blobs)
	if err != nil {
		t.Fatal(err)
	}
	h := srv.Handler()
	scrape := func() string {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
		return rec.Body.String()
	}
	if !strings.Contains(scrape(), "flint_meta_store_poisoned 0\n") {
		t.Fatal("healthy store reported poisoned")
	}

	m.SetFault(func(op fsys.Op, name string) error {
		if op == fsys.OpSync && filepath.Ext(name) == ".log" {
			return errors.New("injected fsync failure")
		}
		return nil
	})
	var b meta.Batch
	b.Put([]byte("k"), []byte("v"))
	if _, err := store.Commit(context.Background(), &b); !errors.Is(err, meta.ErrPoisoned) {
		t.Fatalf("Commit = %v, want ErrPoisoned", err)
	}

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/readyz", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("/readyz with a poisoned store = %d %q, want 200", rec.Code, rec.Body)
	}
	if out := scrape(); !strings.Contains(out, "flint_meta_store_poisoned 1\n") {
		t.Errorf("poisoned store not reported:\n%s", out)
	}
}

// writeTestCert writes a self-signed certificate for 127.0.0.1 and its key.
func writeTestCert(t *testing.T, dir string) (certFile, keyFile string, cert *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "flint test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
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
	certFile, keyFile = filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600)
	cert, _ = x509.ParseCertificate(der)
	return certFile, keyFile, cert
}
