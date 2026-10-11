package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/terrabyteian/flint/internal/metrics"
)

// logBuffer collects JSON log lines safely across goroutines.
type logBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *logBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

// records decodes every log line.
func (b *logBuffer) records(t *testing.T) []map[string]any {
	t.Helper()
	b.mu.Lock()
	defer b.mu.Unlock()
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(b.buf.String()), "\n") {
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("log line %q is not JSON: %v", line, err)
		}
		out = append(out, m)
	}
	return out
}

// find returns the first log record with the given message and fields.
func (b *logBuffer) find(t *testing.T, msg string, fields map[string]any) map[string]any {
	t.Helper()
	for _, rec := range b.records(t) {
		if rec["msg"] != msg {
			continue
		}
		match := true
		for k, v := range fields {
			if rec[k] != v {
				match = false
			}
		}
		if match {
			return rec
		}
	}
	return nil
}

func newTestServer(t *testing.T, opts Options) (*Server, *logBuffer) {
	t.Helper()
	logs := &logBuffer{}
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	}
	if opts.Metrics == nil {
		opts.Metrics = metrics.NewRegistry()
	}
	s, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	return s, logs
}

func do(t *testing.T, h http.Handler, method, target string, header http.Header) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(method, target, nil)
	for k, vs := range header {
		r.Header[k] = vs
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

func scrape(t *testing.T, h http.Handler) string {
	t.Helper()
	rec := do(t, h, "GET", "/metrics", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("/metrics: %d", rec.Code)
	}
	return rec.Body.String()
}

func TestHealth(t *testing.T) {
	s, _ := newTestServer(t, Options{})
	h := s.Handler()
	for _, path := range []string{"/healthz", "/readyz"} {
		rec := do(t, h, "GET", path, nil)
		if rec.Code != http.StatusOK || rec.Body.String() != "ok\n" {
			t.Errorf("GET %s = %d %q, want 200 ok", path, rec.Code, rec.Body)
		}
		if rec := do(t, h, "HEAD", path, nil); rec.Code != http.StatusOK {
			t.Errorf("HEAD %s = %d", path, rec.Code)
		}
	}
	if rec := do(t, h, "POST", "/healthz", nil); rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST /healthz = %d, want 405", rec.Code)
	}
}

func TestReadinessChecks(t *testing.T) {
	s, _ := newTestServer(t, Options{})
	var mu sync.Mutex
	var dbErr error
	s.AddReadinessCheck("db", func(ctx context.Context) error {
		mu.Lock()
		defer mu.Unlock()
		return dbErr
	})
	s.AddReadinessCheck("other", func(ctx context.Context) error { return nil })
	h := s.Handler()

	if rec := do(t, h, "GET", "/readyz", nil); rec.Code != http.StatusOK {
		t.Fatalf("readyz = %d %q, want 200", rec.Code, rec.Body)
	}
	mu.Lock()
	dbErr = errors.New("disk on fire")
	mu.Unlock()
	rec := do(t, h, "GET", "/readyz", nil)
	if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "db: disk on fire") {
		t.Errorf("readyz = %d %q, want 503 naming the failed check", rec.Code, rec.Body)
	}
	if strings.Contains(rec.Body.String(), "other") {
		t.Errorf("readyz body %q names a passing check", rec.Body)
	}
	// Liveness is independent of readiness.
	if rec := do(t, h, "GET", "/healthz", nil); rec.Code != http.StatusOK {
		t.Errorf("healthz = %d while not ready, want 200", rec.Code)
	}
}

func TestReadinessDuringShutdown(t *testing.T) {
	s, _ := newTestServer(t, Options{})
	h := s.Handler()
	if err := s.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	rec := do(t, h, "GET", "/readyz", nil)
	if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "shutting down") {
		t.Errorf("readyz after Shutdown = %d %q, want 503", rec.Code, rec.Body)
	}
	if rec := do(t, h, "GET", "/healthz", nil); rec.Code != http.StatusOK {
		t.Errorf("healthz after Shutdown = %d, want 200", rec.Code)
	}
}

// TestMiddleware checks that Use wraps registered routes in order and
// leaves the built-in endpoints alone.
func TestMiddleware(t *testing.T) {
	s, _ := newTestServer(t, Options{})
	var order []string
	mw := func(name string) Middleware {
		return func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				order = append(order, name)
				if r.Header.Get("Authorization") == "" {
					http.Error(w, "unauthorized", http.StatusUnauthorized)
					return
				}
				next.ServeHTTP(w, r)
			})
		}
	}
	s.Use(mw("outer"))
	s.Use(mw("inner"))
	s.HandleFunc("GET /v2/", func(w http.ResponseWriter, r *http.Request) {
		order = append(order, "handler")
		io.WriteString(w, "{}")
	})
	h := s.Handler()

	if rec := do(t, h, "GET", "/v2/", nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("unauthenticated /v2/ = %d, want 401", rec.Code)
	}
	order = nil
	rec := do(t, h, "GET", "/v2/", http.Header{"Authorization": {"Bearer x"}})
	if rec.Code != http.StatusOK || strings.Join(order, ",") != "outer,inner,handler" {
		t.Errorf("authenticated /v2/ = %d, order %v", rec.Code, order)
	}
	order = nil
	for _, path := range []string{"/healthz", "/readyz", "/metrics"} {
		if rec := do(t, h, "GET", path, nil); rec.Code != http.StatusOK {
			t.Errorf("%s = %d, want 200 without credentials", path, rec.Code)
		}
	}
	if len(order) != 0 {
		t.Errorf("middleware ran for built-in endpoints: %v", order)
	}
}

func TestRegistrationClosesWhenServing(t *testing.T) {
	s, _ := newTestServer(t, Options{})
	s.Handler()
	for name, fn := range map[string]func(){
		"Handle":            func() { s.Handle("/x", http.NotFoundHandler()) },
		"Use":               func() { s.Use(func(h http.Handler) http.Handler { return h }) },
		"AddReadinessCheck": func() { s.AddReadinessCheck("x", func(context.Context) error { return nil }) },
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("%s after Handler did not panic", name)
				}
			}()
			fn()
		}()
	}
}

func TestRequestMetrics(t *testing.T) {
	s, _ := newTestServer(t, Options{})
	s.HandleFunc("PUT /v2/", func(w http.ResponseWriter, r *http.Request) {
		SetRoute(r.Context(), "oci.blob.upload")
		w.WriteHeader(http.StatusCreated)
		io.WriteString(w, "hello")
	})
	h := s.Handler()
	do(t, h, "GET", "/healthz", nil)
	do(t, h, "PUT", "/v2/library/app/blobs/uploads/x", nil)
	do(t, h, "GET", "/nothing-here", nil)
	do(t, h, "BREW", "/healthz", nil)

	out := scrape(t, h)
	for _, want := range []string{
		`flint_http_requests_total{method="GET",route="GET /healthz",code="200"} 1`,
		`flint_http_requests_total{method="PUT",route="oci.blob.upload",code="201"} 1`,
		`flint_http_requests_total{method="GET",route="unmatched",code="404"} 1`,
		`flint_http_requests_total{method="other",route="unmatched",code="405"} 1`,
		`flint_http_response_bytes_total{method="PUT",route="oci.blob.upload"} 5`,
		`flint_http_request_duration_seconds_count{method="PUT",route="oci.blob.upload"} 1`,
		// The scrape itself is in flight while it is written.
		`flint_http_requests_in_flight 1`,
	} {
		if !strings.Contains(out, want+"\n") {
			t.Errorf("metrics missing %q:\n%s", want, out)
		}
	}
}

func TestRequestLog(t *testing.T) {
	s, logs := newTestServer(t, Options{TrustedProxies: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}})
	var info RequestInfo
	s.HandleFunc("GET /v2/{rest...}", func(w http.ResponseWriter, r *http.Request) {
		info = Info(r.Context())
		LogAttrs(r.Context(), slog.String("user", "alice"))
		w.WriteHeader(http.StatusAccepted)
	})
	h := s.Handler()
	// httptest.NewRequest uses RemoteAddr 192.0.2.1, a trusted proxy here.
	rec := do(t, h, "GET", "/v2/a/b?secret=1", http.Header{
		"X-Forwarded-For":   {"198.51.100.7"},
		"X-Forwarded-Proto": {"https"},
		"User-Agent":        {"docker/27"},
	})
	id := rec.Header().Get("X-Request-Id")
	if id == "" || info.ID != id {
		t.Fatalf("X-Request-Id %q, handler saw ID %q", id, info.ID)
	}
	if info.ClientIP != netip.MustParseAddr("198.51.100.7") || info.Scheme != "https" || info.Host != "example.com" {
		t.Errorf("Info = %+v", info)
	}
	rec2 := logs.find(t, "request", map[string]any{"request_id": id})
	if rec2 == nil {
		t.Fatalf("no request log for %s in %v", id, logs.records(t))
	}
	want := map[string]any{
		"level": "INFO", "method": "GET", "path": "/v2/a/b", "route": "GET /v2/{rest...}",
		"status": float64(202), "bytes": float64(0), "client_ip": "198.51.100.7",
		"user_agent": "docker/27", "user": "alice", "proto": "HTTP/1.1",
	}
	for k, v := range want {
		if rec2[k] != v {
			t.Errorf("log %s = %v, want %v", k, rec2[k], v)
		}
	}
	if _, ok := rec2["duration_ms"].(float64); !ok {
		t.Errorf("log duration_ms = %v", rec2["duration_ms"])
	}
	for k, v := range rec2 {
		if s, _ := v.(string); strings.Contains(s, "secret") {
			t.Errorf("log field %s = %q leaks the query string", k, s)
		}
	}

	// Probes and scrapes log at debug level.
	do(t, h, "GET", "/healthz", nil)
	if rec := logs.find(t, "request", map[string]any{"path": "/healthz"}); rec == nil || rec["level"] != "DEBUG" {
		t.Errorf("healthz log = %v, want a DEBUG record", rec)
	}
}

func TestPanicRecovery(t *testing.T) {
	s, logs := newTestServer(t, Options{})
	s.HandleFunc("GET /boom", func(w http.ResponseWriter, r *http.Request) { panic("kaboom") })
	h := s.Handler()
	rec := do(t, h, "GET", "/boom", nil)
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", rec.Code)
	}
	if logs.find(t, "panic serving request", map[string]any{"panic": "kaboom"}) == nil {
		t.Error("panic not logged")
	}
	if !strings.Contains(scrape(t, h), `flint_http_requests_total{method="GET",route="GET /boom",code="500"} 1`) {
		t.Error("panic not counted as a 500")
	}
}

// TestPanicAfterHeadersAborts checks that a handler panicking mid-response
// cuts the connection instead of letting the client see a complete,
// truncated response.
func TestPanicAfterHeadersAborts(t *testing.T) {
	s, _ := newTestServer(t, Options{})
	s.HandleFunc("GET /half", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		io.WriteString(w, "partial")
		w.(http.Flusher).Flush()
		panic("midway")
	})
	ts := httptest.NewServer(s.Handler())
	defer ts.Close()
	resp, err := http.Get(ts.URL + "/half")
	if err != nil {
		return // the connection was cut before the headers arrived: also fine
	}
	defer resp.Body.Close()
	if _, err := io.ReadAll(resp.Body); err == nil {
		t.Error("reading a response whose handler panicked mid-body succeeded")
	}
}

// TestReadFromPreserved checks that the response writer passed to handlers
// delegates io.ReaderFrom, which is how net/http reaches sendfile.
func TestReadFromPreserved(t *testing.T) {
	f, err := os.Create(filepath.Join(t.TempDir(), "blob"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	content := strings.Repeat("x", 100_000)
	f.WriteString(content)

	inner := &readFromRecorder{ResponseRecorder: httptest.NewRecorder()}
	rw := &responseWriter{ResponseWriter: inner}
	var w http.ResponseWriter = rw
	if _, ok := w.(io.ReaderFrom); !ok {
		t.Fatal("responseWriter does not implement io.ReaderFrom")
	}
	f.Seek(0, io.SeekStart)
	n, err := io.Copy(w, f)
	if err != nil || n != int64(len(content)) {
		t.Fatalf("io.Copy = %d, %v", n, err)
	}
	if !inner.readFrom {
		t.Error("io.Copy did not reach the underlying ReadFrom")
	}
	if rw.bytes != int64(len(content)) || rw.status != http.StatusOK {
		t.Errorf("recorded %d bytes, status %d", rw.bytes, rw.status)
	}
	if http.NewResponseController(w).Flush() != nil {
		t.Error("ResponseController cannot flush through the wrapper")
	}
}

type readFromRecorder struct {
	*httptest.ResponseRecorder
	readFrom bool
}

func (r *readFromRecorder) ReadFrom(src io.Reader) (int64, error) {
	r.readFrom = true
	return io.Copy(r.ResponseRecorder, src)
}

// TestServeAndGracefulShutdown runs a real listener: an in-flight request
// finishes during shutdown, readiness fails, and Serve returns nil.
func TestServeAndGracefulShutdown(t *testing.T) {
	s, logs := newTestServer(t, Options{Addr: "127.0.0.1:0"})
	started := make(chan struct{})
	release := make(chan struct{})
	s.HandleFunc("GET /slow", func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-release
		io.WriteString(w, "done")
	})
	addr, err := s.Listen()
	if err != nil {
		t.Fatal(err)
	}
	served := make(chan error, 1)
	go func() { served <- s.Serve() }()
	base := "http://" + addr.String()

	resp, err := http.Get(base + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.TLS != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("plain healthz: %d, tls %v", resp.StatusCode, resp.TLS != nil)
	}

	slow := make(chan string, 1)
	go func() {
		resp, err := http.Get(base + "/slow")
		if err != nil {
			slow <- "error: " + err.Error()
			return
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		slow <- string(b)
	}()
	<-started

	shutdown := make(chan error, 1)
	go func() { shutdown <- s.Shutdown(context.Background()) }()
	// Shutdown waits for the in-flight request.
	deadline := time.Now().Add(5 * time.Second)
	for !s.draining.Load() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	select {
	case err := <-shutdown:
		t.Fatalf("Shutdown returned %v with a request in flight", err)
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	if got := <-slow; got != "done" {
		t.Errorf("in-flight request got %q", got)
	}
	if err := <-shutdown; err != nil {
		t.Errorf("Shutdown: %v", err)
	}
	if err := <-served; err != nil {
		t.Errorf("Serve: %v", err)
	}
	if _, err := http.Get(base + "/healthz"); err == nil {
		t.Error("server still accepts connections after Shutdown")
	}
	if logs.find(t, "request", map[string]any{"path": "/slow", "status": float64(200)}) == nil {
		t.Error("in-flight request not logged")
	}
}

func TestShutdownTimeout(t *testing.T) {
	s, _ := newTestServer(t, Options{Addr: "127.0.0.1:0"})
	started := make(chan struct{})
	s.HandleFunc("GET /hang", func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-r.Context().Done() // ends only when the connection is closed
	})
	addr, err := s.Listen()
	if err != nil {
		t.Fatal(err)
	}
	served := make(chan error, 1)
	go func() { served <- s.Serve() }()
	go http.Get("http://" + addr.String() + "/hang")
	<-started

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := s.Shutdown(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("Shutdown = %v, want DeadlineExceeded", err)
	}
	if err := <-served; err != nil {
		t.Errorf("Serve: %v", err)
	}
}

func TestListenError(t *testing.T) {
	s, _ := newTestServer(t, Options{Addr: "127.0.0.1:0"})
	addr, err := s.Listen()
	if err != nil {
		t.Fatal(err)
	}
	defer s.Shutdown(context.Background())
	s2, _ := newTestServer(t, Options{Addr: addr.String()})
	if _, err := s2.Listen(); err == nil {
		t.Error("second Listen on the same address succeeded")
	}
	s3, _ := newTestServer(t, Options{})
	if err := s3.Serve(); err == nil {
		t.Error("Serve before Listen succeeded")
	}
}
