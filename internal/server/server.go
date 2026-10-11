// Package server is flint's HTTP server: routing, TLS from certificate
// files with hot reload, trusted-proxy handling, request logging and
// metrics, health endpoints, and graceful shutdown.
//
// Format and auth packages plug in without editing the server: they
// register routes with Handle and wrap those routes in middleware with Use,
// for example to authenticate requests. The built-in endpoints are not
// wrapped, so probes and scrapes never need credentials:
//
//	GET /healthz   liveness: 200 while the process serves HTTP
//	GET /readyz    readiness: 200 unless shutting down or a readiness check fails
//	GET /metrics   Prometheus metrics
//
// Every request, built-in or registered, passes through the server's own
// middleware first: it resolves the client's address, scheme, and host
// (see Info), assigns a request ID, recovers panics, records request
// metrics, and writes one JSON log line. The response writer it passes on
// keeps net/http's io.ReaderFrom, so blob downloads over plain HTTP/1.1
// still use sendfile.
package server

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/terrabyteian/flint/internal/metrics"
)

// DefaultTLSReloadInterval is how often the certificate files are checked
// for changes.
const DefaultTLSReloadInterval = 10 * time.Second

// Options configures a Server.
type Options struct {
	// Addr is the TCP address to listen on, host:port.
	Addr string
	// TLS, if set, serves HTTPS from these files and reloads them when
	// they change. Nil serves plain HTTP.
	TLS *TLSFiles
	// TrustedProxies are the peers whose forwarded headers are believed.
	TrustedProxies []netip.Prefix
	// Logger receives request and server logs; nil means slog.Default().
	Logger *slog.Logger
	// Metrics receives the server's metrics and is served at /metrics;
	// nil means a new registry.
	Metrics *metrics.Registry
	// TLSReloadInterval is how often the TLS files are checked for
	// changes; zero means DefaultTLSReloadInterval.
	TLSReloadInterval time.Duration
}

// TLSFiles names a PEM certificate chain and private key.
type TLSFiles struct {
	CertFile, KeyFile string
}

// Middleware wraps a handler.
type Middleware func(http.Handler) http.Handler

// ReadinessCheck reports whether a dependency is ready to serve traffic.
// It should return quickly.
type ReadinessCheck func(ctx context.Context) error

// Server is the HTTP server. Register routes, middleware, and readiness
// checks before Handler, Listen, or Serve; registering afterwards panics.
type Server struct {
	opts    Options
	log     *slog.Logger
	reg     *metrics.Registry
	proxies proxies
	certs   *certReloader

	mu      sync.Mutex
	routes  []route
	mws     []Middleware
	checks  []namedCheck
	handler http.Handler // built on first use; registration is closed after

	draining atomic.Bool
	httpSrv  *http.Server
	ln       net.Listener
	stop     context.CancelFunc // stops the certificate reloader
	stopped  chan struct{}

	requests  *metrics.Counter
	durations *metrics.Histogram
	respBytes *metrics.Counter
	inFlight  *metrics.GaugeSeries
}

type route struct {
	pattern string
	h       http.Handler
	builtin bool
}

type namedCheck struct {
	name string
	fn   ReadinessCheck
}

// New returns a server. With TLS configured, it loads the certificate now
// and fails if it cannot.
func New(opts Options) (*Server, error) {
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.Metrics == nil {
		opts.Metrics = metrics.NewRegistry()
	}
	if opts.TLSReloadInterval <= 0 {
		opts.TLSReloadInterval = DefaultTLSReloadInterval
	}
	s := &Server{
		opts:    opts,
		log:     opts.Logger,
		reg:     opts.Metrics,
		proxies: proxies(opts.TrustedProxies),
	}
	if opts.TLS != nil {
		certs, err := newCertReloader(opts.TLS.CertFile, opts.TLS.KeyFile, s.log, s.reg)
		if err != nil {
			return nil, err
		}
		s.certs = certs
	}

	s.requests = s.reg.Counter("flint_http_requests_total",
		"HTTP requests completed, by method, route, and status code.", "method", "route", "code")
	s.durations = s.reg.Histogram("flint_http_request_duration_seconds",
		"Time from receiving request headers to finishing the response, by method and route.",
		nil, "method", "route")
	s.respBytes = s.reg.Counter("flint_http_response_bytes_total",
		"Response body bytes written, by method and route.", "method", "route")
	s.inFlight = s.reg.Gauge("flint_http_requests_in_flight", "HTTP requests being served.").With()

	s.routes = []route{
		{pattern: "GET /healthz", h: http.HandlerFunc(s.healthz), builtin: true},
		{pattern: "GET /readyz", h: http.HandlerFunc(s.readyz), builtin: true},
		{pattern: "GET /metrics", h: s.reg.Handler(), builtin: true},
	}
	return s, nil
}

// Handle registers h for pattern, in net/http.ServeMux syntax. The
// handler runs inside every middleware added with Use.
func (s *Server) Handle(pattern string, h http.Handler) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.mustBeOpen("Handle")
	s.routes = append(s.routes, route{pattern: pattern, h: h})
}

// HandleFunc registers f for pattern; see Handle.
func (s *Server) HandleFunc(pattern string, f func(http.ResponseWriter, *http.Request)) {
	s.Handle(pattern, http.HandlerFunc(f))
}

// Use adds middleware around every handler registered with Handle, but
// not the built-in endpoints. The first middleware added is the outermost.
func (s *Server) Use(mw Middleware) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.mustBeOpen("Use")
	s.mws = append(s.mws, mw)
}

// AddReadinessCheck makes /readyz fail while check returns an error.
func (s *Server) AddReadinessCheck(name string, check ReadinessCheck) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.mustBeOpen("AddReadinessCheck")
	s.checks = append(s.checks, namedCheck{name, check})
}

func (s *Server) mustBeOpen(method string) {
	if s.handler != nil {
		panic("server: " + method + " called after the server started serving")
	}
}

// Handler returns the server's complete handler, closing registration.
func (s *Server) Handler() http.Handler {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.handler == nil {
		mux := http.NewServeMux()
		for _, rt := range s.routes {
			h := rt.h
			if !rt.builtin {
				for i := len(s.mws) - 1; i >= 0; i-- {
					h = s.mws[i](h)
				}
			}
			mux.Handle(rt.pattern, withRoute(h, rt.builtin))
		}
		s.handler = s.observe(mux)
	}
	return s.handler
}

// withRoute records the matched mux pattern as the request's default
// route label.
func withRoute(h http.Handler, quiet bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if st := stateFrom(r.Context()); st != nil {
			st.setDefaultRoute(r.Pattern, quiet)
		}
		h.ServeHTTP(w, r)
	})
}

// Listen binds the listening socket and starts the certificate reloader.
// It returns the bound address, which tells a caller the port chosen for
// a ":0" address.
func (s *Server) Listen() (net.Addr, error) {
	h := s.Handler()
	ln, err := net.Listen("tcp", s.opts.Addr)
	if err != nil {
		return nil, fmt.Errorf("server: %w", err)
	}
	s.ln = ln
	s.httpSrv = &http.Server{
		Handler: h,
		// Bound the time to send headers, against slow-header attacks.
		// There is no read or write timeout: blob transfers can
		// legitimately take a long time.
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
		ErrorLog:          slog.NewLogLogger(s.log.Handler(), slog.LevelWarn),
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.stop = cancel
	s.stopped = make(chan struct{})
	if s.certs != nil {
		s.httpSrv.TLSConfig = &tls.Config{
			MinVersion:     tls.VersionTLS12,
			GetCertificate: s.certs.getCertificate,
		}
		go func() {
			defer close(s.stopped)
			s.certs.run(ctx, s.opts.TLSReloadInterval)
		}()
	} else {
		close(s.stopped)
	}
	return ln.Addr(), nil
}

// Serve serves connections on the socket bound by Listen until Shutdown.
// It returns nil after a shutdown.
func (s *Server) Serve() error {
	if s.httpSrv == nil {
		return errors.New("server: Serve called before Listen")
	}
	var err error
	if s.certs != nil {
		// ServeTLS, unlike a plain tls.Listener, also enables HTTP/2.
		err = s.httpSrv.ServeTLS(s.ln, "", "")
	} else {
		err = s.httpSrv.Serve(s.ln)
	}
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// Shutdown makes /readyz fail, stops accepting connections, and waits for
// in-flight requests until ctx is done; then it closes the remaining
// connections and returns ctx's error.
func (s *Server) Shutdown(ctx context.Context) error {
	s.draining.Store(true)
	if s.httpSrv == nil {
		return nil
	}
	err := s.httpSrv.Shutdown(ctx)
	if err != nil {
		s.httpSrv.Close()
	}
	s.stop()
	<-s.stopped
	return err
}

func (s *Server) healthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	io.WriteString(w, "ok\n")
}

func (s *Server) readyz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if s.draining.Load() {
		w.WriteHeader(http.StatusServiceUnavailable)
		io.WriteString(w, "shutting down\n")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	var failed []string
	for _, c := range s.checks {
		if err := c.fn(ctx); err != nil {
			failed = append(failed, c.name+": "+err.Error())
		}
	}
	if len(failed) > 0 {
		w.WriteHeader(http.StatusServiceUnavailable)
		io.WriteString(w, "not ready\n"+strings.Join(failed, "\n")+"\n")
		return
	}
	io.WriteString(w, "ok\n")
}

// observe is the server's outermost middleware: request state, panic
// recovery, metrics, and the request log.
func (s *Server) observe(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		st := &requestState{info: resolve(r, s.proxies)}
		st.info.ID = rand.Text()
		w.Header().Set("X-Request-Id", st.info.ID)
		rw := &responseWriter{ResponseWriter: w}
		s.inFlight.Inc()

		defer func() {
			p := recover()
			abort := p == http.ErrAbortHandler
			if p != nil && !abort {
				s.log.Error("panic serving request", "request_id", st.info.ID, "panic", fmt.Sprint(p),
					"stack", string(debug.Stack()))
				if rw.status == 0 {
					http.Error(rw, "internal server error", http.StatusInternalServerError)
				} else {
					// Part of the response is out; abort the connection
					// so the client cannot take it for a whole one.
					abort = true
				}
			}
			s.inFlight.Dec()
			s.finish(r, rw, st, time.Since(start), abort)
			if abort {
				panic(http.ErrAbortHandler) // net/http closes the connection without logging
			}
		}()
		next.ServeHTTP(rw, r.WithContext(context.WithValue(r.Context(), stateKey{}, st)))
	})
}

// finish records metrics and writes the request log line.
func (s *Server) finish(r *http.Request, rw *responseWriter, st *requestState, d time.Duration, aborted bool) {
	route, quiet, attrs := st.snapshot()
	if route == "" {
		route = "unmatched"
	}
	status := rw.status
	if status == 0 {
		status = http.StatusOK
	}
	if aborted {
		status = 0 // the response was cut off; no status reached the client intact
	}
	method := methodLabel(r.Method)
	code := strconv.Itoa(status)
	s.requests.With(method, route, code).Inc()
	s.durations.With(method, route).Observe(d.Seconds())
	s.respBytes.With(method, route).Add(float64(rw.bytes))

	level := slog.LevelInfo
	if quiet {
		level = slog.LevelDebug
	}
	if !s.log.Enabled(r.Context(), level) {
		return
	}
	base := []slog.Attr{
		slog.String("request_id", st.info.ID),
		slog.String("method", r.Method),
		slog.String("path", r.URL.Path),
		slog.String("route", route),
		slog.Int("status", status),
		slog.Int64("bytes", rw.bytes),
		slog.Float64("duration_ms", float64(d.Microseconds())/1000),
		slog.String("client_ip", st.info.ClientIP.String()),
		slog.String("proto", r.Proto),
		slog.String("user_agent", r.UserAgent()),
	}
	s.log.LogAttrs(context.Background(), level, "request", append(base, attrs...)...)
}

// methodLabel bounds the method label to the standard methods.
func methodLabel(m string) string {
	switch m {
	case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch,
		http.MethodDelete, http.MethodOptions, http.MethodConnect, http.MethodTrace:
		return m
	}
	return "other"
}

// responseWriter records the status and body size. It implements
// io.ReaderFrom by delegating to the underlying writer, so io.Copy from
// an *os.File still reaches net/http's sendfile path, and Unwrap, so
// http.ResponseController finds Flush, Hijack, and deadlines.
type responseWriter struct {
	http.ResponseWriter
	status int
	bytes  int64
}

func (w *responseWriter) WriteHeader(code int) {
	if w.status == 0 && code >= 200 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *responseWriter) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(p)
	w.bytes += int64(n)
	return n, err
}

func (w *responseWriter) ReadFrom(r io.Reader) (int64, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	var n int64
	var err error
	if rf, ok := w.ResponseWriter.(io.ReaderFrom); ok {
		n, err = rf.ReadFrom(r)
	} else {
		n, err = io.Copy(writerOnly{w.ResponseWriter}, r)
	}
	w.bytes += n
	return n, err
}

// Flush implements http.Flusher for handlers that assert it directly.
func (w *responseWriter) Flush() {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	http.NewResponseController(w.ResponseWriter).Flush()
}

func (w *responseWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// writerOnly hides any ReadFrom method, so io.Copy does not recurse.
type writerOnly struct{ io.Writer }
