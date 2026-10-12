// Package upstream is the client that flint's proxy repositories use to
// reach the registries they cache.
//
// A Client talks to one upstream registry. It follows the registry token
// authentication handshake: a request answered with a 401 Bearer
// challenge is retried with a token from the challenge's realm, fetched
// anonymously or with the configured credentials and cached until it
// expires; a Basic challenge is answered with the credentials directly,
// and a Cargo challenge with the password, a token, as the Authorization
// header, as Cargo sends it.
// Transient failures (network errors, 429, 500, 502, 503, and 504) are
// retried with exponential backoff. A request that still fails, or whose
// authentication fails, marks the upstream offline for a short time, so
// callers that hold a cached copy serve it at once instead of waiting on
// an upstream that is down or asking one that refuses flint's access.
//
// Content is verified against its digest while it streams: a manifest
// before it is returned, and a blob before its final bytes are released
// to the client (see CopyVerified and Fetcher), so a corrupted or
// tampered upstream response never reaches a client whole or enters the
// cache.
//
// The package also holds the pieces a caching proxy shares across
// formats: Fetcher, which downloads each blob once into the blob store
// however many clients ask for it at the same time and streams it to all
// of them as it arrives; Space, which watches the data directory's free
// space so proxies stop caching before the disk fills; and Group, which
// collapses concurrent identical lookups into one.
package upstream

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Errors returned by a Client. They are wrapped in an *Error that names
// the request.
var (
	// ErrNotFound means the upstream answered 404: it does not have the
	// content, or the name does not exist. A token service refusing a
	// token for a repository with 400, 404, 410, or 451 is such an
	// answer too.
	ErrNotFound = errors.New("not found upstream")
	// ErrDenied means the upstream refused access to the content even
	// after authentication, or refused anonymous access to it.
	ErrDenied = errors.New("access denied by the upstream")
	// ErrAuth means flint could not authenticate to the upstream: the
	// upstream or its token service refused the configured credentials,
	// its challenge was unusable, or its token realm is invalid. It is a
	// failure of flint's own access, not an answer about the content.
	ErrAuth = errors.New("upstream authentication failed")
	// ErrUnavailable means the upstream could not be reached or kept
	// failing: network errors, timeouts, rate limits, or server errors.
	ErrUnavailable = errors.New("upstream unavailable")
	// ErrDigestMismatch means upstream content did not match its digest.
	ErrDigestMismatch = errors.New("upstream content does not match its digest")
	// ErrTooLarge means a response exceeded the size the caller accepts.
	ErrTooLarge = errors.New("upstream response too large")
	// ErrGone means the upstream answered 410: the content existed and
	// was removed. It wraps ErrNotFound, so callers that do not
	// distinguish the two treat it as not found.
	ErrGone = fmt.Errorf("%w: gone", ErrNotFound)
)

// Error describes a failed upstream request.
type Error struct {
	// Op is the request, such as "GET /v2/library/alpine/manifests/3".
	Op string
	// Status is the upstream's HTTP status, or 0 if there was no response.
	Status int
	// Err is one of the package's errors, possibly wrapping a cause.
	Err error
}

func (e *Error) Error() string {
	if e.Status != 0 {
		return fmt.Sprintf("upstream %s: status %d: %v", e.Op, e.Status, e.Err)
	}
	return fmt.Sprintf("upstream %s: %v", e.Op, e.Err)
}

func (e *Error) Unwrap() error { return e.Err }

// Defaults for Options.
const (
	DefaultAttempts   = 3
	DefaultBackoff    = 250 * time.Millisecond
	DefaultOfflineFor = 30 * time.Second
	// DefaultMaxConcurrent bounds a Client's concurrent requests.
	DefaultMaxConcurrent = 64
	// maxRetryAfter bounds how long a Retry-After header may delay a
	// retry; a longer one, such as a rate limit's, ends the retries.
	maxRetryAfter = 5 * time.Second
)

// Options configures a Client.
type Options struct {
	// URL is the registry's base URL, such as "https://ghcr.io". Required.
	URL string
	// Username and PasswordFile are the upstream credentials, if any.
	// The password file is read whenever credentials are sent, so a
	// rotated secret takes effect without a restart; one trailing
	// newline is ignored.
	Username     string
	PasswordFile string
	// Preemptive sends the credentials with every request to the
	// upstream's own scheme and host, without waiting for a challenge, as
	// npm clients do with registries, which may answer a request without
	// credentials 404 rather than challenge it: HTTP basic credentials,
	// or with no Username, the password as a bearer token.
	Preemptive bool
	// HTTPClient sends the requests; nil means a client with a transport
	// like NewTransport's that also enforces Policy's address rule, and
	// no overall timeout. A given client's redirects are still checked
	// against Policy, but its transport is used as it is.
	HTTPClient *http.Client
	// Policy decides which hosts besides the upstream's own the client
	// may fetch from; the zero Policy allows none.
	Policy Policy
	// MaxConcurrent bounds the requests the client has in flight at
	// once, each from its first byte sent until its response body is
	// closed; zero means DefaultMaxConcurrent. Further requests wait.
	MaxConcurrent int
	// UserAgent is sent with every request.
	UserAgent string
	// Attempts bounds how often a transiently failing request is sent;
	// zero means DefaultAttempts.
	Attempts int
	// Backoff is the delay before the first retry, doubled for each
	// later one; zero means DefaultBackoff.
	Backoff time.Duration
	// OfflineFor is how long a request that failed with ErrUnavailable
	// or ErrAuth marks the upstream offline; zero means DefaultOfflineFor.
	OfflineFor time.Duration
	// Logger receives warnings; nil means slog.Default().
	Logger *slog.Logger
	// Now is the clock; nil means time.Now.
	Now func() time.Time
}

// Client is a client of one upstream registry. It is safe for concurrent
// use.
type Client struct {
	base         *url.URL
	username     string
	passwordFile string
	preemptive   bool
	hc           *http.Client
	userAgent    string
	attempts     int
	backoff      time.Duration
	offlineFor   time.Duration
	log          *slog.Logger
	now          func() time.Time
	pol          *policy
	slots        chan struct{} // one per request in flight

	mu            sync.Mutex
	tokens        map[string]token // by scope
	offlineUntil  time.Time
	basicAccepted atomic.Bool // the upstream accepted basic credentials
	tokenAccepted atomic.Bool // the upstream accepted the password as a Cargo token
}

// token is a bearer token and when it stops being used.
type token struct {
	value   string
	expires time.Time
}

// maxTokens bounds the token cache; expired tokens are dropped when it
// is full.
const maxTokens = 1024

// New returns a Client. If credentials are configured, the password file
// must be readable now.
func New(opts Options) (*Client, error) {
	u, err := url.Parse(opts.URL)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return nil, fmt.Errorf("upstream: %q is not an http or https URL", opts.URL)
	}
	u.Path, u.RawPath = "", ""
	c := &Client{
		base:         u,
		username:     opts.Username,
		passwordFile: opts.PasswordFile,
		preemptive:   opts.Preemptive && opts.PasswordFile != "",
		hc:           opts.HTTPClient,
		userAgent:    opts.UserAgent,
		attempts:     opts.Attempts,
		backoff:      opts.Backoff,
		offlineFor:   opts.OfflineFor,
		log:          opts.Logger,
		now:          opts.Now,
		tokens:       map[string]token{},
	}
	if c.pol, err = compilePolicy(u, opts.Policy); err != nil {
		return nil, err
	}
	if c.hc == nil {
		t := NewTransport()
		t.Proxy = c.pol.proxyFunc()
		t.DialContext = c.pol.dialContext(newDialer())
		c.hc = &http.Client{Transport: t}
	} else {
		hc := *c.hc
		c.hc = &hc
	}
	c.hc.CheckRedirect = c.pol.checkRedirect
	n := opts.MaxConcurrent
	if n <= 0 {
		n = DefaultMaxConcurrent
	}
	c.slots = make(chan struct{}, n)
	if c.attempts <= 0 {
		c.attempts = DefaultAttempts
	}
	if c.backoff <= 0 {
		c.backoff = DefaultBackoff
	}
	if c.offlineFor <= 0 {
		c.offlineFor = DefaultOfflineFor
	}
	if c.log == nil {
		c.log = slog.Default()
	}
	if c.now == nil {
		c.now = time.Now
	}
	if c.username != "" || c.preemptive {
		if _, err := c.password(); err != nil {
			return nil, err
		}
	}
	return c, nil
}

// NewTransport returns the HTTP transport upstream clients use by
// default: it honors the HTTPS_PROXY, HTTP_PROXY, and NO_PROXY
// environment variables and bounds connection setup and the wait for
// response headers, but not how long a body takes to stream.
func NewTransport() *http.Transport {
	return &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           newDialer().DialContext,
		ForceAttemptHTTP2:     true,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		ExpectContinueTimeout: time.Second,
		IdleConnTimeout:       90 * time.Second,
		MaxIdleConnsPerHost:   32,
	}
}

func newDialer() *net.Dialer {
	return &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
}

// URL returns the upstream's base URL.
func (c *Client) URL() string { return c.base.String() }

// Host returns the upstream's host, with its port if it has one.
func (c *Client) Host() string { return c.base.Host }

// Offline reports whether a recent request found the upstream
// unavailable or failed to authenticate. Callers holding a cached copy
// serve it without asking the upstream while it is offline.
func (c *Client) Offline() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now().Before(c.offlineUntil)
}

// MarkOffline marks the upstream offline, as a request that fails with
// ErrUnavailable does. Callers use it for such failures they detect
// themselves, such as a response body that stalls.
func (c *Client) MarkOffline() { c.setOffline(true) }

func (c *Client) setOffline(offline bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if offline {
		c.offlineUntil = c.now().Add(c.offlineFor)
	} else {
		c.offlineUntil = time.Time{}
	}
}

// password reads the password file.
func (c *Client) password() (string, error) {
	b, err := os.ReadFile(c.passwordFile)
	if err != nil {
		return "", fmt.Errorf("upstream %s: reading the password file: %w", c.base.Host, err)
	}
	s := string(b)
	s = strings.TrimSuffix(s, "\n")
	s = strings.TrimSuffix(s, "\r")
	return s, nil
}

// Do sends a request for the upstream API path, such as
// "/v2/library/alpine/manifests/3", with the query and headers given,
// authorizing it for scope (a token scope such as
// "repository:library/alpine:pull"). It answers authentication
// challenges and retries transient failures. A response with a 2xx or
// 3xx status is returned for the caller to read and close; any other is
// an *Error wrapping ErrNotFound, ErrDenied, ErrAuth, ErrUnavailable, or a
// generic error for other statuses. A request whose ctx deadline passes
// fails with ErrUnavailable.
func (c *Client) Do(ctx context.Context, method, path string, query url.Values, header http.Header, scope string) (*http.Response, error) {
	u := *c.base
	u.Path = path
	u.RawQuery = query.Encode()
	return c.do(ctx, method, &u, header, nil, scope)
}

// GetURL fetches an absolute http or https URL, such as a package file
// that an index links to, which may be on another host, such as a
// content delivery network, if the client's Policy allows that host;
// otherwise it fails with ErrPolicy. It retries and fails as Do does.
// Only the upstream's own scheme and host are sent credentials or have
// their authentication challenges answered; a 401 from anywhere else is
// ErrDenied.
func (c *Client) GetURL(ctx context.Context, rawURL string, header http.Header) (*http.Response, error) {
	return c.Request(ctx, http.MethodGet, rawURL, header)
}

// Request is GetURL for another method, such as HEAD.
func (c *Client) Request(ctx context.Context, method, rawURL string, header http.Header) (*http.Response, error) {
	return c.Send(ctx, method, rawURL, header, nil)
}

// Send is Request with a request body, such as a POST of a query that
// is forwarded to the upstream; body is sent again with every retry.
func (c *Client) Send(ctx context.Context, method, rawURL string, header http.Header, body []byte) (*http.Response, error) {
	u, err := url.Parse(rawURL)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return nil, &Error{Op: method + " " + rawURL, Err: fmt.Errorf("%q is not an http or https URL", rawURL)}
	}
	u.Fragment, u.RawFragment = "", ""
	if err := c.pol.check(u); err != nil {
		return nil, &Error{Op: method + " " + u.Redacted(), Err: err}
	}
	return c.do(ctx, method, u, header, body, "")
}

// idleWatch is a timer that gives up on a request when the upstream is
// silent for d.
type idleWatch struct {
	t *time.Timer
	d time.Duration
}

type watchdogKey struct{}

// withWatchdog returns ctx carrying the watchdog t, armed for d: a
// Client stops it while a request waits for a concurrency slot, which is
// not the upstream's silence, and arms it again once a slot is free.
func withWatchdog(ctx context.Context, t *time.Timer, d time.Duration) context.Context {
	return context.WithValue(ctx, watchdogKey{}, &idleWatch{t, d})
}

// WithTimeout is context.WithTimeout for upstream requests: the returned
// context ends with context.DeadlineExceeded d after it is made, except
// that time a request waits for one of a Client's concurrency slots
// (proxy.maxConcurrent) does not count: the timeout starts again once
// the request holds a slot, since waiting for one is not the upstream's
// silence.
func WithTimeout(ctx context.Context, d time.Duration) (context.Context, context.CancelFunc) {
	inner, cancel := context.WithCancelCause(ctx)
	t := time.AfterFunc(d, func() { cancel(context.DeadlineExceeded) })
	return withWatchdog(&timeoutCtx{inner}, t, d), func() {
		t.Stop()
		cancel(nil)
	}
}

// timeoutCtx is a WithTimeout context: it reports the end of its timeout
// as context.DeadlineExceeded, as a context.WithTimeout context does.
type timeoutCtx struct{ context.Context }

func (c *timeoutCtx) Err() error {
	err := c.Context.Err()
	if err != nil && errors.Is(context.Cause(c.Context), context.DeadlineExceeded) {
		return context.DeadlineExceeded
	}
	return err
}

// acquire waits for a request slot and returns its release.
func (c *Client) acquire(ctx context.Context, op string) (func(), error) {
	select {
	case c.slots <- struct{}{}:
	default:
		wd, _ := ctx.Value(watchdogKey{}).(*idleWatch)
		if wd != nil && !wd.t.Stop() {
			wd = nil // it fired already
		}
		select {
		case c.slots <- struct{}{}:
		case <-ctx.Done():
			return nil, &Error{Op: op, Err: fmt.Errorf("waiting for one of the %d concurrent upstream requests allowed: %w", cap(c.slots), ctx.Err())}
		}
		if wd != nil {
			wd.t.Reset(wd.d)
		}
	}
	var once sync.Once
	return func() { once.Do(func() { <-c.slots }) }, nil
}

// releaseBody releases a request slot when the response body is closed.
type releaseBody struct {
	io.ReadCloser
	release func()
}

func (b *releaseBody) Close() error {
	err := b.ReadCloser.Close()
	b.release()
	return err
}

// do sends a request for u; see Do.
func (c *Client) do(ctx context.Context, method string, u *url.URL, header http.Header, body []byte, scope string) (*http.Response, error) {
	op := method + " " + u.Path
	var lastErr error
	for attempt := 1; ; attempt++ {
		release, err := c.acquire(ctx, op)
		if err != nil {
			return nil, err
		}
		resp, err := c.send(ctx, method, u, header, body, scope)
		if err != nil {
			release()
		} else {
			resp.Body = &releaseBody{resp.Body, release}
		}
		retryAfter := time.Duration(0)
		switch {
		case err == nil && !retryable(resp.StatusCode):
			c.setOffline(false) // it answered
			if resp.StatusCode < 400 {
				return resp, nil
			}
			return nil, statusError(op, resp)
		case err == nil:
			retryAfter = parseRetryAfter(resp.Header.Get("Retry-After"), c.now())
			lastErr = &Error{Op: op, Status: resp.StatusCode, Err: ErrUnavailable}
			drain(resp)
		case ctx.Err() != nil:
			return nil, c.ctxError(op, ctx)
		case !errors.Is(err, ErrUnavailable):
			if errors.Is(err, ErrAuth) {
				c.setOffline(true)
			}
			return nil, err
		default:
			lastErr = err
		}
		if attempt >= c.attempts || retryAfter > maxRetryAfter {
			c.setOffline(true)
			return nil, lastErr
		}
		wait := max(c.backoff<<(attempt-1), retryAfter)
		wait += time.Duration(jitter(int64(wait / 2)))
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return nil, c.ctxError(op, ctx)
		case <-t.C:
		}
	}
}

// ctxError is the error of request op when ctx ends. A deadline means
// the upstream took too long to answer, so it is ErrUnavailable and marks
// the upstream offline; a cancellation means the caller gave up.
func (c *Client) ctxError(op string, ctx context.Context) error {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		c.setOffline(true)
		return &Error{Op: op, Err: fmt.Errorf("%w: %w", ErrUnavailable, ctx.Err())}
	}
	return &Error{Op: op, Err: ctx.Err()}
}

// send sends one request, answering an authentication challenge once.
// Network failures are *Errors wrapping ErrUnavailable.
func (c *Client) send(ctx context.Context, method string, u *url.URL, header http.Header, body []byte, scope string) (*http.Response, error) {
	op := method + " " + u.Path
	own := strings.EqualFold(u.Scheme, c.base.Scheme) && strings.EqualFold(u.Host, c.base.Host)
	auth, preempted := "", false
	if tok, ok := c.cachedToken(scope); ok && own {
		auth = "Bearer " + tok
	} else if own && c.preemptive {
		preempted = true
		pw, err := c.password()
		if err != nil {
			return nil, &Error{Op: op, Err: err}
		}
		auth = "Bearer " + pw
		if c.username != "" {
			auth = "Basic " + basicAuth(c.username, pw)
		}
	} else if own && c.username != "" && (c.basicAccepted.Load() || c.tokenAccepted.Load()) {
		// The upstream took the credentials before: send them at once
		// rather than waiting for its challenge.
		pw, err := c.password()
		if err != nil {
			return nil, &Error{Op: op, Err: err}
		}
		auth = pw
		if c.basicAccepted.Load() {
			auth = "Basic " + basicAuth(c.username, pw)
		}
	}
	resp, err := c.roundTrip(ctx, method, u.String(), header, body, auth)
	if err != nil {
		return nil, transportError(op, err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		return resp, nil
	}
	if !own {
		drain(resp)
		return nil, &Error{Op: op, Status: http.StatusUnauthorized,
			Err: fmt.Errorf("%w: %s asks for credentials, which flint sends only to %s", ErrDenied, u.Host, c.base.Host)}
	}
	if preempted {
		// The credentials were sent, and refused.
		drain(resp)
		return nil, &Error{Op: op, Status: http.StatusUnauthorized, Err: fmt.Errorf("%w: the upstream refused the credentials", ErrAuth)}
	}
	ch, ok := parseChallenge(resp.Header.Values("WWW-Authenticate"))
	drain(resp)
	if !ok {
		return nil, &Error{Op: op, Status: http.StatusUnauthorized, Err: fmt.Errorf("%w: no usable authentication challenge", ErrAuth)}
	}
	switch ch.scheme {
	case "bearer":
		tok, err := c.fetchToken(ctx, ch, scope)
		if err != nil {
			return nil, err
		}
		auth = "Bearer " + tok
	case "basic", "cargo":
		if c.username == "" {
			return nil, &Error{Op: op, Status: http.StatusUnauthorized, Err: fmt.Errorf("%w: the upstream needs credentials", ErrDenied)}
		}
		pw, err := c.password()
		if err != nil {
			return nil, &Error{Op: op, Err: err}
		}
		auth = pw // a Cargo registry takes its token as the header itself
		if ch.scheme == "basic" {
			auth = "Basic " + basicAuth(c.username, pw)
		}
	}
	resp, err = c.roundTrip(ctx, method, u.String(), header, body, auth)
	if err != nil {
		return nil, transportError(op, err)
	}
	accepted := &c.basicAccepted
	if ch.scheme == "cargo" {
		accepted = &c.tokenAccepted
	}
	if ch.scheme != "bearer" && resp.StatusCode == http.StatusUnauthorized {
		drain(resp)
		accepted.Store(false)
		return nil, &Error{Op: op, Status: http.StatusUnauthorized, Err: fmt.Errorf("%w: the upstream refused the credentials", ErrAuth)}
	}
	if ch.scheme != "bearer" {
		accepted.Store(true)
	}
	return resp, nil
}

// transportError is the error of request op that failed in the
// transport: a refusal of the fetch policy, such as a redirect to a host
// it does not allow, or else the upstream being unavailable.
func transportError(op string, err error) error {
	if errors.Is(err, ErrPolicy) {
		return &Error{Op: op, Err: fmt.Errorf("%w", unwrapURLError(err))}
	}
	return &Error{Op: op, Err: fmt.Errorf("%w: %v", ErrUnavailable, err)}
}

// unwrapURLError returns the error a *url.Error wraps, whose own message
// repeats the URL the *Error already names.
func unwrapURLError(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err
	}
	return err
}

func (c *Client) roundTrip(ctx context.Context, method, u string, header http.Header, body []byte, auth string) (*http.Response, error) {
	var rb io.Reader
	if body != nil {
		rb = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rb)
	if err != nil {
		return nil, err
	}
	for k, vs := range header {
		req.Header[k] = vs
	}
	if c.userAgent != "" {
		req.Header.Set("User-Agent", c.userAgent)
	}
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	return c.hc.Do(req)
}

// retryable reports whether a status is worth retrying.
func retryable(status int) bool {
	switch status {
	case http.StatusTooManyRequests, http.StatusInternalServerError, http.StatusBadGateway,
		http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	}
	return false
}

// statusError turns a final 4xx or 5xx response into an *Error, closing it.
func statusError(op string, resp *http.Response) error {
	defer drain(resp)
	e := &Error{Op: op, Status: resp.StatusCode}
	switch resp.StatusCode {
	case http.StatusNotFound:
		e.Err = ErrNotFound
	case http.StatusGone:
		e.Err = ErrGone
	case http.StatusUnavailableForLegalReasons:
		// Taken down, as a registry does with content it may not serve:
		// an answer about the content, like a 404.
		e.Err = ErrNotFound
	case http.StatusUnauthorized, http.StatusForbidden:
		e.Err = ErrDenied
	default:
		e.Err = fmt.Errorf("unexpected status %s", resp.Status)
	}
	return e
}

// drain reads a little of a response body, so its connection can be
// reused, and closes it.
func drain(resp *http.Response) {
	io.CopyN(io.Discard, resp.Body, 4<<10)
	resp.Body.Close()
}

// parseRetryAfter parses a Retry-After header: seconds or an HTTP date.
func parseRetryAfter(s string, now time.Time) time.Duration {
	if s == "" {
		return 0
	}
	if n, err := strconv.Atoi(s); err == nil && n >= 0 {
		return time.Duration(n) * time.Second
	}
	if t, err := http.ParseTime(s); err == nil {
		return max(t.Sub(now), 0)
	}
	return 0
}

// jitter returns a random duration in [0, n).
func jitter(n int64) int64 {
	if n <= 0 {
		return 0
	}
	var b [8]byte
	rand.Read(b[:])
	return int64(binary.LittleEndian.Uint64(b[:]) % uint64(n))
}
