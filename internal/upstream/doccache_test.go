package upstream_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/terrabyteian/flint/internal/blob"
	"github.com/terrabyteian/flint/internal/fsys"
	"github.com/terrabyteian/flint/internal/meta"
	"github.com/terrabyteian/flint/internal/metrics"
	"github.com/terrabyteian/flint/internal/upstream"
)

// docUpstream is a fake upstream serving mutable documents with ETags
// and Last-Modified times, which it compares against conditional
// requests.
type docUpstream struct {
	*httptest.Server

	mu       sync.Mutex
	docs     map[string]*upDoc
	status   int // if not zero, every request is answered with it
	requests []string
	hold     chan struct{} // if not nil, answers wait for it to close
}

type upDoc struct {
	body    []byte
	etag    string
	lastMod string
	ctype   string
}

func newDocUpstream(t *testing.T) *docUpstream {
	u := &docUpstream{docs: map[string]*upDoc{}}
	u.Server = httptest.NewServer(http.HandlerFunc(u.serve))
	t.Cleanup(u.Close)
	return u
}

func (u *docUpstream) set(path string, body []byte, etag, lastMod string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.docs[path] = &upDoc{body: body, etag: etag, lastMod: lastMod, ctype: "application/json"}
}

func (u *docUpstream) setStatus(s int) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.status = s
}

// took returns and forgets the requests received: the method, path,
// and conditional headers.
func (u *docUpstream) took() []string {
	u.mu.Lock()
	defer u.mu.Unlock()
	r := u.requests
	u.requests = nil
	return r
}

func (u *docUpstream) serve(w http.ResponseWriter, r *http.Request) {
	u.mu.Lock()
	u.requests = append(u.requests, strings.TrimSpace(r.Method+" "+r.URL.Path+" "+r.Header.Get("If-None-Match")+" "+r.Header.Get("If-Modified-Since")))
	status, d, hold := u.status, u.docs[r.URL.Path], u.hold
	u.mu.Unlock()
	if hold != nil {
		<-hold
	}
	if status != 0 {
		w.WriteHeader(status)
		return
	}
	if d == nil {
		http.NotFound(w, r)
		return
	}
	if d.etag != "" {
		w.Header().Set("ETag", d.etag)
	}
	if d.lastMod != "" {
		w.Header().Set("Last-Modified", d.lastMod)
	}
	if (d.etag != "" && r.Header.Get("If-None-Match") == d.etag) ||
		(d.etag == "" && d.lastMod != "" && r.Header.Get("If-Modified-Since") == d.lastMod) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("Content-Type", d.ctype)
	w.Write(d.body)
}

// docEnv is a DocCache over in-memory stores, with a fake clock.
type docEnv struct {
	t      *testing.T
	fs     *fsys.Mem
	meta   meta.Store
	blobs  blob.Store
	up     *docUpstream
	client *upstream.Client
	clock  *fakeClock
	space  *upstream.Space
	free   atomic.Int64 // free bytes the fake statfs reports
	reg    *metrics.Registry
	pm     *upstream.Metrics
	c      *upstream.DocCache
	budget int64
}

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func newDocEnv(t *testing.T) *docEnv {
	e := &docEnv{t: t, fs: fsys.NewMem(), up: newDocUpstream(t), clock: &fakeClock{t: time.Unix(1700000000, 0)}}
	e.free.Store(1 << 40)
	var err error
	if e.blobs, err = blob.NewFS("/data", blob.Options{FS: e.fs}); err != nil {
		t.Fatal(err)
	}
	e.client = newClient(t, e.up.URL, upstream.Options{Now: e.clock.Now})
	e.space = upstream.NewSpace(upstream.SpaceOptions{Path: "/data", Now: e.clock.Now, Logger: quiet,
		MinFree: func(uint64) uint64 { return 1 << 20 },
		Statfs: func(string) (uint64, uint64, error) {
			return uint64(e.free.Load()), 1 << 41, nil
		}})
	e.restart()
	return e
}

// restart opens the metadata store again and builds a new DocCache over
// the same stores, as a restart would.
func (e *docEnv) restart() {
	e.t.Helper()
	if e.meta != nil {
		e.meta.Close()
	}
	var err error
	if e.meta, err = meta.Open("/data/meta", meta.Options{FS: e.fs, Logger: quiet}); err != nil {
		e.t.Fatal(err)
	}
	e.t.Cleanup(func() { e.meta.Close() })
	e.reg = metrics.NewRegistry()
	e.pm = upstream.NewMetrics(e.reg, nil, nil)
	e.c = upstream.NewDocCache(upstream.DocCacheOptions{Meta: e.meta, Blobs: e.blobs, Space: e.space, Metrics: e.pm,
		Logger: quiet, Now: e.clock.Now, DeriveBudget: e.budget})
}

const docWindow = time.Minute

func (e *docEnv) req(key string) *upstream.DocRequest {
	return &upstream.DocRequest{Repo: "remote", Key: key, Client: e.client, URL: e.up.URL + "/" + key,
		Revalidate: docWindow, Actor: "tester"}
}

func (e *docEnv) get(key string) (*upstream.Doc, error) {
	return e.c.Get(ctx, e.req(key))
}

// body reads a resolved document's content.
func (e *docEnv) body(d *upstream.Doc) string {
	e.t.Helper()
	r, err := e.c.Open(ctx, d)
	if err != nil {
		e.t.Fatal(err)
	}
	defer r.Close()
	b, err := io.ReadAll(r)
	if err != nil {
		e.t.Fatal(err)
	}
	return string(b)
}

func (e *docEnv) want(key, body, result string) *upstream.Doc {
	e.t.Helper()
	d, err := e.get(key)
	if err != nil {
		e.t.Fatalf("Get(%s): %v", key, err)
	}
	if got := e.body(d); got != body || d.Result != result {
		e.t.Fatalf("Get(%s) = %q, %s; want %q, %s", key, got, d.Result, body, result)
	}
	return d
}

func eqStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestDocCacheRevalidation(t *testing.T) {
	e := newDocEnv(t)
	lm := "Mon, 02 Jan 2006 15:04:05 GMT"
	e.up.set("/pkg", []byte(`{"v":1}`), `"e1"`, lm)
	d := e.want("pkg", `{"v":1}`, upstream.ResultFetched)
	if d.ETag != `"e1"` || d.LastModified != lm || d.ContentType != "application/json" || d.URL != e.up.URL+"/pkg" {
		t.Errorf("record %+v", d.DocRecord)
	}
	if !d.Stored() {
		t.Error("the document was not stored")
	}
	// Stored verbatim in the blob store, named by its record.
	rec, err := e.c.Lookup("remote", "pkg")
	if err != nil || rec == nil || rec.Digest != blob.FromBytes([]byte(`{"v":1}`)) {
		t.Fatalf("record: %+v, %v", rec, err)
	}
	e.up.took()
	// Within the window, the cache answers alone.
	e.want("pkg", `{"v":1}`, upstream.ResultHit)
	if got := e.up.took(); len(got) != 0 {
		t.Errorf("requests within the window: %q", got)
	}
	// After it, a conditional request; a 304 refreshes the window only.
	e.clock.Add(docWindow)
	e.want("pkg", `{"v":1}`, upstream.ResultRevalidated)
	if got, want := e.up.took(), []string{`GET /pkg "e1" ` + lm}; !eqStrings(got, want) {
		t.Errorf("revalidation requests: %q, want %q", got, want)
	}
	e.want("pkg", `{"v":1}`, upstream.ResultHit)
	// The ETag is durable: after a restart, the first revalidation is a
	// conditional request answered 304, not a refetch.
	e.restart()
	e.up.took()
	e.want("pkg", `{"v":1}`, upstream.ResultRevalidated)
	if got, want := e.up.took(), []string{`GET /pkg "e1" ` + lm}; !eqStrings(got, want) {
		t.Errorf("first request after a restart: %q, want %q", got, want)
	}
	// A changed document replaces the stored copy.
	e.clock.Add(docWindow)
	e.up.set("/pkg", []byte(`{"v":2}`), `"e2"`, "")
	d = e.want("pkg", `{"v":2}`, upstream.ResultFetched)
	if rec, _ := e.c.Lookup("remote", "pkg"); rec.Digest != d.Digest || rec.ETag != `"e2"` || rec.LastModified != "" {
		t.Errorf("record after a change: %+v", rec)
	}
	e.want("pkg", `{"v":2}`, upstream.ResultHit)
	// The same content under a new ETag counts as revalidated and keeps
	// the new ETag.
	e.clock.Add(docWindow)
	e.up.set("/pkg", []byte(`{"v":2}`), `"e3"`, "")
	e.want("pkg", `{"v":2}`, upstream.ResultRevalidated)
	if rec, _ := e.c.Lookup("remote", "pkg"); rec.ETag != `"e3"` {
		t.Errorf("record ETag %s, want the new one", rec.ETag)
	}
	// Without an ETag, Last-Modified alone makes the request conditional.
	e.up.set("/lm", []byte("lm"), "", lm)
	e.want("lm", "lm", upstream.ResultFetched)
	e.clock.Add(docWindow)
	e.up.took()
	e.want("lm", "lm", upstream.ResultRevalidated)
	if got, want := e.up.took(), []string{"GET /lm  " + lm}; !eqStrings(got, want) {
		t.Errorf("Last-Modified revalidation: %q, want %q", got, want)
	}
}

func TestDocCacheUpstreamOutcomes(t *testing.T) {
	e := newDocEnv(t)
	e.up.set("/pkg", []byte("one"), `"1"`, "")
	e.want("pkg", "one", upstream.ResultFetched)
	// An upstream that cannot be reached has the cached copy served.
	e.clock.Add(docWindow)
	e.up.setStatus(http.StatusServiceUnavailable)
	e.want("pkg", "one", upstream.ResultStale)
	// It is marked offline, so the next lookup does not wait on it.
	e.up.took()
	e.want("pkg", "one", upstream.ResultStale)
	if got := e.up.took(); len(got) != 0 {
		t.Errorf("requests to an offline upstream: %q", got)
	}
	// With nothing cached, the outage is the answer.
	if _, err := e.get("other"); !errors.Is(err, upstream.ErrUnavailable) {
		t.Errorf("uncached document from an unreachable upstream: %v, want ErrUnavailable", err)
	}
	e.clock.Add(upstream.DefaultOfflineFor)
	// A document the upstream says is gone is answered not found, even
	// though it is cached, and the cached copy stays.
	for _, status := range []int{http.StatusNotFound, http.StatusGone, http.StatusForbidden} {
		e.up.setStatus(status)
		_, err := e.get("pkg")
		if !upstream.Answered(err) {
			t.Errorf("upstream %d: %v, want an answered error", status, err)
		}
		if status == http.StatusGone && !errors.Is(err, upstream.ErrGone) {
			t.Errorf("upstream 410: %v, want ErrGone", err)
		}
		if rec, _ := e.c.Lookup("remote", "pkg"); rec == nil {
			t.Fatalf("upstream %d removed the cached document", status)
		}
	}
	e.up.setStatus(0)
	e.want("pkg", "one", upstream.ResultRevalidated)
	var out strings.Builder
	e.reg.WriteTo(&out)
	if !strings.Contains(out.String(), `flint_proxy_upstream_errors_total{repository="remote"}`) {
		t.Error("upstream errors were not counted")
	}
}

func TestDocCacheCollapses(t *testing.T) {
	e := newDocEnv(t)
	e.up.set("/pkg", []byte("one"), `"1"`, "")
	e.up.hold = make(chan struct{})
	var wg sync.WaitGroup
	for range 10 {
		wg.Go(func() {
			if d, err := e.get("pkg"); err != nil || e.body(d) != "one" {
				t.Errorf("Get: %v", err)
			}
		})
	}
	time.Sleep(20 * time.Millisecond)
	close(e.up.hold)
	wg.Wait()
	if got := e.up.took(); len(got) != 1 {
		t.Errorf("%d upstream requests for concurrent lookups, want 1", len(got))
	}
}

func TestDocCacheValidateAndLimits(t *testing.T) {
	e := newDocEnv(t)
	e.up.set("/pkg", []byte("good"), `"1"`, "")
	valid := func(ctx context.Context, d *upstream.Doc) error {
		r, err := e.c.Open(ctx, d)
		if err != nil {
			return err
		}
		defer r.Close()
		b, _ := io.ReadAll(r)
		if string(b) == "bad" {
			return errors.New("unreadable document")
		}
		return nil
	}
	req := e.req("pkg")
	req.Validate = valid
	if d, err := e.c.Get(ctx, req); err != nil || d.Result != upstream.ResultFetched {
		t.Fatalf("Get: %+v, %v", d, err)
	}
	// A document the format cannot read never replaces the cached one.
	e.clock.Add(docWindow)
	e.up.set("/pkg", []byte("bad"), `"2"`, "")
	d, err := e.c.Get(ctx, req)
	if err != nil || d.Result != upstream.ResultStale || e.body(d) != "good" {
		t.Fatalf("an unreadable update: %+v, %v; want the cached copy, stale", d, err)
	}
	e.up.set("/new", []byte("bad"), `"2"`, "")
	nreq := e.req("new")
	nreq.Validate = valid
	if _, err := e.c.Get(ctx, nreq); err == nil {
		t.Error("an unreadable document was served")
	}
	if rec, _ := e.c.Lookup("remote", "new"); rec != nil {
		t.Error("an unreadable document was cached")
	}
	// Documents over the size limit are refused.
	e.up.set("/big", bytes.Repeat([]byte("x"), 100), "", "")
	breq := e.req("big")
	breq.MaxSize = 99
	if _, err := e.c.Get(ctx, breq); !errors.Is(err, upstream.ErrTooLarge) {
		t.Errorf("a document over the limit: %v, want ErrTooLarge", err)
	}
}

func TestDocCacheDiskPressure(t *testing.T) {
	e := newDocEnv(t)
	e.up.set("/pkg", []byte("one"), `"1"`, "")
	e.want("pkg", "one", upstream.ResultFetched)
	e.free.Store(0)
	e.clock.Add(docWindow)
	// A changed document is served from memory, not stored, and not
	// marked confirmed: the next request asks again.
	e.up.set("/pkg", []byte("two"), `"2"`, "")
	d := e.want("pkg", "two", upstream.ResultPassthrough)
	if d.Stored() {
		t.Error("a document was stored under disk pressure")
	}
	if rec, _ := e.c.Lookup("remote", "pkg"); rec.ETag != `"1"` {
		t.Errorf("the record changed under disk pressure: %+v", rec)
	}
	e.up.took()
	e.want("pkg", "two", upstream.ResultPassthrough)
	if got := e.up.took(); len(got) != 1 {
		t.Errorf("requests after a pass-through: %q, want one", got)
	}
	// One too large to hold in memory is answered from the cache, or
	// fails with nothing cached.
	req := e.req("pkg")
	req.MaxMemory = 2
	if d, err := e.c.Get(ctx, req); err != nil || d.Result != upstream.ResultStale || e.body(d) != "one" {
		t.Errorf("a large document under disk pressure: %+v, %v; want the cached copy", d, err)
	}
	e.up.set("/big", []byte("too large"), "", "")
	req = e.req("big")
	req.MaxMemory = 2
	if _, err := e.c.Get(ctx, req); !errors.Is(err, upstream.ErrNoSpace) {
		t.Errorf("a large uncached document under disk pressure: %v, want ErrNoSpace", err)
	}
	// With room again, it is stored.
	e.free.Store(1 << 40)
	e.clock.Add(time.Second)
	e.want("pkg", "two", upstream.ResultFetched)
}

func TestDocCacheMissingBlob(t *testing.T) {
	e := newDocEnv(t)
	e.up.set("/pkg", []byte("one"), `"1"`, "")
	d := e.want("pkg", "one", upstream.ResultFetched)
	if err := e.blobs.Delete(ctx, d.Digest); err != nil {
		t.Fatal(err)
	}
	e.up.took()
	// A record whose blob is gone is fetched again, unconditionally.
	e.want("pkg", "one", upstream.ResultFetched)
	if got, want := e.up.took(), []string{"GET /pkg"}; !eqStrings(got, want) {
		t.Errorf("requests: %q, want %q", got, want)
	}
}

func upper(dst io.Writer, src io.Reader) error {
	b, err := io.ReadAll(src)
	if err != nil {
		return err
	}
	_, err = dst.Write(bytes.ToUpper(b))
	return err
}

func TestDocCacheDerive(t *testing.T) {
	e := newDocEnv(t)
	e.budget = 1 << 20
	e.restart()
	e.up.set("/small", []byte("small doc"), "", "")
	e.up.set("/large", bytes.Repeat([]byte("large doc "), 30000), "", "") // 300 kB: over a quarter of the budget
	var calls atomic.Int32
	rw := func(dst io.Writer, src io.Reader) error {
		calls.Add(1)
		return upper(dst, src)
	}
	small, _ := e.get("small")
	for range 2 {
		got, err := e.c.Derive(ctx, small, "upper", rw)
		if err != nil || string(got.Bytes) != "SMALL DOC" {
			t.Fatalf("Derive = %+v, %v", got, err)
		}
	}
	if calls.Load() != 1 {
		t.Errorf("a small document was rewritten %d times, want once", calls.Load())
	}
	// Another variant is another derivation.
	if got, _ := e.c.Derive(ctx, small, "upper2", rw); string(got.Bytes) != "SMALL DOC" || calls.Load() != 2 {
		t.Errorf("another variant: %q after %d rewrites", got.Bytes, calls.Load())
	}
	held := e.c.DerivedBytes()
	large, _ := e.get("large")
	for range 2 {
		got, err := e.c.Derive(ctx, large, "upper", rw)
		if err != nil || got.Bytes != nil || got.Stream == nil {
			t.Fatalf("Derive of a large document = %+v, %v; want a stream", got, err)
		}
		b, err := io.ReadAll(got.Stream)
		got.Stream.Close()
		if err != nil || !bytes.Equal(b, bytes.ToUpper(bytes.Repeat([]byte("large doc "), 30000))) {
			t.Fatalf("streamed %d bytes, %v", len(b), err)
		}
	}
	if calls.Load() != 4 || e.c.DerivedBytes() != held {
		t.Errorf("a large document: %d rewrites, %d bytes held; want streamed each time, never held", calls.Load(), e.c.DerivedBytes())
	}
	// A failing rewriter fails the stream.
	got, err := e.c.Derive(ctx, large, "fail", func(dst io.Writer, src io.Reader) error { return errors.New("boom") })
	if err == nil {
		_, err = io.ReadAll(got.Stream)
		got.Stream.Close()
	}
	if err == nil {
		t.Error("a failing rewriter's stream read cleanly")
	}
	// Held documents stay within the budget.
	for i := range 40 {
		key := "doc" + strings.Repeat("x", i)
		e.up.set("/"+key, bytes.Repeat([]byte{'a' + byte(i%26)}, 100000), "", "")
		d, _ := e.get(key)
		if _, err := e.c.Derive(ctx, d, "upper", upper); err != nil {
			t.Fatal(err)
		}
	}
	if e.c.DerivedBytes() > 1<<20 {
		t.Errorf("%d bytes held, over the budget", e.c.DerivedBytes())
	}
}

// TestDocCacheLargeDocument stores and serves a document the size of
// the largest npm packuments with the default budget: it streams into
// the blob store and through the rewriter without being held.
func TestDocCacheLargeDocument(t *testing.T) {
	if testing.Short() {
		t.Skip("large document")
	}
	e := newDocEnv(t)
	big := bytes.Repeat([]byte(`{"name":"next","versions":{}}`+"\n"), 32<<20/30)
	e.up.set("/next", big, `"big"`, "")
	d := e.want("next", string(big), upstream.ResultFetched)
	got, err := e.c.Derive(ctx, d, "upper", upper)
	if err != nil || got.Stream == nil {
		t.Fatalf("Derive = %+v, %v; want a stream", got, err)
	}
	n, err := io.Copy(io.Discard, got.Stream)
	got.Stream.Close()
	if err != nil || n != int64(len(big)) || e.c.DerivedBytes() != 0 {
		t.Errorf("streamed %d of %d bytes, %v; %d bytes held", n, len(big), err, e.c.DerivedBytes())
	}
}
