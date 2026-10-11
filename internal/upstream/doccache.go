package upstream

import (
	"bytes"
	"cmp"
	"container/list"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"sync"
	"time"

	"github.com/terrabyteian/flint/internal/blob"
	"github.com/terrabyteian/flint/internal/meta"
)

// DocCache caches mutable upstream documents, such as package listings,
// version lists, and index files, for proxy repositories of every
// format. Documents are kept in the blob store, never only in memory,
// with a cache\0doc record naming the stored copy and what revalidating
// it needs:
//
//   - A document is served from the cache for the repository's
//     revalidation window after the upstream last confirmed it. The
//     confirmation time is kept in memory, as for OCI tags.
//   - After the window, flint sends a conditional request with the
//     stored ETag and Last-Modified. A 304 only refreshes the
//     confirmation time; since the ETag is durable, the first
//     revalidation after a restart is a cheap 304, not a refetch.
//   - An upstream that answers not found (404 or 410) or denies access
//     is answered so, even if the document is cached; the cached copy
//     stays in the cache. An upstream that cannot be reached, or sends a
//     document the format cannot read, has the cached copy served.
//   - Concurrent lookups of one document collapse into one.
//
// Upstream bytes are stored verbatim, streamed into the blob store as
// they arrive, so documents of hundreds of megabytes are never held in
// memory to be stored. A format that must rewrite a document, such as
// to point its links at flint, or filter it, does so when serving it
// (Derive), so a change to the URL flint is reached at never needs a
// cache flush. Replacing a stored copy only relinks the record; garbage
// collection reclaims the old blob.
type DocCache struct {
	meta    meta.Store
	blobs   blob.Store
	space   *Space
	m       *Metrics
	log     *slog.Logger
	now     func() time.Time
	idle    time.Duration
	fresh   *Freshness
	calls   Group[*Doc]
	derived *derivedCache
}

// Defaults for DocCacheOptions and DocRequest.
const (
	// DefaultDeriveBudget bounds the derived documents a DocCache keeps
	// in memory.
	DefaultDeriveBudget = 64 << 20
	// DefaultMaxDocSize bounds a document fetched from upstream.
	DefaultMaxDocSize = 1 << 30
	// DefaultRevalidateTimeout bounds the wait for an upstream's answer
	// when a cached copy could be served instead.
	DefaultRevalidateTimeout = 10 * time.Second
	// DefaultDocFetchTimeout bounds the wait for an upstream's answer to
	// a document that is not cached.
	DefaultDocFetchTimeout = time.Minute
)

// DocCacheOptions configures a DocCache.
type DocCacheOptions struct {
	// Meta and Blobs are the stores. Required.
	Meta  meta.Store
	Blobs blob.Store
	// Space, if not nil, is consulted before a document is stored.
	Space *Space
	// Metrics, if not nil, counts upstream bytes and errors.
	Metrics *Metrics
	// DeriveBudget bounds the bytes of derived documents kept in memory;
	// zero means DefaultDeriveBudget. A document whose stored copy is
	// larger than a quarter of it is streamed through the rewriter
	// instead of being held.
	DeriveBudget int64
	// IdleTimeout bounds the wait for the next bytes of a document's
	// body; zero means DefaultIdleTimeout.
	IdleTimeout time.Duration
	// Logger receives warnings; nil means slog.Default().
	Logger *slog.Logger
	// Now is the clock; nil means time.Now.
	Now func() time.Time
}

// NewDocCache returns a DocCache.
func NewDocCache(opts DocCacheOptions) *DocCache {
	c := &DocCache{meta: opts.Meta, blobs: opts.Blobs, space: opts.Space, m: opts.Metrics, log: opts.Logger,
		now: opts.Now, idle: opts.IdleTimeout}
	if c.log == nil {
		c.log = slog.Default()
	}
	if c.now == nil {
		c.now = time.Now
	}
	if c.idle <= 0 {
		c.idle = DefaultIdleTimeout
	}
	budget := opts.DeriveBudget
	if budget <= 0 {
		budget = DefaultDeriveBudget
	}
	c.fresh = NewFreshness(c.now)
	c.derived = newDerivedCache(budget)
	return c
}

// DocRequest names a document of a proxy repository and how to fetch it.
type DocRequest struct {
	// Repo is the proxy repository's name, and Key the document's name
	// within it, which the format chooses, such as a package name.
	Repo, Key string
	// Client is the repository's upstream client, and URL the document's
	// absolute URL.
	Client *Client
	URL    string
	// Header holds further request headers, such as Accept.
	Header http.Header
	// Revalidate is the repository's revalidation window; zero means
	// the document is revalidated on every request.
	Revalidate time.Duration
	// RevalidateTimeout and FetchTimeout bound the wait for the
	// upstream's answer, when a cached copy could be served instead and
	// when none could; zero means DefaultRevalidateTimeout and
	// DefaultDocFetchTimeout. The body then streams with the cache's idle
	// timeout between reads, so a large document is not cut off.
	RevalidateTimeout, FetchTimeout time.Duration
	// MaxSize bounds the document; zero means DefaultMaxDocSize.
	MaxSize int64
	// MaxMemory bounds a document held in memory because it cannot be
	// stored, such as when the data directory is nearly full; zero means
	// DefaultDeriveBudget. A larger one is answered from the cached copy
	// if there is one, and fails with ErrNoSpace otherwise.
	MaxMemory int64
	// Validate, if not nil, checks a newly fetched document before it is
	// linked and served, such as by parsing it; it reads it with
	// DocCache.Open. A document that fails is treated as an upstream
	// failure: the cached copy is served if there is one.
	Validate func(ctx context.Context, d *Doc) error
	// Actor and Action are the origin of the batch that caches the
	// document; Action defaults to "proxy.cache".
	Actor, Action string
}

// ErrNoSpace means a document could be neither stored, because the data
// directory is nearly full, nor held in memory, because it is too large.
var ErrNoSpace = errors.New("the data directory is nearly full and the document is too large to pass through")

// Doc is a document as a DocCache resolved it.
type Doc struct {
	DocRecord
	// Result says how it was resolved: ResultHit, ResultRevalidated,
	// ResultFetched, ResultStale, or ResultPassthrough (fetched but not
	// stored, held in memory).
	Result string

	body []byte // the content of a document not stored
}

// Stored reports whether the document is in the blob store, as opposed
// to held in memory because it could not be stored.
func (d *Doc) Stored() bool { return d.body == nil }

func freshKey(repo, key string) string { return repo + "\x00" + key }

// Lookup returns the record of repo's cached document key, or nil.
func (c *DocCache) Lookup(repo, key string) (*DocRecord, error) {
	v := c.meta.View()
	defer v.Release()
	rec, ok := v.Get(DocKey(repo, key))
	if !ok {
		return nil, nil
	}
	return DecodeDocRecord(rec.Value)
}

// present reports whether the blob a record names is in the store.
func (c *DocCache) present(ctx context.Context, r *DocRecord) bool {
	if r == nil {
		return false
	}
	if _, err := c.blobs.Stat(ctx, r.Digest); err != nil {
		if errors.Is(err, blob.ErrNotFound) {
			c.log.WarnContext(ctx, "a cached document's blob is missing from the blob store; fetching it again",
				"digest", r.Digest.String())
		}
		return false
	}
	return true
}

// Get returns the document req names: from the cache while the upstream
// confirmed it within the revalidation window, and from the upstream
// otherwise, falling back to the cached copy if the upstream cannot be
// reached. A document the upstream answers is not found or denied
// fails with an error for which Answered is true.
func (c *DocCache) Get(ctx context.Context, req *DocRequest) (*Doc, error) {
	fk := freshKey(req.Repo, req.Key)
	cached, err := c.Lookup(req.Repo, req.Key)
	if err != nil {
		return nil, err
	}
	if cached != nil && req.Revalidate > 0 && c.fresh.Fresh(fk, req.Revalidate) && c.present(ctx, cached) {
		return &Doc{DocRecord: *cached, Result: ResultHit}, nil
	}
	return c.calls.Do(ctx, fk, func(ctx context.Context) (*Doc, error) {
		return c.resolve(ctx, req, cached)
	})
}

// resolve asks the upstream about a document, cached or not.
func (c *DocCache) resolve(ctx context.Context, req *DocRequest, cached *DocRecord) (*Doc, error) {
	fk := freshKey(req.Repo, req.Key)
	if cached != nil && !c.present(ctx, cached) {
		cached = nil
	}
	stale := func(cause error) (*Doc, error) {
		c.countError(req)
		c.log.WarnContext(ctx, "serving a cached document the upstream could not confirm", "repository", req.Repo,
			"document", req.Key, "upstream", req.Client.Host(), "err", cause)
		return &Doc{DocRecord: *cached, Result: ResultStale}, nil
	}
	if cached != nil && req.Client.Offline() {
		return &Doc{DocRecord: *cached, Result: ResultStale}, nil
	}
	doc, err := c.fetch(ctx, req, cached)
	switch {
	case err == nil && doc == nil: // 304
		c.fresh.Confirm(fk)
		return &Doc{DocRecord: *cached, Result: ResultRevalidated}, nil
	case err == nil:
		return doc, nil
	case Answered(err):
		if !errors.Is(err, ErrNotFound) {
			c.countError(req)
		}
		return nil, err
	case cached != nil:
		return stale(err)
	}
	if !errors.Is(err, ErrNotFound) {
		c.countError(req)
	}
	return nil, err
}

func (c *DocCache) countError(req *DocRequest) {
	if c.m != nil {
		c.m.UpstreamErrors.With(req.Repo).Inc()
	}
}

// fetch fetches a document from the upstream, conditionally if cached is
// not nil, and stores it. It returns nil and no error for a 304.
func (c *DocCache) fetch(ctx context.Context, req *DocRequest, cached *DocRecord) (*Doc, error) {
	// The answer must start within the timeout; the body then has the
	// idle timeout between reads, so a large document is not cut off.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	timeout := cmp.Or(req.FetchTimeout, DefaultDocFetchTimeout)
	if cached != nil {
		timeout = cmp.Or(req.RevalidateTimeout, DefaultRevalidateTimeout)
	}
	watchdog := time.AfterFunc(timeout, cancel)
	defer watchdog.Stop()
	hdr := http.Header{}
	for k, vs := range req.Header {
		hdr[k] = vs
	}
	if cached != nil {
		if cached.ETag != "" {
			hdr.Set("If-None-Match", cached.ETag)
		}
		if cached.LastModified != "" {
			hdr.Set("If-Modified-Since", cached.LastModified)
		}
	}
	op := "GET " + req.URL
	resp, err := req.Client.GetURL(withWatchdog(ctx, watchdog, timeout), req.URL, hdr)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusNotModified && cached != nil:
		return nil, nil
	case resp.StatusCode != http.StatusOK:
		return nil, &Error{Op: op, Status: resp.StatusCode, Err: fmt.Errorf("unexpected status %s", resp.Status)}
	}
	maxSize := req.MaxSize
	if maxSize <= 0 {
		maxSize = DefaultMaxDocSize
	}
	if resp.ContentLength > maxSize {
		return nil, &Error{Op: op, Err: ErrTooLarge}
	}
	rec := DocRecord{
		ContentType:  resp.Header.Get("Content-Type"),
		ETag:         resp.Header.Get("ETag"),
		LastModified: resp.Header.Get("Last-Modified"),
		URL:          resp.Request.URL.String(),
		Fetched:      c.now().UTC(),
	}
	body := &idleReader{r: io.LimitReader(resp.Body, maxSize+1), reset: func() { watchdog.Reset(c.idle) }}
	watchdog.Reset(c.idle)
	release, ok := func() (func(), bool) {
		if c.space == nil {
			return func() {}, true
		}
		return c.space.Reserve(resp.ContentLength)
	}()
	var doc *Doc
	if ok {
		doc, err = c.store(ctx, req, rec, body, maxSize)
		release()
	} else {
		doc, err = c.hold(req, rec, body, maxSize)
	}
	if err != nil {
		if ctx.Err() != nil && !errors.Is(err, ErrTooLarge) {
			err = fmt.Errorf("%w: no data from the upstream for %v while fetching the document", ErrUnavailable, c.idle)
		}
		return nil, wrapOp(op, err)
	}
	if c.m != nil {
		c.m.UpstreamBytes.With(req.Repo).Add(float64(doc.Size))
	}
	if req.Validate != nil {
		if err := req.Validate(ctx, doc); err != nil {
			return nil, wrapOp(op, err)
		}
	}
	if !doc.Stored() {
		return doc, nil
	}
	// Link it, unless the record already says the same.
	same := cached != nil && cached.Digest == doc.Digest
	if same && cached.ETag == doc.ETag && cached.LastModified == doc.LastModified && cached.URL == doc.URL {
		doc.Result = ResultRevalidated
		c.fresh.Confirm(freshKey(req.Repo, req.Key))
		return doc, nil
	}
	action := req.Action
	if action == "" {
		action = "proxy.cache"
	}
	err = CommitLink(ctx, c.meta, c.blobs, []blob.Digest{doc.Digest}, func(_ meta.View, b *meta.Batch) {
		b.Put(DocKey(req.Repo, req.Key), doc.DocRecord.encode())
		b.SetOrigin(meta.Origin{Actor: req.Actor, Action: action, Target: req.Repo + "/" + req.Key})
	})
	if err != nil {
		// Served, but not confirmed: the next request asks again rather
		// than serving the older cached copy for a whole window.
		c.log.WarnContext(ctx, "caching a document failed", "repository", req.Repo, "document", req.Key, "err", err)
		return doc, nil
	}
	if same {
		doc.Result = ResultRevalidated
	}
	c.fresh.Confirm(freshKey(req.Repo, req.Key))
	return doc, nil
}

// wrapOp wraps err in an *Error naming op, unless it is one already.
func wrapOp(op string, err error) error {
	var e *Error
	if errors.As(err, &e) {
		return err
	}
	return &Error{Op: op, Err: err}
}

// store streams a document body into the blob store.
func (c *DocCache) store(ctx context.Context, req *DocRequest, rec DocRecord, body io.Reader, maxSize int64) (*Doc, error) {
	up, err := c.blobs.NewUpload(ctx)
	if err != nil {
		return nil, err
	}
	n, err := io.Copy(up, body)
	if err == nil && n > maxSize {
		err = ErrTooLarge
	}
	if err != nil {
		up.Cancel()
		if !errors.Is(err, ErrTooLarge) {
			err = fmt.Errorf("%w: reading the document: %v", ErrUnavailable, err)
		}
		return nil, err
	}
	info, err := up.Commit(ctx, blob.Digest{})
	if err != nil {
		return nil, err
	}
	rec.Digest, rec.Size = info.Digest, info.Size
	return &Doc{DocRecord: rec, Result: ResultFetched}, nil
}

// hold reads a document that cannot be stored into memory.
func (c *DocCache) hold(req *DocRequest, rec DocRecord, body io.Reader, maxSize int64) (*Doc, error) {
	limit := req.MaxMemory
	if limit <= 0 {
		limit = DefaultDeriveBudget
	}
	b, err := io.ReadAll(io.LimitReader(body, min(limit, maxSize)+1))
	switch {
	case err != nil:
		return nil, fmt.Errorf("%w: reading the document: %v", ErrUnavailable, err)
	case int64(len(b)) > maxSize:
		return nil, ErrTooLarge
	case int64(len(b)) > limit:
		return nil, ErrNoSpace
	}
	rec.Digest, rec.Size = blob.FromBytes(b), int64(len(b))
	if b == nil {
		b = []byte{}
	}
	return &Doc{DocRecord: rec, Result: ResultPassthrough, body: b}, nil
}

// idleReader calls reset after every read, to push back an idle timeout.
type idleReader struct {
	r     io.Reader
	reset func()
}

func (r *idleReader) Read(p []byte) (int, error) {
	n, err := r.r.Read(p)
	r.reset()
	return n, err
}

// Open returns a document's content as the upstream sent it, size
// d.Size. For a stored document, it is the blob store's reader: the
// filesystem store's *os.File, so a server can send it with sendfile.
func (c *DocCache) Open(ctx context.Context, d *Doc) (io.ReadSeekCloser, error) {
	if !d.Stored() {
		return nopCloser{bytes.NewReader(d.body)}, nil
	}
	return c.blobs.Open(ctx, d.Digest)
}

type nopCloser struct{ io.ReadSeeker }

func (nopCloser) Close() error { return nil }

// Rewrite writes a document as served, read from src, to dst: with its
// links rewritten, filtered, or otherwise derived.
type Rewrite func(dst io.Writer, src io.Reader) error

// Derived is a document as served after a Rewrite: either its bytes,
// held in memory, or a stream through the rewriter.
type Derived struct {
	// Bytes is the derived document, if held in memory.
	Bytes []byte
	// Stream, if Bytes is nil, yields the derived document while the
	// rewriter runs; the caller must close it. A rewriter error fails
	// its Read.
	Stream io.ReadCloser
}

// Derive returns document d as rewritten by rw. variant must name
// everything the result depends on besides the document's content, such
// as the format, the rewriting, and the base URL links point at: derived
// documents are cached in memory by d's digest and variant, within the
// cache's budget, so a document is rewritten once however often it is
// served. A document whose stored copy is larger than a quarter of the
// budget is streamed through rw instead of being held.
func (c *DocCache) Derive(ctx context.Context, d *Doc, variant string, rw Rewrite) (*Derived, error) {
	k := d.Digest.String() + "\x00" + variant
	if b := c.derived.get(k); b != nil {
		return &Derived{Bytes: b}, nil
	}
	src, err := c.Open(ctx, d)
	if err != nil {
		return nil, err
	}
	if d.Size > c.derived.maxEntry() {
		pr, pw := io.Pipe()
		go func() {
			defer src.Close()
			pw.CloseWithError(rw(pw, src))
		}()
		return &Derived{Stream: pr}, nil
	}
	defer src.Close()
	var out bytes.Buffer
	if err := rw(&out, src); err != nil {
		return nil, err
	}
	b := out.Bytes()
	if b == nil {
		b = []byte{}
	}
	c.derived.put(k, b)
	return &Derived{Bytes: b}, nil
}

// MediaType returns a document's media type, without parameters, or "".
func (d *Doc) MediaType() string {
	mt, _, _ := mime.ParseMediaType(d.ContentType)
	return mt
}

// Prune forgets confirmations older than window, the longest
// revalidation window of any repository.
func (c *DocCache) Prune(window time.Duration) { c.fresh.Prune(window) }

// Run prunes confirmations older than window, the longest revalidation
// window of any repository, every PullFlushInterval until ctx is done.
func (c *DocCache) Run(ctx context.Context, window time.Duration) {
	t := time.NewTicker(PullFlushInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			c.Prune(window)
		}
	}
}

// derivedCache holds derived documents by key, least recently used out
// first, within a byte budget.
type derivedCache struct {
	budget int64

	mu    sync.Mutex
	ll    *list.List // of *derivedEntry, most recently used first
	m     map[string]*list.Element
	total int64
}

type derivedEntry struct {
	key string
	b   []byte
}

func newDerivedCache(budget int64) *derivedCache {
	return &derivedCache{budget: budget, ll: list.New(), m: map[string]*list.Element{}}
}

func (c *derivedCache) maxEntry() int64 { return c.budget / 4 }

func (c *derivedCache) get(k string) []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	e := c.m[k]
	if e == nil {
		return nil
	}
	c.ll.MoveToFront(e)
	return e.Value.(*derivedEntry).b
}

func (c *derivedCache) put(k string, b []byte) {
	if int64(len(b)) > c.maxEntry() {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if e := c.m[k]; e != nil {
		c.total -= int64(len(e.Value.(*derivedEntry).b))
		c.ll.Remove(e)
	}
	c.m[k] = c.ll.PushFront(&derivedEntry{k, b})
	c.total += int64(len(b))
	for c.total > c.budget {
		e := c.ll.Back()
		de := e.Value.(*derivedEntry)
		c.ll.Remove(e)
		delete(c.m, de.key)
		c.total -= int64(len(de.b))
	}
}

// DerivedBytes returns the bytes of derived documents held in memory.
func (c *DocCache) DerivedBytes() int64 { return c.derived.size() }

// size returns the bytes held.
func (c *derivedCache) size() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.total
}
