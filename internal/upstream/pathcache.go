package upstream

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/terrabyteian/flint/internal/blob"
	"github.com/terrabyteian/flint/internal/meta"
)

// PathCache is the engine of path-addressed proxy repositories, whose
// clients name content by path: Maven, Go modules, generic files, Linux
// package repositories, and the like. The format classifies each
// request (Route) as one of three kinds, and the engine does the rest:
//
//   - Immutable content is fetched once, verified against what the
//     format expects (Expect) before it is cached and before any client
//     receives its final byte, and cached forever under a cache\0file
//     record with its digest, size, content type, and the other digests
//     verified or computed. Concurrent requests share one fetch.
//   - Mutable content is a document, cached and revalidated by the
//     DocCache.
//   - Pass-through content is never cached.
//
// A proxy repository serves only content its own upstream sent it: a
// file is fetched and recorded for the repository even when a blob with
// the same digest is stored for another one, since a path, unlike a
// digest, says nothing about the content, and a digest is not a secret.
//
// An upstream not-found answer is remembered for a short time (the
// repository's NotFoundTTL), so build tools probing for content that
// does not exist cost one upstream request per window. When the data
// directory is nearly full, or a file would not fit the repository's
// size limit, content is passed through without being cached, still
// verified; nothing is deleted to make room except by the size limit's
// eviction, which is opt-in.
type PathCache struct {
	meta    meta.Store
	blobs   blob.Store
	fetcher *Fetcher
	docs    *DocCache
	space   *Space
	m       *Metrics
	limits  *Limits
	log     *slog.Logger
	now     func() time.Time
	neg     *NegativeCache

	mu    sync.Mutex
	repos map[string]*PathRepo
}

// PathCacheOptions configures a PathCache.
type PathCacheOptions struct {
	// Meta, Blobs, Fetcher, and Docs are the stores and the shared
	// fetcher and document cache. Required.
	Meta    meta.Store
	Blobs   blob.Store
	Fetcher *Fetcher
	Docs    *DocCache
	// Space, if not nil, is consulted before content is cached.
	Space *Space
	// Metrics receives the proxy metrics. Required.
	Metrics *Metrics
	// Logger receives warnings; nil means slog.Default().
	Logger *slog.Logger
	// Now is the clock; nil means time.Now.
	Now func() time.Time
}

// NewPathCache returns a PathCache without repositories.
func NewPathCache(opts PathCacheOptions) *PathCache {
	pc := &PathCache{meta: opts.Meta, blobs: opts.Blobs, fetcher: opts.Fetcher, docs: opts.Docs, space: opts.Space,
		m: opts.Metrics, log: opts.Logger, now: opts.Now, repos: map[string]*PathRepo{}}
	if pc.log == nil {
		pc.log = slog.Default()
	}
	if pc.now == nil {
		pc.now = time.Now
	}
	pc.neg = NewNegativeCache(pc.now)
	pc.limits = NewLimits(LimitsOptions{Meta: pc.meta, Metrics: pc.m, PulledKey: pulledKey, Now: pc.now,
		FormatOf: func(repo string) string {
			pc.mu.Lock()
			defer pc.mu.Unlock()
			if rp := pc.repos[repo]; rp != nil {
				return rp.Format
			}
			return "proxy"
		}})
	return pc
}

// PathRepo is a path-addressed proxy repository.
type PathRepo struct {
	// Name is the repository's name.
	Name string
	// Format names the format, for the origins of the batches that cache
	// content, save pull times, and evict, as "<format>.proxy.cache",
	// "<format>.proxy.pulled", and "<format>.proxy.evict".
	Format string
	// Client is the repository's upstream client.
	Client *Client
	// Revalidate is the revalidation window of mutable content.
	Revalidate time.Duration
	// NotFoundTTL is how long an upstream not-found answer is
	// remembered; zero means DefaultNotFoundTTL, and a negative value
	// turns remembering off.
	NotFoundTTL time.Duration
	// SizeLimit, if positive, caps the files cached in the repository;
	// over it, the least recently pulled are evicted. Documents are not
	// counted.
	SizeLimit int64
	// WriteError, if not nil, writes an error response in the format's
	// form; nil means a plain-text body.
	WriteError func(w http.ResponseWriter, r *http.Request, status int, msg string)

	tracker *CacheTracker
}

// Add adds a repository, loading what a size-limited one caches.
func (pc *PathCache) Add(rp *PathRepo) error {
	if rp.SizeLimit > 0 {
		rp.tracker = NewCacheTracker(rp.Name, rp.SizeLimit)
		v := pc.meta.View()
		defer v.Release()
		pfx := FileKey(rp.Name, "")
		var failure error
		v.Scan(pfx, nil, func(k []byte, rec meta.Record) bool {
			f, err := DecodeFileRecord(rec.Value)
			if err != nil {
				failure = fmt.Errorf("upstream: metadata key %q: %w", k, err)
				return false
			}
			rp.tracker.Load(string(k), f.Size)
			return true
		})
		if failure == nil {
			failure = pc.limits.LoadPulled(rp.tracker, v, pfx)
		}
		if failure != nil {
			return failure
		}
	}
	pc.mu.Lock()
	pc.repos[rp.Name] = rp
	pc.mu.Unlock()
	if rp.tracker != nil {
		pc.limits.Add(rp.tracker)
	}
	return nil
}

// Kind classifies a request path.
type Kind int

// Kinds of request paths.
const (
	// Immutable content never changes: cached forever and verified.
	Immutable Kind = iota + 1
	// Mutable content is a document, revalidated (see DocCache).
	Mutable
	// PassThrough content is never cached.
	PassThrough
)

// Route is how a format serves one request of a path-addressed proxy
// repository.
type Route struct {
	// Kind classifies the request.
	Kind Kind
	// Path names the content within the repository: the cache key of
	// immutable and mutable content, normally the request path.
	Path string
	// URL is the absolute upstream URL to fetch.
	URL string
	// Header holds further upstream request headers, such as Accept.
	Header http.Header
	// Expect is what immutable content must match. Its Size is -1 when
	// unknown.
	Expect Expect
	// ContentType is the media type served; "" means the upstream's,
	// or application/octet-stream if it sent none.
	ContentType string
	// Rewrite, if not nil, derives mutable content as served, with
	// Variant naming the derivation (see DocCache.Derive).
	Rewrite Rewrite
	Variant string
	// MaxSize bounds mutable content; zero means DefaultMaxDocSize.
	MaxSize int64
	// KeepGone answers an upstream 410 with 410 rather than 404, for
	// protocols that distinguish them.
	KeepGone bool
}

// Lookup returns the record of the file rp cached at path, or nil.
func (pc *PathCache) Lookup(rp *PathRepo, path string) (*FileRecord, error) {
	v := pc.meta.View()
	defer v.Release()
	rec, ok := v.Get(FileKey(rp.Name, path))
	if !ok {
		return nil, nil
	}
	return DecodeFileRecord(rec.Value)
}

// Serve answers a GET or HEAD request r of repository rp as rt says.
// actor is the origin actor of any batch that caches content.
func (pc *PathCache) Serve(w http.ResponseWriter, r *http.Request, rp *PathRepo, rt *Route, actor string) {
	switch rt.Kind {
	case Immutable:
		pc.serveImmutable(w, r, rp, rt, actor)
	case Mutable:
		pc.serveMutable(w, r, rp, rt, actor)
	default:
		pc.servePassThrough(w, r, rp, rt)
	}
}

func (rp *PathRepo) notFoundTTL() time.Duration {
	if rp.NotFoundTTL == 0 {
		return DefaultNotFoundTTL
	}
	return rp.NotFoundTTL
}

func negKey(rp *PathRepo, path string) string { return rp.Name + "\x00" + path }

// serveImmutable serves immutable content: from the cache, or else
// fetched, verified, and cached while it streams to the client.
func (pc *PathCache) serveImmutable(w http.ResponseWriter, r *http.Request, rp *PathRepo, rt *Route, actor string) {
	ctx := r.Context()
	k := FileKey(rp.Name, rt.Path)
	f, err := pc.Lookup(rp, rt.Path)
	if err != nil {
		pc.fail(w, r, rp, rt, err)
		return
	}
	if f != nil {
		pc.limits.Touch(rp.tracker, k)
		ct := f.ContentType
		if rt.ContentType != "" {
			ct = rt.ContentType
		}
		if pc.serveBlob(w, r, f.Digest, ct) {
			pc.m.Requests.With(rp.Name, ResultHit).Inc()
			return
		}
		// Linked but missing from the store: fetch it again.
	}
	if pc.neg.Known(negKey(rp, rt.Path)) {
		pc.fail(w, r, rp, rt, &Error{Op: "GET " + rt.URL, Status: http.StatusNotFound, Err: ErrNotFound})
		return
	}
	if r.Method == http.MethodHead {
		pc.head(w, r, rp, rt)
		return
	}
	if pc.space != nil && pc.space.Pressure() {
		pc.passThroughVerified(w, r, rp, rt)
		return
	}
	var release func()
	open := func(ctx context.Context) (io.ReadCloser, int64, string, error) {
		resp, err := rp.Client.GetURL(ctx, rt.URL, rt.Header)
		if err != nil {
			return nil, 0, "", err
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return nil, 0, "", &Error{Op: "GET " + rt.URL, Status: resp.StatusCode, Err: fmt.Errorf("unexpected status %s", resp.Status)}
		}
		size := resp.ContentLength
		if rt.Expect.Size >= 0 {
			size = rt.Expect.Size
		}
		rel, ok := pc.admit(rp, size)
		if !ok {
			resp.Body.Close()
			return nil, 0, "", errPassThrough
		}
		release = rel
		return resp.Body, resp.ContentLength, resp.Header.Get("Content-Type"), nil
	}
	done := func(ctx context.Context, res PathResult, err error) {
		if release != nil {
			release()
		}
		if err != nil {
			pc.fetchFailed(rp, rt, err)
			return
		}
		pc.m.UpstreamBytes.With(rp.Name).Add(float64(res.Info.Size))
		ct := rt.ContentType
		if ct == "" {
			ct = orOctetStream(res.ContentType)
		}
		rec := &FileRecord{Digest: res.Info.Digest, Size: res.Info.Size, ContentType: ct, Sums: res.Sums, Fetched: pc.now().UTC()}
		err = commitLink(ctx, pc.meta, pc.blobs, []blob.Digest{rec.Digest}, func(_ meta.View, b *meta.Batch) {
			b.Put(k, rec.encode())
			b.SetOrigin(meta.Origin{Actor: actor, Action: rp.Format + ".proxy.cache", Target: rp.Name + "/" + rt.Path})
		})
		if err != nil {
			pc.log.Warn("caching a proxied file failed", "repository", rp.Name, "path", rt.Path, "err", err)
			return
		}
		pc.limits.Track(rp.tracker, k, rec.Size)
	}
	fe, _ := pc.fetcher.FetchPath("path\x00"+rp.Name+"\x00"+rt.Path, rp.Name+"/"+rt.Path, rt.Expect, open, done)
	defer fe.Release()
	size, err := fe.Wait(ctx)
	if errors.Is(err, errPassThrough) {
		pc.passThroughVerified(w, r, rp, rt)
		return
	}
	if err != nil {
		if ctx.Err() != nil {
			return
		}
		pc.fail(w, r, rp, rt, err)
		return
	}
	ct := rt.ContentType
	if ct == "" {
		ct = orOctetStream(fe.ContentType())
	}
	w.Header().Set("Content-Type", ct)
	if size >= 0 {
		w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
	}
	w.WriteHeader(http.StatusOK)
	if _, err := fe.Stream(ctx, w); err != nil {
		// Part of the file is out: cut the connection, so the client
		// cannot take it for the whole file. The fetch logs its failure.
		panic(http.ErrAbortHandler)
	}
	pc.m.Requests.With(rp.Name, ResultFetched).Inc()
}

func orOctetStream(ct string) string {
	if ct == "" {
		return "application/octet-stream"
	}
	return ct
}

// errPassThrough means content must be passed through, not cached.
var errPassThrough = errors.New("upstream: content passed through without caching")

// fetchFailed logs and counts a failed fetch of immutable content, once
// however many clients waited on it, and remembers a not-found answer.
func (pc *PathCache) fetchFailed(rp *PathRepo, rt *Route, err error) {
	switch {
	case errors.Is(err, errPassThrough):
	case errors.Is(err, ErrNotFound):
		pc.neg.Remember(negKey(rp, rt.Path), rp.notFoundTTL())
	default:
		if errors.Is(err, ErrUnavailable) {
			rp.Client.MarkOffline()
		}
		pc.m.UpstreamErrors.With(rp.Name).Inc()
		pc.log.Warn("proxy file fetch failed", "repository", rp.Name, "path", rt.Path, "upstream", rp.Client.Host(), "err", err)
	}
}

// admit decides whether content of size bytes (-1 if unknown) may be
// cached in rp: the data directory must have room for it, and it must
// fit the repository's size limit.
func (pc *PathCache) admit(rp *PathRepo, size int64) (release func(), ok bool) {
	if rp.SizeLimit > 0 && size > rp.SizeLimit {
		return nil, false
	}
	if pc.space == nil {
		return func() {}, true
	}
	return pc.space.Reserve(size)
}

// serveBlob serves a cached blob, reporting false if it is missing from
// the blob store.
func (pc *PathCache) serveBlob(w http.ResponseWriter, r *http.Request, d blob.Digest, ct string) bool {
	f, err := pc.blobs.Open(r.Context(), d)
	if errors.Is(err, blob.ErrNotFound) {
		pc.log.WarnContext(r.Context(), "a cached file's blob is missing from the blob store", "digest", d.String())
		return false
	}
	if err != nil {
		http.Error(w, "reading the blob store failed", http.StatusInternalServerError)
		return true
	}
	defer f.Close()
	w.Header().Set("Content-Type", orOctetStream(ct))
	w.Header().Set("ETag", `"`+d.String()+`"`)
	// The filesystem store returns the *os.File itself, so on plain
	// HTTP/1.1 ServeContent's copy reaches sendfile. It also answers
	// Range and conditional requests, and HEAD.
	http.ServeContent(w, r, "", time.Time{}, f)
	return true
}

// head answers a HEAD request for immutable content that is not cached
// from the upstream's answer to one.
func (pc *PathCache) head(w http.ResponseWriter, r *http.Request, rp *PathRepo, rt *Route) {
	resp, err := rp.Client.Request(r.Context(), http.MethodHead, rt.URL, rt.Header)
	if err == nil && resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		err = &Error{Op: "HEAD " + rt.URL, Status: resp.StatusCode, Err: fmt.Errorf("unexpected status %s", resp.Status)}
	}
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			pc.neg.Remember(negKey(rp, rt.Path), rp.notFoundTTL())
		}
		pc.fail(w, r, rp, rt, err)
		return
	}
	resp.Body.Close()
	ct := rt.ContentType
	if ct == "" {
		ct = orOctetStream(resp.Header.Get("Content-Type"))
	}
	w.Header().Set("Content-Type", ct)
	if resp.ContentLength >= 0 {
		w.Header().Set("Content-Length", strconv.FormatInt(resp.ContentLength, 10))
	}
	w.WriteHeader(http.StatusOK)
}

// maxCheckInMemory bounds immutable content with an Expect.Check that is
// passed through: it is held in memory to be checked before it is sent.
const maxCheckInMemory = 64 << 20

// passThroughVerified streams immutable content to the client without
// caching it, verified against rt.Expect on the way: the final bytes are
// sent only once the content has matched. Content with an Expect.Check
// is held in memory, up to maxCheckInMemory, and checked before any of
// it is sent.
func (pc *PathCache) passThroughVerified(w http.ResponseWriter, r *http.Request, rp *PathRepo, rt *Route) {
	ctx := r.Context()
	resp, err := rp.Client.GetURL(ctx, rt.URL, rt.Header)
	if err == nil && resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		err = &Error{Op: "GET " + rt.URL, Status: resp.StatusCode, Err: fmt.Errorf("unexpected status %s", resp.Status)}
	}
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			pc.neg.Remember(negKey(rp, rt.Path), rp.notFoundTTL())
		} else if !errors.Is(err, context.Canceled) {
			pc.m.UpstreamErrors.With(rp.Name).Inc()
		}
		pc.fail(w, r, rp, rt, err)
		return
	}
	defer resp.Body.Close()
	size := resp.ContentLength
	if rt.Expect.Size >= 0 {
		if size >= 0 && size != rt.Expect.Size {
			pc.m.UpstreamErrors.With(rp.Name).Inc()
			pc.fail(w, r, rp, rt, fmt.Errorf("%w: the upstream announced %d bytes, want %d", ErrDigestMismatch, size, rt.Expect.Size))
			return
		}
		size = rt.Expect.Size
	}
	ct := rt.ContentType
	if ct == "" {
		ct = orOctetStream(resp.Header.Get("Content-Type"))
	}
	er, err := newExpectReader(resp.Body, &rt.Expect, rp.Name+"/"+rt.Path)
	if err != nil {
		pc.fail(w, r, rp, rt, err)
		return
	}
	if rt.Expect.Check != nil {
		b, err := io.ReadAll(io.LimitReader(er, maxCheckInMemory+1))
		switch {
		case err == nil && len(b) > maxCheckInMemory:
			err = fmt.Errorf("%w: %s cannot be verified without being cached while the data directory is nearly full", ErrNoSpace, rt.Path)
		case err == nil:
			err = rt.Expect.Check(ctx, bytes.NewReader(b), int64(len(b)))
		}
		if err != nil {
			if !errors.Is(err, ErrNoSpace) {
				pc.m.UpstreamErrors.With(rp.Name).Inc()
			}
			pc.fail(w, r, rp, rt, err)
			return
		}
		w.Header().Set("Content-Type", ct)
		w.Header().Set("Content-Length", strconv.Itoa(len(b)))
		w.WriteHeader(http.StatusOK)
		w.Write(b)
		pc.m.UpstreamBytes.With(rp.Name).Add(float64(len(b)))
		pc.m.Requests.With(rp.Name, ResultPassthrough).Inc()
		return
	}
	w.Header().Set("Content-Type", ct)
	if size >= 0 {
		w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
	}
	w.WriteHeader(http.StatusOK)
	n, err := copyHeld(w, er)
	pc.m.UpstreamBytes.With(rp.Name).Add(float64(n))
	if err != nil {
		if ctx.Err() == nil {
			pc.m.UpstreamErrors.With(rp.Name).Inc()
			pc.log.WarnContext(ctx, "passing a file through from upstream failed", "repository", rp.Name,
				"path", rt.Path, "upstream", rp.Client.Host(), "err", err)
		}
		panic(http.ErrAbortHandler)
	}
	pc.m.Requests.With(rp.Name, ResultPassthrough).Inc()
}

// serveMutable serves a document through the DocCache.
func (pc *PathCache) serveMutable(w http.ResponseWriter, r *http.Request, rp *PathRepo, rt *Route, actor string) {
	ctx := r.Context()
	if pc.neg.Known(negKey(rp, rt.Path)) {
		pc.fail(w, r, rp, rt, &Error{Op: "GET " + rt.URL, Status: http.StatusNotFound, Err: ErrNotFound})
		return
	}
	doc, err := pc.docs.Get(ctx, &DocRequest{Repo: rp.Name, Key: rt.Path, Client: rp.Client, URL: rt.URL, Header: rt.Header,
		Revalidate: rp.Revalidate, MaxSize: rt.MaxSize, Actor: actor, Action: rp.Format + ".proxy.cache"})
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			pc.neg.Remember(negKey(rp, rt.Path), rp.notFoundTTL())
		}
		pc.fail(w, r, rp, rt, err)
		return
	}
	pc.m.Requests.With(rp.Name, doc.Result).Inc()
	ct := rt.ContentType
	if ct == "" {
		ct = orOctetStream(doc.ContentType)
	}
	w.Header().Set("Content-Type", ct)
	if rt.Rewrite == nil {
		f, err := pc.docs.Open(ctx, doc)
		if err != nil {
			pc.fail(w, r, rp, rt, err)
			return
		}
		defer f.Close()
		w.Header().Set("ETag", `"`+doc.Digest.String()+`"`)
		http.ServeContent(w, r, "", time.Time{}, f)
		return
	}
	der, err := pc.docs.Derive(ctx, doc, rt.Variant, rt.Rewrite)
	if err != nil {
		pc.fail(w, r, rp, rt, err)
		return
	}
	if der.Bytes != nil {
		w.Header().Set("ETag", derivedETag(doc.Digest, rt.Variant))
		http.ServeContent(w, r, "", time.Time{}, bytes.NewReader(der.Bytes))
		return
	}
	defer der.Stream.Close()
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodHead {
		return
	}
	if _, err := io.Copy(w, der.Stream); err != nil {
		if ctx.Err() == nil {
			pc.log.WarnContext(ctx, "rewriting a document failed", "repository", rp.Name, "path", rt.Path, "err", err)
		}
		panic(http.ErrAbortHandler)
	}
}

// derivedETag is the ETag of a derived document.
func derivedETag(d blob.Digest, variant string) string {
	h := sha256.New()
	h.Write([]byte(d.String()))
	h.Write([]byte{0})
	h.Write([]byte(variant))
	return `"` + hex.EncodeToString(h.Sum(nil)[:16]) + `"`
}

// servePassThrough serves content that is never cached.
func (pc *PathCache) servePassThrough(w http.ResponseWriter, r *http.Request, rp *PathRepo, rt *Route) {
	ctx := r.Context()
	method := http.MethodGet
	if r.Method == http.MethodHead {
		method = http.MethodHead
	}
	resp, err := rp.Client.Request(ctx, method, rt.URL, rt.Header)
	if err == nil && resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		err = &Error{Op: method + " " + rt.URL, Status: resp.StatusCode, Err: fmt.Errorf("unexpected status %s", resp.Status)}
	}
	if err != nil {
		if !errors.Is(err, ErrNotFound) && !errors.Is(err, context.Canceled) {
			pc.m.UpstreamErrors.With(rp.Name).Inc()
		}
		pc.fail(w, r, rp, rt, err)
		return
	}
	defer resp.Body.Close()
	ct := rt.ContentType
	if ct == "" {
		ct = orOctetStream(resp.Header.Get("Content-Type"))
	}
	w.Header().Set("Content-Type", ct)
	if resp.ContentLength >= 0 {
		w.Header().Set("Content-Length", strconv.FormatInt(resp.ContentLength, 10))
	}
	w.WriteHeader(http.StatusOK)
	n, err := io.Copy(w, resp.Body)
	pc.m.UpstreamBytes.With(rp.Name).Add(float64(n))
	if err != nil {
		panic(http.ErrAbortHandler)
	}
	pc.m.Requests.With(rp.Name, ResultPassthrough).Inc()
}

// fail writes the response for a failed request of rp. A request whose
// client went away gets none.
func (pc *PathCache) fail(w http.ResponseWriter, r *http.Request, rp *PathRepo, rt *Route, err error) {
	if r.Context().Err() != nil {
		return
	}
	status, msg := StatusOf(err, rp.Client.Host())
	if status == http.StatusNotFound && rt.KeepGone && errors.Is(err, ErrGone) {
		status = http.StatusGone
	}
	if status == http.StatusNotFound && !errors.Is(err, ErrDenied) {
		msg = rt.Path + " is not found"
	}
	if rp.WriteError != nil {
		rp.WriteError(w, r, status, msg)
		return
	}
	http.Error(w, msg, status)
}

// StatusOf maps a failed proxy request to an HTTP status and message,
// as every format's proxy answers it: not found for content the
// upstream does not have or denies access to, 503 for an upstream that
// cannot be reached or a cache that cannot take the content, and 502
// for an upstream that failed otherwise, such as content that did not
// match its digest or a host the fetch policy refuses.
func StatusOf(err error, host string) (int, string) {
	switch {
	case errors.Is(err, ErrNotFound):
		return http.StatusNotFound, "not found upstream"
	case errors.Is(err, ErrDenied):
		return http.StatusNotFound, fmt.Sprintf("not found: the upstream %s denied access; it may not exist, or may need credentials", host)
	case errors.Is(err, ErrUnavailable):
		return http.StatusServiceUnavailable, fmt.Sprintf("the upstream %s is unavailable, and the content is not cached", host)
	case errors.Is(err, ErrNoSpace), errors.Is(err, ErrBusy):
		return http.StatusServiceUnavailable, err.Error()
	case errors.Is(err, ErrAuth):
		return http.StatusBadGateway, fmt.Sprintf("flint could not authenticate to the upstream %s, and the content is not cached", host)
	case errors.Is(err, ErrDigestMismatch):
		return http.StatusBadGateway, fmt.Sprintf("content from the upstream %s did not match what it should be", host)
	case errors.Is(err, ErrPolicy):
		return http.StatusBadGateway, fmt.Sprintf("the upstream %s pointed at a host flint does not fetch from: %v", host, err)
	}
	return http.StatusBadGateway, fmt.Sprintf("the upstream %s failed: %v", host, err)
}

// Run does the repositories' background work until ctx is done: it
// persists the last-pull times of size-limited repositories, evicts
// files over their limits, and forgets expired confirmations and
// not-found answers.
func (pc *PathCache) Run(ctx context.Context) {
	var window time.Duration
	pc.mu.Lock()
	for _, rp := range pc.repos {
		window = max(window, rp.Revalidate)
	}
	pc.mu.Unlock()
	pc.limits.Run(ctx, func(msg string, err error) { pc.log.Warn(msg, "err", err) }, func() {
		pc.docs.Prune(window)
		pc.neg.Prune()
	})
}

// FlushPullTimes persists the last-pull times recorded since the last
// flush.
func (pc *PathCache) FlushPullTimes(ctx context.Context) error { return pc.limits.Flush(ctx) }

// Evict evicts the least recently pulled files of every size-limited
// repository over its limit.
func (pc *PathCache) Evict(ctx context.Context) error { return pc.limits.Evict(ctx) }

// expectReader reads content and checks it against an Expect's size,
// sha256 digest, and other digests. At the end of the content, Read
// returns io.EOF only if they match; otherwise it returns an error
// wrapping ErrDigestMismatch. An Expect.Check is not run.
type expectReader struct {
	r     io.Reader
	e     *Expect
	label string
	sha   hash.Hash
	hs    *hashers
	n     int64
	err   error
}

func newExpectReader(r io.Reader, e *Expect, label string) (*expectReader, error) {
	hs, err := newHashers(e)
	if err != nil {
		return nil, err
	}
	return &expectReader{r: r, e: e, label: label, sha: sha256.New(), hs: hs}, nil
}

func (v *expectReader) Read(p []byte) (int, error) {
	if v.err != nil {
		return 0, v.err
	}
	n, err := v.r.Read(p)
	v.sha.Write(p[:n])
	v.hs.Write(p[:n])
	v.n += int64(n)
	if v.e.Size >= 0 && v.n > v.e.Size {
		v.err = fmt.Errorf("%w: more than the %d bytes expected of %s", ErrDigestMismatch, v.e.Size, v.label)
		return 0, v.err
	}
	switch {
	case err == io.EOF:
		got := hex.EncodeToString(v.sha.Sum(nil))
		switch {
		case v.e.Size >= 0 && v.n != v.e.Size:
			err = fmt.Errorf("%w: %d bytes, want %d of %s", io.ErrUnexpectedEOF, v.n, v.e.Size, v.label)
		case v.e.SHA256 != "" && got != v.e.SHA256:
			err = fmt.Errorf("%w: sha256 of %s is %s, want %s", ErrDigestMismatch, v.label, got, v.e.SHA256)
		default:
			if _, verr := v.hs.verify(v.e, v.label); verr != nil {
				err = verr
			}
		}
		v.err = err
	case err != nil:
		v.err = fmt.Errorf("%w: reading %s: %w", ErrUnavailable, v.label, err)
		err = v.err
	}
	return n, err
}
