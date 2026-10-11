package pypi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/terrabyteian/flint/internal/blob"
	"github.com/terrabyteian/flint/internal/config"
	"github.com/terrabyteian/flint/internal/gc"
	"github.com/terrabyteian/flint/internal/meta"
	"github.com/terrabyteian/flint/internal/upstream"
)

// A proxy repository caches one upstream index, such as pypi.org:
//
//   - A project page is served from the cache for the repository's
//     revalidation window after the upstream last confirmed it. After
//     that it is fetched again, conditionally with the upstream's ETag,
//     and stored when it changed. When the upstream cannot be reached,
//     the cached page is served; a project the upstream answers is not
//     found or denied is answered so, even if cached.
//   - Files and core-metadata files never change, so once cached they are
//     served forever without asking the upstream. They are fetched from
//     wherever the page links, often another host, and verified against
//     the sha256 digest the page gives before a client receives their
//     last byte. A file whose page gives no sha256 digest is passed
//     through without being cached. A file is fetched even when a blob
//     with its digest is stored already, for another repository: a digest
//     is not a secret, so a proxy serves only what its upstream sent it.
//
// Pages are stored in flint's own form (projectDoc) in the blob store,
// with links that point back at flint. When the data directory is nearly
// full, or a file would not fit the repository's size limit, content is
// passed through without being cached; only the size limit's eviction,
// which is opt-in, ever removes cached content.

// Proxy timeouts; tests shorten them.
var (
	// revalidateTimeout bounds a page revalidation when a cached copy
	// could be served instead.
	revalidateTimeout = 10 * time.Second
	// fetchTimeout bounds fetching a page or core-metadata file that is
	// not cached.
	fetchTimeout = time.Minute
)

// errPassThrough means content must be passed through, not cached.
var errPassThrough = errors.New("pypi: content passed through without caching")

// proxyRepo is the upstream side of a proxy repository.
type proxyRepo struct {
	client     *upstream.Client
	index      string // the simple index URL, ending in "/"
	revalidate time.Duration
	cache      *upstream.CacheTracker // nil without a size limit
}

func newProxyRepo(rc config.Repository, defaults upstream.Options) (*proxyRepo, error) {
	pc := rc.Proxy
	p := &proxyRepo{index: config.PyPIIndexURL(pc.URL), revalidate: pc.RevalidateAfter.Duration}
	if p.revalidate <= 0 {
		p.revalidate = config.DefaultRevalidateAfter
	}
	opts := defaults
	opts.URL = p.index
	opts.Username, opts.PasswordFile = pc.Username, pc.PasswordFile
	var err error
	if p.client, err = upstream.New(opts); err != nil {
		return nil, err
	}
	if pc.SizeLimit.Bytes > 0 {
		p.cache = upstream.NewCacheTracker(rc.Name, pc.SizeLimit.Bytes)
	}
	return p, nil
}

// pageResult is a project page resolved through a proxy repository.
type pageResult struct {
	doc    *projectDoc
	result string // upstream.ResultHit and so on
}

// cachedPage returns the record of rp's cached page of project, or nil.
func (h *Handler) cachedPage(rp *repository, project string) (*pageRecord, error) {
	v := h.view()
	defer v.Release()
	rec, ok := v.Get(pageKey(rp.name, project))
	if !ok {
		return nil, nil
	}
	return decodePage(rec.Value)
}

// proxyProject returns rp's page of project: from the cache while the
// upstream confirmed it within the revalidation window, and from the
// upstream otherwise, falling back to the cached page if the upstream
// cannot be reached.
func (h *Handler) proxyProject(ctx context.Context, actor string, rp *repository, project string) (*pageResult, error) {
	p := rp.proxy
	fk := rp.name + "\x00" + project
	cached, err := h.cachedPage(rp, project)
	if err != nil {
		return nil, err
	}
	if cached != nil && h.fresh.Fresh(fk, p.revalidate) {
		if doc, err := h.loadPage(ctx, rp, cached); err == nil {
			return &pageResult{doc, upstream.ResultHit}, nil
		}
	}
	return h.pageCalls.Do(ctx, fk, func(gctx context.Context) (*pageResult, error) {
		timeout := fetchTimeout
		if cached != nil {
			timeout = revalidateTimeout
		}
		ctx, cancel := context.WithTimeout(gctx, timeout)
		defer cancel()
		stale := func(cause error) (*pageResult, error) {
			doc, err := h.loadPage(gctx, rp, cached)
			if err != nil {
				return nil, h.upstreamFailure(gctx, rp, "project "+project, cause)
			}
			return &pageResult{doc, upstream.ResultStale}, nil
		}
		if cached != nil && p.client.Offline() {
			return stale(&upstream.Error{Op: "GET " + project, Err: upstream.ErrUnavailable})
		}
		etag := ""
		if cached != nil {
			etag = cached.ETag
		}
		doc, tag, notModified, err := h.fetchPage(ctx, rp, project, etag)
		if err == nil && notModified {
			if doc, err := h.loadPage(ctx, rp, cached); err == nil {
				h.fresh.Confirm(fk)
				return &pageResult{doc, upstream.ResultRevalidated}, nil
			}
			doc, tag, _, err = h.fetchPage(ctx, rp, project, "")
		}
		if err != nil {
			if cached == nil || upstream.Answered(err) {
				return nil, h.upstreamFailure(ctx, rp, "project "+project, err)
			}
			h.pm.UpstreamErrors.With(rp.name).Inc()
			h.log.WarnContext(ctx, "serving a cached project page the upstream could not confirm", "repository", rp.name,
				"project", project, "upstream", p.client.Host(), "err", err)
			return stale(err)
		}
		result := upstream.ResultFetched
		if cached != nil && blob.FromBytes(mustJSON(doc)) == cached.Digest {
			result = upstream.ResultRevalidated
		}
		// Only a page now in the cache counts as confirmed; one that
		// could not be stored is fetched again next time, rather than the
		// older cached page being served for a whole window.
		if h.storePage(ctx, actor, rp, project, doc, tag, cached) {
			h.fresh.Confirm(fk)
		}
		return &pageResult{doc, result}, nil
	})
}

// fetchPage fetches rp's upstream page of project, conditionally on etag
// if it is not empty; notModified reports a 304 answer.
func (h *Handler) fetchPage(ctx context.Context, rp *repository, project, etag string) (doc *projectDoc, tag string, notModified bool, err error) {
	p := rp.proxy
	hdr := http.Header{"Accept": {upstreamAccept}}
	if etag != "" {
		hdr.Set("If-None-Match", etag)
	}
	resp, err := p.client.GetURL(ctx, p.index+project+"/", hdr)
	if err != nil {
		return nil, "", false, err
	}
	defer resp.Body.Close()
	op := "GET " + p.index + project + "/"
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotModified:
		return nil, etag, true, nil
	default:
		return nil, "", false, &upstream.Error{Op: op, Status: resp.StatusCode, Err: errors.New("unexpected status " + resp.Status)}
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxPageSize+1))
	if err != nil {
		return nil, "", false, &upstream.Error{Op: op, Err: errors.Join(upstream.ErrUnavailable, err)}
	}
	if len(body) > maxPageSize {
		return nil, "", false, &upstream.Error{Op: op, Err: upstream.ErrTooLarge}
	}
	doc, err = parsePage(body, resp.Header.Get("Content-Type"), resp.Request.URL, project)
	if err != nil {
		return nil, "", false, &upstream.Error{Op: op, Err: err}
	}
	for _, f := range doc.Files {
		f.src = rp
	}
	return doc, resp.Header.Get("ETag"), false, nil
}

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

// storePage caches a project page fetched from the upstream, unless it is
// unchanged, and reports whether the cache now holds it. A page that
// cannot be stored is still served.
func (h *Handler) storePage(ctx context.Context, actor string, rp *repository, project string, doc *projectDoc, etag string, cached *pageRecord) bool {
	body := mustJSON(doc)
	d := blob.FromBytes(body)
	if cached != nil && cached.Digest == d && cached.ETag == etag {
		return true
	}
	release, ok := h.reserve(int64(len(body)))
	if !ok {
		return false
	}
	defer release()
	if _, err := h.putBlob(ctx, body); err != nil {
		h.log.WarnContext(ctx, "caching a project page failed", "repository", rp.name, "project", project, "err", err)
		return false
	}
	rec := &pageRecord{Digest: d, Size: int64(len(body)), ETag: etag, Fetched: h.now().UTC()}
	err := h.commitLink(ctx, []blob.Digest{d}, func(v meta.View, b *meta.Batch) {
		b.Put(pageKey(rp.name, project), rec.encode())
		b.SetOrigin(meta.Origin{Actor: actor, Action: "pypi.proxy.cache", Target: rp.name + "/" + project})
	})
	if err != nil {
		h.log.WarnContext(ctx, "caching a project page failed", "repository", rp.name, "project", project, "err", err)
		return false
	}
	h.pm.UpstreamBytes.With(rp.name).Add(float64(len(body)))
	h.pages.put(rp.name+"\x00"+d.String(), doc, rec.Size)
	return true
}

// loadPage reads a cached project page.
func (h *Handler) loadPage(ctx context.Context, rp *repository, rec *pageRecord) (*projectDoc, error) {
	if rec == nil {
		return nil, errors.New("pypi: no cached page")
	}
	ck := rp.name + "\x00" + rec.Digest.String()
	if doc := h.pages.get(ck); doc != nil {
		return doc, nil
	}
	f, err := h.blobs.Open(ctx, rec.Digest)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var doc projectDoc
	if err := json.NewDecoder(io.LimitReader(f, maxPageSize)).Decode(&doc); err != nil {
		return nil, err
	}
	if doc.Format != pageFormat {
		return nil, errors.New("pypi: a cached page has an unknown format")
	}
	for _, f := range doc.Files {
		f.src = rp
	}
	h.pages.put(ck, &doc, rec.Size)
	return &doc, nil
}

// commitLink commits a batch that links the blobs ds, under the
// garbage-collection precondition, retrying when a precondition fails.
func (h *Handler) commitLink(ctx context.Context, ds []blob.Digest, build func(v meta.View, b *meta.Batch)) error {
	for attempt := 0; ; attempt++ {
		v := h.view()
		var b meta.Batch
		err := gc.Guard(v, &b, ds...)
		if err == nil {
			build(v, &b)
		}
		v.Release()
		if err == nil {
			err = h.statBlobs(ctx, ds...)
		}
		if err == nil {
			_, err = h.meta.Commit(ctx, &b)
		}
		switch {
		case err == nil:
			return nil
		case errors.Is(err, meta.ErrConflict) && attempt < maxLinkAttempts-1:
		case errors.Is(err, meta.ErrConflict), errors.Is(err, gc.ErrDoomed):
			return errRetry
		default:
			return err
		}
	}
}

// reserve reserves room for n bytes of new cached content in the data
// directory, if it has room.
func (h *Handler) reserve(n int64) (release func(), ok bool) {
	if h.space == nil {
		return func() {}, true
	}
	return h.space.Reserve(n)
}

// admit decides whether content of size bytes (-1 if unknown) may be
// cached in rp: the data directory must have room for it, and it must fit
// the repository's size limit.
func (h *Handler) admit(rp *repository, size int64) (release func(), ok bool) {
	if c := rp.proxy.cache; c != nil && size > c.Limit() {
		return nil, false
	}
	return h.reserve(size)
}

// upstreamFailure turns a failed upstream request about what into the
// response error, and logs and counts it unless the upstream does not
// have the content.
func (h *Handler) upstreamFailure(ctx context.Context, rp *repository, what string, err error) error {
	if _, ok := err.(*httpError); ok {
		return err
	}
	if !errors.Is(err, upstream.ErrNotFound) {
		h.pm.UpstreamErrors.With(rp.name).Inc()
		h.log.WarnContext(ctx, "proxy upstream request failed", "repository", rp.name,
			"upstream", rp.proxy.client.Host(), "err", err)
	}
	return h.upstreamError(rp, what, err)
}

// upstreamError maps a failed upstream request about what to the
// response error.
func (h *Handler) upstreamError(rp *repository, what string, err error) error {
	host := rp.proxy.client.Host()
	switch {
	case errors.Is(err, upstream.ErrNotFound):
		return errorf(http.StatusNotFound, "%s is not found", what)
	case errors.Is(err, upstream.ErrDenied):
		return errorf(http.StatusNotFound, "%s is not found: the upstream index %s denied access; it may not exist, or may need credentials", what, host)
	case errors.Is(err, upstream.ErrUnavailable):
		return errorf(http.StatusServiceUnavailable, "the upstream index %s is unavailable, and %s is not cached", host, what)
	case errors.Is(err, upstream.ErrAuth):
		return errorf(http.StatusBadGateway, "flint could not authenticate to the upstream index %s, and %s is not cached", host, what)
	case errors.Is(err, upstream.ErrDigestMismatch):
		return errorf(http.StatusBadGateway, "%s from the upstream index %s did not match its sha256 digest", what, host)
	}
	return errorf(http.StatusBadGateway, "the upstream index %s failed: %v", host, err)
}

// cachedBlob returns the blob a proxy repository cached under key k, a
// file record of project or, if metadata, a core-metadata record.
func (h *Handler) cachedBlob(k []byte, project string, metadata bool) (blob.Digest, int64, bool) {
	v := h.view()
	defer v.Release()
	rec, ok := v.Get(k)
	if !ok {
		return blob.Digest{}, 0, false
	}
	if metadata {
		b, err := decodeBlobRecord(rec.Value)
		return b.Digest, b.Size, err == nil
	}
	f, err := decodeFile(rec.Value)
	if err != nil || f.Kind != kindCached || f.Project != project {
		return blob.Digest{}, 0, false
	}
	return f.Digest, f.Size, true
}

// proxyFile serves a file of a proxy repository: from the cache, or else
// fetched from the upstream while it streams to the client. f is the
// file's page entry if the caller has it.
func (h *Handler) proxyFile(w http.ResponseWriter, r *http.Request, rp *repository, project, filename string, f *file) {
	ctx := r.Context()
	fk := fileKey(rp.name, filename)
	if d, size, ok := h.cachedBlob(fk, project, false); ok {
		h.touch(rp, fk)
		if h.serveBlob(w, r, d, size, filename) {
			h.pm.Requests.With(rp.name, upstream.ResultHit).Inc()
			return
		}
		// Linked but missing from the store: fetch it again.
	}
	if f == nil {
		res, err := h.proxyProject(ctx, h.actor(r), rp, project)
		if err != nil {
			h.fail(w, r, err)
			return
		}
		if f = res.doc.find(filename); f == nil {
			writeError(w, http.StatusNotFound, "%s is not a file of project %s", filename, project)
			return
		}
	}
	if f.SHA256 == "" {
		h.passThrough(w, r, rp, f.URL, blob.Digest{}, f.Size, filename)
		return
	}
	d, _ := blob.ParseDigest("sha256:" + f.SHA256)
	if r.Method == http.MethodHead {
		setFileHeaders(w, f.SHA256, filename)
		if f.Size >= 0 {
			w.Header().Set("Content-Length", strconv.FormatInt(f.Size, 10))
		}
		w.WriteHeader(http.StatusOK)
		return
	}
	if h.space != nil && h.space.Pressure() {
		h.passThrough(w, r, rp, f.URL, d, f.Size, filename)
		return
	}
	h.fetchFile(w, r, rp, project, filename, f, d)
}

// linkCached records blob d, size bytes, as rp's cached copy of a file of
// project, or of its core-metadata file.
func (h *Handler) linkCached(ctx context.Context, actor string, rp *repository, project, filename string, metadata bool, d blob.Digest, size int64) error {
	k := fileKey(rp.name, filename)
	rec := (&fileRecord{Kind: kindCached, Project: project, Digest: d, Size: size}).encode()
	target := rp.name + "/" + project + "/" + filename
	if metadata {
		k = metadataKey(rp.name, filename)
		rec = (&blobRecord{Digest: d, Size: size}).encode()
		target += ".metadata"
	}
	err := h.commitLink(ctx, []blob.Digest{d}, func(v meta.View, b *meta.Batch) {
		b.Put(k, rec)
		b.SetOrigin(meta.Origin{Actor: actor, Action: "pypi.proxy.cache", Target: target})
	})
	if err == nil {
		h.track(rp, k, size)
	}
	return err
}

// fetchFile fetches file f into the cache while streaming it to the
// client, sharing the fetch with concurrent requests for it, or passes it
// through if it cannot be cached.
func (h *Handler) fetchFile(w http.ResponseWriter, r *http.Request, rp *repository, project, filename string, f *file, d blob.Digest) {
	ctx := r.Context()
	p := rp.proxy
	actor := h.actor(r)
	var release func()
	open := func(ctx context.Context) (io.ReadCloser, int64, error) {
		resp, err := p.client.GetURL(ctx, f.URL, nil)
		if err != nil {
			return nil, 0, err
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return nil, 0, &upstream.Error{Op: "GET " + f.URL, Status: resp.StatusCode, Err: errors.New("unexpected status " + resp.Status)}
		}
		rel, ok := h.admit(rp, resp.ContentLength)
		if !ok {
			resp.Body.Close()
			return nil, 0, errPassThrough
		}
		release = rel
		return resp.Body, resp.ContentLength, nil
	}
	done := func(ctx context.Context, info blob.Info, err error) {
		if release != nil {
			release()
		}
		if err != nil {
			if errors.Is(err, upstream.ErrUnavailable) {
				p.client.MarkOffline()
			}
			if !errors.Is(err, errPassThrough) && !errors.Is(err, upstream.ErrNotFound) {
				h.pm.UpstreamErrors.With(rp.name).Inc()
				h.log.Warn("proxy file fetch failed", "repository", rp.name, "file", filename,
					"upstream", f.URL, "err", err)
			}
			return
		}
		h.pm.UpstreamBytes.With(rp.name).Add(float64(info.Size))
		if err := h.linkCached(ctx, actor, rp, project, filename, false, d, info.Size); err != nil {
			h.log.Warn("caching a proxied file failed", "repository", rp.name, "file", filename, "err", err)
		}
	}
	fe, _ := h.fetcher.Fetch("pypi\x00"+rp.name+"\x00"+d.String(), d, open, done)
	defer fe.Release()
	size, err := fe.Wait(ctx)
	if errors.Is(err, errPassThrough) {
		h.passThrough(w, r, rp, f.URL, d, f.Size, filename)
		return
	}
	if err != nil {
		if ctx.Err() == nil {
			err = h.upstreamError(rp, filename, err)
		}
		h.fail(w, r, err)
		return
	}
	setFileHeaders(w, f.SHA256, filename)
	if size >= 0 {
		w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
	}
	w.WriteHeader(http.StatusOK)
	if _, err := fe.Stream(ctx, w); err != nil {
		// Part of the file is out: cut the connection, so the client
		// cannot take it for the whole file. The fetch logs its failure.
		panic(http.ErrAbortHandler)
	}
	h.pm.Requests.With(rp.name, upstream.ResultFetched).Inc()
}

// passThrough streams upstream content to the client without caching it,
// verifying it against d unless d is zero.
func (h *Handler) passThrough(w http.ResponseWriter, r *http.Request, rp *repository, rawURL string, d blob.Digest, size int64, filename string) {
	ctx := r.Context()
	p := rp.proxy
	resp, err := p.client.GetURL(ctx, rawURL, nil)
	if err == nil && resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		err = &upstream.Error{Op: "GET " + rawURL, Status: resp.StatusCode, Err: errors.New("unexpected status " + resp.Status)}
	}
	if err != nil {
		h.fail(w, r, h.upstreamFailure(ctx, rp, filename, err))
		return
	}
	defer resp.Body.Close()
	if size < 0 {
		size = resp.ContentLength
	}
	sha := ""
	if !d.IsZero() {
		sha = d.Hex()
	}
	setFileHeaders(w, sha, filename)
	if size >= 0 {
		w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
	}
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodHead {
		return
	}
	var n int64
	if d.IsZero() {
		n, err = io.Copy(w, resp.Body)
	} else {
		n, err = upstream.CopyVerified(w, upstream.NewVerifier(resp.Body, d, size))
	}
	h.pm.UpstreamBytes.With(rp.name).Add(float64(n))
	if err != nil {
		if ctx.Err() == nil {
			h.pm.UpstreamErrors.With(rp.name).Inc()
			h.log.WarnContext(ctx, "passing a file through from upstream failed", "repository", rp.name,
				"file", filename, "upstream", rawURL, "err", err)
		}
		panic(http.ErrAbortHandler)
	}
	h.pm.Requests.With(rp.name, upstream.ResultPassthrough).Inc()
}

// proxyMetadata serves the core-metadata file of a proxy repository's
// file: from the cache, or else fetched from the upstream, verified, and
// cached.
func (h *Handler) proxyMetadata(w http.ResponseWriter, r *http.Request, rp *repository, project, filename string, f *file) {
	ctx := r.Context()
	mk := metadataKey(rp.name, filename)
	if d, size, ok := h.cachedBlob(mk, project, true); ok {
		h.touch(rp, mk)
		if h.serveBlob(w, r, d, size, filename+".metadata") {
			h.pm.Requests.With(rp.name, upstream.ResultHit).Inc()
			return
		}
	}
	if f == nil {
		res, err := h.proxyProject(ctx, h.actor(r), rp, project)
		if err != nil {
			h.fail(w, r, err)
			return
		}
		f = res.doc.find(filename)
	}
	if f == nil || !f.Metadata {
		writeError(w, http.StatusNotFound, "%s has no core-metadata file", filename)
		return
	}
	u, err := url.Parse(f.URL)
	if err != nil {
		writeError(w, http.StatusNotFound, "%s has no core-metadata file", filename)
		return
	}
	u.Path += ".metadata"
	u.RawPath = ""
	if f.MetadataSHA256 == "" {
		h.passThrough(w, r, rp, u.String(), blob.Digest{}, -1, filename+".metadata")
		return
	}
	d, _ := blob.ParseDigest("sha256:" + f.MetadataSHA256)
	body, err := h.fetchMetadata(ctx, h.actor(r), rp, project, filename, u.String(), d)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	setFileHeaders(w, d.Hex(), filename+".metadata")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		w.Write(body)
	}
}

// fetchMetadata returns a core-metadata file, digest d, fetched from
// rawURL, verified, and cached if it may be.
func (h *Handler) fetchMetadata(ctx context.Context, actor string, rp *repository, project, filename, rawURL string, d blob.Digest) ([]byte, error) {
	mk := metadataKey(rp.name, filename)
	body, err := h.metaCalls.Do(ctx, string(mk), func(ctx context.Context) ([]byte, error) {
		ctx, cancel := context.WithTimeout(ctx, fetchTimeout)
		defer cancel()
		p := rp.proxy
		resp, err := p.client.GetURL(ctx, rawURL, nil)
		if err == nil && resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			err = &upstream.Error{Op: "GET " + rawURL, Status: resp.StatusCode, Err: errors.New("unexpected status " + resp.Status)}
		}
		if err != nil {
			return nil, h.upstreamFailure(ctx, rp, filename+".metadata", err)
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(io.LimitReader(resp.Body, maxMetadataSize+1))
		if err != nil {
			return nil, h.upstreamFailure(ctx, rp, filename+".metadata", &upstream.Error{Op: "GET " + rawURL, Err: errors.Join(upstream.ErrUnavailable, err)})
		}
		if len(body) > maxMetadataSize || blob.FromBytes(body) != d {
			return nil, h.upstreamFailure(ctx, rp, filename+".metadata", &upstream.Error{Op: "GET " + rawURL, Err: upstream.ErrDigestMismatch})
		}
		h.pm.UpstreamBytes.With(rp.name).Add(float64(len(body)))
		if release, ok := h.admit(rp, int64(len(body))); ok {
			_, err := h.putBlob(ctx, body)
			if err == nil {
				err = h.linkCached(ctx, actor, rp, project, filename, true, d, int64(len(body)))
			}
			release()
			if err != nil {
				h.log.WarnContext(ctx, "caching a core-metadata file failed", "repository", rp.name, "file", filename, "err", err)
			}
		}
		return body, nil
	})
	if err == nil {
		h.pm.Requests.With(rp.name, upstream.ResultFetched).Inc()
	}
	return body, err
}

// pageCache keeps recently used cached project pages decoded, by
// repository and page digest, up to a total of maxPageCache bytes of
// page blobs. Pages are content-addressed, so an entry never goes stale.
type pageCache struct {
	mu    sync.Mutex
	m     map[string]*pageEntry
	total int64
	tick  uint64
}

type pageEntry struct {
	doc  *projectDoc
	size int64
	used uint64
}

const maxPageCache = 64 << 20

func (c *pageCache) get(k string) *projectDoc {
	c.mu.Lock()
	defer c.mu.Unlock()
	e := c.m[k]
	if e == nil {
		return nil
	}
	c.tick++
	e.used = c.tick
	return e.doc
}

func (c *pageCache) put(k string, doc *projectDoc, size int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m == nil {
		c.m = map[string]*pageEntry{}
	}
	if old := c.m[k]; old != nil {
		c.total -= old.size
	}
	c.tick++
	c.m[k] = &pageEntry{doc: doc, size: size, used: c.tick}
	c.total += size
	for c.total > maxPageCache && len(c.m) > 1 {
		var oldest string
		var used uint64
		for k, e := range c.m {
			if oldest == "" || e.used < used {
				oldest, used = k, e.used
			}
		}
		c.total -= c.m[oldest].size
		delete(c.m, oldest)
	}
}
