package oci

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/terrabyteian/flint/internal/blob"
	"github.com/terrabyteian/flint/internal/config"
	"github.com/terrabyteian/flint/internal/meta"
	"github.com/terrabyteian/flint/internal/upstream"
)

// A proxy repository caches one upstream registry. Pulls are served from
// the cache when possible and fetched from the upstream otherwise:
//
//   - Content addressed by digest (blobs, and manifests by digest) never
//     changes, so once cached it is served forever without asking the
//     upstream.
//   - A tag is served from the cache for the repository's revalidation
//     window after the upstream last confirmed it; after that a HEAD
//     request asks the upstream for the tag's current digest, and the
//     manifest is fetched again only if it moved.
//   - When the upstream cannot be reached, the cached copy is served. A
//     tag the upstream answers is not found or denied is answered so,
//     even if it is cached.
//   - Tag listings and referrers come from the upstream, cached in memory
//     for the revalidation window, with the cached tags and referrers as
//     the fallback when the upstream cannot be reached.
//
// Cached content lives in the shared blob store, linked to the proxy
// repository with the same records hosted repositories use. A blob that
// is not cached yet streams to the client while it is written to the
// store, and concurrent requests for it share one upstream fetch (see
// upstream.Fetcher). When the data directory is nearly full, or content
// would not fit a repository's size limit, it is passed through from the
// upstream without being cached; nothing is deleted to make room, except
// by the size limit's eviction, which is opt-in.
//
// Proxy repositories are read-only: pushes and deletes are refused.

// Proxy timeouts; tests shorten them.
var (
	// revalidateTimeout bounds a tag revalidation when a cached copy
	// could be served instead.
	revalidateTimeout = 10 * time.Second
	// fetchTimeout bounds fetching a manifest or listing that is not
	// cached.
	fetchTimeout = time.Minute
)

const (
	// maxListingSize bounds an upstream tag listing or referrers index.
	maxListingSize = 16 << 20
	// maxListings bounds the in-memory cache of listings.
	maxListings = 1024
)

// Results of proxy requests, for the flint_proxy_requests_total metric.
const (
	resultHit         = "hit"         // served from the cache without asking the upstream
	resultRevalidated = "revalidated" // served after the upstream confirmed it
	resultFetched     = "fetched"     // fetched from the upstream and cached
	resultPassthrough = "passthrough" // fetched from the upstream, not cached
	resultStale       = "stale"       // served from the cache because the upstream failed
)

// errPassThrough means content must be passed through, not cached.
var errPassThrough = errors.New("oci: content passed through without caching")

// proxyRepo is the upstream side of a proxy repository.
type proxyRepo struct {
	client     *upstream.Client
	dockerHub  bool
	revalidate time.Duration
	cache      *cacheTracker // nil without a size limit
}

// dockerHubHost is the host of Docker Hub's registry API.
const dockerHubHost = "registry-1.docker.io"

func newProxyRepo(rc config.Repository, defaults upstream.Options) (*proxyRepo, error) {
	pc := rc.Proxy
	u, err := url.Parse(pc.URL)
	if err != nil {
		return nil, err
	}
	p := &proxyRepo{revalidate: pc.RevalidateAfter.Duration, dockerHub: strings.EqualFold(u.Hostname(), dockerHubHost)}
	if p.revalidate <= 0 {
		p.revalidate = config.DefaultRevalidateAfter
	}
	opts := defaults
	opts.URL = pc.URL
	opts.Username, opts.PasswordFile = pc.Username, pc.PasswordFile
	if p.client, err = upstream.New(opts); err != nil {
		return nil, err
	}
	if pc.SizeLimit.Bytes > 0 {
		p.cache = newCacheTracker(rc.Name, pc.SizeLimit.Bytes)
	}
	return p, nil
}

// upstreamName returns the upstream's name for image name. Docker Hub
// keeps official images under "library/", which clients add for a
// single-component name, so this proxy does too.
func (p *proxyRepo) upstreamName(name string) string {
	if p.dockerHub && !strings.Contains(name, "/") {
		return "library/" + name
	}
	return name
}

// proxied is a manifest resolved through a proxy repository.
type proxied struct {
	d      blob.Digest
	rec    *manifestRecord
	body   []byte // the manifest's bytes when it was not cached, else nil
	result string
}

// serveProxy routes a request to a proxy repository.
func (h *Handler) serveProxy(w http.ResponseWriter, r *http.Request, rn *repoName, ep endpoint, arg string) {
	var serve func(http.ResponseWriter, *http.Request, *repoName, string)
	switch {
	case ep == epBlob && (r.Method == http.MethodGet || r.Method == http.MethodHead):
		serve = h.proxyGetBlob
	case ep == epManifest && (r.Method == http.MethodGet || r.Method == http.MethodHead):
		serve = h.proxyGetManifest
	case ep == epTags && r.Method == http.MethodGet:
		serve = h.proxyListTags
	case ep == epReferrers && r.Method == http.MethodGet:
		serve = h.proxyListReferrers
	case ep == epTags || ep == epReferrers:
		allow(w, r, h, http.MethodGet)
		return
	default:
		allowed := "" // uploads: nothing is allowed
		if ep == epBlob || ep == epManifest {
			allowed = "GET, HEAD"
		}
		w.Header().Set("Allow", allowed)
		h.writeError(w, r, newError(http.StatusMethodNotAllowed, codeUnsupported,
			"repository %s is a read-only proxy of %s; push to a hosted repository instead", rn.repo, rn.cfg.proxy.client.URL()))
		return
	}
	if !h.auth.Authorize(w, r, rn.full, ActionPull) {
		return
	}
	serve(w, r, rn, arg)
}

// upstreamFailure turns a failed upstream request into the response
// error with upstreamError, and logs and counts the failure unless the
// upstream does not have the content. Only a cancelled ctx means the
// client went away; a ctx past its deadline is an upstream that took too
// long.
func (h *Handler) upstreamFailure(ctx context.Context, rn *repoName, err error, notFound *apiError) error {
	if errors.Is(ctx.Err(), context.Canceled) {
		return ctx.Err()
	}
	if _, ok := err.(*apiError); !ok && !errors.Is(err, upstream.ErrNotFound) {
		h.upstreamErrors.With(rn.repo).Inc()
		h.log.WarnContext(ctx, "proxy upstream request failed", "repository", rn.repo,
			"upstream", rn.cfg.proxy.client.Host(), "err", err)
	}
	return h.upstreamError(rn, err, notFound)
}

// upstreamError maps a failed upstream request to the response error:
// notFound when the upstream does not have the content or denies access
// to it, and an unavailable or bad-gateway error otherwise.
func (h *Handler) upstreamError(rn *repoName, err error, notFound *apiError) error {
	p := rn.cfg.proxy
	if _, ok := err.(*apiError); ok {
		return err
	}
	switch {
	case errors.Is(err, upstream.ErrNotFound):
		return notFound
	case errors.Is(err, upstream.ErrDenied):
		// Docker Hub, among others, denies access to names that do
		// not exist, so this is most often a typo.
		return newError(notFound.status, notFound.Code,
			"%s: the upstream registry %s denied access; the name may not exist, or may need credentials",
			notFound.Message, p.client.Host()).withDetail(notFound.Detail)
	case errors.Is(err, upstream.ErrUnavailable):
		return newError(http.StatusServiceUnavailable, codeUnavailable,
			"the upstream registry %s is unavailable, and the content is not cached", p.client.Host())
	case errors.Is(err, upstream.ErrDigestMismatch):
		return newError(http.StatusBadGateway, codeUnknown,
			"content from the upstream registry %s did not match its digest", p.client.Host())
	}
	return newError(http.StatusBadGateway, codeUnknown, "the upstream registry %s failed: %v", p.client.Host(), err)
}

// admit decides whether content of size bytes (-1 if unknown) may be
// cached in rn's repository: the data directory must have room for it,
// and it must fit the repository's size limit. If it may, release ends
// the space reservation once the content is stored.
func (h *Handler) admit(rn *repoName, size int64) (release func(), ok bool) {
	if c := rn.cfg.proxy.cache; c != nil && size > c.limit {
		return nil, false
	}
	if h.space == nil {
		return func() {}, true
	}
	return h.space.Reserve(size)
}

// proxyOrigin is the origin of a batch that caches upstream content for
// the request whose origin is who.
func proxyOrigin(who meta.Origin, target string) meta.Origin {
	who.Action, who.Target = "oci.proxy.cache", target
	return who
}

// proxyGetBlob serves GET and HEAD /v2/<name>/blobs/<digest> of a proxy
// repository.
func (h *Handler) proxyGetBlob(w http.ResponseWriter, r *http.Request, rn *repoName, arg string) {
	ctx := r.Context()
	d, err := parseDigest(arg)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	size, ok, err := h.lookupBlob(rn, d)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	if ok {
		h.touch(rn, blobKey(rn, d))
		if h.serveBlob(w, r, rn, d, size) {
			h.proxyResults.With(rn.repo, resultHit).Inc()
			return
		}
		// Linked but missing from the store: fetch it again.
	}
	p := rn.cfg.proxy
	up := p.upstreamName(rn.name)
	// The blob may be stored already, for another repository. A digest is
	// not a secret, so it is linked here only once the upstream confirms
	// that this repository has it.
	if info, err := h.blobs.Stat(ctx, d); err == nil {
		usize, err := p.client.HeadBlob(ctx, up, d)
		if err != nil {
			h.writeError(w, r, h.upstreamFailure(ctx, rn, err, blobUnknownError(d)))
			return
		}
		if usize < 0 || usize == info.Size {
			// Linking costs no space, but content over the size limit is
			// served without being linked, as if passed through.
			if c := p.cache; c == nil || info.Size <= c.limit {
				if err := h.linkProxyBlob(ctx, h.origin(r, "", ""), rn, d, info.Size); err != nil {
					h.writeError(w, r, err)
					return
				}
			}
			if h.serveBlob(w, r, rn, d, info.Size) {
				h.proxyResults.With(rn.repo, resultHit).Inc()
				return
			}
		}
	}
	if r.Method == http.MethodHead {
		usize, err := p.client.HeadBlob(ctx, up, d)
		if err != nil {
			h.writeError(w, r, h.upstreamFailure(ctx, rn, err, blobUnknownError(d)))
			return
		}
		setBlobHeaders(w, d, usize)
		w.WriteHeader(http.StatusOK)
		return
	}
	h.fetchBlob(w, r, rn, d)
}

func blobUnknownError(d blob.Digest) *apiError { return blobUnknown(d).(*apiError) }

func setBlobHeaders(w http.ResponseWriter, d blob.Digest, size int64) {
	hd := w.Header()
	hd.Set("Docker-Content-Digest", d.String())
	hd.Set("Content-Type", "application/octet-stream")
	if size >= 0 {
		hd.Set("Content-Length", strconv.FormatInt(size, 10))
	}
}

// linkProxyBlob links stored blob d, size bytes, in rn.
func (h *Handler) linkProxyBlob(ctx context.Context, who meta.Origin, rn *repoName, d blob.Digest, size int64) error {
	err := h.commitLink(ctx, []blob.Digest{d}, func(v meta.View, b *meta.Batch) error {
		b.Put(blobKey(rn, d), encodeBlobLink(size))
		b.SetOrigin(proxyOrigin(who, rn.full+"@"+d.String()))
		return nil
	}, h.statExists(ctx, d))
	if err == nil {
		h.track(rn, blobKey(rn, d), size)
	}
	return err
}

// fetchBlob fetches blob d from rn's upstream into the cache while
// streaming it to the client, sharing the fetch with concurrent requests
// for the same blob, or passes it through if it cannot be cached.
func (h *Handler) fetchBlob(w http.ResponseWriter, r *http.Request, rn *repoName, d blob.Digest) {
	ctx := r.Context()
	p := rn.cfg.proxy
	up := p.upstreamName(rn.name)
	if h.space != nil && h.space.Pressure() {
		h.passThroughBlob(w, r, rn, d)
		return
	}
	who := h.origin(r, "", "")
	var release func()
	open := func(ctx context.Context) (io.ReadCloser, int64, error) {
		body, size, err := p.client.GetBlob(ctx, up, d)
		if err != nil {
			return nil, 0, err
		}
		rel, ok := h.admit(rn, size)
		if !ok {
			body.Close()
			return nil, 0, errPassThrough
		}
		release = rel
		return body, size, nil
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
				h.upstreamErrors.With(rn.repo).Inc()
				h.log.Warn("proxy blob fetch failed", "repository", rn.full, "digest", d.String(),
					"upstream", p.client.Host(), "err", err)
			}
			return
		}
		h.upstreamBytes.With(rn.repo).Add(float64(info.Size))
		if err := h.linkProxyBlob(ctx, who, rn, d, info.Size); err != nil {
			h.log.Warn("caching a proxied blob failed", "repository", rn.full, "digest", d.String(), "err", err)
		}
	}
	fe, _ := h.fetcher.Fetch(rn.repo+"\x00"+up+"\x00"+d.String(), d, open, done)
	defer fe.Release()
	size, err := fe.Wait(ctx)
	if errors.Is(err, errPassThrough) {
		h.passThroughBlob(w, r, rn, d)
		return
	}
	if err != nil {
		// The fetch logs and counts its failure once, however many
		// clients wait on it.
		if ctx.Err() == nil {
			err = h.upstreamError(rn, err, blobUnknownError(d))
		}
		h.writeError(w, r, err)
		return
	}
	setBlobHeaders(w, d, size)
	w.WriteHeader(http.StatusOK)
	if _, err := fe.Stream(ctx, w); err != nil {
		// Part of the blob is out: cut the connection, so the client
		// cannot take it for the whole blob. The fetch logs its failure.
		panic(http.ErrAbortHandler)
	}
	h.proxyResults.With(rn.repo, resultFetched).Inc()
}

// passThroughBlob streams blob d from rn's upstream to the client without
// caching it, verifying it on the way.
func (h *Handler) passThroughBlob(w http.ResponseWriter, r *http.Request, rn *repoName, d blob.Digest) {
	ctx := r.Context()
	p := rn.cfg.proxy
	body, size, err := p.client.GetBlob(ctx, p.upstreamName(rn.name), d)
	if err != nil {
		h.writeError(w, r, h.upstreamFailure(ctx, rn, err, blobUnknownError(d)))
		return
	}
	defer body.Close()
	setBlobHeaders(w, d, size)
	w.WriteHeader(http.StatusOK)
	n, err := upstream.CopyVerified(w, upstream.NewVerifier(body, d, size))
	h.upstreamBytes.With(rn.repo).Add(float64(n))
	if err != nil {
		if ctx.Err() == nil {
			h.upstreamErrors.With(rn.repo).Inc()
			h.log.WarnContext(ctx, "passing a blob through from upstream failed", "repository", rn.full,
				"digest", d.String(), "upstream", p.client.Host(), "err", err)
		}
		panic(http.ErrAbortHandler)
	}
	h.proxyResults.With(rn.repo, resultPassthrough).Inc()
}

// proxyGetManifest serves GET and HEAD /v2/<name>/manifests/<reference>
// of a proxy repository.
func (h *Handler) proxyGetManifest(w http.ResponseWriter, r *http.Request, rn *repoName, ref string) {
	var res *proxied
	var err error
	switch {
	case strings.Contains(ref, ":"):
		var d blob.Digest
		if d, err = parseDigest(ref); err == nil {
			res, err = h.proxyManifestByDigest(r, rn, d)
		}
	case validTag(ref):
		res, err = h.proxyManifestByTag(r, rn, ref)
	default:
		err = manifestUnknown(rn, ref)
	}
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	h.proxyResults.With(rn.repo, res.result).Inc()
	if res.body == nil {
		h.touch(rn, manifestKey(rn, res.d))
	}
	h.serveManifest(w, r, rn, ref, res.d, res.rec, res.body)
}

// cachedManifest returns the record of manifest d cached in rn, or nil.
func cachedManifest(v meta.View, rn *repoName, d blob.Digest) (*manifestRecord, error) {
	rec, ok := v.Get(manifestKey(rn, d))
	if !ok {
		return nil, nil
	}
	return decodeManifest(rec.Value)
}

// proxyManifestByDigest resolves a manifest by digest: from the cache,
// or else from the upstream.
func (h *Handler) proxyManifestByDigest(r *http.Request, rn *repoName, d blob.Digest) (*proxied, error) {
	v := h.view()
	m, err := cachedManifest(v, rn, d)
	v.Release()
	if err != nil || m != nil {
		return &proxied{d: d, rec: m, result: resultHit}, err
	}
	who := h.origin(r, "", "")
	return h.manifestCalls.Do(r.Context(), rn.full+"@"+d.String(), func(ctx context.Context) (*proxied, error) {
		ctx, cancel := context.WithTimeout(ctx, fetchTimeout)
		defer cancel()
		p := rn.cfg.proxy
		um, err := p.client.GetManifest(ctx, p.upstreamName(rn.name), d.String())
		if err != nil {
			return nil, h.upstreamFailure(ctx, rn, err, manifestUnknown(rn, d.String()).(*apiError))
		}
		return h.cacheManifest(ctx, who, rn, um, "")
	})
}

// proxyManifestByTag resolves a manifest by tag: from the cache while the
// upstream confirmed the tag within the revalidation window, and from the
// upstream otherwise, falling back to the cached copy if the upstream
// cannot be reached. A tag the upstream answers is not found or denied is
// answered so.
func (h *Handler) proxyManifestByTag(r *http.Request, rn *repoName, tag string) (*proxied, error) {
	key := tagKey(rn, tag)
	var cached blob.Digest
	var crec *manifestRecord
	v := h.view()
	if rec, ok := v.Get(key); ok {
		d, err := decodeTag(rec.Value)
		if err == nil {
			crec, err = cachedManifest(v, rn, d)
		}
		if err != nil {
			v.Release()
			return nil, err
		}
		cached = d
	}
	v.Release()
	p := rn.cfg.proxy
	if crec != nil && h.validatedWithin(key, p.revalidate) {
		return &proxied{d: cached, rec: crec, result: resultHit}, nil
	}
	who := h.origin(r, "", "")
	return h.tagCalls.Do(r.Context(), string(key), func(ctx context.Context) (*proxied, error) {
		up := p.upstreamName(rn.name)
		timeout := fetchTimeout
		if crec != nil {
			timeout = revalidateTimeout
		}
		ctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		fail := func(err error) (*proxied, error) {
			if crec == nil || errors.Is(err, upstream.ErrNotFound) || errors.Is(err, upstream.ErrDenied) {
				return nil, h.upstreamFailure(ctx, rn, err, manifestUnknown(rn, tag).(*apiError))
			}
			h.upstreamErrors.With(rn.repo).Inc()
			h.log.WarnContext(ctx, "serving a cached tag the upstream could not confirm", "repository", rn.full,
				"tag", tag, "digest", cached.String(), "upstream", p.client.Host(), "err", err)
			return &proxied{d: cached, rec: crec, result: resultStale}, nil
		}
		if crec != nil {
			if p.client.Offline() {
				return &proxied{d: cached, rec: crec, result: resultStale}, nil
			}
			desc, err := p.client.HeadManifest(ctx, up, tag)
			switch {
			case err == nil && desc.Digest == cached:
				h.markValidated(key)
				return &proxied{d: cached, rec: crec, result: resultRevalidated}, nil
			case err != nil && !errors.Is(err, upstream.ErrNoDigest):
				return fail(err)
			}
			// The tag moved, or the upstream does not report digests on
			// HEAD: fetch the manifest.
		}
		um, err := p.client.GetManifest(ctx, up, tag)
		if err != nil {
			return fail(err)
		}
		res, err := h.cacheManifest(ctx, who, rn, um, tag)
		if err == nil && res.body == nil {
			h.markValidated(key)
			if crec != nil && res.d == cached {
				res.result = resultRevalidated
			}
		}
		return res, err
	})
}

// cacheManifest stores an upstream manifest in rn, and tags it if tag is
// not empty. If it cannot be cached, it is returned to be served from
// memory.
func (h *Handler) cacheManifest(ctx context.Context, who meta.Origin, rn *repoName, um *upstream.Manifest, tag string) (*proxied, error) {
	pm, err := parseManifest(um.Body, um.MediaType)
	if err != nil {
		msg := err.Error()
		if ae, ok := err.(*apiError); ok {
			msg = ae.Message
		}
		h.log.WarnContext(ctx, "the upstream returned a manifest flint cannot serve", "repository", rn.full,
			"digest", um.Digest.String(), "upstream", rn.cfg.proxy.client.Host(), "err", msg)
		return nil, newError(http.StatusBadGateway, codeUnknown, "the upstream returned a manifest flint cannot serve: %s", msg)
	}
	d := um.Digest
	rec := pm.record
	seen := map[manifestRef]bool{}
	add := func(kind refKind, ds []descriptor) {
		for _, desc := range ds {
			dg, _ := blob.ParseDigest(desc.Digest)
			if ref := (manifestRef{kind, dg}); !seen[ref] {
				seen[ref] = true
				rec.Refs = append(rec.Refs, ref)
			}
		}
	}
	add(refBlob, pm.blobs)
	add(refManifest, pm.members)
	passThrough := &proxied{d: d, rec: &rec, body: um.Body, result: resultPassthrough}

	release, ok := h.admit(rn, rec.Size)
	if !ok {
		return passThrough, nil
	}
	defer release()
	target := rn.full + "@" + d.String()
	if tag != "" {
		target = rn.full + ":" + tag + "@" + d.String()
	}
	err = h.commitLink(ctx, []blob.Digest{d}, func(v meta.View, b *meta.Batch) error {
		b.Put(manifestKey(rn, d), rec.encode())
		if !rec.Subject.IsZero() {
			b.Put(referrerKey(rn, rec.Subject, d), newEnc())
		}
		if tag != "" {
			b.Put(tagKey(rn, tag), encodeTag(d))
		}
		b.SetOrigin(proxyOrigin(who, target))
		return nil
	}, func(int) error {
		up, err := h.blobs.NewUpload(ctx)
		if err != nil {
			return err
		}
		if _, err := up.Write(um.Body); err != nil {
			up.Cancel()
			return err
		}
		_, err = up.Commit(ctx, d)
		return err
	})
	if err != nil {
		h.log.WarnContext(ctx, "caching a proxied manifest failed; serving it uncached", "repository", rn.full,
			"digest", d.String(), "err", err)
		return passThrough, nil
	}
	h.upstreamBytes.With(rn.repo).Add(float64(rec.Size))
	h.track(rn, manifestKey(rn, d), rec.Size)
	return &proxied{d: d, rec: &rec, result: resultFetched}, nil
}

// validatedWithin reports whether the upstream confirmed tag key within
// the window.
func (h *Handler) validatedWithin(key []byte, window time.Duration) bool {
	h.validatedMu.Lock()
	defer h.validatedMu.Unlock()
	t, ok := h.validated[string(key)]
	return ok && h.now().Sub(t) < window
}

func (h *Handler) markValidated(key []byte) {
	h.validatedMu.Lock()
	defer h.validatedMu.Unlock()
	h.validated[string(key)] = h.now()
}

// pruneValidated forgets confirmations older than every revalidation
// window, which no lookup would trust anyway, so the map stays as small
// as the set of recently pulled tags.
func (h *Handler) pruneValidated() {
	var window time.Duration
	for _, rc := range h.repos {
		if rc.proxy != nil {
			window = max(window, rc.proxy.revalidate)
		}
	}
	h.validatedMu.Lock()
	defer h.validatedMu.Unlock()
	now := h.now()
	for k, t := range h.validated {
		if now.Sub(t) >= window {
			delete(h.validated, k)
		}
	}
}

// listing is an upstream tag list or referrers index, cached in memory.
type listing struct {
	body    []byte
	header  http.Header
	fetched time.Time
}

// listingCache holds recently fetched listings.
type listingCache struct {
	mu sync.Mutex
	m  map[string]*listing
}

func (c *listingCache) get(key string) *listing {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.m[key]
}

func (c *listingCache) put(key string, l *listing) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m == nil {
		c.m = map[string]*listing{}
	}
	if len(c.m) >= maxListings {
		for k := range c.m { // drop an arbitrary entry
			delete(c.m, k)
			break
		}
	}
	c.m[key] = l
}

func writeListing(w http.ResponseWriter, l *listing) {
	hd := w.Header()
	for k, vs := range l.header {
		hd[k] = vs
	}
	hd.Set("Content-Length", strconv.Itoa(len(l.body)))
	w.WriteHeader(http.StatusOK)
	w.Write(l.body)
}

// fetchListing fetches an upstream API path of rn and reads the body.
func (h *Handler) fetchListing(ctx context.Context, rn *repoName, path string, q url.Values) ([]byte, http.Header, error) {
	p := rn.cfg.proxy
	ctx, cancel := context.WithTimeout(ctx, revalidateTimeout)
	defer cancel()
	resp, err := p.client.Get(ctx, p.upstreamName(rn.name), path, q)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxListingSize+1))
	if err != nil {
		return nil, nil, &upstream.Error{Op: "GET " + path, Err: errors.Join(upstream.ErrUnavailable, err)}
	}
	if len(body) > maxListingSize {
		return nil, nil, &upstream.Error{Op: "GET " + path, Err: upstream.ErrTooLarge}
	}
	return body, resp.Header, nil
}

// proxyListing serves a listing from the in-memory cache while it is
// fresh, else from the upstream through fetch, which returns the
// listing to cache and serve. If the upstream fails, it serves the
// cached listing, or else calls local. A listing the upstream answers is
// not found or denied is answered with notFound, or by local if notFound
// is nil.
func (h *Handler) proxyListing(w http.ResponseWriter, r *http.Request, rn *repoName, key string, notFound *apiError,
	fetch func(ctx context.Context) (*listing, error), local func()) {
	p := rn.cfg.proxy
	cached := h.listings.get(key)
	if cached != nil && h.now().Sub(cached.fetched) < p.revalidate {
		h.proxyResults.With(rn.repo, resultHit).Inc()
		writeListing(w, cached)
		return
	}
	if !p.client.Offline() {
		l, err := fetch(r.Context())
		switch {
		case err == nil:
			l.fetched = h.now()
			h.listings.put(key, l)
			h.proxyResults.With(rn.repo, resultRevalidated).Inc()
			writeListing(w, l)
			return
		case errors.Is(err, upstream.ErrNotFound), errors.Is(err, upstream.ErrDenied):
			if notFound != nil {
				h.writeError(w, r, h.upstreamFailure(r.Context(), rn, err, notFound))
				return
			}
			h.proxyResults.With(rn.repo, resultHit).Inc()
			local()
			return
		case r.Context().Err() != nil:
			return
		}
		h.upstreamErrors.With(rn.repo).Inc()
		h.log.WarnContext(r.Context(), "proxy listing request failed; serving the cached listing",
			"repository", rn.full, "upstream", p.client.Host(), "err", err)
	}
	h.proxyResults.With(rn.repo, resultStale).Inc()
	if cached != nil {
		writeListing(w, cached)
		return
	}
	local()
}

// proxyListTags serves GET /v2/<name>/tags/list of a proxy repository:
// the upstream's tags, or the cached ones if the upstream cannot be
// reached.
func (h *Handler) proxyListTags(w http.ResponseWriter, r *http.Request, rn *repoName, _ string) {
	if _, _, err := pageParams(r); err != nil {
		h.writeError(w, r, err)
		return
	}
	q := url.Values{}
	for _, k := range []string{"n", "last"} {
		if v := r.URL.Query().Get(k); v != "" {
			q.Set(k, v)
		}
	}
	up := rn.cfg.proxy.upstreamName(rn.name)
	notFound := newError(http.StatusNotFound, codeNameUnknown, "repository %s is not known", rn.full)
	h.proxyListing(w, r, rn, "tags\x00"+rn.full+"?"+q.Encode(), notFound, func(ctx context.Context) (*listing, error) {
		body, hdr, err := h.fetchListing(ctx, rn, "/v2/"+up+"/tags/list", q)
		if err != nil {
			return nil, err
		}
		var tl struct {
			Tags []string `json:"tags"`
		}
		if err := json.Unmarshal(body, &tl); err != nil {
			return nil, &upstream.Error{Op: "GET tags of " + up, Err: errors.New("the tag list is not valid JSON")}
		}
		if tl.Tags == nil {
			tl.Tags = []string{}
		}
		out, _ := json.Marshal(struct {
			Name string   `json:"name"`
			Tags []string `json:"tags"`
		}{rn.full, tl.Tags})
		l := &listing{body: out, header: http.Header{"Content-Type": {"application/json"}}}
		if next := nextQuery(hdr.Get("Link")); next != "" {
			l.header.Set("Link", "</v2/"+rn.full+"/tags/list?"+next+`>; rel="next"`)
		}
		return l, nil
	}, func() { h.listTags(w, r, rn, "") })
}

// nextQuery returns the query of the rel="next" URL in a Link header, or
// "" if there is none.
func nextQuery(link string) string {
	for part := range strings.SplitSeq(link, ",") {
		target, params, ok := strings.Cut(part, ";")
		if !ok || !strings.Contains(params, `rel="next"`) && !strings.Contains(params, "rel=next") {
			continue
		}
		target = strings.Trim(strings.TrimSpace(target), "<>")
		u, err := url.Parse(target)
		if err != nil {
			return ""
		}
		q := url.Values{}
		for _, k := range []string{"n", "last"} {
			if v := u.Query().Get(k); v != "" {
				q.Set(k, v)
			}
		}
		return q.Encode()
	}
	return ""
}

// proxyListReferrers serves GET /v2/<name>/referrers/<digest> of a proxy
// repository: the upstream's referrers index, or the cached referrers if
// the upstream fails or does not support the referrers API.
func (h *Handler) proxyListReferrers(w http.ResponseWriter, r *http.Request, rn *repoName, arg string) {
	d, err := parseDigest(arg)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	q := url.Values{}
	if at := r.URL.Query().Get("artifactType"); at != "" {
		q.Set("artifactType", at)
	}
	up := rn.cfg.proxy.upstreamName(rn.name)
	h.proxyListing(w, r, rn, "referrers\x00"+rn.full+"@"+d.String()+"?"+q.Encode(), nil, func(ctx context.Context) (*listing, error) {
		body, hdr, err := h.fetchListing(ctx, rn, "/v2/"+up+"/referrers/"+d.String(), q)
		if err != nil {
			return nil, err
		}
		var idx struct {
			Manifests []json.RawMessage `json:"manifests"`
		}
		if err := json.Unmarshal(body, &idx); err != nil || idx.Manifests == nil {
			return nil, &upstream.Error{Op: "GET referrers of " + up, Err: errors.New("the referrers response is not an image index")}
		}
		l := &listing{body: body, header: http.Header{"Content-Type": {mtOCIIndex}}}
		if f := hdr.Get("OCI-Filters-Applied"); f != "" {
			l.header.Set("OCI-Filters-Applied", f)
		}
		return l, nil
	}, func() { h.listReferrers(w, r, rn, arg) })
}
