package maven

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/terrabyteian/flint/internal/blob"
	"github.com/terrabyteian/flint/internal/config"
	"github.com/terrabyteian/flint/internal/upstream"
)

// A proxy repository caches one upstream Maven repository, such as Maven
// Central, on the shared path-cache engine:
//
//   - Artifact files (jars, POMs, Gradle module files, signatures, and
//     timestamped snapshot files) never change, so they are cached
//     forever. Each is verified before it is cached, and before a client
//     receives its last byte, against the checksum the upstream announces
//     in an X-Checksum-SHA1 header, as Maven Central does, or else the
//     strongest checksum sidecar it serves (.sha512, .sha256, .sha1, then
//     .md5). A file the upstream offers no checksum for is passed through
//     without being cached. md5, sha1, and sha512 are computed while the
//     file is cached, so its sidecars are served from flint's own
//     digests.
//   - maven-metadata.xml is a mutable document, kept by the shared
//     document cache and revalidated after the repository's window; its
//     sidecars are computed from the copy flint serves.
//   - Non-unique snapshot files and paths outside the layout are passed
//     through without being cached; directory listings are not served.
//
// Upstream not-found answers are remembered briefly, because builds probe
// several repositories for every artifact.

// proxyRepo is the upstream side of a proxy repository.
type proxyRepo struct {
	pr   *upstream.PathRepo
	base string // the upstream repository's URL, ending in "/"
	// checks fetches checksum sidecars while a file's response is open.
	// It is a client of its own, with its own concurrency bound, so a
	// sidecar never waits for a slot that a file it verifies holds.
	checks *upstream.Client
	// alg is the sidecar algorithm the upstream last served, tried first.
	alg atomic.Value // string
}

// formatHosts are the hosts well-known upstreams redirect files to.
var formatHosts = map[string][]string{
	"plugins.gradle.org": {"plugins-artifacts.gradle.org"},
	"maven.google.com":   {"dl.google.com"},
}

func newProxyRepo(rc config.Repository, defaults upstream.Options) (*proxyRepo, error) {
	pc := rc.Proxy
	p := &proxyRepo{base: strings.TrimRight(pc.URL, "/") + "/"}
	u, err := url.Parse(p.base)
	if err != nil {
		return nil, err
	}
	opts := defaults
	opts.URL = p.base
	opts.Username, opts.PasswordFile = pc.Username, pc.PasswordFile
	opts.MaxConcurrent = pc.MaxConcurrent
	opts.Policy = upstream.Policy{AllowHosts: pc.AllowHosts, FormatHosts: formatHosts[strings.ToLower(u.Hostname())]}
	client, err := upstream.New(opts)
	if err != nil {
		return nil, err
	}
	if p.checks, err = upstream.New(opts); err != nil {
		return nil, err
	}
	revalidate := pc.RevalidateAfter.Duration
	if revalidate <= 0 {
		revalidate = config.DefaultRevalidateAfter
	}
	p.pr = &upstream.PathRepo{Name: rc.Name, Format: config.FormatMaven, Client: client, Revalidate: revalidate,
		SizeLimit: pc.SizeLimit.Bytes, WriteError: writeProxyError}
	return p, nil
}

// serveProxy answers a GET or HEAD request of a proxy repository.
func (h *Handler) serveProxy(w http.ResponseWriter, r *http.Request, rp *repository, mp *mpath) {
	p := rp.proxy
	actor := h.actor(r)
	switch mp.kind {
	case kindMetadata:
		md, err := h.proxyDocument(r.Context(), actor, rp, mp.path)
		if err != nil {
			h.proxyFail(w, r, rp, mp.path, err)
			return
		}
		serveDocument(w, r, md.b)
	case kindSidecar:
		switch mp.target.kind {
		case kindMetadata:
			md, err := h.proxyDocument(r.Context(), actor, rp, mp.target.path)
			if err != nil {
				h.proxyFail(w, r, rp, mp.path, err)
				return
			}
			serveDocumentChecksum(w, r, md.b, mp.alg)
		case kindFile:
			rec, err := h.pc.Lookup(p.pr, mp.target.path)
			if err != nil {
				h.fail(w, r, err)
				return
			}
			if rec != nil {
				serveChecksum(w, r, cachedDigests(rec).get(mp.alg))
				return
			}
			h.passThrough(w, r, rp, mp.path, actor)
		default:
			h.passThrough(w, r, rp, mp.path, actor)
		}
	case kindFile:
		if mp.c.NonUnique {
			h.passThrough(w, r, rp, mp.path, actor)
			return
		}
		rec, err := h.pc.Lookup(p.pr, mp.path)
		if err != nil {
			h.fail(w, r, err)
			return
		}
		if rec != nil {
			cachedDigests(rec).setHeaders(w)
		}
		h.pc.Serve(w, r, p.pr, &upstream.Route{
			Kind:        upstream.Immutable,
			Path:        mp.path,
			URL:         p.base + mp.path,
			ContentType: contentType(mp.path),
			Expect: upstream.Expect{Size: -1, Compute: []string{upstream.MD5, upstream.SHA1, upstream.SHA512},
				FromResponse: p.verifier(mp.path)},
		}, actor)
	default:
		if mp.path == "" || strings.HasSuffix(mp.path, "/") {
			writeError(w, http.StatusNotFound, "directory listings are not served")
			return
		}
		h.passThrough(w, r, rp, mp.path, actor)
	}
}

// passThrough answers a request with the upstream's answer, without
// caching it.
func (h *Handler) passThrough(w http.ResponseWriter, r *http.Request, rp *repository, path, actor string) {
	h.pc.Serve(w, r, rp.proxy.pr, &upstream.Route{Kind: upstream.PassThrough, Path: path, URL: rp.proxy.base + path}, actor)
}

// cachedDigests are a cached file's digests.
func cachedDigests(rec *upstream.FileRecord) digests {
	sum, _ := hex.DecodeString(rec.Digest.Hex())
	return digests{md5: rec.Sums[upstream.MD5], sha1: rec.Sums[upstream.SHA1], sha256: sum, sha512: rec.Sums[upstream.SHA512]}
}

// proxyFail answers a failed proxy request.
func (h *Handler) proxyFail(w http.ResponseWriter, r *http.Request, rp *repository, path string, err error) {
	if r.Context().Err() != nil {
		return
	}
	var he *httpError
	if errors.As(err, &he) {
		h.fail(w, r, err)
		return
	}
	status, msg := upstream.StatusOf(err, rp.proxy.pr.Client.Host())
	if status == http.StatusNotFound && !errors.Is(err, upstream.ErrDenied) {
		msg = path + " is not found"
	}
	writeError(w, status, "%s", msg)
}

// verifier returns the Expect.FromResponse of a file: the checksum the
// upstream announces in X-Checksum-SHA1, or else one from a sidecar.
func (p *proxyRepo) verifier(path string) func(context.Context, http.Header) (upstream.Sums, error) {
	return func(ctx context.Context, hd http.Header) (upstream.Sums, error) {
		if sum, err := hex.DecodeString(strings.TrimSpace(hd.Get("X-Checksum-SHA1"))); err == nil && len(sum) == sha1.Size {
			return upstream.Sums{upstream.SHA1: sum}, nil
		}
		return p.sidecarSums(ctx, path)
	}
}

// sidecarSums returns the strongest checksum the upstream serves a
// sidecar of for path, trying the algorithm it last served first, or
// ErrUnverifiable if it serves none.
func (p *proxyRepo) sidecarSums(ctx context.Context, path string) (upstream.Sums, error) {
	order := sidecarAlgs
	if last, _ := p.alg.Load().(string); last != "" && last != order[0] {
		order = append([]string{last}, slices.DeleteFunc(slices.Clone(order), func(a string) bool { return a == last })...)
	}
	for _, alg := range order {
		sum, err := p.fetchSidecar(ctx, path, alg)
		switch {
		case err == nil:
			p.alg.Store(alg)
			return upstream.Sums{sumsAlg(alg): sum}, nil
		case !errors.Is(err, upstream.ErrNotFound) && !errors.Is(err, upstream.ErrDenied):
			return nil, err
		}
	}
	return nil, upstream.ErrUnverifiable
}

// sumsAlg is the upstream.Sums algorithm of a sidecar algorithm.
func sumsAlg(alg string) string {
	switch alg {
	case algMD5:
		return upstream.MD5
	case algSHA1:
		return upstream.SHA1
	case algSHA256:
		return upstream.SHA256
	}
	return upstream.SHA512
}

// fetchSidecar fetches and parses the upstream's checksum sidecar of
// algorithm alg for path.
func (p *proxyRepo) fetchSidecar(ctx context.Context, path, alg string) ([]byte, error) {
	u := p.base + path + "." + alg
	resp, err := p.checks.GetURL(ctx, u, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxChecksum+1))
	if err != nil {
		return nil, &upstream.Error{Op: "GET " + u, Err: errors.Join(upstream.ErrUnavailable, err)}
	}
	sum, ok := parseChecksum(b, len(digestsOf(nil).get(alg)))
	if len(b) > maxChecksum || !ok {
		return nil, &upstream.Error{Op: "GET " + u, Err: errors.Join(upstream.ErrDigestMismatch, errors.New("the upstream's checksum sidecar is malformed"))}
	}
	return sum, nil
}

// memoDoc is an upstream maven-metadata.xml document, read.
type memoDoc struct {
	b []byte
	m *metadataXML
}

// proxyDocument returns the maven-metadata.xml at path of proxy
// repository rp, through the shared document cache: from the cache while
// the upstream confirmed it within the revalidation window, and from the
// upstream otherwise, falling back to the cached copy if the upstream
// cannot be reached. A document flint cannot read never replaces the
// cached one.
func (h *Handler) proxyDocument(ctx context.Context, actor string, rp *repository, path string) (*memoDoc, error) {
	p := rp.proxy
	nk := rp.name + "\x00" + path
	if known, _ := h.neg.Known(nk); known {
		return nil, &upstream.Error{Op: "GET " + p.base + path, Status: http.StatusNotFound, Err: upstream.ErrNotFound}
	}
	d, err := h.docs.Get(ctx, &upstream.DocRequest{
		Repo:       rp.name,
		Key:        path,
		Client:     p.pr.Client,
		URL:        p.base + path,
		Revalidate: p.pr.Revalidate,
		MaxSize:    maxMetadata,
		MaxMemory:  maxMetadata,
		Actor:      actor,
		Action:     config.FormatMaven + ".proxy.cache",
		Validate: func(ctx context.Context, d *upstream.Doc) error {
			_, err := h.readDocument(ctx, d)
			return err
		},
	})
	if err != nil {
		if errors.Is(err, upstream.ErrNotFound) {
			h.neg.Remember(nk, false, upstream.DefaultNotFoundTTL)
		} else if ctx.Err() == nil {
			h.log.WarnContext(ctx, "proxy upstream request failed", "repository", rp.name, "path", path,
				"upstream", p.pr.Client.Host(), "err", err)
		}
		return nil, err
	}
	h.pm.Requests.With(rp.name, d.Result).Inc()
	return h.readDocument(ctx, d)
}

// readDocument reads a document the document cache resolved, keeping it
// in memory by its digest.
func (h *Handler) readDocument(ctx context.Context, d *upstream.Doc) (*memoDoc, error) {
	if md := h.docMemo.get(d.Digest); md != nil {
		return md, nil
	}
	f, err := h.docs.Open(ctx, d)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxMetadata+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxMetadata {
		return nil, &upstream.Error{Op: "GET " + d.URL, Err: upstream.ErrTooLarge}
	}
	m, err := parseMetadata(b)
	if err != nil {
		return nil, &upstream.Error{Op: "GET " + d.URL, Err: err}
	}
	md := &memoDoc{b: b, m: m}
	h.docMemo.put(d.Digest, md)
	return md, nil
}

// docMemo keeps read documents in memory by their digest, which never go
// stale, within a budget.
type docMemo struct {
	mu   sync.Mutex
	docs map[blob.Digest]*memoDoc
	size int
}

// docMemoBudget bounds the bytes of documents a docMemo keeps.
const docMemoBudget = 32 << 20

func (c *docMemo) get(d blob.Digest) *memoDoc {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.docs[d]
}

func (c *docMemo) put(d blob.Digest, md *memoDoc) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.size+len(md.b) > docMemoBudget {
		// Start over: the documents in use are read again once.
		c.docs, c.size = nil, 0
	}
	if c.docs == nil {
		c.docs = map[blob.Digest]*memoDoc{}
	}
	if _, ok := c.docs[d]; !ok {
		c.docs[d] = md
		c.size += len(md.b)
	}
}

// RunProxy does the proxy repositories' background work until ctx is
// done: it persists the last-pull times of size-limited repositories,
// evicts files over their limits, and forgets expired not-found answers;
// and with a document cache of its own, prunes its confirmations.
func (h *Handler) RunProxy(ctx context.Context) {
	var wg sync.WaitGroup
	if h.ownDocs {
		wg.Go(func() { h.docs.Run(ctx, h.maxWin) })
	}
	wg.Go(func() { h.pc.Run(ctx) })
	wg.Go(func() {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				h.neg.Prune()
			}
		}
	})
	wg.Wait()
}

// FlushPullTimes persists the last-pull times recorded since the last
// flush.
func (h *Handler) FlushPullTimes(ctx context.Context) error { return h.pc.FlushPullTimes(ctx) }

// Evict evicts the least recently pulled files of every size-limited
// proxy repository over its limit.
func (h *Handler) Evict(ctx context.Context) error { return h.pc.Evict(ctx) }
