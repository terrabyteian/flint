package npm

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/terrabyteian/flint/internal/blob"
	"github.com/terrabyteian/flint/internal/config"
	"github.com/terrabyteian/flint/internal/upstream"
)

// A proxy repository caches one upstream npm registry, such as
// https://registry.npmjs.org/:
//
//   - Packuments are documents of the shared document cache, the full
//     and the abbreviated form each its own, under
//     cache\0doc\0<repo>\0packument/<name> and abbreviated/<name>:
//     served from the cache for the repository's revalidation window
//     after the upstream last confirmed them, then revalidated with the
//     upstream's ETag. When the upstream cannot be reached, the cached
//     copy is served; a package the upstream answers is not found or
//     denied is answered 404, even if cached. They are stored verbatim
//     and rewritten when served, as a stream, so the tarball and
//     attestation URLs point at flint: lockfiles then record flint's
//     URLs, and npm sends flint's credentials with tarball requests.
//     Everything else, dist.signatures too, is served as the upstream
//     sent it.
//   - Tarballs never change, so they are fetched once through the shared
//     path-cache engine, under cache\0file\0<repo>\0<name>/-/<file>,
//     verified against the packument's dist.integrity (sha512), or
//     dist.shasum (sha1) for versions too old to have one, before they
//     are cached and before a client receives their last byte, and
//     cached forever, unless a size limit evicts them. A cached tarball
//     is served even once the upstream removes its version, so lockfile
//     installs keep working.
//   - The registry's signing keys and attestations are documents too;
//     search and audit are passed through to the upstream.

// Proxy timeouts and limits; tests shorten the timeouts.
var (
	// revalidateTimeout bounds a packument revalidation when a cached
	// copy could be served instead.
	revalidateTimeout = 10 * time.Second
	// fetchTimeout bounds fetching a packument that is not cached, a
	// search, or an audit.
	fetchTimeout = time.Minute
)

const (
	// maxPackumentSize bounds an upstream packument. The npm registry's
	// largest full packuments are a few hundred megabytes.
	maxPackumentSize = 512 << 20
	// maxSmallDoc bounds the upstream's signing keys and one version's
	// attestations.
	maxSmallDoc = 8 << 20
	// maxForwarded bounds an upstream's answer to a search or an audit.
	maxForwarded = 16 << 20
)

// Accept headers of packument requests, as npm sends them.
const (
	acceptFull        = mtJSON
	acceptAbbreviated = mtAbbreviated + "; q=1.0, application/json; q=0.8, */*"
)

// proxyRepo is the upstream side of a proxy repository.
type proxyRepo struct {
	client     *upstream.Client
	registry   string // the upstream registry URL, ending in "/"
	revalidate time.Duration
	path       *upstream.PathRepo // its tarballs
}

func newProxyRepo(rc config.Repository, defaults upstream.Options) (*proxyRepo, error) {
	pc := rc.Proxy
	p := &proxyRepo{registry: config.NPMRegistryURL(pc.URL), revalidate: pc.RevalidateAfter.Duration}
	if p.revalidate <= 0 {
		p.revalidate = config.DefaultRevalidateAfter
	}
	opts := defaults
	opts.URL = p.registry
	opts.Username, opts.PasswordFile = pc.Username, pc.PasswordFile
	// A registry may answer a request without credentials 404 rather
	// than challenge it, so they are sent with every request, as npm
	// sends them.
	opts.Preemptive = true
	opts.MaxConcurrent = pc.MaxConcurrent
	opts.Policy = upstream.Policy{AllowHosts: pc.AllowHosts}
	var err error
	if p.client, err = upstream.New(opts); err != nil {
		return nil, err
	}
	p.path = &upstream.PathRepo{Name: rc.Name, Format: config.FormatNPM, Client: p.client, Revalidate: p.revalidate,
		SizeLimit: pc.SizeLimit.Bytes}
	return p, nil
}

// upstreamError maps a failed upstream request about what to the
// response error.
func upstreamError(rp *repository, what string, err error) error {
	var he *httpError
	if errors.As(err, &he) {
		return err
	}
	status, msg := upstream.StatusOf(err, rp.proxy.client.Host())
	if status == http.StatusNotFound && !errors.Is(err, upstream.ErrDenied) {
		msg = what + " is not found"
	} else {
		msg = what + ": " + msg
	}
	return errorf(status, "%s", msg)
}

// isNotFound reports whether err is a not-found answer.
func isNotFound(err error) bool {
	var he *httpError
	return errors.As(err, &he) && he.status == http.StatusNotFound
}

// packumentKey is the document cache key of a packument of a proxy
// repository.
func packumentKey(name string, abbreviated bool) string {
	if abbreviated {
		return "abbreviated/" + name
	}
	return "packument/" + name
}

// proxyPackument returns rp's packument of name, the abbreviated form or
// the full one, through the shared document cache.
func (h *Handler) proxyPackument(ctx context.Context, actor string, rp *repository, name string, abbreviated bool) (*upstream.Doc, error) {
	p := rp.proxy
	accept := acceptFull
	if abbreviated {
		accept = acceptAbbreviated
	}
	d, err := h.docs.Get(ctx, &upstream.DocRequest{
		Repo:   rp.name,
		Key:    packumentKey(name, abbreviated),
		Client: p.client,
		URL:    p.registry + escapeName(name),
		Header: http.Header{"Accept": {accept}},
		// Read at request time, so tests can shorten them.
		Revalidate:        p.revalidate,
		RevalidateTimeout: revalidateTimeout,
		FetchTimeout:      fetchTimeout,
		MaxSize:           maxPackumentSize,
		Actor:             actor,
		Action:            "npm.proxy.cache",
		// A packument flint cannot read, or of another package, never
		// replaces the cached one.
		Validate: func(ctx context.Context, d *upstream.Doc) error {
			f, err := h.docs.Open(ctx, d)
			if err != nil {
				return err
			}
			defer f.Close()
			return checkPackument(f, name)
		},
	})
	if err != nil {
		if !upstream.Answered(err) {
			h.log.WarnContext(ctx, "proxy upstream request failed", "repository", rp.name,
				"upstream", p.client.Host(), "err", err)
		}
		return nil, upstreamError(rp, "package "+name, err)
	}
	return d, nil
}

// escapeName escapes a package name for a URL as npm does: a scoped
// name's "/" as "%2f".
func escapeName(name string) string { return strings.Replace(name, "/", "%2f", 1) }

// checkPackument checks that a document is a packument of package name:
// readable, with versions that are objects, and naming no other
// package.
func checkPackument(r io.Reader, name string) error {
	return scanPackument(r, packumentVisitor{
		field: func(k string, raw json.RawMessage) error {
			if k != "name" {
				return nil
			}
			var got string
			if json.Unmarshal(raw, &got) != nil || got != name {
				return fmt.Errorf("%w: it names package %.100s, not %s", errNotPackument, raw, name)
			}
			return nil
		},
		version: func(string, json.RawMessage) error { return nil },
	})
}

// packumentVariant names the derivation of a served packument: the
// package, the form, and the registry URL its URLs point below.
func packumentVariant(name, base string) string {
	return "npm\x00" + name + "\x00" + base
}

// proxyBody returns rp's packument of name as served, with its URLs
// pointing below base.
func (h *Handler) proxyBody(ctx context.Context, actor string, rp *repository, name string, abbreviated bool, base string) (*docBody, error) {
	d, err := h.proxyPackument(ctx, actor, rp, name, abbreviated)
	if err != nil {
		return nil, err
	}
	h.pm.Requests.With(rp.name, d.Result).Inc()
	variant := packumentVariant(name, base)
	der, err := h.docs.Derive(ctx, d, variant, func(dst io.Writer, src io.Reader) error {
		return rewritePackument(dst, src, name, base)
	})
	if err != nil {
		return nil, err
	}
	body := &docBody{b: der.Bytes, stream: der.Stream, streamSize: d.Size, id: "p" + d.Digest.String(),
		abbreviated: abbreviated && d.MediaType() == mtAbbreviated}
	if der.Bytes != nil {
		body.etag = derivedETag(d.Digest, variant)
	}
	return body, nil
}

// derivedETag is the ETag of a document derived from the stored document
// d by variant.
func derivedETag(d blob.Digest, variant string) string {
	h := sha256.New()
	h.Write([]byte(d.String()))
	h.Write([]byte{0})
	h.Write([]byte(variant))
	return `"` + hex.EncodeToString(h.Sum(nil)[:16]) + `"`
}

// distInfo is where a proxied version's tarball is fetched from and
// what it must match.
type distInfo struct {
	url          string // absolute
	sha512, sha1 []byte
}

// proxyDists returns where each version of name in rp's upstream
// packument has its tarball, read from the abbreviated packument, or the
// full one if the abbreviated one cannot be had.
func (h *Handler) proxyDists(ctx context.Context, actor string, rp *repository, name string) (map[string]*distInfo, error) {
	d, err := h.proxyPackument(ctx, actor, rp, name, true)
	if err != nil && !isNotFound(err) {
		if full, ferr := h.proxyPackument(ctx, actor, rp, name, false); ferr == nil {
			d, err = full, nil
		}
	}
	if err != nil {
		return nil, err
	}
	if ds, ok := h.dists.get(d.Digest); ok {
		return ds, nil
	}
	f, err := h.docs.Open(ctx, d)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	base, err := url.Parse(d.URL)
	if err != nil {
		return nil, err
	}
	ds := map[string]*distInfo{}
	var size int64
	err = scanPackument(f, packumentVisitor{version: func(ver string, raw json.RawMessage) error {
		var m struct {
			Dist struct {
				Tarball   string `json:"tarball"`
				Integrity string `json:"integrity"`
				Shasum    string `json:"shasum"`
			} `json:"dist"`
		}
		if json.Unmarshal(raw, &m) != nil || m.Dist.Tarball == "" {
			return nil // a version without a tarball cannot be fetched
		}
		u, err := base.Parse(m.Dist.Tarball)
		if err != nil {
			return nil
		}
		di := &distInfo{url: u.String()}
		di.sha512, di.sha1 = parseIntegrity(m.Dist.Integrity)
		if di.sha1 == nil {
			if b, err := hex.DecodeString(m.Dist.Shasum); err == nil && len(b) == 20 {
				di.sha1 = b
			}
		}
		ds[ver] = di
		size += int64(len(ver) + len(di.url) + 128)
		return nil
	}})
	if err != nil {
		return nil, upstreamError(rp, "package "+name, &upstream.Error{Op: "GET " + d.URL, Err: err})
	}
	h.dists.put(d.Digest, ds, size)
	return ds, nil
}

// parseIntegrity returns the sha512 and sha1 digests of a Subresource
// Integrity string, such as "sha512-<base64>", or nil for those it does
// not have.
func parseIntegrity(s string) (sha512, sha1 []byte) {
	for part := range strings.FieldsSeq(s) {
		alg, val, ok := strings.Cut(part, "-")
		if !ok {
			continue
		}
		val, _, _ = strings.Cut(val, "?") // options
		b, err := base64.StdEncoding.DecodeString(val)
		switch {
		case err != nil:
		case alg == "sha512" && len(b) == 64:
			sha512 = b
		case alg == "sha1" && len(b) == 20:
			sha1 = b
		}
	}
	return sha512, sha1
}

// tarballPath is a tarball's path in the path-cache engine.
func tarballPath(name, file string) string { return name + "/-/" + file }

// proxyTarballVersion returns the version a tarball file of package name
// names, as tarballVersion does but without requiring a valid version,
// since upstream packuments list versions flint would not publish.
func proxyTarballVersion(name, file string) (string, bool) {
	stem, ok := strings.CutSuffix(file, ".tgz")
	if !ok {
		return "", false
	}
	for _, prefix := range []string{unscoped(name) + "-", name + "-"} {
		if v, ok := strings.CutPrefix(stem, prefix); ok && v != "" {
			return v, true
		}
	}
	return "", false
}

// cachedTarball reports whether rp has the tarball file of name cached.
func (h *Handler) cachedTarball(ctx context.Context, rp *repository, name, file string) bool {
	f, err := h.paths.Lookup(rp.proxy.path, tarballPath(name, file))
	if err != nil || f == nil {
		return false
	}
	_, err = h.blobs.Stat(ctx, f.Digest)
	return err == nil
}

// proxyTarball serves a tarball of proxy repository rp, as repository
// front, which the request named: from the cache, or else fetched from
// where the upstream packument says, verified against its integrity, and
// cached while it streams to the client. dists, if not nil, are the
// upstream's dists of name, which the caller read.
func (h *Handler) proxyTarball(w http.ResponseWriter, r *http.Request, front, rp *repository, name, file string, dists map[string]*distInfo) {
	ctx := r.Context()
	actor := h.actor(r)
	pr := rp.proxy.path
	path := tarballPath(name, file)
	// A version's tarball never changes.
	w.Header().Set("Cache-Control", cacheControl(front, "max-age=31536000, immutable"))
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if h.cachedTarball(ctx, rp, name, file) {
		h.paths.Serve(w, r, pr, &upstream.Route{Kind: upstream.Immutable, Path: path, ContentType: mtTarball}, actor)
		return
	}
	ver, ok := proxyTarballVersion(name, file)
	if !ok {
		writeError(w, http.StatusNotFound, "%s is not a tarball of %s", abbrev(file), name)
		return
	}
	if dists == nil {
		var err error
		if dists, err = h.proxyDists(ctx, actor, rp, name); err != nil {
			h.fail(w, r, err)
			return
		}
	}
	di := dists[ver]
	if di == nil {
		writeError(w, http.StatusNotFound, "%s@%s is not found", name, abbrev(ver))
		return
	}
	expect := upstream.Expect{Size: -1, Sums: upstream.Sums{}}
	if di.sha512 != nil {
		expect.Sums[upstream.SHA512] = di.sha512
	}
	if di.sha1 != nil {
		expect.Sums[upstream.SHA1] = di.sha1
	}
	if len(expect.Sums) == 0 {
		writeError(w, http.StatusBadGateway, "the upstream packument of %s@%s has no integrity or shasum, so the tarball cannot be verified", name, ver)
		return
	}
	h.paths.Serve(w, r, pr, &upstream.Route{Kind: upstream.Immutable, Path: path, URL: di.url, Expect: expect,
		ContentType: mtTarball}, actor)
}

// mtTarball is the media type tarballs are served with.
const mtTarball = "application/octet-stream"

// proxyDoc returns a small document of rp's upstream, such as its signing
// keys, through the shared document cache.
func (h *Handler) proxyDoc(ctx context.Context, actor string, rp *repository, key, path, what string) (*upstream.Doc, error) {
	p := rp.proxy
	d, err := h.docs.Get(ctx, &upstream.DocRequest{
		Repo:              rp.name,
		Key:               key,
		Client:            p.client,
		URL:               p.registry + path,
		Header:            http.Header{"Accept": {mtJSON}},
		Revalidate:        p.revalidate,
		RevalidateTimeout: revalidateTimeout,
		FetchTimeout:      fetchTimeout,
		MaxSize:           maxSmallDoc,
		MaxMemory:         maxSmallDoc,
		Actor:             actor,
		Action:            "npm.proxy.cache",
		Validate: func(ctx context.Context, d *upstream.Doc) error {
			_, err := h.readDoc(ctx, d)
			return err
		},
	})
	if err != nil {
		return nil, upstreamError(rp, what, err)
	}
	h.pm.Requests.With(rp.name, d.Result).Inc()
	return d, nil
}

// readDoc reads a small document, which must be a JSON object.
func (h *Handler) readDoc(ctx context.Context, d *upstream.Doc) (map[string]json.RawMessage, error) {
	f, err := h.docs.Open(ctx, d)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxSmallDoc))
	if err != nil {
		return nil, err
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil || m == nil {
		return nil, fmt.Errorf("the document is not a JSON object")
	}
	return m, nil
}

// proxyKeys returns the keys rp's upstream signs packuments with: the
// entries of its /-/npm/v1/keys, none if it has no such endpoint.
func (h *Handler) proxyKeys(ctx context.Context, actor string, rp *repository) ([]json.RawMessage, error) {
	d, err := h.proxyDoc(ctx, actor, rp, "keys", "-/npm/v1/keys", "the upstream's signing keys")
	if isNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	m, err := h.readDoc(ctx, d)
	if err != nil {
		return nil, err
	}
	var keys []json.RawMessage
	json.Unmarshal(m["keys"], &keys)
	return keys, nil
}

// serveProxyAttestations serves the attestations of name@ver from proxy
// repository rp's upstream, as repository front, which the request
// named.
func (h *Handler) serveProxyAttestations(w http.ResponseWriter, r *http.Request, front, rp *repository, name, ver string) {
	ctx := r.Context()
	d, err := h.proxyDoc(ctx, h.actor(r), rp, "attestations/"+name+"@"+ver,
		"-/npm/v1/attestations/"+escapeName(name)+"@"+url.PathEscape(ver), name+"@"+ver+" attestations")
	if err != nil {
		h.fail(w, r, err)
		return
	}
	f, err := h.docs.Open(ctx, d)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", mtJSON)
	w.Header().Set("Cache-Control", cacheControl(front, "max-age=300"))
	http.ServeContent(w, r, "", time.Time{}, f)
}

// forward sends a request to rp's upstream registry, at path below its
// registry URL, and returns its answer, which must be a JSON object.
// body, if not nil, is sent as JSON with a POST.
func (h *Handler) forward(ctx context.Context, rp *repository, path string, body []byte, what string) (json.RawMessage, error) {
	ctx, cancel := upstream.WithTimeout(ctx, fetchTimeout)
	defer cancel()
	u := rp.proxy.registry + path
	method, hdr := http.MethodGet, http.Header{"Accept": {mtJSON}}
	if body != nil {
		method = http.MethodPost
		hdr.Set("Content-Type", mtJSON)
	}
	resp, err := rp.proxy.client.Send(ctx, method, u, hdr, body)
	if err == nil && resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		err = &upstream.Error{Op: method + " " + u, Status: resp.StatusCode, Err: fmt.Errorf("unexpected status %s", resp.Status)}
	}
	if err != nil {
		if !errors.Is(err, upstream.ErrNotFound) {
			h.pm.UpstreamErrors.With(rp.name).Inc()
		}
		return nil, upstreamError(rp, what, err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxForwarded+1))
	if err == nil && (len(b) > maxForwarded || !json.Valid(b) || len(bytes.TrimSpace(b)) == 0 || bytes.TrimSpace(b)[0] != '{') {
		err = errors.New("the upstream's answer is not a JSON object")
	}
	if err != nil {
		h.pm.UpstreamErrors.With(rp.name).Inc()
		return nil, upstreamError(rp, what, &upstream.Error{Op: method + " " + u, Err: err})
	}
	h.pm.Requests.With(rp.name, upstream.ResultPassthrough).Inc()
	return b, nil
}

// distCache keeps the dists of recently used upstream packuments, by the
// packument's digest, up to a total of maxDistCache bytes, least
// recently used out first. Documents are content-addressed, so an entry
// never goes stale.
type distCache struct {
	mu    sync.Mutex
	m     map[blob.Digest]*distEntry
	total int64
	tick  uint64
}

type distEntry struct {
	ds   map[string]*distInfo
	size int64
	used uint64
}

const maxDistCache = 32 << 20

func (c *distCache) get(d blob.Digest) (map[string]*distInfo, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e := c.m[d]
	if e == nil {
		return nil, false
	}
	c.tick++
	e.used = c.tick
	return e.ds, true
}

func (c *distCache) put(d blob.Digest, ds map[string]*distInfo, size int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m == nil {
		c.m = map[blob.Digest]*distEntry{}
	}
	if old := c.m[d]; old != nil {
		c.total -= old.size
	}
	c.tick++
	c.m[d] = &distEntry{ds: ds, size: size, used: c.tick}
	c.total += size
	for c.total > maxDistCache && len(c.m) > 1 {
		var oldest blob.Digest
		var used uint64
		first := true
		for k, e := range c.m {
			if first || e.used < used {
				oldest, used, first = k, e.used, false
			}
		}
		c.total -= c.m[oldest].size
		delete(c.m, oldest)
	}
}
