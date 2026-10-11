package cargo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/terrabyteian/flint/internal/blob"
	"github.com/terrabyteian/flint/internal/config"
	"github.com/terrabyteian/flint/internal/upstream"
)

// A proxy repository caches one upstream sparse index, such as
// crates.io's at sparse+https://index.crates.io/:
//
//   - Index files and the upstream's config.json are documents of the
//     shared document cache: served from the cache for the repository's
//     revalidation window after the upstream last confirmed them, then
//     revalidated with the upstream's ETag. When the upstream cannot be
//     reached, the cached copy is served; a crate the upstream answers is
//     not found (404, 410, or 451) or denied is answered 404, even if
//     cached. Index files are served verbatim: their lines carry no URLs,
//     and a dependency without a registry means the registry serving the
//     line, which is now flint.
//   - flint serves its own config.json, naming its own download and API
//     URLs, and reads the upstream's to learn where .crate files are
//     downloaded from (its dl), such as https://static.crates.io/crates.
//   - .crate files never change, so they are fetched once through the
//     shared path-cache engine, verified against the cksum of the index
//     line that lists them before they are cached and before a client
//     receives their last byte, and cached forever, unless a size limit
//     evicts them.
//   - Search is passed through to the upstream's web API.

// Proxy timeouts and limits; tests shorten the timeouts.
var (
	// revalidateTimeout bounds an index revalidation when a cached copy
	// could be served instead.
	revalidateTimeout = 10 * time.Second
	// fetchTimeout bounds fetching an index file that is not cached, or a
	// search.
	fetchTimeout = time.Minute
)

const (
	// maxIndexSize bounds an upstream index file. crates.io's largest are
	// a few megabytes.
	maxIndexSize = 64 << 20
	// maxConfigSize bounds an upstream config.json.
	maxConfigSize = 1 << 20
	// maxSearchSize bounds an upstream search response.
	maxSearchSize = 8 << 20
)

// proxyRepo is the upstream side of a proxy repository.
type proxyRepo struct {
	client     *upstream.Client
	index      string // the upstream sparse index URL, without "sparse+", ending in "/"
	revalidate time.Duration
	path       *upstream.PathRepo // its .crate files
}

// knownHosts are the hosts besides its own that well-known indexes
// download .crate files from and serve their web API on.
var knownHosts = map[string][]string{
	"index.crates.io": {"static.crates.io", "crates.io"},
}

func newProxyRepo(rc config.Repository, defaults upstream.Options) (*proxyRepo, error) {
	pc := rc.Proxy
	p := &proxyRepo{index: config.CargoIndexURL(pc.URL), revalidate: pc.RevalidateAfter.Duration}
	if p.revalidate <= 0 {
		p.revalidate = config.DefaultRevalidateAfter
	}
	u, err := url.Parse(p.index)
	if err != nil {
		return nil, err
	}
	opts := defaults
	opts.URL = p.index
	opts.Username, opts.PasswordFile = pc.Username, pc.PasswordFile
	opts.MaxConcurrent = pc.MaxConcurrent
	opts.Policy = upstream.Policy{AllowHosts: pc.AllowHosts, FormatHosts: knownHosts[strings.ToLower(u.Hostname())]}
	if p.client, err = upstream.New(opts); err != nil {
		return nil, err
	}
	p.path = &upstream.PathRepo{Name: rc.Name, Format: config.FormatCargo, Client: p.client, Revalidate: p.revalidate,
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

// proxyIndex returns rp's index file of crate, a lowercase name, through
// the shared document cache, read into entries.
func (h *Handler) proxyIndex(ctx context.Context, actor string, rp *repository, crate string) ([]*entry, *upstream.Doc, error) {
	p := rp.proxy
	path := indexPath(crate)
	d, err := h.docs.Get(ctx, &upstream.DocRequest{
		Repo:       rp.name,
		Key:        path,
		Client:     p.client,
		URL:        p.index + path,
		Revalidate: p.revalidate,
		// Read at request time, so tests can shorten them.
		RevalidateTimeout: revalidateTimeout,
		FetchTimeout:      fetchTimeout,
		MaxSize:           maxIndexSize,
		MaxMemory:         maxIndexSize,
		Actor:             actor,
		Action:            "cargo.proxy.cache",
		// An index file flint cannot read never replaces the cached one.
		Validate: func(ctx context.Context, d *upstream.Doc) error {
			_, err := h.loadIndex(ctx, d, crate)
			return err
		},
	})
	if err != nil {
		if !upstream.Answered(err) {
			h.log.WarnContext(ctx, "proxy upstream request failed", "repository", rp.name,
				"upstream", p.client.Host(), "err", err)
		}
		return nil, nil, upstreamError(rp, "crate "+crate, err)
	}
	es, err := h.loadIndex(ctx, d, crate)
	if err != nil {
		return nil, nil, err
	}
	out := make([]*entry, len(es))
	for i, e := range es {
		c := *e
		c.src = rp.name
		out[i] = &c
	}
	return out, d, nil
}

// loadIndex reads an index file the document cache resolved into
// entries, which are kept in memory by the file's digest.
func (h *Handler) loadIndex(ctx context.Context, d *upstream.Doc, crate string) ([]*entry, error) {
	ck := d.Digest.String() + "\x00" + crate
	if es, ok := h.indexes.get(ck); ok {
		return es, nil
	}
	f, err := h.docs.Open(ctx, d)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxIndexSize))
	if err != nil {
		return nil, err
	}
	es, err := parseIndex(b, crate)
	if err != nil {
		return nil, &upstream.Error{Op: "GET " + d.URL, Err: err}
	}
	h.indexes.put(ck, es, int64(len(b)))
	return es, nil
}

// proxyIndexFile serves a proxy repository's index file of crate
// verbatim.
func (h *Handler) proxyIndexFile(w http.ResponseWriter, r *http.Request, rp *repository, crate string) {
	ctx := r.Context()
	_, d, err := h.proxyIndex(ctx, h.actor(r), rp, crate)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	h.pm.Requests.With(rp.name, d.Result).Inc()
	f, err := h.docs.Open(ctx, d)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	defer f.Close()
	hd := w.Header()
	hd.Set("Content-Type", indexType)
	hd.Set("ETag", `"`+d.Digest.String()+`"`)
	hd.Set("Cache-Control", "max-age=0, must-revalidate")
	http.ServeContent(w, r, "", time.Time{}, f)
}

// upstreamConfig is what flint reads from an upstream's config.json.
type upstreamConfig struct {
	dl  string // the download URL template, absolute
	api string // the web API's base URL, or ""
}

// proxyConfig returns the upstream's config.json, through the shared
// document cache.
func (h *Handler) proxyConfig(ctx context.Context, actor string, rp *repository) (*upstreamConfig, error) {
	p := rp.proxy
	d, err := h.docs.Get(ctx, &upstream.DocRequest{
		Repo:              rp.name,
		Key:               "config.json",
		Client:            p.client,
		URL:               p.index + "config.json",
		Revalidate:        p.revalidate,
		RevalidateTimeout: revalidateTimeout,
		FetchTimeout:      fetchTimeout,
		MaxSize:           maxConfigSize,
		MaxMemory:         maxConfigSize,
		Actor:             actor,
		Action:            "cargo.proxy.cache",
		Validate: func(ctx context.Context, d *upstream.Doc) error {
			_, err := h.loadConfig(ctx, rp, d)
			return err
		},
	})
	if err != nil {
		return nil, upstreamError(rp, "the upstream index's config.json", err)
	}
	return h.loadConfig(ctx, rp, d)
}

// errBadConfig means an upstream config.json could not be read.
var errBadConfig = errors.New("the upstream index's config.json has no valid dl URL")

// configCache keeps each proxy repository's upstream config.json, read,
// by its digest.
type configCache struct {
	mu sync.Mutex
	m  map[string]configEntry
}

type configEntry struct {
	digest blob.Digest
	cfg    *upstreamConfig
}

func (h *Handler) loadConfig(ctx context.Context, rp *repository, d *upstream.Doc) (*upstreamConfig, error) {
	c := &h.configs
	c.mu.Lock()
	if e, ok := c.m[rp.name]; ok && e.digest == d.Digest {
		c.mu.Unlock()
		return e.cfg, nil
	}
	c.mu.Unlock()
	f, err := h.docs.Open(ctx, d)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxConfigSize))
	if err != nil {
		return nil, err
	}
	var raw struct {
		DL  string `json:"dl"`
		API string `json:"api"`
	}
	base, perr := url.Parse(d.URL)
	if json.Unmarshal(b, &raw) != nil || perr != nil {
		return nil, &upstream.Error{Op: "GET " + d.URL, Err: errBadConfig}
	}
	cfg := &upstreamConfig{}
	// A relative URL, which Cargo does not accept, resolves against the
	// config's own URL; an absolute one is kept as it is, so the markers
	// of a template stay unescaped. Without a valid dl, nothing can be
	// downloaded; without a valid api, nothing can be searched.
	for _, field := range []struct {
		s    string
		out  *string
		need bool
	}{{raw.DL, &cfg.dl, true}, {raw.API, &cfg.api, false}} {
		u, err := url.Parse(field.s)
		if err == nil && field.s != "" && !u.IsAbs() {
			u = base.ResolveReference(u)
			field.s = u.String()
		}
		switch {
		case field.s != "" && err == nil && (u.Scheme == "http" || u.Scheme == "https"):
			*field.out = field.s
		case field.need:
			return nil, &upstream.Error{Op: "GET " + d.URL, Err: errBadConfig}
		}
	}
	c.mu.Lock()
	if c.m == nil {
		c.m = map[string]configEntry{}
	}
	c.m[rp.name] = configEntry{d.Digest, cfg}
	c.mu.Unlock()
	return cfg, nil
}

// Markers of a download URL template.
var dlMarkers = []string{"{crate}", "{version}", "{prefix}", "{lowerprefix}", "{sha256-checksum}"}

// downloadURL returns the URL a .crate file is downloaded from, by the
// dl template of an index's config.json, as Cargo expands it: with
// "/{crate}/{version}/download" appended if it has no markers.
func downloadURL(dl, name, vers, cksum string) string {
	marked := false
	for _, m := range dlMarkers {
		if strings.Contains(dl, m) {
			marked = true
		}
	}
	if !marked {
		return dl + "/" + name + "/" + vers + "/download"
	}
	return strings.NewReplacer("{crate}", name, "{version}", vers, "{prefix}", prefixOf(name),
		"{lowerprefix}", strings.ToLower(prefixOf(name)), "{sha256-checksum}", cksum).Replace(dl)
}

// cratePath is a .crate file's path in the path-cache engine.
func cratePath(crate, vers string) string { return "crates/" + strings.ToLower(crate) + "/" + vers }

// proxyDownload serves a .crate file of a proxy repository: from the
// cache, or else fetched from where the upstream's config.json says,
// verified against the index line's cksum, and cached while it streams to
// the client. e is the version's index line if the caller has it.
func (h *Handler) proxyDownload(w http.ResponseWriter, r *http.Request, rp *repository, crate, vers string, e *entry) {
	ctx := r.Context()
	actor := h.actor(r)
	pr := rp.proxy.path
	path := cratePath(crate, vers)
	if f, err := h.paths.Lookup(pr, path); err == nil && f != nil {
		if _, err := h.blobs.Stat(ctx, f.Digest); err == nil {
			h.paths.Serve(w, r, pr, &upstream.Route{Kind: upstream.Immutable, Path: path, ContentType: crateType}, actor)
			return
		}
		// Linked but missing from the store: fetch it again.
	}
	if e == nil {
		es, _, err := h.proxyIndex(ctx, actor, rp, strings.ToLower(crate))
		if err != nil {
			h.fail(w, r, err)
			return
		}
		if e = findVersion(es, vers); e == nil {
			writeError(w, http.StatusNotFound, "crate %s has no version %s", crate, vers)
			return
		}
	}
	if e.cksum == "" {
		writeError(w, http.StatusBadGateway, "the upstream index line of %s@%s has no valid cksum, so the crate cannot be verified", e.name, e.vers)
		return
	}
	cfg, err := h.proxyConfig(ctx, actor, rp)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	h.paths.Serve(w, r, pr, &upstream.Route{
		Kind:        upstream.Immutable,
		Path:        path,
		URL:         downloadURL(cfg.dl, e.name, e.vers, e.cksum),
		Expect:      upstream.Expect{Size: -1, SHA256: e.cksum},
		ContentType: crateType,
	}, actor)
}

// findVersion returns the entry of version vers, or of one that differs
// from it only in build metadata, or nil.
func findVersion(es []*entry, vers string) *entry {
	for _, e := range es {
		if e.vers == vers {
			return e
		}
	}
	k := canonicalVersion(vers)
	for _, e := range es {
		if e.key == k {
			return e
		}
	}
	return nil
}

// proxySearch passes a search through to the upstream's web API.
func (h *Handler) proxySearch(ctx context.Context, actor string, rp *repository, q string, perPage int) (*searchResult, error) {
	cfg, err := h.proxyConfig(ctx, actor, rp)
	if err != nil {
		return nil, err
	}
	if cfg.api == "" {
		return &searchResult{Crates: []searchCrate{}}, nil
	}
	ctx, cancel := upstream.WithTimeout(ctx, fetchTimeout)
	defer cancel()
	u := strings.TrimSuffix(cfg.api, "/") + "/api/v1/crates?q=" + url.QueryEscape(q) + "&per_page=" + strconv.Itoa(perPage)
	resp, err := rp.proxy.client.GetURL(ctx, u, http.Header{"Accept": {"application/json"}})
	if err == nil && resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		err = &upstream.Error{Op: "GET " + u, Status: resp.StatusCode, Err: fmt.Errorf("unexpected status %s", resp.Status)}
	}
	if err != nil {
		h.pm.UpstreamErrors.With(rp.name).Inc()
		return nil, upstreamError(rp, "the upstream search", err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxSearchSize+1))
	var res searchResult
	if err == nil && (len(b) > maxSearchSize || json.Unmarshal(b, &res) != nil) {
		err = errors.New("the upstream search response is not valid")
	}
	if err != nil {
		h.pm.UpstreamErrors.With(rp.name).Inc()
		return nil, upstreamError(rp, "the upstream search", &upstream.Error{Op: "GET " + u, Err: err})
	}
	if res.Crates == nil {
		res.Crates = []searchCrate{}
	}
	h.pm.Requests.With(rp.name, upstream.ResultPassthrough).Inc()
	return &res, nil
}

// indexCache keeps recently used upstream index files read into entries,
// by digest and crate, up to a total of maxIndexCache bytes of index
// files. Documents are content-addressed, so an entry never goes stale.
type indexCache struct {
	mu    sync.Mutex
	m     map[string]*indexCacheEntry
	total int64
	tick  uint64
}

type indexCacheEntry struct {
	es   []*entry
	size int64
	used uint64
}

const maxIndexCache = 64 << 20

func (c *indexCache) get(k string) ([]*entry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e := c.m[k]
	if e == nil {
		return nil, false
	}
	c.tick++
	e.used = c.tick
	return e.es, true
}

func (c *indexCache) put(k string, es []*entry, size int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m == nil {
		c.m = map[string]*indexCacheEntry{}
	}
	if old := c.m[k]; old != nil {
		c.total -= old.size
	}
	c.tick++
	c.m[k] = &indexCacheEntry{es: es, size: size, used: c.tick}
	c.total += size
	for c.total > maxIndexCache && len(c.m) > 1 {
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
