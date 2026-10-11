// Package oci serves hosted and proxy OCI repositories over the OCI
// Distribution Spec v1.1 API at /v2/: blob pulls, monolithic, chunked,
// and streamed uploads, cross-repository mounts, manifests (OCI image
// manifests and indexes, Docker schema 2 manifests and manifest lists),
// the referrers API, paginated tag and catalog listings, and deletes.
// Proxy repositories cache an upstream registry and are read-only; see
// proxy.go.
//
// Clients address an image as <repository>/<name>: the first path
// component is a repository declared in the configuration, and the rest
// is an image name below it, as in docker-local/team/app. Blob bytes,
// manifests included, live once in the blob store; the metadata store
// records which repository name may see which blob (link records),
// manifests, tags, the referrers index, and upload sessions.
//
// Every request is authorized through an Authorizer before it is served.
package oci

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/terrabyteian/flint/internal/blob"
	"github.com/terrabyteian/flint/internal/config"
	"github.com/terrabyteian/flint/internal/meta"
	"github.com/terrabyteian/flint/internal/metrics"
	"github.com/terrabyteian/flint/internal/server"
	"github.com/terrabyteian/flint/internal/upstream"
)

// Actions passed to Authorizer.Authorize.
const (
	ActionPull   = "pull"
	ActionPush   = "push"
	ActionDelete = "delete"
)

// Authorizer decides whether a request may act on a repository.
//
// repo is the full repository name as the client addressed it, such as
// "docker-local/team/app"; its first path component is the configured
// repository that permissions apply to. actions are ActionPull,
// ActionPush, and ActionDelete; Docker-style clients ask for pull and push
// together when pushing. The API base check (GET /v2/) calls Authorize
// with an empty repo and no actions: it asks only whether the request is
// acceptable at all, and an authorizer that requires credentials answers
// it with a challenge, which is how Docker clients discover the token
// service.
//
// Authorize returns true to let the request proceed. When it returns
// false it has already written the response: a 401 with a
// Docker-compatible WWW-Authenticate Bearer challenge naming the scope,
// such as repository:docker-local/team/app:pull,push, or a 403.
type Authorizer interface {
	Authorize(w http.ResponseWriter, r *http.Request, repo string, actions ...string) bool
}

// CatalogAuthorizer is an optional extension of Authorizer for the
// catalog, GET /v2/_catalog. AuthorizeCatalog returns whether the request
// may list repositories at all, having written the response when it may
// not, and a filter that reports which full repository names to include.
// With an Authorizer that does not implement it, the catalog is not
// served.
type CatalogAuthorizer interface {
	AuthorizeCatalog(w http.ResponseWriter, r *http.Request) (visible func(repo string) bool, ok bool)
}

// AllowAll is an Authorizer that allows every request, for tests.
type AllowAll struct{}

// Authorize allows the request.
func (AllowAll) Authorize(http.ResponseWriter, *http.Request, string, ...string) bool { return true }

// AuthorizeCatalog allows the request and lists every repository.
func (AllowAll) AuthorizeCatalog(http.ResponseWriter, *http.Request) (func(string) bool, bool) {
	return func(string) bool { return true }, true
}

// Options configures a Handler.
type Options struct {
	// Meta and Blobs are the stores. Required.
	Meta  meta.Store
	Blobs blob.Store
	// Repositories are the configured repositories; those with format
	// "oci" and type "hosted" or "proxy" are served.
	Repositories []config.Repository
	// Upstream holds the defaults for proxy repositories' upstream
	// clients, such as the user agent; each repository's URL and
	// credentials come from its configuration.
	Upstream upstream.Options
	// Space, if set, watches the data directory's free space, so proxy
	// repositories stop caching new content when it runs low.
	Space *upstream.Space
	// FetchIdleTimeout is how long a proxy's blob fetch waits for the
	// upstream to send more; zero means upstream.DefaultIdleTimeout.
	FetchIdleTimeout time.Duration
	// Authorizer authorizes every request. Required.
	Authorizer Authorizer
	// Logger receives failures; nil means slog.Default().
	Logger *slog.Logger
	// Metrics, if set, receives the OCI metrics.
	Metrics *metrics.Registry
	// Actor names the principal behind a request in the origin of the
	// metadata batches it writes, for the audit log; nil names the
	// client address. It must not return secrets.
	Actor func(*http.Request) string
	// Now is the clock; nil means time.Now.
	Now func() time.Time
}

// repository is a configured OCI repository.
type repository struct {
	name          string
	immutableTags bool
	proxy         *proxyRepo // nil for a hosted repository
}

// Handler serves the OCI distribution API.
type Handler struct {
	meta  meta.Store
	blobs blob.Store
	repos map[string]*repository
	auth  Authorizer
	log   *slog.Logger
	actor func(*http.Request) string
	now   func() time.Time

	uploadBytes   *metrics.Counter
	manifestPuts  *metrics.Counter
	linkConflicts *metrics.CounterSeries

	// Proxy repositories.
	hasProxy      bool
	fetcher       *upstream.Fetcher
	space         *upstream.Space
	tagCalls      upstream.Group[*proxied]
	manifestCalls upstream.Group[*proxied]
	validatedMu   sync.Mutex
	validated     map[string]time.Time // tag key: when the upstream last confirmed it
	listings      listingCache
	evictKick     chan struct{}

	proxyResults   *metrics.Counter
	upstreamErrors *metrics.Counter
	upstreamBytes  *metrics.Counter
	evictions      *metrics.Counter
	cachedBytes    *metrics.Gauge

	// linkHook, if set, is called by every link batch after it read its
	// view and before it checks that the blobs exist, so tests can
	// interleave a garbage-collection sweep there.
	linkHook func(ds []blob.Digest)
}

// New returns a Handler.
func New(opts Options) (*Handler, error) {
	if opts.Meta == nil || opts.Blobs == nil {
		return nil, errors.New("oci: Meta and Blobs are required")
	}
	if opts.Authorizer == nil {
		return nil, errors.New("oci: an Authorizer is required")
	}
	h := &Handler{
		meta:      opts.Meta,
		blobs:     opts.Blobs,
		repos:     map[string]*repository{},
		auth:      opts.Authorizer,
		log:       opts.Logger,
		actor:     opts.Actor,
		now:       opts.Now,
		space:     opts.Space,
		fetcher:   upstream.NewFetcher(opts.Blobs, opts.FetchIdleTimeout),
		validated: map[string]time.Time{},
		evictKick: make(chan struct{}, 1),
	}
	if h.log == nil {
		h.log = slog.Default()
	}
	if h.now == nil {
		h.now = time.Now
	}
	if h.actor == nil {
		h.actor = clientActor
	}
	upOpts := opts.Upstream
	if upOpts.Logger == nil {
		upOpts.Logger = h.log
	}
	if upOpts.Now == nil {
		upOpts.Now = h.now
	}
	for _, rc := range opts.Repositories {
		if rc.Format != config.FormatOCI {
			continue
		}
		switch rc.Type {
		case config.TypeHosted:
			h.repos[rc.Name] = &repository{name: rc.Name, immutableTags: rc.ImmutableTags}
		case config.TypeProxy:
			if rc.Proxy == nil {
				return nil, fmt.Errorf("oci: proxy repository %s has no upstream", rc.Name)
			}
			p, err := newProxyRepo(rc, upOpts)
			if err != nil {
				return nil, fmt.Errorf("oci: proxy repository %s: %w", rc.Name, err)
			}
			h.repos[rc.Name] = &repository{name: rc.Name, proxy: p}
			h.hasProxy = true
		}
	}
	reg := opts.Metrics
	if reg == nil {
		reg = metrics.NewRegistry() // unexposed; keeps the counters usable
	}
	h.uploadBytes = reg.Counter("flint_oci_upload_bytes_total",
		"Blob bytes received in OCI uploads, by repository.", "repository")
	h.manifestPuts = reg.Counter("flint_oci_manifest_pushes_total",
		"Manifests pushed, by repository.", "repository")
	h.linkConflicts = reg.Counter("flint_oci_link_retries_total",
		"Link batches retried after a metadata precondition failed.").With()
	h.proxyResults = reg.Counter("flint_proxy_requests_total",
		"Pulls from proxy repositories, by repository and result: hit (served from the cache), "+
			"revalidated (served after the upstream confirmed a tag or listing), fetched (fetched from the upstream and cached), "+
			"passthrough (fetched from the upstream without caching), stale (served from the cache because the upstream failed).",
		"repository", "result")
	h.upstreamErrors = reg.Counter("flint_proxy_upstream_errors_total",
		"Proxy requests to upstream registries that failed, by repository.", "repository")
	h.upstreamBytes = reg.Counter("flint_proxy_upstream_bytes_total",
		"Bytes proxy repositories fetched from upstream registries, by repository.", "repository")
	h.evictions = reg.Counter("flint_proxy_evictions_total",
		"Cached items proxy repositories evicted to stay within their size limits, by repository.", "repository")
	h.cachedBytes = reg.Gauge("flint_proxy_cached_bytes",
		"Bytes cached by size-limited proxy repositories, by repository.", "repository")
	fetcher := h.fetcher
	reg.GaugeFunc("flint_proxy_fetches_in_flight", "Blobs proxy repositories are fetching from upstream registries.",
		func() float64 { return float64(fetcher.Active()) })
	if h.space != nil && h.hasProxy {
		space := h.space
		reg.GaugeFunc("flint_proxy_disk_pressure",
			"1 while the data directory's free space is below proxyCache.minFreeSpace and proxy repositories pass new content through without caching it, else 0.",
			func() float64 {
				if space.Pressure() {
					return 1
				}
				return 0
			})
		reg.GaugeFunc("flint_data_free_bytes", "Free bytes on the data directory's filesystem, as last measured.",
			func() float64 { return float64(space.Free()) })
	}
	if err := h.loadTrackers(); err != nil {
		return nil, err
	}
	return h, nil
}

// loadTrackers loads the size-limited proxy repositories' cached items,
// and asks for an eviction if one is over its limit.
func (h *Handler) loadTrackers() error {
	v := h.view()
	defer v.Release()
	for _, c := range h.trackers() {
		if err := c.load(v); err != nil {
			return fmt.Errorf("oci: loading the cache of proxy repository %s: %w", c.repo, err)
		}
		h.cachedBytes.With(c.repo).Set(float64(c.size()))
		if c.size() > c.limit {
			select {
			case h.evictKick <- struct{}{}:
			default:
			}
		}
	}
	return nil
}

// Register mounts the handler at /v2/ on a server.
func (h *Handler) Register(s interface{ Handle(string, http.Handler) }) {
	s.Handle("/v2/", h)
}

// repoName is a parsed, validated repository name.
type repoName struct {
	full string // as addressed: "docker-local/team/app"
	repo string // the configured repository: "docker-local"
	name string // the image name below it: "team/app"
	cfg  *repository
}

// resolve parses a full repository name.
func (h *Handler) resolve(full string) (*repoName, error) {
	if !validName(full) {
		return nil, newError(http.StatusBadRequest, codeNameInvalid, "invalid repository name %q", abbrev(full))
	}
	repo, name, ok := strings.Cut(full, "/")
	cfg := h.repos[repo]
	if cfg == nil {
		return nil, newError(http.StatusNotFound, codeNameUnknown,
			"repository %q is not an OCI repository on this registry", repo)
	}
	if !ok {
		return nil, newError(http.StatusNotFound, codeNameUnknown,
			"%q is a repository; address an image below it, such as %s/app", repo, repo)
	}
	return &repoName{full: full, repo: repo, name: name, cfg: cfg}, nil
}

// ServeHTTP routes a /v2/ request.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Docker-Distribution-API-Version", "registry/2.0")
	ctx := r.Context()
	p := strings.TrimPrefix(r.URL.Path, "/v2/")
	switch p {
	case "":
		server.SetRoute(ctx, "oci.base")
		if !allow(w, r, h, http.MethodGet, http.MethodHead) || !h.auth.Authorize(w, r, "") {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", "2")
		if r.Method == http.MethodGet {
			io.WriteString(w, "{}")
		}
		return
	case "_catalog":
		server.SetRoute(ctx, "oci.catalog")
		if allow(w, r, h, http.MethodGet) {
			h.catalog(w, r)
		}
		return
	}

	full, ep, arg, ok := splitPath(p)
	if !ok {
		server.SetRoute(ctx, "oci.unknown")
		h.writeError(w, r, newError(http.StatusNotFound, codeUnsupported, "unknown API endpoint"))
		return
	}
	server.SetRoute(ctx, endpointRoutes[ep])
	rn, err := h.resolve(full)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	server.LogAttrs(ctx, slog.String("repository", rn.full))
	if rn.cfg.proxy != nil {
		h.serveProxy(w, r, rn, ep, arg)
		return
	}

	push := []string{ActionPull, ActionPush}
	type op struct {
		actions []string
		serve   func(http.ResponseWriter, *http.Request, *repoName, string)
	}
	var ops map[string]op
	switch ep {
	case epBlob:
		ops = map[string]op{
			http.MethodGet:    {[]string{ActionPull}, h.getBlob},
			http.MethodHead:   {[]string{ActionPull}, h.getBlob},
			http.MethodDelete: {[]string{ActionDelete}, h.deleteBlob},
		}
	case epUploadStart:
		ops = map[string]op{http.MethodPost: {push, h.startUpload}}
	case epUpload:
		ops = map[string]op{
			http.MethodGet:    {push, h.uploadStatus},
			http.MethodPatch:  {push, h.patchUpload},
			http.MethodPut:    {push, h.finishUpload},
			http.MethodDelete: {push, h.cancelUpload},
		}
	case epManifest:
		ops = map[string]op{
			http.MethodGet:    {[]string{ActionPull}, h.getManifest},
			http.MethodHead:   {[]string{ActionPull}, h.getManifest},
			http.MethodPut:    {push, h.putManifest},
			http.MethodDelete: {[]string{ActionDelete}, h.deleteManifest},
		}
	case epTags:
		ops = map[string]op{http.MethodGet: {[]string{ActionPull}, h.listTags}}
	case epReferrers:
		ops = map[string]op{http.MethodGet: {[]string{ActionPull}, h.listReferrers}}
	}
	o, ok := ops[r.Method]
	if !ok {
		methods := make([]string, 0, len(ops))
		for m := range ops {
			methods = append(methods, m)
		}
		allow(w, r, h, methods...)
		return
	}
	if !h.auth.Authorize(w, r, rn.full, o.actions...) {
		return
	}
	o.serve(w, r, rn, arg)
}

var endpointRoutes = map[endpoint]string{
	epBlob:        "oci.blob",
	epUploadStart: "oci.upload",
	epUpload:      "oci.upload",
	epManifest:    "oci.manifest",
	epTags:        "oci.tags",
	epReferrers:   "oci.referrers",
}

// allow reports whether the request's method is one of methods, and
// answers 405 if it is not.
func allow(w http.ResponseWriter, r *http.Request, h *Handler, methods ...string) bool {
	for _, m := range methods {
		if r.Method == m {
			return true
		}
	}
	w.Header().Set("Allow", strings.Join(sortedMethods(methods), ", "))
	h.writeError(w, r, newError(http.StatusMethodNotAllowed, codeUnsupported,
		"method %s is not allowed here", r.Method))
	return false
}

func sortedMethods(ms []string) []string {
	order := []string{http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete}
	var out []string
	for _, o := range order {
		for _, m := range ms {
			if m == o {
				out = append(out, m)
			}
		}
	}
	return out
}

// parseDigest parses a digest from a request, answering DIGEST_INVALID.
func parseDigest(s string) (blob.Digest, error) {
	d, err := blob.ParseDigest(s)
	if err != nil {
		return blob.Digest{}, newError(http.StatusBadRequest, codeDigestInvalid, "%v", err)
	}
	return d, nil
}

// view returns a metadata view that the caller must release.
func (h *Handler) view() meta.View { return h.meta.View() }

// commit commits b, mapping store failures to errors.
func (h *Handler) commit(ctx context.Context, b *meta.Batch) error {
	_, err := h.meta.Commit(ctx, b)
	return err
}

// clientActor names a request's principal by its client address.
func clientActor(r *http.Request) string {
	if ip := server.Info(r.Context()).ClientIP; ip.IsValid() {
		return "client " + ip.String()
	}
	return "anonymous"
}

func (h *Handler) origin(r *http.Request, action, target string) meta.Origin {
	return meta.Origin{Actor: h.actor(r), Action: action, Target: target}
}

// abbrev shortens s for error messages.
func abbrev(s string) string {
	const max = 100
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}

// errRetry means a link batch lost a race with garbage collection and the
// client should retry.
var errRetry = newError(http.StatusServiceUnavailable, codeUnavailable,
	"the registry is reclaiming this content; retry the request")

// storeError maps a metadata store failure to a response error.
func storeError(err error) error {
	switch {
	case errors.Is(err, meta.ErrPoisoned), errors.Is(err, meta.ErrClosed):
		return newError(http.StatusServiceUnavailable, codeUnavailable, "the registry cannot accept writes now")
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return err
	}
	return fmt.Errorf("metadata commit: %w", err)
}
