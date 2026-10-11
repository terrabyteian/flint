// Package oci serves hosted and proxy OCI repositories over the OCI
// Distribution Spec v1.1 API at /v2/: blob pulls, monolithic, chunked,
// and streamed uploads, cross-repository mounts, manifests (OCI image
// manifests and indexes, Docker schema 2 manifests and manifest lists),
// the referrers API, paginated tag and catalog listings, and deletes.
// Proxy repositories cache an upstream registry and are read-only; see
// proxy.go. Virtual repositories serve one view of hosted and proxy
// repositories, and pass pushes to a hosted one; see virtual.go. Hosted
// repositories with helmIndex also serve the Helm charts
// pushed to them as a classic Helm chart repository at /helm/; see
// helm.go.
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
	"github.com/terrabyteian/flint/internal/repo"
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

// VirtualAuthorizer is an optional extension of Authorizer for virtual
// repositories. AuthorizeVirtual is Authorize for virtual, a full
// repository name within a virtual repository, such as
// "docker-all/team/app": pulling needs pull on virtual, and pushing and
// deleting need push and delete on publishTo, the same image name within
// the virtual repository's publishTo member, such as
// "docker-local/team/app". A challenge names the scope on virtual, which
// is what Docker clients ask a token service for. With an Authorizer that
// does not implement it, each action is authorized with Authorize on the
// repository whose permissions govern it.
type VirtualAuthorizer interface {
	AuthorizeVirtual(w http.ResponseWriter, r *http.Request, virtual, publishTo string, actions ...string) bool
}

// AllowAll is an Authorizer that allows every request, for tests.
type AllowAll struct{}

// Authorize allows the request.
func (AllowAll) Authorize(http.ResponseWriter, *http.Request, string, ...string) bool { return true }

// AuthorizeVirtual allows the request.
func (AllowAll) AuthorizeVirtual(http.ResponseWriter, *http.Request, string, string, ...string) bool {
	return true
}

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
	// "oci" are served.
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
	// Fetcher, if set, fetches proxied blobs, shared with other formats'
	// proxy repositories; nil means a new one with FetchIdleTimeout.
	Fetcher *upstream.Fetcher
	// ProxyMetrics, if set, are the proxy metrics shared with other
	// formats' proxy repositories; nil registers them on Metrics, with
	// the fetches in flight and, with a proxy repository, the disk
	// pressure of Space.
	ProxyMetrics *upstream.Metrics
	// Authorizer authorizes every request. Required.
	Authorizer Authorizer
	// HelmAuthorizer, if set, authorizes the Helm view's requests instead,
	// so they can be answered in the challenge style Helm clients expect:
	// they send HTTP basic credentials and know no token service.
	HelmAuthorizer Authorizer
	// Logger receives failures; nil means slog.Default().
	Logger *slog.Logger
	// Metrics, if set, receives the OCI metrics.
	Metrics *metrics.Registry
	// VirtualMetrics, if set, are the virtual repository metrics shared
	// with other formats' virtual repositories; nil registers them on
	// Metrics.
	VirtualMetrics *repo.Metrics
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
	helmIndex     bool          // serve the Helm view
	proxy         *proxyRepo    // for a proxy repository
	virtual       *repo.Virtual // for a virtual repository
}

// Handler serves the OCI distribution API.
type Handler struct {
	meta  meta.Store
	blobs blob.Store
	repos map[string]*repository
	auth  Authorizer
	// helmAuth authorizes the Helm view: Options.HelmAuthorizer, or auth.
	helmAuth Authorizer
	log      *slog.Logger
	actor    func(*http.Request) string
	now      func() time.Time

	// Blob links' reads, which garbage collection counts like link times,
	// and when the handler started, before which it knows no reads; see
	// GCPruner.
	linkMu    sync.Mutex
	linkReads map[string]time.Time // by blob link key
	started   time.Time

	uploadBytes   *metrics.Counter
	manifestPuts  *metrics.Counter
	linkConflicts *metrics.CounterSeries

	// Proxy repositories.
	hasProxy      bool
	fetcher       *upstream.Fetcher
	space         *upstream.Space
	tagCalls      upstream.Group[*proxied]
	manifestCalls upstream.Group[*proxied]
	validated     *upstream.Freshness // by tag key: when the upstream last confirmed it
	listings      listingCache
	limits        *upstream.Limits

	// Virtual repositories: the member that last served each image
	// name's manifest, and the proxy members' recent not-found answers.
	suppliers suppliers
	misses    *upstream.NegativeCache

	// The Helm view.
	helmMu     sync.Mutex
	helmViews  map[string]*helmView // by repository and path; only views with charts
	helmBuilds upstream.Group[*helmView]

	proxyResults   *metrics.Counter
	upstreamErrors *metrics.Counter
	upstreamBytes  *metrics.Counter

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
		helmAuth:  opts.HelmAuthorizer,
		log:       opts.Logger,
		actor:     opts.Actor,
		now:       opts.Now,
		space:     opts.Space,
		fetcher:   opts.Fetcher,
		linkReads: map[string]time.Time{},
		helmViews: map[string]*helmView{},
	}
	if h.log == nil {
		h.log = slog.Default()
	}
	if h.helmAuth == nil {
		h.helmAuth = h.auth
	}
	if h.fetcher == nil {
		h.fetcher = upstream.NewFetcher(opts.Blobs, opts.FetchIdleTimeout)
	}
	if h.now == nil {
		h.now = time.Now
	}
	h.started = h.now()
	if h.actor == nil {
		h.actor = clientActor
	}
	h.validated = upstream.NewFreshness(h.now)
	h.misses = upstream.NewNegativeCache(h.now)
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
			h.repos[rc.Name] = &repository{name: rc.Name, immutableTags: rc.ImmutableTags, helmIndex: rc.HelmIndex}
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
	vm := opts.VirtualMetrics
	for _, rc := range opts.Repositories {
		if rc.Format != config.FormatOCI || rc.Type != config.TypeVirtual {
			continue
		}
		if vm == nil {
			vm = repo.NewMetrics(reg)
		}
		v, err := repo.NewVirtual(rc, opts.Repositories, repo.VirtualOptions{Logger: h.log, Metrics: vm})
		if err != nil {
			return nil, fmt.Errorf("oci: %w", err)
		}
		h.repos[rc.Name] = &repository{name: rc.Name, virtual: v}
	}
	h.uploadBytes = reg.Counter("flint_oci_upload_bytes_total",
		"Blob bytes received in OCI uploads, by repository.", "repository")
	h.manifestPuts = reg.Counter("flint_oci_manifest_pushes_total",
		"Manifests pushed, by repository.", "repository")
	h.linkConflicts = reg.Counter("flint_oci_link_retries_total",
		"Link batches retried after a metadata precondition failed.").With()
	pm := opts.ProxyMetrics
	if pm == nil {
		space := h.space
		if !h.hasProxy {
			space = nil
		}
		pm = upstream.NewMetrics(reg, h.fetcher, space)
	}
	h.proxyResults = pm.Requests
	h.upstreamErrors = pm.UpstreamErrors
	h.upstreamBytes = pm.UpstreamBytes
	h.limits = upstream.NewLimits(upstream.LimitsOptions{Meta: h.meta, Metrics: pm, Format: "oci", PulledKey: pulledKey,
		EvictMore: func(v meta.View, b *meta.Batch, repo, key string, rec meta.Record) {
			if strings.HasPrefix(key, nsManifest) {
				evictManifestRefs(v, b, h.repos[repo], key, rec)
			}
		}, Evicted: func(keys []string) { h.forgetLinkReads(keys...) }, Now: h.now})
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
	for _, rc := range h.repos {
		if rc.proxy == nil || rc.proxy.cache == nil {
			continue
		}
		c := rc.proxy.cache
		if err := h.loadTracker(c, v); err != nil {
			return fmt.Errorf("oci: loading the cache of proxy repository %s: %w", c.Repo(), err)
		}
		h.limits.Add(c)
	}
	return nil
}

// Register mounts the handler at /v2/ on a server, and the Helm view at
// /helm/.
func (h *Handler) Register(s interface{ Handle(string, http.Handler) }) {
	s.Handle("/v2/", h)
	s.Handle("/helm/", http.HandlerFunc(h.serveHelm))
}

// repoName is a parsed, validated repository name.
type repoName struct {
	full string // as addressed: "docker-local/team/app"
	repo string // the configured repository: "docker-local"
	name string // the image name below it: "team/app"
	cfg  *repository
	// addr, if set, is the name the client addressed instead of full, for
	// a member of a virtual repository serving it: "docker-all/team/app".
	// The locations returned to the client use it.
	addr string
}

// path returns the name the client addresses: addr, or else full.
func (rn *repoName) path() string {
	if rn.addr != "" {
		return rn.addr
	}
	return rn.full
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
	ops := h.hostedOps(ep)
	o, ok := ops[r.Method]
	if !ok {
		allowOps(w, r, h, ops)
		return
	}
	if rn.cfg.virtual != nil {
		h.serveVirtual(w, r, rn, ep, arg, o)
		return
	}
	if !h.auth.Authorize(w, r, rn.full, o.actions...) {
		return
	}
	o.serve(w, r, rn, arg)
}

// op is how a hosted repository serves a method of an endpoint.
type op struct {
	actions []string // the actions to authorize
	serve   func(http.ResponseWriter, *http.Request, *repoName, string)
}

// hostedOps returns how a hosted repository serves each method of ep.
func (h *Handler) hostedOps(ep endpoint) map[string]op {
	push := []string{ActionPull, ActionPush}
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
	return ops
}

// allowOps answers 405 for a method that is not one of ops'.
func allowOps(w http.ResponseWriter, r *http.Request, h *Handler, ops map[string]op) {
	methods := make([]string, 0, len(ops))
	for m := range ops {
		methods = append(methods, m)
	}
	allow(w, r, h, methods...)
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
	return meta.ActorAnonymous
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
