// Package maven serves Maven repositories in the Maven 2 repository
// layout that Maven, Gradle, sbt, and other JVM build tools use: hosted
// repositories that clients deploy to with PUT, proxy repositories that
// cache an upstream such as Maven Central, and virtual repositories that
// merge hosted and proxy repositories behind one URL with
// dependency-confusion protection.
//
// Each repository is served under /maven/<repo>/:
//
//	GET, HEAD /maven/<repo>/<group path>/<artifactId>/<version>/<file>   artifact file
//	GET, HEAD /maven/<repo>/<path>.md5|.sha1|.sha256|.sha512             checksum sidecar
//	GET, HEAD /maven/<repo>/<group path>/<artifactId>/maven-metadata.xml  versions
//	GET, HEAD /maven/<repo>/<...>/<version>-SNAPSHOT/maven-metadata.xml   snapshot files
//	GET, HEAD /maven/<repo>/<group path>/maven-metadata.xml              plugin prefixes
//	PUT       /maven/<repo>/<path>                                       deploy
//	DELETE    /maven/<repo>/<path> or <version directory>/               delete
//
// flint owns maven-metadata.xml in hosted repositories: it generates it
// from its records, and accepts and discards the copies clients upload,
// keeping only plugin prefixes, so concurrent deploys never clobber each
// other's versions. Checksum sidecars are served from the digests flint
// computed itself, and artifact responses carry them in X-Checksum-*
// headers, which Maven reads instead of fetching sidecars.
//
// File bytes live once in the blob store, keyed by their sha256 digest;
// the metadata store records which repository has which file (see
// records.go). Every request is authorized through an Authorizer that
// answers refusals with a Basic challenge, which Maven and Gradle wait
// for before they send credentials.
package maven

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/terrabyteian/flint/internal/blob"
	"github.com/terrabyteian/flint/internal/config"
	"github.com/terrabyteian/flint/internal/meta"
	"github.com/terrabyteian/flint/internal/metrics"
	"github.com/terrabyteian/flint/internal/repo"
	"github.com/terrabyteian/flint/internal/server"
	"github.com/terrabyteian/flint/internal/upstream"
)

// Actions an Authorizer checks.
const (
	ActionPull   = "pull"
	ActionPush   = "push"
	ActionDelete = "delete"
)

// Authorizer decides whether a request may act on a repository, and
// answers it when it may not.
type Authorizer interface {
	// Authorize reports whether the request may perform every action on
	// repository repo; when it may not, it has written the response: 401
	// with a Basic challenge if the request has no valid credentials, or
	// 403. When it may, it records the principal for the actor.
	Authorize(w http.ResponseWriter, r *http.Request, repo string, actions ...string) bool
	// AuthorizeVirtual is Authorize for a virtual repository: pulling
	// needs read on it only, and pushing and deleting need write and
	// delete on publishTo.
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

// Options configures a Handler.
type Options struct {
	// Meta and Blobs are the stores. Required.
	Meta  meta.Store
	Blobs blob.Store
	// Repositories are the configured repositories; those with format
	// "maven" are served.
	Repositories []config.Repository
	// Authorizer authorizes every request. Required.
	Authorizer Authorizer
	// Upstream holds the defaults for proxy repositories' upstream
	// clients, such as the user agent.
	Upstream upstream.Options
	// Space, if set, watches the data directory's free space, so proxy
	// repositories stop caching new content when it runs low.
	Space *upstream.Space
	// Fetcher fetches files into the cache, shared with other formats'
	// proxy repositories; nil means a new one.
	Fetcher *upstream.Fetcher
	// ProxyMetrics are the proxy metrics shared with other formats; nil
	// registers them on Metrics.
	ProxyMetrics *upstream.Metrics
	// Docs caches maven-metadata.xml, shared with other formats' proxy
	// repositories; nil means a new one, which RunProxy prunes.
	Docs *upstream.DocCache
	// VirtualMetrics are the virtual repository metrics shared with other
	// formats; nil registers them on Metrics.
	VirtualMetrics *repo.Metrics
	// Logger receives failures; nil means slog.Default().
	Logger *slog.Logger
	// Metrics, if set, receives the Maven metrics.
	Metrics *metrics.Registry
	// Actor names the principal behind a request in the origin of the
	// metadata batches it writes; nil names the client address.
	Actor func(*http.Request) string
	// Now is the clock; nil means time.Now.
	Now func() time.Time
}

// repository is a configured Maven repository.
type repository struct {
	name    string
	typ     string        // config.TypeHosted, TypeProxy, or TypeVirtual
	policy  string        // a hosted repository's version policy
	proxy   *proxyRepo    // for a proxy repository
	virtual *repo.Virtual // for a virtual repository
}

// Handler serves Maven repositories.
type Handler struct {
	meta  meta.Store
	blobs blob.Store
	repos map[string]*repository
	auth  Authorizer
	log   *slog.Logger
	actor func(*http.Request) string
	now   func() time.Time

	deploys     *metrics.Counter
	deployBytes *metrics.Counter

	// Proxy repositories.
	pc      *upstream.PathCache
	pm      *upstream.Metrics
	docs    *upstream.DocCache
	ownDocs bool // docs is this handler's own, which it prunes
	neg     *upstream.NegativeCache
	docMemo docMemo
	maxWin  time.Duration // the longest revalidation window
}

// New returns a Handler.
func New(opts Options) (*Handler, error) {
	if opts.Meta == nil || opts.Blobs == nil {
		return nil, errors.New("maven: Meta and Blobs are required")
	}
	if opts.Authorizer == nil {
		return nil, errors.New("maven: an Authorizer is required")
	}
	h := &Handler{meta: opts.Meta, blobs: opts.Blobs, repos: map[string]*repository{}, auth: opts.Authorizer,
		log: opts.Logger, actor: opts.Actor, now: opts.Now, docs: opts.Docs}
	if h.log == nil {
		h.log = slog.Default()
	}
	if h.now == nil {
		h.now = time.Now
	}
	if h.actor == nil {
		h.actor = clientActor
	}
	fetcher := opts.Fetcher
	if fetcher == nil {
		fetcher = upstream.NewFetcher(opts.Blobs, 0)
	}
	upOpts := opts.Upstream
	if upOpts.Logger == nil {
		upOpts.Logger = h.log
	}
	if upOpts.Now == nil {
		upOpts.Now = h.now
	}
	reg := opts.Metrics
	if reg == nil {
		reg = metrics.NewRegistry() // unexposed; keeps the counters usable
	}
	vm := opts.VirtualMetrics
	if vm == nil {
		vm = repo.NewMetrics(reg)
	}
	pm := opts.ProxyMetrics
	hasProxy := false
	for _, rc := range opts.Repositories {
		hasProxy = hasProxy || rc.Format == config.FormatMaven && rc.Type == config.TypeProxy
	}
	if pm == nil {
		space := opts.Space
		if !hasProxy {
			space = nil
		}
		pm = upstream.NewMetrics(reg, fetcher, space)
	}
	if h.docs == nil {
		h.docs = upstream.NewDocCache(upstream.DocCacheOptions{Meta: h.meta, Blobs: h.blobs, Space: opts.Space,
			Metrics: pm, Logger: h.log, Now: h.now})
		h.ownDocs = true
	}
	h.pm = pm
	h.pc = upstream.NewPathCache(upstream.PathCacheOptions{Meta: h.meta, Blobs: h.blobs, Fetcher: fetcher, Docs: h.docs,
		Space: opts.Space, Metrics: pm, Logger: h.log, Now: h.now})
	h.neg = upstream.NewNegativeCache(h.now)
	for _, rc := range opts.Repositories {
		if rc.Format != config.FormatMaven {
			continue
		}
		r := &repository{name: rc.Name, typ: rc.Type}
		switch rc.Type {
		case config.TypeHosted:
			r.policy = rc.Maven.Policy()
		case config.TypeProxy:
			if rc.Proxy == nil {
				return nil, fmt.Errorf("maven: proxy repository %s has no upstream", rc.Name)
			}
			p, err := newProxyRepo(rc, upOpts)
			if err != nil {
				return nil, fmt.Errorf("maven: proxy repository %s: %w", rc.Name, err)
			}
			if err := h.pc.Add(p.pr); err != nil {
				return nil, err
			}
			r.proxy = p
			h.maxWin = max(h.maxWin, p.pr.Revalidate)
		case config.TypeVirtual:
			v, err := repo.NewVirtual(rc, opts.Repositories, repo.VirtualOptions{Normalize: normalizeName, Logger: h.log, Metrics: vm})
			if err != nil {
				return nil, err
			}
			r.virtual = v
		default:
			return nil, fmt.Errorf("maven: repository %s has unsupported type %q", rc.Name, rc.Type)
		}
		h.repos[rc.Name] = r
	}
	h.deploys = reg.Counter("flint_maven_deploys_total",
		"Files deployed to hosted Maven repositories, by repository; identical re-uploads are not counted.", "repository")
	h.deployBytes = reg.Counter("flint_maven_deploy_bytes_total",
		"Bytes of files deployed to hosted Maven repositories, by repository.", "repository")
	return h, nil
}

// Register mounts the handler at /maven/ on a server.
func (h *Handler) Register(s interface{ Handle(string, http.Handler) }) {
	s.Handle(repo.Prefix(config.FormatMaven), h)
}

// ServeHTTP routes a /maven/ request.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	name, sub, slash, _ := repo.Split(config.FormatMaven, r.URL.Path)
	rp := h.repos[name]
	if rp == nil {
		// Repositories of other formats are not found here either.
		server.SetRoute(ctx, "maven.unknown")
		writeError(w, http.StatusNotFound, "%q is not a Maven repository on this server", abbrev(name))
		return
	}
	server.LogAttrs(ctx, slog.String("repository", name))
	mp, ok := parsePath(sub)
	if !slash || !ok {
		server.SetRoute(ctx, "maven.unknown")
		if r.Method == http.MethodPut {
			writeError(w, http.StatusBadRequest, "%q is not a valid path in a Maven repository", abbrev(sub))
			return
		}
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	switch mp.kind {
	case kindFile:
		server.SetRoute(ctx, "maven.file")
	case kindMetadata:
		server.SetRoute(ctx, "maven.metadata")
	case kindSidecar:
		server.SetRoute(ctx, "maven.checksum")
	default:
		server.SetRoute(ctx, "maven.other")
	}
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		if !h.authorize(w, r, rp, ActionPull) {
			return
		}
		switch rp.typ {
		case config.TypeHosted:
			h.serveHosted(w, r, rp, mp)
		case config.TypeProxy:
			h.serveProxy(w, r, rp, mp)
		default:
			h.serveVirtual(w, r, rp, mp)
		}
	case http.MethodPut:
		h.servePut(w, r, rp, mp)
	case http.MethodDelete:
		h.serveDelete(w, r, rp, mp)
	default:
		w.Header().Set("Allow", "GET, HEAD, PUT, DELETE")
		writeError(w, http.StatusMethodNotAllowed, "method %s is not allowed here", r.Method)
	}
}

// normalizeName is how virtual repositories compare artifact names,
// groupId:artifactId, with their members' filters: ":" and "." are one
// separator, so the filter com.acme.* matches the artifacts of group
// com.acme, such as com.acme:lib, and of its subgroups, such as
// com.acme.tools:cli.
func normalizeName(s string) string { return strings.ReplaceAll(s, ":", ".") }

// authorize authorizes the request for actions on rp, writing the
// response when it is refused. On a virtual repository, pushing and
// deleting are checked on its publishTo member.
func (h *Handler) authorize(w http.ResponseWriter, r *http.Request, rp *repository, actions ...string) bool {
	if rp.typ == config.TypeVirtual {
		return h.auth.AuthorizeVirtual(w, r, rp.name, rp.virtual.PublishTo, actions...)
	}
	return h.auth.Authorize(w, r, rp.name, actions...)
}

// writeError writes a plain-text error, which Maven and Gradle show.
func writeError(w http.ResponseWriter, status int, format string, args ...any) {
	hd := w.Header()
	hd.Del("Content-Length")
	for k := range hd {
		if strings.HasPrefix(k, "X-Checksum-") {
			hd.Del(k)
		}
	}
	hd.Del("ETag")
	hd.Del("Last-Modified")
	hd.Set("Content-Type", "text/plain; charset=utf-8")
	hd.Set("X-Content-Type-Options", "nosniff")
	hd.Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	fmt.Fprintf(w, format+"\n", args...)
}

// writeProxyError writes a proxy's error response.
func writeProxyError(w http.ResponseWriter, _ *http.Request, status int, msg string) {
	writeError(w, status, "%s", msg)
}

// httpError is an error with the response to answer it with.
type httpError struct {
	status int
	msg    string
}

func (e *httpError) Error() string { return e.msg }

func errorf(status int, format string, args ...any) error {
	return &httpError{status: status, msg: fmt.Sprintf(format, args...)}
}

// errRetry means a batch lost a race with garbage collection or another
// writer and the client should retry.
var errRetry = errorf(http.StatusServiceUnavailable, "the registry is busy with this content; retry the request")

// fail answers a request with err: its own response for an *httpError,
// nothing for a cancelled request, and 500 otherwise.
func (h *Handler) fail(w http.ResponseWriter, r *http.Request, err error) {
	var he *httpError
	switch {
	case errors.As(err, &he):
		if he.status == http.StatusServiceUnavailable {
			w.Header().Set("Retry-After", "1")
		}
		writeError(w, he.status, "%s", he.msg)
	case r.Context().Err() != nil:
		// The client went away.
	case errors.Is(err, meta.ErrPoisoned), errors.Is(err, meta.ErrClosed):
		writeError(w, http.StatusServiceUnavailable, "the registry cannot accept writes now")
	default:
		h.log.ErrorContext(r.Context(), "maven request failed", "path", r.URL.Path, "err", err)
		writeError(w, http.StatusInternalServerError, "internal error")
	}
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

// abbrev shortens s for messages.
func abbrev(s string) string {
	const max = 100
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}

// Content types.
const (
	ctXML      = "text/xml"
	ctChecksum = "text/plain; charset=utf-8"
)

// contentType returns the media type of a file, by its extension.
func contentType(name string) string {
	switch path.Ext(name) {
	case ".pom", ".xml":
		return ctXML
	case ".jar", ".war", ".ear", ".aar", ".rar":
		return "application/java-archive"
	case ".module", ".json":
		return "application/json"
	case ".asc":
		return "application/pgp-signature"
	case ".zip":
		return "application/zip"
	case ".gz", ".tgz":
		return "application/gzip"
	}
	return "application/octet-stream"
}

// digests are a file's digests in every sidecar algorithm, raw.
type digests struct {
	md5, sha1, sha256, sha512 []byte
}

// digestsOf computes the digests of b.
func digestsOf(b []byte) digests {
	m, s1, s256, s512 := md5.Sum(b), sha1.Sum(b), sha256.Sum256(b), sha512.Sum512(b)
	return digests{m[:], s1[:], s256[:], s512[:]}
}

// get returns the digest of algorithm alg, or nil.
func (d digests) get(alg string) []byte {
	switch alg {
	case algMD5:
		return d.md5
	case algSHA1:
		return d.sha1
	case algSHA256:
		return d.sha256
	case algSHA512:
		return d.sha512
	}
	return nil
}

// setHeaders sets the X-Checksum headers of a response.
func (d digests) setHeaders(w http.ResponseWriter) {
	for _, x := range []struct {
		name string
		sum  []byte
	}{{"X-Checksum-MD5", d.md5}, {"X-Checksum-SHA1", d.sha1}, {"X-Checksum-SHA256", d.sha256}, {"X-Checksum-SHA512", d.sha512}} {
		if len(x.sum) > 0 {
			w.Header().Set(x.name, hex.EncodeToString(x.sum))
		}
	}
}

// serveChecksum answers a sidecar request with sum, as Maven writes
// sidecars: the hex digest alone.
func serveChecksum(w http.ResponseWriter, r *http.Request, sum []byte) {
	b := []byte(hex.EncodeToString(sum))
	w.Header().Set("Content-Type", ctChecksum)
	w.Header().Set("Content-Length", strconv.Itoa(len(b)))
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		w.Write(b)
	}
}

// serveDocument answers a request with a document flint generated or
// merged, with its checksum headers.
func serveDocument(w http.ResponseWriter, r *http.Request, b []byte) {
	digestsOf(b).setHeaders(w)
	w.Header().Set("Content-Type", ctXML)
	w.Header().Set("Content-Length", strconv.Itoa(len(b)))
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		w.Write(b)
	}
}

// serveDocumentChecksum answers a request for a sidecar of a document.
func serveDocumentChecksum(w http.ResponseWriter, r *http.Request, b []byte, alg string) {
	serveChecksum(w, r, digestsOf(b).get(alg))
}
