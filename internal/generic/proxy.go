package generic

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/terrabyteian/flint/internal/config"
	"github.com/terrabyteian/flint/internal/upstream"
)

// proxyRepo is a proxy repository's upstream: any base URL, under which
// a request for <path> fetches <base><path>.
type proxyRepo struct {
	base      *url.URL // ending in "/"
	immutable bool     // generic.immutable: files are cached forever
	path      *upstream.PathRepo
}

// noSizeLimit bounds a file a proxy repository revalidates, which the
// document cache would otherwise bound like a package listing.
const noSizeLimit = 1 << 50

func newProxyRepo(rc config.Repository, defaults upstream.Options) (*proxyRepo, error) {
	pc := rc.Proxy
	base, err := url.Parse(pc.URL)
	if err != nil {
		return nil, err
	}
	if !strings.HasSuffix(base.Path, "/") {
		base.Path += "/"
		base.RawPath = ""
	}
	p := &proxyRepo{base: base, immutable: rc.Generic != nil && rc.Generic.Immutable}
	opts := defaults
	opts.URL = base.String()
	opts.Username, opts.PasswordFile = pc.Username, pc.PasswordFile
	opts.MaxConcurrent = pc.MaxConcurrent
	opts.Policy = upstream.Policy{AllowHosts: pc.AllowHosts}
	client, err := upstream.New(opts)
	if err != nil {
		return nil, err
	}
	revalidate := pc.RevalidateAfter.Duration
	if revalidate <= 0 {
		revalidate = config.DefaultRevalidateAfter
	}
	p.path = &upstream.PathRepo{Name: rc.Name, Format: config.FormatGeneric, Client: client, Revalidate: revalidate,
		WriteError: writeErrorMsg}
	if p.immutable {
		// Only files cached forever count against a size limit; the
		// configuration refuses one without generic.immutable.
		p.path.SizeLimit = pc.SizeLimit.Bytes
	}
	return p, nil
}

// route says how the path cache serves the file at path p: fetched from
// the upstream once and cached forever with generic.immutable, and
// otherwise kept as a document of the proxy cache and revalidated after
// the repository's window, since flint cannot know whether a path of an
// arbitrary upstream changes.
func (p *proxyRepo) route(path string) *upstream.Route {
	u := *p.base
	u.Path += path
	u.RawPath = ""
	rt := &upstream.Route{Kind: upstream.Mutable, Path: path, URL: u.String(), MaxSize: noSizeLimit}
	if p.immutable {
		rt.Kind, rt.Expect = upstream.Immutable, upstream.Expect{Size: -1}
	}
	return rt
}

// proxyFile serves GET and HEAD of the file at path p of proxy
// repository rp.
func (h *Handler) proxyFile(w http.ResponseWriter, r *http.Request, rp *repository, p string) {
	setFileHeaders(w.Header())
	h.paths.Serve(w, r, rp.proxy.path, rp.proxy.route(p), h.actor(r))
}
