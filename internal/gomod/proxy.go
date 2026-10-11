package gomod

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/terrabyteian/flint/internal/config"
	"github.com/terrabyteian/flint/internal/meta"
	"github.com/terrabyteian/flint/internal/repo"
	"github.com/terrabyteian/flint/internal/sumdb"
	"github.com/terrabyteian/flint/internal/upstream"
)

// A proxy repository caches one upstream module proxy, and the checksum
// database, on the shared path-cache engine:
//
//   - A canonical version's .info, .mod, and .zip never change, as the
//     GOPROXY protocol requires of a proxy, so they are cached forever.
//     Before a .mod or .zip is cached, or a client receives its final
//     byte, its h1: hash is computed from the fetched bytes and compared
//     with the module version's record in the checksum database;
//     content that does not match is never cached. Modules matching the
//     repository's go.noSumCheck patterns are cached unverified. A
//     canonical .info must name its version.
//   - A module's version list, its @latest, and the .info answering a
//     query that is not a canonical version, such as a branch name, are
//     documents, revalidated after the repository's revalidateAfter. A
//     query's answer naming a canonical version is also cached as that
//     version's .info, so a build that resolved a branch online finds
//     the version's .info offline.
//   - The checksum database's lookups and tiles never change, so they
//     are cached forever. A lookup is cached, and its record trusted,
//     only once it is proven as the go command proves it: the
//     database's public key verifies the signature of its tree head,
//     the database's tiles prove that the tree contains the record, and
//     that the tree is consistent with the latest tree head the
//     repository has seen since flint started. The partial tiles of
//     that latest tree are kept in memory, so records of it, and of the
//     trees before it, are proven without fetching them again; a
//     partial tile is never cached. A full tile is cached once it is
//     proven, read from the cache by every proof that needs it, and
//     fetched again and replaced if the cached copy fails its proof.
//     The signed tree head (latest) is a document revalidated
//     every minute, replaced only by one proven consistent with it. The
//     database is fetched from go.sumdb.url, not from the module proxy,
//     which need not proxy it.
//   - An upstream 404 or 410 is passed on as it is, so the go command
//     falls back to the next GOPROXY entry as it would from any proxy.

// sumdbRevalidate is how long the checksum database's tree head is
// served before it is fetched again.
const sumdbRevalidate = time.Minute

// Bounds on what the handler reads into memory.
const (
	maxInfo   = 1 << 20   // a .info or @latest answer
	maxList   = 16 << 20  // a version list
	maxLookup = 64 << 10  // a checksum database lookup
	maxNote   = 64 << 10  // the checksum database's tree head
	maxTile   = 8 << 10   // a tile of the checksum database: 256 hashes
	maxZip    = 500 << 20 // a module zip, as the go command bounds it
)

// Media types served.
const (
	ctText = "text/plain; charset=utf-8"
	ctJSON = "application/json"
	ctZip  = "application/zip"
)

// proxyRepo is the upstream side of a proxy repository.
type proxyRepo struct {
	path *upstream.PathRepo
	// base is the module proxy's URL, without a trailing "/".
	base string
	// sumdb fetches the checksum database at sumdbURL, whose key
	// verifies its notes.
	sumdb      *upstream.Client
	sumdbURL   string
	verifier   *sumdb.Verifier
	noSumCheck []string

	// latest proves the latest tree head of the checksum database seen,
	// or is nil; every tree head trusted is consistent with it.
	mu     sync.Mutex
	latest *sumdb.Prover
}

func newProxyRepo(rc config.Repository, defaults upstream.Options) (*proxyRepo, error) {
	pc := rc.Proxy
	p := &proxyRepo{base: strings.TrimRight(pc.URL, "/"), sumdbURL: config.GoSumDBURL(rc.Go)}
	if rc.Go != nil {
		p.noSumCheck = rc.Go.NoSumCheck
	}
	var err error
	if p.verifier, err = sumdb.ParseKey(config.GoSumDBKey(rc.Go)); err != nil {
		return nil, err
	}
	opts := defaults
	opts.URL = p.base
	opts.Username, opts.PasswordFile = pc.Username, pc.PasswordFile
	opts.MaxConcurrent = pc.MaxConcurrent
	opts.Policy = upstream.Policy{AllowHosts: pc.AllowHosts}
	client, err := upstream.New(opts)
	if err != nil {
		return nil, err
	}
	// The checksum database is public: it never gets the upstream's
	// credentials.
	opts.URL, opts.Username, opts.PasswordFile = p.sumdbURL, "", ""
	if p.sumdb, err = upstream.New(opts); err != nil {
		return nil, err
	}
	revalidate := pc.RevalidateAfter.Duration
	if revalidate <= 0 {
		revalidate = config.DefaultRevalidateAfter
	}
	p.path = &upstream.PathRepo{Name: rc.Name, Format: config.FormatGo, Client: client, Revalidate: revalidate,
		SizeLimit: pc.SizeLimit.Bytes, WriteError: func(w http.ResponseWriter, _ *http.Request, status int, msg string) {
			writeError(w, status, "%s", msg)
		}}
	return p, nil
}

// checked reports whether modules of path are verified against the
// checksum database.
func (p *proxyRepo) checked(path string) bool {
	for _, pat := range p.noSumCheck {
		if repo.Match(pat, path) {
			return false
		}
	}
	return true
}

// route returns the route of a module request in p; the caller checked
// that .mod and .zip requests name canonical versions.
func (h *Handler) route(p *proxyRepo, req *request, actor string) *upstream.Route {
	path := req.escMod + "/@latest"
	if req.kind != kindLatest {
		path = req.escMod + "/@v/list"
		if req.kind != kindList {
			path = req.escMod + "/@v/" + req.escVer + "." + req.kind
		}
	}
	rt := &upstream.Route{Path: path, URL: p.base + "/" + path, Expect: upstream.Expect{Size: -1}, KeepGone: true}
	switch req.kind {
	case kindList:
		rt.Kind, rt.ContentType, rt.MaxSize = upstream.Mutable, ctText, maxList
	case kindLatest:
		rt.Kind, rt.ContentType, rt.MaxSize = upstream.Mutable, ctJSON, maxInfo
		rt.Validate, rt.Also = h.validInfo, h.alsoInfo(req.escMod)
	case kindInfo:
		rt.ContentType = ctJSON
		if !canonical(req.ver) {
			rt.Kind, rt.MaxSize = upstream.Mutable, maxInfo
			rt.Validate, rt.Also = h.validInfo, h.alsoInfo(req.escMod)
			break
		}
		rt.Kind, rt.Expect.Check = upstream.Immutable, checkInfo(req.ver)
	case kindMod, kindZip:
		rt.Kind, rt.ContentType = upstream.Immutable, ctText
		if req.kind == kindZip {
			rt.ContentType = ctZip
		}
		if p.checked(req.mod) {
			rt.Expect.Check = h.checkSum(p, req, actor)
		}
	}
	return rt
}

// info is what the handler reads of a .info or @latest answer.
type info struct {
	Version string
}

// readInfo decodes a .info or @latest answer.
func readInfo(b []byte) (*info, error) {
	var i info
	if err := json.Unmarshal(b, &i); err != nil {
		return nil, fmt.Errorf("not a version's metadata: %v", err)
	}
	if !validVersion(i.Version) {
		return nil, fmt.Errorf("not a version's metadata: the version %q is not valid", i.Version)
	}
	return &i, nil
}

// readDoc reads a document, at most max bytes.
func (h *Handler) readDoc(ctx context.Context, d *upstream.Doc, max int64) ([]byte, error) {
	if d.Size > max {
		return nil, fmt.Errorf("%w: a document of %d bytes", upstream.ErrTooLarge, d.Size)
	}
	f, err := h.docs.Open(ctx, d)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b := make([]byte, d.Size)
	if _, err := io.ReadFull(f, b); err != nil {
		return nil, err
	}
	return b, nil
}

// validInfo checks a newly fetched @latest or query answer: one flint
// cannot read never replaces the cached one.
func (h *Handler) validInfo(ctx context.Context, d *upstream.Doc) error {
	b, err := h.readDoc(ctx, d, maxInfo)
	if err == nil {
		_, err = readInfo(b)
	}
	return err
}

// alsoInfo returns the Route.Also of a query of module escMod: the
// answer is also the .info of the version it names, if that is
// canonical.
func (h *Handler) alsoInfo(escMod string) func(ctx context.Context, d *upstream.Doc) string {
	return func(ctx context.Context, d *upstream.Doc) string {
		b, err := h.readDoc(ctx, d, maxInfo)
		if err != nil {
			return ""
		}
		i, err := readInfo(b)
		if err != nil || !canonical(i.Version) {
			return ""
		}
		return escMod + "/@v/" + escape(i.Version) + ".info"
	}
}

// checkInfo returns the Expect.Check of the .info of canonical version
// ver: it must name the version.
func checkInfo(ver string) func(ctx context.Context, r io.ReaderAt, size int64) error {
	return func(_ context.Context, r io.ReaderAt, size int64) error {
		b, err := readAt(r, size, maxInfo, "a .info file")
		if err != nil {
			return err
		}
		i, err := readInfo(b)
		if err != nil {
			return fmt.Errorf("%w: %v", upstream.ErrDigestMismatch, err)
		}
		if i.Version != ver {
			return fmt.Errorf("%w: the .info of %s names version %s", upstream.ErrDigestMismatch, ver, i.Version)
		}
		return nil
	}
}

// checkSum returns the Expect.Check of the .mod or .zip req names: its
// h1: hash must be the one the checksum database records.
func (h *Handler) checkSum(p *proxyRepo, req *request, actor string) func(ctx context.Context, r io.ReaderAt, size int64) error {
	return func(ctx context.Context, r io.ReaderAt, size int64) error {
		if req.kind == kindZip && size > maxZip {
			return fmt.Errorf("%w: a module zip of %d bytes", upstream.ErrTooLarge, size)
		}
		rec, err := h.lookup(ctx, p, req.mod, req.ver, req.escMod, req.escVer, actor)
		if err != nil {
			// Not wrapped: the checksum database's failure is no answer
			// about the module proxy's content.
			return fmt.Errorf("verifying %s@%s against the checksum database %s: %v", req.mod, req.ver, p.verifier.Name(), err)
		}
		if req.kind == kindZip {
			return upstream.CheckGoZipH1(rec.Zip)(ctx, r, size)
		}
		return upstream.CheckGoModH1(rec.Mod)(ctx, r, size)
	}
}

// lookup returns the checksum database's record of module mod at
// version ver, escaped escMod and escVer, through p's cache of the
// database.
func (h *Handler) lookup(ctx context.Context, p *proxyRepo, mod, ver, escMod, escVer, actor string) (*sumdb.Record, error) {
	rt := h.sumdbRoute(p, "lookup/"+escMod+"@"+escVer)
	rt.Expect.Check = h.checkLookup(p, mod, ver)
	b, _, err := h.paths.Read(ctx, p.path, rt, actor, maxLookup)
	if err != nil {
		return nil, err
	}
	return p.verifier.OpenLookup(b, mod, ver)
}

// checkLookup returns the Expect.Check of a lookup of module mod at
// version ver in p's checksum database: it must be the module version's
// record, with a tree head the database signed, in that tree, which must
// be consistent with the latest one p has seen.
func (h *Handler) checkLookup(p *proxyRepo, mod, ver string) func(ctx context.Context, r io.ReaderAt, size int64) error {
	return func(ctx context.Context, r io.ReaderAt, size int64) error {
		b, err := readAt(r, size, maxLookup, "a lookup")
		if err != nil {
			return err
		}
		rec, err := p.verifier.OpenLookup(b, mod, ver)
		var pt *sumdb.Prover
		if err == nil {
			pt, err = h.prover(ctx, p, rec.Tree)
		}
		if err == nil {
			err = pt.Includes(ctx, rec)
		}
		if errors.Is(err, sumdb.ErrBadNote) {
			return fmt.Errorf("%w: %v", upstream.ErrDigestMismatch, err)
		}
		return err
	}
}

// prover returns the Prover of a tree that contains tree, a tree head
// p's checksum database signed, once tree is proven consistent with the
// latest tree head p has seen: the latest's, if tree is no larger, or
// else tree's own, which becomes the latest.
func (h *Handler) prover(ctx context.Context, p *proxyRepo, tree sumdb.Tree) (*sumdb.Prover, error) {
	var pt *sumdb.Prover
	for {
		p.mu.Lock()
		latest := p.latest
		p.mu.Unlock()
		if latest != nil && tree.N <= latest.Tree().N {
			if err := latest.Consistent(ctx, tree); err != nil {
				return nil, err
			}
			return latest, nil
		}
		if pt == nil {
			var err error
			if pt, err = sumdb.NewProver(ctx, tree, h.readTile(p)); err != nil {
				return nil, err
			}
		}
		if latest != nil {
			if err := pt.Consistent(ctx, latest.Tree()); err != nil {
				return nil, err
			}
		}
		p.mu.Lock()
		if p.latest == latest {
			p.latest = pt
			p.mu.Unlock()
			return pt, nil
		}
		// Another tree became the latest meanwhile: check against it.
		p.mu.Unlock()
	}
}

// readTile returns the reader of the tiles of p's checksum database,
// which proves its answers, as flint's own work: through the cache
// clients' tile requests use for a full tile, which is cached only once
// its check passes, and fetched again and replaced if the cached copy
// fails it, and never cached for a partial one.
func (h *Handler) readTile(p *proxyRepo) sumdb.TileReader {
	return func(ctx context.Context, path string, check func([]byte) error) ([]byte, error) {
		rt := h.sumdbRoute(p, path)
		if check == nil {
			rt.Kind = upstream.PassThrough
		} else {
			rt.Recheck = true
			rt.Expect.Check = func(_ context.Context, r io.ReaderAt, size int64) error {
				b, err := readAt(r, size, maxTile, "a tile")
				if err == nil {
					if err = check(b); err != nil {
						err = fmt.Errorf("%w: %v", upstream.ErrDigestMismatch, err)
					}
				}
				return err
			}
		}
		b, _, err := h.paths.Read(ctx, p.path, rt, meta.ActorSystem, maxTile)
		return b, err
	}
}

// readAt reads content of size bytes, at most max, named what in errors.
func readAt(r io.ReaderAt, size, max int64, what string) ([]byte, error) {
	if size > max {
		return nil, fmt.Errorf("%w: %s of %d bytes", upstream.ErrTooLarge, what, size)
	}
	b := make([]byte, size)
	if _, err := r.ReadAt(b, 0); err != nil && err != io.EOF {
		return nil, err
	}
	return b, nil
}

// sumdbRoute returns the route of path below p's checksum database,
// such as "latest" or "tile/8/0/001", whose cache key is below
// "sumdb/<name>/": no module path starts with "sumdb/", since a module
// path's first element has a dot.
func (h *Handler) sumdbRoute(p *proxyRepo, path string) *upstream.Route {
	return &upstream.Route{Kind: upstream.Immutable, Path: "sumdb/" + p.verifier.Name() + "/" + path,
		URL: p.sumdbURL + "/" + path, Expect: upstream.Expect{Size: -1}, Client: p.sumdb, KeepGone: true}
}

// serveSumDB serves a checksum database request through p.
func (h *Handler) serveSumDB(w http.ResponseWriter, r *http.Request, p *proxyRepo, req *request) {
	if req.db != p.verifier.Name() {
		writeError(w, http.StatusNotFound, "the checksum database %s is not proxied here; %s is", abbrev(req.db), p.verifier.Name())
		return
	}
	var rt *upstream.Route
	switch sub := req.dbPath; {
	case sub == "supported":
		w.WriteHeader(http.StatusOK)
		return
	case sub == "latest":
		rt = h.sumdbRoute(p, sub)
		rt.Kind, rt.ContentType, rt.MaxSize, rt.Revalidate = upstream.Mutable, ctText, maxNote, sumdbRevalidate
		rt.Validate = func(ctx context.Context, d *upstream.Doc) error {
			b, err := h.readDoc(ctx, d, maxNote)
			var tree sumdb.Tree
			if err == nil {
				tree, err = p.verifier.OpenTree(b)
			}
			if err == nil {
				_, err = h.prover(ctx, p, tree)
			}
			return err
		}
	case strings.HasPrefix(sub, "lookup/"):
		escMod, escVer, ok := strings.Cut(strings.TrimPrefix(sub, "lookup/"), "@")
		mod, mok := unescape(escMod)
		ver, vok := unescape(escVer)
		if !ok || !mok || !vok || !validPath(mod) || !canonical(ver) {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		rt = h.sumdbRoute(p, sub)
		rt.ContentType, rt.Expect.Check = ctText, h.checkLookup(p, mod, ver)
	case strings.HasPrefix(sub, "tile/") && validTile(strings.TrimPrefix(sub, "tile/")):
		rt = h.sumdbRoute(p, sub)
		rt.ContentType = "application/octet-stream"
	default:
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	h.paths.Serve(w, r, p.path, rt, h.actor(r))
}

// serveProxy serves a request of proxy repository p.
func (h *Handler) serveProxy(w http.ResponseWriter, r *http.Request, p *proxyRepo, req *request) {
	if req.kind == kindSumDB {
		h.serveSumDB(w, r, p, req)
		return
	}
	actor := h.actor(r)
	h.paths.Serve(w, r, p.path, h.route(p, req, actor), actor)
}

// serveBytes serves content the handler read.
func serveBytes(w http.ResponseWriter, r *http.Request, ct string, b []byte) {
	w.Header().Set("Content-Type", ct)
	http.ServeContent(w, r, "", time.Time{}, bytes.NewReader(b))
}

// notFound reports whether err is an upstream's answer that it does not
// have something, or denies access to it: the answers a member of a
// virtual repository gives for what it does not serve.
func notFound(err error) bool {
	return errors.Is(err, upstream.ErrNotFound) || errors.Is(err, upstream.ErrDenied)
}
