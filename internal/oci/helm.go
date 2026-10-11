package oci

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/terrabyteian/flint/internal/blob"
	"github.com/terrabyteian/flint/internal/meta"
	"github.com/terrabyteian/flint/internal/server"
)

// The classic Helm chart repository view. A hosted OCI repository with
// helmIndex serves, at /helm/<repo>/ for the charts directly below the
// repository and at /helm/<repo>/<path>/ for those below a deeper path:
//
//	index.yaml                          the chart index
//	charts/<name>-<version>.tgz         a chart
//	charts/<name>-<version>.tgz.prov    its provenance file, if one was pushed
//
// The view is derived from the charts pushed with helm push: every tag
// <path>/<name>:<version> whose manifest has the Helm config media type.
// Nothing is stored for it. The index is written as JSON, which every Helm
// release reads (JSON is a subset of YAML), and is cached in memory until
// the tags in the view change.

// Helm media types, as helm push writes them.
const (
	mtHelmConfig       = "application/vnd.cncf.helm.config.v1+json"
	mtHelmChart        = "application/vnd.cncf.helm.chart.content.v1.tar+gzip"
	mtHelmProvenance   = "application/vnd.cncf.helm.chart.provenance.v1.prov"
	helmIndexFile      = "index.yaml"
	helmChartsDir      = "charts"
	helmProvSuffix     = ".prov"
	helmMaxConfigBytes = 4 << 20
)

// BasicAuthorizer is an optional extension of Authorizer for the Helm
// view, whose clients send HTTP basic credentials and know no token
// service. It is Authorize, except that it answers a request without
// valid credentials with a Basic challenge. With an Authorizer that does
// not implement it, the view uses Authorize.
type BasicAuthorizer interface {
	AuthorizeBasic(w http.ResponseWriter, r *http.Request, repo string, actions ...string) bool
}

// AuthorizeBasic allows the request.
func (AllowAll) AuthorizeBasic(http.ResponseWriter, *http.Request, string, ...string) bool {
	return true
}

// helmFile is a chart or provenance file in a view.
type helmFile struct {
	digest blob.Digest
	size   int64
	prov   bool
}

// helmChart is what a view needs from a chart's manifest: its metadata
// and files. Its fields depend only on the manifest's content, so it is
// cached by manifest digest.
type helmChart struct {
	meta    map[string]json.RawMessage // the config blob: the chart's metadata
	name    string
	version string
	chart   helmFile
	prov    *helmFile
}

// helmStamp identifies the state of a view's tags: it changes whenever a
// tag in the view is added, moved, or deleted.
type helmStamp struct {
	tags   int
	latest meta.Seq // the version of the most recently written tag
}

// helmView is a built view.
type helmView struct {
	seq    meta.Seq // the metadata view it was built from
	stamp  helmStamp
	index  []byte
	etag   string
	files  map[string]helmFile        // by file name below charts/
	charts map[blob.Digest]*helmChart // by manifest digest; nil for a manifest that is not a chart
}

// helmTag is a tag in a view.
type helmTag struct {
	name   string // the chart name: the last component of the image name
	tag    string
	digest blob.Digest
}

// serveHelm routes a /helm/ request.
func (h *Handler) serveHelm(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	server.SetRoute(ctx, "helm.unknown")
	repo, rest, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, "/helm/"), "/")
	cfg := h.repos[repo]
	if cfg == nil || !cfg.helmIndex {
		helmError(w, r, http.StatusNotFound, fmt.Sprintf("%q is not a Helm chart repository on this registry", abbrev(repo)))
		return
	}
	dir, file := "", rest
	if i := strings.LastIndexByte(rest, '/'); i >= 0 {
		dir, file = rest[:i], rest[i+1:]
	}
	isChart := false
	switch {
	case file == helmIndexFile:
		server.SetRoute(ctx, "helm.index")
	case (dir == helmChartsDir || strings.HasSuffix(dir, "/"+helmChartsDir)) &&
		(strings.HasSuffix(file, ".tgz") || strings.HasSuffix(file, ".tgz"+helmProvSuffix)):
		server.SetRoute(ctx, "helm.chart")
		dir = strings.TrimSuffix(strings.TrimSuffix(dir, helmChartsDir), "/")
		isChart = true
	default:
		helmError(w, r, http.StatusNotFound, "not found")
		return
	}
	full := repo
	if dir != "" {
		full += "/" + dir
	}
	if !validName(full) {
		helmError(w, r, http.StatusNotFound, "not found")
		return
	}
	server.LogAttrs(ctx, slog.String("repository", full))
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		helmError(w, r, http.StatusMethodNotAllowed, fmt.Sprintf("method %s is not allowed here", r.Method))
		return
	}
	if ba, ok := h.auth.(BasicAuthorizer); ok {
		if !ba.AuthorizeBasic(w, r, full, ActionPull) {
			return
		}
	} else if !h.auth.Authorize(w, r, full, ActionPull) {
		return
	}
	view, err := h.helmView(ctx, repo, dir)
	if err != nil {
		if !errors.Is(err, context.Canceled) {
			h.log.ErrorContext(ctx, "building the Helm index failed", "repository", full, "err", err)
		}
		helmError(w, r, http.StatusInternalServerError, "internal server error")
		return
	}
	if !isChart {
		hd := w.Header()
		hd.Set("ETag", view.etag)
		hd.Set("Cache-Control", "no-cache")
		if inm := r.Header.Get("If-None-Match"); inm != "" && etagMatch(inm, view.etag) {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		hd.Set("Content-Type", "application/json")
		hd.Set("Content-Length", strconv.Itoa(len(view.index)))
		w.WriteHeader(http.StatusOK)
		if r.Method != http.MethodHead {
			w.Write(view.index)
		}
		return
	}
	f, ok := view.files[file]
	if !ok {
		helmError(w, r, http.StatusNotFound, fmt.Sprintf("chart file %q is not in this repository", abbrev(file)))
		return
	}
	h.serveHelmFile(w, r, full, cfg, f)
}

// serveHelmFile serves a chart or provenance file from the blob store.
func (h *Handler) serveHelmFile(w http.ResponseWriter, r *http.Request, full string, cfg *repository, f helmFile) {
	var content io.ReadSeeker
	if r.Method != http.MethodHead {
		rd, err := h.blobs.Open(r.Context(), f.digest)
		if err != nil {
			if errors.Is(err, blob.ErrNotFound) {
				h.log.WarnContext(r.Context(), "a chart's blob is missing from the blob store",
					"repository", full, "digest", f.digest.String())
				helmError(w, r, http.StatusNotFound, "not found")
				return
			}
			h.log.ErrorContext(r.Context(), "opening a chart failed", "repository", full, "err", err)
			helmError(w, r, http.StatusInternalServerError, "internal server error")
			return
		}
		defer rd.Close()
		content = rd
	}
	hd := w.Header()
	hd.Set("ETag", `"`+f.digest.String()+`"`)
	if f.prov {
		hd.Set("Content-Type", "application/octet-stream")
	} else {
		hd.Set("Content-Type", "application/gzip")
	}
	if cfg.immutableTags {
		hd.Set("Cache-Control", "max-age=31536000") // a chart version never changes
	} else {
		hd.Set("Cache-Control", "no-cache") // a re-pushed version changes it
	}
	if content == nil {
		hd.Set("Accept-Ranges", "bytes")
		hd.Set("Content-Length", strconv.FormatInt(f.size, 10))
		w.WriteHeader(http.StatusOK)
		return
	}
	http.ServeContent(w, r, "", time.Time{}, content)
}

// helmError writes a plain-text error response.
func helmError(w http.ResponseWriter, r *http.Request, status int, msg string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Length", strconv.Itoa(len(msg)+1))
	w.WriteHeader(status)
	if r.Method != http.MethodHead {
		io.WriteString(w, msg+"\n")
	}
}

// etagMatch reports whether an If-None-Match header matches etag.
func etagMatch(header, etag string) bool {
	for part := range strings.SplitSeq(header, ",") {
		part = strings.TrimPrefix(strings.TrimSpace(part), "W/")
		if part == etag || part == "*" {
			return true
		}
	}
	return false
}

// helmView returns the view of the charts below repo/dir, rebuilding it
// if its tags changed since it was built.
func (h *Handler) helmView(ctx context.Context, repo, dir string) (*helmView, error) {
	v := h.view()
	seq := v.Seq()
	tags, stamp := scanHelmTags(v, repo, dir)
	v.Release()
	key := repo + "\x00" + dir
	h.helmMu.Lock()
	cached := h.helmViews[key]
	h.helmMu.Unlock()
	if cached != nil && cached.stamp == stamp {
		return cached, nil
	}
	return h.helmBuilds.Do(ctx, fmt.Sprintf("%s\x00%d\x00%d", key, stamp.tags, stamp.latest),
		func(ctx context.Context) (*helmView, error) {
			view, err := h.buildHelmView(ctx, repo, dir, tags, stamp, cached)
			if err != nil {
				return nil, err
			}
			view.seq = seq
			h.helmMu.Lock()
			defer h.helmMu.Unlock()
			switch cur := h.helmViews[key]; {
			case cur != nil && cur.seq > seq:
				// A build from a later view finished first.
			case len(view.files) == 0:
				// An empty view is cheap to build and may be any path a
				// client asked for, so it is not kept.
				delete(h.helmViews, key)
			default:
				h.helmViews[key] = view
			}
			return view, nil
		})
}

// scanHelmTags lists the tags of the image names directly below
// repo/dir, and their stamp.
func scanHelmTags(v meta.View, repo, dir string) ([]helmTag, helmStamp) {
	pfx := append([]byte(nsTag), repo...)
	pfx = append(pfx, 0)
	if dir != "" {
		pfx = append(append(pfx, dir...), '/')
	}
	var tags []helmTag
	var stamp helmStamp
	// Tag keys are ordered by image name, and the names below a deeper
	// path, which belong to other views, sort together, so on meeting
	// one the scan resumes after all of them.
	var after []byte
	for more := true; more; {
		more = false
		v.Scan(pfx, after, func(key []byte, rec meta.Record) bool {
			name, tag, ok := bytes.Cut(key[len(pfx):], []byte{0})
			if !ok {
				return true
			}
			if i := bytes.IndexByte(name, '/'); i >= 0 {
				after = append(bytes.Clone(key[:len(pfx)+i+1]), 0xff) // past every name below <name>/
				more = true
				return false
			}
			stamp.tags++
			stamp.latest = max(stamp.latest, rec.Version)
			if d, err := decodeTag(rec.Value); err == nil {
				tags = append(tags, helmTag{name: string(name), tag: string(tag), digest: d})
			}
			return true
		})
	}
	return tags, stamp
}

// buildHelmView builds a view from its tags, reusing the charts prev has
// already read.
func (h *Handler) buildHelmView(ctx context.Context, repo, dir string, tags []helmTag, stamp helmStamp, prev *helmView) (*helmView, error) {
	view := &helmView{
		stamp:  stamp,
		etag:   fmt.Sprintf(`"%d.%d"`, stamp.latest, stamp.tags),
		files:  map[string]helmFile{},
		charts: map[blob.Digest]*helmChart{},
	}
	entries := map[string][]json.RawMessage{}
	// The push times are in the manifest records; a record deleted since
	// the tags were read leaves its chart without one.
	pushed := make([]time.Time, len(tags))
	v := h.view()
	for i, t := range tags {
		if rec, ok := v.Get(manifestKey(helmImage(repo, dir, t.name), t.digest)); ok {
			if m, err := decodeManifest(rec.Value); err == nil {
				pushed[i] = m.Pushed
			}
		}
	}
	v.Release()
	type listed struct {
		chart   *helmChart
		file    string
		created time.Time
	}
	var charts []listed
	claims := map[string]int{}
	for i, t := range tags {
		c, seen := view.charts[t.digest]
		if !seen && prev != nil {
			c, seen = prev.charts[t.digest]
		}
		if !seen {
			var err error
			c, err = h.readHelmChart(ctx, helmImage(repo, dir, t.name), t.digest)
			if errors.Is(err, errHelmMissing) {
				continue
			}
			if err != nil {
				return nil, err
			}
		}
		view.charts[t.digest] = c
		// helm push names the image after the chart and tags it with the
		// version, "+" replaced by "_"; any other tag of the manifest
		// would list the chart twice.
		if c == nil || c.name != t.name || strings.ReplaceAll(c.version, "+", "_") != t.tag {
			continue
		}
		file := c.name + "-" + c.version + ".tgz"
		charts = append(charts, listed{c, file, pushed[i]})
		claims[file]++
	}
	for _, l := range charts {
		// Names and versions may both contain "-", so two charts can
		// claim one file name; neither is listed.
		c, file := l.chart, l.file
		if claims[file] > 1 {
			continue
		}
		view.files[file] = c.chart
		if c.prov != nil {
			view.files[file+helmProvSuffix] = *c.prov
		}
		e := make(map[string]json.RawMessage, len(c.meta)+3)
		for k, val := range c.meta {
			e[k] = val
		}
		e["urls"], _ = json.Marshal([]string{helmChartsDir + "/" + file})
		e["digest"], _ = json.Marshal(c.chart.digest.Hex())
		if !l.created.IsZero() {
			e["created"], _ = json.Marshal(l.created.UTC())
		}
		body, err := json.Marshal(e)
		if err != nil {
			return nil, err
		}
		entries[c.name] = append(entries[c.name], body)
	}
	index, err := json.Marshal(struct {
		APIVersion string                       `json:"apiVersion"`
		Entries    map[string][]json.RawMessage `json:"entries"`
		Generated  time.Time                    `json:"generated"`
	}{"v1", entries, h.now().UTC()})
	if err != nil {
		return nil, err
	}
	view.index = index
	return view, nil
}

// helmImage returns the image name of chart name in the view of repo/dir.
func helmImage(repo, dir, name string) *repoName {
	if dir != "" {
		name = dir + "/" + name
	}
	return &repoName{full: repo + "/" + name, repo: repo, name: name}
}

// errHelmMissing reports that a chart's manifest record or one of its
// blobs is gone, which unlike the manifest's content can change.
var errHelmMissing = errors.New("the chart's manifest or a blob it needs is missing")

// readHelmChart reads the chart that manifest d in rn holds, or returns
// nil if it holds none.
func (h *Handler) readHelmChart(ctx context.Context, rn *repoName, d blob.Digest) (*helmChart, error) {
	v := h.view()
	rec, ok := v.Get(manifestKey(rn, d))
	v.Release()
	if !ok {
		return nil, errHelmMissing // deleted since the tags were read
	}
	m, err := decodeManifest(rec.Value)
	if err != nil {
		return nil, err
	}
	// A manifest records its config media type as its artifact type
	// unless it declares one.
	if isIndexType(m.MediaType) || m.ArtifactType != mtHelmConfig || m.Size > maxManifestSize {
		return nil, nil
	}
	body, err := h.readBlob(ctx, d, m.Size)
	if err != nil {
		return nil, err
	}
	var doc manifestDoc
	if err := json.Unmarshal(body, &doc); err != nil || doc.Config == nil || doc.Config.MediaType != mtHelmConfig {
		return nil, nil
	}
	c := &helmChart{}
	for _, l := range doc.Layers {
		ld, err := blob.ParseDigest(l.Digest)
		if err != nil {
			return nil, nil
		}
		switch l.MediaType {
		case mtHelmChart:
			c.chart = helmFile{digest: ld, size: l.Size}
		case mtHelmProvenance:
			c.prov = &helmFile{digest: ld, size: l.Size, prov: true}
		}
	}
	cd, err := blob.ParseDigest(doc.Config.Digest)
	if err != nil || c.chart.digest.IsZero() || doc.Config.Size > helmMaxConfigBytes {
		return nil, nil
	}
	config, err := h.readBlob(ctx, cd, doc.Config.Size)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(config, &c.meta); err != nil {
		return nil, nil
	}
	json.Unmarshal(c.meta["name"], &c.name)
	json.Unmarshal(c.meta["version"], &c.version)
	if !validComponent(c.name) || !validChartVersion(c.version) {
		return nil, nil
	}
	return c, nil
}

// readBlob reads blob d of size bytes, returning errHelmMissing if the
// blob store does not hold it.
func (h *Handler) readBlob(ctx context.Context, d blob.Digest, size int64) ([]byte, error) {
	f, err := h.blobs.Open(ctx, d)
	if errors.Is(err, blob.ErrNotFound) {
		return nil, errHelmMissing
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b := make([]byte, size)
	if _, err := io.ReadFull(f, b); err != nil {
		return nil, fmt.Errorf("reading blob %s: %w", d, err)
	}
	return b, nil
}

// validChartVersion reports whether s can be a chart version in a file
// name: the characters of a semantic version, which Helm requires.
func validChartVersion(s string) bool {
	if s == "" || len(s) > 128 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !alnum(c) && !(c >= 'A' && c <= 'Z') && c != '.' && c != '-' && c != '+' {
			return false
		}
	}
	return true
}
