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
	"maps"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/terrabyteian/flint/internal/blob"
	"github.com/terrabyteian/flint/internal/config"
	"github.com/terrabyteian/flint/internal/meta"
	"github.com/terrabyteian/flint/internal/repo"
	"github.com/terrabyteian/flint/internal/server"
)

// Media types of packuments.
const (
	// mtAbbreviated is the abbreviated packument, which installers ask
	// for: what resolving dependencies needs, without readmes and other
	// display fields.
	mtAbbreviated = "application/vnd.npm.install-v1+json"
	mtJSON        = "application/json"
)

// packument is a package as a repository serves it: its dist-tags and
// live versions. Hosted repositories assemble it from their records.
type packument struct {
	name     string
	rev      string // the CouchDB-style _rev of a hosted package
	created  time.Time
	modified time.Time
	tags     []distTag
	versions []*pkgVersion // in SemVer order
	// readme and readmeFilename are loaded only for the full packument.
	readme, readmeFilename string
}

// pkgVersion is a live version of a packument.
type pkgVersion struct {
	version string
	// manifest is the version's manifest, without the fields flint sets
	// itself (dist and deprecated).
	manifest   map[string]json.RawMessage
	published  time.Time
	deprecated string
	integrity  string // the SRI string, such as "sha512-..."
	shasum     string // hex sha1
	// predicateType is the type of the version's provenance attestation,
	// or "" without one.
	predicateType string
	rec           *versionRecord // a hosted version's record
}

// latest returns the version the "latest" dist-tag points at, or nil.
func (p *packument) latest() *pkgVersion {
	for _, t := range p.tags {
		if t.Tag == "latest" {
			return p.version(t.Version)
		}
	}
	return nil
}

// version returns the live version v, or nil.
func (p *packument) version(v string) *pkgVersion {
	for _, pv := range p.versions {
		if pv.version == v {
			return pv
		}
	}
	return nil
}

// formatRev returns the _rev of a package record at version seq in the
// metadata store: the CouchDB form "<number>-<hash>" that npm sends back
// when it edits the package.
func formatRev(seq meta.Seq, value []byte) string {
	sum := sha256.Sum256(value)
	return strconv.FormatUint(uint64(seq), 10) + "-" + hex.EncodeToString(sum[:8])
}

// parseRev returns the metadata version a _rev names, or 0 if it names
// none.
func parseRev(rev string) meta.Seq {
	n, _, _ := strings.Cut(rev, "-")
	s, err := strconv.ParseUint(n, 10, 64)
	if err != nil {
		return 0
	}
	return meta.Seq(s)
}

// hostedPackage reads a hosted package's record. It returns nil if the
// repository never had the package.
func hostedPackage(v meta.View, rp *repository, name string) (*pkgRecord, meta.Record, error) {
	rec, ok := v.Get(pkgKey(rp.name, name))
	if !ok {
		return nil, rec, nil
	}
	p, err := decodePkg(rec.Value)
	if err != nil {
		return nil, rec, fmt.Errorf("npm: package record of %s in %s: %w", name, rp.name, err)
	}
	return p, rec, nil
}

// hostedVersions returns the version records of a hosted package, live
// and tombstones, by version.
func hostedVersions(v meta.View, rp *repository, name string) (map[string]*versionRecord, error) {
	out := map[string]*versionRecord{}
	pfx := versionPrefix(rp.name, name)
	var failure error
	v.Scan(pfx, nil, func(k []byte, rec meta.Record) bool {
		vr, err := decodeVersion(rec.Value)
		if err != nil {
			failure = fmt.Errorf("npm: version record %s@%s in %s: %w", name, k[len(pfx):], rp.name, err)
			return false
		}
		out[string(k[len(pfx):])] = vr
		return true
	})
	return out, failure
}

// hostedPackument assembles a hosted package's packument from the view,
// reading its manifests, and its readme if full. It returns a 404 error
// if the package has no live version.
func (h *Handler) hostedPackument(ctx context.Context, v meta.View, rp *repository, name string, full bool) (*packument, error) {
	p, rec, err := hostedPackage(v, rp, name)
	if err != nil {
		return nil, err
	}
	if p == nil || p.tag("latest") == "" {
		return nil, notFound(name)
	}
	vrs, err := hostedVersions(v, rp, name)
	if err != nil {
		return nil, err
	}
	doc := &packument{name: name, rev: formatRev(rec.Version, rec.Value), created: p.Created, modified: p.Modified, tags: p.Tags}
	for ver, vr := range vrs {
		if vr.Kind != kindLive {
			continue
		}
		pv, err := h.liveVersion(ctx, ver, vr)
		if err != nil {
			return nil, fmt.Errorf("npm: %s@%s in %s: %w", name, ver, rp.name, err)
		}
		doc.versions = append(doc.versions, pv)
	}
	slices.SortFunc(doc.versions, func(a, b *pkgVersion) int { return compareVersions(a.version, b.version) })
	if full && !p.Readme.IsZero() {
		b, err := h.readBlob(ctx, p.Readme, p.ReadmeSize)
		if err != nil {
			return nil, fmt.Errorf("npm: readme of %s in %s: %w", name, rp.name, err)
		}
		doc.readme, doc.readmeFilename = string(b), p.ReadmeFilename
	}
	return doc, nil
}

// liveVersion reads a live hosted version's manifest.
func (h *Handler) liveVersion(ctx context.Context, ver string, vr *versionRecord) (*pkgVersion, error) {
	b, err := h.readBlob(ctx, vr.Manifest, vr.ManifestSize)
	if err != nil {
		return nil, err
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("the stored manifest cannot be read: %w", err)
	}
	return &pkgVersion{
		version: ver, manifest: m, published: vr.Published, deprecated: vr.Deprecated,
		integrity: "sha512-" + base64.StdEncoding.EncodeToString(vr.SHA512), shasum: hex.EncodeToString(vr.SHA1),
		predicateType: vr.PredicateType, rec: vr,
	}, nil
}

// readBlob reads a blob of size bytes.
func (h *Handler) readBlob(ctx context.Context, d blob.Digest, size int64) ([]byte, error) {
	f, err := h.blobs.Open(ctx, d)
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

// packumentOf returns the packument rp serves for name, or a 404 error if
// it has none.
func (h *Handler) packumentOf(ctx context.Context, rp *repository, name string, full bool) (*packument, error) {
	v := h.meta.View()
	defer v.Release()
	return h.hostedPackument(ctx, v, rp, name, full)
}

// wantsAbbreviated reports whether the request asks for the abbreviated
// packument, as installers do in their Accept header.
func wantsAbbreviated(r *http.Request) bool {
	for _, a := range r.Header.Values("Accept") {
		for part := range strings.SplitSeq(a, ",") {
			mt, params, _ := strings.Cut(strings.TrimSpace(part), ";")
			if !strings.EqualFold(strings.TrimSpace(mt), mtAbbreviated) {
				continue
			}
			// A zero quality refuses the type.
			for p := range strings.SplitSeq(params, ";") {
				if k, v, ok := strings.Cut(strings.TrimSpace(p), "="); ok && strings.EqualFold(k, "q") {
					if q, err := strconv.ParseFloat(v, 64); err == nil && q == 0 {
						return false
					}
				}
			}
			return true
		}
	}
	return false
}

// tarballBase returns the URL below which the tarballs of a packument rp
// serves are: rp's registry URL, absolute, from the public URL.
func tarballBase(r *http.Request, rp *repository) string {
	return server.BaseURL(r) + repo.Path(config.FormatNPM, rp.name)
}

// docBody is a packument as served: its bytes, or for one too large to
// hold, a stream of them, which must be closed.
type docBody struct {
	b      []byte
	stream io.ReadCloser
	// streamSize, for a stream, is the size of the stored document it is
	// derived from.
	streamSize int64
	etag       string // for b
	// abbreviated reports whether it is the abbreviated form.
	abbreviated bool
	// id names what the body was rendered from, so a document derived
	// from it can be cached under it: a hosted package's record version,
	// or a proxied packument's digest.
	id string
}

// reader returns the body's content; it is the stream itself for a
// stream, so it can be read once.
func (d *docBody) reader() io.ReadCloser {
	if d.stream != nil {
		return d.stream
	}
	return io.NopCloser(bytes.NewReader(d.b))
}

// size returns the size of the body's content; for a stream, that of the
// stored document it is derived from.
func (d *docBody) size() int64 {
	if d.stream != nil {
		return d.streamSize
	}
	return int64(len(d.b))
}

// close closes a stream that was not read.
func (d *docBody) close() {
	if d.stream != nil {
		d.stream.Close()
	}
}

// hostedBody returns hosted repository rp's packument of name, its
// tarball URLs below base, rendered from the records. It returns a 404
// error if the package has no live version.
func (h *Handler) hostedBody(ctx context.Context, rp *repository, name string, abbreviated bool, base string) (*docBody, error) {
	variant := "full"
	if abbreviated {
		variant = "abbreviated"
	}
	// The package record's version names the packument's state, so a
	// rendering cached under it never goes stale.
	v := h.meta.View()
	defer v.Release()
	_, rec, err := hostedPackage(v, rp, name)
	if err != nil {
		return nil, err
	}
	seq := strconv.FormatUint(uint64(rec.Version), 10)
	cacheKey := ""
	if rec.Version != 0 {
		cacheKey = strings.Join([]string{rp.name, name, seq, base, variant}, "\x00")
	}
	body, etag, ok := h.renders.get(cacheKey)
	if !ok {
		doc, err := h.hostedPackument(ctx, v, rp, name, !abbreviated)
		if err != nil {
			return nil, err
		}
		body = renderPackument(doc, base, abbreviated)
		etag = h.renders.put(cacheKey, body)
	}
	return &docBody{b: body, etag: etag, abbreviated: abbreviated, id: "h" + rp.name + ":" + seq}, nil
}

// packumentBody returns the packument of name that rp serves, its URLs
// below base.
func (h *Handler) packumentBody(ctx context.Context, actor string, rp *repository, name string, abbreviated bool, base string) (*docBody, error) {
	switch rp.typ {
	case config.TypeProxy:
		return h.proxyBody(ctx, actor, rp, name, abbreviated, base)
	case config.TypeVirtual:
		return h.virtualBody(ctx, actor, rp, name, abbreviated, base)
	}
	return h.hostedBody(ctx, rp, name, abbreviated, base)
}

// servePackument serves GET /npm/<repo>/<name>: the abbreviated
// packument if the client asks for it, else the full one. A request with
// ?write=true, which npm sends before it edits a package, always gets
// the full packument, uncached; through a virtual repository, that of
// its publishTo member, which the edit is sent to, if that member's
// filters admit the package.
func (h *Handler) servePackument(w http.ResponseWriter, r *http.Request, rp *repository, name string) {
	ctx := r.Context()
	write := r.URL.Query().Get("write") == "true"
	abbreviated := !write && wantsAbbreviated(r)
	base := tarballBase(r, rp)
	var body *docBody
	var err error
	if pt := h.repos[publishTo(rp)]; write && pt != nil && rp.virtual.CheckPublish(name) == nil {
		body, err = h.hostedBody(ctx, pt, name, false, base)
	} else {
		body, err = h.packumentBody(ctx, h.actor(r), rp, name, abbreviated, base)
	}
	if err != nil {
		h.fail(w, r, err)
		return
	}
	defer body.close()
	hd := w.Header()
	if body.abbreviated {
		hd.Set("Content-Type", mtAbbreviated)
	} else {
		hd.Set("Content-Type", mtJSON)
	}
	hd.Set("Vary", "Accept")
	switch {
	case write:
		hd.Set("Cache-Control", "no-store")
	default:
		if body.etag != "" {
			hd.Set("ETag", body.etag)
		}
		hd.Set("Cache-Control", cacheControl(rp, "max-age=0, must-revalidate"))
	}
	if body.stream == nil {
		http.ServeContent(w, r, "", time.Time{}, bytes.NewReader(body.b))
		return
	}
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodHead {
		return
	}
	if _, err := io.Copy(w, body.stream); err != nil {
		if ctx.Err() == nil {
			h.log.WarnContext(ctx, "serving a packument failed", "repository", rp.name, "package", name, "err", err)
		}
		// Part of the packument is out: cut the connection, so the client
		// cannot take it for the whole document.
		panic(http.ErrAbortHandler)
	}
}

// publishTo returns the name of a virtual repository's publishTo member,
// or "".
func publishTo(rp *repository) string {
	if rp.virtual != nil {
		return rp.virtual.PublishTo
	}
	return ""
}

// cacheControl returns a Cache-Control value: directives, after "public"
// for a repository anyone may pull from, so shared caches may keep the
// response, or else "private".
func cacheControl(rp *repository, directives string) string {
	if rp.anonymous {
		return "public, " + directives
	}
	return "private, " + directives
}

// serveVersion serves GET /npm/<repo>/<name>/<spec>: the manifest of a
// version, or of the version a dist-tag points at.
func (h *Handler) serveVersion(w http.ResponseWriter, r *http.Request, rp *repository, name, spec string) {
	ctx := r.Context()
	var out []byte
	if rp.typ == config.TypeHosted {
		doc, err := h.packumentOf(ctx, rp, name, false)
		if err != nil {
			h.fail(w, r, err)
			return
		}
		pv := doc.version(spec)
		if pv == nil {
			for _, t := range doc.tags {
				if t.Tag == spec {
					pv = doc.version(t.Version)
				}
			}
		}
		if pv != nil {
			out = renderVersion(doc.name, pv, tarballBase(r, rp), false)
		}
	} else {
		body, err := h.packumentBody(ctx, h.actor(r), rp, name, false, tarballBase(r, rp))
		if err != nil {
			h.fail(w, r, err)
			return
		}
		f := body.reader()
		out, err = versionIn(f, spec)
		f.Close()
		if err != nil {
			h.fail(w, r, err)
			return
		}
	}
	if out == nil {
		writeError(w, http.StatusNotFound, "version %s of %s is not found", abbrev(spec), name)
		return
	}
	w.Header().Set("Content-Type", mtJSON)
	w.Header().Set("Cache-Control", cacheControl(rp, "max-age=0, must-revalidate"))
	http.ServeContent(w, r, "", time.Time{}, bytes.NewReader(out))
}

// versionIn returns the manifest of a served packument's version spec, or
// of the version the dist-tag spec points at, or nil if it has none.
func versionIn(r io.Reader, spec string) (json.RawMessage, error) {
	var tags map[string]string
	var exact, tagged json.RawMessage
	pending := map[string]json.RawMessage{} // versions read before the dist-tags
	_, isVersion := parseVersion(spec)
	err := scanPackument(r, packumentVisitor{
		field: func(k string, raw json.RawMessage) error {
			if k == "dist-tags" {
				json.Unmarshal(raw, &tags)
				if tags == nil {
					tags = map[string]string{}
				}
			}
			return nil
		},
		version: func(ver string, raw json.RawMessage) error {
			switch {
			case ver == spec:
				exact = raw
			case tags != nil:
				if t, ok := tags[spec]; ok && t == ver {
					tagged = raw
				}
			case !isVersion:
				pending[ver] = raw
			}
			return nil
		},
	})
	switch {
	case err != nil:
		return nil, err
	case exact != nil:
		return exact, nil
	case tagged != nil:
		return tagged, nil
	}
	if t, ok := tags[spec]; ok {
		return pending[t], nil
	}
	return nil, nil
}

// distTagsIn returns the dist-tags of a served packument.
func distTagsIn(r io.Reader) (map[string]string, error) {
	tags := map[string]string{}
	err := scanPackument(r, packumentVisitor{
		field: func(k string, raw json.RawMessage) error {
			if k == "dist-tags" {
				json.Unmarshal(raw, &tags)
			}
			return nil
		},
		version: func(string, json.RawMessage) error { return nil },
	})
	return tags, err
}

// abbreviatedFields are the version fields of the abbreviated packument:
// what installing needs.
var abbreviatedFields = []string{
	"name", "version", "deprecated", "dependencies", "optionalDependencies", "devDependencies",
	"bundleDependencies", "bundledDependencies", "peerDependencies", "peerDependenciesMeta",
	"acceptDependencies", "bin", "directories", "dist", "engines", "_hasShrinkwrap", "hasInstallScript",
	"cpu", "os", "libc", "funding", "license",
}

// packageFields are the fields of the full packument that come from the
// latest version's manifest, as the npm registry serves them.
var packageFields = []string{"description", "keywords", "license", "homepage", "repository", "bugs", "author",
	"maintainers", "contributors"}

// object writes a JSON object with keys in the order they are added.
type object struct {
	b     bytes.Buffer
	empty bool
}

func newObject() *object {
	o := &object{empty: true}
	o.b.WriteByte('{')
	return o
}

// raw adds a key with a JSON value.
func (o *object) raw(k string, v []byte) {
	if !o.empty {
		o.b.WriteByte(',')
	}
	o.empty = false
	kb, _ := json.Marshal(k)
	o.b.Write(kb)
	o.b.WriteByte(':')
	o.b.Write(v)
}

// value adds a key with a value json.Marshal encodes.
func (o *object) value(k string, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		b = []byte("null")
	}
	o.raw(k, b)
}

func (o *object) bytes() []byte {
	o.b.WriteByte('}')
	return o.b.Bytes()
}

// npmTime formats a time as the npm registry does.
func npmTime(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05.000Z") }

// renderPackument renders a packument, its tarball URLs below base.
func renderPackument(p *packument, base string, abbreviated bool) []byte {
	o := newObject()
	tags := newObject()
	for _, t := range p.tags {
		tags.value(t.Tag, t.Version)
	}
	versions := newObject()
	for _, pv := range p.versions {
		versions.raw(pv.version, renderVersion(p.name, pv, base, abbreviated))
	}
	if abbreviated {
		o.value("name", p.name)
		o.value("modified", npmTime(p.modified))
		o.raw("dist-tags", tags.bytes())
		o.raw("versions", versions.bytes())
		return o.bytes()
	}
	o.value("_id", p.name)
	if p.rev != "" {
		o.value("_rev", p.rev)
	}
	o.value("name", p.name)
	if latest := p.latest(); latest != nil {
		for _, f := range packageFields {
			if v, ok := latest.manifest[f]; ok {
				o.raw(f, v)
			}
		}
	}
	o.raw("dist-tags", tags.bytes())
	o.raw("versions", versions.bytes())
	times := newObject()
	times.value("created", npmTime(p.created))
	times.value("modified", npmTime(p.modified))
	for _, pv := range p.versions {
		times.value(pv.version, npmTime(pv.published))
	}
	o.raw("time", times.bytes())
	o.value("readme", p.readme)
	if p.readmeFilename != "" {
		o.value("readmeFilename", p.readmeFilename)
	}
	return o.bytes()
}

// renderVersion renders a version's manifest with the fields flint sets:
// dist, with the tarball URL below base, and deprecated. The abbreviated
// form keeps only what installing needs.
func renderVersion(name string, pv *pkgVersion, base string, abbreviated bool) []byte {
	dist := newObject()
	dist.value("integrity", pv.integrity)
	dist.value("shasum", pv.shasum)
	dist.value("tarball", base+name+"/-/"+tarballName(name, pv.version))
	if pv.predicateType != "" {
		att := newObject()
		att.value("url", base+"-/npm/v1/attestations/"+name+"@"+pv.version)
		att.value("provenance", map[string]string{"predicateType": pv.predicateType})
		dist.raw("attestations", att.bytes())
	}
	fields := map[string][]byte{"dist": dist.bytes()}
	if pv.deprecated != "" {
		fields["deprecated"], _ = json.Marshal(pv.deprecated)
	}
	o := newObject()
	if abbreviated {
		if hasInstallScript(pv.manifest) {
			fields["hasInstallScript"] = []byte("true")
		}
		for _, k := range abbreviatedFields {
			if v, ok := fields[k]; ok {
				o.raw(k, v)
			} else if v, ok := pv.manifest[k]; ok {
				o.raw(k, v)
			}
		}
		return o.bytes()
	}
	for _, k := range slices.Sorted(maps.Keys(pv.manifest)) {
		if _, ours := fields[k]; !ours {
			o.raw(k, pv.manifest[k])
		}
	}
	for _, k := range []string{"deprecated", "dist"} {
		if v, ok := fields[k]; ok {
			o.raw(k, v)
		}
	}
	return o.bytes()
}

// hasInstallScript reports whether a manifest has a script npm runs when
// it installs the package, which installers want to know before they
// fetch the tarball.
func hasInstallScript(m map[string]json.RawMessage) bool {
	var scripts map[string]json.RawMessage
	if json.Unmarshal(m["scripts"], &scripts) != nil {
		return false
	}
	for _, s := range []string{"preinstall", "install", "postinstall"} {
		if _, ok := scripts[s]; ok {
			return true
		}
	}
	return false
}

// serveTarball serves GET and HEAD /npm/<repo>/<name>/-/<file>.
func (h *Handler) serveTarball(w http.ResponseWriter, r *http.Request, rp *repository, name, file string) {
	switch rp.typ {
	case config.TypeProxy:
		h.proxyTarball(w, r, rp, rp, name, file, nil)
		return
	case config.TypeVirtual:
		h.virtualTarball(w, r, rp, name, file)
		return
	}
	h.hostedTarball(w, r, rp, rp, name, file)
}

// hostedTarball serves a tarball of hosted repository rp, as repository
// front, which the request named.
func (h *Handler) hostedTarball(w http.ResponseWriter, r *http.Request, front, rp *repository, name, file string) {
	version, ok := tarballVersion(name, file)
	if !ok {
		writeError(w, http.StatusNotFound, "%s is not a tarball of %s", abbrev(file), name)
		return
	}
	v := h.meta.View()
	rec, found := v.Get(versionKey(rp.name, name, version))
	v.Release()
	var vr *versionRecord
	if found {
		var err error
		if vr, err = decodeVersion(rec.Value); err != nil {
			h.fail(w, r, err)
			return
		}
	}
	if vr == nil || vr.Kind != kindLive {
		writeError(w, http.StatusNotFound, "%s@%s is not found", name, version)
		return
	}
	h.serveBlob(w, r, front, vr.Tarball, vr.Size)
}

// serveBlob streams blob d, size bytes, as a tarball.
func (h *Handler) serveBlob(w http.ResponseWriter, r *http.Request, rp *repository, d blob.Digest, size int64) {
	var f blob.Reader
	if r.Method != http.MethodHead {
		var err error
		f, err = h.blobs.Open(r.Context(), d)
		if errors.Is(err, blob.ErrNotFound) {
			h.log.ErrorContext(r.Context(), "a linked blob is missing from the blob store", "digest", d.String())
			writeError(w, http.StatusInternalServerError, "the tarball cannot be read")
			return
		}
		if err != nil {
			h.fail(w, r, err)
			return
		}
		defer f.Close()
	}
	hd := w.Header()
	hd.Set("Content-Type", "application/octet-stream")
	hd.Set("ETag", `"sha256:`+d.Hex()+`"`)
	// A version's tarball never changes: a version is never published
	// twice.
	hd.Set("Cache-Control", cacheControl(rp, "max-age=31536000, immutable"))
	hd.Set("X-Content-Type-Options", "nosniff")
	if r.Method == http.MethodHead {
		hd.Set("Accept-Ranges", "bytes")
		hd.Set("Content-Length", strconv.FormatInt(size, 10))
		w.WriteHeader(http.StatusOK)
		return
	}
	// The filesystem store returns the *os.File itself, so on plain
	// HTTP/1.1 ServeContent's copy reaches sendfile.
	http.ServeContent(w, r, "", time.Time{}, f)
}
