package npm

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"strings"

	"github.com/terrabyteian/flint/internal/blob"
	"github.com/terrabyteian/flint/internal/meta"
	"github.com/terrabyteian/flint/internal/server"
)

// servePut serves PUT /npm/<repo>/<name> and PUT
// /npm/<repo>/<name>/-rev/<rev>: a publish, whose body carries the new
// version's tarball in _attachments, or else an edit of the packument,
// with which npm deprecates and unpublishes versions.
func (h *Handler) servePut(w http.ResponseWriter, r *http.Request, rp *repository, name, rev string) {
	if !h.permit(w, r, rp, ActionPush) {
		return
	}
	rb, err := requestBody(r)
	var body *putBody
	if err == nil {
		body, err = h.readPut(r.Context(), rb)
	}
	if err != nil {
		h.fail(w, r, err)
		return
	}
	defer body.cancel()
	if err := checkNames(body, name); err != nil {
		h.fail(w, r, err)
		return
	}
	if len(body.attachments) == 0 {
		server.SetRoute(r.Context(), "npm.edit")
		h.serveEdit(w, r, rp, name, rev, body)
		return
	}
	if rev != "" {
		writeError(w, http.StatusBadRequest, "a publish is sent to the package's URL, not to a revision")
		return
	}
	h.servePublish(w, r, rp, name, body)
}

// checkNames checks that a PUT body names the package of its URL.
func checkNames(body *putBody, name string) error {
	for _, f := range []string{"name", "_id"} {
		var s string
		if ok, err := body.field(f, &s); err != nil {
			return err
		} else if ok && s != name {
			return errorf(http.StatusBadRequest, "the body's %s %q is not the package %s of the URL", f, abbrev(s), name)
		}
	}
	return nil
}

// publication is a validated publish.
type publication struct {
	version string
	// manifest is the version's manifest as stored: without dist,
	// deprecated, and the readme.
	manifest       []byte
	tags           []string
	tarball        *attachment
	provenance     []byte // the Sigstore bundle, or nil
	predicateType  string
	readme         string
	readmeFilename string
}

// checkPublish validates a publish of package name by user: one new
// version, with its tarball and optionally a provenance bundle, and the
// dist-tags to point at it.
func checkPublish(body *putBody, name, user string) (*publication, error) {
	bad := func(format string, args ...any) (*publication, error) {
		return nil, errorf(http.StatusBadRequest, format, args...)
	}
	if !ValidNewName(name) {
		return bad("%s", invalidName(name))
	}
	var versions map[string]map[string]json.RawMessage
	if _, err := body.field("versions", &versions); err != nil {
		return nil, err
	}
	if len(versions) != 1 {
		return bad("a publish must carry exactly one version, not %d", len(versions))
	}
	pub := &publication{}
	var m map[string]json.RawMessage
	for ver, vm := range versions {
		pub.version, m = ver, vm
	}
	if _, ok := parseVersion(pub.version); !ok {
		return bad("invalid version %q: it must be a semantic version, such as 1.0.0 or 2.0.0-beta.1, without build metadata", abbrev(pub.version))
	}
	var mname, mversion string
	json.Unmarshal(m["name"], &mname)
	json.Unmarshal(m["version"], &mversion)
	if mname != name || mversion != pub.version {
		return bad("the manifest of version %s names %s@%s, not %s@%s", abbrev(pub.version), abbrev(mname), abbrev(mversion), name, abbrev(pub.version))
	}

	var tags map[string]string
	if _, err := body.field("dist-tags", &tags); err != nil {
		return nil, err
	}
	for tag, v := range tags {
		if !validTag(tag) {
			return bad("invalid dist-tag %q: use a letter, then letters, digits, \".\", \"_\", and \"-\", in a name that is not a version range", abbrev(tag))
		}
		if v != pub.version {
			return bad("the dist-tag %s points at %s, not at the version published, %s", tag, abbrev(v), pub.version)
		}
		pub.tags = append(pub.tags, tag)
	}

	for _, a := range body.attachments {
		switch {
		case a.name == name+"-"+pub.version+".tgz" || a.name == tarballName(name, pub.version):
			if pub.tarball != nil {
				return bad("a publish has one tarball")
			}
			if a.up == nil {
				return bad("the attachment %s has no data", abbrev(a.name))
			}
			pub.tarball = a
		case a.name == name+"-"+pub.version+".sigstore" || a.name == unscoped(name)+"-"+pub.version+".sigstore":
			if pub.provenance != nil || !a.seen {
				return bad("a publish has one provenance bundle, with data")
			}
			pub.provenance = a.data
			a.size = int64(len(a.data))
		default:
			return bad("unexpected attachment %q: a publish of %s@%s attaches %s, and optionally a provenance bundle",
				abbrev(a.name), name, pub.version, tarballName(name, pub.version))
		}
		if a.length >= 0 && a.length != a.size {
			return bad("the attachment %s has %d bytes, but its length says %d", abbrev(a.name), a.size, a.length)
		}
	}
	if pub.tarball == nil {
		return bad("the publish has no tarball: attach %s", tarballName(name, pub.version))
	}
	if err := checkDist(m["dist"], pub.tarball); err != nil {
		return nil, err
	}
	if pub.provenance != nil {
		pt, err := predicateType(pub.provenance)
		if err != nil {
			return bad("the provenance bundle cannot be read: %v", err)
		}
		pub.predicateType = pt
	}

	// The readme is kept with the package; npm sends it in the manifest,
	// older clients at the top level.
	if json.Unmarshal(m["readme"], &pub.readme) != nil || pub.readme == "" {
		body.field("readme", &pub.readme)
	}
	json.Unmarshal(m["readmeFilename"], &pub.readmeFilename)
	for _, f := range []string{"readme", "dist", "deprecated", "_rev", "_attachments", "_npmUser"} {
		delete(m, f)
	}
	m["_id"], _ = json.Marshal(name + "@" + pub.version)
	if user != "" {
		// The user who published, as the npm registry records it.
		m["_npmUser"], _ = json.Marshal(map[string]string{"name": user})
	}
	var err error
	if pub.manifest, err = json.Marshal(m); err != nil {
		return bad("the manifest of version %s is not valid: %v", pub.version, err)
	}
	return pub, nil
}

// checkDist checks the digests a publish declares in dist against the
// tarball: every sha512 and sha1 hash of dist.integrity, and
// dist.shasum. flint computes both itself, so a publish that declares
// none is accepted; one that declares a wrong one is refused, as the
// tarball is not what the client meant to publish.
func checkDist(raw json.RawMessage, a *attachment) error {
	var dist struct {
		Integrity string `json:"integrity"`
		Shasum    string `json:"shasum"`
	}
	if len(raw) > 0 && json.Unmarshal(raw, &dist) != nil {
		return errorf(http.StatusBadRequest, "the version's dist is not valid")
	}
	if dist.Shasum != "" && !strings.EqualFold(dist.Shasum, hex.EncodeToString(a.sha1)) {
		return errorf(http.StatusBadRequest, "the tarball does not match dist.shasum: its sha1 is %x", a.sha1)
	}
	for entry := range strings.FieldsSeq(dist.Integrity) {
		alg, sum, ok := strings.Cut(entry, "-")
		sum, _, _ = strings.Cut(sum, "?") // options
		var want []byte
		switch {
		case !ok:
			return errorf(http.StatusBadRequest, "dist.integrity %q is not a subresource integrity string", abbrev(entry))
		case alg == "sha512":
			want = a.sha512
		case alg == "sha1":
			want = a.sha1
		default:
			continue // a hash flint does not compute
		}
		got, err := base64.StdEncoding.DecodeString(sum)
		if err != nil || !bytes.Equal(got, want) {
			return errorf(http.StatusBadRequest, "the tarball does not match dist.integrity: its %s is %s-%s",
				alg, alg, base64.StdEncoding.EncodeToString(want))
		}
	}
	return nil
}

// predicateType returns the predicate type of the in-toto statement in a
// Sigstore bundle's DSSE envelope, such as
// "https://slsa.dev/provenance/v1".
func predicateType(bundle []byte) (string, error) {
	var b struct {
		DSSEEnvelope *struct {
			Payload string `json:"payload"`
		} `json:"dsseEnvelope"`
	}
	if err := json.Unmarshal(bundle, &b); err != nil {
		return "", err
	}
	if b.DSSEEnvelope == nil {
		return "", errors.New("it has no DSSE envelope")
	}
	payload, err := base64.StdEncoding.DecodeString(b.DSSEEnvelope.Payload)
	if err != nil {
		return "", errors.New("its DSSE payload is not base64")
	}
	var st struct {
		PredicateType string `json:"predicateType"`
	}
	if err := json.Unmarshal(payload, &st); err != nil || st.PredicateType == "" {
		return "", errors.New("its DSSE payload is not an in-toto statement with a predicate type")
	}
	return st.PredicateType, nil
}

// servePublish publishes a version: it stores its tarball, manifest,
// readme, and provenance bundle, records the version, and points the
// dist-tags at it, "latest" too if the package has none. The package's
// readme becomes the version's if the version becomes the latest.
func (h *Handler) servePublish(w http.ResponseWriter, r *http.Request, rp *repository, name string, body *putBody) {
	ctx := r.Context()
	pub, err := checkPublish(body, name, h.user(r))
	if err == nil {
		// A version that is taken refuses the publish before anything is
		// stored.
		v := h.meta.View()
		err = versionFree(v, rp, name, pub.version)
		v.Release()
	}
	var tarball, manifest, readme, provenance blob.Info
	if err == nil {
		tarball, err = pub.tarball.up.Commit(ctx, blob.Digest{})
	}
	if err == nil {
		manifest, err = h.putBlob(ctx, pub.manifest)
	}
	if err == nil && pub.readme != "" {
		readme, err = h.putBlob(ctx, []byte(pub.readme))
	}
	if err == nil && pub.provenance != nil {
		provenance, err = h.putBlob(ctx, pub.provenance)
	}
	if err != nil {
		h.fail(w, r, err)
		return
	}
	now := h.now().UTC()
	vr := &versionRecord{
		Kind: kindLive, Manifest: manifest.Digest, ManifestSize: manifest.Size,
		Tarball: tarball.Digest, Size: tarball.Size, SHA512: pub.tarball.sha512, SHA1: pub.tarball.sha1,
		Published: now, Provenance: provenance.Digest, ProvenanceSize: provenance.Size, PredicateType: pub.predicateType,
	}
	rev, _, err := h.update(r, rp, name, 0, func(v meta.View, p *pkgRecord, vrs map[string]*versionRecord) (*change, error) {
		if err := versionFree(v, rp, name, pub.version); err != nil {
			return nil, err
		}
		np := p.clone(h.now)
		np.Modified = now
		for _, t := range pub.tags {
			np.setTag(t, pub.version)
		}
		if np.tag("latest") == "" {
			np.setTag("latest", pub.version)
		}
		if np.tag("latest") == pub.version {
			np.Readme, np.ReadmeSize, np.ReadmeFilename = readme.Digest, readme.Size, pub.readmeFilename
		}
		return &change{
			action: "npm.publish", target: rp.name + "/" + name + "@" + pub.version,
			pkg: np, versions: map[string]*versionRecord{pub.version: vr},
			digests: nonZero(vr.Tarball, vr.Manifest, vr.Provenance, np.Readme),
		}, nil
	})
	if err != nil {
		h.fail(w, r, err)
		return
	}
	h.publishes.With(rp.name).Inc()
	h.publishBytes.With(rp.name).Add(float64(vr.Size))
	writeJSON(w, http.StatusOK, okResponse{OK: true, ID: name, Rev: rev})
}

// okResponse answers a change to a package as CouchDB does.
type okResponse struct {
	OK  bool   `json:"ok"`
	ID  string `json:"id,omitempty"`
	Rev string `json:"rev,omitempty"`
}

// versionFree returns a 409 error if version of the package is published
// or was unpublished: a version is never published twice.
func versionFree(v meta.View, rp *repository, name, version string) error {
	rec, ok := v.Get(versionKey(rp.name, name, version))
	if !ok {
		return nil
	}
	vr, err := decodeVersion(rec.Value)
	switch {
	case err != nil:
		return err
	case vr.Kind == kindTombstone:
		return errorf(http.StatusConflict, "cannot publish %s@%s: the version was unpublished, and a version can never be published again; publish a new version",
			name, version)
	}
	return errorf(http.StatusConflict, "cannot publish over the previously published version %s@%s; publish a new version", name, version)
}

// serveEdit serves a PUT of a whole packument, as npm sends it to
// deprecate versions (npm deprecate) and to unpublish some (npm
// unpublish <name>@<version>): the packument it read, edited. Only two
// edits are accepted: a version's deprecation message changed, which
// needs write, and versions left out, which unpublishes them and needs
// delete, and the revision being edited, in the URL or in _rev. Any other
// difference in a version is refused with 400; dist-tags and the other
// top-level fields are what flint derives, and are ignored.
func (h *Handler) serveEdit(w http.ResponseWriter, r *http.Request, rp *repository, name, revStr string, body *putBody) {
	if revStr == "" {
		body.field("_rev", &revStr)
	}
	var rev meta.Seq
	if revStr != "" {
		if rev = parseRev(revStr); rev == 0 {
			writeError(w, http.StatusConflict, "%q is not a revision of %s; read the package again and retry", abbrev(revStr), name)
			return
		}
	}
	var edited map[string]map[string]json.RawMessage
	if ok, err := body.field("versions", &edited); err != nil {
		h.fail(w, r, err)
		return
	} else if !ok {
		writeError(w, http.StatusBadRequest, "an edit of %s must carry its versions", name)
		return
	}
	// Unpublishing needs delete, and a revision, so that a version
	// published after the client read the package is never taken for
	// one it left out.
	v := h.meta.View()
	_, _, err := hostedPackage(v, rp, name)
	var vrs map[string]*versionRecord
	if err == nil {
		vrs, err = hostedVersions(v, rp, name)
	}
	v.Release()
	if err != nil {
		h.fail(w, r, err)
		return
	}
	if removed := leftOut(vrs, edited); len(removed) > 0 {
		if rev == 0 {
			writeError(w, http.StatusBadRequest, "an edit that unpublishes versions of %s must name the revision it edits", name)
			return
		}
		if !h.permit(w, r, rp, ActionDelete) {
			return
		}
	}
	ctx := r.Context()
	newRev, _, err := h.update(r, rp, name, rev, func(v meta.View, p *pkgRecord, vrs map[string]*versionRecord) (*change, error) {
		if p == nil || p.tag("latest") == "" {
			return nil, notFound(name)
		}
		c := &change{versions: map[string]*versionRecord{}, action: "npm.deprecate"}
		for _, ver := range sortedKeys(edited) {
			m := edited[ver]
			vr := vrs[ver]
			switch {
			case vr == nil:
				return nil, errorf(http.StatusBadRequest, "%s@%s is not published: publish new versions with npm publish", name, abbrev(ver))
			case vr.Kind == kindTombstone:
				return nil, errorf(http.StatusBadRequest, "%s@%s was unpublished and cannot be edited", name, ver)
			}
			stored, err := h.readBlob(ctx, vr.Manifest, vr.ManifestSize)
			if err != nil {
				return nil, err
			}
			if f, err := changedField(stored, m); err != nil {
				return nil, err
			} else if f != "" {
				return nil, errorf(http.StatusBadRequest, "%s@%s differs in %s: an edit of a package can only change deprecation messages", name, ver, abbrev(f))
			}
			var dep string
			if raw, ok := m["deprecated"]; ok && string(raw) != "null" {
				if json.Unmarshal(raw, &dep) != nil {
					return nil, errorf(http.StatusBadRequest, "the deprecation message of %s@%s is not a string", name, ver)
				}
			}
			if dep != vr.Deprecated {
				nv := *vr
				nv.Deprecated = dep
				c.versions[ver] = &nv
			}
		}
		removed := leftOut(vrs, edited)
		if len(removed) > 0 && rev == 0 {
			return nil, errorf(http.StatusConflict, "package %s changed since it was read; read it again and retry", name)
		}
		if len(c.versions) == 0 && len(removed) == 0 {
			return nil, nil
		}
		now := h.now().UTC()
		c.pkg = p.clone(h.now)
		c.pkg.Modified = now
		if len(removed) > 0 {
			c.action = "npm.unpublish"
			unpublish(c, c.pkg, vrs, removed, now)
		}
		c.target = rp.name + "/" + name + "@" + strings.Join(sortedKeys(c.versions), ",")
		return c, nil
	})
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, okResponse{OK: true, ID: name, Rev: newRev})
}

// leftOut returns the live versions that an edited packument leaves out.
func leftOut(vrs map[string]*versionRecord, edited map[string]map[string]json.RawMessage) []string {
	var out []string
	for ver, vr := range vrs {
		if _, ok := edited[ver]; !ok && vr.Kind == kindLive {
			out = append(out, ver)
		}
	}
	return out
}

// editableFields are the version fields an edit may differ in from what
// is stored: what flint sets itself when it serves a version.
var editableFields = map[string]bool{"dist": true, "deprecated": true, "readme": true}

// changedField returns the first field, in sorted order, in which an
// edited manifest differs from the stored one, other than the editable
// fields, or "" if none.
func changedField(stored []byte, edited map[string]json.RawMessage) (string, error) {
	var orig map[string]json.RawMessage
	if err := json.Unmarshal(stored, &orig); err != nil {
		return "", err
	}
	keys := map[string]bool{}
	for k := range orig {
		keys[k] = true
	}
	for k := range edited {
		keys[k] = true
	}
	for _, k := range sortedKeys(keys) {
		if editableFields[k] {
			continue
		}
		var a, b any
		ea, eb := json.Unmarshal(orig[k], &a), json.Unmarshal(edited[k], &b)
		if _, ok := orig[k]; !ok || ea != nil {
			return k, nil
		}
		if _, ok := edited[k]; !ok || eb != nil || !reflect.DeepEqual(a, b) {
			return k, nil
		}
	}
	return "", nil
}

// serveUnpublishAll serves DELETE /npm/<repo>/<name>/-rev/<rev>, with
// which npm unpublishes a whole package: every version is unpublished,
// leaving tombstones, and the package keeps no dist-tags. The package
// record stays, so the repository keeps owning the name, and new versions
// can be published later.
func (h *Handler) serveUnpublishAll(w http.ResponseWriter, r *http.Request, rp *repository, name, revStr string) {
	if !h.permit(w, r, rp, ActionDelete) {
		return
	}
	rev := parseRev(revStr)
	if rev == 0 {
		writeError(w, http.StatusConflict, "%q is not a revision of %s; read the package again and retry", abbrev(revStr), name)
		return
	}
	_, _, err := h.update(r, rp, name, rev, func(_ meta.View, p *pkgRecord, vrs map[string]*versionRecord) (*change, error) {
		var live []string
		for ver, vr := range vrs {
			if vr.Kind == kindLive {
				live = append(live, ver)
			}
		}
		if p == nil || len(live) == 0 {
			return nil, notFound(name)
		}
		now := h.now().UTC()
		c := &change{action: "npm.unpublish", target: rp.name + "/" + name, pkg: p.clone(h.now), versions: map[string]*versionRecord{}}
		c.pkg.Modified = now
		unpublish(c, c.pkg, vrs, live, now)
		return c, nil
	})
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, okResponse{OK: true, ID: name})
}

// serveTarballDelete serves DELETE /npm/<repo>/<name>/-/<file>/-rev/<rev>,
// with which npm unpublish removes a version's tarball after it has
// removed the version from the packument. A version already unpublished
// is answered with success; a live one is unpublished.
func (h *Handler) serveTarballDelete(w http.ResponseWriter, r *http.Request, rp *repository, name, file, revStr string) {
	if !h.permit(w, r, rp, ActionDelete) {
		return
	}
	ver, ok := tarballVersion(name, file)
	if !ok {
		writeError(w, http.StatusNotFound, "%s is not a tarball of %s", abbrev(file), name)
		return
	}
	rev := parseRev(revStr)
	if rev == 0 {
		writeError(w, http.StatusConflict, "%q is not a revision of %s; read the package again and retry", abbrev(revStr), name)
		return
	}
	_, _, err := h.update(r, rp, name, rev, func(_ meta.View, p *pkgRecord, vrs map[string]*versionRecord) (*change, error) {
		vr := vrs[ver]
		switch {
		case p == nil || vr == nil:
			return nil, errorf(http.StatusNotFound, "%s@%s is not found", name, ver)
		case vr.Kind == kindTombstone:
			return nil, nil
		}
		now := h.now().UTC()
		c := &change{action: "npm.unpublish", target: rp.name + "/" + name + "@" + ver, pkg: p.clone(h.now), versions: map[string]*versionRecord{}}
		c.pkg.Modified = now
		unpublish(c, c.pkg, vrs, []string{ver}, now)
		return c, nil
	})
	if err != nil {
		h.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, okResponse{OK: true, ID: name})
}
