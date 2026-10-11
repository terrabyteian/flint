package oci

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/terrabyteian/flint/internal/blob"
	"github.com/terrabyteian/flint/internal/meta"
)

// Manifest media types.
const (
	mtOCIManifest    = "application/vnd.oci.image.manifest.v1+json"
	mtOCIIndex       = "application/vnd.oci.image.index.v1+json"
	mtDockerManifest = "application/vnd.docker.distribution.manifest.v2+json"
	mtDockerList     = "application/vnd.docker.distribution.manifest.list.v2+json"
	mtDockerSchema1  = "application/vnd.docker.distribution.manifest.v1+json"
	mtDockerSigned   = "application/vnd.docker.distribution.manifest.v1+prettyjws"
)

// maxManifestSize bounds a pushed manifest at the 4 MiB clients expect registries to accept.
const maxManifestSize = 4 << 20

func isIndexType(mt string) bool { return mt == mtOCIIndex || mt == mtDockerList }

func supportedManifestType(mt string) bool {
	switch mt {
	case mtOCIManifest, mtOCIIndex, mtDockerManifest, mtDockerList:
		return true
	}
	return false
}

// nonDistributable reports whether a layer media type marks content that
// clients fetch from elsewhere (its descriptor's URLs), so a registry
// never holds it.
func nonDistributable(mt string) bool {
	return strings.HasPrefix(mt, "application/vnd.oci.image.layer.nondistributable.") ||
		mt == "application/vnd.docker.image.rootfs.foreign.diff.tar.gzip"
}

type descriptor struct {
	MediaType    string            `json:"mediaType"`
	Digest       string            `json:"digest"`
	Size         int64             `json:"size"`
	ArtifactType string            `json:"artifactType,omitempty"`
	Annotations  map[string]string `json:"annotations,omitempty"`
}

// manifestDoc holds the fields of every supported manifest type that the
// registry reads.
type manifestDoc struct {
	SchemaVersion *int              `json:"schemaVersion"`
	MediaType     string            `json:"mediaType"`
	ArtifactType  string            `json:"artifactType"`
	Config        *descriptor       `json:"config"`
	Layers        []descriptor      `json:"layers"`
	Manifests     []descriptor      `json:"manifests"`
	Subject       *descriptor       `json:"subject"`
	Annotations   map[string]string `json:"annotations"`
}

func manifestInvalid(format string, args ...any) *apiError {
	return newError(http.StatusBadRequest, codeManifestInvalid, format, args...)
}

func manifestUnknown(rn *repoName, ref string) error {
	return newError(http.StatusNotFound, codeManifestUnknown, "manifest %s is not known to repository %s", abbrev(ref), rn.full)
}

// parsedManifest is a validated manifest awaiting its reference checks.
type parsedManifest struct {
	record  manifestRecord
	blobs   []descriptor // config and layers that must be linked
	members []descriptor // index members that must be stored
}

// parseManifest validates a pushed manifest body. contentType is the
// request's Content-Type.
func parseManifest(body []byte, contentType string) (*parsedManifest, error) {
	ct, _, _ := mime.ParseMediaType(contentType)
	var doc manifestDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, manifestInvalid("the manifest is not valid JSON: %v", err)
	}
	mt := doc.MediaType
	switch {
	case mt == mtDockerSchema1 || mt == mtDockerSigned || ct == mtDockerSchema1 || ct == mtDockerSigned ||
		doc.SchemaVersion != nil && *doc.SchemaVersion == 1:
		return nil, manifestInvalid("Docker image manifest schema 1 is not supported; push schema 2 or an OCI manifest")
	case mt != "" && supportedManifestType(ct) && ct != mt:
		return nil, manifestInvalid("the manifest's mediaType %q does not match its Content-Type %q", mt, ct)
	case mt == "" && supportedManifestType(ct):
		mt = ct
	case mt == "" && doc.Manifests != nil:
		mt = mtOCIIndex
	case mt == "" && doc.Config != nil:
		mt = mtOCIManifest
	}
	if !supportedManifestType(mt) {
		return nil, manifestInvalid("unsupported manifest media type %q", abbrev(mt))
	}
	if doc.SchemaVersion == nil || *doc.SchemaVersion != 2 {
		return nil, manifestInvalid("schemaVersion must be 2")
	}

	p := &parsedManifest{record: manifestRecord{MediaType: mt, Size: int64(len(body))}}
	check := func(field string, ds ...descriptor) error {
		for i, d := range ds {
			_, err := blob.ParseDigest(d.Digest)
			if errors.Is(err, blob.ErrDigestUnsupported) {
				return newError(http.StatusBadRequest, codeManifestBlobUnknown, "%s[%d]: %v", field, i, err).
					withDetail(map[string]string{"digest": d.Digest})
			}
			if err != nil {
				return manifestInvalid("%s[%d]: %v", field, i, err)
			}
			if d.Size < 0 {
				return manifestInvalid("%s[%d]: negative size", field, i)
			}
		}
		return nil
	}
	if isIndexType(mt) {
		if doc.Manifests == nil {
			return nil, manifestInvalid("an index needs a manifests array")
		}
		if err := check("manifests", doc.Manifests...); err != nil {
			return nil, err
		}
		p.members = doc.Manifests
		p.record.ArtifactType = doc.ArtifactType
	} else {
		if doc.Config == nil {
			return nil, manifestInvalid("an image manifest needs a config descriptor")
		}
		if err := check("config", *doc.Config); err != nil {
			return nil, err
		}
		if err := check("layers", doc.Layers...); err != nil {
			return nil, err
		}
		p.blobs = append(p.blobs, *doc.Config)
		for _, l := range doc.Layers {
			if !nonDistributable(l.MediaType) {
				p.blobs = append(p.blobs, l)
			}
		}
		// The referrers API reports the config media type when the
		// manifest has no artifactType.
		p.record.ArtifactType = doc.ArtifactType
		if p.record.ArtifactType == "" {
			p.record.ArtifactType = doc.Config.MediaType
		}
	}
	if doc.Subject != nil {
		if err := check("subject", *doc.Subject); err != nil {
			return nil, err
		}
		p.record.Subject, _ = blob.ParseDigest(doc.Subject.Digest)
	}
	if len(doc.Annotations) > 0 {
		a, _ := json.Marshal(doc.Annotations)
		p.record.Annotations = string(a)
	}
	return p, nil
}

// putManifest serves PUT /v2/<name>/manifests/<reference>, by tag or by
// digest, with any extra tags given as ?tag= parameters.
func (h *Handler) putManifest(w http.ResponseWriter, r *http.Request, rn *repoName, ref string) {
	ctx := r.Context()
	var tags []string
	var want blob.Digest
	if strings.Contains(ref, ":") {
		d, err := parseDigest(ref)
		if err != nil {
			h.writeError(w, r, err)
			return
		}
		want = d
	} else if validTag(ref) {
		tags = append(tags, ref)
	} else {
		h.writeError(w, r, manifestInvalid("invalid tag %q", abbrev(ref)))
		return
	}
	for _, t := range r.URL.Query()["tag"] {
		if !validTag(t) {
			h.writeError(w, r, manifestInvalid("invalid tag %q", abbrev(t)))
			return
		}
		if !slices.Contains(tags, t) {
			tags = append(tags, t)
		}
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, maxManifestSize+1))
	if err != nil {
		h.writeError(w, r, manifestInvalid("reading the manifest: %v", err))
		return
	}
	if len(body) > maxManifestSize {
		h.writeError(w, r, newError(http.StatusRequestEntityTooLarge, codeSizeInvalid,
			"the manifest exceeds the limit of %d bytes", maxManifestSize))
		return
	}
	d := blob.FromBytes(body)
	if !want.IsZero() && want != d {
		h.writeError(w, r, newError(http.StatusBadRequest, codeDigestInvalid,
			"the manifest's digest is %s, not %s", d, want).withDetail(map[string]string{"digest": want.String()}))
		return
	}
	pm, err := parseManifest(body, r.Header.Get("Content-Type"))
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	target := rn.full + "@" + d.String()
	if len(tags) > 0 {
		target = rn.full + ":" + strings.Join(tags, ",") + "@" + d.String()
	}

	err = h.commitLink(ctx, []blob.Digest{d}, func(v meta.View, b *meta.Batch) error {
		refs, err := checkReferences(v, b, rn, pm)
		if err != nil {
			return err
		}
		rec := pm.record
		rec.Refs = refs
		b.Put(manifestKey(rn, d), rec.encode())
		if !rec.Subject.IsZero() {
			b.Put(referrerKey(rn, rec.Subject, d), newEnc())
		}
		for _, t := range tags {
			cur, ok := v.Get(tagKey(rn, t))
			if ok && rn.cfg.immutableTags {
				if old, err := decodeTag(cur.Value); err != nil || old != d {
					return newError(http.StatusConflict, codeDenied,
						"tag %q already exists and tags in repository %s are immutable", t, rn.repo).
						withDetail(map[string]string{"tag": t})
				}
				continue // the same manifest again: nothing to change
			}
			if rn.cfg.immutableTags {
				b.Require(tagKey(rn, t), 0)
			}
			b.Put(tagKey(rn, t), encodeTag(d))
		}
		b.SetOrigin(h.origin(r, "oci.manifest.push", target))
		return nil
	}, func(attempt int) error {
		// Store the manifest's bytes as a blob. Identical content is
		// stored once, so a retry costs little.
		up, err := h.blobs.NewUpload(ctx)
		if err != nil {
			return err
		}
		if _, err := up.Write(body); err != nil {
			up.Cancel()
			return err
		}
		_, err = up.Commit(ctx, d)
		return err
	})
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	h.manifestPuts.With(rn.repo).Inc()
	hd := w.Header()
	hd.Set("Location", "/v2/"+rn.full+"/manifests/"+d.String())
	hd.Set("Docker-Content-Digest", d.String())
	if !pm.record.Subject.IsZero() {
		hd.Set("OCI-Subject", pm.record.Subject.String())
	}
	hd.Set("Content-Length", "0")
	w.WriteHeader(http.StatusCreated)
}

// checkReferences verifies, in view v, that every blob a manifest
// references is linked in rn and every index member is stored there, each
// with the size its descriptor claims. It requires each of them to be
// unchanged when b commits, so a concurrent delete cannot leave the
// manifest pointing at nothing, and returns the references for the record.
func checkReferences(v meta.View, b *meta.Batch, rn *repoName, pm *parsedManifest) ([]manifestRef, error) {
	refs := make([]manifestRef, 0, len(pm.blobs)+len(pm.members))
	seen := map[manifestRef]bool{}
	missing := func(d descriptor, what string) error {
		return newError(http.StatusBadRequest, codeManifestBlobUnknown,
			"the manifest references %s %s, which is not in repository %s; push it first", what, d.Digest, rn.full).
			withDetail(map[string]string{"digest": d.Digest})
	}
	for _, desc := range pm.blobs {
		d, _ := blob.ParseDigest(desc.Digest)
		key := blobKey(rn, d)
		rec, ok := v.Get(key)
		if !ok {
			return nil, missing(desc, "blob")
		}
		size, err := decodeBlobLink(rec.Value)
		if err != nil {
			return nil, err
		}
		if size != desc.Size {
			return nil, manifestInvalid("the descriptor of blob %s gives size %d, but the blob has %d bytes", d, desc.Size, size)
		}
		if r := (manifestRef{refBlob, d}); !seen[r] {
			seen[r] = true
			b.Require(key, rec.Version)
			refs = append(refs, r)
		}
	}
	for _, desc := range pm.members {
		d, _ := blob.ParseDigest(desc.Digest)
		key := manifestKey(rn, d)
		rec, ok := v.Get(key)
		if !ok {
			return nil, missing(desc, "manifest")
		}
		m, err := decodeManifest(rec.Value)
		if err != nil {
			return nil, err
		}
		if m.Size != desc.Size {
			return nil, manifestInvalid("the descriptor of manifest %s gives size %d, but the manifest has %d bytes", d, desc.Size, m.Size)
		}
		if r := (manifestRef{refManifest, d}); !seen[r] {
			seen[r] = true
			b.Require(key, rec.Version)
			refs = append(refs, r)
		}
	}
	return refs, nil
}

// lookupManifest resolves a tag or digest reference in view v.
func lookupManifest(v meta.View, rn *repoName, ref string) (blob.Digest, *manifestRecord, meta.Seq, error) {
	var d blob.Digest
	if strings.Contains(ref, ":") {
		var err error
		if d, err = parseDigest(ref); err != nil {
			return d, nil, 0, err
		}
	} else {
		if !validTag(ref) {
			return d, nil, 0, manifestUnknown(rn, ref)
		}
		rec, ok := v.Get(tagKey(rn, ref))
		if !ok {
			return d, nil, 0, manifestUnknown(rn, ref)
		}
		var err error
		if d, err = decodeTag(rec.Value); err != nil {
			return d, nil, 0, err
		}
	}
	rec, ok := v.Get(manifestKey(rn, d))
	if !ok {
		return d, nil, 0, manifestUnknown(rn, ref)
	}
	m, err := decodeManifest(rec.Value)
	return d, m, rec.Version, err
}

// accepts reports whether the request's Accept headers admit media type
// mt. A request without Accept headers accepts anything.
func accepts(r *http.Request, mt string) bool {
	values := r.Header.Values("Accept")
	if len(values) == 0 {
		return true
	}
	major, _, _ := strings.Cut(mt, "/")
	for _, v := range values {
		for part := range strings.SplitSeq(v, ",") {
			a, _, _ := strings.Cut(part, ";")
			switch a = strings.TrimSpace(a); a {
			case mt, "*/*", major + "/*":
				return true
			}
		}
	}
	return false
}

// getManifest serves GET and HEAD /v2/<name>/manifests/<reference>.
func (h *Handler) getManifest(w http.ResponseWriter, r *http.Request, rn *repoName, ref string) {
	v := h.view()
	d, m, _, err := lookupManifest(v, rn, ref)
	v.Release()
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	h.serveManifest(w, r, rn, ref, d, m, nil)
}

// serveManifest serves manifest d, described by m, from body if it is
// not nil, or else from the blob store.
func (h *Handler) serveManifest(w http.ResponseWriter, r *http.Request, rn *repoName, ref string, d blob.Digest, m *manifestRecord, body []byte) {
	if !accepts(r, m.MediaType) {
		h.writeError(w, r, newError(http.StatusNotFound, codeManifestUnknown,
			"manifest %s is %s, which the request's Accept header does not include", abbrev(ref), m.MediaType))
		return
	}
	var content io.Reader = bytes.NewReader(body)
	if body == nil && r.Method != http.MethodHead {
		f, err := h.blobs.Open(r.Context(), d)
		if err != nil {
			if errors.Is(err, blob.ErrNotFound) {
				h.log.WarnContext(r.Context(), "stored manifest is missing from the blob store",
					"repository", rn.full, "digest", d.String())
				err = manifestUnknown(rn, ref)
			}
			h.writeError(w, r, err)
			return
		}
		defer f.Close()
		content = f
	}
	hd := w.Header()
	hd.Set("Content-Type", m.MediaType)
	hd.Set("Docker-Content-Digest", d.String())
	hd.Set("ETag", `"`+d.String()+`"`)
	hd.Set("Content-Length", strconv.FormatInt(m.Size, 10))
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		io.CopyN(w, content, m.Size)
	}
}

// deleteManifest serves DELETE /v2/<name>/manifests/<reference>. By tag it
// removes the tag; by digest it removes the manifest and every tag that
// points to it. Tags in a repository with immutable tags are permanent.
func (h *Handler) deleteManifest(w http.ResponseWriter, r *http.Request, rn *repoName, ref string) {
	ctx := r.Context()
	for attempt := 0; ; attempt++ {
		var b meta.Batch
		v := h.view()
		err := h.buildManifestDelete(v, &b, r, rn, ref)
		v.Release()
		if err == nil {
			err = h.commit(ctx, &b)
			if errors.Is(err, meta.ErrConflict) && attempt < maxLinkAttempts-1 {
				continue // a concurrent push changed the manifest; look again
			}
			if err != nil {
				err = storeError(err)
			}
		}
		if err != nil {
			h.writeError(w, r, err)
			return
		}
		w.Header().Set("Content-Length", "0")
		w.WriteHeader(http.StatusAccepted)
		return
	}
}

func (h *Handler) buildManifestDelete(v meta.View, b *meta.Batch, r *http.Request, rn *repoName, ref string) error {
	immutable := func(tag string) error {
		return newError(http.StatusConflict, codeDenied,
			"tag %q cannot be deleted: tags in repository %s are immutable", tag, rn.repo).
			withDetail(map[string]string{"tag": tag})
	}
	if !strings.Contains(ref, ":") {
		if !validTag(ref) {
			return manifestUnknown(rn, ref)
		}
		rec, ok := v.Get(tagKey(rn, ref))
		if !ok {
			return manifestUnknown(rn, ref)
		}
		if rn.cfg.immutableTags {
			return immutable(ref)
		}
		b.Require(tagKey(rn, ref), rec.Version)
		b.Delete(tagKey(rn, ref))
		b.SetOrigin(h.origin(r, "oci.tag.delete", rn.full+":"+ref))
		return nil
	}

	d, m, version, err := lookupManifest(v, rn, ref)
	if err != nil {
		return err
	}
	// A push that tags this manifest rewrites its record, so requiring
	// the record unchanged keeps a tag added meanwhile from dangling;
	// requiring each tag unchanged keeps a tag moved meanwhile alive.
	b.Require(manifestKey(rn, d), version)
	b.Delete(manifestKey(rn, d))
	if !m.Subject.IsZero() {
		b.Delete(referrerKey(rn, m.Subject, d))
	}
	var tagErr error
	pfx := prefix(nsTag, rn)
	v.Scan(pfx, nil, func(key []byte, rec meta.Record) bool {
		if td, err := decodeTag(rec.Value); err == nil && td == d {
			tag := string(key[len(pfx):])
			if rn.cfg.immutableTags {
				tagErr = immutable(tag)
				return false
			}
			b.Require(key, rec.Version)
			b.Delete(key)
		}
		return true
	})
	if tagErr != nil {
		return tagErr
	}
	b.SetOrigin(h.origin(r, "oci.manifest.delete", rn.full+"@"+d.String()))
	return nil
}
