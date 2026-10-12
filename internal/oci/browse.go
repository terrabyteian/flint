package oci

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/terrabyteian/flint/internal/blob"
	"github.com/terrabyteian/flint/internal/browse"
	"github.com/terrabyteian/flint/internal/meta"
)

// The web UI's view of hosted and proxy OCI repositories, read from the
// records the registry keeps: a proxy repository shows what it cached.
// Virtual repositories have none of their own.

var _ browse.Images = (*Handler)(nil)

// browseRepo returns the hosted or proxy repository named repo.
func (h *Handler) browseRepo(repo string) (*repository, error) {
	cfg := h.repos[repo]
	if cfg == nil || cfg.virtual != nil {
		return nil, browse.ErrNotFound
	}
	return cfg, nil
}

// ListImages implements browse.Images.
func (h *Handler) ListImages(repo string, q browse.Query) ([]browse.Image, bool, error) {
	if _, err := h.browseRepo(repo); err != nil {
		return nil, false, err
	}
	v := h.view()
	defer v.Release()
	pfx := []byte(nsManifest + repo + "\x00")
	var after []byte
	if q.After != "" {
		// Past every manifest of the image named After: its keys are
		// After, 0x00, digest, and 0x01 sorts after 0x00.
		after = append(append(bytes.Clone(pfx), q.After...), 1)
	}
	var out []browse.Image
	more := false
	for !more {
		var name string
		v.Scan(pfx, after, func(k []byte, _ meta.Record) bool {
			rest := k[len(pfx):]
			if i := bytes.IndexByte(rest, 0); i > 0 {
				name = string(rest[:i])
			}
			return false
		})
		if name == "" {
			break
		}
		after = append(append(bytes.Clone(pfx), name...), 1)
		if !q.Match(name) {
			continue
		}
		if q.Full(len(out)) {
			more = true
			break
		}
		img, err := imageSummary(v, &repoName{repo: repo, name: name})
		if err != nil {
			return nil, false, err
		}
		out = append(out, img)
	}
	return out, more, nil
}

// imageSummary counts an image's tags and manifests.
func imageSummary(v meta.View, rn *repoName) (browse.Image, error) {
	img := browse.Image{Name: rn.name}
	var failure error
	v.Scan(prefix(nsManifest, rn), nil, func(k []byte, r meta.Record) bool {
		img.Manifests++
		m, err := decodeManifest(r.Value)
		if err != nil {
			failure = fmt.Errorf("oci: manifest record %q: %w", k, err)
			return false
		}
		if m.Pushed.After(img.Updated) {
			img.Updated = m.Pushed
		}
		return true
	})
	v.Scan(prefix(nsTag, rn), nil, func([]byte, meta.Record) bool {
		img.Tags++
		return true
	})
	return img, failure
}

// Image implements browse.Images.
func (h *Handler) Image(repo, name string) (*browse.ImageDetail, error) {
	if _, err := h.browseRepo(repo); err != nil {
		return nil, err
	}
	rn := &repoName{repo: repo, name: name}
	v := h.view()
	defer v.Release()
	img := &browse.ImageDetail{Name: name}
	tagsOf := map[string][]string{}
	var failure error
	tp := prefix(nsTag, rn)
	v.Scan(tp, nil, func(k []byte, r meta.Record) bool {
		d, err := decodeTag(r.Value)
		if err != nil {
			failure = fmt.Errorf("oci: tag record %q: %w", k, err)
			return false
		}
		tag := string(k[len(tp):])
		img.Tags = append(img.Tags, browse.ImageTag{Name: tag, Digest: d.String()})
		tagsOf[d.String()] = append(tagsOf[d.String()], tag)
		return true
	})
	if failure != nil {
		return nil, failure
	}
	mp := prefix(nsManifest, rn)
	v.Scan(mp, nil, func(k []byte, r meta.Record) bool {
		m, err := decodeManifest(r.Value)
		if err != nil {
			failure = fmt.Errorf("oci: manifest record %q: %w", k, err)
			return false
		}
		d := string(k[len(mp):])
		img.Manifests = append(img.Manifests, manifestSummary(d, m, tagsOf[d]))
		return true
	})
	if failure != nil {
		return nil, failure
	}
	if len(img.Manifests) == 0 && len(img.Tags) == 0 {
		return nil, browse.ErrNotFound
	}
	slices.SortStableFunc(img.Manifests, func(a, b browse.ManifestSummary) int {
		// Tagged first, then newest first.
		if (len(a.Tags) > 0) != (len(b.Tags) > 0) {
			if len(a.Tags) > 0 {
				return -1
			}
			return 1
		}
		return b.Pushed.Compare(a.Pushed)
	})
	return img, nil
}

func manifestSummary(digest string, m *manifestRecord, tags []string) browse.ManifestSummary {
	s := browse.ManifestSummary{Digest: digest, MediaType: m.MediaType, ArtifactType: m.ArtifactType, Size: m.Size,
		Pushed: m.Pushed, Tags: tags, Index: isIndexType(m.MediaType)}
	if !m.Subject.IsZero() {
		s.Subject = m.Subject.String()
	}
	return s
}

// browseDescriptor is a descriptor as the UI reads it, with an index
// child's platform.
type browseDescriptor struct {
	descriptor
	Platform *struct {
		OS           string `json:"os"`
		Architecture string `json:"architecture"`
		Variant      string `json:"variant"`
		OSVersion    string `json:"os.version"`
	} `json:"platform"`
}

// Manifest implements browse.Images.
func (h *Handler) Manifest(ctx context.Context, repo, name, digest string) (*browse.Manifest, error) {
	if _, err := h.browseRepo(repo); err != nil {
		return nil, err
	}
	d, err := blob.ParseDigest(digest)
	if err != nil {
		return nil, browse.ErrNotFound
	}
	rn := &repoName{repo: repo, name: name}
	v := h.view()
	rec, ok := v.Get(manifestKey(rn, d))
	if !ok {
		v.Release()
		return nil, browse.ErrNotFound
	}
	m, err := decodeManifest(rec.Value)
	if err != nil {
		v.Release()
		return nil, fmt.Errorf("oci: manifest record of %s in %s/%s: %w", d, repo, name, err)
	}
	var tags []string
	tp := prefix(nsTag, rn)
	v.Scan(tp, nil, func(k []byte, r meta.Record) bool {
		if td, err := decodeTag(r.Value); err == nil && td == d {
			tags = append(tags, string(k[len(tp):]))
		}
		return true
	})
	out := &browse.Manifest{ManifestSummary: manifestSummary(digest, m, tags), TotalSize: m.Size}
	rp := referrerPrefix(rn, d)
	var referrers []blob.Digest
	v.Scan(rp, nil, func(k []byte, _ meta.Record) bool {
		if rd, err := blob.ParseDigest(string(k[len(rp):])); err == nil {
			referrers = append(referrers, rd)
		}
		return true
	})
	for _, rd := range referrers {
		rr, ok := v.Get(manifestKey(rn, rd))
		if !ok {
			continue
		}
		rm, err := decodeManifest(rr.Value)
		if err != nil {
			continue
		}
		out.Referrers = append(out.Referrers, browse.Descriptor{MediaType: rm.MediaType, ArtifactType: rm.ArtifactType,
			Digest: rd.String(), Size: rm.Size, Annotations: annotationsJSON(rm.Annotations), Stored: true})
	}
	slices.SortFunc(out.Referrers, func(a, b browse.Descriptor) int {
		return strings.Compare(a.ArtifactType+a.Digest, b.ArtifactType+b.Digest)
	})
	v.Release()

	body, err := h.readBlob(ctx, d, m.Size)
	if err != nil {
		return nil, fmt.Errorf("oci: reading manifest %s: %w", d, err)
	}
	var doc struct {
		Config      *browseDescriptor  `json:"config"`
		Layers      []browseDescriptor `json:"layers"`
		Manifests   []browseDescriptor `json:"manifests"`
		Annotations map[string]string  `json:"annotations"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("oci: manifest %s: %w", d, err)
	}
	if doc.Config != nil {
		c := toBrowse(*doc.Config)
		out.Config = &c
		out.TotalSize += c.Size
	}
	for _, l := range doc.Layers {
		out.Layers = append(out.Layers, toBrowse(l))
		out.TotalSize += l.Size
	}
	if len(doc.Manifests) > 0 {
		v := h.view()
		for _, c := range doc.Manifests {
			bd := toBrowse(c)
			if cd, err := blob.ParseDigest(c.Digest); err == nil {
				_, bd.Stored = v.Get(manifestKey(rn, cd))
			}
			out.Manifests = append(out.Manifests, bd)
		}
		v.Release()
	}
	out.Annotations = sortedAnnotations(doc.Annotations)
	return out, nil
}

func toBrowse(d browseDescriptor) browse.Descriptor {
	out := browse.Descriptor{MediaType: d.MediaType, ArtifactType: d.ArtifactType, Digest: d.Digest, Size: d.Size,
		Annotations: sortedAnnotations(d.Annotations)}
	if p := d.Platform; p != nil {
		out.Platform = p.OS + "/" + p.Architecture
		if p.Variant != "" {
			out.Platform += "/" + p.Variant
		}
		if p.OSVersion != "" {
			out.Platform += " (" + p.OSVersion + ")"
		}
	}
	return out
}

// annotationsJSON decodes the annotations a manifest record keeps as a
// JSON object.
func annotationsJSON(s string) []browse.Annotation {
	if s == "" {
		return nil
	}
	var m map[string]string
	if json.Unmarshal([]byte(s), &m) != nil {
		return nil
	}
	return sortedAnnotations(m)
}

func sortedAnnotations(m map[string]string) []browse.Annotation {
	var out []browse.Annotation
	for k, v := range m {
		out = append(out, browse.Annotation{Key: k, Value: v})
	}
	slices.SortFunc(out, func(a, b browse.Annotation) int { return strings.Compare(a.Key, b.Key) })
	return out
}
