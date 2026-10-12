package ui

import (
	"slices"
	"strings"
	"time"

	"github.com/terrabyteian/flint/internal/browse"
)

// An image's page groups its manifests as a tree: each index with its
// platform manifests, and every manifest with the signatures, SBOMs, and
// attestations that refer to it, so a release reads as one unit.

// Referrer kinds, by artifact type.
const (
	kindSignature   = "signature"
	kindSBOM        = "SBOM"
	kindAttestation = "attestation"
	kindReferrer    = "referrer"
)

// referrerKind names what a referrer of artifact type at is.
func referrerKind(at string) string {
	a := strings.ToLower(at)
	has := func(ss ...string) bool {
		return slices.ContainsFunc(ss, func(s string) bool { return strings.Contains(a, s) })
	}
	switch {
	case has("signature", "sigstore", "cosign.artifact.sig", "notary"):
		return kindSignature
	case has("spdx", "cyclonedx", "sbom"):
		return kindSBOM
	case has("in-toto", "intoto", "attestation", "provenance"):
		return kindAttestation
	}
	return kindReferrer
}

// imageConfigTypes are the config media types of plain container images.
// The registry reports a manifest's config media type as its artifact
// type, as the referrers API requires, but for an image that names
// nothing worth showing.
var imageConfigTypes = []string{
	"application/vnd.oci.image.config.v1+json",
	"application/vnd.docker.container.image.v1+json",
}

// artifactTypeOf returns the artifact type worth showing for a manifest
// whose recorded artifact type is at: none for a plain image.
func artifactTypeOf(at string) string {
	if slices.Contains(imageConfigTypes, at) {
		return ""
	}
	return at
}

// manifestRow is a row of an image's grouped manifest listing.
type manifestRow struct {
	browse.ManifestSummary
	Href string
	// Depth is the row's level in the tree: 0 for an index or a manifest
	// of its own, 1 for an index's child or a referrer of a level-0 row,
	// and 2 for a referrer of a child.
	Depth int
	// Platform is a child's platform, from its index.
	Platform string
	// Artifact is the artifact type worth showing; Kind names a
	// referrer's kind.
	Artifact, Kind string
	// Missing reports a child its index names that is not stored under
	// the image, as a proxy repository that cached one platform has.
	Missing bool
	// First marks the first row of a group, after which a new group
	// starts.
	First bool
}

// tagRow is a tag with what its manifest holds.
type tagRow struct {
	browse.ImageTag
	Href string
	// Index reports whether the tag names an index.
	Index     bool
	Platforms []string
	// Proofs are the kinds of the manifest's referrers, such as
	// "signature" and "SBOM", each once.
	Proofs []string
	Pushed time.Time
}

// imageStats summarize an image for its page's stat strip.
type imageStats struct {
	Tags, Manifests int
	Platforms       []string
	// Signed counts the tagged manifests that have a signature, of
	// Tagged.
	Signed, Tagged int
	LastPush       time.Time
}

// groupImage builds an image's tag rows, grouped manifest rows, and
// stats. href links a manifest digest.
func groupImage(img *browse.ImageDetail, href func(digest string) string) ([]tagRow, []manifestRow, imageStats) {
	byDigest := map[string]*browse.ManifestSummary{}
	for i := range img.Manifests {
		byDigest[img.Manifests[i].Digest] = &img.Manifests[i]
	}
	// childOf holds the stored manifests that an index names, which
	// appear under it rather than on their own.
	childOf := map[string]bool{}
	refs := map[string][]*browse.ManifestSummary{}
	for i := range img.Manifests {
		m := &img.Manifests[i]
		for _, c := range m.Children {
			if byDigest[c.Digest] != nil {
				childOf[c.Digest] = true
			}
		}
		if m.Subject != "" && byDigest[m.Subject] != nil {
			refs[m.Subject] = append(refs[m.Subject], m)
		}
	}
	shown := map[string]bool{}
	var rows []manifestRow
	row := func(m *browse.ManifestSummary, depth int) manifestRow {
		shown[m.Digest] = true
		r := manifestRow{ManifestSummary: *m, Href: href(m.Digest), Depth: depth, Artifact: artifactTypeOf(m.ArtifactType)}
		if m.Subject != "" {
			r.Kind = referrerKind(m.ArtifactType)
		}
		return r
	}
	addRefs := func(digest string, depth int) {
		for _, rm := range refs[digest] {
			rows = append(rows, row(rm, depth))
		}
	}
	top := func(m *browse.ManifestSummary) {
		r := row(m, 0)
		r.First = true
		rows = append(rows, r)
		for _, c := range m.Children {
			cm := byDigest[c.Digest]
			if cm == nil {
				rows = append(rows, manifestRow{ManifestSummary: browse.ManifestSummary{Digest: c.Digest, MediaType: c.MediaType, Size: c.Size},
					Depth: 1, Platform: c.Platform, Missing: true})
				continue
			}
			cr := row(cm, 1)
			cr.Platform = c.Platform
			rows = append(rows, cr)
			addRefs(c.Digest, 2)
		}
		addRefs(m.Digest, 1)
	}
	for i := range img.Manifests {
		m := &img.Manifests[i]
		if !childOf[m.Digest] && (m.Subject == "" || byDigest[m.Subject] == nil) {
			top(m)
		}
	}
	// Whatever no group took, such as the children of an index that is
	// itself a child, is listed on its own.
	for i := range img.Manifests {
		if m := &img.Manifests[i]; !shown[m.Digest] {
			top(m)
		}
	}

	st := imageStats{Tags: len(img.Tags), Manifests: len(img.Manifests)}
	platforms := map[string]bool{}
	for _, m := range img.Manifests {
		for _, c := range m.Children {
			if c.Platform != "" && !platforms[c.Platform] {
				platforms[c.Platform] = true
				st.Platforms = append(st.Platforms, c.Platform)
			}
		}
		if m.Pushed.After(st.LastPush) {
			st.LastPush = m.Pushed
		}
	}
	slices.Sort(st.Platforms)
	proofsOf := func(digest string) []string {
		var out []string
		for _, rm := range refs[digest] {
			if k := referrerKind(rm.ArtifactType); !slices.Contains(out, k) {
				out = append(out, k)
			}
		}
		slices.Sort(out)
		return out
	}
	var tags []tagRow
	tagged := map[string]bool{}
	for _, t := range img.Tags {
		tr := tagRow{ImageTag: t, Href: href(t.Digest), Proofs: proofsOf(t.Digest)}
		if m := byDigest[t.Digest]; m != nil {
			tr.Index, tr.Pushed = m.Index, m.Pushed
			for _, c := range m.Children {
				if c.Platform != "" {
					tr.Platforms = append(tr.Platforms, c.Platform)
				}
			}
		}
		tags = append(tags, tr)
		if !tagged[t.Digest] {
			tagged[t.Digest] = true
			st.Tagged++
			if slices.Contains(tr.Proofs, kindSignature) {
				st.Signed++
			}
		}
	}
	return tags, rows, st
}
