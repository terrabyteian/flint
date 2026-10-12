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

// schemeTag parses a tag of cosign's tag scheme, sha256-<hex>.sig, .att,
// or .sbom, under which cosign stores a signature, attestation, or SBOM of
// the manifest sha256:<hex>. It returns that manifest's digest and the
// artifact's kind.
func schemeTag(tag string) (digest, kind string, ok bool) {
	hex, ok := strings.CutPrefix(tag, "sha256-")
	if !ok {
		return "", "", false
	}
	i := strings.LastIndexByte(hex, '.')
	if i < 0 {
		return "", "", false
	}
	switch hex[i:] {
	case ".sig":
		kind = kindSignature
	case ".att":
		kind = kindAttestation
	case ".sbom":
		kind = kindSBOM
	default:
		return "", "", false
	}
	hex = hex[:i]
	if len(hex) != 64 || strings.Trim(hex, "0123456789abcdef") != "" {
		return "", "", false
	}
	return "sha256:" + hex, kind, true
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
	// Proofs are the kinds of the manifest's referrers and of its
	// cosign tag-scheme artifacts, such as "signature" and "SBOM", each
	// once.
	Proofs []string
	Pushed time.Time
}

// imageStats summarize an image for its page's stat strip.
type imageStats struct {
	Tags, Manifests int
	Platforms       []string
	// Signed counts the tagged manifests that have a signature, of
	// Tagged, which leaves out cosign's tag-scheme artifact tags.
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
	// refs holds the referrers of each stored manifest, by subject or by
	// cosign tag scheme; kindOf names each referrer's kind, and proofs
	// the kinds each manifest has.
	refs := map[string][]*browse.ManifestSummary{}
	kindOf := map[string]string{}
	proofs := map[string][]string{}
	addProof := func(digest, kind string) {
		if !slices.Contains(proofs[digest], kind) {
			proofs[digest] = append(proofs[digest], kind)
		}
	}
	for i := range img.Manifests {
		m := &img.Manifests[i]
		for _, c := range m.Children {
			if byDigest[c.Digest] != nil {
				childOf[c.Digest] = true
			}
		}
		if m.Subject != "" {
			kindOf[m.Digest] = referrerKind(m.ArtifactType)
			if byDigest[m.Subject] != nil {
				refs[m.Subject] = append(refs[m.Subject], m)
				addProof(m.Subject, kindOf[m.Digest])
			}
		}
	}
	for _, t := range img.Tags {
		d, k, ok := schemeTag(t.Name)
		if !ok {
			continue
		}
		addProof(d, k)
		if m := byDigest[t.Digest]; m != nil && byDigest[d] != nil && kindOf[m.Digest] == "" {
			refs[d] = append(refs[d], m)
			kindOf[m.Digest] = k
		}
	}
	referred := map[string]bool{}
	for _, rs := range refs {
		for _, rm := range rs {
			referred[rm.Digest] = true
		}
	}
	shown := map[string]bool{}
	var rows []manifestRow
	row := func(m *browse.ManifestSummary, depth int) manifestRow {
		shown[m.Digest] = true
		return manifestRow{ManifestSummary: *m, Href: href(m.Digest), Depth: depth, Artifact: artifactTypeOf(m.ArtifactType),
			Kind: kindOf[m.Digest]}
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
		if !childOf[m.Digest] && !referred[m.Digest] {
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
	for _, p := range proofs {
		slices.Sort(p)
	}
	var tags []tagRow
	tagged := map[string]bool{}
	for _, t := range img.Tags {
		tr := tagRow{ImageTag: t, Href: href(t.Digest), Proofs: proofs[t.Digest]}
		if m := byDigest[t.Digest]; m != nil {
			tr.Index, tr.Pushed = m.Index, m.Pushed
			for _, c := range m.Children {
				if c.Platform != "" {
					tr.Platforms = append(tr.Platforms, c.Platform)
				}
			}
		}
		tags = append(tags, tr)
		if _, _, artifact := schemeTag(t.Name); !artifact && !tagged[t.Digest] {
			tagged[t.Digest] = true
			st.Tagged++
			if slices.Contains(tr.Proofs, kindSignature) {
				st.Signed++
			}
		}
	}
	return tags, rows, st
}
