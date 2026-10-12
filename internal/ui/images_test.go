package ui

import (
	"strings"
	"testing"
	"time"

	"github.com/terrabyteian/flint/internal/browse"
)

func TestReferrerKind(t *testing.T) {
	for at, want := range map[string]string{
		"application/vnd.dev.sigstore.bundle.v0.3+json":   kindSignature,
		"application/vnd.dev.cosign.artifact.sig.v1+json": kindSignature,
		"application/vnd.cncf.notary.signature":           kindSignature,
		"application/spdx+json":                           kindSBOM,
		"application/vnd.cyclonedx+json":                  kindSBOM,
		"application/vnd.in-toto+json":                    kindAttestation,
		"application/vnd.example.provenance+json":         kindAttestation,
		"application/vnd.example.thing":                   kindReferrer,
		"":                                                kindReferrer,
	} {
		if got := referrerKind(at); got != want {
			t.Errorf("referrerKind(%q) = %q, want %q", at, got, want)
		}
	}
}

func TestArtifactTypeOf(t *testing.T) {
	for at, want := range map[string]string{
		"application/vnd.oci.image.config.v1+json":       "",
		"application/vnd.docker.container.image.v1+json": "",
		"application/vnd.cncf.helm.config.v1+json":       "application/vnd.cncf.helm.config.v1+json",
		"application/spdx+json":                          "application/spdx+json",
		"":                                               "",
	} {
		if got := artifactTypeOf(at); got != want {
			t.Errorf("artifactTypeOf(%q) = %q, want %q", at, got, want)
		}
	}
}

// TestGroupImage groups manifests as a tree: indexes with their children
// and every manifest with its referrers, and lists what no group takes on
// its own.
func TestGroupImage(t *testing.T) {
	day := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	img := &browse.ImageDetail{
		Tags: []browse.ImageTag{{Name: "latest", Digest: "idx"}, {Name: "v1", Digest: "idx"}, {Name: "old", Digest: "solo"}},
		Manifests: []browse.ManifestSummary{
			{Digest: "idx", Index: true, Tags: []string{"latest", "v1"}, Pushed: day.Add(2 * time.Hour),
				Children: []browse.Descriptor{{Digest: "amd", Platform: "linux/amd64", Stored: true},
					{Digest: "arm", Platform: "linux/arm64"}, {Digest: "nested", Stored: true}}},
			{Digest: "solo", Tags: []string{"old"}, Pushed: day},
			{Digest: "amd", ArtifactType: "application/vnd.oci.image.config.v1+json", Pushed: day.Add(time.Hour)},
			{Digest: "sig", ArtifactType: "application/vnd.dev.sigstore.bundle.v0.3+json", Subject: "idx"},
			{Digest: "sbom", ArtifactType: "application/spdx+json", Subject: "idx"},
			{Digest: "amd-sig", ArtifactType: "application/vnd.dev.sigstore.bundle.v0.3+json", Subject: "amd"},
			{Digest: "orphan", ArtifactType: "application/spdx+json", Subject: "gone"},
			{Digest: "nested", Index: true, Children: []browse.Descriptor{{Digest: "deep", Platform: "linux/ppc64le", Stored: true}}},
			{Digest: "deep"},
		},
	}
	tags, rows, st := groupImage(img, func(d string) string { return "/m/" + d })

	var got []string
	for _, r := range rows {
		s := strings.Repeat(">", r.Depth) + r.Digest
		if r.Platform != "" {
			s += "@" + r.Platform
		}
		if r.Kind != "" {
			s += "=" + r.Kind
		}
		if r.Missing {
			s += "!"
		}
		got = append(got, s)
	}
	want := []string{
		"idx", ">amd@linux/amd64", ">>amd-sig=signature", ">arm@linux/arm64!", ">nested", ">sig=signature", ">sbom=SBOM",
		"solo",
		"orphan=SBOM",
		// The child of an index that is itself a child is listed on its own.
		"deep",
	}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("rows\n got %v\nwant %v", got, want)
	}
	for _, r := range rows {
		switch {
		case r.Missing && r.Href != "":
			t.Errorf("a child not stored here is linked: %+v", r)
		case !r.Missing && r.Href != "/m/"+r.Digest:
			t.Errorf("row %s links %q", r.Digest, r.Href)
		case r.Digest == "amd" && r.Artifact != "":
			t.Errorf("a plain image shows artifact type %q", r.Artifact)
		case r.First != (r.Depth == 0):
			t.Errorf("row %s at depth %d: First %v", r.Digest, r.Depth, r.First)
		}
	}

	if len(tags) != 3 || strings.Join(tags[0].Platforms, ",") != "linux/amd64,linux/arm64" ||
		strings.Join(tags[0].Proofs, ",") != "SBOM,signature" || !tags[0].Index || !tags[0].Pushed.Equal(day.Add(2*time.Hour)) {
		t.Errorf("tag latest %+v", tags[0])
	}
	if tags[2].Index || len(tags[2].Platforms) != 0 || len(tags[2].Proofs) != 0 || tags[2].Href != "/m/solo" {
		t.Errorf("tag old %+v", tags[2])
	}
	// Two tags of one index count once.
	if st.Tags != 3 || st.Manifests != 9 || st.Tagged != 2 || st.Signed != 1 || !st.LastPush.Equal(day.Add(2*time.Hour)) ||
		strings.Join(st.Platforms, ",") != "linux/amd64,linux/arm64,linux/ppc64le" {
		t.Errorf("stats %+v", st)
	}
}
