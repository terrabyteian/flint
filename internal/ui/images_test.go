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

func TestSchemeTag(t *testing.T) {
	hex := strings.Repeat("ab", 32)
	for tag, want := range map[string]string{
		"sha256-" + hex + ".sig":                  kindSignature,
		"sha256-" + hex + ".att":                  kindAttestation,
		"sha256-" + hex + ".sbom":                 kindSBOM,
		"sha256-" + hex + ".txt":                  "",
		"sha256-" + hex:                           "",
		"sha256-" + hex[:62] + ".sig":             "",
		"sha256-" + strings.ToUpper(hex) + ".sig": "",
		"sha512-" + hex + ".sig":                  "",
		"v1.sig":                                  "",
	} {
		d, k, ok := schemeTag(tag)
		if ok != (want != "") || k != want || ok && d != "sha256:"+hex {
			t.Errorf("schemeTag(%q) = %q, %q, %v; want kind %q", tag, d, k, ok, want)
		}
	}
}

// TestGroupImageCosignTags recognizes cosign's tag-scheme artifacts as
// proofs of the manifest they name, groups them under it, and does not
// count their tags as releases.
func TestGroupImageCosignTags(t *testing.T) {
	app := "sha256:" + strings.Repeat("a", 64)
	old := "sha256:" + strings.Repeat("b", 64)
	scheme := func(d, ext string) string { return "sha256-" + strings.TrimPrefix(d, "sha256:") + "." + ext }
	img := &browse.ImageDetail{
		Tags: []browse.ImageTag{
			{Name: "latest", Digest: app}, {Name: "v1", Digest: app}, {Name: "v0", Digest: old},
			{Name: scheme(app, "sig"), Digest: "sig"}, {Name: scheme(app, "att"), Digest: "att"},
			{Name: scheme(app, "sbom"), Digest: "sbom"},
			// An artifact of a manifest not stored here.
			{Name: scheme("sha256:"+strings.Repeat("c", 64), "sig"), Digest: "stray"},
		},
		Manifests: []browse.ManifestSummary{
			{Digest: app}, {Digest: old},
			{Digest: "sig", ArtifactType: "application/vnd.oci.image.config.v1+json"},
			{Digest: "att"}, {Digest: "sbom"}, {Digest: "stray"},
		},
	}
	tags, rows, st := groupImage(img, func(d string) string { return "/m/" + d })

	var got []string
	for _, r := range rows {
		s := strings.Repeat(">", r.Depth) + r.Digest
		if r.Kind != "" {
			s += "=" + r.Kind
		}
		got = append(got, s)
	}
	want := []string{app, ">sig=signature", ">att=attestation", ">sbom=SBOM", old, "stray=signature"}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("rows\n got %v\nwant %v", got, want)
	}

	if len(tags) != 7 {
		t.Fatalf("tags %+v", tags)
	}
	for _, i := range []int{0, 1} {
		if p := strings.Join(tags[i].Proofs, ","); p != "SBOM,attestation,signature" {
			t.Errorf("tag %s proofs %q", tags[i].Name, p)
		}
	}
	for _, tr := range tags[2:] {
		if len(tr.Proofs) != 0 {
			t.Errorf("tag %s proofs %v", tr.Name, tr.Proofs)
		}
	}
	// Only the artifact tags are marked, so only their long names wrap.
	for i, tr := range tags {
		if want := i >= 3; tr.Artifact != want {
			t.Errorf("tag %s artifact %v, want %v", tr.Name, tr.Artifact, want)
		}
	}
	// The artifact tags are listed but are not releases.
	if st.Tags != 7 || st.Tagged != 2 || st.Signed != 1 {
		t.Errorf("stats %+v", st)
	}
}

// TestGroupImageAttestationChildren treats the attestation manifests
// BuildKit adds to an index as attestations of it, not as platforms.
func TestGroupImageAttestationChildren(t *testing.T) {
	att := []browse.Annotation{{Key: "vnd.docker.reference.type", Value: "attestation-manifest"}}
	img := &browse.ImageDetail{
		Tags: []browse.ImageTag{{Name: "v1", Digest: "idx"}},
		Manifests: []browse.ManifestSummary{
			{Digest: "idx", Index: true, Tags: []string{"v1"}, Children: []browse.Descriptor{
				{Digest: "amd", Platform: "linux/amd64", Stored: true},
				{Digest: "amd-att", Platform: "unknown/unknown", Annotations: att, Stored: true},
				{Digest: "arm", Platform: "linux/arm64"},
				{Digest: "arm-att", Platform: "unknown/unknown"},
			}},
			{Digest: "amd"}, {Digest: "amd-att"},
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
	want := []string{"idx", ">amd@linux/amd64", ">amd-att=attestation", ">arm@linux/arm64!", ">arm-att=attestation!"}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("rows\n got %v\nwant %v", got, want)
	}
	if p := strings.Join(tags[0].Platforms, ","); p != "linux/amd64,linux/arm64" {
		t.Errorf("tag platforms %q", p)
	}
	if p := strings.Join(tags[0].Proofs, ","); p != "attestation" {
		t.Errorf("tag proofs %q", p)
	}
	if p := strings.Join(st.Platforms, ","); p != "linux/amd64,linux/arm64" || st.Signed != 0 || st.Tagged != 1 {
		t.Errorf("stats %+v", st)
	}
}

func TestImageRef(t *testing.T) {
	sig := "sha256-" + strings.Repeat("a", 64) + ".sig"
	rows := []manifestRow{
		{ManifestSummary: browse.ManifestSummary{Digest: "orphan"}, Kind: kindSBOM},
		{ManifestSummary: browse.ManifestSummary{Digest: "img"}},
		{ManifestSummary: browse.ManifestSummary{Digest: "child"}, Depth: 1},
	}
	for _, c := range []struct {
		tags []string
		rows []manifestRow
		want string
	}{
		{[]string{"a", "latest", "v1"}, rows, ":latest"},
		{[]string{sig, "v1.2.0", "v1.3.0"}, rows, ":v1.2.0"},
		{[]string{sig}, rows, "@img"},
		{nil, rows, "@img"},
		{[]string{sig}, rows[:1], ""},
	} {
		var tags []browse.ImageTag
		for _, n := range c.tags {
			tags = append(tags, browse.ImageTag{Name: n})
		}
		if got := imageRef(tags, c.rows); got != c.want {
			t.Errorf("imageRef(%v) = %q, want %q", c.tags, got, c.want)
		}
	}
}

// TestImageRefStrayArtifact never pulls a cosign artifact whose image is
// gone: its row reads as its kind, and there is nothing to pull.
func TestImageRefStrayArtifact(t *testing.T) {
	img := &browse.ImageDetail{
		Tags:      []browse.ImageTag{{Name: "sha256-" + strings.Repeat("a", 64) + ".sig", Digest: "sig"}},
		Manifests: []browse.ManifestSummary{{Digest: "sig", ArtifactType: "application/vnd.oci.image.config.v1+json"}},
	}
	tags, rows, _ := groupImage(img, func(d string) string { return "/m/" + d })
	if len(rows) != 1 || rows[0].Depth != 0 || rows[0].Kind != kindSignature {
		t.Errorf("rows %+v", rows)
	}
	if ref := imageRef(img.Tags, rows); ref != "" {
		t.Errorf("imageRef = %q", ref)
	}
	if len(tags) != 1 || len(tags[0].Proofs) != 0 {
		t.Errorf("tags %+v", tags)
	}
}
