package oci

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/terrabyteian/flint/internal/blob"
	"github.com/terrabyteian/flint/internal/browse"
)

func TestBrowseImages(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()

	amd := newImage("amd64", nil)
	arm := newImage("arm64", nil)
	want(t, e.pushImage("hosted/team/app", amd.digest.String(), amd), 201, "")
	want(t, e.pushImage("hosted/team/app", arm.digest.String(), arm), 201, "")
	index := mustJSON(map[string]any{
		"schemaVersion": 2,
		"mediaType":     mtOCIIndex,
		"manifests": []any{
			map[string]any{"mediaType": mtOCIManifest, "digest": amd.digest.String(), "size": len(amd.manifest),
				"platform": map[string]any{"os": "linux", "architecture": "amd64"}},
			map[string]any{"mediaType": mtOCIManifest, "digest": arm.digest.String(), "size": len(arm.manifest),
				"platform": map[string]any{"os": "linux", "architecture": "arm64", "variant": "v8"}},
		},
		"annotations": map[string]any{"org.opencontainers.image.version": "1.0"},
	})
	indexDigest := blob.FromBytes(index)
	e.now = e.now.Add(time.Minute)
	want(t, e.do("PUT", "/v2/hosted/team/app/manifests/v1", index, "Content-Type", mtOCIIndex), 201, "")
	want(t, e.do("PUT", "/v2/hosted/team/app/manifests/latest", index, "Content-Type", mtOCIIndex), 201, "")
	sig := newImage("sig", map[string]any{
		"artifactType": "application/vnd.dev.cosign.artifact.sig.v1+json",
		"subject":      map[string]any{"mediaType": mtOCIIndex, "digest": indexDigest.String(), "size": len(index)},
	})
	want(t, e.pushImage("hosted/team/app", sig.digest.String(), sig), 201, "")
	for _, name := range []string{"hosted/team", "hosted/web", "hosted/team/app/sub"} {
		img := newImage(name, nil)
		want(t, e.pushImage(name, "v1", img), 201, "")
	}

	names := func(q browse.Query) ([]string, bool) {
		t.Helper()
		imgs, more, err := e.h.ListImages("hosted", q)
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, i := range imgs {
			out = append(out, i.Name)
		}
		return out, more
	}
	if got, more := names(browse.Query{}); !equal(got, []string{"team", "team/app", "team/app/sub", "web"}) || more {
		t.Errorf("all images: %v, %v", got, more)
	}
	if got, more := names(browse.Query{Limit: 2}); !equal(got, []string{"team", "team/app"}) || !more {
		t.Errorf("first page: %v, %v", got, more)
	}
	if got, more := names(browse.Query{Limit: 2, After: "team/app"}); !equal(got, []string{"team/app/sub", "web"}) || more {
		t.Errorf("second page: %v, %v", got, more)
	}
	if got, _ := names(browse.Query{Filter: "APP"}); !equal(got, []string{"team/app", "team/app/sub"}) {
		t.Errorf("filtered: %v", got)
	}
	imgs, _, _ := e.h.ListImages("hosted", browse.Query{Filter: "team/app", Limit: 1})
	if imgs[0].Tags != 2 || imgs[0].Manifests != 4 || !imgs[0].Updated.Equal(e.now) {
		t.Errorf("summary %+v", imgs[0])
	}

	img, err := e.h.Image(ctx, "hosted", "team/app")
	if err != nil {
		t.Fatal(err)
	}
	if len(img.Tags) != 2 || img.Tags[0].Name != "latest" || img.Tags[0].Digest != indexDigest.String() {
		t.Errorf("tags %+v", img.Tags)
	}
	if len(img.Manifests) != 4 || img.Manifests[0].Digest != indexDigest.String() || !img.Manifests[0].Index ||
		!equal(img.Manifests[0].Tags, []string{"latest", "v1"}) {
		t.Errorf("manifests %+v", img.Manifests)
	}
	// An index lists its children with their platforms, so the UI can
	// group them under it.
	if c := img.Manifests[0].Children; len(c) != 2 || c[0].Platform != "linux/amd64" || !c[0].Stored ||
		c[1].Platform != "linux/arm64/v8" {
		t.Errorf("index children in the listing %+v", c)
	}
	for _, m := range img.Manifests[1:] {
		if m.Children != nil {
			t.Errorf("image manifest %s has children %+v", m.Digest, m.Children)
		}
	}

	m, err := e.h.Manifest(ctx, "hosted", "team/app", indexDigest.String())
	if err != nil {
		t.Fatal(err)
	}
	if !m.Index || len(m.Manifests) != 2 || m.Manifests[0].Platform != "linux/amd64" ||
		m.Manifests[1].Platform != "linux/arm64/v8" || !m.Manifests[0].Stored {
		t.Errorf("index children %+v", m.Manifests)
	}
	if len(m.Annotations) != 1 || m.Annotations[0].Value != "1.0" {
		t.Errorf("annotations %+v", m.Annotations)
	}
	if len(m.Referrers) != 1 || m.Referrers[0].Digest != sig.digest.String() ||
		m.Referrers[0].ArtifactType != "application/vnd.dev.cosign.artifact.sig.v1+json" {
		t.Errorf("referrers %+v", m.Referrers)
	}

	m, err = e.h.Manifest(ctx, "hosted", "team/app", amd.digest.String())
	if err != nil {
		t.Fatal(err)
	}
	if m.Index || m.Config == nil || len(m.Layers) != 1 || m.Layers[0].Size != int64(len(amd.layer)) ||
		m.TotalSize != int64(len(amd.manifest)+len(amd.config)+len(amd.layer)) {
		t.Errorf("image manifest %+v", m)
	}

	for _, c := range []struct{ repo, name, digest string }{
		{"nope", "team/app", amd.digest.String()},
		{"hosted", "team/missing", amd.digest.String()},
		{"hosted", "web", amd.digest.String()},
		{"hosted", "team/app", "sha256:bad"},
	} {
		if _, err := e.h.Manifest(ctx, c.repo, c.name, c.digest); !errors.Is(err, browse.ErrNotFound) {
			t.Errorf("Manifest(%v): got %v", c, err)
		}
	}
	if _, err := e.h.Image(ctx, "hosted", "missing"); !errors.Is(err, browse.ErrNotFound) {
		t.Errorf("missing image: got %v", err)
	}
	if _, _, err := e.h.ListImages("nope", browse.Query{}); !errors.Is(err, browse.ErrNotFound) {
		t.Errorf("unknown repository: got %v", err)
	}
	if got, _, err := e.h.ListImages("other", browse.Query{}); err != nil || len(got) != 0 {
		t.Errorf("empty repository: %v, %v", got, err)
	}

	// An index whose body cannot be read is listed without children
	// rather than failing the listing.
	if err := e.blobs.Delete(ctx, indexDigest); err != nil {
		t.Fatal(err)
	}
	img, err = e.h.Image(ctx, "hosted", "team/app")
	if err != nil {
		t.Fatal(err)
	}
	if len(img.Manifests) != 4 || img.Manifests[0].Digest != indexDigest.String() || img.Manifests[0].Children != nil {
		t.Errorf("manifests without the index body %+v", img.Manifests)
	}
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
