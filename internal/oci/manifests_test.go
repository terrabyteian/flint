package oci

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/terrabyteian/flint/internal/blob"
	"github.com/terrabyteian/flint/internal/meta"
)

func TestManifestPushAndPull(t *testing.T) {
	e := newEnv(t)
	img := newImage("a", map[string]any{"annotations": map[string]string{"k": "v"}})
	w := e.pushImage("hosted/app", "v1", img)
	want(t, w, 201, "")
	if w.Header().Get("Location") != "/v2/hosted/app/manifests/"+img.digest.String() ||
		w.Header().Get("Docker-Content-Digest") != img.digest.String() || w.Header().Get("OCI-Subject") != "" {
		t.Errorf("PUT headers = %v", w.Header())
	}

	for _, ref := range []string{"v1", img.digest.String()} {
		w = e.do("GET", "/v2/hosted/app/manifests/"+ref, nil, "Accept", mtOCIManifest)
		want(t, w, 200, "")
		if !bytes.Equal(w.Body.Bytes(), img.manifest) {
			t.Errorf("GET %s body = %s", ref, w.Body)
		}
		if w.Header().Get("Content-Type") != mtOCIManifest || w.Header().Get("Docker-Content-Digest") != img.digest.String() {
			t.Errorf("GET %s headers = %v", ref, w.Header())
		}
		w = e.do("HEAD", "/v2/hosted/app/manifests/"+ref, nil)
		want(t, w, 200, "")
		if w.Body.Len() != 0 || w.Header().Get("Content-Length") != strconv.Itoa(len(img.manifest)) {
			t.Errorf("HEAD %s = %q %v", ref, w.Body, w.Header())
		}
	}

	// Content negotiation.
	for _, accept := range []string{"*/*", "application/*", mtDockerManifest + ", " + mtOCIManifest + ";q=0.9"} {
		want(t, e.do("GET", "/v2/hosted/app/manifests/v1", nil, "Accept", accept), 200, "")
	}
	w = e.do("GET", "/v2/hosted/app/manifests/v1", nil, "Accept", mtDockerManifest, "Accept", mtDockerList)
	want(t, w, 404, codeManifestUnknown)

	// Unknown references.
	want(t, e.do("GET", "/v2/hosted/app/manifests/v2", nil), 404, codeManifestUnknown)
	want(t, e.do("HEAD", "/v2/hosted/app/manifests/v2", nil), 404, "")
	want(t, e.do("GET", "/v2/hosted/app/manifests/-bad", nil), 404, codeManifestUnknown)
	want(t, e.do("GET", "/v2/hosted/app/manifests/sha256:totallywrong", nil), 400, codeDigestInvalid)
	want(t, e.do("GET", "/v2/hosted/other/manifests/v1", nil), 404, codeManifestUnknown)
	want(t, e.do("GET", "/v2/hosted/other/manifests/"+img.digest.String(), nil), 404, codeManifestUnknown)

	// Pushing by digest, with extra tags.
	img2 := newImage("b", nil)
	e.pushBlob("hosted/app", img2.config)
	e.pushBlob("hosted/app", img2.layer)
	w = e.do("PUT", "/v2/hosted/app/manifests/"+img2.digest.String()+"?tag=x&tag=y&tag=x", img2.manifest, "Content-Type", mtOCIManifest)
	want(t, w, 201, "")
	for _, tag := range []string{"x", "y"} {
		if w := e.do("GET", "/v2/hosted/app/manifests/"+tag, nil); w.Header().Get("Docker-Content-Digest") != img2.digest.String() {
			t.Errorf("tag %s = %d %v", tag, w.Code, w.Header())
		}
	}

	// Tags are mutable by default.
	want(t, e.do("PUT", "/v2/hosted/app/manifests/v1", img2.manifest, "Content-Type", mtOCIManifest), 201, "")
	if w := e.do("GET", "/v2/hosted/app/manifests/v1", nil); w.Header().Get("Docker-Content-Digest") != img2.digest.String() {
		t.Errorf("v1 not moved: %v", w.Header())
	}

	var buf bytes.Buffer
	e.reg.WriteTo(&buf)
	if !strings.Contains(buf.String(), `flint_oci_manifest_pushes_total{repository="hosted"} 3`) {
		t.Errorf("metrics missing manifest pushes:\n%s", buf.String())
	}
}

func TestManifestWithoutLayers(t *testing.T) {
	e := newEnv(t)
	cfg := []byte("{}")
	e.pushBlob("hosted/app", cfg)
	m := mustJSON(map[string]any{
		"schemaVersion": 2, "mediaType": mtOCIManifest,
		"config": desc("application/vnd.oci.empty.v1+json", cfg), "layers": []any{},
	})
	want(t, e.do("PUT", "/v2/hosted/app/manifests/empty", m, "Content-Type", mtOCIManifest), 201, "")
}

func TestManifestValidation(t *testing.T) {
	e := newEnv(t)
	img := newImage("a", nil)
	e.pushBlob("hosted/app", img.config)
	e.pushBlob("hosted/app", img.layer)
	cfg := desc("application/vnd.oci.image.config.v1+json", img.config)
	layer := desc("application/vnd.oci.image.layer.v1.tar+gzip", img.layer)
	missing := desc("application/vnd.oci.image.layer.v1.tar+gzip", []byte("not pushed"))
	wrongSize := desc("application/vnd.oci.image.layer.v1.tar+gzip", img.layer)
	wrongSize["size"] = 3
	manifest := func(fields map[string]any) []byte {
		m := map[string]any{"schemaVersion": 2, "mediaType": mtOCIManifest, "config": cfg, "layers": []any{layer}}
		for k, v := range fields {
			if v == nil {
				delete(m, k)
			} else {
				m[k] = v
			}
		}
		return mustJSON(m)
	}

	tests := []struct {
		name   string
		ref    string
		ct     string
		body   []byte
		status int
		code   string
	}{
		{"not JSON", "t", mtOCIManifest, []byte("{"), 400, codeManifestInvalid},
		{"JSON array", "t", mtOCIManifest, []byte("[]"), 400, codeManifestInvalid},
		{"schema 1 by type", "t", mtDockerSigned, []byte(`{"schemaVersion":1}`), 400, codeManifestInvalid},
		{"schema 1 by version", "t", mtOCIManifest, manifest(map[string]any{"schemaVersion": 1}), 400, codeManifestInvalid},
		{"no schema version", "t", mtOCIManifest, manifest(map[string]any{"schemaVersion": nil}), 400, codeManifestInvalid},
		{"type mismatch", "t", mtDockerManifest, manifest(nil), 400, codeManifestInvalid},
		{"unsupported type", "t", "application/vnd.oci.artifact.manifest.v1+json",
			manifest(map[string]any{"mediaType": "application/vnd.oci.artifact.manifest.v1+json"}), 400, codeManifestInvalid},
		{"unknown structure", "t", "application/json", []byte(`{"schemaVersion":2}`), 400, codeManifestInvalid},
		{"no config", "t", mtOCIManifest, manifest(map[string]any{"config": nil}), 400, codeManifestInvalid},
		{"bad layer digest", "t", mtOCIManifest,
			manifest(map[string]any{"layers": []any{map[string]any{"mediaType": "x", "digest": "sha256:zz", "size": 1}}}), 400, codeManifestInvalid},
		{"negative size", "t", mtOCIManifest,
			manifest(map[string]any{"layers": []any{map[string]any{"mediaType": "x", "digest": img.digest.String(), "size": -1}}}), 400, codeManifestInvalid},
		{"sha512 layer", "t", mtOCIManifest,
			manifest(map[string]any{"layers": []any{map[string]any{"mediaType": "x", "digest": "sha512:" + strings.Repeat("a", 128), "size": 1}}}), 400, codeManifestBlobUnknown},
		{"missing layer", "t", mtOCIManifest, manifest(map[string]any{"layers": []any{layer, missing}}), 400, codeManifestBlobUnknown},
		{"missing config", "t", mtOCIManifest, manifest(map[string]any{"config": missing}), 400, codeManifestBlobUnknown},
		{"size mismatch", "t", mtOCIManifest, manifest(map[string]any{"layers": []any{wrongSize}}), 400, codeManifestInvalid},
		{"bad subject", "t", mtOCIManifest, manifest(map[string]any{"subject": map[string]any{"digest": "nope", "size": 1}}), 400, codeManifestInvalid},
		{"index without manifests", "t", mtOCIIndex, []byte(`{"schemaVersion":2,"mediaType":"` + mtOCIIndex + `"}`), 400, codeManifestInvalid},
		{"invalid tag", "-t", mtOCIManifest, manifest(nil), 400, codeManifestInvalid},
		{"invalid extra tag", "t?tag=a:b", mtOCIManifest, manifest(nil), 400, codeManifestInvalid},
		{"invalid digest", "sha256:totallywrong", mtOCIManifest, manifest(nil), 400, codeDigestInvalid},
		{"digest mismatch", img.digest.String(), mtOCIManifest, manifest(map[string]any{"annotations": map[string]string{"x": "y"}}), 400, codeDigestInvalid},
		{"too large", "t", mtOCIManifest, bytes.Repeat([]byte(" "), maxManifestSize+1), 413, codeSizeInvalid},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			want(t, e.do("PUT", "/v2/hosted/app/manifests/"+tt.ref, tt.body, "Content-Type", tt.ct), tt.status, tt.code)
		})
	}
	want(t, e.do("GET", "/v2/hosted/app/tags/list", nil), 404, codeNameUnknown)

	// Accepted variations.
	for name, body := range map[string][]byte{
		"type from the body":         manifest(nil),
		"type from the Content-Type": manifest(map[string]any{"mediaType": nil}),
		"type from the structure":    manifest(map[string]any{"mediaType": nil, "annotations": map[string]string{"s": "1"}}),
		"non-distributable layer": manifest(map[string]any{"layers": []any{layer, map[string]any{
			"mediaType": "application/vnd.docker.image.rootfs.foreign.diff.tar.gzip",
			"digest":    blob.FromBytes([]byte("windows")).String(), "size": 7, "urls": []string{"https://example.com/l"}}}}),
	} {
		t.Run(name, func(t *testing.T) {
			ct := mtOCIManifest
			if name == "type from the body" || name == "type from the structure" {
				ct = "application/json"
			}
			want(t, e.do("PUT", "/v2/hosted/app/manifests/ok", body, "Content-Type", ct), 201, "")
		})
	}
}

// TestDockerManifestList pushes Docker schema 2 manifests and a manifest
// list over them: a multi-arch image.
func TestDockerManifestList(t *testing.T) {
	e := newEnv(t)
	var children []any
	for _, arch := range []string{"amd64", "arm64"} {
		cfg, layer := []byte(`{"architecture":"`+arch+`"}`), []byte("rootfs "+arch)
		e.pushBlob("hosted/multi", cfg)
		e.pushBlob("hosted/multi", layer)
		m := mustJSON(map[string]any{
			"schemaVersion": 2, "mediaType": mtDockerManifest,
			"config": desc("application/vnd.docker.container.image.v1+json", cfg),
			"layers": []any{desc("application/vnd.docker.image.rootfs.diff.tar.gzip", layer)},
		})
		d := blob.FromBytes(m)
		want(t, e.do("PUT", "/v2/hosted/multi/manifests/"+d.String(), m, "Content-Type", mtDockerManifest), 201, "")
		c := desc(mtDockerManifest, m)
		c["platform"] = map[string]string{"os": "linux", "architecture": arch}
		children = append(children, c)
	}
	list := mustJSON(map[string]any{"schemaVersion": 2, "mediaType": mtDockerList, "manifests": children})
	want(t, e.do("PUT", "/v2/hosted/multi/manifests/latest", list, "Content-Type", mtDockerList), 201, "")
	w := e.do("GET", "/v2/hosted/multi/manifests/latest", nil, "Accept", mtDockerList+","+mtDockerManifest)
	want(t, w, 200, "")
	if w.Header().Get("Content-Type") != mtDockerList || !bytes.Equal(w.Body.Bytes(), list) {
		t.Errorf("GET list = %v %s", w.Header(), w.Body)
	}

	// A list whose member is not in the repository name is refused.
	orphan := mustJSON(map[string]any{"schemaVersion": 2, "mediaType": mtDockerList, "manifests": []any{
		desc(mtDockerManifest, []byte(`{"not":"pushed"}`))}})
	want(t, e.do("PUT", "/v2/hosted/multi/manifests/orphan", orphan, "Content-Type", mtDockerList), 400, codeManifestBlobUnknown)
	want(t, e.do("PUT", "/v2/hosted/elsewhere/manifests/l", list, "Content-Type", mtDockerList), 400, codeManifestBlobUnknown)
	// So is one whose member's size is wrong.
	bad := children[0].(map[string]any)
	bad["size"] = 1
	wrong := mustJSON(map[string]any{"schemaVersion": 2, "mediaType": mtDockerList, "manifests": []any{bad}})
	want(t, e.do("PUT", "/v2/hosted/multi/manifests/wrong", wrong, "Content-Type", mtDockerList), 400, codeManifestInvalid)
}

func TestOCIIndex(t *testing.T) {
	e := newEnv(t)
	a, b := newImage("amd64", nil), newImage("arm64", nil)
	want(t, e.pushImage("hosted/idx", a.digest.String(), a), 201, "")
	want(t, e.pushImage("hosted/idx", b.digest.String(), b), 201, "")
	idx := mustJSON(map[string]any{"schemaVersion": 2, "mediaType": mtOCIIndex, "manifests": []any{
		desc(mtOCIManifest, a.manifest), desc(mtOCIManifest, b.manifest), desc(mtOCIManifest, a.manifest)}})
	want(t, e.do("PUT", "/v2/hosted/idx/manifests/latest", idx, "Content-Type", mtOCIIndex), 201, "")

	v := e.meta.View()
	rec, _ := v.Get(manifestKey(&repoName{repo: "hosted", name: "idx"}, blob.FromBytes(idx)))
	v.Release()
	m, err := decodeManifest(rec.Value)
	if err != nil || len(m.Refs) != 2 || m.Refs[0] != (manifestRef{refManifest, a.digest}) {
		t.Errorf("index record = %+v, %v", m, err)
	}
}

func TestImmutableTags(t *testing.T) {
	e := newEnv(t)
	a, b := newImage("a", nil), newImage("b", nil)
	want(t, e.pushImage("frozen/app", "v1", a), 201, "")
	// The same manifest again is fine.
	want(t, e.pushImage("frozen/app", "v1", a), 201, "")
	// Another manifest under the tag is not.
	w := e.pushImage("frozen/app", "v1", b)
	want(t, w, 409, codeDenied)
	if !strings.Contains(w.Body.String(), "immutable") {
		t.Errorf("immutable tag error = %s", w.Body)
	}
	// Nor through ?tag=.
	want(t, e.do("PUT", "/v2/frozen/app/manifests/"+b.digest.String()+"?tag=v1", b.manifest, "Content-Type", mtOCIManifest), 409, codeDenied)
	if w := e.do("GET", "/v2/frozen/app/manifests/v1", nil); w.Header().Get("Docker-Content-Digest") != a.digest.String() {
		t.Errorf("v1 moved to %s", w.Header().Get("Docker-Content-Digest"))
	}
	// New tags and untagged manifests are fine.
	want(t, e.pushImage("frozen/app", "v2", b), 201, "")
	c := newImage("c", nil)
	want(t, e.pushImage("frozen/app", c.digest.String(), c), 201, "")

	// Tags are permanent: neither the tag nor its manifest can be deleted.
	want(t, e.do("DELETE", "/v2/frozen/app/manifests/v1", nil), 409, codeDenied)
	want(t, e.do("DELETE", "/v2/frozen/app/manifests/"+a.digest.String(), nil), 409, codeDenied)
	want(t, e.do("GET", "/v2/frozen/app/manifests/v1", nil), 200, "")
	// An untagged manifest can.
	want(t, e.do("DELETE", "/v2/frozen/app/manifests/"+c.digest.String(), nil), 202, "")
}

func TestDeleteManifest(t *testing.T) {
	e := newEnv(t)
	img := newImage("a", nil)
	want(t, e.pushImage("hosted/app", "v1", img), 201, "")
	want(t, e.do("PUT", "/v2/hosted/app/manifests/v2", img.manifest, "Content-Type", mtOCIManifest), 201, "")
	want(t, e.pushImage("hosted/app", "other", newImage("b", nil)), 201, "")

	// By tag: only the tag goes.
	want(t, e.do("DELETE", "/v2/hosted/app/manifests/v1", nil), 202, "")
	want(t, e.do("GET", "/v2/hosted/app/manifests/v1", nil), 404, codeManifestUnknown)
	want(t, e.do("GET", "/v2/hosted/app/manifests/"+img.digest.String(), nil), 200, "")
	want(t, e.do("DELETE", "/v2/hosted/app/manifests/v1", nil), 404, codeManifestUnknown)
	want(t, e.do("DELETE", "/v2/hosted/app/manifests/-x", nil), 404, codeManifestUnknown)

	// By digest: the manifest and its remaining tags go.
	want(t, e.do("DELETE", "/v2/hosted/app/manifests/"+img.digest.String(), nil), 202, "")
	want(t, e.do("GET", "/v2/hosted/app/manifests/"+img.digest.String(), nil), 404, codeManifestUnknown)
	want(t, e.do("GET", "/v2/hosted/app/manifests/v2", nil), 404, codeManifestUnknown)
	want(t, e.do("DELETE", "/v2/hosted/app/manifests/"+img.digest.String(), nil), 404, codeManifestUnknown)
	want(t, e.do("DELETE", "/v2/hosted/app/manifests/sha256:x", nil), 400, codeDigestInvalid)
	w := e.do("GET", "/v2/hosted/app/tags/list", nil)
	if w.Body.String() != `{"name":"hosted/app","tags":["other"]}` {
		t.Errorf("tags after deletes = %s", w.Body)
	}
}

// TestDeleteManifestRace retags a manifest between a delete's view and its
// commit: the delete must look again rather than leave the tag dangling.
func TestDeleteManifestRace(t *testing.T) {
	e := newEnv(t)
	img := newImage("a", nil)
	want(t, e.pushImage("hosted/app", "v1", img), 201, "")
	rn := &repoName{full: "hosted/app", repo: "hosted", name: "app", cfg: e.h.repos["hosted"]}

	var b meta.Batch
	v := e.meta.View()
	if err := e.h.buildManifestDelete(v, &b, httptest.NewRequest("DELETE", "/", nil), rn, img.digest.String()); err != nil {
		t.Fatal(err)
	}
	v.Release()
	want(t, e.do("PUT", "/v2/hosted/app/manifests/v2", img.manifest, "Content-Type", mtOCIManifest), 201, "")
	if _, err := e.meta.Commit(context.Background(), &b); !errors.Is(err, meta.ErrConflict) {
		t.Fatalf("stale delete committed: %v", err)
	}
	want(t, e.do("DELETE", "/v2/hosted/app/manifests/"+img.digest.String(), nil), 202, "")
	want(t, e.do("GET", "/v2/hosted/app/manifests/v2", nil), 404, codeManifestUnknown)
}

// TestDeleteManifestRetagRace moves a tag to another manifest between a
// delete's view and its commit: the delete must not take the moved tag.
func TestDeleteManifestRetagRace(t *testing.T) {
	e := newEnv(t)
	a, other := newImage("a", nil), newImage("b", nil)
	want(t, e.pushImage("hosted/app", "latest", a), 201, "")
	rn := &repoName{full: "hosted/app", repo: "hosted", name: "app", cfg: e.h.repos["hosted"]}

	var b meta.Batch
	v := e.meta.View()
	if err := e.h.buildManifestDelete(v, &b, httptest.NewRequest("DELETE", "/", nil), rn, a.digest.String()); err != nil {
		t.Fatal(err)
	}
	v.Release()
	want(t, e.pushImage("hosted/app", "latest", other), 201, "")
	if _, err := e.meta.Commit(context.Background(), &b); !errors.Is(err, meta.ErrConflict) {
		t.Fatalf("stale delete committed: %v", err)
	}
	want(t, e.do("DELETE", "/v2/hosted/app/manifests/"+a.digest.String(), nil), 202, "")
	w := e.do("GET", "/v2/hosted/app/manifests/latest", nil)
	want(t, w, 200, "")
	if got := w.Header().Get("Docker-Content-Digest"); got != other.digest.String() {
		t.Errorf("latest = %s, want %s", got, other.digest)
	}
}

// TestManifestReferenceRace deletes a layer between a push's view and its
// commit: the push must not commit a manifest whose layer is gone.
func TestManifestReferenceRace(t *testing.T) {
	e := newEnv(t)
	img := newImage("a", nil)
	e.pushBlob("hosted/app", img.config)
	layer := e.pushBlob("hosted/app", img.layer)
	pm, err := parseManifest(img.manifest, mtOCIManifest)
	if err != nil {
		t.Fatal(err)
	}
	rn := &repoName{full: "hosted/app", repo: "hosted", name: "app", cfg: e.h.repos["hosted"]}
	var b meta.Batch
	v := e.meta.View()
	if _, err := checkReferences(v, &b, rn, pm); err != nil {
		t.Fatal(err)
	}
	v.Release()
	b.Put(manifestKey(rn, img.digest), []byte{1})
	want(t, e.do("DELETE", "/v2/hosted/app/blobs/"+layer.String(), nil), 202, "")
	if _, err := e.meta.Commit(context.Background(), &b); !errors.Is(err, meta.ErrConflict) {
		t.Fatalf("manifest committed over a deleted layer: %v", err)
	}
}

func TestReferrers(t *testing.T) {
	e := newEnv(t)
	subject := newImage("subject", nil)
	subjectDesc := desc(mtOCIManifest, subject.manifest)

	// Referrers may be pushed before their subject.
	sig := newImage("sig", map[string]any{
		"artifactType": "application/vnd.example.signature",
		"subject":      subjectDesc,
		"annotations":  map[string]string{"org.example.key": "sig"},
	})
	w := e.pushImage("hosted/app", sig.digest.String(), sig)
	want(t, w, 201, "")
	if w.Header().Get("OCI-Subject") != subject.digest.String() {
		t.Errorf("OCI-Subject = %q", w.Header().Get("OCI-Subject"))
	}
	want(t, e.pushImage("hosted/app", "v1", subject), 201, "")

	// An artifact without artifactType reports its config media type.
	sbomCfg := []byte(`{"sbom":true}`)
	e.pushBlob("hosted/app", sbomCfg)
	sbom := mustJSON(map[string]any{
		"schemaVersion": 2, "mediaType": mtOCIManifest,
		"config":  desc("application/vnd.example.sbom", sbomCfg),
		"layers":  []any{},
		"subject": subjectDesc,
	})
	want(t, e.do("PUT", "/v2/hosted/app/manifests/sbom", sbom, "Content-Type", mtOCIManifest), 201, "")

	// An index can refer too.
	idx := mustJSON(map[string]any{
		"schemaVersion": 2, "mediaType": mtOCIIndex, "artifactType": "application/vnd.example.bundle",
		"manifests": []any{}, "subject": subjectDesc,
	})
	want(t, e.do("PUT", "/v2/hosted/app/manifests/bundle", idx, "Content-Type", mtOCIIndex), 201, "")

	type index struct {
		SchemaVersion int    `json:"schemaVersion"`
		MediaType     string `json:"mediaType"`
		Manifests     []struct {
			MediaType    string            `json:"mediaType"`
			Size         int64             `json:"size"`
			Digest       string            `json:"digest"`
			ArtifactType string            `json:"artifactType"`
			Annotations  map[string]string `json:"annotations"`
		} `json:"manifests"`
	}
	list := func(query string) (index, *httptest.ResponseRecorder) {
		t.Helper()
		w := e.do("GET", "/v2/hosted/app/referrers/"+subject.digest.String()+query, nil)
		want(t, w, 200, "")
		if w.Header().Get("Content-Type") != mtOCIIndex {
			t.Errorf("referrers Content-Type = %q", w.Header().Get("Content-Type"))
		}
		var ix index
		if err := json.Unmarshal(w.Body.Bytes(), &ix); err != nil {
			t.Fatal(err)
		}
		return ix, w
	}
	ix, w := list("")
	if len(ix.Manifests) != 3 || ix.SchemaVersion != 2 || ix.MediaType != mtOCIIndex || w.Header().Get("OCI-Filters-Applied") != "" {
		t.Fatalf("referrers = %s", w.Body)
	}
	byType := map[string]int{}
	for i, m := range ix.Manifests {
		byType[m.ArtifactType] = i
	}
	s := ix.Manifests[byType["application/vnd.example.signature"]]
	if s.Digest != sig.digest.String() || s.Size != int64(len(sig.manifest)) || s.MediaType != mtOCIManifest ||
		s.Annotations["org.example.key"] != "sig" {
		t.Errorf("signature referrer = %+v", s)
	}
	if _, ok := byType["application/vnd.example.sbom"]; !ok {
		t.Errorf("no referrer reports the config media type: %s", w.Body)
	}
	if b := ix.Manifests[byType["application/vnd.example.bundle"]]; b.MediaType != mtOCIIndex {
		t.Errorf("index referrer = %+v", b)
	}

	ix, w = list("?artifactType=application/vnd.example.sbom")
	if len(ix.Manifests) != 1 || w.Header().Get("OCI-Filters-Applied") != "artifactType" {
		t.Errorf("filtered referrers = %s %v", w.Body, w.Header())
	}

	// Deleting a referrer removes it from the list.
	want(t, e.do("DELETE", "/v2/hosted/app/manifests/"+sig.digest.String(), nil), 202, "")
	if ix, _ := list(""); len(ix.Manifests) != 2 {
		t.Errorf("%d referrers after a delete, want 2", len(ix.Manifests))
	}

	// No referrers: an empty index, not null.
	w = e.do("GET", "/v2/hosted/app/referrers/"+blob.FromBytes([]byte("none")).String(), nil)
	want(t, w, 200, "")
	if !strings.Contains(w.Body.String(), `"manifests":[]`) {
		t.Errorf("empty referrers = %s", w.Body)
	}
	want(t, e.do("GET", "/v2/hosted/app/referrers/sha256:x", nil), 400, codeDigestInvalid)
	// Referrers are per repository name.
	w = e.do("GET", "/v2/hosted/other/referrers/"+subject.digest.String(), nil)
	if !strings.Contains(w.Body.String(), `"manifests":[]`) {
		t.Errorf("referrers leaked across names: %s", w.Body)
	}
}

func TestAccepts(t *testing.T) {
	tests := []struct {
		accept []string
		mt     string
		want   bool
	}{
		{nil, mtOCIManifest, true},
		{[]string{mtOCIManifest}, mtOCIManifest, true},
		{[]string{mtDockerManifest, mtOCIManifest}, mtOCIManifest, true},
		{[]string{mtDockerManifest + " , " + mtOCIIndex + ";q=0.5"}, mtOCIIndex, true},
		{[]string{"application/*"}, mtOCIIndex, true},
		{[]string{"*/*"}, mtOCIIndex, true},
		{[]string{mtDockerManifest}, mtOCIManifest, false},
		{[]string{"text/*"}, mtOCIManifest, false},
	}
	for _, tt := range tests {
		r := httptest.NewRequest("GET", "/", nil)
		for _, a := range tt.accept {
			r.Header.Add("Accept", a)
		}
		if got := accepts(r, tt.mt); got != tt.want {
			t.Errorf("accepts(%q, %s) = %v", tt.accept, tt.mt, got)
		}
	}
}

// TestManifestBlobMissing serves 404 for a manifest whose bytes are gone.
func TestManifestBlobMissing(t *testing.T) {
	e := newEnv(t)
	img := newImage("a", nil)
	want(t, e.pushImage("hosted/app", "v1", img), 201, "")
	if err := e.blobs.Delete(context.Background(), img.digest); err != nil {
		t.Fatal(err)
	}
	want(t, e.do("GET", "/v2/hosted/app/manifests/v1", nil), 404, codeManifestUnknown)
	want(t, e.do("HEAD", "/v2/hosted/app/manifests/v1", nil), 200, "")
}
