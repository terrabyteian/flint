package oci

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/terrabyteian/flint/internal/blob"
)

type tagList struct {
	Name string   `json:"name"`
	Tags []string `json:"tags"`
}

func TestListTags(t *testing.T) {
	e := newEnv(t)
	img := newImage("a", nil)
	want(t, e.pushImage("hosted/app", "v1", img), 201, "")
	all := []string{"v1"}
	for _, tag := range []string{"latest", "a", "B", "v10", "v2", "z"} {
		want(t, e.do("PUT", "/v2/hosted/app/manifests/"+tag, img.manifest, "Content-Type", mtOCIManifest), 201, "")
		all = append(all, tag)
	}
	slices.Sort(all)
	// A tag in a longer name must not show up.
	want(t, e.do("PUT", "/v2/hosted/app/sub/manifests/x", img.manifest, "Content-Type", mtOCIManifest), 400, codeManifestBlobUnknown)
	want(t, e.pushImage("hosted/app/sub", "nested", img), 201, "")

	list := func(query string) (tagList, string) {
		t.Helper()
		w := e.do("GET", "/v2/hosted/app/tags/list"+query, nil)
		want(t, w, 200, "")
		var tl tagList
		if err := json.Unmarshal(w.Body.Bytes(), &tl); err != nil {
			t.Fatal(err)
		}
		if tl.Name != "hosted/app" || tl.Tags == nil {
			t.Fatalf("tag list = %s", w.Body)
		}
		return tl, w.Header().Get("Link")
	}
	tl, link := list("")
	if !slices.Equal(tl.Tags, all) || link != "" {
		t.Errorf("tags = %v link %q, want %v", tl.Tags, link, all)
	}

	// Paginate two at a time, following the Link header.
	var paged []string
	query := "?n=2"
	for range 10 {
		tl, link := list(query)
		if len(tl.Tags) > 2 {
			t.Fatalf("page %s has %d tags", query, len(tl.Tags))
		}
		paged = append(paged, tl.Tags...)
		if link == "" {
			break
		}
		u, err := url.Parse(strings.TrimSuffix(strings.TrimPrefix(link, "<"), `>; rel="next"`))
		if err != nil || u.Path != "/v2/hosted/app/tags/list" {
			t.Fatalf("Link = %q", link)
		}
		query = "?" + u.RawQuery
	}
	if !slices.Equal(paged, all) {
		t.Errorf("paged tags = %v, want %v", paged, all)
	}

	if tl, _ := list("?last=v1"); !slices.Equal(tl.Tags, []string{"v10", "v2", "z"}) {
		t.Errorf("tags after v1 = %v", tl.Tags)
	}
	if tl, _ := list("?last=zz"); len(tl.Tags) != 0 {
		t.Errorf("tags after the last = %v", tl.Tags)
	}
	if tl, link := list("?n=0"); len(tl.Tags) != 0 || link != "" {
		t.Errorf("n=0 = %v %q", tl.Tags, link)
	}
	if tl, _ := list("?n=100000"); len(tl.Tags) != len(all) {
		t.Errorf("large n = %v", tl.Tags)
	}
	want(t, e.do("GET", "/v2/hosted/app/tags/list?n=-1", nil), 400, "PAGINATION_NUMBER_INVALID")
	want(t, e.do("GET", "/v2/hosted/app/tags/list?n=x", nil), 400, "PAGINATION_NUMBER_INVALID")
	want(t, e.do("GET", "/v2/hosted/none/tags/list", nil), 404, codeNameUnknown)

	// A name with manifests but no tags lists no tags.
	b := newImage("b", nil)
	want(t, e.pushImage("hosted/untagged", b.digest.String(), b), 201, "")
	w := e.do("GET", "/v2/hosted/untagged/tags/list", nil)
	want(t, w, 200, "")
	if w.Body.String() != `{"name":"hosted/untagged","tags":[]}` {
		t.Errorf("untagged tag list = %s", w.Body)
	}
}

func TestListTagsPageLimit(t *testing.T) {
	e := newEnv(t)
	img := newImage("a", nil)
	want(t, e.pushImage("hosted/app", "t0000", img), 201, "")
	for i := 1; i < maxPageSize+5; i++ {
		want(t, e.do("PUT", fmt.Sprintf("/v2/hosted/app/manifests/t%04d", i), img.manifest, "Content-Type", mtOCIManifest), 201, "")
	}
	w := e.do("GET", "/v2/hosted/app/tags/list", nil)
	var tl tagList
	json.Unmarshal(w.Body.Bytes(), &tl)
	if len(tl.Tags) != maxPageSize || !strings.Contains(w.Header().Get("Link"), "last=t0999") {
		t.Errorf("unbounded listing returned %d tags, Link %q", len(tl.Tags), w.Header().Get("Link"))
	}
}

func TestCatalog(t *testing.T) {
	e := newEnv(t)
	names := []string{"hosted/a", "hosted/a/b", "hosted/a-b", "hosted/z", "other/x", "frozen/y"}
	for i, n := range names {
		want(t, e.pushImage(n, "v1", newImage(fmt.Sprint(i), nil)), 201, "")
	}
	// A name with only blobs is not listed.
	e.pushBlob("hosted/blobsonly", []byte("x"))

	catalog := func(query string) ([]string, string) {
		t.Helper()
		w := e.do("GET", "/v2/_catalog"+query, nil)
		want(t, w, 200, "")
		var c struct {
			Repositories []string `json:"repositories"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &c); err != nil || c.Repositories == nil {
			t.Fatalf("catalog = %s", w.Body)
		}
		return c.Repositories, w.Header().Get("Link")
	}
	all, link := catalog("")
	wantAll := []string{"frozen/y", "hosted/a", "hosted/a-b", "hosted/a/b", "hosted/z", "other/x"}
	if !slices.Equal(all, wantAll) || link != "" {
		t.Errorf("catalog = %v %q, want %v", all, link, wantAll)
	}
	var paged []string
	query := "?n=4"
	for range 10 {
		page, link := catalog(query)
		paged = append(paged, page...)
		if link == "" {
			break
		}
		u, _ := url.Parse(strings.TrimSuffix(strings.TrimPrefix(link, "<"), `>; rel="next"`))
		query = "?" + u.RawQuery
	}
	if !slices.Equal(paged, wantAll) {
		t.Errorf("paged catalog = %v", paged)
	}
	if page, _ := catalog("?last=hosted/a"); !slices.Equal(page, wantAll[2:]) {
		t.Errorf("catalog after hosted/a = %v", page)
	}
	if page, _ := catalog("?n=0"); len(page) != 0 {
		t.Errorf("n=0 catalog = %v", page)
	}
	want(t, e.do("GET", "/v2/_catalog?n=x", nil), 400, "PAGINATION_NUMBER_INVALID")

	// Repositories no longer configured are not listed.
	h, err := New(Options{Meta: e.meta, Blobs: e.blobs, Repositories: testRepos[:1], Authorizer: AllowAll{}, Logger: quiet})
	if err != nil {
		t.Fatal(err)
	}
	e.h = h
	if page, _ := catalog(""); !slices.Equal(page, []string{"hosted/a", "hosted/a-b", "hosted/a/b", "hosted/z"}) {
		t.Errorf("catalog with one configured repository = %v", page)
	}
}

func TestRecords(t *testing.T) {
	d1, d2 := blob.FromBytes([]byte("1")), blob.FromBytes([]byte("2"))
	m := manifestRecord{
		MediaType: mtOCIManifest, Size: 1234, ArtifactType: "application/x", Subject: d1,
		Annotations: `{"a":"b"}`, Refs: []manifestRef{{refBlob, d1}, {refManifest, d2}},
	}
	got, err := decodeManifest(m.encode())
	if err != nil || got.MediaType != m.MediaType || got.Size != m.Size || got.ArtifactType != m.ArtifactType ||
		got.Subject != d1 || got.Annotations != m.Annotations || !slices.Equal(got.Refs, m.Refs) {
		t.Errorf("manifest round trip = %+v, %v", got, err)
	}
	empty := manifestRecord{MediaType: mtOCIIndex}
	if got, err := decodeManifest(empty.encode()); err != nil || !got.Subject.IsZero() || len(got.Refs) != 0 {
		t.Errorf("empty manifest round trip = %+v, %v", got, err)
	}
	if d, err := decodeTag(encodeTag(d2)); err != nil || d != d2 {
		t.Errorf("tag round trip = %v, %v", d, err)
	}
	if n, err := decodeBlobLink(encodeBlobLink(1 << 40)); err != nil || n != 1<<40 {
		t.Errorf("blob link round trip = %d, %v", n, err)
	}
	u := uploadRecord{Name: "hosted/app", Started: time.Unix(1700000000, 5)}
	if got, err := decodeUpload(u.encode()); err != nil || got.Name != u.Name || !got.Started.Equal(u.Started) {
		t.Errorf("upload round trip = %+v, %v", got, err)
	}

	enc := m.encode()
	for i := range len(enc) {
		if _, err := decodeManifest(enc[:i]); err == nil {
			t.Errorf("decodeManifest accepted a %d-byte prefix", i)
		}
	}
	for name, b := range map[string][]byte{
		"empty":         nil,
		"wrong version": {9, 1},
		"trailing":      append(encodeTag(d1), 0),
		"short tag":     encodeTag(d1)[:20],
	} {
		if _, err := decodeTag(b); err == nil {
			t.Errorf("decodeTag(%s) succeeded", name)
		}
	}
	if _, err := decodeBlobLink([]byte{1, 0xff}); err == nil {
		t.Error("decodeBlobLink accepted a truncated varint")
	}
	if _, err := decodeUpload([]byte{1}); err == nil {
		t.Error("decodeUpload accepted a truncated record")
	}
	huge := append(newEnc().str("x").uvarint(1).str(""), 0).str("").uvarint(1 << 40)
	if _, err := decodeManifest(huge); err == nil {
		t.Error("decodeManifest accepted an absurd reference count")
	}
}

func TestKeysDoNotCollide(t *testing.T) {
	a := &repoName{repo: "r", name: "a"}
	ab := &repoName{repo: "r", name: "a/b"}
	if bytes.HasPrefix(prefix(nsTag, ab), prefix(nsTag, a)) {
		t.Error("the tag prefix of r/a matches r/a/b")
	}
	ra := &repoName{repo: "r-a", name: "x"}
	if bytes.HasPrefix(prefix(nsTag, ra), []byte(nsTag+"r\x00")) {
		t.Error("the prefix of repository r matches r-a")
	}
}
