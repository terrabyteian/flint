package pypi

import (
	"archive/zip"
	"bytes"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/terrabyteian/flint/internal/blob"
)

func TestNegotiate(t *testing.T) {
	for _, tt := range []struct {
		accept, query string
		want          string
	}{
		{"", "", mtHTML},
		{"*/*", "", mtHTML},
		{"text/html", "", mtHTML},
		{"application/vnd.pypi.simple.v1+json", "", mtSimpleJSON},
		{"application/vnd.pypi.simple.latest+json", "", mtSimpleJSON},
		{"application/vnd.pypi.simple.latest+html", "", mtSimpleHTML},
		// pip's header.
		{"application/vnd.pypi.simple.v1+json, application/vnd.pypi.simple.v1+html; q=0.1, text/html; q=0.01", "", mtSimpleJSON},
		{"text/html, application/vnd.pypi.simple.v1+json", "", mtHTML},
		{"application/vnd.pypi.simple.v1+json;q=0.5, text/html;q=0.6", "", mtHTML},
		{"application/*", "", mtSimpleJSON},
		{"text/*;q=0.1, application/vnd.pypi.simple.v1+html", "", mtSimpleHTML},
		{"application/vnd.pypi.simple.v1+json;q=0, */*", "", mtHTML},
		{"application/json", "", ""},
		{"application/vnd.pypi.simple.v2+json", "", ""},
		{"text/html;q=0", "", ""},
		{"text/html", "format=" + mtSimpleJSON, mtSimpleJSON},
		{"", "format=application%2Fjson", ""},
	} {
		r := httptest.NewRequest("GET", "/pypi/x/simple/?"+tt.query, nil)
		if tt.accept != "" {
			r.Header.Set("Accept", tt.accept)
		}
		got, ok := negotiate(r)
		if got != tt.want || ok != (tt.want != "") {
			t.Errorf("negotiate(%q, %q) = %q, %v; want %q", tt.accept, tt.query, got, ok, tt.want)
		}
	}
}

func TestRouting(t *testing.T) {
	e := newEnv(t)
	e.mustUpload("local", wheel("My.Pkg", "1.0", nil))
	for _, tt := range []struct {
		method, path string
		status       int
		location     string
	}{
		{"GET", "/pypi/local", http.StatusMovedPermanently, "/pypi/local/simple/"},
		{"GET", "/pypi/local/", http.StatusMovedPermanently, "/pypi/local/simple/"},
		{"GET", "/pypi/local/simple", http.StatusMovedPermanently, "/pypi/local/simple/"},
		{"GET", "/pypi/local/simple/My.Pkg/", http.StatusMovedPermanently, "/pypi/local/simple/my-pkg/"},
		{"GET", "/pypi/local/simple/my-pkg", http.StatusMovedPermanently, "/pypi/local/simple/my-pkg/"},
		{"GET", "/pypi/local/simple/My_Pkg?format=text/html", http.StatusMovedPermanently, "/pypi/local/simple/my-pkg/?format=text/html"},
		{"GET", "/pypi/local/simple/my-pkg/", http.StatusOK, ""},
		{"HEAD", "/pypi/local/simple/my-pkg/", http.StatusOK, ""},
		{"GET", "/pypi/local/simple/-bad-/", http.StatusNotFound, ""},
		{"GET", "/pypi/local/simple/my-pkg/extra", http.StatusNotFound, ""},
		{"POST", "/pypi/local/simple/my-pkg/", http.StatusMethodNotAllowed, ""},
		{"GET", "/pypi/nope/simple/", http.StatusNotFound, ""},
		{"GET", "/pypi/oci/simple/", http.StatusNotFound, ""},
		{"GET", "/pypi/local/files/My.Pkg/my_pkg-1.0-py3-none-any.whl", http.StatusNotFound, ""},
		{"GET", "/pypi/local/files/my-pkg/.hidden", http.StatusNotFound, ""},
		{"GET", "/pypi/local/files/my-pkg", http.StatusNotFound, ""},
		{"DELETE", "/pypi/local/files/my-pkg/my_pkg-1.0-py3-none-any.whl", http.StatusMethodNotAllowed, ""},
		{"GET", "/pypi/local/pypi/My.Pkg/json", http.StatusOK, ""},
		{"GET", "/pypi/local/pypi/my-pkg/1.0/json", http.StatusOK, ""},
		{"GET", "/pypi/local/pypi/my-pkg", http.StatusNotFound, ""},
		{"GET", "/pypi/local/other", http.StatusNotFound, ""},
		{"GET", "/pypi/local/simple/my-pkg/", http.StatusNotAcceptable, ""},
	} {
		var hdr []string
		if tt.status == http.StatusNotAcceptable {
			hdr = []string{"Accept", "image/png"}
		}
		w := e.do(tt.method, tt.path, nil, hdr...)
		if w.Code != tt.status || w.Header().Get("Location") != tt.location {
			t.Errorf("%s %s: %d %q, want %d %q", tt.method, tt.path, w.Code, w.Header().Get("Location"), tt.status, tt.location)
		}
	}
}

func TestParseMetadata(t *testing.T) {
	m := parseMetadata([]byte("Metadata-Version: 1.1\r\nName: pkg\r\nDescription: line one\r\n        |line two\r\n        line three\r\n" +
		"License: MIT\n  continued\nClassifier: A\nClassifier: B\nnot a field\nKeywords:\n\nbody text\n"))
	if m.get("name") != "pkg" || m.description() != "line one\nline two\nline three" || m.get("license") != "MIT\ncontinued" ||
		!slices.Equal(m.all("classifier"), []string{"A", "B"}) || m.get("keywords") != "" || m.body != "body text\n" {
		t.Errorf("parsed %+v body %q", m.fields, m.body)
	}
	if m := parseMetadata([]byte("Name: x\n\nthe body")); m.description() != "the body" {
		t.Errorf("description from the body: %q", m.description())
	}
	if !reliableSdistMetadata(parseMetadata([]byte("Metadata-Version: 2.4\n"))) ||
		reliableSdistMetadata(parseMetadata([]byte("Metadata-Version: 2.1\n"))) ||
		reliableSdistMetadata(parseMetadata([]byte("Metadata-Version: 2.3\nDynamic: Version\n"))) {
		t.Error("reliableSdistMetadata is wrong")
	}
	form := map[string][]string{"name": {"pkg"}, "version": {"1.0"}, "summary": {"S"}, "license": {"line1\nline2"},
		"requires_dist": {"a", "b"}, "description": {"desc"}, "author": {"UNKNOWN"}}
	fm := parseMetadata(formMetadata(form))
	if fm.get("name") != "pkg" || fm.get("metadata-version") != "2.1" || fm.get("license") != "line1\nline2" ||
		!slices.Equal(fm.all("requires-dist"), []string{"a", "b"}) || fm.description() != "desc" || fm.get("author") != "" {
		t.Errorf("form metadata %+v %q", fm.fields, fm.body)
	}
}

func TestWheelMetadata(t *testing.T) {
	build := func(files map[string]string) []byte {
		var b bytes.Buffer
		zw := zip.NewWriter(&b)
		for n, c := range files {
			w, _ := zw.Create(n)
			w.Write([]byte(c))
		}
		zw.Close()
		return b.Bytes()
	}
	md := "Metadata-Version: 2.1\nName: Pkg\nVersion: 1.0.0\n"
	for _, tt := range []struct {
		name  string
		files map[string]string
		want  string // "" for success
	}{
		{"ok", map[string]string{"pkg-1.0.dist-info/METADATA": md}, ""},
		{"ok with case and zeros", map[string]string{"Pkg-1.0.0.dist-info/METADATA": md}, ""},
		{"missing", map[string]string{"pkg/__init__.py": ""}, "has no pkg-1.0.dist-info/METADATA"},
		{"nested", map[string]string{"x/pkg-1.0.dist-info/METADATA": md}, "has no"},
		{"other project", map[string]string{"other-1.0.dist-info/METADATA": md}, "has no"},
		{"two", map[string]string{"pkg-1.0.dist-info/METADATA": md, "pkg-1.0.0.dist-info/METADATA": md}, "more than one"},
		{"wrong version inside", map[string]string{"pkg-1.0.dist-info/METADATA": "Name: pkg\nVersion: 2.0\n"}, `names version "2.0"`},
	} {
		b := build(tt.files)
		_, err := wheelMetadata(bytes.NewReader(b), int64(len(b)), "pkg", "1.0")
		if tt.want == "" && err != nil || tt.want != "" && (err == nil || !strings.Contains(err.Error(), tt.want)) {
			t.Errorf("%s: %v, want %q", tt.name, err, tt.want)
		}
	}
	// A .zip source distribution's PKG-INFO.
	b := build(map[string]string{"pkg-1.0/PKG-INFO": md, "pkg-1.0/setup.py": ""})
	if got, err := sdistMetadata(nil, bytes.NewReader(b), int64(len(b)), "pkg-1.0.zip", "pkg", "1.0"); err != nil || string(got) != md {
		t.Errorf("zip sdist metadata %q, %v", got, err)
	}
	b = build(map[string]string{"pkg-1.0/sub/PKG-INFO": md})
	if _, err := sdistMetadata(nil, bytes.NewReader(b), int64(len(b)), "pkg-1.0.zip", "pkg", "1.0"); err == nil {
		t.Error("a nested PKG-INFO was used")
	}
	if _, err := sdistMetadata(strings.NewReader("not gzip"), nil, 0, "pkg-1.0.tar.gz", "pkg", "1.0"); err == nil {
		t.Error("an invalid archive had metadata")
	}
}

func TestRecords(t *testing.T) {
	d := blob.FromBytes([]byte("x"))
	now := time.Date(2026, 1, 2, 3, 4, 5, 6, time.UTC)
	for _, f := range []*fileRecord{
		{Kind: kindHosted, Project: "p", Version: "1.0", Digest: d, Size: 9, MD5: make([]byte, 16), Blake2b: make([]byte, 32),
			Uploaded: now, RequiresPython: ">=3", PackageType: typeWheel, PythonVersion: "py3", Yanked: true, YankedReason: "r",
			Meta: d, MetaSize: 3, MetaServed: true},
		{Kind: kindHosted, Project: "p", Version: "1.0", Digest: d, Size: 9},
		{Kind: kindTombstone, Project: "p", Version: "1.0", Deleted: now},
		{Kind: kindCached, Project: "p", Digest: d, Size: 9},
	} {
		got, err := decodeFile(f.encode())
		if err != nil {
			t.Fatal(err)
		}
		if string(got.encode()) != string(f.encode()) || got.Kind != f.Kind || got.Digest != f.Digest || !got.Deleted.Equal(f.Deleted) {
			t.Errorf("round trip of %+v: %+v", f, got)
		}
	}
	if _, err := decodeFile([]byte{recordFormat, 9}); err == nil {
		t.Error("an unknown kind decoded")
	}
	if _, err := decodeFile(append((&fileRecord{Kind: kindCached, Digest: d}).encode(), 0)); err == nil {
		t.Error("trailing bytes decoded")
	}
	if got, err := decodeProject((&projectRecord{Name: "P", Created: now}).encode()); err != nil || got.Name != "P" || !got.Created.Equal(now) {
		t.Errorf("project record %+v, %v", got, err)
	}
	if string(pulledKey(fileKey("r", "f"))) != "pypi\x00pulled\x00file\x00r\x00f" {
		t.Errorf("pulled key %q", pulledKey(fileKey("r", "f")))
	}
}

func TestPageCache(t *testing.T) {
	var c pageCache
	docs := make([]*projectDoc, 4)
	for i := range docs {
		docs[i] = &projectDoc{Name: string(rune('a' + i))}
		c.put(docs[i].Name, docs[i], maxPageCache/3)
		if i == 1 {
			c.get("a") // a is used again, so b is the oldest
		}
	}
	if c.get("b") != nil || c.get("a") == nil || c.get("d") == nil || c.total > maxPageCache {
		t.Errorf("cache keeps %d bytes: a %v b %v d %v", c.total, c.get("a") != nil, c.get("b") != nil, c.get("d") != nil)
	}
}
