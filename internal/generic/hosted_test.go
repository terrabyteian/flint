package generic

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/terrabyteian/flint/internal/gc"
	"github.com/terrabyteian/flint/internal/meta"
)

// TestHostedUploadDownload checks an upload and the download of it:
// headers, HEAD, ranges, and conditional requests.
func TestHostedUploadDownload(t *testing.T) {
	e := newEnv(t)
	body := []byte("hello, generic files\n")
	w := e.put(http.StatusCreated, "/generic/local/tools/v1/hello.txt", body, "Content-Type", "text/plain; charset=utf-8")
	if got := w.Header().Get("Location"); got != "/generic/local/tools/v1/hello.txt" {
		t.Errorf("Location = %q", got)
	}
	if !strings.Contains(w.Body.String(), `"sha256":"`+sha(body)+`"`) {
		t.Errorf("upload response %s does not name the digest", w.Body)
	}

	w = e.expect(http.StatusOK, "GET", "/generic/local/tools/v1/hello.txt", nil)
	if w.Body.String() != string(body) {
		t.Errorf("body = %q", w.Body)
	}
	for k, want := range map[string]string{
		"Content-Type":            "text/plain; charset=utf-8",
		"ETag":                    `"sha256:` + sha(body) + `"`,
		"Content-Security-Policy": "sandbox",
		"X-Content-Type-Options":  "nosniff",
		"Cache-Control":           "private, max-age=31536000, immutable",
		"Last-Modified":           "Thu, 01 Oct 2026 12:00:00 GMT",
	} {
		if got := w.Header().Get(k); got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}

	w = e.expect(http.StatusOK, "HEAD", "/generic/local/tools/v1/hello.txt", nil)
	if w.Body.Len() != 0 || w.Header().Get("Content-Length") != "21" {
		t.Errorf("HEAD: body %q, Content-Length %q", w.Body, w.Header().Get("Content-Length"))
	}
	w = e.expect(http.StatusPartialContent, "GET", "/generic/local/tools/v1/hello.txt", nil, "Range", "bytes=7-13")
	if w.Body.String() != "generic" {
		t.Errorf("range = %q", w.Body)
	}
	e.expect(http.StatusNotModified, "GET", "/generic/local/tools/v1/hello.txt", nil, "If-None-Match", `"sha256:`+sha(body)+`"`)

	e.get(http.StatusNotFound, "/generic/local/tools/v1/other.txt")
	e.get(http.StatusNotFound, "/generic/team/tools/v1/hello.txt") // another repository
	e.get(http.StatusNotFound, "/generic/pypi/tools/v1/hello.txt") // another format
	e.get(http.StatusNotFound, "/generic/nope/x")

	// Anonymous pull makes a file cacheable by shared caches.
	e.put(http.StatusCreated, "/generic/team/a.bin", body)
	w = e.expect(http.StatusOK, "GET", "/generic/team/a.bin", nil)
	if got := w.Header().Get("Cache-Control"); got != "public, max-age=31536000, immutable" {
		t.Errorf("Cache-Control of an anonymous repository = %q", got)
	}
}

// TestContentType checks the content type a file is served with: as
// uploaded, or inferred from the extension when the upload names none
// or names the form type curl and wget send by default.
func TestContentType(t *testing.T) {
	e := newEnv(t)
	for _, c := range []struct{ path, sent, want string }{
		{"a.json", "", "application/json"},
		{"b.json", "application/x-www-form-urlencoded", "application/json"},
		{"c.bin", "", "application/octet-stream"},
		{"d", "application/vnd.acme+tar; Version=2", "application/vnd.acme+tar; version=2"},
		{"e.html", "", "text/html; charset=utf-8"},
	} {
		var hdr []string
		if c.sent != "" {
			hdr = []string{"Content-Type", c.sent}
		}
		e.put(http.StatusCreated, "/generic/local/"+c.path, []byte("x"), hdr...)
		w := e.expect(http.StatusOK, "GET", "/generic/local/"+c.path, nil)
		if got := w.Header().Get("Content-Type"); got != c.want {
			t.Errorf("%s uploaded as %q: Content-Type %q, want %q", c.path, c.sent, got, c.want)
		}
		if got := w.Header().Get("Content-Security-Policy"); got != "sandbox" {
			t.Errorf("%s: Content-Security-Policy %q", c.path, got)
		}
	}
	e.put(http.StatusBadRequest, "/generic/local/f", []byte("x"), "Content-Type", "not a type")
}

// TestUploadDigests checks that the digest headers an upload sends are
// verified, and that a mismatch stores nothing.
func TestUploadDigests(t *testing.T) {
	e := newEnv(t)
	body := []byte("checked content")
	sum, _ := hex.DecodeString(sha(body))
	b64 := base64.StdEncoding.EncodeToString(sum)
	other := base64.StdEncoding.EncodeToString(make([]byte, 32))
	for i, c := range []struct {
		hdr    []string
		status int
	}{
		{[]string{"Content-Digest", "sha-256=:" + b64 + ":"}, http.StatusCreated},
		{[]string{"Content-Digest", "sha-512=:AAAA:, sha-256=:" + b64 + ":"}, http.StatusCreated},
		{[]string{"X-Checksum-Sha256", strings.ToUpper(sha(body))}, http.StatusCreated},
		{[]string{"Content-Digest", "sha-256=:" + b64 + ":", "X-Checksum-Sha256", sha(body)}, http.StatusCreated},
		{[]string{"Content-Digest", "sha-512=:AAAA:"}, http.StatusCreated}, // not checked
		{[]string{"Content-Digest", "sha-256=:" + other + ":"}, http.StatusBadRequest},
		{[]string{"X-Checksum-Sha256", strings.Repeat("0", 64)}, http.StatusBadRequest},
		{[]string{"X-Checksum-Sha256", "abc"}, http.StatusBadRequest},
		{[]string{"Content-Digest", "sha-256=" + b64}, http.StatusBadRequest},
		{[]string{"Content-Digest", "sha-256"}, http.StatusBadRequest},
		{[]string{"Content-Digest", "sha-256=:" + b64 + ":", "X-Checksum-Sha256", strings.Repeat("0", 64)}, http.StatusBadRequest},
	} {
		p := "/generic/local/d/" + string(rune('a'+i))
		e.put(c.status, p, body, c.hdr...)
		want := http.StatusOK
		if c.status != http.StatusCreated {
			want = http.StatusNotFound
		}
		e.get(want, p)
	}
	// A digest header that disagrees with a published file is refused
	// before the body is read.
	e.put(http.StatusConflict, "/generic/local/d/a", []byte("other"), "X-Checksum-Sha256", sha([]byte("other")))
}

// TestImmutableFiles checks the immutable-name rule: an identical
// upload succeeds without a change, different content is refused, and
// a deleted path can never be used again.
func TestImmutableFiles(t *testing.T) {
	e := newEnv(t)
	a, b := content(1), content(2)
	e.put(http.StatusCreated, "/generic/local/app.tgz", a)
	before := e.record("local", "app.tgz")
	e.advance(testWindow)
	w := e.put(http.StatusOK, "/generic/local/app.tgz", a)
	if w.Header().Get("Location") != "" {
		t.Error("an identical upload answers with a Location")
	}
	if after := e.record("local", "app.tgz"); !after.Uploaded.Equal(before.Uploaded) {
		t.Errorf("an identical upload changed the record: %v, then %v", before.Uploaded, after.Uploaded)
	}
	w = e.put(http.StatusConflict, "/generic/local/app.tgz", b)
	if !strings.Contains(w.Body.String(), "different content") {
		t.Errorf("conflict message %q", w.Body)
	}
	if got := e.get(http.StatusOK, "/generic/local/app.tgz"); got != string(a) {
		t.Errorf("after a refused overwrite: %q", got)
	}

	e.expect(http.StatusNoContent, "DELETE", "/generic/local/app.tgz", nil)
	e.get(http.StatusNotFound, "/generic/local/app.tgz")
	e.expect(http.StatusNotFound, "HEAD", "/generic/local/app.tgz", nil)
	e.expect(http.StatusNotFound, "DELETE", "/generic/local/app.tgz", nil)
	for _, body := range [][]byte{a, b} {
		w := e.put(http.StatusConflict, "/generic/local/app.tgz", body)
		if !strings.Contains(w.Body.String(), "never be used again") {
			t.Errorf("upload after delete: %q", w.Body)
		}
	}
	if f := e.record("local", "app.tgz"); f == nil || f.Kind != kindTombstone || !f.Digest.IsZero() {
		t.Errorf("after delete the record is %+v, want a tombstone without a digest", f)
	}
	e.expect(http.StatusNotFound, "DELETE", "/generic/local/never.tgz", nil)
}

// TestAllowOverwrite checks a repository with generic.allowOverwrite:
// an upload replaces a file, and a delete removes it without a
// tombstone.
func TestAllowOverwrite(t *testing.T) {
	e := newEnv(t)
	e.put(http.StatusCreated, "/generic/scratch/latest/app", content(1))
	e.put(http.StatusOK, "/generic/scratch/latest/app", content(1))
	e.put(http.StatusOK, "/generic/scratch/latest/app", content(2))
	w := e.expect(http.StatusOK, "GET", "/generic/scratch/latest/app", nil)
	if w.Body.String() != string(content(2)) || w.Header().Get("Cache-Control") != "no-cache" {
		t.Errorf("after overwrite: %q, Cache-Control %q", w.Body, w.Header().Get("Cache-Control"))
	}
	e.expect(http.StatusNoContent, "DELETE", "/generic/scratch/latest/app", nil)
	if f := e.record("scratch", "latest/app"); f != nil {
		t.Errorf("after delete the record is %+v, want none", f)
	}
	e.get(http.StatusNotFound, "/generic/scratch/latest/app")
	e.put(http.StatusCreated, "/generic/scratch/latest/app", content(1))
}

// TestConcurrentUploads checks that of concurrent uploads to one path,
// all with identical content succeed, and of different content exactly
// one does.
func TestConcurrentUploads(t *testing.T) {
	e := newEnv(t)
	const n = 8
	statuses := func(path string, body func(i int) []byte) []int {
		var wg sync.WaitGroup
		out := make([]int, n)
		for i := range n {
			wg.Go(func() { out[i] = e.do("PUT", path, body(i)).Code })
		}
		wg.Wait()
		slices.Sort(out)
		return out
	}
	same := statuses("/generic/local/same", func(int) []byte { return content(0) })
	if same[0] != http.StatusOK && same[0] != http.StatusCreated || same[n-1] != http.StatusCreated && same[n-1] != http.StatusOK {
		t.Errorf("identical uploads: %v", same)
	}
	if created := slices.Index(same, http.StatusCreated); created < 0 || slices.Contains(same[created+1:], http.StatusCreated) {
		t.Errorf("identical uploads: %v, want exactly one 201", same)
	}
	diff := statuses("/generic/local/diff", content)
	if want := append([]int{http.StatusCreated}, slices.Repeat([]int{http.StatusConflict}, n-1)...); !slices.Equal(diff, want) {
		t.Errorf("different uploads: %v, want %v", diff, want)
	}
}

// TestPaths checks which request paths name files and directories.
func TestPaths(t *testing.T) {
	e := newEnv(t)
	for _, p := range []string{"a", "a/b/c.tar.gz", "with space/ünïcode", "a:b", strings.Repeat("x", maxPath)} {
		if !ValidPath(p) {
			t.Errorf("ValidPath(%q) = false", p)
		}
	}
	for _, p := range []string{"", "/a", "a/", "a//b", "./a", "a/../b", "a/.", "a\x00b", "a\nb", "a\x7f", "a\u0085", strings.Repeat("x", maxPath+1), "\xff"} {
		if ValidPath(p) {
			t.Errorf("ValidPath(%q) = true", p)
		}
	}
	e.put(http.StatusCreated, "/generic/local/with%20space/a%3Fb", []byte("q"))
	if got := e.get(http.StatusOK, "/generic/local/with%20space/a%3Fb"); got != "q" {
		t.Errorf("escaped path: %q", got)
	}
	if w := e.put(http.StatusCreated, "/generic/local/x:y/a%20b", []byte("q")); w.Header().Get("Location") != "/generic/local/x:y/a%20b" {
		t.Errorf("Location = %q", w.Header().Get("Location"))
	}
	e.put(http.StatusNotFound, "/generic/local/a%00b", []byte("q"))
	e.expect(http.StatusMovedPermanently, "GET", "/generic/local", nil)
	e.expect(http.StatusMethodNotAllowed, "POST", "/generic/local/a", []byte("q"))
	e.expect(http.StatusMethodNotAllowed, "PUT", "/generic/local/dir/", []byte("q"))
	e.expect(http.StatusMethodNotAllowed, "DELETE", "/generic/local/", nil)
}

// TestListing checks directory listings of a hosted repository: only
// the entries directly below, as JSON or HTML, without deleted files.
func TestListing(t *testing.T) {
	e := newEnv(t)
	for _, p := range []string{"a.txt", "dir/one", "dir/sub/two", "dir/sub/three", "dir-x", "gone/x", "gone2/x", "gone2/y", "b%3Ac"} {
		e.put(http.StatusCreated, "/generic/local/"+p, []byte(p))
	}
	e.expect(http.StatusNoContent, "DELETE", "/generic/local/gone/x", nil)
	e.expect(http.StatusNoContent, "DELETE", "/generic/local/gone2/x", nil)

	l := e.list("/generic/local/")
	if got, want := names(l), "a.txt b:c dir-x dir/ gone2/"; got != want {
		t.Errorf("root: %q, want %q", got, want)
	}
	if l.Path != "" || l.Repository != "local" {
		t.Errorf("root listing names %q in %q", l.Path, l.Repository)
	}
	if f := l.Entries[0]; f.Type != "file" || f.Size == nil || *f.Size != 5 || f.SHA256 != sha([]byte("a.txt")) || f.Uploaded == nil {
		t.Errorf("file entry %+v", f)
	}
	if d := l.Entries[3]; d.Type != "directory" || d.Size != nil || d.SHA256 != "" {
		t.Errorf("directory entry %+v", d)
	}
	if got, want := names(e.list("/generic/local/dir/")), "one sub/"; got != want {
		t.Errorf("dir/: %q, want %q", got, want)
	}
	if got, want := names(e.list("/generic/local/dir/sub/")), "three two"; got != want {
		t.Errorf("dir/sub/: %q, want %q", got, want)
	}
	e.get(http.StatusNotFound, "/generic/local/gone/")
	e.get(http.StatusNotFound, "/generic/local/nothing/")
	if got := e.list("/generic/team/"); len(got.Entries) != 0 {
		t.Errorf("an empty repository lists %v", got.Entries)
	}

	html := e.get(http.StatusOK, "/generic/local/")
	for _, want := range []string{`<a href="a.txt">a.txt</a>`, `<a href="./b:c">b:c</a>`, `<a href="dir/">dir/</a>`} {
		if !strings.Contains(html, want) {
			t.Errorf("HTML listing lacks %s:\n%s", want, html)
		}
	}
	if strings.Contains(html, `href="../"`) {
		t.Error("the root listing links its parent")
	}
	if html := e.get(http.StatusOK, "/generic/local/dir/sub/"); !strings.Contains(html, `<a href="../">`) {
		t.Errorf("a directory listing does not link its parent:\n%s", html)
	}
	e.get(http.StatusNotFound, "/generic/remote/") // listings are not proxied
}

// TestReadOnlyRepositories checks the writes proxy and virtual
// repositories refuse, and that only clients that may read the
// repository learn why.
func TestReadOnlyRepositories(t *testing.T) {
	e := newEnv(t)
	e.put(http.StatusMethodNotAllowed, "/generic/remote/a", []byte("x"))
	e.put(http.StatusMethodNotAllowed, "/generic/all/a", []byte("x"))
	e.expect(http.StatusMethodNotAllowed, "DELETE", "/generic/remote/a", nil)
	e.expect(http.StatusMethodNotAllowed, "DELETE", "/generic/filtered/a", nil)
	want := []string{"remote:pull", "virtual all>:pull", "remote:pull", "virtual filtered>team:pull"}
	if got := e.auth.reset(); !slices.Equal(got, want) {
		t.Errorf("authorized %q, want %q", got, want)
	}

	e.auth.deny = "remote"
	if w := e.put(http.StatusUnauthorized, "/generic/remote/a", []byte("x")); strings.Contains(w.Body.String(), e.up.URL) {
		t.Errorf("an unauthorized upload refusal names the upstream: %q", w.Body)
	}
	e.expect(http.StatusUnauthorized, "DELETE", "/generic/remote/a", nil)
	e.auth.deny = "all"
	if w := e.put(http.StatusUnauthorized, "/generic/all/a", []byte("x")); strings.Contains(w.Body.String(), "local") {
		t.Errorf("an unauthorized upload refusal names the members: %q", w.Body)
	}
	e.expect(http.StatusUnauthorized, "DELETE", "/generic/all/a", nil)
}

// TestAuthorization checks the actions each request is authorized for.
func TestAuthorization(t *testing.T) {
	e := newEnv(t)
	e.put(http.StatusCreated, "/generic/local/a", []byte("x"))
	e.get(http.StatusOK, "/generic/local/a")
	e.get(http.StatusOK, "/generic/local/")
	e.expect(http.StatusNoContent, "DELETE", "/generic/local/a", nil)
	e.get(http.StatusNotFound, "/generic/all/a")
	e.put(http.StatusCreated, "/generic/filtered/b", []byte("x"))
	want := []string{"local:push", "local:pull", "local:pull", "local:delete", "virtual all>:pull", "virtual filtered>team:push"}
	if got := e.auth.reset(); !slices.Equal(got, want) {
		t.Errorf("authorized %q, want %q", got, want)
	}
	e.auth.deny = "local"
	w := e.put(http.StatusUnauthorized, "/generic/local/c", []byte("x"))
	if w.Header().Get("WWW-Authenticate") == "" {
		t.Error("no challenge")
	}
	e.auth.deny = ""
	e.get(http.StatusNotFound, "/generic/local/c")
}

// TestRestart checks that files and tombstones survive a restart.
func TestRestart(t *testing.T) {
	e := newEnv(t)
	e.put(http.StatusCreated, "/generic/local/kept", content(1))
	e.put(http.StatusCreated, "/generic/local/deleted", content(2))
	e.expect(http.StatusNoContent, "DELETE", "/generic/local/deleted", nil)
	e.restart()
	if got := e.get(http.StatusOK, "/generic/local/kept"); got != string(content(1)) {
		t.Errorf("after restart: %q", got)
	}
	e.put(http.StatusConflict, "/generic/local/deleted", content(2))
}

// TestUploadDoomedBlob checks that an upload of content a running
// garbage-collection sweep is about to delete asks the client to retry,
// and links nothing.
func TestUploadDoomedBlob(t *testing.T) {
	e := newEnv(t)
	body := content(7)
	var b meta.Batch
	b.Put(gc.DoomedKey(digestOf(body)), []byte{1})
	if _, err := e.meta.Commit(context.Background(), &b); err != nil {
		t.Fatal(err)
	}
	w := e.put(http.StatusServiceUnavailable, "/generic/local/x", body)
	if w.Header().Get("Retry-After") == "" {
		t.Error("no Retry-After")
	}
	if f := e.record("local", "x"); f != nil {
		t.Errorf("record %+v", f)
	}
	e.put(http.StatusServiceUnavailable, "/generic/scratch/x", body)
	if f := e.record("scratch", "x"); f != nil {
		t.Errorf("record %+v", f)
	}
}
