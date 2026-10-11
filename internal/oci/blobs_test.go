package oci

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/terrabyteian/flint/internal/blob"
	"github.com/terrabyteian/flint/internal/fsys"
	"github.com/terrabyteian/flint/internal/gc"
	"github.com/terrabyteian/flint/internal/meta"
)

func TestMonolithicUploadAndPull(t *testing.T) {
	e := newEnv(t)
	content := []byte("hello, blob")
	d := blob.FromBytes(content)

	w := e.do("POST", "/v2/hosted/app/blobs/uploads/?digest="+d.String(), content)
	want(t, w, 201, "")
	if got := w.Header().Get("Location"); got != "/v2/hosted/app/blobs/"+d.String() {
		t.Errorf("Location = %q", got)
	}
	if got := w.Header().Get("Docker-Content-Digest"); got != d.String() {
		t.Errorf("Docker-Content-Digest = %q", got)
	}

	w = e.do("GET", "/v2/hosted/app/blobs/"+d.String(), nil)
	want(t, w, 200, "")
	if !bytes.Equal(w.Body.Bytes(), content) {
		t.Errorf("GET body = %q", w.Body)
	}
	for k, v := range map[string]string{
		"Docker-Content-Digest": d.String(),
		"Content-Type":          "application/octet-stream",
		"Content-Length":        "11",
		"ETag":                  `"` + d.String() + `"`,
	} {
		if got := w.Header().Get(k); got != v {
			t.Errorf("GET %s = %q, want %q", k, got, v)
		}
	}

	w = e.do("HEAD", "/v2/hosted/app/blobs/"+d.String(), nil)
	want(t, w, 200, "")
	if w.Body.Len() != 0 || w.Header().Get("Content-Length") != "11" || w.Header().Get("Docker-Content-Digest") != d.String() {
		t.Errorf("HEAD = %q %v", w.Body, w.Header())
	}

	w = e.do("GET", "/v2/hosted/app/blobs/"+d.String(), nil, "Range", "bytes=7-")
	want(t, w, http.StatusPartialContent, "")
	if w.Body.String() != "blob" || w.Header().Get("Content-Range") != "bytes 7-10/11" {
		t.Errorf("range GET = %q %v", w.Body, w.Header())
	}
	w = e.do("GET", "/v2/hosted/app/blobs/"+d.String(), nil, "If-None-Match", `"`+d.String()+`"`)
	want(t, w, http.StatusNotModified, "")

	// Blobs are visible only in the name they were pushed or mounted to.
	want(t, e.do("GET", "/v2/hosted/other/blobs/"+d.String(), nil), 404, codeBlobUnknown)
	want(t, e.do("HEAD", "/v2/other/app/blobs/"+d.String(), nil), 404, "")
	want(t, e.do("GET", "/v2/hosted/app/blobs/sha256:nothex", nil), 400, codeDigestInvalid)
	want(t, e.do("GET", "/v2/hosted/app/blobs/sha512:"+strings.Repeat("a", 128), nil), 400, codeDigestInvalid)

	if got := e.reg; got == nil {
		t.Fatal("no registry")
	}
	var buf bytes.Buffer
	e.reg.WriteTo(&buf)
	if !strings.Contains(buf.String(), `flint_oci_upload_bytes_total{repository="hosted"} 11`) {
		t.Errorf("metrics missing upload bytes:\n%s", buf.String())
	}
}

func TestMonolithicUploadErrors(t *testing.T) {
	e := newEnv(t)
	content := []byte("content")
	wrong := blob.FromBytes([]byte("other"))
	want(t, e.do("POST", "/v2/hosted/app/blobs/uploads/?digest="+wrong.String(), content), 400, codeDigestInvalid)
	want(t, e.do("GET", "/v2/hosted/app/blobs/"+wrong.String(), nil), 404, codeBlobUnknown)
	want(t, e.do("POST", "/v2/hosted/app/blobs/uploads/?digest=sha256:x", content), 400, codeDigestInvalid)
	d := blob.FromBytes(content)
	want(t, e.do("POST", "/v2/hosted/app/blobs/uploads/?digest="+d.String(), content, "Content-Range", "5-11"), 416, codeBlobUploadInvalid)
	if n := countUploads(t, e); n != 0 {
		t.Errorf("%d upload sessions left after failed monolithic uploads", n)
	}
}

func countUploads(t *testing.T, e *env) int {
	t.Helper()
	v := e.meta.View()
	defer v.Release()
	n := 0
	v.Scan([]byte(nsUpload), nil, func([]byte, meta.Record) bool { n++; return true })
	return n
}

// startSession starts an upload session and returns its location.
func (e *env) startSession(name string) string {
	e.t.Helper()
	w := e.do("POST", "/v2/"+name+"/blobs/uploads/", nil)
	want(e.t, w, 202, "")
	loc := w.Header().Get("Location")
	id := w.Header().Get("Docker-Upload-UUID")
	if loc != "/v2/"+name+"/blobs/uploads/"+id || id == "" || w.Header().Get("Range") != "0-0" {
		e.t.Fatalf("POST upload headers = %v", w.Header())
	}
	return loc
}

func TestSessionUpload(t *testing.T) {
	e := newEnv(t)
	loc := e.startSession("hosted/app")
	content := []byte("one request after the POST")
	d := blob.FromBytes(content)
	w := e.do("PUT", loc+"?digest="+d.String(), content)
	want(t, w, 201, "")
	if w.Header().Get("Location") != "/v2/hosted/app/blobs/"+d.String() {
		t.Errorf("Location = %q", w.Header().Get("Location"))
	}
	want(t, e.do("GET", "/v2/hosted/app/blobs/"+d.String(), nil), 200, "")
	// The session is over.
	want(t, e.do("GET", loc, nil), 404, codeBlobUploadUnknown)
	if n := countUploads(t, e); n != 0 {
		t.Errorf("%d upload records left", n)
	}
}

func TestChunkedUpload(t *testing.T) {
	e := newEnv(t)
	loc := e.startSession("hosted/app")
	chunk1, chunk2 := []byte("first chunk, "), []byte("second chunk")
	d := blob.FromBytes(append(append([]byte{}, chunk1...), chunk2...))

	// Out of order: the first chunk must start at 0.
	w := e.do("PATCH", loc, chunk2, "Content-Range", "13-24")
	want(t, w, 416, codeBlobUploadInvalid)
	if w.Header().Get("Range") != "0-0" || w.Header().Get("Location") != loc {
		t.Errorf("416 headers = %v", w.Header())
	}

	w = e.do("PATCH", loc, chunk1, "Content-Range", "0-12", "Content-Type", "application/octet-stream")
	want(t, w, 202, "")
	if w.Header().Get("Range") != "0-12" || w.Header().Get("Location") != loc {
		t.Errorf("PATCH headers = %v", w.Header())
	}
	// Retrying the same chunk is out of order now.
	want(t, e.do("PATCH", loc, chunk1, "Content-Range", "0-12"), 416, codeBlobUploadInvalid)

	w = e.do("GET", loc, nil)
	want(t, w, 204, "")
	if w.Header().Get("Range") != "0-12" || w.Header().Get("Location") != loc || w.Header().Get("Docker-Upload-UUID") == "" {
		t.Errorf("status headers = %v", w.Header())
	}

	w = e.do("PATCH", loc, chunk2, "Content-Range", "bytes 13-24")
	want(t, w, 202, "")
	if w.Header().Get("Range") != "0-24" {
		t.Errorf("Range after chunk 2 = %q", w.Header().Get("Range"))
	}
	want(t, e.do("PUT", loc+"?digest="+d.String(), nil, "Content-Length", "0"), 201, "")
	w = e.do("GET", "/v2/hosted/app/blobs/"+d.String(), nil)
	want(t, w, 200, "")
	if w.Body.String() != "first chunk, second chunk" {
		t.Errorf("assembled blob = %q", w.Body)
	}
}

func TestFinalChunkInPut(t *testing.T) {
	e := newEnv(t)
	loc := e.startSession("hosted/app")
	want(t, e.do("PATCH", loc, []byte("abc"), "Content-Range", "0-2"), 202, "")
	d := blob.FromBytes([]byte("abcdef"))
	want(t, e.do("PUT", loc+"?digest="+d.String(), []byte("def"), "Content-Range", "3-5"), 201, "")
	w := e.do("GET", "/v2/hosted/app/blobs/"+d.String(), nil)
	if w.Body.String() != "abcdef" {
		t.Errorf("blob = %q", w.Body)
	}
}

// TestStreamedUpload streams a blob in a chunked request body without a
// Content-Range, as Docker does, over a real connection.
func TestStreamedUpload(t *testing.T) {
	e := newEnv(t)
	srv := httptest.NewServer(e.h)
	defer srv.Close()
	loc := e.startSession("hosted/app")

	content := bytes.Repeat([]byte("0123456789abcdef"), 64<<10) // 1 MiB
	pr, pw := io.Pipe()
	go func() {
		for i := 0; i < len(content); i += 100_000 {
			pw.Write(content[i:min(i+100_000, len(content))])
		}
		pw.Close()
	}()
	req, _ := http.NewRequest("PATCH", srv.URL+loc, pr)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 202 || resp.Header.Get("Range") != "0-1048575" {
		t.Fatalf("streamed PATCH = %d %v", resp.StatusCode, resp.Header)
	}
	d := blob.FromBytes(content)
	req, _ = http.NewRequest("PUT", srv.URL+loc+"?digest="+d.String(), nil)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 201 {
		t.Fatalf("PUT = %d", resp.StatusCode)
	}
	resp, err = http.Get(srv.URL + "/v2/hosted/app/blobs/" + d.String())
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !bytes.Equal(got, content) {
		t.Errorf("pulled %d bytes, want %d", len(got), len(content))
	}
}

func TestUploadErrors(t *testing.T) {
	e := newEnv(t)
	content := []byte("payload")
	d := blob.FromBytes(content)

	want(t, e.do("GET", "/v2/hosted/app/blobs/uploads/nope", nil), 404, codeBlobUploadUnknown)
	want(t, e.do("PATCH", "/v2/hosted/app/blobs/uploads/"+strings.Repeat("a", 32), content), 404, codeBlobUploadUnknown)
	want(t, e.do("DELETE", "/v2/hosted/app/blobs/uploads/nope", nil), 404, codeBlobUploadUnknown)

	// A session belongs to the name it was started in.
	loc := e.startSession("hosted/app")
	id := loc[strings.LastIndex(loc, "/")+1:]
	want(t, e.do("PATCH", "/v2/hosted/other/blobs/uploads/"+id, content), 404, codeBlobUploadUnknown)
	want(t, e.do("PUT", "/v2/other/app/blobs/uploads/"+id+"?digest="+d.String(), content), 404, codeBlobUploadUnknown)

	// Bad chunks leave the session usable.
	want(t, e.do("PATCH", loc, content, "Content-Range", "zero-six"), 400, codeBlobUploadInvalid)
	want(t, e.do("PATCH", loc, content, "Content-Range", "0-3"), 400, codeBlobUploadInvalid) // length mismatch
	want(t, e.do("PATCH", loc, content, "Content-Range", "6-0"), 400, codeBlobUploadInvalid)
	want(t, e.do("PUT", loc, content), 400, codeDigestInvalid) // no digest
	want(t, e.do("PUT", loc+"?digest=sha256:zz", content), 400, codeDigestInvalid)
	w := e.do("GET", loc, nil)
	want(t, w, 204, "")
	if w.Header().Get("Range") != "0-0" {
		t.Errorf("Range after rejected chunks = %q", w.Header().Get("Range"))
	}

	// A digest mismatch ends the session.
	wrong := blob.FromBytes([]byte("else"))
	want(t, e.do("PUT", loc+"?digest="+wrong.String(), content), 400, codeDigestInvalid)
	want(t, e.do("GET", loc, nil), 404, codeBlobUploadUnknown)
	want(t, e.do("GET", "/v2/hosted/app/blobs/"+wrong.String(), nil), 404, codeBlobUnknown)

	// Cancel.
	loc = e.startSession("hosted/app")
	want(t, e.do("PATCH", loc, content), 202, "")
	want(t, e.do("DELETE", loc, nil), 204, "")
	want(t, e.do("GET", loc, nil), 404, codeBlobUploadUnknown)
	if n := countUploads(t, e); n != 0 {
		t.Errorf("%d upload records left", n)
	}
}

// TestUploadBusy checks that a session open in one request is refused to
// another.
func TestUploadBusy(t *testing.T) {
	e := newEnv(t)
	loc := e.startSession("hosted/app")
	id := loc[strings.LastIndex(loc, "/")+1:]
	up, err := e.blobs.ResumeUpload(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	want(t, e.do("PATCH", loc, []byte("x")), 409, codeBlobUploadInvalid)
	up.Suspend()
	want(t, e.do("PATCH", loc, []byte("x")), 202, "")
}

// TestUploadSurvivesRestart continues a chunked upload after the stores
// are closed and reopened.
func TestUploadSurvivesRestart(t *testing.T) {
	fs := fsys.NewMem()
	e := newEnvFS(t, fs, "/data")
	loc := e.startSession("hosted/app")
	want(t, e.do("PATCH", loc, []byte("before "), "Content-Range", "0-6"), 202, "")
	if err := e.meta.Close(); err != nil {
		t.Fatal(err)
	}

	e = newEnvFS(t, fs.Restart(nil), "/data")
	w := e.do("GET", loc, nil)
	want(t, w, 204, "")
	if w.Header().Get("Range") != "0-6" {
		t.Fatalf("Range after restart = %q", w.Header().Get("Range"))
	}
	d := blob.FromBytes([]byte("before after"))
	want(t, e.do("PUT", loc+"?digest="+d.String(), []byte("after"), "Content-Range", "7-11"), 201, "")
	if w := e.do("GET", "/v2/hosted/app/blobs/"+d.String(), nil); w.Body.String() != "before after" {
		t.Errorf("blob after restart = %q", w.Body)
	}
}

// TestUploadOfLostBlobUpload forgets a session whose staged upload is gone.
func TestUploadOfLostBlobUpload(t *testing.T) {
	e := newEnv(t)
	loc := e.startSession("hosted/app")
	id := loc[strings.LastIndex(loc, "/")+1:]
	up, err := e.blobs.ResumeUpload(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	up.Cancel()
	want(t, e.do("PATCH", loc, []byte("x")), 404, codeBlobUploadUnknown)
	if n := countUploads(t, e); n != 0 {
		t.Errorf("stale session record kept")
	}
}

func TestMount(t *testing.T) {
	e := newEnv(t)
	content := []byte("shared layer")
	d := e.pushBlob("hosted/src", content)
	e.auth.reset()

	w := e.do("POST", "/v2/other/dst/blobs/uploads/?mount="+d.String()+"&from=hosted/src", nil)
	want(t, w, 201, "")
	calls := e.auth.reset()
	if len(calls) != 2 || calls[0] != (authCall{"other/dst", "pull,push"}) || calls[1] != (authCall{"hosted/src", "pull"}) {
		t.Errorf("mount authorization = %v", calls)
	}
	if w.Header().Get("Location") != "/v2/other/dst/blobs/"+d.String() || w.Header().Get("Docker-Content-Digest") != d.String() {
		t.Errorf("mount headers = %v", w.Header())
	}
	if w := e.do("GET", "/v2/other/dst/blobs/"+d.String(), nil); w.Code != 200 || w.Body.String() != "shared layer" {
		t.Errorf("mounted blob = %d %q", w.Code, w.Body)
	}

	missing := blob.FromBytes([]byte("missing"))
	for name, query := range map[string]string{
		"no from":         "mount=" + d.String(),
		"not in source":   "mount=" + missing.String() + "&from=hosted/src",
		"invalid digest":  "mount=sha256:x&from=hosted/src",
		"invalid source":  "mount=" + d.String() + "&from=Hosted/src",
		"unknown source":  "mount=" + d.String() + "&from=nope/src",
		"empty source":    "mount=" + d.String() + "&from=hosted/empty",
		"repository only": "mount=" + d.String() + "&from=hosted",
	} {
		t.Run(name, func(t *testing.T) {
			w := e.do("POST", "/v2/other/fallback/blobs/uploads/?"+query, nil)
			want(t, w, 202, "")
			if !strings.HasPrefix(w.Header().Get("Location"), "/v2/other/fallback/blobs/uploads/") {
				t.Errorf("fallback Location = %q", w.Header().Get("Location"))
			}
		})
	}

	// A source the caller may not pull from falls back too.
	e.auth.deny = func(repo string, _ []string) bool { return repo == "hosted/src" }
	want(t, e.do("POST", "/v2/other/denied/blobs/uploads/?mount="+d.String()+"&from=hosted/src", nil), 202, "")
	want(t, e.do("GET", "/v2/other/denied/blobs/"+d.String(), nil), 404, codeBlobUnknown)
}

// doom marks d as doomed by a running garbage-collection sweep and bumps
// the GC epoch, as a sweep's start batch does.
func (e *env) doom(d blob.Digest) {
	e.t.Helper()
	var b meta.Batch
	b.Put([]byte(gc.EpochKey), []byte{1})
	b.Put(gc.DoomedKey(d), []byte{1})
	if _, err := e.meta.Commit(context.Background(), &b); err != nil {
		e.t.Fatal(err)
	}
}

func TestMountOfDoomedBlobFallsBack(t *testing.T) {
	e := newEnv(t)
	d := e.pushBlob("hosted/src", []byte("doomed"))
	e.doom(d)
	want(t, e.do("POST", "/v2/hosted/dst/blobs/uploads/?mount="+d.String()+"&from=hosted/src", nil), 202, "")
	want(t, e.do("GET", "/v2/hosted/dst/blobs/"+d.String(), nil), 404, codeBlobUnknown)
}

func TestUploadOfDoomedBlobIsRetryable(t *testing.T) {
	e := newEnv(t)
	content := []byte("doomed content")
	d := blob.FromBytes(content)
	e.doom(d)
	w := e.do("POST", "/v2/hosted/app/blobs/uploads/?digest="+d.String(), content)
	want(t, w, 503, codeUnavailable)
	if w.Header().Get("Retry-After") == "" {
		t.Error("503 without Retry-After")
	}
	loc := e.startSession("hosted/app")
	want(t, e.do("PUT", loc+"?digest="+d.String(), content), 503, codeUnavailable)
	want(t, e.do("GET", loc, nil), 404, codeBlobUploadUnknown)
	if n := countUploads(t, e); n != 0 {
		t.Errorf("%d upload records left", n)
	}
}

// TestLinkEpochPrecondition starts a sweep (bumps the GC epoch) between a
// link's epoch read and its commit: the commit must fail and be retried
// from a fresh view, which sees the doomed entry if the sweep doomed it.
func TestLinkEpochPrecondition(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	rn := &repoName{full: "hosted/app", repo: "hosted", name: "app", cfg: e.h.repos["hosted"]}
	d := e.pushBlob("hosted/src", []byte("bytes"))
	bump := func(doom bool) {
		var b meta.Batch
		v := e.meta.View()
		epoch, _ := v.Get([]byte(gc.EpochKey))
		v.Release()
		b.Put([]byte(gc.EpochKey), []byte{byte(epoch.Version)})
		if doom {
			b.Put(gc.DoomedKey(d), []byte{1})
		}
		if _, err := e.meta.Commit(ctx, &b); err != nil {
			t.Fatal(err)
		}
	}
	build := func(v meta.View, b *meta.Batch) error {
		b.Put(blobKey(rn, d), encodeBlobLink(5))
		return nil
	}

	// A sweep that starts after the epoch read but does not doom the
	// digest: the commit fails once and the retry succeeds.
	var attempts []int
	err := e.h.commitLink(ctx, []blob.Digest{d}, build, func(attempt int) error {
		attempts = append(attempts, attempt)
		if attempt == 0 {
			bump(false)
		}
		return nil
	})
	if err != nil || len(attempts) != 2 {
		t.Fatalf("commitLink = %v after attempts %v, want success on the second", err, attempts)
	}

	// A sweep that dooms the digest: the retry sees it and fails.
	e.do("DELETE", "/v2/hosted/app/blobs/"+d.String(), nil)
	attempts = nil
	err = e.h.commitLink(ctx, []blob.Digest{d}, build, func(attempt int) error {
		attempts = append(attempts, attempt)
		if attempt == 0 {
			bump(true)
		}
		return nil
	})
	if err != errRetry || len(attempts) != 1 {
		t.Fatalf("commitLink = %v after attempts %v, want errRetry after one", err, attempts)
	}
	want(t, e.do("GET", "/v2/hosted/app/blobs/"+d.String(), nil), 404, codeBlobUnknown)

	// A link that keeps losing gives up with errRetry.
	other := blob.FromBytes([]byte("other"))
	err = e.h.commitLink(ctx, []blob.Digest{other}, build, func(int) error { bump(false); return nil })
	if err != errRetry {
		t.Fatalf("commitLink under constant sweeps = %v", err)
	}
}

// TestLinkOfSweptBlob retries a link whose blob was deleted meanwhile.
func TestLinkOfSweptBlob(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	d := blob.FromBytes([]byte("gone"))
	err := e.h.statExists(ctx, d)(1)
	if err != errRetry {
		t.Errorf("statExists of a missing blob = %v", err)
	}
	d = e.pushBlob("hosted/a", []byte("here"))
	if err := e.h.statExists(ctx, d)(1); err != nil {
		t.Errorf("statExists of a present blob = %v", err)
	}
}

func TestDeleteBlob(t *testing.T) {
	e := newEnv(t)
	d := e.pushBlob("hosted/app", []byte("to delete"))
	e.pushBlob("hosted/keep", []byte("to delete"))
	w := e.do("DELETE", "/v2/hosted/app/blobs/"+d.String(), nil)
	want(t, w, 202, "")
	want(t, e.do("GET", "/v2/hosted/app/blobs/"+d.String(), nil), 404, codeBlobUnknown)
	want(t, e.do("DELETE", "/v2/hosted/app/blobs/"+d.String(), nil), 404, codeBlobUnknown)
	want(t, e.do("DELETE", "/v2/hosted/app/blobs/sha256:bad", nil), 400, codeDigestInvalid)
	// Other names keep their link, and the bytes stay for them.
	want(t, e.do("GET", "/v2/hosted/keep/blobs/"+d.String(), nil), 200, "")
}

// TestLinkedBlobMissing serves 404 for a link whose blob is gone.
func TestLinkedBlobMissing(t *testing.T) {
	e := newEnv(t)
	d := e.pushBlob("hosted/app", []byte("vanishing"))
	if err := e.blobs.Delete(context.Background(), d); err != nil {
		t.Fatal(err)
	}
	want(t, e.do("GET", "/v2/hosted/app/blobs/"+d.String(), nil), 404, codeBlobUnknown)
}

func TestExpireUploads(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	old := e.startSession("hosted/app")
	e.now = e.now.Add(23 * time.Hour)
	recent := e.startSession("hosted/app")
	e.now = e.now.Add(2 * time.Hour)

	if err := e.h.ExpireUploads(ctx, UploadMaxAge); err != nil {
		t.Fatal(err)
	}
	want(t, e.do("GET", old, nil), 404, codeBlobUploadUnknown)
	want(t, e.do("GET", recent, nil), 204, "")
	if n := countUploads(t, e); n != 1 {
		t.Errorf("%d upload records, want 1", n)
	}

	// RunJanitor runs once at once and stops with its context.
	e.now = e.now.Add(48 * time.Hour)
	ctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { e.h.RunJanitor(ctx, time.Hour, UploadMaxAge); close(done) }()
	deadline := time.Now().Add(10 * time.Second)
	for countUploads(t, e) != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	cancel()
	<-done
	if n := countUploads(t, e); n != 0 {
		t.Errorf("janitor left %d upload records", n)
	}
}

func TestParseContentRange(t *testing.T) {
	tests := []struct {
		in         string
		start, end int64
		ok         bool
	}{
		{"0-0", 0, 0, true},
		{"5-9", 5, 9, true},
		{"bytes 5-9", 5, 9, true},
		{"bytes=5-9", 5, 9, true},
		{"9-5", 0, 0, false},
		{"-1-5", 0, 0, false},
		{"5", 0, 0, false},
		{"a-b", 0, 0, false},
	}
	for _, tt := range tests {
		s, en, ok := parseContentRange(tt.in)
		if s != tt.start || en != tt.end || ok != tt.ok {
			t.Errorf("parseContentRange(%q) = %d %d %v", tt.in, s, en, ok)
		}
	}
}

// failingBody fails after some bytes, like a client that disconnects.
type failingBody struct{ n int }

func (b *failingBody) Read(p []byte) (int, error) {
	if b.n == 0 {
		return 0, errors.New("connection reset")
	}
	k := min(len(p), b.n)
	for i := range k {
		p[i] = 'x'
	}
	b.n -= k
	return k, nil
}

// TestInterruptedChunk keeps the bytes received before a client went away,
// so the client can resume from the reported range.
func TestInterruptedChunk(t *testing.T) {
	e := newEnv(t)
	loc := e.startSession("hosted/app")
	r := httptest.NewRequest("PATCH", loc, &failingBody{n: 10})
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, r)
	want(t, w, 400, codeBlobUploadInvalid)
	w = e.do("GET", loc, nil)
	if w.Code != 204 || w.Header().Get("Range") != "0-9" {
		t.Errorf("after an interrupted chunk: %d Range %q", w.Code, w.Header().Get("Range"))
	}
}
