package oci

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/terrabyteian/flint/internal/blob"
	"github.com/terrabyteian/flint/internal/config"
	"github.com/terrabyteian/flint/internal/fsys"
	"github.com/terrabyteian/flint/internal/meta"
	"github.com/terrabyteian/flint/internal/metrics"
	"github.com/terrabyteian/flint/internal/upstream"
	"github.com/terrabyteian/flint/internal/upstream/upstreamtest"
)

// proxyEnv is a Handler with proxy repositories of a fake upstream:
// "hub" without a size limit and "small" with one, next to "hosted".
type proxyEnv struct {
	*env
	up   *upstreamtest.Registry
	fs   *fsys.Mem
	free atomic.Uint64 // free bytes the fake statfs reports; 1 GiB is the threshold

	mu    sync.Mutex
	clock time.Time
}

const (
	testWindow    = time.Minute
	testThreshold = 1 << 30
)

func newProxyEnv(t *testing.T, sizeLimit int64) *proxyEnv {
	t.Helper()
	pe := &proxyEnv{up: upstreamtest.New(t), fs: fsys.NewMem(), clock: time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)}
	pe.free.Store(100 << 30)
	ms, err := meta.Open("/data/meta", meta.Options{FS: pe.fs, Logger: quiet})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ms.Close() })
	bs, err := blob.NewFS("/data", blob.Options{FS: pe.fs})
	if err != nil {
		t.Fatal(err)
	}
	pe.env = &env{t: t, meta: ms, blobs: bs, auth: &catalogAuth{visible: func(string) bool { return true }}}
	pe.h = pe.newHandler(sizeLimit, nil)
	return pe
}

// newHandler builds a Handler over pe's stores, as a restart would.
func (pe *proxyEnv) newHandler(sizeLimit int64, mod func(*config.Proxy)) *Handler {
	pe.t.Helper()
	hub := &config.Proxy{URL: pe.up.URL, RevalidateAfter: config.Duration{Duration: testWindow}}
	if mod != nil {
		mod(hub)
	}
	small := &config.Proxy{URL: pe.up.URL, RevalidateAfter: config.Duration{Duration: testWindow},
		SizeLimit: config.ByteSize{Bytes: sizeLimit}}
	repos := []config.Repository{
		{Name: "hosted", Format: config.FormatOCI, Type: config.TypeHosted},
		{Name: "hub", Format: config.FormatOCI, Type: config.TypeProxy, Proxy: hub},
		{Name: "small", Format: config.FormatOCI, Type: config.TypeProxy, Proxy: small},
	}
	space := upstream.NewSpace(upstream.SpaceOptions{
		Path:    "/data",
		Statfs:  func(string) (uint64, uint64, error) { return pe.free.Load(), 1 << 40, nil },
		MinFree: func(uint64) uint64 { return testThreshold },
		Now:     pe.now,
		Logger:  quiet,
	})
	pe.reg = metrics.NewRegistry()
	h, err := New(Options{Meta: pe.meta, Blobs: pe.blobs, Repositories: repos, Authorizer: pe.auth,
		Logger: quiet, Metrics: pe.reg, Now: pe.now, Space: space,
		Upstream: upstream.Options{Attempts: 2, Backoff: time.Millisecond}})
	if err != nil {
		pe.t.Fatal(err)
	}
	return h
}

func (pe *proxyEnv) now() time.Time {
	pe.mu.Lock()
	defer pe.mu.Unlock()
	return pe.clock
}

func (pe *proxyEnv) advance(d time.Duration) {
	pe.mu.Lock()
	defer pe.mu.Unlock()
	pe.clock = pe.clock.Add(d)
}

// setFree sets the free space and lets the next check measure it.
func (pe *proxyEnv) setFree(n uint64) {
	pe.free.Store(n)
	pe.advance(2 * time.Second)
}

// metric returns the value of a sample line of the exposition, or "".
func (pe *proxyEnv) metric(sample string) string {
	var b bytes.Buffer
	pe.reg.WriteTo(&b)
	for line := range strings.SplitSeq(b.String(), "\n") {
		if v, ok := strings.CutPrefix(line, sample+" "); ok {
			return v
		}
	}
	return ""
}

// get serves a GET and checks a 200 with the wanted body.
func (pe *proxyEnv) get(path string, body []byte) *httptest.ResponseRecorder {
	pe.t.Helper()
	w := pe.do("GET", path, nil)
	want(pe.t, w, http.StatusOK, "")
	if !bytes.Equal(w.Body.Bytes(), body) {
		pe.t.Fatalf("GET %s: body %.100q, want %.100q", path, w.Body.Bytes(), body)
	}
	return w
}

// pull pulls an image by tag through the proxy, checking every byte.
func (pe *proxyEnv) pull(name, tag string, img upstreamtest.Image) {
	pe.t.Helper()
	w := pe.get("/v2/"+name+"/manifests/"+tag, img.Manifest)
	if got := w.Header().Get("Docker-Content-Digest"); got != img.Digest {
		pe.t.Fatalf("pulled manifest %s, want %s", got, img.Digest)
	}
	for _, d := range append([]string{img.Config}, img.Layers...) {
		pe.get("/v2/"+name+"/blobs/"+d, img.Blobs[d])
	}
	pe.settle()
}

// settle waits until the fetches in progress have linked their blobs.
func (pe *proxyEnv) settle() {
	pe.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for pe.h.fetcher.Active() > 0 {
		if time.Now().After(deadline) {
			pe.t.Fatal("fetches did not finish")
		}
		time.Sleep(time.Millisecond)
	}
}

func (pe *proxyEnv) linked(key []byte) bool {
	v := pe.meta.View()
	defer v.Release()
	_, ok := v.Get(key)
	return ok
}

func (pe *proxyEnv) rn(full string) *repoName {
	pe.t.Helper()
	rn, err := pe.h.resolve(full)
	if err != nil {
		pe.t.Fatal(err)
	}
	return rn
}

func digestOf(t *testing.T, s string) blob.Digest {
	t.Helper()
	d, err := blob.ParseDigest(s)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestProxyPullAndCache(t *testing.T) {
	pe := newProxyEnv(t, 0)
	img := pe.up.PutImage("library/app", "v1", []byte("layer one"), []byte("layer two"))
	pe.pull("hub/library/app", "v1", img)

	rn := pe.rn("hub/library/app")
	if !pe.linked(tagKey(rn, "v1")) || !pe.linked(manifestKey(rn, digestOf(t, img.Digest))) {
		t.Error("the tag or manifest was not cached")
	}
	for _, d := range img.Layers {
		if !pe.linked(blobKey(rn, digestOf(t, d))) {
			t.Errorf("layer %s was not cached", d)
		}
	}
	v := pe.meta.View()
	rec, _ := v.Get(manifestKey(rn, digestOf(t, img.Digest)))
	v.Release()
	m, err := decodeManifest(rec.Value)
	if err != nil || len(m.Refs) != 3 || m.MediaType != mtOCIManifest {
		t.Errorf("manifest record %+v, %v: want the config and two layers as references", m, err)
	}

	// Pulling again, also by digest, with HEAD, and with containerd's ns
	// parameter, is served from the cache.
	before := len(pe.up.Requests())
	pe.pull("hub/library/app", "v1", img)
	pe.get("/v2/hub/library/app/manifests/"+img.Digest, img.Manifest)
	pe.get("/v2/hub/library/app/manifests/v1?ns=docker.io", img.Manifest)
	pe.get("/v2/hub/library/app/blobs/"+img.Layers[0]+"?ns=docker.io", img.Blobs[img.Layers[0]])
	w := pe.do("HEAD", "/v2/hub/library/app/manifests/v1", nil)
	want(t, w, 200, "")
	if w.Header().Get("Content-Length") != strconv.Itoa(len(img.Manifest)) || w.Body.Len() != 0 {
		t.Errorf("HEAD: %v, body %d bytes", w.Header(), w.Body.Len())
	}
	if n := len(pe.up.Requests()) - before; n != 0 {
		t.Errorf("cached pulls sent %d upstream requests: %v", n, pe.up.Requests()[before:])
	}
	if got := pe.metric(`flint_proxy_requests_total{repository="hub",result="fetched"}`); got != "4" {
		t.Errorf("fetched = %s, want 4", got)
	}
	if got := pe.metric(`flint_proxy_upstream_bytes_total{repository="hub"}`); got == "" || got == "0" {
		t.Errorf("upstream bytes = %q", got)
	}

	// A range request of a cached blob is served from the store.
	w = pe.do("GET", "/v2/hub/library/app/blobs/"+img.Layers[0], nil, "Range", "bytes=6-")
	want(t, w, http.StatusPartialContent, "")
	if w.Body.String() != "one" {
		t.Errorf("range body %q", w.Body)
	}

	// Content the upstream does not have is unknown.
	want(t, pe.do("GET", "/v2/hub/library/app/manifests/v2", nil), 404, codeManifestUnknown)
	want(t, pe.do("GET", "/v2/hub/library/nope/manifests/v1", nil), 404, codeManifestUnknown)
	want(t, pe.do("GET", "/v2/hub/library/app/blobs/"+blob.FromBytes([]byte("no")).String(), nil), 404, codeBlobUnknown)
	want(t, pe.do("GET", "/v2/hub/library/app/manifests/"+blob.FromBytes([]byte("no")).String(), nil), 404, codeManifestUnknown)
	want(t, pe.do("GET", "/v2/hub/library/app/manifests/bad~tag", nil), 404, codeManifestUnknown)
	want(t, pe.do("GET", "/v2/hub/library/app/blobs/sha256:short", nil), 400, codeDigestInvalid)
	if got := pe.metric(`flint_proxy_upstream_errors_total{repository="hub"}`); got != "" && got != "0" {
		t.Errorf("not-found answers counted as upstream errors: %s", got)
	}
}

func TestProxyIndex(t *testing.T) {
	pe := newProxyEnv(t, 0)
	amd := pe.up.PutImage("multi", "", []byte("amd64"))
	arm := pe.up.PutImage("multi", "", []byte("arm64"))
	index := mustJSON(map[string]any{
		"schemaVersion": 2,
		"mediaType":     mtOCIIndex,
		"manifests": []any{
			map[string]any{"mediaType": mtOCIManifest, "digest": amd.Digest, "size": len(amd.Manifest),
				"platform": map[string]string{"os": "linux", "architecture": "amd64"}},
			map[string]any{"mediaType": mtOCIManifest, "digest": arm.Digest, "size": len(arm.Manifest),
				"platform": map[string]string{"os": "linux", "architecture": "arm64"}},
		},
	})
	id := pe.up.PutManifest("multi", "latest", mtOCIIndex, index)
	w := pe.get("/v2/hub/multi/manifests/latest", index)
	if w.Header().Get("Content-Type") != mtOCIIndex {
		t.Errorf("Content-Type %q", w.Header().Get("Content-Type"))
	}
	// A client picks a platform and pulls its manifest by digest.
	pe.pull("hub/multi", arm.Digest, arm)
	rn := pe.rn("hub/multi")
	v := pe.meta.View()
	m, err := cachedManifest(v, rn, digestOf(t, id))
	v.Release()
	if err != nil || m == nil || len(m.Refs) != 2 || m.Refs[0].Kind != refManifest {
		t.Errorf("index record %+v, %v", m, err)
	}
	// A client that does not accept indexes is told so, as for hosted.
	want(t, pe.do("GET", "/v2/hub/multi/manifests/latest", nil, "Accept", mtDockerManifest), 404, codeManifestUnknown)
}

func TestProxyRevalidation(t *testing.T) {
	pe := newProxyEnv(t, 0)
	img := pe.up.PutImage("app", "v1", []byte("x"))
	pe.get("/v2/hub/app/manifests/v1", img.Manifest)
	heads, gets := pe.up.Count("HEAD", "/manifests/v1"), pe.up.Count("GET", "/manifests/v1")

	// Within the window the tag is not checked.
	pe.advance(testWindow - time.Second)
	pe.get("/v2/hub/app/manifests/v1", img.Manifest)
	if pe.up.Count("HEAD", "/manifests/v1") != heads {
		t.Error("the tag was revalidated within the window")
	}
	// After it, a HEAD confirms the tag, and nothing is fetched again.
	pe.advance(2 * time.Second)
	pe.get("/v2/hub/app/manifests/v1", img.Manifest)
	if pe.up.Count("HEAD", "/manifests/v1") != heads+1 || pe.up.Count("GET", "/manifests/v1") != gets {
		t.Errorf("revalidation sent %d HEADs and %d GETs, want 1 and 0",
			pe.up.Count("HEAD", "/manifests/v1")-heads, pe.up.Count("GET", "/manifests/v1")-gets)
	}
	if got := pe.metric(`flint_proxy_requests_total{repository="hub",result="revalidated"}`); got != "1" {
		t.Errorf("revalidated = %q, want 1", got)
	}
	// The confirmation starts a new window.
	pe.get("/v2/hub/app/manifests/v1", img.Manifest)
	if pe.up.Count("HEAD", "/manifests/v1") != heads+1 {
		t.Error("revalidated again right after a confirmation")
	}

	// The tag moves upstream: after the window, the new manifest is
	// fetched and served.
	img2 := pe.up.PutImage("app", "v1", []byte("y"))
	pe.get("/v2/hub/app/manifests/v1", img.Manifest) // still within the window
	pe.advance(testWindow)
	pe.pull("hub/app", "v1", img2)
	if pe.up.Count("GET", "/manifests/v1") != gets+1 {
		t.Errorf("fetched the moved tag %d times", pe.up.Count("GET", "/manifests/v1")-gets)
	}
	// The old manifest stays cached by digest.
	pe.get("/v2/hub/app/manifests/"+img.Digest, img.Manifest)

	// An upstream that reports no digest on HEAD is asked with GET.
	pe.up.NoHeadDigest = true
	pe.advance(testWindow)
	gets = pe.up.Count("GET", "/manifests/v1")
	pe.get("/v2/hub/app/manifests/v1", img2.Manifest)
	if pe.up.Count("GET", "/manifests/v1") != gets+1 {
		t.Error("without a HEAD digest, the tag was not fetched")
	}
}

func TestProxyConcurrentRevalidation(t *testing.T) {
	pe := newProxyEnv(t, 0)
	img := pe.up.PutImage("app", "v1", []byte("x"))
	pe.get("/v2/hub/app/manifests/v1", img.Manifest)
	pe.advance(testWindow)
	heads := pe.up.Count("HEAD", "/manifests/v1")
	var wg sync.WaitGroup
	for range 10 {
		wg.Go(func() {
			w := pe.do("GET", "/v2/hub/app/manifests/v1", nil)
			if w.Code != 200 {
				t.Errorf("status %d", w.Code)
			}
		})
	}
	wg.Wait()
	if n := pe.up.Count("HEAD", "/manifests/v1") - heads; n < 1 || n > 2 {
		t.Errorf("10 concurrent pulls of a stale tag sent %d HEADs", n)
	}
}

func TestProxyOutage(t *testing.T) {
	pe := newProxyEnv(t, 0)
	img := pe.up.PutImage("app", "v1", []byte("x"))
	other := pe.up.PutImage("app", "v2", []byte("y"))
	pe.pull("hub/app", "v1", img)

	pe.up.SetDown(true)
	pe.advance(testWindow)
	// The cached tag, manifest, and blobs keep being served.
	pe.pull("hub/app", "v1", img)
	if got := pe.metric(`flint_proxy_requests_total{repository="hub",result="stale"}`); got != "1" {
		t.Errorf("stale = %q, want 1", got)
	}
	// The upstream is now marked offline, so the next pull does not wait
	// on it.
	before := len(pe.up.Requests())
	pe.get("/v2/hub/app/manifests/v1", img.Manifest)
	if n := len(pe.up.Requests()) - before; n != 0 {
		t.Errorf("a pull while offline sent %d upstream requests", n)
	}
	// Content that is not cached cannot be served.
	want(t, pe.do("GET", "/v2/hub/app/manifests/v2", nil), 503, codeUnavailable)
	want(t, pe.do("GET", "/v2/hub/app/blobs/"+other.Layers[0], nil), 503, codeUnavailable)
	// Listings fall back to what is cached.
	w := pe.do("GET", "/v2/hub/app/tags/list", nil)
	want(t, w, 200, "")
	if !strings.Contains(w.Body.String(), `"tags":["v1"]`) {
		t.Errorf("tags while down: %s", w.Body)
	}

	// Back up, the tag is confirmed again.
	pe.up.SetDown(false)
	pe.advance(time.Hour)
	pe.pull("hub/app", "v2", other)

	// A tag the upstream fails to answer keeps being served from the
	// cache, and so does a rate-limited one.
	for _, status := range []int{http.StatusInternalServerError, http.StatusTooManyRequests} {
		pe.up.SetStatus(func(r *http.Request) int {
			if r.Method == http.MethodHead {
				return status
			}
			return 0
		})
		pe.advance(time.Hour)
		pe.get("/v2/hub/app/manifests/v2", other.Manifest)
	}
	pe.up.SetStatus(nil)

	// A tag deleted upstream is not found, although it is cached; its
	// manifest stays cached by digest.
	pe.up.DeleteTag("app", "v1")
	pe.advance(time.Hour)
	want(t, pe.do("GET", "/v2/hub/app/manifests/v1", nil), 404, codeManifestUnknown)
	want(t, pe.do("HEAD", "/v2/hub/app/manifests/v1", nil), 404, "")
	pe.get("/v2/hub/app/manifests/"+img.Digest, img.Manifest)
	// So is one the upstream denies access to.
	pe.up.SetStatus(func(r *http.Request) int {
		if strings.Contains(r.URL.Path, "/manifests/") {
			return http.StatusForbidden
		}
		return 0
	})
	pe.advance(testWindow)
	want(t, pe.do("GET", "/v2/hub/app/manifests/v2", nil), 404, codeManifestUnknown)
	pe.get("/v2/hub/app/manifests/"+other.Digest, other.Manifest)
}

// TestProxyStalledUpstream checks that an upstream that accepts requests
// but never answers counts as unavailable once the proxy's own timeouts
// pass: a cached tag is served stale, uncached content is answered 503,
// the failures are counted, and the upstream is marked offline.
func TestProxyStalledUpstream(t *testing.T) {
	defer func(f, r time.Duration) { fetchTimeout, revalidateTimeout = f, r }(fetchTimeout, revalidateTimeout)
	fetchTimeout, revalidateTimeout = 200*time.Millisecond, 100*time.Millisecond
	pe := newProxyEnv(t, 0)
	pe.h.fetcher = upstream.NewFetcher(pe.blobs, 100*time.Millisecond)
	img := pe.up.PutImage("app", "v1", []byte("x"))
	other := pe.up.PutImage("app", "v2", []byte("y"))
	pe.pull("hub/app", "v1", img)

	pe.up.SetStatus(func(r *http.Request) int {
		<-r.Context().Done()
		return 0
	})
	pe.advance(testWindow)
	pe.get("/v2/hub/app/manifests/v1", img.Manifest)
	if got := pe.metric(`flint_proxy_requests_total{repository="hub",result="stale"}`); got != "1" {
		t.Errorf("stale = %q, want 1", got)
	}
	if !pe.h.repos["hub"].proxy.client.Offline() {
		t.Error("a stalled revalidation did not mark the upstream offline")
	}
	want(t, pe.do("GET", "/v2/hub/app/manifests/v2", nil), 503, codeUnavailable)
	want(t, pe.do("GET", "/v2/hub/app/manifests/"+other.Digest, nil), 503, codeUnavailable)
	want(t, pe.do("GET", "/v2/hub/app/blobs/"+other.Layers[0], nil), 503, codeUnavailable)
	pe.settle()
	if got := pe.metric(`flint_proxy_upstream_errors_total{repository="hub"}`); got != "5" {
		t.Errorf("upstream errors = %q, want 5", got)
	}
}

// server serves pe's handler over HTTP, so a response a handler aborts
// reaches the client as a broken connection.
func (pe *proxyEnv) server() *httptest.Server {
	srv := httptest.NewServer(pe.h)
	pe.t.Cleanup(srv.Close)
	return srv
}

func TestProxyDigestMismatch(t *testing.T) {
	pe := newProxyEnv(t, 0)
	layer := bytes.Repeat([]byte("L"), 200000)
	img := pe.up.PutImage("app", "v1", layer)
	pe.up.Corrupt(img.Layers[0])
	srv := pe.server()

	resp, err := http.Get(srv.URL + "/v2/hub/app/blobs/" + img.Layers[0])
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err == nil || len(got) >= len(layer) {
		t.Fatalf("a corrupt blob was delivered whole: %d bytes, %v", len(got), err)
	}
	d := digestOf(t, img.Layers[0])
	if _, err := pe.blobs.Stat(context.Background(), d); err == nil {
		t.Error("the corrupt blob was stored")
	}
	if pe.linked(blobKey(pe.rn("hub/app"), d)) {
		t.Error("the corrupt blob was linked")
	}
	if got := pe.metric(`flint_proxy_upstream_errors_total{repository="hub"}`); got != "1" {
		t.Errorf("upstream errors = %q, want 1", got)
	}

	// A corrupt manifest is refused.
	pe.up.Corrupt(img.Digest)
	want(t, pe.do("GET", "/v2/hub/app/manifests/v1", nil), 502, codeUnknown)
	want(t, pe.do("GET", "/v2/hub/app/manifests/"+img.Digest, nil), 502, codeUnknown)
}

func TestProxyConcurrentFetch(t *testing.T) {
	pe := newProxyEnv(t, 0)
	layer := bytes.Repeat([]byte("0123456789"), 50000)
	img := pe.up.PutImage("app", "v1", layer)
	pe.get("/v2/hub/app/manifests/v1", img.Manifest) // fetches the token
	release := pe.up.Stall(img.Layers[0])
	srv := pe.server()

	const clients = 6
	var wg sync.WaitGroup
	results := make(chan []byte, clients)
	for range clients {
		wg.Go(func() {
			resp, err := http.Get(srv.URL + "/v2/hub/app/blobs/" + img.Layers[0])
			if err != nil {
				t.Error(err)
				return
			}
			defer resp.Body.Close()
			if resp.ContentLength != int64(len(layer)) {
				t.Errorf("Content-Length %d", resp.ContentLength)
			}
			b, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Error(err)
			}
			results <- b
		})
	}
	// Every client is waiting on the one stalled upstream request.
	deadline := time.Now().Add(5 * time.Second)
	for pe.metric("flint_http_requests_in_flight") == "" && time.Now().Before(deadline) {
		if pe.up.Count("GET", "/blobs/"+img.Layers[0]) >= 1 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond)
	release()
	wg.Wait()
	close(results)
	for b := range results {
		if !bytes.Equal(b, layer) {
			t.Errorf("a client received %d bytes", len(b))
		}
	}
	if n := pe.up.Count("GET", "/blobs/"+img.Layers[0]); n != 1 {
		t.Errorf("%d concurrent pulls sent %d upstream requests for the blob, want 1", clients, n)
	}
	// The fetch linked the blob for later pulls.
	deadline = time.Now().Add(5 * time.Second)
	for !pe.linked(blobKey(pe.rn("hub/app"), digestOf(t, img.Layers[0]))) {
		if time.Now().After(deadline) {
			t.Fatal("the fetched blob was not linked")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestProxyDiskPressure(t *testing.T) {
	pe := newProxyEnv(t, 0)
	img := pe.up.PutImage("app", "v1", []byte("layer"))
	pe.setFree(testThreshold - 1)

	pe.pull("hub/app", "v1", img)
	rn := pe.rn("hub/app")
	if pe.linked(tagKey(rn, "v1")) || pe.linked(manifestKey(rn, digestOf(t, img.Digest))) ||
		pe.linked(blobKey(rn, digestOf(t, img.Layers[0]))) {
		t.Error("content was cached while the disk was nearly full")
	}
	if _, err := pe.blobs.Stat(context.Background(), digestOf(t, img.Layers[0])); err == nil {
		t.Error("a blob was stored while the disk was nearly full")
	}
	if got := pe.metric(`flint_proxy_requests_total{repository="hub",result="passthrough"}`); got != "3" {
		t.Errorf("passthrough = %q, want 3", got)
	}
	if got := pe.metric("flint_proxy_disk_pressure"); got != "1" {
		t.Errorf("flint_proxy_disk_pressure = %q, want 1", got)
	}

	// A blob that would cross the threshold is passed through too.
	big := pe.up.PutImage("app", "big", bytes.Repeat([]byte("b"), 1000))
	pe.setFree(testThreshold + 500)
	pe.get("/v2/hub/app/blobs/"+big.Layers[0], big.Blobs[big.Layers[0]])
	pe.settle()
	if pe.linked(blobKey(rn, digestOf(t, big.Layers[0]))) {
		t.Error("a blob that does not fit was cached")
	}
	if got := pe.metric("flint_proxy_disk_pressure"); got != "0" {
		t.Errorf("flint_proxy_disk_pressure = %q, want 0 with room for small content", got)
	}

	// A corrupt blob passed through is cut off.
	bad := pe.up.PutImage("app", "bad", bytes.Repeat([]byte("c"), 200000))
	pe.up.Corrupt(bad.Layers[0])
	pe.setFree(0)
	resp, err := http.Get(pe.server().URL + "/v2/hub/app/blobs/" + bad.Layers[0])
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err == nil || len(got) >= 200000 {
		t.Errorf("a corrupt passed-through blob was delivered whole: %d bytes, %v", len(got), err)
	}

	// With space again, content is cached.
	pe.setFree(100 << 30)
	pe.pull("hub/app", "v1", img)
	if !pe.linked(tagKey(rn, "v1")) || !pe.linked(blobKey(rn, digestOf(t, img.Layers[0]))) {
		t.Error("content was not cached once there was space")
	}
}

func TestProxySizeLimit(t *testing.T) {
	pe := newProxyEnv(t, 2500)
	var layers []string
	var data [][]byte
	for _, s := range []string{"a", "b", "c"} {
		b := bytes.Repeat([]byte(s), 1000)
		data = append(data, b)
		layers = append(layers, pe.up.PutBlob("app", b))
	}
	for i, d := range layers {
		pe.get("/v2/small/app/blobs/"+d, data[i])
		pe.settle()
		pe.advance(time.Minute)
	}
	// Pulling "a" again makes "b" the least recently pulled.
	pe.get("/v2/small/app/blobs/"+layers[0], data[0])
	select {
	case <-pe.h.evictKick:
	default:
		t.Error("going over the limit did not ask for an eviction")
	}
	if err := pe.h.Evict(context.Background()); err != nil {
		t.Fatal(err)
	}
	rn := pe.rn("small/app")
	for i, wantLinked := range []bool{true, false, true} {
		if got := pe.linked(blobKey(rn, digestOf(t, layers[i]))); got != wantLinked {
			t.Errorf("blob %d linked = %v, want %v", i, got, wantLinked)
		}
	}
	if got := pe.metric(`flint_proxy_evictions_total{repository="small"}`); got != "1" {
		t.Errorf("evictions = %q, want 1", got)
	}
	if got := pe.metric(`flint_proxy_cached_bytes{repository="small"}`); got != "2000" {
		t.Errorf("cached bytes = %q, want 2000", got)
	}
	// An evicted blob is fetched again on its next pull.
	pe.get("/v2/small/app/blobs/"+layers[1], data[1])

	// A blob larger than the limit is passed through.
	huge := bytes.Repeat([]byte("h"), 3000)
	hd := pe.up.PutBlob("app", huge)
	pe.get("/v2/small/app/blobs/"+hd, huge)
	pe.settle()
	if pe.linked(blobKey(rn, digestOf(t, hd))) {
		t.Error("a blob over the size limit was cached")
	}
	// The repository without a limit tracks nothing.
	pe.get("/v2/hub/app/blobs/"+hd, huge)
	if pe.h.repos["hub"].proxy.cache != nil {
		t.Error("a repository without a size limit has a tracker")
	}
}

func TestProxySizeLimitPersistence(t *testing.T) {
	pe := newProxyEnv(t, 10000)
	img := pe.up.PutImage("app", "v1", bytes.Repeat([]byte("1"), 1000))
	old := pe.up.PutImage("old", "v1", bytes.Repeat([]byte("2"), 1000))
	pe.pull("small/old", "v1", old)
	pe.advance(time.Hour)
	pe.pull("small/app", "v1", img)
	if err := pe.h.FlushPullTimes(context.Background()); err != nil {
		t.Fatal(err)
	}
	// The pull times survive a restart, which loads the cached items; a
	// lower limit then evicts the older image first, tags included.
	h := pe.newHandler(1500, nil)
	if got := h.repos["small"].proxy.cache.size(); got != pe.h.repos["small"].proxy.cache.size() {
		t.Errorf("reloaded size %d, want %d", got, pe.h.repos["small"].proxy.cache.size())
	}
	select {
	case <-h.evictKick:
	default:
		t.Error("starting over the limit did not ask for an eviction")
	}
	pe.h = h
	if err := h.Evict(context.Background()); err != nil {
		t.Fatal(err)
	}
	oldRN, appRN := pe.rn("small/old"), pe.rn("small/app")
	if pe.linked(tagKey(oldRN, "v1")) || pe.linked(manifestKey(oldRN, digestOf(t, old.Digest))) ||
		pe.linked(blobKey(oldRN, digestOf(t, old.Layers[0]))) {
		t.Error("the least recently pulled image was not evicted")
	}
	if !pe.linked(tagKey(appRN, "v1")) || !pe.linked(blobKey(appRN, digestOf(t, img.Layers[0]))) {
		t.Error("the recently pulled image was evicted")
	}
	v := pe.meta.View()
	n := 0
	v.Scan([]byte(nsPulled), nil, func([]byte, meta.Record) bool { n++; return true })
	v.Release()
	if n != 3 { // the remaining manifest, config, and layer
		t.Errorf("%d pull times persisted, want 3", n)
	}
}

func TestProxyReadOnly(t *testing.T) {
	pe := newProxyEnv(t, 0)
	d := blob.FromBytes(nil).String()
	for _, tt := range []struct{ method, path, allow string }{
		{"POST", "/v2/hub/app/blobs/uploads/", ""},
		{"POST", "/v2/hub/app/blobs/uploads/?digest=" + d, ""},
		{"PATCH", "/v2/hub/app/blobs/uploads/x", ""},
		{"PUT", "/v2/hub/app/blobs/uploads/x", ""},
		{"PUT", "/v2/hub/app/manifests/v1", "GET, HEAD"},
		{"DELETE", "/v2/hub/app/manifests/v1", "GET, HEAD"},
		{"DELETE", "/v2/hub/app/blobs/" + d, "GET, HEAD"},
	} {
		w := pe.do(tt.method, tt.path, []byte("x"))
		want(t, w, 405, codeUnsupported)
		if !strings.Contains(w.Body.String(), "read-only proxy") {
			t.Errorf("%s %s: %s", tt.method, tt.path, w.Body)
		}
		if got, ok := w.Header()["Allow"]; !ok || got[0] != tt.allow {
			t.Errorf("%s %s: Allow = %q, want %q", tt.method, tt.path, got, tt.allow)
		}
	}
	want(t, pe.do("DELETE", "/v2/hub/app/tags/list", nil), 405, codeUnsupported)
	if calls := pe.auth.reset(); len(calls) != 0 {
		t.Errorf("refused writes consulted the authorizer: %v", calls)
	}
	if len(pe.up.Requests()) != 0 {
		t.Error("refused writes reached the upstream")
	}
}

func TestProxyAuthorization(t *testing.T) {
	pe := newProxyEnv(t, 0)
	img := pe.up.PutImage("app", "v1")
	pe.auth.deny = func(string, []string) bool { return true }
	for _, p := range []string{"manifests/v1", "blobs/" + img.Config, "tags/list", "referrers/" + img.Digest} {
		w := pe.do("GET", "/v2/hub/app/"+p, nil)
		if w.Code != 401 {
			t.Errorf("GET %s denied: status %d", p, w.Code)
		}
		if calls := pe.auth.reset(); !slices.Equal(calls, []authCall{{"hub/app", "pull"}}) {
			t.Errorf("GET %s authorized as %v", p, calls)
		}
	}
	if len(pe.up.Requests()) != 0 {
		t.Error("denied requests reached the upstream")
	}
}

func TestProxyBlobStoredForAnotherRepository(t *testing.T) {
	pe := newProxyEnv(t, 0)
	secret := []byte("pushed to a hosted repository")
	d := pe.pushBlob("hosted/private", secret)
	// The upstream does not have it: knowing the digest does not reveal it.
	want(t, pe.do("GET", "/v2/hub/app/blobs/"+d.String(), nil), 404, codeBlobUnknown)
	want(t, pe.do("HEAD", "/v2/hub/app/blobs/"+d.String(), nil), 404, "")
	if pe.linked(blobKey(pe.rn("hub/app"), d)) {
		t.Error("a blob the upstream does not have was linked")
	}
	// Once the upstream has it, it is linked without being downloaded.
	pe.up.PutBlob("app", secret)
	pe.get("/v2/hub/app/blobs/"+d.String(), secret)
	if n := pe.up.Count("GET", "/blobs/"); n != 0 {
		t.Errorf("%d upstream blob GETs, want 0", n)
	}
	if !pe.linked(blobKey(pe.rn("hub/app"), d)) {
		t.Error("the confirmed blob was not linked")
	}
}

func TestProxyHeadBlob(t *testing.T) {
	pe := newProxyEnv(t, 0)
	img := pe.up.PutImage("app", "v1", []byte("some layer"))
	w := pe.do("HEAD", "/v2/hub/app/blobs/"+img.Layers[0], nil)
	want(t, w, 200, "")
	if w.Header().Get("Content-Length") != "10" || w.Header().Get("Docker-Content-Digest") != img.Layers[0] {
		t.Errorf("HEAD headers %v", w.Header())
	}
	if pe.up.Count("GET", "/blobs/") != 0 || pe.linked(blobKey(pe.rn("hub/app"), digestOf(t, img.Layers[0]))) {
		t.Error("HEAD fetched or linked the blob")
	}
	want(t, pe.do("HEAD", "/v2/hub/app/blobs/"+blob.FromBytes([]byte("x")).String(), nil), 404, "")
}

func TestProxyTagList(t *testing.T) {
	pe := newProxyEnv(t, 0)
	for _, tag := range []string{"a", "b", "c"} {
		pe.up.PutImage("library/app", tag)
	}
	w := pe.get("/v2/hub/library/app/tags/list?n=2", []byte(`{"name":"hub/library/app","tags":["a","b"]}`))
	if got := w.Header().Get("Link"); got != `</v2/hub/library/app/tags/list?last=b&n=2>; rel="next"` {
		t.Errorf("Link = %q", got)
	}
	pe.get("/v2/hub/library/app/tags/list?last=b&n=2", []byte(`{"name":"hub/library/app","tags":["c"]}`))
	// Cached for the window.
	pe.up.PutImage("library/app", "d")
	before := pe.up.Count("GET", "/tags/list")
	pe.get("/v2/hub/library/app/tags/list?n=2", []byte(`{"name":"hub/library/app","tags":["a","b"]}`))
	if pe.up.Count("GET", "/tags/list") != before {
		t.Error("a fresh listing was fetched again")
	}
	pe.advance(testWindow)
	pe.get("/v2/hub/library/app/tags/list", []byte(`{"name":"hub/library/app","tags":["a","b","c","d"]}`))
	// Down, the last listing is served.
	pe.up.SetDown(true)
	pe.advance(testWindow)
	pe.get("/v2/hub/library/app/tags/list", []byte(`{"name":"hub/library/app","tags":["a","b","c","d"]}`))
	// A name the upstream does not have, with nothing cached, is unknown.
	pe.up.SetDown(false)
	pe.advance(time.Hour)
	want(t, pe.do("GET", "/v2/hub/nope/tags/list", nil), 404, codeNameUnknown)
	// So is one the upstream no longer has, or denies, although its
	// tags are cached.
	pe.pull("hub/library/app", "a", pe.up.PutImage("library/app", "a"))
	for _, status := range []int{http.StatusNotFound, http.StatusForbidden} {
		pe.up.SetStatus(func(r *http.Request) int {
			if strings.HasSuffix(r.URL.Path, "/tags/list") {
				return status
			}
			return 0
		})
		pe.advance(testWindow)
		want(t, pe.do("GET", "/v2/hub/library/app/tags/list", nil), 404, codeNameUnknown)
	}
	want(t, pe.do("GET", "/v2/hub/library/app/tags/list?n=x", nil), 400, "PAGINATION_NUMBER_INVALID")
}

func TestProxyReferrers(t *testing.T) {
	pe := newProxyEnv(t, 0)
	img := pe.up.PutImage("app", "v1")
	sig := mustJSON(map[string]any{
		"schemaVersion": 2,
		"mediaType":     mtOCIManifest,
		"artifactType":  "application/vnd.example.sig",
		"config":        desc("application/vnd.oci.empty.v1+json", []byte("{}")),
		"layers":        []any{},
		"subject":       map[string]any{"mediaType": mtOCIManifest, "digest": img.Digest, "size": len(img.Manifest)},
	})
	pe.up.PutBlob("app", []byte("{}"))
	sd := pe.up.PutManifest("app", "", mtOCIManifest, sig)

	// Without upstream support, the cached referrers are listed: none yet,
	// then the signature once it is pulled.
	w := pe.do("GET", "/v2/hub/app/referrers/"+img.Digest, nil)
	want(t, w, 200, "")
	if !strings.Contains(w.Body.String(), `"manifests":[]`) {
		t.Errorf("referrers: %s", w.Body)
	}
	pe.get("/v2/hub/app/manifests/"+sd, sig)
	pe.advance(testWindow)
	w = pe.do("GET", "/v2/hub/app/referrers/"+img.Digest, nil)
	if !strings.Contains(w.Body.String(), sd) {
		t.Errorf("cached referrers do not list the signature: %s", w.Body)
	}

	// With upstream support, the upstream's index is served.
	pe.up.Referrers = true
	other := pe.up.PutImage("app", "v2")
	w = pe.do("GET", "/v2/hub/app/referrers/"+other.Digest+"?artifactType=x", nil)
	want(t, w, 200, "")
	if w.Header().Get("Content-Type") != mtOCIIndex || !strings.Contains(w.Body.String(), `"manifests":[]`) {
		t.Errorf("upstream referrers: %v %s", w.Header(), w.Body)
	}
	if pe.up.Count("GET", "/referrers/"+other.Digest) == 0 {
		t.Error("the upstream's referrers API was not asked")
	}
	want(t, pe.do("GET", "/v2/hub/app/referrers/sha256:x", nil), 400, codeDigestInvalid)
}

func TestProxyCredentials(t *testing.T) {
	pe := newProxyEnv(t, 0)
	pe.up.Username, pe.up.Password = "bot", "token-value"
	img := pe.up.PutImage("private/app", "v1", []byte("x"))
	want(t, pe.do("GET", "/v2/hub/private/app/manifests/v1", nil), 404, codeManifestUnknown)

	pw := filepath.Join(t.TempDir(), "password")
	if err := os.WriteFile(pw, []byte("token-value\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	pe.h = pe.newHandler(0, func(p *config.Proxy) { p.Username, p.PasswordFile = "bot", pw })
	pe.pull("hub/private/app", "v1", img)

	// A missing password file fails startup.
	h, err := New(Options{Meta: pe.meta, Blobs: pe.blobs, Authorizer: pe.auth, Logger: quiet,
		Repositories: []config.Repository{{Name: "p", Format: config.FormatOCI, Type: config.TypeProxy,
			Proxy: &config.Proxy{URL: pe.up.URL, Username: "bot", PasswordFile: pw + ".missing"}}}})
	if err == nil {
		t.Errorf("New with a missing password file = %v", h)
	}
}

func TestDockerHubNames(t *testing.T) {
	for _, tc := range []struct {
		url       string
		dockerHub bool
		base      string
	}{
		{"https://registry-1.docker.io", true, "https://registry-1.docker.io"},
		{"https://docker.io", false, "https://docker.io"},
		{"https://index.docker.io", false, "https://index.docker.io"},
		{"https://ghcr.io", false, "https://ghcr.io"},
		{"http://localhost:5000", false, "http://localhost:5000"},
	} {
		p, err := newProxyRepo(config.Repository{Name: "p", Proxy: &config.Proxy{URL: tc.url}}, upstream.Options{Logger: quiet})
		if err != nil {
			t.Fatal(err)
		}
		if p.dockerHub != tc.dockerHub || p.client.URL() != tc.base || p.revalidate != config.DefaultRevalidateAfter {
			t.Errorf("%s: dockerHub %v, URL %s, revalidate %v", tc.url, p.dockerHub, p.client.URL(), p.revalidate)
		}
		wantName := "nginx"
		if tc.dockerHub {
			wantName = "library/nginx"
		}
		if got := p.upstreamName("nginx"); got != wantName {
			t.Errorf("%s: upstreamName(nginx) = %s, want %s", tc.url, got, wantName)
		}
		if got := p.upstreamName("bitnami/redis"); got != "bitnami/redis" {
			t.Errorf("%s: upstreamName(bitnami/redis) = %s", tc.url, got)
		}
	}
}

func TestProxyDockerHubLibraryPrefix(t *testing.T) {
	pe := newProxyEnv(t, 0)
	img := pe.up.PutImage("library/nginx", "latest", []byte("x"))
	pe.h.repos["hub"].proxy.dockerHub = true
	// Docker clients send "nginx" for an official image; the proxy asks
	// the upstream for library/nginx.
	pe.pull("hub/nginx", "latest", img)
	if pe.up.Count("GET", "/v2/library/nginx/manifests/latest") == 0 {
		t.Errorf("upstream requests: %v", pe.up.Requests())
	}
}

func TestRunProxy(t *testing.T) {
	pe := newProxyEnv(t, 1500)
	a := bytes.Repeat([]byte("a"), 1000)
	b := bytes.Repeat([]byte("b"), 1000)
	ad, bd := pe.up.PutBlob("app", a), pe.up.PutBlob("app", b)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { pe.h.RunProxy(ctx); close(done) }()
	pe.get("/v2/small/app/blobs/"+ad, a)
	pe.settle()
	pe.advance(time.Minute)
	pe.get("/v2/small/app/blobs/"+bd, b)
	// RunProxy evicts in the background.
	rn := pe.rn("small/app")
	deadline := time.Now().Add(5 * time.Second)
	for pe.linked(blobKey(rn, digestOf(t, ad))) {
		if time.Now().After(deadline) {
			t.Fatal("the background eviction did not run")
		}
		time.Sleep(time.Millisecond)
	}
	// Stopping it persists the pull times.
	cancel()
	<-done
	if !pe.linked(pulledKey(blobKey(rn, digestOf(t, bd)))) {
		t.Error("the pull times were not persisted on stop")
	}
}
