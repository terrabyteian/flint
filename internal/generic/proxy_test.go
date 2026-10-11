package generic

import (
	"net/http"
	"strings"
	"testing"
)

// TestProxyRevalidated checks a proxy repository without
// generic.immutable: a file is cached as a document, served from the
// cache within the revalidation window, revalidated after it, refetched
// when it changed, and served from the cache while the upstream cannot
// be reached.
func TestProxyRevalidated(t *testing.T) {
	e := newEnv(t)
	e.up.set("/dl/tool/v1/tool.sh", content(1))
	w := e.expect(http.StatusOK, "GET", "/generic/remote/tool/v1/tool.sh", nil)
	if w.Body.String() != string(content(1)) || w.Header().Get("Content-Type") != "application/x-test" {
		t.Errorf("first fetch: %q, Content-Type %q", w.Body, w.Header().Get("Content-Type"))
	}
	if got := w.Header().Get("Content-Security-Policy"); got != "sandbox" {
		t.Errorf("Content-Security-Policy = %q", got)
	}
	e.get(http.StatusOK, "/generic/remote/tool/v1/tool.sh")
	if n := e.up.count("/dl/tool/v1/tool.sh"); n != 1 {
		t.Errorf("upstream asked %d times within the window", n)
	}
	w = e.expect(http.StatusPartialContent, "GET", "/generic/remote/tool/v1/tool.sh", nil, "Range", "bytes=0-6")
	if w.Body.String() != "content" {
		t.Errorf("range: %q", w.Body)
	}

	e.advance(testWindow + 1)
	e.get(http.StatusOK, "/generic/remote/tool/v1/tool.sh") // a 304
	if n := e.up.count("/dl/tool/v1/tool.sh"); n != 2 {
		t.Errorf("upstream asked %d times after the window", n)
	}
	e.up.set("/dl/tool/v1/tool.sh", content(2))
	e.advance(testWindow + 1)
	if got := e.get(http.StatusOK, "/generic/remote/tool/v1/tool.sh"); got != string(content(2)) {
		t.Errorf("after the upstream changed: %q", got)
	}

	e.up.down.Store(true)
	e.advance(testWindow + 1)
	if got := e.get(http.StatusOK, "/generic/remote/tool/v1/tool.sh"); got != string(content(2)) {
		t.Errorf("with the upstream down: %q", got)
	}
	e.restart()
	if got := e.get(http.StatusOK, "/generic/remote/tool/v1/tool.sh"); got != string(content(2)) {
		t.Errorf("after a restart with the upstream down: %q", got)
	}
	e.get(http.StatusServiceUnavailable, "/generic/remote/tool/v1/never-cached")

	// An upstream that answers not found is answered so, even if cached.
	e.up.down.Store(false)
	e.up.remove("/dl/tool/v1/tool.sh")
	e.advance(testWindow + 1)
	e.restart() // forget the offline mark
	e.get(http.StatusNotFound, "/generic/remote/tool/v1/tool.sh")
}

// TestProxyImmutable checks a proxy repository with generic.immutable:
// a file is fetched once and served from the cache forever, never
// revalidated, also with the upstream down.
func TestProxyImmutable(t *testing.T) {
	e := newEnv(t)
	body := []byte(strings.Repeat("release binary ", 1000))
	e.up.set("/dl/v1.0/app-linux-amd64", body)
	if got := e.get(http.StatusOK, "/generic/releases/v1.0/app-linux-amd64"); got != string(body) {
		t.Errorf("first fetch: %d bytes", len(got))
	}
	e.settle()
	e.advance(100 * testWindow)
	e.up.set("/dl/v1.0/app-linux-amd64", []byte("changed"))
	w := e.expect(http.StatusOK, "GET", "/generic/releases/v1.0/app-linux-amd64", nil)
	if w.Body.String() != string(body) {
		t.Error("a cached immutable file was revalidated")
	}
	if got := w.Header().Get("ETag"); got != `"sha256:`+sha(body)+`"` {
		t.Errorf("ETag = %q", got)
	}
	if n := e.up.count("/dl/v1.0/app-linux-amd64"); n != 1 {
		t.Errorf("upstream asked %d times", n)
	}
	e.up.down.Store(true)
	e.restart()
	e.get(http.StatusOK, "/generic/releases/v1.0/app-linux-amd64")
	e.expect(http.StatusOK, "HEAD", "/generic/releases/v1.0/app-linux-amd64", nil)

	// Not found is remembered for a short time.
	e.up.down.Store(false)
	e.get(http.StatusNotFound, "/generic/releases/v1.0/missing")
	e.get(http.StatusNotFound, "/generic/releases/v1.0/missing")
	if n := e.up.count("/dl/v1.0/missing"); n != 1 {
		t.Errorf("a missing file was asked for %d times", n)
	}
}

// TestProxyRedirects checks that a proxy repository follows a redirect
// only to a host its fetch policy allows, as for release download sites
// that redirect to a storage host.
func TestProxyRedirects(t *testing.T) {
	e := newEnv(t)
	e.other.set("/storage/asset", content(3))
	e.up.mu.Lock()
	e.up.redirect["/dl/v2/asset"] = e.other.URL + "/storage/asset"
	e.up.mu.Unlock()
	e.get(http.StatusBadGateway, "/generic/releases/v2/asset")
	if got := e.get(http.StatusOK, "/generic/elsewhere/v2/asset"); got != string(content(3)) {
		t.Errorf("through an allowed redirect: %q", got)
	}
}

// TestProxyQueries checks that a proxy repository refuses query strings,
// so the cache key is always the path.
func TestProxyQueries(t *testing.T) {
	e := newEnv(t)
	e.up.set("/dl/a", content(1))
	e.get(http.StatusBadRequest, "/generic/remote/a?x=1")
	e.get(http.StatusBadRequest, "/generic/all/a?")
	if n := e.up.count("/dl/a"); n != 0 {
		t.Errorf("upstream asked %d times", n)
	}
	e.get(http.StatusOK, "/generic/remote/a")
}
