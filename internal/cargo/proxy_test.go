package cargo

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/terrabyteian/flint/internal/upstream"
)

func TestProxyIndexAndDownload(t *testing.T) {
	e := newEnv(t)
	a1, a2 := newCrate("Serde_Json", "1.0.0"), newCrate("Serde_Json", "1.1.0")
	e.up.add(a1)
	e.up.add(a2)

	// The index file is served verbatim.
	w := e.get("/cargo/remote/se/rd/serde_json", http.StatusOK)
	if got := versions(decodeLines(t, w.Body.Bytes())); !slices.Equal(got, []string{"1.0.0", "1.1.0"}) {
		t.Errorf("index %v", got)
	}
	etag := w.Header().Get("ETag")
	e.get("/cargo/remote/se/rd/serde_json", http.StatusNotModified, "If-None-Match", etag)
	if n := e.up.count("/index/se/rd/serde_json"); n != 1 {
		t.Errorf("%d upstream index requests within the window", n)
	}

	w = e.get("/cargo/remote/api/v1/crates/Serde_Json/1.0.0/download", http.StatusOK)
	if !bytes.Equal(w.Body.Bytes(), a1.body) {
		t.Fatal("the download is not the upstream's .crate file")
	}
	e.settle()
	if n := e.up.count("/files/se/rd/Serde_Json/Serde_Json-1.0.0.crate"); n != 1 {
		t.Errorf("%d upstream downloads", n)
	}
	if !e.has(upstream.FileKey("remote", cratePath("Serde_Json", "1.0.0"))) {
		t.Fatal("the .crate file is not cached")
	}
	// Cached: served without asking the upstream, even about the index.
	e.up.down.Store(true)
	e.advance(2 * testWindow)
	w = e.get("/cargo/remote/api/v1/crates/serde_json/1.0.0/download", http.StatusOK)
	if !bytes.Equal(w.Body.Bytes(), a1.body) || w.Header().Get("Content-Type") != crateType {
		t.Error("the cached download differs")
	}
	// The index file is served stale; an uncached crate fails.
	e.get("/cargo/remote/se/rd/serde_json", http.StatusOK)
	e.get("/cargo/remote/api/v1/crates/Serde_Json/1.1.0/download", http.StatusServiceUnavailable)
	e.get("/cargo/remote/3/x/xyz", http.StatusServiceUnavailable)
	e.up.down.Store(false)

	e.get("/cargo/remote/api/v1/crates/Serde_Json/9.0.0/download", http.StatusNotFound)
	e.get("/cargo/remote/api/v1/crates/nope/1.0.0/download", http.StatusNotFound)
	if v := e.metric(`flint_proxy_requests_total{repository="remote",result="stale"}`); v == "" || v == "0" {
		t.Errorf("stale requests %q", v)
	}
}

func TestProxyVerifies(t *testing.T) {
	e := newEnv(t)
	good, bad := newCrate("foo", "1.0.0"), newCrate("foo", "2.0.0")
	e.up.add(good)
	e.up.add(bad, strings.Repeat("ab", 32))
	w := e.do("GET", "/cargo/remote/api/v1/crates/foo/2.0.0/download", nil)
	if w.Code != aborted && w.Code != http.StatusBadGateway || bytes.Equal(w.Body.Bytes(), bad.body) {
		t.Errorf("a .crate file that does not match its cksum: %d, served whole: %v", w.Code, bytes.Equal(w.Body.Bytes(), bad.body))
	}
	e.settle()
	if e.has(upstream.FileKey("remote", cratePath("foo", "2.0.0"))) {
		t.Error("a .crate file that does not match its cksum was cached")
	}
	e.get("/cargo/remote/api/v1/crates/foo/1.0.0/download", http.StatusOK)
}

func TestProxyNotFound(t *testing.T) {
	e := newEnv(t)
	e.up.add(newCrate("gone", "1.0.0"))
	e.get("/cargo/remote/4/gone", http.StatusNotFound) // not an index path
	e.get("/cargo/remote/go/ne/gone", http.StatusOK)
	for _, status := range []int{http.StatusNotFound, http.StatusGone, http.StatusUnavailableForLegalReasons} {
		e.up.setStatus(func(r *http.Request) int {
			if strings.HasPrefix(r.URL.Path, "/index/go/") {
				return status
			}
			return 0
		})
		e.advance(2 * testWindow)
		e.get("/cargo/remote/go/ne/gone", http.StatusNotFound)
	}
	e.up.setStatus(nil)
	e.advance(2 * testWindow)
	e.get("/cargo/remote/go/ne/gone", http.StatusOK)
}

func TestProxyRevalidates(t *testing.T) {
	e := newEnv(t)
	e.up.add(newCrate("foo", "1.0.0"))
	e.get("/cargo/remote/3/f/foo", http.StatusOK)
	e.advance(2 * testWindow)
	e.get("/cargo/remote/3/f/foo", http.StatusOK)
	e.up.add(newCrate("foo", "1.1.0"))
	if got := versions(e.index("remote", "foo")); !slices.Equal(got, []string{"1.0.0"}) {
		t.Errorf("within the window: %v", got)
	}
	e.advance(2 * testWindow)
	if got := versions(e.index("remote", "foo")); !slices.Equal(got, []string{"1.0.0", "1.1.0"}) {
		t.Errorf("after the window: %v", got)
	}
	// After a restart, the stored ETag makes the revalidation a 304.
	e.restart()
	e.get("/cargo/remote/3/f/foo", http.StatusOK)
	if v := e.metric(`flint_proxy_requests_total{repository="remote",result="revalidated"}`); v != "1" {
		t.Errorf("revalidated after a restart: %q", v)
	}
}

func TestProxySizeLimit(t *testing.T) {
	e := newEnv(t)
	var cs []crate
	for _, v := range []string{"1.0.0", "2.0.0", "3.0.0"} {
		c := newCrate("foo", v)
		cs = append(cs, c)
		e.up.add(c)
	}
	if n := len(cs[0].body); 2*n > 400 || 3*n <= 400 {
		t.Fatalf("a .crate file is %d bytes; the test needs three to exceed the limit and two to fit", n)
	}
	for _, c := range cs {
		e.get("/cargo/small/api/v1/crates/foo/"+c.vers()+"/download", http.StatusOK)
		e.settle()
		e.advance(testWindow / 10)
	}
	if err := e.h.Evict(context.Background()); err != nil {
		t.Fatal(err)
	}
	if e.has(upstream.FileKey("small", cratePath("foo", "1.0.0"))) {
		t.Error("the least recently pulled .crate file was not evicted")
	}
	if !e.has(upstream.FileKey("small", cratePath("foo", "3.0.0"))) {
		t.Error("the most recently pulled .crate file was evicted")
	}
	e.get("/cargo/small/api/v1/crates/foo/1.0.0/download", http.StatusOK)
}

func TestProxySearch(t *testing.T) {
	e := newEnv(t)
	e.up.add(newCrate("tokio", "1.0.0"))
	e.up.add(newCrate("tokio-util", "0.7.0"))
	w := e.get("/cargo/remote/api/v1/crates?q=tokio&per_page=5", http.StatusOK)
	var res searchResult
	if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, c := range res.Crates {
		names = append(names, c.Name)
	}
	slices.Sort(names)
	if !slices.Equal(names, []string{"tokio", "tokio-util"}) || res.Meta.Total != 7 {
		t.Errorf("search %s", w.Body)
	}
	e.up.down.Store(true)
	e.get("/cargo/remote/api/v1/crates?q=tokio", http.StatusServiceUnavailable)
}

func TestProxyConfig(t *testing.T) {
	e := newEnv(t)
	c := newCrate("ab", "1.0.0")
	e.up.add(c)
	// A dl without markers gets /{crate}/{version}/download, as in Cargo.
	e.up.mu.Lock()
	e.up.config = `{"dl": "` + e.up.URL + `/files/2"}`
	e.up.mu.Unlock()
	w := e.do("GET", "/cargo/remote/api/v1/crates/ab/1.0.0/download", nil)
	if n := e.up.count("/files/2/ab/1.0.0/download"); n != 1 || w.Code != http.StatusNotFound {
		t.Errorf("dl without markers: %d requests, %d", n, w.Code)
	}
	// A config.json flint cannot read never replaces the cached one; with
	// none cached, downloads fail.
	for _, cfg := range []string{`{}`, `{"dl": "ftp://x/"}`, `not json`} {
		e := newEnv(t)
		e.up.add(c)
		e.up.config = cfg
		if w := e.do("GET", "/cargo/remote/api/v1/crates/ab/1.0.0/download", nil); w.Code != http.StatusBadGateway {
			t.Errorf("config %s: %d %s", cfg, w.Code, w.Body)
		}
	}
}

func TestDownloadURL(t *testing.T) {
	for _, tc := range []struct{ dl, want string }{
		{"https://static.crates.io/crates", "https://static.crates.io/crates/Serde/1.0.0/download"},
		{"https://h/{crate}/{version}", "https://h/Serde/1.0.0"},
		{"https://h/{prefix}/{lowerprefix}/{crate}-{version}.crate?s={sha256-checksum}", "https://h/Se/rd/se/rd/Serde-1.0.0.crate?s=abc"},
	} {
		if got := downloadURL(tc.dl, "Serde", "1.0.0", "abc"); got != tc.want {
			t.Errorf("%s: %s, want %s", tc.dl, got, tc.want)
		}
	}
}
