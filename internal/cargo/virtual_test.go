package cargo

import (
	"bytes"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"
)

func TestVirtualMerge(t *testing.T) {
	e := newEnv(t)
	// remote has foo 1.0.0 and 2.0.0; open (no protection) merges them
	// with local's 2.0.0 and 3.0.0, local first.
	up1, up2 := newCrate("foo", "1.0.0"), newCrate("foo", "2.0.0")
	e.up.add(up1)
	e.up.add(up2)
	l2, l3 := newCrate("foo", "2.0.0"), newCrate("foo", "3.0.0")
	e.mustPublish("local", l2)
	e.mustPublish("local", l3)

	e.auth.reset()
	lines := e.index("open", "foo")
	if got := versions(lines); !slices.Equal(got, []string{"1.0.0", "2.0.0", "3.0.0"}) {
		t.Fatalf("merged index %v", got)
	}
	if calls := e.auth.reset(); !slices.Equal(calls, []string{"open>:pull"}) {
		t.Errorf("authorized %v", calls)
	}
	if lines[1]["cksum"] != l2.sha256() {
		t.Error("the first member's line does not win")
	}
	for _, tc := range []struct {
		vers string
		body []byte
	}{{"1.0.0", up1.body}, {"2.0.0", l2.body}, {"3.0.0", l3.body}} {
		w := e.get("/cargo/open/api/v1/crates/foo/"+tc.vers+"/download", http.StatusOK)
		if !bytes.Equal(w.Body.Bytes(), tc.body) {
			t.Errorf("download of %s is not the listing member's", tc.vers)
		}
		if cc := w.Header().Get("Cache-Control"); tc.vers != "1.0.0" && !strings.HasPrefix(cc, "public,") {
			t.Errorf("download of %s from an anonymous virtual repository: Cache-Control %q", tc.vers, cc)
		}
	}
	e.settle()
	e.get("/cargo/open/api/v1/crates/foo/4.0.0/download", http.StatusNotFound)

	// With protection, local owns foo: remote is not even asked.
	n := e.up.count("/index/3/f/foo")
	if got := versions(e.index("all", "foo")); !slices.Equal(got, []string{"2.0.0", "3.0.0"}) {
		t.Errorf("protected index %v", got)
	}
	e.get("/cargo/all/api/v1/crates/foo/1.0.0/download", http.StatusNotFound)
	if e.up.count("/index/3/f/foo") != n {
		t.Error("the proxy member was asked about a name a hosted member owns")
	}
	// ... in any spelling: Foo_Bar owns foo-bar.
	e.up.add(newCrate("foo-bar", "1.0.0"))
	e.mustPublish("local", newCrate("Foo_Bar", "0.1.0"))
	e.get("/cargo/all/fo/o-/foo-bar", http.StatusNotFound)
	if got := versions(e.index("all", "foo_bar")); !slices.Equal(got, []string{"0.1.0"}) {
		t.Errorf("index of foo_bar %v", got)
	}
	// A deleted crate stays owned.
	e.do("DELETE", "/api/v1/cargo/local/crates/Foo_Bar/0.1.0", nil)
	e.get("/cargo/all/fo/o-/foo-bar", http.StatusNotFound)

	// A crate only upstream is served from the proxy member.
	e.up.add(newCrate("bar", "1.0.0"))
	if got := versions(e.index("all", "bar")); !slices.Equal(got, []string{"1.0.0"}) {
		t.Errorf("index of bar %v", got)
	}
	e.get("/cargo/all/3/n/nope", http.StatusNotFound)
}

func TestVirtualFilters(t *testing.T) {
	e := newEnv(t)
	// filtered: local for acme-* only, team, remote except acme_*.
	e.up.add(newCrate("acme-core", "9.0.0"))
	e.up.add(newCrate("tools", "1.0.0"))
	e.mustPublish("local", newCrate("tools", "0.1.0"))
	e.mustPublish("local", newCrate("acme_util", "1.0.0"))
	e.get("/cargo/filtered/ac/me/acme-core", http.StatusNotFound)
	if got := versions(e.index("filtered", "acme_util")); !slices.Equal(got, []string{"1.0.0"}) {
		t.Errorf("acme_util %v", got)
	}
	// local's tools is filtered out, so it does not claim the name.
	if got := versions(e.index("filtered", "tools")); !slices.Equal(got, []string{"1.0.0"}) {
		t.Errorf("tools %v", got)
	}

	// Publishes go to team, if its filters admit the crate.
	e.auth.reset()
	e.mustPublish("filtered", newCrate("teamlib", "1.0.0"))
	if calls := e.auth.reset(); !slices.Equal(calls, []string{"filtered>team:pull,push"}) {
		t.Errorf("publish authorized %v", calls)
	}
	if !e.has(crateKey("team", "teamlib")) {
		t.Error("the publish did not go to team")
	}
	if got := versions(e.index("filtered", "teamlib")); !slices.Equal(got, []string{"1.0.0"}) {
		t.Errorf("teamlib %v", got)
	}
	if w := e.do("DELETE", "/cargo/filtered/api/v1/crates/teamlib/1.0.0/yank", nil); w.Code != http.StatusOK {
		t.Errorf("yank through the virtual repository: %d %s", w.Code, w.Body)
	}
	if l := e.index("team", "teamlib"); l[0]["yanked"] != true {
		t.Error("the yank did not reach team")
	}
	e.mustPublish("all", newCrate("viaall", "1.0.0"))
	if !e.has(crateKey("local", "viaall")) {
		t.Error("the publish did not go to local")
	}
}

func TestVirtualPublishFilter(t *testing.T) {
	e := newEnv(t)
	w := e.publish("scoped", newCrate("other", "1.0.0"))
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "include filter") {
		t.Errorf("a publish the publishTo member's filters refuse: %d %s", w.Code, w.Body)
	}
	e.mustPublish("scoped", newCrate("acme_x", "1.0.0"))
	if w := e.do("DELETE", "/cargo/scoped/api/v1/crates/acme_x/1.0.0/yank", nil); w.Code != http.StatusOK {
		t.Errorf("a yank the filters admit: %d %s", w.Code, w.Body)
	}
	e.mustPublish("local", newCrate("other", "1.0.0"))
	if w := e.do("DELETE", "/cargo/scoped/api/v1/crates/other/1.0.0/yank", nil); w.Code != http.StatusForbidden {
		t.Errorf("a yank the filters refuse: %d", w.Code)
	}
}

func TestVirtualLocalizesDependencies(t *testing.T) {
	e := newEnv(t)
	idx := "sparse+" + e.up.URL + "/index/"
	onUp, onIO, onOther := dep("serde", "^1"), dep("rand", "^0.8"), dep("x", "1")
	onUp["registry"] = strings.TrimPrefix(idx, "sparse+") // the proxy member's upstream, as named without "sparse+"
	onIO["registry"] = "https://github.com/rust-lang/crates.io-index"
	onOther["registry"] = "sparse+https://elsewhere.example/index/"
	e.mustPublish("local", newCrate("app", "1.0.0", onUp, onIO, onOther, dep("base", "1")))
	regs := func(lines []map[string]any) []any {
		var out []any
		for _, d := range lines[0]["deps"].([]any) {
			out = append(out, d.(map[string]any)["registry"])
		}
		return out
	}
	if got := regs(e.index("local", "app")); !slices.Equal(got, []any{onUp["registry"], onIO["registry"], onOther["registry"], nil}) {
		t.Errorf("hosted registries %v", got)
	}
	// remote caches the fake upstream, not crates.io.
	if got := regs(e.index("all", "app")); !slices.Equal(got, []any{nil, onIO["registry"], onOther["registry"], nil}) {
		t.Errorf("virtual registries %v", got)
	}
	if got := regs(e.index("plain", "app")); !slices.Equal(got, []any{onUp["registry"], onIO["registry"], onOther["registry"], nil}) {
		t.Errorf("registries in a virtual repository without proxies %v", got)
	}
}

func TestRegistryAliases(t *testing.T) {
	for _, tc := range []struct {
		index string
		dep   string
		same  bool
	}{
		{"https://index.crates.io/", "https://github.com/rust-lang/crates.io-index", true},
		{"https://index.crates.io/", "sparse+https://index.crates.io/", true},
		{"https://INDEX.crates.io", "https://github.com/rust-lang/crates.io-index.git", true},
		{"https://flint.example/cargo/up/", "sparse+https://flint.example/cargo/up/", true},
		{"https://flint.example/cargo/up/", "sparse+https://flint.example/cargo/other/", false},
		{"https://flint.example/cargo/up/", "https://github.com/rust-lang/crates.io-index", false},
	} {
		if got := slices.Contains(aliases(tc.index), registryID(tc.dep)); got != tc.same {
			t.Errorf("%s names %s: %v, want %v", tc.dep, tc.index, got, tc.same)
		}
	}
}

func TestVirtualSkipsFailingMember(t *testing.T) {
	e := newEnv(t)
	e.mustPublish("local", newCrate("lib", "1.0.0"))
	e.up.down.Store(true)
	// Without protection, open asks remote too, which fails: skipped.
	if got := versions(e.index("open", "lib")); !slices.Equal(got, []string{"1.0.0"}) {
		t.Errorf("index %v", got)
	}
	if v := e.metric(`flint_virtual_member_skips_total{repository="open",member="remote"}`); v != "1" {
		t.Errorf("skips %q", v)
	}
	// Only a failing member: the request fails.
	e.get("/cargo/open/3/n/nop", http.StatusServiceUnavailable)
}

func TestVirtualSearch(t *testing.T) {
	e := newEnv(t)
	e.up.add(newCrate("tokio", "1.0.0"))
	e.up.add(newCrate("tokio-util", "0.7.0"))
	e.mustPublish("local", newCrate("tokio_util", "0.1.0"))
	e.mustPublish("local", newCrate("tokio-extra", "2.0.0"))
	search := func(repo, q string) *searchResult {
		t.Helper()
		w := e.get("/cargo/"+repo+"/api/v1/crates?q="+q, http.StatusOK)
		var res searchResult
		if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
			t.Fatal(err)
		}
		return &res
	}
	names := func(res *searchResult) []string {
		var out []string
		for _, c := range res.Crates {
			out = append(out, c.Name+"@"+c.MaxVersion)
		}
		return out
	}
	if got := names(search("local", "tokio")); !slices.Equal(got, []string{"tokio-extra@2.0.0", "tokio_util@0.1.0"}) {
		t.Errorf("hosted search %v", got)
	}
	// local's results first; remote's tokio-util is owned by local.
	res := search("all", "tokio")
	got := names(res)
	if len(got) != 3 || !slices.Equal(got[:2], []string{"tokio-extra@2.0.0", "tokio_util@0.1.0"}) || got[2] != "tokio@1.0.0" {
		t.Errorf("virtual search %v", got)
	}
	if res.Meta.Total != 3+5 {
		t.Errorf("total %d", res.Meta.Total)
	}
	e.up.down.Store(true)
	if got := names(search("all", "tokio")); len(got) != 2 {
		t.Errorf("virtual search with the proxy down %v", got)
	}
}

func TestSearchHosted(t *testing.T) {
	e := newEnv(t)
	e.mustPublish("local", newCrate("serde", "1.0.0"))
	e.mustPublish("local", newCrate("serde", "1.1.0"))
	e.mustPublish("local", newCrate("serde", "2.0.0-alpha.1"))
	e.mustPublish("local", newCrate("serde_json", "1.0.0"))
	e.mustPublish("local", newCrate("my-serde", "1.0.0"))
	e.mustPublish("local", newCrate("gone", "1.0.0"))
	e.do("DELETE", "/api/v1/cargo/local/crates/gone/1.0.0", nil)
	e.do("DELETE", "/cargo/local/api/v1/crates/serde/1.1.0/yank", nil)
	w := e.get("/cargo/local/api/v1/crates?q=Serde&per_page=2", http.StatusOK)
	var res searchResult
	json.Unmarshal(w.Body.Bytes(), &res)
	if len(res.Crates) != 2 || res.Crates[0] != (searchCrate{"serde", "1.0.0", "The serde crate"}) ||
		res.Crates[1].Name != "serde_json" || res.Meta.Total != 3 {
		t.Errorf("search %s", w.Body)
	}
	w = e.get("/cargo/local/api/v1/crates?q=gone", http.StatusOK)
	if !strings.Contains(w.Body.String(), `"crates":[]`) {
		t.Errorf("search for a deleted crate %s", w.Body)
	}
	e.get("/cargo/local/api/v1/crates?q=x&per_page=0", http.StatusBadRequest)
	e.get("/cargo/local/api/v1/crates?q="+strings.Repeat("x", 300), http.StatusBadRequest)
}
