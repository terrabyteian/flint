package npm

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"runtime"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/terrabyteian/flint/internal/repo"
	"github.com/terrabyteian/flint/internal/upstream"
)

// TestVirtualProxied checks a package only the proxy member has: served
// through the virtual repository with its URLs, and its tarballs cached
// in the proxy member.
func TestVirtualProxied(t *testing.T) {
	e := newEnv(t)
	e.up.add("left-pad", "1.0.0", nil)
	doc := e.packument("all", "left-pad", true)
	if dist(t, doc, "1.0.0")["tarball"] != testBase+"/npm/all/left-pad/-/left-pad-1.0.0.tgz" {
		t.Errorf("tarball URL %v", dist(t, doc, "1.0.0")["tarball"])
	}
	w := e.expect("GET", "/npm/all/left-pad/-/left-pad-1.0.0.tgz", nil, http.StatusOK)
	if !bytes.Equal(w.Body.Bytes(), tarballOf("left-pad", "1.0.0")) {
		t.Fatalf("tarball %q", w.Body)
	}
	e.settle()
	if !e.has(upstream.FileKey("remote", "left-pad/-/left-pad-1.0.0.tgz")) {
		t.Error("the tarball is not cached in the proxy member")
	}
	if calls := e.auth.reset(); !slices.Contains(calls, "all>local:pull") || slices.ContainsFunc(calls, func(c string) bool {
		return strings.HasPrefix(c, "remote:") || strings.HasPrefix(c, "local:")
	}) {
		t.Errorf("authorization calls %q: want read on the virtual repository only", calls)
	}

	// Offline: the cached packument and tarball keep being served.
	e.up.down.Store(true)
	e.advance(2 * testWindow)
	e.packument("all", "left-pad", true)
	e.expect("GET", "/npm/all/left-pad/-/left-pad-1.0.0.tgz", nil, http.StatusOK)
	e.expect("GET", "/npm/all/right-pad", nil, http.StatusServiceUnavailable)
}

// TestVirtualDependencyConfusion checks that once a hosted member owns a
// name, the proxy member is never asked about it, even after every
// hosted version is unpublished, and that a filter keeps a scope from
// the proxy member altogether.
func TestVirtualDependencyConfusion(t *testing.T) {
	e := newEnv(t)
	e.publish("local", newPkg("internal", "1.0.0"), http.StatusOK)
	e.up.add("internal", "1.0.0", nil)
	e.up.add("internal", "9.0.0", nil)

	doc := e.packument("all", "internal", false)
	if len(doc.Versions) != 1 || doc.Tags["latest"] != "1.0.0" || dist(t, doc, "1.0.0")["integrity"] != newPkg("internal", "1.0.0").integrity() {
		t.Errorf("packument %+v", doc)
	}
	e.expect("GET", "/npm/all/internal/-/internal-9.0.0.tgz", nil, http.StatusNotFound)
	w := e.expect("GET", "/npm/all/internal/-/internal-1.0.0.tgz", nil, http.StatusOK)
	if !bytes.Equal(w.Body.Bytes(), newPkg("internal", "1.0.0").tarball) {
		t.Error("the tarball is not the hosted one")
	}
	e.expect("GET", "/npm/all/internal/9.0.0", nil, http.StatusNotFound)
	if n := e.up.count("/registry/internal"); n != 0 {
		t.Errorf("the proxy member was asked about a hosted name %d times", n)
	}
	// Unpublishing hands nothing back to the upstream.
	rev := e.rawPackument("local", "internal")["_rev"].(string)
	e.expect("DELETE", "/npm/local/internal/-rev/"+rev, nil, http.StatusOK)
	e.expect("GET", "/npm/all/internal", nil, http.StatusNotFound)
	e.expect("GET", "/npm/all/internal/-/internal-9.0.0.tgz", nil, http.StatusNotFound)
	if n := e.up.count("/registry/internal"); n != 0 {
		t.Errorf("the proxy member was asked about an unpublished hosted name %d times", n)
	}

	// Without protection, the members merge.
	e.publish("local", newPkg("shared", "1.0.0"), http.StatusOK)
	e.up.add("shared", "1.0.0", nil)
	e.up.add("shared", "2.0.0", nil)
	doc = e.packument("exposed", "shared", false)
	if len(doc.Versions) != 2 || doc.Tags["latest"] != "1.0.0" || dist(t, doc, "1.0.0")["integrity"] != newPkg("shared", "1.0.0").integrity() ||
		doc.ID != "shared" || doc.Time["2.0.0"] != "2021-01-01T00:00:00.000Z" || doc.Time["1.0.0"] == "" || doc.Time["created"] == "" {
		t.Errorf("merged packument %+v", doc)
	}
	for v, d := range doc.Versions {
		if dd, _ := d["dist"].(map[string]any); dd["tarball"] != testBase+"/npm/exposed/shared/-/shared-"+v+".tgz" {
			t.Errorf("tarball URL of %s: %v", v, dd["tarball"])
		}
	}
	abbr := e.packument("exposed", "shared", true)
	if len(abbr.Versions) != 2 || abbr.Modified == "" || abbr.Readme != "" {
		t.Errorf("merged abbreviated packument %+v", abbr)
	}
	if w := e.expect("GET", "/npm/exposed/shared/-/shared-1.0.0.tgz", nil, http.StatusOK); !bytes.Equal(w.Body.Bytes(), newPkg("shared", "1.0.0").tarball) {
		t.Error("1.0.0 is not the first member's")
	}
	if w := e.expect("GET", "/npm/exposed/shared/-/shared-2.0.0.tgz", nil, http.StatusOK); !bytes.Equal(w.Body.Bytes(), tarballOf("shared", "2.0.0")) {
		t.Error("2.0.0 is not the proxy member's")
	}
	tags := jsonOf[map[string]string](t, e.expect("GET", "/npm/exposed/-/package/shared/dist-tags", nil, http.StatusOK))
	if tags["latest"] != "1.0.0" {
		t.Errorf("dist-tags %v", tags)
	}
	// A merged rendering is cached until a member changes.
	etag := e.expect("GET", "/npm/exposed/shared", nil, http.StatusOK).Header().Get("ETag")
	e.publish("local", newPkg("shared", "1.5.0"), http.StatusOK)
	if got := e.expect("GET", "/npm/exposed/shared", nil, http.StatusOK).Header().Get("ETag"); got == etag {
		t.Error("the merged packument did not change with a member")
	}

	// A filter keeps a scope from the proxy member, published here or not.
	e.up.add("@acme/new-thing", "1.0.0", nil)
	e.expect("GET", "/npm/scoped/@acme%2fnew-thing", nil, http.StatusNotFound)
	e.expect("GET", "/npm/scoped/@acme/new-thing/-/new-thing-1.0.0.tgz", nil, http.StatusNotFound)
	if n := e.up.count("acme"); n != 0 {
		t.Errorf("the proxy member was asked about an excluded scope %d times", n)
	}
	e.packument("all", "@acme/new-thing", true)
}

// TestVirtualFailingMember checks that a proxy member whose upstream
// cannot be reached, with nothing cached, is skipped.
func TestVirtualFailingMember(t *testing.T) {
	e := newEnv(t)
	e.publish("local", newPkg("shared", "1.0.0"), http.StatusOK)
	e.up.down.Store(true)
	doc := e.packument("exposed", "shared", true)
	if len(doc.Versions) != 1 {
		t.Errorf("packument %+v", doc)
	}
	e.expect("GET", "/npm/exposed/shared/-/shared-1.0.0.tgz", nil, http.StatusOK)
	e.expect("GET", "/npm/exposed/other", nil, http.StatusServiceUnavailable)
	e.expect("GET", "/npm/exposed/other/-/other-1.0.0.tgz", nil, http.StatusServiceUnavailable)
	if v := e.metric(`flint_virtual_member_skips_total{repository="exposed",member="remote"}`); v == "" || v == "0" {
		t.Errorf("skips %q", v)
	}
}

// TestVirtualPublish checks that changes sent to a virtual repository go
// to its publishTo member, authorized there, and that filters and a
// missing publishTo refuse them.
func TestVirtualPublish(t *testing.T) {
	e := newEnv(t)
	e.auth.reset()
	e.publish("all", newPkg("app", "1.0.0"), http.StatusOK)
	if calls := e.auth.reset(); !slices.Equal(calls, []string{"all>local:pull", "all>local:push"}) {
		t.Errorf("authorization calls %q", calls)
	}
	if doc := e.packument("local", "app", false); doc.Tags["latest"] != "1.0.0" {
		t.Errorf("not published to local: %+v", doc)
	}
	e.publish("all", newPkg("app", "1.0.0"), http.StatusConflict)
	e.publish("all", newPkg("app", "1.1.0"), http.StatusOK)

	// npm's edits read with ?write=true, which is the publishTo member's
	// packument, with tarball URLs at the virtual repository.
	raw := e.rawPackument("all", "app")
	rev := raw["_rev"].(string)
	versions := raw["versions"].(map[string]any)
	v1 := versions["1.0.0"].(map[string]any)
	if d := v1["dist"].(map[string]any); d["tarball"] != testBase+"/npm/all/app/-/app-1.0.0.tgz" || rev == "" {
		t.Errorf("write packument %v", raw)
	}
	v1["deprecated"] = "use 1.1.0"
	e.expect("PUT", "/npm/all/app/-rev/"+rev, bytes.NewReader(mustJSON(raw)), http.StatusOK)
	if m := jsonOf[map[string]any](t, e.expect("GET", "/npm/local/app/1.0.0", nil, http.StatusOK)); m["deprecated"] != "use 1.1.0" {
		t.Errorf("deprecate through the virtual repository: %v", m)
	}
	e.expect("PUT", "/npm/all/-/package/app/dist-tags/stable", strings.NewReader(`"1.0.0"`), http.StatusOK)
	if tags := jsonOf[map[string]string](t, e.expect("GET", "/npm/all/-/package/app/dist-tags", nil, http.StatusOK)); tags["stable"] != "1.0.0" {
		t.Errorf("dist-tags %v", tags)
	}
	e.expect("DELETE", "/npm/all/-/package/app/dist-tags/stable", nil, http.StatusOK)
	e.auth.reset()
	rev = e.rawPackument("all", "app")["_rev"].(string)
	e.expect("DELETE", "/npm/all/app/-/app-1.0.0.tgz/-rev/"+rev, nil, http.StatusOK)
	if calls := e.auth.reset(); !slices.Contains(calls, "all>local:delete") {
		t.Errorf("unpublish authorization calls %q", calls)
	}
	if doc := e.packument("local", "app", false); len(doc.Versions) != 1 {
		t.Errorf("unpublish through the virtual repository: %+v", doc.Versions)
	}

	// Refused: no publishTo, a filter, a proxy member's name is no
	// exception, and no write role.
	if w := e.publish("plain", newPkg("app2", "1.0.0"), http.StatusMethodNotAllowed); !strings.Contains(errorOf(t, w), "local, open") {
		t.Errorf("no publishTo: %s", errorOf(t, w))
	}
	if w := e.publish("acme", newPkg("app2", "1.0.0"), http.StatusForbidden); !strings.Contains(errorOf(t, w), "include filter") {
		t.Errorf("filtered: %s", errorOf(t, w))
	}
	e.publish("acme", newPkg("@acme/app", "1.0.0"), http.StatusOK)
	// A read for an edit shows the publishTo member's package only if its
	// filters admit it, as any other read through the virtual repository.
	e.publish("local", newPkg("app2", "1.0.0"), http.StatusOK)
	e.expect("GET", "/npm/acme/app2?write=true", nil, http.StatusNotFound)
	e.expect("GET", "/npm/acme/app2", nil, http.StatusNotFound)
	if raw := e.rawPackument("acme", "@acme/app"); raw["_rev"] == nil {
		t.Errorf("write packument through acme %v", raw)
	}
	e.auth.setDeny(ActionPush)
	e.publish("all", newPkg("app3", "1.0.0"), http.StatusForbidden)
	e.auth.setDeny()
	e.expect("GET", "/npm/all/app3", nil, http.StatusNotFound)
	e.expect("GET", "/npm/all/app", nil, http.StatusUnauthorized, "X-Test-Anonymous", "1")
}

// TestVirtualAudit checks that an audit through a virtual repository is
// forwarded to its proxy members with only the names each may serve and
// no hosted member owns.
func TestVirtualAudit(t *testing.T) {
	e := newEnv(t)
	e.publish("local", newPkg("internal", "1.0.0"), http.StatusOK)
	req := `{"internal": ["1.0.0"], "left-pad": ["1.0.0"], "@acme/secret": ["1.0.0"]}`
	adv := jsonOf[map[string][]map[string]any](t, e.expect("POST", "/npm/all/-/npm/v1/security/advisories/bulk",
		strings.NewReader(req), http.StatusOK))
	if len(e.up.audits) != 1 || len(e.up.audits[0]) != 2 || e.up.audits[0]["internal"] != nil {
		t.Errorf("all forwarded %v", e.up.audits)
	}
	if len(adv) != 2 || adv["left-pad"] == nil || adv["internal"] != nil {
		t.Errorf("all advisories %v", adv)
	}
	e.up.audits = nil
	e.expect("POST", "/npm/scoped/-/npm/v1/security/advisories/bulk", strings.NewReader(req), http.StatusOK)
	if len(e.up.audits) != 1 || len(e.up.audits[0]) != 1 || e.up.audits[0]["left-pad"] == nil {
		t.Errorf("scoped forwarded %v", e.up.audits)
	}
	// Nothing to forward: nothing is sent.
	e.up.audits = nil
	if adv := jsonOf[map[string]any](t, e.expect("POST", "/npm/plain/-/npm/v1/security/advisories/bulk",
		strings.NewReader(req), http.StatusOK)); len(adv) != 0 || len(e.up.audits) != 0 {
		t.Errorf("plain: %v, forwarded %v", adv, e.up.audits)
	}
}

// TestVirtualSearchKeysAttestations checks the other endpoints of a
// virtual repository.
func TestVirtualSearchKeysAttestations(t *testing.T) {
	e := newEnv(t)
	e.publish("local", newPkg("pad-internal", "1.0.0"), http.StatusOK)
	e.up.add("pad-internal", "1.0.0", nil)
	e.up.add("left-pad", "1.0.0", nil)
	e.up.add("@acme/pad", "1.0.0", nil)
	type result struct {
		Objects []struct {
			Package map[string]any `json:"package"`
		} `json:"objects"`
	}
	res := jsonOf[result](t, e.expect("GET", "/npm/scoped/-/v1/search?text=pad", nil, http.StatusOK))
	var names []string
	for _, o := range res.Objects {
		names = append(names, o.Package["name"].(string))
	}
	if len(names) != 2 || names[0] != "pad-internal" || names[1] != "left-pad" {
		t.Errorf("search %q: want the hosted match first, the upstream's once, without the excluded scope", names)
	}
	res = jsonOf[result](t, e.expect("GET", "/npm/scoped/-/v1/search?text=pad&from=1&size=1", nil, http.StatusOK))
	if len(res.Objects) != 1 || res.Objects[0].Package["name"] != "left-pad" {
		t.Errorf("search page %v", res.Objects)
	}

	keys := jsonOf[map[string][]map[string]any](t, e.expect("GET", "/npm/all/-/npm/v1/keys", nil, http.StatusOK))
	if len(keys["keys"]) != 1 {
		t.Errorf("keys %v", keys)
	}
	if keys := jsonOf[map[string][]any](t, e.expect("GET", "/npm/plain/-/npm/v1/keys", nil, http.StatusOK)); len(keys["keys"]) != 0 {
		t.Errorf("keys of a virtual repository of hosted members %v", keys)
	}
	att := jsonOf[map[string][]map[string]any](t, e.expect("GET", "/npm/all/-/npm/v1/attestations/left-pad@1.0.0", nil, http.StatusOK))
	if len(att["attestations"]) != 1 {
		t.Errorf("attestations %v", att)
	}
	// Cached as the virtual repository is pulled, not as its member.
	w := e.expect("GET", "/npm/pair/-/npm/v1/attestations/left-pad@1.0.0", nil, http.StatusOK)
	if cc := w.Header().Get("Cache-Control"); cc != "private, max-age=300" {
		t.Errorf("Cache-Control %q through a private virtual repository of an anonymous member", cc)
	}
	e.expect("GET", "/npm/all/-/npm/v1/attestations/pad-internal@1.0.0", nil, http.StatusNotFound)
	e.expect("GET", "/npm/all/-/npm/v1/attestations/left-pad@9.0.0", nil, http.StatusNotFound)
	if n := e.up.count("attestations/pad-internal"); n != 0 {
		t.Errorf("the attestations of a hosted name were asked upstream %d times", n)
	}
}

// addBig adds package big upstream, with a packument larger than the
// derive budget of 4KiB lets the document cache hold, so it is streamed.
func addBig(e *env) {
	e.deriveBudget = 4 << 10
	e.restart()
	for i := range 40 {
		e.up.add("big", fmt.Sprintf("1.0.%d", i), map[string]any{"padding": strings.Repeat("x", 200)})
	}
}

// waitRewriters waits until no packument is being streamed through the
// rewriter, as none is once every stream is read or closed.
func waitRewriters(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		buf := make([]byte, 1<<20)
		for n := runtime.Stack(buf, true); n == len(buf); n = runtime.Stack(buf, true) {
			buf = make([]byte, 2*len(buf))
		}
		if !bytes.Contains(buf, []byte("npm.rewritePackument(")) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("a packument stream was left open")
		}
		time.Sleep(time.Millisecond)
	}
}

// TestVirtualMergeLimit checks that members' packuments larger together
// than the merge limit are not merged: the first member's is served
// alone, as it streams, and the fallback counted; and that below the
// limit, a streamed packument merges.
func TestVirtualMergeLimit(t *testing.T) {
	e := newEnv(t)
	addBig(e)
	e.publish("local", newPkg("big", "2.0.0"), http.StatusOK)

	w := e.expect("GET", "/npm/capped/big", nil, http.StatusOK)
	doc := jsonOf[testPackument](t, w)
	if len(doc.Versions) != 40 || doc.Versions["2.0.0"] != nil || w.Header().Get("ETag") != "" {
		t.Errorf("over the limit: %d versions, ETag %q; want the proxy member's alone, streamed", len(doc.Versions), w.Header().Get("ETag"))
	}
	if dist(t, doc, "1.0.7")["tarball"] != testBase+"/npm/capped/big/-/big-1.0.7.tgz" {
		t.Errorf("tarball URL %v", dist(t, doc, "1.0.7")["tarball"])
	}
	e.expect("GET", "/npm/capped/big/-/big-2.0.0.tgz", nil, http.StatusOK)
	if v := e.metric(`flint_npm_virtual_merge_fallbacks_total{repository="capped"}`); v != "1" {
		t.Errorf("fallbacks %q", v)
	}

	// Small packuments still merge.
	e.publish("local", newPkg("tiny", "1.0.0"), http.StatusOK)
	e.up.add("tiny", "2.0.0", nil)
	if doc := e.packument("capped", "tiny", false); len(doc.Versions) != 2 || doc.Tags["latest"] != "2.0.0" {
		t.Errorf("merged below the limit: %+v", doc)
	}
	if v := e.metric(`flint_npm_virtual_merge_fallbacks_total{repository="capped"}`); v != "1" {
		t.Errorf("fallbacks %q after a merge", v)
	}

	// Below the default limit, the streamed packument merges.
	doc = e.packument("exposed", "big", false)
	if len(doc.Versions) != 41 || doc.Tags["latest"] != "2.0.0" ||
		dist(t, doc, "1.0.7")["tarball"] != testBase+"/npm/exposed/big/-/big-1.0.7.tgz" {
		t.Errorf("merged with a streamed packument: %d versions, dist-tags %v", len(doc.Versions), doc.Tags)
	}
	waitRewriters(t)
}

// TestVirtualCanceled checks that a member's streamed packument is
// closed when the client goes away while a later member is consulted.
func TestVirtualCanceled(t *testing.T) {
	e := newEnv(t)
	addBig(e)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var asked atomic.Int32
	e.up.setStatus(func(r *http.Request) int {
		if strings.HasSuffix(r.URL.Path, "/big") && asked.Add(1) > 1 {
			cancel()
			return http.StatusInternalServerError
		}
		return 0
	})
	func() {
		defer func() {
			if v := recover(); v != nil && v != http.ErrAbortHandler {
				panic(v)
			}
		}()
		e.srv.ServeHTTP(httptest.NewRecorder(), httptest.NewRequestWithContext(ctx, "GET", "/npm/pair/big", nil))
	}()
	if asked.Load() < 2 {
		t.Fatal("the second member was not consulted")
	}
	waitRewriters(t)
}

// TestVirtualMergeShared checks that a request for a merge being built
// waits for it rather than building it again, unless its client goes
// away first.
func TestVirtualMergeShared(t *testing.T) {
	e := newEnv(t)
	f := &mergeFlight{done: make(chan struct{})}
	e.h.merges["k"] = f
	answers := []repo.Answer[*docBody]{{Value: &docBody{b: []byte(`{"name": "x", "versions": {}}`)}}}
	got := make(chan []byte, 1)
	go func() {
		b, _, err := e.h.merged(context.Background(), "k", "x", answers, false)
		if err != nil {
			t.Error(err)
		}
		got <- b
	}()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := e.h.merged(ctx, "k", "x", answers, false); !errors.Is(err, context.Canceled) {
		t.Errorf("a canceled wait: %v", err)
	}
	f.b, f.etag = []byte("built once"), `"e"`
	close(f.done)
	if b := <-got; string(b) != "built once" {
		t.Errorf("a waiting request got %q, not the shared merge", b)
	}
}
