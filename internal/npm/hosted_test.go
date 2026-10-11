package npm

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestPublishAndRead publishes an unscoped and a scoped package and reads
// them back the ways clients do.
func TestPublishAndRead(t *testing.T) {
	e := newEnv(t)
	plain := newPkg("plain", "1.0.0")
	plain.readme = "# plain"
	plain.manifest = map[string]any{"dependencies": map[string]string{"dep": "^1.0.0"}, "keywords": []string{"k"},
		"scripts": map[string]string{"postinstall": "node x.js", "test": "true"}, "license": "MIT"}
	w := e.publish("local", plain, http.StatusOK)
	if r := jsonOf[okResponse](t, w); !r.OK || r.ID != "plain" || r.Rev == "" {
		t.Errorf("publish response %+v", r)
	}
	scoped := newPkg("@acme/lib", "2.0.0-beta.1")
	scoped.tags = []string{"next"}
	e.publish("local", scoped, http.StatusOK)

	full := e.packument("local", "plain", false)
	if full.ID != "plain" || full.Name != "plain" || full.Rev == "" || full.Readme != "# plain" {
		t.Errorf("full packument %+v", full)
	}
	if full.Tags["latest"] != "1.0.0" || len(full.Tags) != 1 {
		t.Errorf("dist-tags %v", full.Tags)
	}
	v := full.Versions["1.0.0"]
	dist, _ := v["dist"].(map[string]any)
	if dist["tarball"] != testBase+"/npm/local/plain/-/plain-1.0.0.tgz" || dist["integrity"] != plain.integrity() ||
		dist["shasum"] != plain.shasum() {
		t.Errorf("dist %v", dist)
	}
	if v["_id"] != "plain@1.0.0" || v["readme"] != nil || v["_npmUser"] == nil || v["license"] != "MIT" {
		t.Errorf("version %v", v)
	}
	if full.Time["1.0.0"] != "2026-10-01T12:00:00.000Z" || full.Time["created"] == "" || full.Time["modified"] == "" {
		t.Errorf("time %v", full.Time)
	}

	abbr := e.packument("local", "plain", true)
	av := abbr.Versions["1.0.0"]
	if abbr.Modified == "" || abbr.Readme != "" || av["hasInstallScript"] != true || av["dependencies"] == nil ||
		av["keywords"] != nil || av["scripts"] != nil || av["description"] != nil {
		t.Errorf("abbreviated %+v", abbr)
	}
	w = e.expect("GET", "/npm/local/plain", nil, http.StatusOK, "Accept", "application/vnd.npm.install-v1+json")
	if ct := w.Header().Get("Content-Type"); ct != mtAbbreviated {
		t.Errorf("abbreviated Content-Type %q", ct)
	}
	if cc := w.Header().Get("Cache-Control"); cc != "private, max-age=0, must-revalidate" {
		t.Errorf("Cache-Control %q", cc)
	}
	// A client revalidating its copy gets 304.
	e.expect("GET", "/npm/local/plain", nil, http.StatusNotModified, "Accept", mtAbbreviated, "If-None-Match", w.Header().Get("ETag"))

	// Scoped names are accepted encoded and plain.
	for _, path := range []string{"/npm/local/@acme%2flib", "/npm/local/@acme%2Flib", "/npm/local/@acme/lib"} {
		p := jsonOf[testPackument](t, e.expect("GET", path, nil, http.StatusOK))
		if p.Tags["next"] != "2.0.0-beta.1" || p.Tags["latest"] != "2.0.0-beta.1" {
			t.Errorf("%s: dist-tags %v", path, p.Tags)
		}
		dist, _ := p.Versions["2.0.0-beta.1"]["dist"].(map[string]any)
		if dist["tarball"] != testBase+"/npm/local/@acme/lib/-/lib-2.0.0-beta.1.tgz" {
			t.Errorf("%s: tarball %v", path, dist["tarball"])
		}
	}

	// Tarballs.
	for _, c := range []struct {
		path string
		want []byte
	}{
		{"/npm/local/plain/-/plain-1.0.0.tgz", plain.tarball},
		{"/npm/local/@acme/lib/-/lib-2.0.0-beta.1.tgz", scoped.tarball},
		{"/npm/local/@acme%2flib/-/lib-2.0.0-beta.1.tgz", scoped.tarball},
	} {
		w := e.expect("GET", c.path, nil, http.StatusOK)
		if !bytes.Equal(w.Body.Bytes(), c.want) || w.Header().Get("Cache-Control") != "private, max-age=31536000, immutable" {
			t.Errorf("GET %s: %q %v", c.path, w.Body, w.Header())
		}
	}
	w = e.expect("HEAD", "/npm/local/plain/-/plain-1.0.0.tgz", nil, http.StatusOK)
	if w.Header().Get("Content-Length") != fmt.Sprint(len(plain.tarball)) || w.Body.Len() != 0 {
		t.Errorf("HEAD: %v %q", w.Header(), w.Body)
	}
	for _, path := range []string{"/npm/local/plain/-/plain-9.0.0.tgz", "/npm/local/plain/-/other-1.0.0.tgz",
		"/npm/local/plain/-/plain-1.0.0.zip", "/npm/local/missing/-/missing-1.0.0.tgz"} {
		e.expect("GET", path, nil, http.StatusNotFound)
	}

	// One version, by version or dist-tag.
	if v := jsonOf[map[string]any](t, e.expect("GET", "/npm/local/plain/1.0.0", nil, http.StatusOK)); v["version"] != "1.0.0" {
		t.Errorf("version doc %v", v)
	}
	if v := jsonOf[map[string]any](t, e.expect("GET", "/npm/local/@acme%2flib/next", nil, http.StatusOK)); v["version"] != "2.0.0-beta.1" {
		t.Errorf("tagged version doc %v", v)
	}
	e.expect("GET", "/npm/local/plain/9.9.9", nil, http.StatusNotFound)

	// Other repositories and other formats do not have it.
	e.expect("GET", "/npm/open/plain", nil, http.StatusNotFound)
	if msg := errorOf(t, e.expect("GET", "/npm/oci/plain", nil, http.StatusNotFound)); !strings.Contains(msg, "not an npm repository") {
		t.Errorf("other format: %q", msg)
	}
	e.expect("GET", "/npm/nowhere/plain", nil, http.StatusNotFound)
	e.expect("GET", "/npm/local/missing", nil, http.StatusNotFound)

	if got := e.metric(`flint_npm_publishes_total{repository="local"}`); got != "2" {
		t.Errorf("publishes metric %q", got)
	}
	if got := e.metric(`flint_npm_publish_bytes_total{repository="local"}`); got != fmt.Sprint(len(plain.tarball)+len(scoped.tarball)) {
		t.Errorf("publish bytes metric %q", got)
	}
}

// TestPublishAnonymous checks the caching of a repository anyone may
// pull from.
func TestPublishAnonymous(t *testing.T) {
	e := newEnv(t)
	e.publish("open", newPkg("pub", "1.0.0"), http.StatusOK)
	if cc := e.expect("GET", "/npm/open/pub", nil, http.StatusOK).Header().Get("Cache-Control"); cc != "public, max-age=0, must-revalidate" {
		t.Errorf("packument Cache-Control %q", cc)
	}
	if cc := e.expect("GET", "/npm/open/pub/-/pub-1.0.0.tgz", nil, http.StatusOK).Header().Get("Cache-Control"); cc != "public, max-age=31536000, immutable" {
		t.Errorf("tarball Cache-Control %q", cc)
	}
}

// TestPublishValidation checks the publishes refused.
func TestPublishValidation(t *testing.T) {
	type mod func(p *pkg, body map[string]any)
	version := func(body map[string]any) map[string]any {
		for _, v := range body["versions"].(map[string]any) {
			return v.(map[string]any)
		}
		return nil
	}
	for _, c := range []struct {
		name   string
		pkg    *pkg
		mod    mod
		status int
		msg    string
	}{
		{"uppercase name", newPkg("Upper", "1.0.0"), nil, 400, "invalid package name"},
		{"leading dot", newPkg(".dot", "1.0.0"), nil, 400, "invalid package name"},
		{"special character", newPkg("bang!", "1.0.0"), nil, 400, "invalid package name"},
		{"long name", newPkg(strings.Repeat("a", 215), "1.0.0"), nil, 400, "invalid package name"},
		{"bad version", newPkg("p", "1.0"), nil, 400, "invalid version"},
		{"build metadata", newPkg("p", "1.0.0+build"), nil, 400, "invalid version"},
		{"leading zero", newPkg("p", "01.0.0"), nil, 400, "invalid version"},
		{"name mismatch", newPkg("p", "1.0.0"), func(_ *pkg, b map[string]any) { b["name"] = "q" }, 400, "not the package"},
		{"id mismatch", newPkg("p", "1.0.0"), func(_ *pkg, b map[string]any) { b["_id"] = "q" }, 400, "not the package"},
		{"manifest name", newPkg("p", "1.0.0"), func(_ *pkg, b map[string]any) { version(b)["name"] = "q" }, 400, "names q@1.0.0"},
		{"manifest version", newPkg("p", "1.0.0"), func(_ *pkg, b map[string]any) { version(b)["version"] = "1.0.1" }, 400, "names p@1.0.1"},
		{"two versions", newPkg("p", "1.0.0"), func(_ *pkg, b map[string]any) {
			b["versions"].(map[string]any)["2.0.0"] = map[string]any{"name": "p", "version": "2.0.0"}
		}, 400, "exactly one version"},
		{"wrong integrity", newPkg("p", "1.0.0"), func(_ *pkg, b map[string]any) {
			version(b)["dist"].(map[string]any)["integrity"] = newPkg("p", "9.9.9").integrity()
		}, 400, "does not match dist.integrity"},
		{"bad integrity", newPkg("p", "1.0.0"), func(_ *pkg, b map[string]any) {
			version(b)["dist"].(map[string]any)["integrity"] = "nonsense"
		}, 400, "not a subresource integrity"},
		{"wrong shasum", newPkg("p", "1.0.0"), func(_ *pkg, b map[string]any) {
			version(b)["dist"].(map[string]any)["shasum"] = newPkg("p", "9.9.9").shasum()
		}, 400, "does not match dist.shasum"},
		{"wrong length", newPkg("p", "1.0.0"), func(p *pkg, b map[string]any) {
			b["_attachments"].(map[string]any)["p-1.0.0.tgz"].(map[string]any)["length"] = 1
		}, 400, "its length says 1"},
		{"bad base64", newPkg("p", "1.0.0"), func(p *pkg, b map[string]any) {
			b["_attachments"].(map[string]any)["p-1.0.0.tgz"].(map[string]any)["data"] = "!!!"
		}, 400, "not valid base64"},
		{"no data", newPkg("p", "1.0.0"), func(p *pkg, b map[string]any) {
			delete(b["_attachments"].(map[string]any)["p-1.0.0.tgz"].(map[string]any), "data")
		}, 400, "has no data"},
		{"unexpected attachment", newPkg("p", "1.0.0"), func(p *pkg, b map[string]any) {
			b["_attachments"].(map[string]any)["p-2.0.0.tgz"] = b["_attachments"].(map[string]any)["p-1.0.0.tgz"]
			delete(b["_attachments"].(map[string]any), "p-1.0.0.tgz")
		}, 400, "unexpected attachment"},
		{"three attachments", newPkg("p", "1.0.0"), func(p *pkg, b map[string]any) {
			a := b["_attachments"].(map[string]any)
			a["x.tgz"], a["y.tgz"] = a["p-1.0.0.tgz"], a["p-1.0.0.tgz"]
		}, 400, "one tarball"},
		{"invalid tag", newPkg("p", "1.0.0"), func(_ *pkg, b map[string]any) { b["dist-tags"] = map[string]string{"v1": "1.0.0"} }, 400, "invalid dist-tag"},
		{"tag elsewhere", newPkg("p", "1.0.0"), func(_ *pkg, b map[string]any) { b["dist-tags"] = map[string]string{"latest": "0.9.0"} }, 400, "points at 0.9.0"},
		{"bad provenance", newPkg("p", "1.0.0"), func(_ *pkg, b map[string]any) {
			b["_attachments"].(map[string]any)["p-1.0.0.sigstore"] = map[string]any{"data": "{}"}
		}, 400, "provenance bundle cannot be read"},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t)
			var body map[string]any
			json.Unmarshal(c.pkg.body(), &body)
			if c.mod != nil {
				c.mod(c.pkg, body)
			}
			w := e.expect("PUT", "/npm/local/"+escapeName(c.pkg.name), bytes.NewReader(mustJSON(body)), c.status)
			if msg := errorOf(t, w); !strings.Contains(msg, c.msg) {
				t.Errorf("error %q, want %q", msg, c.msg)
			}
			e.expect("GET", "/npm/local/"+escapeName(c.pkg.name), nil, http.StatusNotFound)
		})
	}
}

// TestPublishBodies checks bodies that are not valid JSON, and that the
// tarball is streamed whatever the order of the fields.
func TestPublishBodies(t *testing.T) {
	e := newEnv(t)
	for _, body := range []string{"", "[]", "{", `{"name": "p"`, `{"name": "p"} x`, `{"_attachments": 5}`,
		`{"a": tru}`, `{"a": "\x01"}`, `{"a": "\q"}`, `{"a": [1,]}`} {
		if w := e.do("PUT", "/npm/local/p", strings.NewReader(body)); w.Code != http.StatusBadRequest {
			t.Errorf("PUT %q: %d %s", body, w.Code, w.Body)
		}
	}

	// Attachments first, escapes in the base64 data and elsewhere, and a
	// tarball larger than the buffers.
	p := newPkg("p", "1.0.0")
	p.tarball = bytes.Repeat([]byte("0123456789abcdef"), 1<<16)
	data := strings.ReplaceAll(base64.StdEncoding.EncodeToString(p.tarball), "/", `\/`)
	body := `{"_attachments": {"p-1.0.0.tgz": {"length": ` + fmt.Sprint(len(p.tarball)) + `, "data": "` + data + `"}},
		"name": "p", "versions": {"1.0.0": {"name": "p", "version": "1.0.0", "description": "café 😀 \"q\"",
		"dist": {"integrity": "` + p.integrity() + `"}}}}`
	e.expect("PUT", "/npm/local/p", strings.NewReader(body), http.StatusOK)
	got := e.expect("GET", "/npm/local/p/-/p-1.0.0.tgz", nil, http.StatusOK)
	if !bytes.Equal(got.Body.Bytes(), p.tarball) {
		t.Error("the tarball differs")
	}
	if d := e.packument("local", "p", false).Versions["1.0.0"]["description"]; d != "café 😀 \"q\"" {
		t.Errorf("description %q", d)
	}

	// A gzip-compressed body.
	q := newPkg("q", "1.0.0")
	var zb bytes.Buffer
	zw := gzip.NewWriter(&zb)
	zw.Write(q.body())
	zw.Close()
	e.expect("PUT", "/npm/local/q", &zb, http.StatusOK, "Content-Encoding", "gzip")
}

// TestPublishDuplicate checks that a version is never published twice,
// not even after it is unpublished, and that of concurrent publishes of
// one version exactly one succeeds.
func TestPublishDuplicate(t *testing.T) {
	e := newEnv(t)
	p := newPkg("p", "1.0.0")
	e.publish("local", p, http.StatusOK)
	if msg := errorOf(t, e.publish("local", p, http.StatusConflict)); !strings.Contains(msg, "previously published") {
		t.Errorf("duplicate: %q", msg)
	}
	other := newPkg("p", "1.0.0")
	other.tarball = []byte("other bytes")
	e.publish("local", other, http.StatusConflict)
	// The same version in another repository is another package.
	e.publish("open", p, http.StatusOK)

	e.publish("local", newPkg("p", "2.0.0"), http.StatusOK)
	rev := e.rawPackument("local", "p")["_rev"].(string)
	e.expect("DELETE", "/npm/local/p/-/p-1.0.0.tgz/-rev/"+rev, nil, http.StatusOK)
	if msg := errorOf(t, e.publish("local", p, http.StatusConflict)); !strings.Contains(msg, "was unpublished") {
		t.Errorf("after unpublish: %q", msg)
	}

	var wg sync.WaitGroup
	codes := make([]int, 8)
	for i := range codes {
		wg.Go(func() {
			q := newPkg("race", "1.0.0")
			q.tarball = []byte(fmt.Sprint("race ", i))
			codes[i] = e.do("PUT", "/npm/local/race", bytes.NewReader(q.body())).Code
		})
	}
	wg.Wait()
	slices.Sort(codes)
	if codes[0] != http.StatusOK || codes[1] != http.StatusConflict || codes[len(codes)-1] != http.StatusConflict {
		t.Errorf("concurrent publishes: %v", codes)
	}
}

// TestDistTags checks dist-tags: set by publishing and through the
// dist-tag endpoints, never pointing at a missing version, and "latest"
// always present.
func TestDistTags(t *testing.T) {
	e := newEnv(t)
	first := newPkg("@s/p", "1.0.0")
	first.tags = []string{"beta"}
	e.publish("local", first, http.StatusOK)
	tags := func() map[string]string {
		return jsonOf[map[string]string](t, e.expect("GET", "/npm/local/-/package/@s%2fp/dist-tags", nil, http.StatusOK))
	}
	// The first publish sets latest too.
	if got := tags(); got["beta"] != "1.0.0" || got["latest"] != "1.0.0" {
		t.Errorf("after the first publish: %v", got)
	}
	second := newPkg("@s/p", "2.0.0")
	second.tags = []string{"next"}
	e.publish("local", second, http.StatusOK)
	if got := tags(); got["latest"] != "1.0.0" || got["next"] != "2.0.0" {
		t.Errorf("after a publish with --tag: %v", got)
	}

	e.auth.reset()
	w := e.expect("PUT", "/npm/local/-/package/@s%2fp/dist-tags/stable", strings.NewReader(`"2.0.0"`), http.StatusOK)
	if got := jsonOf[map[string]string](t, w); got["stable"] != "2.0.0" {
		t.Errorf("PUT response %v", got)
	}
	if calls := e.auth.reset(); !slices.Equal(calls, []string{"local:push"}) {
		t.Errorf("dist-tag add authorized %v", calls)
	}
	e.expect("PUT", "/npm/local/-/package/@s%2fp/dist-tags/latest", strings.NewReader(`"2.0.0"`), http.StatusOK)
	e.expect("DELETE", "/npm/local/-/package/@s%2fp/dist-tags/beta", nil, http.StatusOK)
	if got := tags(); len(got) != 3 || got["latest"] != "2.0.0" || got["stable"] != "2.0.0" || got["next"] != "2.0.0" {
		t.Errorf("after changes: %v", got)
	}
	if p := e.packument("local", "@s/p", true); p.Tags["latest"] != "2.0.0" {
		t.Errorf("the packument's dist-tags %v", p.Tags)
	}

	for _, c := range []struct {
		method, path, body string
		status             int
	}{
		{"DELETE", "/npm/local/-/package/@s%2fp/dist-tags/latest", "", http.StatusBadRequest},
		{"DELETE", "/npm/local/-/package/@s%2fp/dist-tags/missing", "", http.StatusNotFound},
		{"PUT", "/npm/local/-/package/@s%2fp/dist-tags/other", `"9.9.9"`, http.StatusNotFound},
		{"PUT", "/npm/local/-/package/@s%2fp/dist-tags/1.x", `"1.0.0"`, http.StatusBadRequest},
		{"PUT", "/npm/local/-/package/@s%2fp/dist-tags/other", `1`, http.StatusBadRequest},
		{"PUT", "/npm/local/-/package/@s%2fp/dist-tags/latest", `""`, http.StatusBadRequest},
		{"PUT", "/npm/local/-/package/@s%2fp/dist-tags/latest", `null`, http.StatusBadRequest},
		{"PUT", "/npm/local/-/package/@s%2fp/dist-tags/next", `""`, http.StatusBadRequest},
		{"PUT", "/npm/local/-/package/missing/dist-tags/other", `"1.0.0"`, http.StatusNotFound},
		{"GET", "/npm/local/-/package/missing/dist-tags", "", http.StatusNotFound},
		{"GET", "/npm/local/-/package/@s%2fp/dist-tags/x/y", "", http.StatusNotFound},
		{"POST", "/npm/local/-/package/@s%2fp/dist-tags/x", "", http.StatusMethodNotAllowed},
	} {
		if w := e.do(c.method, c.path, strings.NewReader(c.body)); w.Code != c.status {
			t.Errorf("%s %s %s: %d %s, want %d", c.method, c.path, c.body, w.Code, w.Body, c.status)
		}
	}
	if got := tags(); len(got) != 3 || got["latest"] != "2.0.0" || got["next"] != "2.0.0" {
		t.Errorf("after refused changes: %v", got)
	}
	e.auth.setDeny(ActionPush)
	e.expect("PUT", "/npm/local/-/package/@s%2fp/dist-tags/other", strings.NewReader(`"1.0.0"`), http.StatusForbidden)
}

// TestReadmeOfLatest checks that the packument serves the latest
// version's readme: publishing an older line with --tag leaves it, and
// publishing a new latest replaces it.
func TestReadmeOfLatest(t *testing.T) {
	e := newEnv(t)
	for _, c := range []struct {
		version, readme, tag, want string
	}{
		{"1.0.0", "# one", "", "# one"},
		{"2.0.0", "# two", "", "# two"},
		{"1.0.5", "# one, maintained", "maint", "# two"},
		{"3.0.0-rc.1", "# three", "next", "# two"},
		{"2.1.0", "", "", ""},
	} {
		p := newPkg("p", c.version)
		p.readme = c.readme
		if c.tag != "" {
			p.tags = []string{c.tag}
		}
		e.publish("local", p, http.StatusOK)
		if got := e.packument("local", "p", false).Readme; got != c.want {
			t.Errorf("after publishing %s: readme %q, want %q", c.version, got, c.want)
		}
	}
}

// TestDeprecate edits deprecation messages as npm deprecate does: it
// reads the packument with ?write=true and sends it back edited.
func TestDeprecate(t *testing.T) {
	e := newEnv(t)
	e.publish("local", newPkg("p", "1.0.0"), http.StatusOK)
	e.publish("local", newPkg("p", "1.1.0"), http.StatusOK)

	deprecate := func(msg string, versions ...string) *map[string]any {
		doc := e.rawPackument("local", "p")
		for _, v := range versions {
			doc["versions"].(map[string]any)[v].(map[string]any)["deprecated"] = msg
		}
		return &doc
	}
	e.auth.reset()
	doc := deprecate("use 1.1.0", "1.0.0")
	e.expect("PUT", "/npm/local/p", bytes.NewReader(mustJSON(*doc)), http.StatusOK)
	if calls := e.auth.reset(); !slices.Equal(calls, []string{"local:pull", "local:push"}) {
		t.Errorf("deprecate authorized %v", calls)
	}
	abbr := e.packument("local", "p", true)
	if abbr.Versions["1.0.0"]["deprecated"] != "use 1.1.0" || abbr.Versions["1.1.0"]["deprecated"] != nil {
		t.Errorf("after deprecate: %v", abbr.Versions)
	}
	// The same edit again, now of a stale revision.
	e.expect("PUT", "/npm/local/p", bytes.NewReader(mustJSON(*doc)), http.StatusConflict)

	// Undeprecating sends an empty message.
	e.expect("PUT", "/npm/local/p", bytes.NewReader(mustJSON(*deprecate("", "1.0.0"))), http.StatusOK)
	if d := e.packument("local", "p", false).Versions["1.0.0"]["deprecated"]; d != nil {
		t.Errorf("after undeprecate: %v", d)
	}

	// Any other change to a version is refused, and so is adding one.
	for name, edit := range map[string]func(doc map[string]any){
		"field": func(doc map[string]any) {
			doc["versions"].(map[string]any)["1.0.0"].(map[string]any)["main"] = "other.js"
		},
		"new field": func(doc map[string]any) {
			doc["versions"].(map[string]any)["1.0.0"].(map[string]any)["scripts"] = map[string]string{"install": "evil"}
		},
		"removed field": func(doc map[string]any) {
			delete(doc["versions"].(map[string]any)["1.0.0"].(map[string]any), "main")
		},
		"new version": func(doc map[string]any) {
			doc["versions"].(map[string]any)["3.0.0"] = map[string]any{"name": "p", "version": "3.0.0"}
		},
		"no versions": func(doc map[string]any) { delete(doc, "versions") },
		"bad message": func(doc map[string]any) {
			doc["versions"].(map[string]any)["1.0.0"].(map[string]any)["deprecated"] = 5
		},
	} {
		doc := e.rawPackument("local", "p")
		edit(doc)
		if w := e.do("PUT", "/npm/local/p", bytes.NewReader(mustJSON(doc))); w.Code != http.StatusBadRequest {
			t.Errorf("%s: %d %s", name, w.Code, w.Body)
		}
	}

	// Leaving a version out without a revision is refused.
	doc = deprecate("x", "1.0.0")
	delete(*doc, "_rev")
	delete((*doc)["versions"].(map[string]any), "1.1.0")
	e.expect("PUT", "/npm/local/p", bytes.NewReader(mustJSON(*doc)), http.StatusBadRequest)

	// Deprecating needs write.
	e.auth.setDeny(ActionPush)
	e.expect("PUT", "/npm/local/p", bytes.NewReader(mustJSON(*deprecate("x", "1.0.0"))), http.StatusForbidden)
}

// TestUnpublish unpublishes versions and a whole package as npm unpublish
// does.
func TestUnpublish(t *testing.T) {
	e := newEnv(t)
	for _, v := range []string{"1.0.0", "1.1.0", "2.0.0-rc.1"} {
		p := newPkg("p", v)
		if v == "2.0.0-rc.1" {
			p.tags = []string{"next"}
		}
		e.publish("local", p, http.StatusOK)
	}
	e.expect("PUT", "/npm/local/-/package/p/dist-tags/old", strings.NewReader(`"1.1.0"`), http.StatusOK)

	// npm unpublish p@1.1.0: PUT the packument without the version to its
	// revision, then DELETE the tarball at the new revision.
	doc := e.rawPackument("local", "p")
	delete(doc["versions"].(map[string]any), "1.1.0")
	e.auth.setDeny(ActionDelete)
	e.expect("PUT", "/npm/local/p/-rev/"+doc["_rev"].(string), bytes.NewReader(mustJSON(doc)), http.StatusForbidden)
	e.auth.setDeny()
	e.auth.reset()
	e.expect("PUT", "/npm/local/p/-rev/"+doc["_rev"].(string), bytes.NewReader(mustJSON(doc)), http.StatusOK)
	if calls := e.auth.reset(); !slices.Equal(calls, []string{"local:push", "local:delete"}) {
		t.Errorf("unpublish authorized %v", calls)
	}
	// The revision is stale now.
	e.expect("PUT", "/npm/local/p/-rev/"+doc["_rev"].(string), bytes.NewReader(mustJSON(doc)), http.StatusConflict)
	rev := e.rawPackument("local", "p")["_rev"].(string)
	e.expect("DELETE", "/npm/local/p/-/p-1.1.0.tgz/-rev/"+rev, nil, http.StatusOK)
	// The same path below the registry's own path, as npm may resolve it.
	e.expect("DELETE", "/npm/local/npm/local/p/-/p-1.1.0.tgz/-rev/"+rev, nil, http.StatusOK)

	p := e.packument("local", "p", false)
	if _, ok := p.Versions["1.1.0"]; ok || len(p.Versions) != 2 {
		t.Errorf("versions after unpublish %v", p.Versions)
	}
	// latest moved to the highest release left, and old went with 1.1.0.
	if p.Tags["latest"] != "1.0.0" || p.Tags["next"] != "2.0.0-rc.1" || p.Tags["old"] != "" {
		t.Errorf("dist-tags after unpublish %v", p.Tags)
	}
	if _, ok := p.Time["1.1.0"]; ok {
		t.Errorf("time %v", p.Time)
	}
	e.expect("GET", "/npm/local/p/-/p-1.1.0.tgz", nil, http.StatusNotFound)

	// Deleting a live version's tarball unpublishes it.
	rev = e.rawPackument("local", "p")["_rev"].(string)
	e.expect("DELETE", "/npm/local/p/-/p-2.0.0-rc.1.tgz/-rev/"+rev, nil, http.StatusOK)
	if p := e.packument("local", "p", true); len(p.Versions) != 1 || len(p.Tags) != 1 || p.Tags["latest"] != "1.0.0" {
		t.Errorf("after the tarball delete %+v", p)
	}
	rev = e.rawPackument("local", "p")["_rev"].(string)
	e.expect("DELETE", "/npm/local/p/-/p-9.0.0.tgz/-rev/"+rev, nil, http.StatusNotFound)

	// npm unpublish p --force: DELETE the package at its revision.
	e.expect("DELETE", "/npm/local/p/-rev/1-x", nil, http.StatusConflict)
	e.expect("DELETE", "/npm/local/p/-rev/nonsense", nil, http.StatusConflict)
	rev = e.rawPackument("local", "p")["_rev"].(string)
	e.auth.setDeny(ActionDelete)
	e.expect("DELETE", "/npm/local/p/-rev/"+rev, nil, http.StatusForbidden)
	e.auth.setDeny()
	e.expect("DELETE", "/npm/local/p/-rev/"+rev, nil, http.StatusOK)
	e.expect("GET", "/npm/local/p", nil, http.StatusNotFound)
	e.expect("GET", "/npm/local/-/package/p/dist-tags", nil, http.StatusNotFound)
	e.expect("DELETE", "/npm/local/p/-rev/"+rev, nil, http.StatusConflict)

	// The repository keeps owning the name: unpublished versions stay
	// taken, and new ones can be published.
	e.publish("local", newPkg("p", "1.0.0"), http.StatusConflict)
	e.publish("local", newPkg("p", "3.0.0"), http.StatusOK)
	if p := e.packument("local", "p", true); len(p.Versions) != 1 || p.Tags["latest"] != "3.0.0" {
		t.Errorf("after publishing again %+v", p)
	}
}

// TestLogin checks npm's legacy login and whoami.
func TestLogin(t *testing.T) {
	e := newEnv(t)
	login := func(user, body string) *httpResult {
		w := e.do("PUT", "/npm/local/-/user/org.couchdb.user:"+user, strings.NewReader(body))
		return &httpResult{w.Code, w.Body.String()}
	}
	got := login("alice", `{"_id": "org.couchdb.user:alice", "name": "alice", "password": "alice-password", "type": "user", "roles": []}`)
	if got.code != http.StatusCreated || !strings.Contains(got.body, `"token":"flint_minted"`) {
		t.Errorf("login: %+v", got)
	}
	for _, c := range []struct {
		user, body string
		status     int
	}{
		{"alice", `{"name": "alice", "password": "wrong"}`, http.StatusUnauthorized},
		{"bob", `{"name": "alice", "password": "alice-password"}`, http.StatusBadRequest},
		{"alice", `{"name": "alice"}`, http.StatusBadRequest},
		{"alice", `not json`, http.StatusBadRequest},
	} {
		if got := login(c.user, c.body); got.code != c.status {
			t.Errorf("login %s %s: %+v, want %d", c.user, c.body, got, c.status)
		}
	}
	// The user name may come from the URL alone.
	if got := login("alice", `{"password": "alice-password"}`); got.code != http.StatusCreated {
		t.Errorf("login without a name in the body: %+v", got)
	}
	e.expect("GET", "/npm/local/-/user/org.couchdb.user:alice", nil, http.StatusMethodNotAllowed)
	// The web login is not found, so npm falls back to the legacy one.
	e.expect("POST", "/npm/local/-/v1/login", nil, http.StatusNotFound)

	if got := jsonOf[map[string]string](t, e.expect("GET", "/npm/local/-/whoami", nil, http.StatusOK, "X-Test-User", "bob")); got["username"] != "bob" {
		t.Errorf("whoami %v", got)
	}
	e.auth.reset()
	e.expect("GET", "/npm/local/-/whoami", nil, http.StatusUnauthorized, "X-Test-Anonymous", "1")
	if calls := e.auth.reset(); !slices.Equal(calls, []string{":"}) {
		t.Errorf("whoami authorized %v", calls)
	}

	e.login = nil
	e.restart()
	if got := login("alice", `{"password": "alice-password"}`); got.code != http.StatusNotFound {
		t.Errorf("login without Login: %+v", got)
	}
}

type httpResult struct {
	code int
	body string
}

// TestAuthorization checks the action each route asks for, and that a
// refusal is passed on.
func TestAuthorization(t *testing.T) {
	e := newEnv(t)
	e.publish("local", newPkg("p", "1.0.0"), http.StatusOK)
	for _, c := range []struct {
		method, path string
		want         string
	}{
		{"GET", "/npm/local/", "local:pull"},
		{"GET", "/npm/local/p", "local:pull"},
		{"GET", "/npm/local/p/1.0.0", "local:pull"},
		{"GET", "/npm/local/p/-/p-1.0.0.tgz", "local:pull"},
		{"PUT", "/npm/local/p", "local:push"},
		{"DELETE", "/npm/local/p/-rev/1", "local:delete"},
		{"DELETE", "/npm/local/p/-/p-1.0.0.tgz/-rev/1", "local:delete"},
		{"GET", "/npm/local/-/package/p/dist-tags", "local:pull"},
		{"PUT", "/npm/local/-/package/p/dist-tags/x", "local:push"},
		{"GET", "/npm/local/-/v1/search?text=p", "local:pull"},
		{"POST", "/npm/local/-/npm/v1/security/advisories/bulk", "local:pull"},
		{"GET", "/npm/local/-/npm/v1/keys", "local:pull"},
		{"GET", "/npm/local/-/npm/v1/attestations/p@1.0.0", "local:pull"},
	} {
		e.auth.reset()
		w := e.do(c.method, c.path, strings.NewReader("{}"), "X-Test-Anonymous", "1")
		if w.Code != http.StatusUnauthorized || w.Header().Get("WWW-Authenticate") != "" {
			t.Errorf("%s %s anonymous: %d %v", c.method, c.path, w.Code, w.Header())
		}
		if calls := e.auth.reset(); !slices.Equal(calls, []string{c.want}) {
			t.Errorf("%s %s authorized %v, want %s", c.method, c.path, calls, c.want)
		}
	}
	// Ping needs nothing.
	e.expect("GET", "/npm/local/-/ping", nil, http.StatusOK, "X-Test-Anonymous", "1")
	if calls := e.auth.reset(); len(calls) != 0 {
		t.Errorf("ping authorized %v", calls)
	}
}

// TestEndpoints checks search, audit, keys, attestations, and the paths
// that are not found.
func TestEndpoints(t *testing.T) {
	e := newEnv(t)
	for _, n := range []string{"alpha", "beta-alpha", "@team/alpha-tools", "gamma"} {
		p := newPkg(n, "1.0.0")
		p.manifest = map[string]any{"keywords": []string{"kw"}}
		e.publish("local", p, http.StatusOK)
	}
	e.advance(time.Hour)
	e.publish("local", newPkg("unpublished", "1.0.0"), http.StatusOK)
	e.expect("DELETE", "/npm/local/unpublished/-rev/"+e.rawPackument("local", "unpublished")["_rev"].(string), nil, http.StatusOK)

	type searchResult struct {
		Objects []struct {
			Package map[string]any `json:"package"`
		} `json:"objects"`
		Total int `json:"total"`
	}
	search := func(q string) (names []string, total int) {
		res := jsonOf[searchResult](t, e.expect("GET", "/npm/local/-/v1/search?"+q, nil, http.StatusOK))
		for _, o := range res.Objects {
			names = append(names, o.Package["name"].(string))
		}
		return names, res.Total
	}
	if names, total := search("text=alpha"); !slices.Equal(names, []string{"@team/alpha-tools", "alpha", "beta-alpha"}) || total != 3 {
		t.Errorf("search alpha: %v %d", names, total)
	}
	if names, total := search("text=ALPHA+keywords:x&size=1&from=1"); !slices.Equal(names, []string{"alpha"}) || total != 3 {
		t.Errorf("search page: %v %d", names, total)
	}
	if names, _ := search("text=unpublished"); len(names) != 0 {
		t.Errorf("an unpublished package is found: %v", names)
	}
	res := jsonOf[searchResult](t, e.expect("GET", "/npm/local/-/v1/search?text=gamma", nil, http.StatusOK))
	if pkg := res.Objects[0].Package; pkg["version"] != "1.0.0" || pkg["description"] != "the gamma package" ||
		pkg["publisher"].(map[string]any)["username"] != "alice" || pkg["scope"] != "unscoped" {
		t.Errorf("search result %v", pkg)
	}

	// Audit, with the gzip-compressed body npm sends.
	var zb bytes.Buffer
	zw := gzip.NewWriter(&zb)
	zw.Write([]byte(`{"alpha": ["1.0.0"]}`))
	zw.Close()
	if w := e.expect("POST", "/npm/local/-/npm/v1/security/advisories/bulk", &zb, http.StatusOK, "Content-Encoding", "gzip"); w.Body.String() != "{}\n" {
		t.Errorf("audit %q", w.Body)
	}
	e.expect("POST", "/npm/local/-/npm/v1/security/advisories/bulk", strings.NewReader("nope"), http.StatusBadRequest)
	e.expect("POST", "/npm/local/-/npm/v1/security/advisories/bulk", strings.NewReader("{}"), http.StatusUnsupportedMediaType,
		"Content-Encoding", "br")

	if w := e.expect("GET", "/npm/local/-/npm/v1/keys", nil, http.StatusOK); w.Body.String() != "{\"keys\":[]}\n" {
		t.Errorf("keys %q", w.Body)
	}
	if w := e.expect("GET", "/npm/local/-/ping", nil, http.StatusOK); w.Body.String() != "{}\n" {
		t.Errorf("ping %q", w.Body)
	}
	for _, path := range []string{"/npm/local/-/nothing", "/npm/local/-/npm/v1/attestations/alpha@1.0.0",
		"/npm/local/-/npm/v1/attestations/alpha", "/npm/local/a/b/c", "/npm/local/@scope", "/npm/local/.hidden"} {
		e.expect("GET", path, nil, http.StatusNotFound)
	}
	e.expect("GET", "/npm/local", nil, http.StatusMovedPermanently)
	e.expect("POST", "/npm/local/alpha", nil, http.StatusMethodNotAllowed)
}

// TestProvenance publishes a version with a provenance bundle, as npm
// publish --provenance does, and serves it as its attestation.
func TestProvenance(t *testing.T) {
	e := newEnv(t)
	statement := `{"_type": "https://in-toto.io/Statement/v1", "predicateType": "https://slsa.dev/provenance/v1"}`
	bundle := `{"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json", "dsseEnvelope": {"payload": "` +
		base64.StdEncoding.EncodeToString([]byte(statement)) + `", "payloadType": "application/vnd.in-toto+json"}}`
	p := newPkg("@s/prov", "1.0.0")
	p.attachments = map[string]string{"@s/prov-1.0.0.sigstore": bundle}
	e.publish("local", p, http.StatusOK)

	dist, _ := e.packument("local", "@s/prov", true).Versions["1.0.0"]["dist"].(map[string]any)
	att, _ := dist["attestations"].(map[string]any)
	if att["url"] != testBase+"/npm/local/-/npm/v1/attestations/@s/prov@1.0.0" ||
		att["provenance"].(map[string]any)["predicateType"] != "https://slsa.dev/provenance/v1" {
		t.Errorf("dist.attestations %v", att)
	}
	var got struct {
		Attestations []struct {
			PredicateType string          `json:"predicateType"`
			Bundle        json.RawMessage `json:"bundle"`
		} `json:"attestations"`
	}
	w := e.expect("GET", "/npm/local/-/npm/v1/attestations/@s%2fprov@1.0.0", nil, http.StatusOK)
	var want bytes.Buffer
	json.Compact(&want, []byte(bundle))
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil || len(got.Attestations) != 1 ||
		got.Attestations[0].PredicateType != "https://slsa.dev/provenance/v1" || string(got.Attestations[0].Bundle) != want.String() {
		t.Errorf("attestations %s", w.Body)
	}
}

// TestRenderCache checks that a packument reflects every change at once,
// and that the in-memory renderings stay within their budget.
func TestRenderCache(t *testing.T) {
	e := newEnv(t)
	e.publish("local", newPkg("p", "1.0.0"), http.StatusOK)
	before := e.packument("local", "p", true)
	e.publish("local", newPkg("p", "1.1.0"), http.StatusOK)
	if after := e.packument("local", "p", true); len(after.Versions) != 2 || after.Tags["latest"] != "1.1.0" || len(before.Versions) != 1 {
		t.Errorf("before %v, after %v", before.Versions, after.Versions)
	}

	c := newRenderCache(1000)
	for _, k := range []string{"a", "b", "a", "c", "d", "e"} {
		if _, _, ok := c.get(k); !ok {
			c.put(k, make([]byte, 240))
		}
	}
	c.put("big", make([]byte, 300)) // over a quarter of the budget
	for k, want := range map[string]bool{"a": true, "b": false, "c": true, "d": true, "e": true, "big": false, "": false} {
		if _, _, ok := c.get(k); ok != want {
			t.Errorf("%q cached: %v", k, ok)
		}
	}
	if c.size > c.budget {
		t.Errorf("size %d over the budget %d", c.size, c.budget)
	}
}
