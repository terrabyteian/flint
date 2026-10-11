package cargo

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/terrabyteian/flint/internal/blob"
)

func TestConfig(t *testing.T) {
	e := newEnv(t)
	for _, tc := range []struct {
		repo string
		auth bool
	}{{"local", true}, {"team", false}, {"remote", true}, {"all", true}, {"open", false}} {
		w := e.get("/cargo/"+tc.repo+"/config.json", http.StatusOK)
		var c map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &c); err != nil {
			t.Fatal(err)
		}
		api := "http://example.com/cargo/" + tc.repo
		want := map[string]any{"dl": api + "/api/v1/crates", "api": api, "auth-required": tc.auth}
		if !reflect.DeepEqual(c, want) {
			t.Errorf("%s: config.json %v, want %v", tc.repo, c, want)
		}
		if w.Header().Get("ETag") == "" {
			t.Errorf("%s: config.json has no ETag", tc.repo)
		}
	}
	e.get("/cargo/pypi/config.json", http.StatusNotFound)
	e.get("/cargo/nope/config.json", http.StatusNotFound)
	if w := e.do("POST", "/cargo/local/config.json", nil); w.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST config.json: %d", w.Code)
	}
}

func TestPublish(t *testing.T) {
	e := newEnv(t)
	renamed := dep("rand_core", "^0.6")
	renamed["explicit_name_in_toml"] = "core2"
	renamed["registry"] = "https://github.com/rust-lang/crates.io-index"
	dev := dep("Base_Lib", "=1.0.0")
	dev["kind"] = "dev"
	dev["target"] = "cfg(unix)"
	dev["optional"] = true
	dev["features"] = []string{"std"}
	c := newCrate("My-Crate", "1.0.0+build.5", dep("serde", "^1"), renamed, dev)
	c.meta["features"] = map[string][]string{"default": {"std"}, "std": {}, "derive": {"dep:serde", "serde?/derive"}}
	c.meta["links"] = "z"
	c.meta["rust_version"] = "1.70"
	e.mustPublish("local", c)
	if got := e.auth.reset(); !slices.Equal(got, []string{"local:pull,push"}) {
		t.Errorf("authorized %v", got)
	}

	lines := e.index("local", "my-crate")
	if len(lines) != 1 {
		t.Fatalf("index lines %v", lines)
	}
	l := lines[0]
	want := map[string]any{
		"name": "My-Crate", "vers": "1.0.0+build.5", "cksum": c.sha256(), "yanked": false, "links": "z", "v": 2.0,
		"rust_version": "1.70", "pubtime": "2026-10-01T12:00:00Z",
		"features":  map[string]any{"default": []any{"std"}, "std": []any{}},
		"features2": map[string]any{"derive": []any{"dep:serde", "serde?/derive"}},
		"deps": []any{
			map[string]any{"name": "serde", "req": "^1", "features": []any{}, "optional": false, "default_features": true,
				"target": nil, "kind": "normal"},
			map[string]any{"name": "core2", "package": "rand_core", "req": "^0.6", "features": []any{}, "optional": false,
				"default_features": true, "target": nil, "kind": "normal", "registry": "https://github.com/rust-lang/crates.io-index"},
			map[string]any{"name": "Base_Lib", "req": "=1.0.0", "features": []any{"std"}, "optional": true,
				"default_features": true, "target": "cfg(unix)", "kind": "dev"},
		},
	}
	if !reflect.DeepEqual(l, want) {
		gb, _ := json.Marshal(l)
		wb, _ := json.Marshal(want)
		t.Errorf("index line\n %s\nwant\n %s", gb, wb)
	}

	w := e.get("/cargo/local/api/v1/crates/My-Crate/1.0.0+build.5/download", http.StatusOK)
	if !bytes.Equal(w.Body.Bytes(), c.body) {
		t.Error("the download is not the published .crate file")
	}
	if ct, cc := w.Header().Get("Content-Type"), w.Header().Get("Cache-Control"); ct != crateType || !strings.HasPrefix(cc, "private,") {
		t.Errorf("download headers %q %q", ct, cc)
	}
	w = e.do("HEAD", "/cargo/local/api/v1/crates/my-crate/1.0.0/download", nil)
	if w.Code != http.StatusOK || w.Header().Get("Content-Length") != itoa(len(c.body)) || w.Body.Len() != 0 {
		t.Errorf("HEAD download: %d %q", w.Code, w.Header().Get("Content-Length"))
	}
	e.get("/cargo/local/api/v1/crates/My-Crate/2.0.0/download", http.StatusNotFound)
	if e.metric(`flint_cargo_publishes_total{repository="local"}`) != "1" {
		t.Error("the publish was not counted")
	}

	// Only the spelling first published has an index file.
	e.get("/cargo/local/"+indexPath("my_crate"), http.StatusNotFound)
	e.get("/cargo/local/"+indexPath("other"), http.StatusNotFound)
	e.get("/cargo/local/my/cr/other", http.StatusNotFound)
	e.get("/cargo/local/zz/zz/My-Crate", http.StatusNotFound)
}

func itoa(n int) string { b, _ := json.Marshal(n); return string(b) }

func TestPublishRefused(t *testing.T) {
	e := newEnv(t)
	e.mustPublish("local", newCrate("foo-bar", "1.0.0"))
	for _, tc := range []struct {
		name   string
		c      crate
		status int
		msg    string
	}{
		{"duplicate", newCrate("foo-bar", "1.0.0"), http.StatusConflict, "already published"},
		{"build metadata", newCrate("foo-bar", "1.0.0+other"), http.StatusConflict, "already published"},
		{"other spelling", newCrate("Foo_Bar", "2.0.0"), http.StatusConflict, "was published as foo-bar"},
		{"invalid name", newCrate("1abc", "1.0.0"), http.StatusBadRequest, "invalid crate name"},
		{"invalid version", newCrate("abc", "1.0"), http.StatusBadRequest, "invalid version"},
		{"wrong directory", crate{newCrate("abc", "1.0.0").meta, crateFile("abc-1.0.1/", "Cargo.toml")}, http.StatusBadRequest, "is not in the directory abc-1.0.0/"},
		{"no Cargo.toml", crate{newCrate("abc", "1.0.0").meta, crateFile("abc-1.0.0/", "src/lib.rs")}, http.StatusBadRequest, "no abc-1.0.0/Cargo.toml"},
		{"not gzip", crate{newCrate("abc", "1.0.0").meta, []byte("not a crate")}, http.StatusBadRequest, "not gzip"},
	} {
		w := e.publish("local", tc.c)
		if w.Code != tc.status || !strings.Contains(w.Body.String(), tc.msg) {
			t.Errorf("%s: %d %s, want %d %q", tc.name, w.Code, w.Body, tc.status, tc.msg)
		}
		var res errorsObject
		if json.Unmarshal(w.Body.Bytes(), &res) != nil || len(res.Errors) != 1 {
			t.Errorf("%s: the error is not Cargo's errors object: %s", tc.name, w.Body)
		}
	}
	bad := dep("x", "")
	for _, tc := range []struct {
		name string
		body []byte
		msg  string
	}{
		{"empty", nil, "ends before the length of the metadata"},
		{"short metadata", []byte{10, 0, 0, 0, '{'}, "ends inside its metadata"},
		{"not JSON", publishBody([]byte("[1]"), nil), "invalid publish metadata"},
		{"no crate length", publishBody(mustJSON(newCrate("abc", "1.0.0").meta), nil)[:4+len(mustJSON(newCrate("abc", "1.0.0").meta))], "length of the .crate file"},
		{"short crate", publishBody(mustJSON(newCrate("abc", "1.0.0").meta), newCrate("abc", "1.0.0").body)[:60+len(mustJSON(newCrate("abc", "1.0.0").meta))], "ends inside its .crate file"},
		{"trailing data", append(publishBody(mustJSON(newCrate("abc", "1.0.0").meta), newCrate("abc", "1.0.0").body), 'x'), "data after its .crate file"},
		{"bad dependency", publishBody(mustJSON(newCrate("abc", "1.0.0", bad).meta), newCrate("abc", "1.0.0").body), "no valid version requirement"},
		{"huge metadata", []byte{0, 0, 0, 0x40}, "larger than"},
	} {
		w := e.do("PUT", "/cargo/local/api/v1/crates/new", bytes.NewReader(tc.body))
		if w.Code/100 != 4 || !strings.Contains(w.Body.String(), tc.msg) {
			t.Errorf("%s: %d %s, want %q", tc.name, w.Code, w.Body, tc.msg)
		}
	}
	if lines := e.index("local", "foo-bar"); !slices.Equal(versions(lines), []string{"1.0.0"}) {
		t.Errorf("index %v", versions(lines))
	}
	e.get("/cargo/local/"+indexPath("abc"), http.StatusNotFound)

	for _, repo := range []string{"remote", "plain"} {
		e.auth.reset()
		w := e.publish(repo, newCrate("abc", "1.0.0"))
		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("publish to %s: %d %s", repo, w.Code, w.Body)
		}
		if calls := e.auth.reset(); len(calls) != 1 || !strings.HasSuffix(calls[0], ":pull") {
			t.Errorf("publish to %s authorized %v", repo, calls)
		}
	}
	e.auth.status = http.StatusForbidden
	if w := e.publish("local", newCrate("abc", "1.0.0")); w.Code != http.StatusForbidden {
		t.Errorf("a refused publish: %d", w.Code)
	}
}

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

func TestYankAndETag(t *testing.T) {
	e := newEnv(t)
	e.mustPublish("local", newCrate("foo", "1.0.0"))
	e.mustPublish("local", newCrate("foo", "1.1.0-rc.1"))
	e.mustPublish("local", newCrate("foo", "0.9.0"))
	path := "/cargo/local/3/f/foo"
	w := e.get(path, http.StatusOK)
	etag := w.Header().Get("ETag")
	if got := versions(decodeLines(t, w.Body.Bytes())); !slices.Equal(got, []string{"0.9.0", "1.0.0", "1.1.0-rc.1"}) {
		t.Errorf("index versions %v", got)
	}
	e.get(path, http.StatusNotModified, "If-None-Match", etag)
	e.mustPublish("local", newCrate("other", "1.0.0"))
	e.get(path, http.StatusNotModified, "If-None-Match", etag)

	e.auth.reset()
	w = e.do("DELETE", "/cargo/local/api/v1/crates/foo/1.0.0/yank", nil)
	if w.Code != http.StatusOK || strings.TrimSpace(w.Body.String()) != `{"ok":true}` {
		t.Fatalf("yank: %d %s", w.Code, w.Body)
	}
	if calls := e.auth.reset(); !slices.Equal(calls, []string{"local:pull,push"}) {
		t.Errorf("yank authorized %v", calls)
	}
	w = e.get(path, http.StatusOK, "If-None-Match", etag)
	etag2 := w.Header().Get("ETag")
	if etag2 == etag {
		t.Error("yanking did not move the ETag")
	}
	for _, l := range decodeLines(t, w.Body.Bytes()) {
		if l["yanked"] != (l["vers"] == "1.0.0") {
			t.Errorf("line %v", l)
		}
	}
	// A yanked version can still be downloaded.
	e.get("/cargo/local/api/v1/crates/foo/1.0.0/download", http.StatusOK)
	// Yanking again changes nothing.
	if w := e.do("DELETE", "/cargo/local/api/v1/crates/foo/1.0.0/yank", nil); w.Code != http.StatusOK {
		t.Errorf("yank again: %d", w.Code)
	}
	e.get(path, http.StatusNotModified, "If-None-Match", etag2)
	if w := e.do("PUT", "/cargo/local/api/v1/crates/foo/1.0.0/unyank", nil); w.Code != http.StatusOK {
		t.Errorf("unyank: %d %s", w.Code, w.Body)
	}
	for _, l := range e.index("local", "foo") {
		if l["yanked"] != false {
			t.Errorf("line %v", l)
		}
	}
	for _, tc := range []struct {
		method, path string
		status       int
	}{
		{"DELETE", "/cargo/local/api/v1/crates/foo/3.0.0/yank", http.StatusNotFound},
		{"DELETE", "/cargo/local/api/v1/crates/nope/1.0.0/yank", http.StatusNotFound},
		{"PUT", "/cargo/local/api/v1/crates/foo/1.0.0/yank", http.StatusMethodNotAllowed},
		{"DELETE", "/cargo/local/api/v1/crates/foo/x/yank", http.StatusNotFound},
		{"DELETE", "/cargo/remote/api/v1/crates/foo/1.0.0/yank", http.StatusMethodNotAllowed},
		{"GET", "/cargo/local/api/v1/crates/foo/owners", http.StatusBadRequest},
		{"PUT", "/cargo/local/api/v1/crates/foo/owners", http.StatusBadRequest},
		{"GET", "/cargo/local/api/v2/x", http.StatusNotFound},
		{"GET", "/cargo/local/api/v1/crates/foo/1.0.0/other", http.StatusNotFound},
		{"GET", "/cargo/local", http.StatusNotFound},
	} {
		if w := e.do(tc.method, tc.path, nil); w.Code != tc.status {
			t.Errorf("%s %s: %d %s, want %d", tc.method, tc.path, w.Code, w.Body, tc.status)
		}
	}
}

func TestDelete(t *testing.T) {
	e := newEnv(t)
	e.mustPublish("local", newCrate("foo", "1.0.0"))
	e.mustPublish("local", newCrate("foo", "2.0.0"))
	e.auth.reset()
	w := e.do("DELETE", "/api/v1/cargo/local/crates/foo/2.0.0", nil)
	if w.Code != http.StatusOK || strings.TrimSpace(w.Body.String()) != `{"crate":"foo","version":"2.0.0"}` {
		t.Fatalf("delete: %d %s", w.Code, w.Body)
	}
	if calls := e.auth.reset(); !slices.Equal(calls, []string{"local:delete"}) {
		t.Errorf("delete authorized %v", calls)
	}
	if got := versions(e.index("local", "foo")); !slices.Equal(got, []string{"1.0.0"}) {
		t.Errorf("index after delete %v", got)
	}
	e.get("/cargo/local/api/v1/crates/foo/2.0.0/download", http.StatusNotFound)
	if w := e.publish("local", newCrate("foo", "2.0.0")); w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "was deleted") {
		t.Errorf("republishing a deleted version: %d %s", w.Code, w.Body)
	}
	for _, tc := range []struct {
		path   string
		status int
	}{
		{"/api/v1/cargo/local/crates/foo/2.0.0", http.StatusNotFound},
		{"/api/v1/cargo/local/crates/nope/1.0.0", http.StatusNotFound},
		{"/api/v1/cargo/remote/crates/foo/1.0.0", http.StatusMethodNotAllowed},
		{"/api/v1/cargo/nope/crates/foo/1.0.0", http.StatusNotFound},
		{"/api/v1/cargo/pypi/crates/foo/1.0.0", http.StatusNotFound},
	} {
		w := e.do("DELETE", tc.path, nil)
		var res struct{ Error string }
		if w.Code != tc.status || json.Unmarshal(w.Body.Bytes(), &res) != nil || res.Error == "" {
			t.Errorf("DELETE %s: %d %s, want %d and an admin API error", tc.path, w.Code, w.Body, tc.status)
		}
	}
	// Once every version is deleted the crate has no index file, but the
	// repository keeps owning its name.
	e.do("DELETE", "/api/v1/cargo/local/crates/foo/1.0.0", nil)
	e.get("/cargo/local/3/f/foo", http.StatusNotFound)
	if !e.has(crateKey("local", "foo")) {
		t.Error("the crate record is gone")
	}
	if w := e.publish("local", newCrate("Foo", "3.0.0")); w.Code != http.StatusConflict {
		t.Errorf("another spelling after delete: %d", w.Code)
	}
	e.mustPublish("local", newCrate("foo", "3.0.0"))
}

func TestCrateCheck(t *testing.T) {
	for _, tc := range []struct {
		name string
		body []byte
		ok   bool
	}{
		{"valid", crateFile("a-1.0.0/", "Cargo.toml", "src/lib.rs", "Cargo.toml.orig"), true},
		{"nested Cargo.toml only", crateFile("a-1.0.0/", "sub/Cargo.toml"), false},
		{"escape", crateFile("a-1.0.0/", "Cargo.toml", "../x"), true}, // still under the prefix, as the names go
		{"other root", crateFile("", "a-1.0.0/Cargo.toml", "b/x"), false},
		{"empty", crateFile("a-1.0.0/"), false},
		{"truncated", crateFile("a-1.0.0/", "Cargo.toml")[:30], false},
	} {
		err := checkCrate(bytes.NewReader(tc.body), "a-1.0.0/")
		if (err == nil) != tc.ok {
			t.Errorf("%s: %v", tc.name, err)
		}
	}
}

func TestBlobsOnce(t *testing.T) {
	e := newEnv(t)
	c := newCrate("foo", "1.0.0")
	e.mustPublish("local", c)
	d, _ := blob.ParseDigest("sha256:" + c.sha256())
	if _, err := e.blobs.Stat(t.Context(), d); err != nil {
		t.Errorf("the .crate file is not in the blob store under its sha256: %v", err)
	}
}

// failingStore is a blob store whose uploads fail to write.
type failingStore struct{ blob.Store }

func (s failingStore) NewUpload(ctx context.Context) (blob.Upload, error) {
	u, err := s.Store.NewUpload(ctx)
	return failingUpload{u}, err
}

type failingUpload struct{ blob.Upload }

func (failingUpload) Write([]byte) (int, error) { return 0, errors.New("no space left on device") }

func TestPublishStoreFailure(t *testing.T) {
	e := newEnv(t)
	e.h.blobs = failingStore{e.blobs}
	w := e.publish("local", newCrate("foo", "1.0.0"))
	if w.Code != http.StatusInternalServerError || strings.Contains(w.Body.String(), "invalid .crate file") {
		t.Errorf("publish with a failing blob store: %d %s, want 500", w.Code, w.Body)
	}
	e.get("/cargo/local/"+indexPath("foo"), http.StatusNotFound)
}
