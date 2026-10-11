package pypi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
)

func TestUploadAndServe(t *testing.T) {
	e := newEnv(t)
	whl := wheel("My.Pkg", "1.0", nil)
	sd := sdist("My.Pkg", "1.0", metadataFor("My.Pkg", "1.0", "Requires-Python: >=3.9"))
	e.mustUpload("local", whl)
	if w := e.upload("local", sd, sd.form(), true); w.Code != http.StatusOK { // file part first
		t.Fatalf("uploading the sdist: %d %s", w.Code, w.Body)
	}
	if got := e.auth.reset(); !slices.Equal(got, []string{"local:pull,push", "local:pull,push"}) {
		t.Errorf("authorization calls %q", got)
	}

	// The project page, in JSON and HTML, under the normalized name.
	p := e.page("local", "my-pkg")
	if p.Name != "my-pkg" || p.Meta["api-version"] != "1.1" || !slices.Equal(p.Versions, []string{"1.0"}) {
		t.Errorf("page %+v", p)
	}
	// Sorted by name: "-" sorts before ".".
	if got := p.filenames(); !slices.Equal(got, []string{whl.filename, sd.filename}) {
		t.Fatalf("files %q", got)
	}
	for i, d := range []dist{whl, sd} {
		f := p.Files[i]
		if f.Hashes["sha256"] != d.sha256() || f.URL != "../../files/my-pkg/"+d.filename || *f.Size != int64(len(d.body)) ||
			f.RequiresPython != ">=3.9" || f.Yanked != false || f.UploadTime != "2026-10-01T12:00:00Z" {
			t.Errorf("file %+v", f)
		}
	}
	mdHash := sha256hex(whl.metadata)
	if m, ok := p.Files[0].CoreMetadata.(map[string]any); !ok || m["sha256"] != mdHash || p.Files[0].DistInfo == nil {
		t.Errorf("wheel core-metadata %v, want sha256 %s", p.Files[0].CoreMetadata, mdHash)
	}
	if p.Files[1].CoreMetadata != nil {
		t.Errorf("an sdist with metadata 2.1 has a core-metadata file: %v", p.Files[1].CoreMetadata)
	}
	w := e.get("/pypi/local/simple/my-pkg/", http.StatusOK)
	if ct := w.Header().Get("Content-Type"); ct != "text/html; charset=utf-8" || w.Header().Get("Vary") != "Accept" {
		t.Errorf("HTML headers %v", w.Header())
	}
	wantLink := `<a href="../../files/my-pkg/` + whl.filename + `#sha256=` + whl.sha256() +
		`" data-requires-python="&gt;=3.9" data-dist-info-metadata="sha256=` + mdHash + `" data-core-metadata="sha256=` + mdHash + `">`
	if !strings.Contains(w.Body.String(), wantLink) || !strings.Contains(w.Body.String(), `<meta name="pypi:repository-version" content="1.1">`) {
		t.Errorf("HTML page lacks %s:\n%s", wantLink, w.Body)
	}
	// A matching ETag gets 304.
	etag := w.Header().Get("ETag")
	if w := e.get("/pypi/local/simple/my-pkg/", http.StatusNotModified, "If-None-Match", etag); w.Body.Len() != 0 {
		t.Error("304 with a body")
	}

	// The files and the wheel's core metadata.
	for _, d := range []dist{whl, sd} {
		w := e.get("/pypi/local/files/my-pkg/"+d.filename, http.StatusOK)
		if !bytes.Equal(w.Body.Bytes(), d.body) || w.Header().Get("ETag") != `"sha256:`+d.sha256()+`"` {
			t.Errorf("download of %s: %d bytes, headers %v", d.filename, w.Body.Len(), w.Header())
		}
	}
	if w := e.get("/pypi/local/files/my-pkg/"+whl.filename+".metadata", http.StatusOK); !bytes.Equal(w.Body.Bytes(), whl.metadata) {
		t.Errorf("core metadata %q", w.Body)
	}
	e.get("/pypi/local/files/my-pkg/"+sd.filename+".metadata", http.StatusNotFound)
	// A range request, as pip makes to resume a download.
	w = e.get("/pypi/local/files/my-pkg/"+whl.filename, http.StatusPartialContent, "Range", "bytes=0-9")
	if !bytes.Equal(w.Body.Bytes(), whl.body[:10]) {
		t.Errorf("range: %q", w.Body)
	}
	if w := e.do("HEAD", "/pypi/local/files/my-pkg/"+whl.filename, nil); w.Code != http.StatusOK || w.Header().Get("Content-Length") == "" {
		t.Errorf("HEAD: %d %v", w.Code, w.Header())
	}
	// A file is served only under its own project.
	e.get("/pypi/local/files/other/"+whl.filename, http.StatusNotFound)

	// The root index.
	w = e.get("/pypi/local/simple/", http.StatusOK, "Accept", mtSimpleJSON)
	if !strings.Contains(w.Body.String(), `"projects":[{"name":"my-pkg"}]`) {
		t.Errorf("root index %s", w.Body)
	}
	if w := e.get("/pypi/local/simple/", http.StatusOK); !strings.Contains(w.Body.String(), `<a href="my-pkg/">my-pkg</a>`) {
		t.Errorf("root index %s", w.Body)
	}
	if got := e.metric(`flint_pypi_uploads_total{repository="local"}`); got != "2" {
		t.Errorf("uploads metric %q", got)
	}
}

func sha256hex(b []byte) string { return dist{body: b}.sha256() }

func TestUploadValidation(t *testing.T) {
	e := newEnv(t)
	good := wheel("pkg", "1.0", nil)
	tests := []struct {
		name   string
		d      dist
		modify func(map[string][]string)
		status int
		want   string
	}{
		{"no action", good, func(f map[string][]string) { delete(f, ":action") }, 400, "no :action"},
		{"other action", good, func(f map[string][]string) { f[":action"] = []string{"submit"} }, 400, `unsupported :action "submit"`},
		{"protocol", good, func(f map[string][]string) { f["protocol_version"] = []string{"2"} }, 400, "protocol_version"},
		{"attestations", good, func(f map[string][]string) { f["attestations"] = []string{"[]"} }, 400, "attestations"},
		{"bad name", good, func(f map[string][]string) { f["name"] = []string{"-pkg"} }, 400, "invalid project name"},
		{"bad version", good, func(f map[string][]string) { f["version"] = []string{"one"} }, 400, "PEP 440"},
		{"filetype", good, func(f map[string][]string) { f["filetype"] = []string{"sdist"} }, 400, "filetype must be bdist_wheel"},
		{"name mismatch", good, func(f map[string][]string) { f["name"] = []string{"other"} }, 400, "does not follow"},
		{"version mismatch", good, func(f map[string][]string) { f["version"] = []string{"2.0"} }, 400, "has version 1.0"},
		{"sha256", good, func(f map[string][]string) { f["sha256_digest"] = []string{strings.Repeat("0", 64)} }, 400, "sha256_digest"},
		{"md5", good, func(f map[string][]string) { f["md5_digest"] = []string{strings.Repeat("0", 32)} }, 400, "md5_digest"},
		{"blake2", good, func(f map[string][]string) { f["blake2_256_digest"] = []string{strings.Repeat("0", 64)} }, 400, "blake2_256_digest"},
		{"malformed digest", good, func(f map[string][]string) { f["sha256_digest"] = []string{"xyz"} }, 400, "hex digits"},
		{"egg", dist{name: "pkg", version: "1.0", filename: "pkg-1.0-py3.12.egg", body: []byte("egg")},
			func(f map[string][]string) { f["filetype"] = []string{"bdist_egg"} }, 400, "unsupported file"},
		{"wheel without metadata", dist{name: "pkg", version: "1.0", filename: "pkg-1.0-py3-none-any.whl", body: []byte("not a zip")},
			nil, 400, "not a valid zip"},
		{"wheel metadata names another project", wheel("pkg", "1.0", metadataFor("other", "1.0")), nil, 400, `names project "other"`},
		{"sdist name", sdist("pkg", "1.0", nil), func(f map[string][]string) { f["name"] = []string{"pk"} }, 400, "does not start with"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			form := tt.d.form()
			if tt.modify != nil {
				tt.modify(form)
			}
			w := e.upload("local", tt.d, form, false)
			if w.Code != tt.status || !strings.Contains(w.Body.String(), tt.want) {
				t.Errorf("%d %q, want %d containing %q", w.Code, w.Body, tt.status, tt.want)
			}
		})
	}
	// None of them stored anything.
	e.get("/pypi/local/simple/pkg/", http.StatusNotFound)
	// Requests that are not upload forms.
	if w := e.do("POST", "/pypi/local/legacy/", strings.NewReader("x"), "Content-Type", "application/json"); w.Code != 400 {
		t.Errorf("JSON upload: %d", w.Code)
	}
	if w := e.do("GET", "/pypi/local/legacy/", nil); w.Code != http.StatusMethodNotAllowed || w.Header().Get("Allow") != "POST" {
		t.Errorf("GET upload URL: %d %v", w.Code, w.Header())
	}
	form := good.form()
	delete(form, "sha256_digest")
	delete(form, "md5_digest")
	delete(form, "blake2_256_digest")
	if w := e.upload("local", good, form, false); w.Code != http.StatusOK {
		t.Errorf("an upload without digests: %d %s", w.Code, w.Body)
	}
}

func TestUploadRepeatAndConflict(t *testing.T) {
	e := newEnv(t)
	a := wheel("pkg", "1.0", nil)
	e.mustUpload("local", a)
	// The same file again succeeds, as on PyPI, so retries are harmless.
	if w := e.upload("local", a, a.form(), false); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "already uploaded") {
		t.Errorf("repeated upload: %d %s", w.Code, w.Body)
	}
	// Other content under the same name is refused.
	b := wheel("pkg", "1.0", metadataFor("pkg", "1.0", "Summary: changed"))
	w := e.upload("local", b, b.form(), false)
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "File already exists") {
		t.Errorf("conflicting upload: %d %s", w.Code, w.Body)
	}
	// Concurrent uploads of different content under one new name: exactly
	// one wins.
	var wg sync.WaitGroup
	codes := make([]int, 8)
	for i := range codes {
		d := wheel("race", "1.0", metadataFor("race", "1.0", "Summary: "+strings.Repeat("x", i)))
		wg.Go(func() { codes[i] = e.upload("local", d, d.form(), false).Code })
	}
	wg.Wait()
	slices.Sort(codes)
	if codes[0] != http.StatusOK || codes[1] != http.StatusConflict || codes[len(codes)-1] != http.StatusConflict {
		t.Errorf("concurrent upload statuses %v, want one 200 and the rest 409", codes)
	}
}

func TestUploadRefusedOutsideHosted(t *testing.T) {
	e := newEnv(t)
	d := wheel("pkg", "1.0", nil)
	for repo, want := range map[string]string{
		"remote": "read-only proxy",
		"all":    "virtual repository; upload to one of its hosted members: local",
	} {
		w := e.upload(repo, d, d.form(), false)
		if w.Code != http.StatusMethodNotAllowed || !strings.Contains(w.Body.String(), want) {
			t.Errorf("upload to %s: %d %q", repo, w.Code, w.Body)
		}
	}
}

func TestSdistMetadata(t *testing.T) {
	e := newEnv(t)
	// Metadata 2.2 without dynamic fields is served (PEP 643).
	reliable := sdist("good", "1.0", []byte("Metadata-Version: 2.2\nName: good\nVersion: 1.0\nRequires-Dist: six\n"))
	dynamic := sdist("dyn", "1.0", []byte("Metadata-Version: 2.2\nName: dyn\nVersion: 1.0\nDynamic: Requires-Dist\n"))
	bare := sdist("bare", "1.0", nil)
	for _, d := range []dist{reliable, dynamic, bare} {
		e.mustUpload("local", d)
	}
	if p := e.page("local", "good"); p.Files[0].CoreMetadata == nil {
		t.Error("reliable sdist metadata is not served")
	}
	e.get("/pypi/local/files/good/"+reliable.filename+".metadata", http.StatusOK)
	for _, d := range []dist{dynamic, bare} {
		if p := e.page("local", Normalize(d.name)); p.Files[0].CoreMetadata != nil {
			t.Errorf("%s: core metadata served", d.filename)
		}
		e.get("/pypi/local/files/"+Normalize(d.name)+"/"+d.filename+".metadata", http.StatusNotFound)
	}
	// The JSON API falls back to the upload form's metadata.
	var out struct {
		Info struct {
			Summary     string   `json:"summary"`
			Description string   `json:"description"`
			Classifiers []string `json:"classifiers"`
		} `json:"info"`
	}
	json.Unmarshal(e.get("/pypi/local/pypi/bare/json", http.StatusOK).Body.Bytes(), &out)
	if out.Info.Summary != "The bare package" || out.Info.Description != "A description." || len(out.Info.Classifiers) != 2 {
		t.Errorf("info from the form: %+v", out.Info)
	}
}

func TestYankAndDelete(t *testing.T) {
	e := newEnv(t)
	v1, v1s := wheel("pkg", "1.0", nil), sdist("pkg", "1.0", nil)
	v2 := wheel("pkg", "2.0", nil)
	for _, d := range []dist{v1, v1s, v2} {
		e.mustUpload("local", d)
	}
	e.auth.reset()
	admin := func(method, path, body string) (int, string) {
		w := e.do(method, "/api/v1/pypi/"+path, strings.NewReader(body))
		return w.Code, w.Body.String()
	}
	// Yank release 2.0 with a reason.
	if code, body := admin("PUT", "local/projects/Pkg/releases/2.0/yank", `{"reason": "broken"}`); code != 200 || !strings.Contains(body, v2.filename) {
		t.Fatalf("yank: %d %s", code, body)
	}
	if got := e.auth.reset(); !slices.Equal(got, []string{"local:delete"}) {
		t.Errorf("yank authorization %q", got)
	}
	p := e.page("local", "pkg")
	if p.Files[2].Yanked != "broken" || p.Files[0].Yanked != false {
		t.Errorf("yanked: %v %v", p.Files[2].Yanked, p.Files[0].Yanked)
	}
	if w := e.get("/pypi/local/simple/pkg/", http.StatusOK); !strings.Contains(w.Body.String(), `data-yanked="broken">`+v2.filename) {
		t.Errorf("HTML yank:\n%s", w.Body)
	}
	// The JSON API's latest release skips the yanked one.
	if v := jsonVersion(t, e, "/pypi/local/pypi/pkg/json"); v != "1.0" {
		t.Errorf("latest = %s, want 1.0 while 2.0 is yanked", v)
	}
	// Yanking without a reason, and unyanking.
	admin("PUT", "local/projects/pkg/releases/2.0/yank", "")
	if p := e.page("local", "pkg"); p.Files[2].Yanked != true {
		t.Errorf("yank without reason: %v", p.Files[2].Yanked)
	}
	admin("DELETE", "local/projects/pkg/releases/2.0/yank", "")
	if p := e.page("local", "pkg"); p.Files[2].Yanked != false {
		t.Errorf("unyanked: %v", p.Files[2].Yanked)
	}
	if code, _ := admin("PUT", "local/projects/pkg/releases/3.0/yank", ""); code != http.StatusNotFound {
		t.Errorf("yanking a missing release: %d", code)
	}
	if code, _ := admin("PUT", "local/projects/pkg/releases/2.0/yank", `{"reason": 1}`); code != http.StatusBadRequest {
		t.Errorf("a bad body: %d", code)
	}

	// Delete one file, then a release.
	if code, body := admin("DELETE", "local/projects/pkg/files/"+v1.filename, ""); code != 200 {
		t.Fatalf("delete file: %d %s", code, body)
	}
	e.get("/pypi/local/files/pkg/"+v1.filename, http.StatusNotFound)
	if got := e.page("local", "pkg").filenames(); !slices.Equal(got, []string{v1s.filename, v2.filename}) {
		t.Errorf("after deleting a file: %q", got)
	}
	if code, body := admin("DELETE", "local/projects/pkg/releases/2.0", ""); code != 200 || !strings.Contains(body, v2.filename) {
		t.Fatalf("delete release: %d %s", code, body)
	}
	if code, _ := admin("DELETE", "local/projects/pkg/files/"+v1.filename, ""); code != http.StatusNotFound {
		t.Errorf("deleting a deleted file: %d", code)
	}
	// A deleted name can never be uploaded again, not even with the same
	// content.
	for _, d := range []dist{v1, v2} {
		if w := e.upload("local", d, d.form(), false); w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "was deleted") {
			t.Errorf("re-uploading %s: %d %s", d.filename, w.Code, w.Body)
		}
	}
	// The tombstone survives a restart.
	e.restart()
	if w := e.upload("local", v1, v1.form(), false); w.Code != http.StatusConflict {
		t.Errorf("re-uploading after a restart: %d", w.Code)
	}
	// Deleting every file leaves the project owned, but without a page or
	// a place in the root index.
	admin("DELETE", "local/projects/pkg/files/"+v1s.filename, "")
	e.get("/pypi/local/simple/pkg/", http.StatusNotFound)
	if w := e.get("/pypi/local/simple/", http.StatusOK); strings.Contains(w.Body.String(), "pkg") {
		t.Errorf("the root index lists a project without files:\n%s", w.Body)
	}
	if !e.has(projectKey("local", "pkg")) {
		t.Error("the project record went away")
	}
}

func TestAdminRefusals(t *testing.T) {
	e := newEnv(t)
	e.mustUpload("local", wheel("pkg", "1.0", nil))
	for _, tt := range []struct {
		path   string
		status int
		auth   int
		want   string
	}{
		{"/api/v1/pypi/nope/projects/pkg/releases/1.0/yank", 404, 0, "no PyPI repository"},
		{"/api/v1/pypi/oci/projects/pkg/releases/1.0/yank", 404, 0, "no PyPI repository"},
		{"/api/v1/pypi/remote/projects/pkg/releases/1.0/yank", 405, 0, "hosted repositories"},
		{"/api/v1/pypi/local/projects/pkg/releases/1.0/yank", 401, http.StatusUnauthorized, "authentication required"},
		{"/api/v1/pypi/local/projects/pkg/releases/1.0/yank", 403, http.StatusForbidden, "delete role"},
		{"/api/v1/pypi/local/projects/-x/releases/1.0/yank", 404, 0, "not found"},
	} {
		e.auth.status = tt.auth
		w := e.do("PUT", tt.path, nil)
		if w.Code != tt.status || !strings.Contains(w.Body.String(), tt.want) {
			t.Errorf("PUT %s with auth %d: %d %s", tt.path, tt.auth, w.Code, w.Body)
		}
		if tt.status == 401 && w.Header().Get("WWW-Authenticate") != `Basic realm="flint"` {
			t.Errorf("401 challenge %q", w.Header().Get("WWW-Authenticate"))
		}
	}
}

func jsonVersion(t *testing.T, e *env, path string) string {
	t.Helper()
	var out struct {
		Info struct {
			Version string `json:"version"`
		} `json:"info"`
	}
	if err := json.Unmarshal(e.get(path, http.StatusOK).Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out.Info.Version
}

func TestJSONAPI(t *testing.T) {
	e := newEnv(t)
	for _, d := range []dist{
		wheel("pkg", "1.0", metadataFor("pkg", "1.0", "Requires-Dist: six", "Project-URL: Source, https://example.com/src",
			"Classifier: A", "Classifier: B", "Requires-Python: >=3.8", "License-Expression: MIT")),
		sdist("pkg", "1.0", nil),
		wheel("pkg", "1.1", nil),
		wheel("pkg", "2.0rc1", nil),
	} {
		e.mustUpload("local", d)
	}
	var out struct {
		Info       map[string]any              `json:"info"`
		LastSerial int64                       `json:"last_serial"`
		Releases   map[string][]map[string]any `json:"releases"`
		URLs       []map[string]any            `json:"urls"`
		Vulns      []any                       `json:"vulnerabilities"`
	}
	w := e.get("http://registry.example/pypi/local/pypi/PKG/json", http.StatusOK)
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	// The latest final release, not the release candidate.
	if out.Info["version"] != "1.1" || len(out.Releases) != 3 || len(out.URLs) != 1 || out.LastSerial == 0 || out.Vulns == nil {
		t.Fatalf("JSON API: %s", w.Body)
	}
	u := out.URLs[0]
	if u["url"] != "http://registry.example/pypi/local/files/pkg/pkg-1.1-py3-none-any.whl" || u["packagetype"] != "bdist_wheel" ||
		u["python_version"] != "py3" || u["digests"].(map[string]any)["blake2b_256"] == nil || u["upload_time"] != "2026-10-01T12:00:00" {
		t.Errorf("url entry %v", u)
	}
	// One version's endpoint describes it, without releases.
	var one struct {
		Info     map[string]any `json:"info"`
		Releases map[string]any `json:"releases"`
		URLs     []any          `json:"urls"`
	}
	json.Unmarshal(e.get("/pypi/local/pypi/pkg/1.0/json", http.StatusOK).Body.Bytes(), &one)
	info := one.Info
	if info["version"] != "1.0" || one.Releases != nil || len(one.URLs) != 2 || info["summary"] != "The pkg package" ||
		info["requires_python"] != ">=3.8" || info["license_expression"] != "MIT" ||
		info["project_urls"].(map[string]any)["Source"] != "https://example.com/src" ||
		len(info["classifiers"].([]any)) != 2 || info["requires_dist"].([]any)[0] != "six" ||
		info["description"] != "The long description of pkg.\n" {
		t.Errorf("version info %v", info)
	}
	e.get("/pypi/local/pypi/pkg/9.9/json", http.StatusNotFound)
	e.get("/pypi/local/pypi/nope/json", http.StatusNotFound)
	e.get("/pypi/local/pypi/pkg/1.0/json/x", http.StatusNotFound)
}
