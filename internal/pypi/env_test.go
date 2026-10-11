package pypi

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/terrabyteian/flint/internal/blake2b"
	"github.com/terrabyteian/flint/internal/blob"
	"github.com/terrabyteian/flint/internal/config"
	"github.com/terrabyteian/flint/internal/fsys"
	"github.com/terrabyteian/flint/internal/meta"
	"github.com/terrabyteian/flint/internal/metrics"
	"github.com/terrabyteian/flint/internal/upstream"
)

var quiet = slog.New(slog.DiscardHandler)

const testWindow = time.Minute

// testAuth records Permit calls and answers with status, by default 200.
type testAuth struct {
	mu     sync.Mutex
	calls  []string
	status int
}

func (a *testAuth) Permit(r *http.Request, repo string, actions ...string) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.calls = append(a.calls, repo+":"+strings.Join(actions, ","))
	if a.status != 0 {
		return a.status
	}
	return http.StatusOK
}

func (a *testAuth) reset() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	c := a.calls
	a.calls = nil
	return c
}

// env is a Handler over in-memory stores with these repositories:
//
//	local     hosted
//	team      hosted
//	remote    proxy of the fake upstream index up
//	small     proxy of up with a size limit
//	all       virtual: local, remote
//	open      virtual: local, remote, without dependency-confusion protection
type env struct {
	t     *testing.T
	fs    *fsys.Mem
	meta  meta.Store
	blobs blob.Store
	auth  *testAuth
	up    *index
	h     *Handler
	reg   *metrics.Registry
	srv   http.Handler
	free  atomic.Uint64

	mu    sync.Mutex
	clock time.Time
}

func newEnv(t *testing.T) *env {
	t.Helper()
	e := &env{t: t, fs: fsys.NewMem(), auth: &testAuth{}, up: newIndex(t), clock: time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)}
	e.free.Store(100 << 30)
	ms, err := meta.Open("/data/meta", meta.Options{FS: e.fs, Logger: quiet})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ms.Close() })
	bs, err := blob.NewFS("/data", blob.Options{FS: e.fs})
	if err != nil {
		t.Fatal(err)
	}
	e.meta, e.blobs = ms, bs
	e.restart()
	return e
}

// restart builds a new Handler over the same stores, as a restart would.
func (e *env) restart() {
	e.t.Helper()
	off := false
	repos := []config.Repository{
		{Name: "local", Format: config.FormatPyPI, Type: config.TypeHosted},
		{Name: "team", Format: config.FormatPyPI, Type: config.TypeHosted},
		{Name: "remote", Format: config.FormatPyPI, Type: config.TypeProxy,
			Proxy: &config.Proxy{URL: e.up.URL + "/simple/", RevalidateAfter: config.Duration{Duration: testWindow}}},
		{Name: "small", Format: config.FormatPyPI, Type: config.TypeProxy,
			Proxy: &config.Proxy{URL: e.up.URL + "/simple", RevalidateAfter: config.Duration{Duration: testWindow},
				SizeLimit: config.ByteSize{Bytes: 2500}}},
		{Name: "all", Format: config.FormatPyPI, Type: config.TypeVirtual, Virtual: &config.Virtual{Members: []string{"local", "remote"}}},
		{Name: "open", Format: config.FormatPyPI, Type: config.TypeVirtual,
			Virtual: &config.Virtual{Members: []string{"local", "remote"}, DependencyConfusionProtection: &off}},
		{Name: "oci", Format: config.FormatOCI, Type: config.TypeHosted},
	}
	space := upstream.NewSpace(upstream.SpaceOptions{
		Path:    "/data",
		Statfs:  func(string) (uint64, uint64, error) { return e.free.Load(), 1 << 40, nil },
		MinFree: func(uint64) uint64 { return 1 << 30 },
		Now:     e.now,
		Logger:  quiet,
	})
	e.reg = metrics.NewRegistry()
	h, err := New(Options{Meta: e.meta, Blobs: e.blobs, Repositories: repos, Authorizer: e.auth, Logger: quiet,
		Metrics: e.reg, Now: e.now, Space: space, Upstream: upstream.Options{Attempts: 2, Backoff: time.Millisecond}})
	if err != nil {
		e.t.Fatal(err)
	}
	e.h = h
	mux := http.NewServeMux()
	h.Register(mux)
	e.srv = mux
}

func (e *env) now() time.Time {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.clock
}

func (e *env) advance(d time.Duration) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.clock = e.clock.Add(d)
}

// do serves a request; hdr holds header name and value pairs.
func (e *env) do(method, path string, body io.Reader, hdr ...string) *httptest.ResponseRecorder {
	e.t.Helper()
	r := httptest.NewRequest(method, path, body)
	for i := 0; i+1 < len(hdr); i += 2 {
		r.Header.Set(hdr[i], hdr[i+1])
	}
	w := httptest.NewRecorder()
	e.srv.ServeHTTP(w, r)
	return w
}

// get serves a GET and checks the status.
func (e *env) get(path string, status int, hdr ...string) *httptest.ResponseRecorder {
	e.t.Helper()
	w := e.do("GET", path, nil, hdr...)
	if w.Code != status {
		e.t.Fatalf("GET %s: %d %q, want %d", path, w.Code, w.Body.String(), status)
	}
	return w
}

// page fetches a project page as JSON.
func (e *env) page(repo, project string) *jsonPage {
	e.t.Helper()
	w := e.get("/pypi/"+repo+"/simple/"+project+"/", http.StatusOK, "Accept", mtSimpleJSON)
	var p jsonPage
	if err := json.Unmarshal(w.Body.Bytes(), &p); err != nil {
		e.t.Fatalf("page %s/%s: %v: %s", repo, project, err, w.Body)
	}
	return &p
}

// jsonPage is a PEP 691 project page as clients read it.
type jsonPage struct {
	Meta     map[string]string `json:"meta"`
	Name     string            `json:"name"`
	Versions []string          `json:"versions"`
	Files    []struct {
		Filename       string            `json:"filename"`
		URL            string            `json:"url"`
		Hashes         map[string]string `json:"hashes"`
		RequiresPython string            `json:"requires-python"`
		CoreMetadata   any               `json:"core-metadata"`
		DistInfo       any               `json:"dist-info-metadata"`
		Yanked         any               `json:"yanked"`
		Size           *int64            `json:"size"`
		UploadTime     string            `json:"upload-time"`
	} `json:"files"`
}

func (p *jsonPage) filenames() []string {
	var out []string
	for _, f := range p.Files {
		out = append(out, f.Filename)
	}
	return out
}

// metric returns the value of a sample line of the exposition, or "".
func (e *env) metric(sample string) string {
	var b bytes.Buffer
	e.reg.WriteTo(&b)
	for line := range strings.SplitSeq(b.String(), "\n") {
		if v, ok := strings.CutPrefix(line, sample+" "); ok {
			return v
		}
	}
	return ""
}

// settle waits until fetches in progress have linked their files.
func (e *env) settle() {
	e.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for e.h.fetcher.Active() > 0 {
		if time.Now().After(deadline) {
			e.t.Fatal("fetches did not finish")
		}
		time.Sleep(time.Millisecond)
	}
}

func (e *env) has(k []byte) bool {
	v := e.meta.View()
	defer v.Release()
	_, ok := v.Get(k)
	return ok
}

// dist is a built distribution file.
type dist struct {
	name, version, filename string
	body                    []byte
	metadata                []byte // the core metadata inside, if any
}

func (d dist) sha256() string {
	s := sha256.Sum256(d.body)
	return hex.EncodeToString(s[:])
}

// metadataFor writes core metadata for a project.
func metadataFor(name, version string, extra ...string) []byte {
	var b strings.Builder
	b.WriteString("Metadata-Version: 2.1\nName: " + name + "\nVersion: " + version + "\nSummary: The " + name + " package\n")
	for _, x := range extra {
		b.WriteString(x + "\n")
	}
	b.WriteString("\nThe long description of " + name + ".\n")
	return []byte(b.String())
}

// wheel builds a wheel whose METADATA is md, or metadataFor the project.
func wheel(name, version string, md []byte) dist {
	escaped := strings.ReplaceAll(Normalize(name), "-", "_")
	if md == nil {
		md = metadataFor(name, version, "Requires-Python: >=3.9", "Requires-Dist: six>=1.0")
	}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	add := func(n string, b []byte) {
		w, _ := zw.Create(n)
		w.Write(b)
	}
	add(escaped+"/__init__.py", []byte("x = 1\n"))
	add(escaped+"-"+version+".dist-info/METADATA", md)
	add(escaped+"-"+version+".dist-info/WHEEL", []byte("Wheel-Version: 1.0\n"))
	zw.Close()
	return dist{name: name, version: version, filename: escaped + "-" + version + "-py3-none-any.whl", body: buf.Bytes(), metadata: md}
}

// sdist builds a .tar.gz source distribution, with PKG-INFO md if md is
// not nil.
func sdist(name, version string, md []byte) dist {
	escaped := strings.ReplaceAll(Normalize(name), "-", "_")
	top := escaped + "-" + version
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	add := func(n string, b []byte) {
		tw.WriteHeader(&tar.Header{Name: n, Mode: 0o644, Size: int64(len(b)), Typeflag: tar.TypeReg})
		tw.Write(b)
	}
	add(top+"/setup.py", []byte("# setup\n"))
	if md != nil {
		add(top+"/PKG-INFO", md)
	}
	tw.Close()
	gz.Close()
	return dist{name: name, version: version, filename: top + ".tar.gz", body: buf.Bytes(), metadata: md}
}

// form returns the upload form fields twine sends for d.
func (d dist) form() map[string][]string {
	md5sum := md5.Sum(d.body)
	b2 := blake2b.Sum256(d.body)
	filetype := typeSdist
	if strings.HasSuffix(d.filename, ".whl") {
		filetype = typeWheel
	}
	return map[string][]string{
		":action": {"file_upload"}, "protocol_version": {"1"}, "metadata_version": {"2.1"},
		"name": {d.name}, "version": {d.version}, "filetype": {filetype}, "pyversion": {"py3"},
		"summary": {"The " + d.name + " package"}, "description": {"A description."},
		"md5_digest": {hex.EncodeToString(md5sum[:])}, "sha256_digest": {d.sha256()},
		"blake2_256_digest": {hex.EncodeToString(b2[:])},
		"classifiers":       {"Programming Language :: Python :: 3", "License :: OSI Approved"},
	}
}

// upload posts d with form fields to repository repo, the file part last
// unless fileFirst.
func (e *env) upload(repo string, d dist, form map[string][]string, fileFirst bool) *httptest.ResponseRecorder {
	e.t.Helper()
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	writeFile := func() {
		fw, _ := mw.CreateFormFile("content", d.filename)
		fw.Write(d.body)
	}
	if fileFirst {
		writeFile()
	}
	keys := make([]string, 0, len(form))
	for k := range form {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		for _, v := range form[k] {
			mw.WriteField(k, v)
		}
	}
	if !fileFirst {
		writeFile()
	}
	mw.Close()
	return e.do("POST", "/pypi/"+repo+"/legacy/", &body, "Content-Type", mw.FormDataContentType())
}

// mustUpload uploads d with its form and checks the 200.
func (e *env) mustUpload(repo string, d dist) {
	e.t.Helper()
	if w := e.upload(repo, d, d.form(), false); w.Code != http.StatusOK {
		e.t.Fatalf("uploading %s to %s: %d %s", d.filename, repo, w.Code, w.Body)
	}
}

// index is a fake upstream package index. Its project pages link files
// on a second server, as pypi.org links files.pythonhosted.org.
type index struct {
	*httptest.Server
	files *httptest.Server

	mu       sync.Mutex
	projects map[string][]upFile
	html     bool // serve HTML pages instead of JSON
	noETag   bool
	down     bool
	corrupt  map[string]bool // file names served with a flipped byte
	requests []string
}

// upFile is a file the fake index serves.
type upFile struct {
	dist
	noHash   bool // list it without a sha256 hash
	yanked   string
	metadata bool // serve its core-metadata file
	relative bool // link it relatively from an HTML page, on the page's own server
}

func newIndex(t *testing.T) *index {
	x := &index{projects: map[string][]upFile{}, corrupt: map[string]bool{}}
	x.Server = httptest.NewServer(http.HandlerFunc(x.servePage))
	x.files = httptest.NewServer(http.HandlerFunc(x.serveFile))
	t.Cleanup(x.Close)
	t.Cleanup(x.files.Close)
	return x
}

func (x *index) add(project string, fs ...upFile) {
	x.mu.Lock()
	defer x.mu.Unlock()
	x.projects[project] = append(x.projects[project], fs...)
}

func (x *index) set(f func(x *index)) {
	x.mu.Lock()
	defer x.mu.Unlock()
	f(x)
}

// took returns and forgets the requests served.
func (x *index) took() []string {
	x.mu.Lock()
	defer x.mu.Unlock()
	r := x.requests
	x.requests = nil
	return r
}

func (x *index) servePage(w http.ResponseWriter, r *http.Request) {
	if name, ok := strings.CutPrefix(r.URL.Path, "/relative/"); ok {
		r.URL.Path = "/packages/" + name
		x.serveFile(w, r)
		return
	}
	x.mu.Lock()
	defer x.mu.Unlock()
	x.requests = append(x.requests, "page "+r.URL.Path+" "+r.Header.Get("If-None-Match"))
	if x.down {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	project, ok := strings.CutPrefix(r.URL.Path, "/simple/")
	project = strings.TrimSuffix(project, "/")
	files, found := x.projects[project]
	if !ok || !found {
		http.NotFound(w, r)
		return
	}
	var body bytes.Buffer
	if x.html {
		w.Header().Set("Content-Type", "text/html")
		body.WriteString("<!DOCTYPE html><html><body><!-- <a href=\"bogus.whl\">no</a> -->\n")
		for _, f := range files {
			href := x.files.URL + "/packages/" + f.filename
			if f.relative {
				href = "../../relative/" + f.filename
			}
			if !f.noHash {
				href += "#sha256=" + f.sha256()
			}
			fmt.Fprintf(&body, `<A HREF="%s" data-requires-python="&gt;=3.9"`, href)
			if f.yanked != "" {
				fmt.Fprintf(&body, ` data-yanked="%s"`, f.yanked)
			}
			if f.metadata {
				s := sha256.Sum256(f.dist.metadata)
				fmt.Fprintf(&body, ` data-dist-info-metadata="sha256=%x"`, s)
			}
			fmt.Fprintf(&body, ">%s</a><br/>\n", f.filename)
		}
		body.WriteString("</body></html>")
	} else {
		w.Header().Set("Content-Type", mtSimpleJSON)
		type jf struct {
			Filename     string            `json:"filename"`
			URL          string            `json:"url"`
			Hashes       map[string]string `json:"hashes"`
			CoreMetadata any               `json:"core-metadata,omitempty"`
			Yanked       any               `json:"yanked"`
			Size         int               `json:"size"`
			UploadTime   string            `json:"upload-time"`
		}
		page := struct {
			Meta     map[string]string `json:"meta"`
			Name     string            `json:"name"`
			Versions []string          `json:"versions"`
			Files    []jf              `json:"files"`
		}{Meta: map[string]string{"api-version": "1.1"}, Name: project}
		for _, f := range files {
			j := jf{Filename: f.filename, URL: x.files.URL + "/packages/" + f.filename, Hashes: map[string]string{},
				Yanked: false, Size: len(f.body), UploadTime: "2026-01-02T03:04:05.123456Z"}
			if !f.noHash {
				j.Hashes["sha256"] = f.sha256()
			}
			if f.yanked != "" {
				j.Yanked = f.yanked
			}
			if f.metadata {
				s := sha256.Sum256(f.dist.metadata)
				j.CoreMetadata = map[string]string{"sha256": hex.EncodeToString(s[:])}
			}
			page.Files = append(page.Files, j)
			if !slices.Contains(page.Versions, f.version) {
				page.Versions = append(page.Versions, f.version)
			}
		}
		json.NewEncoder(&body).Encode(page)
	}
	sum := sha256.Sum256(body.Bytes())
	etag := `"` + hex.EncodeToString(sum[:8]) + `"`
	if !x.noETag {
		w.Header().Set("ETag", etag)
		if r.Header.Get("If-None-Match") == etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
	}
	w.Write(body.Bytes())
}

func (x *index) serveFile(w http.ResponseWriter, r *http.Request) {
	x.mu.Lock()
	defer x.mu.Unlock()
	x.requests = append(x.requests, "file "+r.URL.Path)
	if x.down {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	name := strings.TrimPrefix(r.URL.Path, "/packages/")
	md := strings.HasSuffix(name, ".metadata")
	name = strings.TrimSuffix(name, ".metadata")
	for _, files := range x.projects {
		for _, f := range files {
			if f.filename != name {
				continue
			}
			body := f.body
			if md {
				if !f.metadata {
					break
				}
				body = f.dist.metadata
			}
			body = slices.Clone(body)
			if x.corrupt[name] {
				body[len(body)-1] ^= 0xff
			}
			w.Header().Set("Content-Length", strconv.Itoa(len(body)))
			w.Write(body)
			return
		}
	}
	http.NotFound(w, r)
}

func mustURL(t *testing.T, s string) *url.URL {
	t.Helper()
	u, err := url.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return u
}
