package oci

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
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

// virtualAuth adds the VirtualAuthorizer extension to catalogAuth,
// recording its calls as "virtual publishTo actions".
type virtualAuth struct {
	catalogAuth
	vmu    sync.Mutex
	vcalls []string
	vdeny  func(virtual, publishTo string, actions []string) bool
}

func (a *virtualAuth) AuthorizeVirtual(w http.ResponseWriter, r *http.Request, virtual, publishTo string, actions ...string) bool {
	a.vmu.Lock()
	a.vcalls = append(a.vcalls, virtual+" "+publishTo+" "+strings.Join(actions, ","))
	deny := a.vdeny
	a.vmu.Unlock()
	if deny != nil && deny(virtual, publishTo, actions) {
		w.WriteHeader(http.StatusUnauthorized)
		return false
	}
	return true
}

func (a *virtualAuth) virtualCalls() []string {
	a.vmu.Lock()
	defer a.vmu.Unlock()
	c := a.vcalls
	a.vcalls = nil
	return c
}

// virtualEnv is a Handler with virtual repositories over a hosted
// repository, "local", and proxies of two fake upstreams, "hub" and
// "ghcr":
//
//	all       local, hub, ghcr; publishTo local
//	open      the same, without dependency-confusion protection
//	ro        local, hub; no publishTo
//	filtered  local only for team/*, hub never for team/*; publishTo local
type virtualEnv struct {
	*env
	hub, ghcr *upstreamtest.Registry
	fs        *fsys.Mem
	vauth     *virtualAuth
}

func newVirtualEnv(t *testing.T) *virtualEnv {
	t.Helper()
	ve := &virtualEnv{hub: upstreamtest.New(t), ghcr: upstreamtest.New(t), fs: fsys.NewMem()}
	ms, err := meta.Open("/data/meta", meta.Options{FS: ve.fs, Logger: quiet})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ms.Close() })
	bs, err := blob.NewFS("/data", blob.Options{FS: ve.fs})
	if err != nil {
		t.Fatal(err)
	}
	ve.vauth = &virtualAuth{catalogAuth: catalogAuth{visible: func(string) bool { return true }}}
	ve.env = &env{t: t, meta: ms, blobs: bs, auth: &ve.vauth.catalogAuth, now: time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)}
	ve.h = ve.newHandler()
	return ve
}

// newHandler builds a Handler over ve's stores, as a restart would.
func (ve *virtualEnv) newHandler() *Handler {
	ve.t.Helper()
	off := false
	proxy := func(url string) *config.Proxy {
		return &config.Proxy{URL: url, RevalidateAfter: config.Duration{Duration: time.Minute}}
	}
	repos := []config.Repository{
		{Name: "local", Format: config.FormatOCI, Type: config.TypeHosted},
		{Name: "hub", Format: config.FormatOCI, Type: config.TypeProxy, Proxy: proxy(ve.hub.URL)},
		{Name: "ghcr", Format: config.FormatOCI, Type: config.TypeProxy, Proxy: proxy(ve.ghcr.URL)},
		{Name: "all", Format: config.FormatOCI, Type: config.TypeVirtual,
			Virtual: &config.Virtual{Members: config.Members("local", "hub", "ghcr"), PublishTo: "local"}},
		{Name: "open", Format: config.FormatOCI, Type: config.TypeVirtual,
			Virtual: &config.Virtual{Members: config.Members("local", "hub", "ghcr"), DependencyConfusionProtection: &off}},
		{Name: "ro", Format: config.FormatOCI, Type: config.TypeVirtual,
			Virtual: &config.Virtual{Members: config.Members("local", "hub")}},
		{Name: "filtered", Format: config.FormatOCI, Type: config.TypeVirtual,
			Virtual: &config.Virtual{PublishTo: "local", Members: []config.VirtualMember{
				{Name: "local", Include: []string{"team/*"}}, {Name: "hub", Exclude: []string{"team/*"}}}}},
	}
	ve.reg = metrics.NewRegistry()
	h, err := New(Options{Meta: ve.meta, Blobs: ve.blobs, Repositories: repos, Authorizer: ve.vauth,
		Logger: quiet, Metrics: ve.reg, Now: func() time.Time { return ve.now },
		Upstream: upstream.Options{Attempts: 1, Backoff: time.Millisecond}})
	if err != nil {
		ve.t.Fatal(err)
	}
	return h
}

// metric returns the value of a sample line of the exposition, or "".
func (ve *virtualEnv) metric(sample string) string {
	var b bytes.Buffer
	ve.reg.WriteTo(&b)
	for line := range strings.SplitSeq(b.String(), "\n") {
		if v, ok := strings.CutPrefix(line, sample+" "); ok {
			return v
		}
	}
	return ""
}

// pull pulls image img by ref through name, checking every byte.
func (ve *virtualEnv) pull(name, ref string, manifest []byte, blobs map[string][]byte) {
	ve.t.Helper()
	w := ve.do("GET", "/v2/"+name+"/manifests/"+ref, nil)
	want(ve.t, w, http.StatusOK, "")
	if !bytes.Equal(w.Body.Bytes(), manifest) {
		ve.t.Fatalf("GET %s:%s: manifest %.100q, want %.100q", name, ref, w.Body.Bytes(), manifest)
	}
	for d, b := range blobs {
		w := ve.do("GET", "/v2/"+name+"/blobs/"+d, nil)
		want(ve.t, w, http.StatusOK, "")
		if !bytes.Equal(w.Body.Bytes(), b) {
			ve.t.Fatalf("GET %s blob %s: %.100q, want %.100q", name, d, w.Body.Bytes(), b)
		}
	}
	deadline := time.Now().Add(5 * time.Second)
	for ve.h.fetcher.Active() > 0 {
		if time.Now().After(deadline) {
			ve.t.Fatal("fetches did not finish")
		}
		time.Sleep(time.Millisecond)
	}
}

func (ve *virtualEnv) pullImage(name, ref string, img upstreamtest.Image) {
	ve.t.Helper()
	ve.pull(name, ref, img.Manifest, img.Blobs)
}

func (ve *virtualEnv) pullLocal(name, ref string, img image) {
	ve.t.Helper()
	ve.pull(name, ref, img.manifest, map[string][]byte{
		blob.FromBytes(img.config).String(): img.config, blob.FromBytes(img.layer).String(): img.layer})
}

// tags lists the tags of name.
func (ve *virtualEnv) tags(path string) ([]string, string) {
	ve.t.Helper()
	w := ve.do("GET", "/v2/"+path, nil)
	want(ve.t, w, http.StatusOK, "")
	var tl struct {
		Name string   `json:"name"`
		Tags []string `json:"tags"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &tl); err != nil {
		ve.t.Fatal(err)
	}
	return tl.Tags, w.Header().Get("Link")
}

// referrers lists the digests in the referrers listing at path.
func (ve *virtualEnv) referrers(path string) []string {
	ve.t.Helper()
	w := ve.do("GET", "/v2/"+path, nil, "Accept", mtOCIIndex)
	want(ve.t, w, http.StatusOK, "")
	var idx struct {
		Manifests []struct {
			Digest string `json:"digest"`
		} `json:"manifests"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &idx); err != nil || w.Header().Get("Content-Type") != mtOCIIndex {
		ve.t.Fatalf("referrers %s: %s", w.Header().Get("Content-Type"), w.Body)
	}
	var out []string
	for _, m := range idx.Manifests {
		out = append(out, m.Digest)
	}
	return out
}

// errorMessage returns the message of an error response.
func errorMessage(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	var body struct {
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || len(body.Errors) == 0 {
		t.Fatalf("error body %q", w.Body)
	}
	return body.Errors[0].Message
}

// TestVirtualResolution checks that each image name is pulled from the
// member that has it: the hosted member, the first proxy, or a later one,
// with its blobs asked of that member first.
func TestVirtualResolution(t *testing.T) {
	ve := newVirtualEnv(t)
	local := newImage("local", nil)
	want(t, ve.pushImage("local/team/app", "v1", local), http.StatusCreated, "")
	nginx := ve.hub.PutImage("library/nginx", "1.27", []byte("nginx layer"))
	tool := ve.ghcr.PutImage("org/tool", "v2", []byte("tool layer one"), []byte("tool layer two"))

	ve.pullLocal("all/team/app", "v1", local)
	ve.pullLocal("all/team/app", local.digest.String(), local)
	ve.pullImage("all/library/nginx", "1.27", nginx)
	ve.pullImage("all/library/nginx", nginx.Digest, nginx)
	ve.pullImage("all/org/tool", "v2", tool)
	// The blobs came from ghcr, which served the manifest: hub was asked
	// for the manifest only.
	if n := ve.hub.Count("GET", "org/tool/blobs/") + ve.hub.Count("HEAD", "org/tool/blobs/"); n != 0 {
		t.Errorf("hub was asked for %d blobs of an image ghcr served: %v", n, ve.hub.Requests())
	}
	// Docker Hub's not found is remembered for its revalidation window,
	// so pulling the tag again does not ask it, nor does listing the tags
	// twice, until the window has passed.
	asked := func() int { return ve.hub.Count("GET", "org/tool/manifests/") + ve.hub.Count("GET", "org/tool/tags/") }
	before := asked()
	ve.pullImage("all/org/tool", "v2", tool)
	ve.tags("all/org/tool/tags/list")
	ve.tags("all/org/tool/tags/list")
	if n := asked() - before; n != 1 {
		t.Errorf("hub was asked %d times within its window, want once for the tag listing", n)
	}
	ve.now = ve.now.Add(2 * time.Minute)
	ve.pullImage("all/org/tool", "v2", tool)
	if n := asked() - before; n != 2 {
		t.Errorf("hub was asked %d times, want again once the window passed", n)
	}

	// HEAD works too, and after a restart, which forgets which member
	// served the manifest, cached blobs are served by the member holding
	// them without asking any upstream.
	w := ve.do("HEAD", "/v2/all/org/tool/manifests/v2", nil)
	want(t, w, http.StatusOK, "")
	if w.Header().Get("Docker-Content-Digest") != tool.Digest || w.Body.Len() != 0 {
		t.Errorf("HEAD: %v, %d bytes", w.Header(), w.Body.Len())
	}
	if got := ve.metric(`flint_proxy_requests_total{repository="ghcr",result="fetched"}`); got == "" {
		t.Error("ghcr's fetches are not counted")
	}
	ve.h = ve.newHandler()
	before = len(ve.hub.Requests()) + len(ve.ghcr.Requests())
	ve.pull("all/org/tool", tool.Digest, tool.Manifest, tool.Blobs)
	if n := len(ve.hub.Requests()) + len(ve.ghcr.Requests()) - before; n != 0 {
		t.Errorf("pulling cached content by digest sent %d upstream requests", n)
	}

	// Unknown content is not found, by the virtual repository's name.
	w = ve.do("GET", "/v2/all/team/app/manifests/nope", nil)
	want(t, w, http.StatusNotFound, codeManifestUnknown)
	if msg := errorMessage(t, w); !strings.Contains(msg, "all/team/app") {
		t.Errorf("not found names %q, want the virtual repository", msg)
	}
	missing := blob.FromBytes([]byte("missing")).String()
	want(t, ve.do("GET", "/v2/all/team/app/blobs/"+missing, nil), http.StatusNotFound, codeBlobUnknown)
	want(t, ve.do("GET", "/v2/all/nobody/manifests/"+missing, nil), http.StatusNotFound, codeManifestUnknown)
	want(t, ve.do("GET", "/v2/all/nobody/tags/list", nil), http.StatusNotFound, codeNameUnknown)
	want(t, ve.do("GET", "/v2/all/team/app/blobs/sha256:short", nil), http.StatusBadRequest, codeDigestInvalid)
	want(t, ve.do("GET", "/v2/all/team/app/manifests/bad~tag", nil), http.StatusNotFound, codeManifestUnknown)
	want(t, ve.do("GET", "/v2/all", nil), http.StatusNotFound, codeUnsupported)

	// The virtual repository stores nothing of its own, so garbage
	// collection needs to know nothing about it.
	v := ve.meta.View()
	defer v.Release()
	v.Scan([]byte("oci\x00"), nil, func(k []byte, _ meta.Record) bool {
		if parts := bytes.Split(k, []byte{0}); len(parts) > 2 && slices.Contains([]string{"all", "open", "ro", "filtered"}, string(parts[2])) {
			t.Errorf("a virtual repository has a record: %q", k)
		}
		return true
	})
}

// TestVirtualTags checks that a tag listing merges the members' tags,
// sorted, and paginates them.
func TestVirtualTags(t *testing.T) {
	ve := newVirtualEnv(t)
	ve.hub.PutImage("shared/app", "1.0", []byte("a"))
	ve.hub.PutImage("shared/app", "2.0", []byte("b"))
	ve.ghcr.PutImage("shared/app", "2.0", []byte("c"))
	ve.ghcr.PutImage("shared/app", "3.0", []byte("d"))
	ve.ghcr.PutImage("shared/app", "latest", []byte("e"))

	if got, link := ve.tags("all/shared/app/tags/list"); !slices.Equal(got, []string{"1.0", "2.0", "3.0", "latest"}) || link != "" {
		t.Errorf("tags = %v, link %q", got, link)
	}
	got, link := ve.tags("all/shared/app/tags/list?n=2")
	if !slices.Equal(got, []string{"1.0", "2.0"}) || link != `</v2/all/shared/app/tags/list?last=2.0&n=2>; rel="next"` {
		t.Errorf("first page = %v, link %q", got, link)
	}
	if got, link := ve.tags("all/shared/app/tags/list?n=2&last=2.0"); !slices.Equal(got, []string{"3.0", "latest"}) || link != "" {
		t.Errorf("second page = %v, link %q", got, link)
	}
	if got, _ := ve.tags("all/shared/app/tags/list?last=2.5"); !slices.Equal(got, []string{"3.0", "latest"}) {
		t.Errorf("tags after 2.5 = %v", got)
	}
	if got, _ := ve.tags("all/shared/app/tags/list?n=0"); len(got) != 0 {
		t.Errorf("n=0 = %v", got)
	}
	want(t, ve.do("GET", "/v2/all/shared/app/tags/list?n=x", nil), http.StatusBadRequest, "PAGINATION_NUMBER_INVALID")

	// A member's own pages are all read.
	for i := range 1100 {
		ve.ghcr.PutManifest("many", fmt.Sprintf("t%04d", i), upstreamtest.MediaTypeManifest, []byte(fmt.Sprintf(`{"n":%d}`, i)))
	}
	img := newImage("many", nil)
	want(t, ve.pushImage("local/many", "local-tag", img), http.StatusCreated, "")
	if got, _ := ve.tags("open/many/tags/list?n=5000"); len(got) != 1000 {
		t.Errorf("a page of %d tags, want the maximum of 1000", len(got))
	}
	got, _ = ve.tags("open/many/tags/list?last=t1095")
	if !slices.Equal(got, []string{"t1096", "t1097", "t1098", "t1099"}) {
		t.Errorf("the last tags = %v", got)
	}
}

// TestVirtualOwnership checks the hosted-ownership rule: once the hosted
// member holds a manifest of a name, the proxies are never asked about
// it, and without dependency-confusion protection the first member's tag
// wins.
func TestVirtualOwnership(t *testing.T) {
	ve := newVirtualEnv(t)
	local := newImage("first-party", nil)
	want(t, ve.pushImage("local/team/app", "v1", local), http.StatusCreated, "")
	upstreamV1 := ve.hub.PutImage("team/app", "v1", []byte("impostor"))
	evil := ve.hub.PutImage("team/app", "evil", []byte("evil"))

	ve.pullLocal("all/team/app", "v1", local)
	want(t, ve.do("GET", "/v2/all/team/app/manifests/evil", nil), http.StatusNotFound, codeManifestUnknown)
	want(t, ve.do("GET", "/v2/all/team/app/manifests/"+upstreamV1.Digest, nil), http.StatusNotFound, codeManifestUnknown)
	if got, _ := ve.tags("all/team/app/tags/list"); !slices.Equal(got, []string{"v1"}) {
		t.Errorf("tags = %v, want the hosted member's only", got)
	}
	if n := len(ve.hub.Requests()); n != 0 {
		t.Errorf("hub was asked about a name the hosted member owns: %v", ve.hub.Requests())
	}

	// Without protection, the first member's tag wins and the others' are
	// served too.
	ve.pullLocal("open/team/app", "v1", local)
	ve.pullImage("open/team/app", "evil", evil)
	if got, _ := ve.tags("open/team/app/tags/list"); !slices.Equal(got, []string{"evil", "v1"}) {
		t.Errorf("unprotected tags = %v", got)
	}

	// The filters decide which members are asked at all.
	ve.pullLocal("filtered/team/app", "v1", local)
	want(t, ve.do("GET", "/v2/filtered/team/other/manifests/v1", nil), http.StatusNotFound, codeManifestUnknown)
	other := ve.hub.PutImage("library/redis", "7", []byte("redis"))
	ve.pullImage("filtered/library/redis", "7", other)
	before := ve.hub.Count("GET", "team/other")
	want(t, ve.do("GET", "/v2/filtered/team/other/manifests/v1", nil), http.StatusNotFound, codeManifestUnknown)
	if ve.hub.Count("GET", "team/other") != before || before != 0 {
		t.Error("hub was asked for a name its exclude filter refuses")
	}
}

// TestVirtualBlobNeedsHolder checks that a blob is served only by a member
// that holds it under the image name: a digest stored for another name is
// not enough.
func TestVirtualBlobNeedsHolder(t *testing.T) {
	ve := newVirtualEnv(t)
	img := newImage("secret", nil)
	want(t, ve.pushImage("local/private/app", "v1", img), http.StatusCreated, "")
	layer := blob.FromBytes(img.layer).String()
	want(t, ve.do("GET", "/v2/all/private/app/blobs/"+layer, nil), http.StatusOK, "")
	want(t, ve.do("GET", "/v2/all/someone/else/blobs/"+layer, nil), http.StatusNotFound, codeBlobUnknown)
	want(t, ve.do("HEAD", "/v2/all/someone/else/blobs/"+layer, nil), http.StatusNotFound, "")
	want(t, ve.do("GET", "/v2/all/someone/else/manifests/"+img.digest.String(), nil), http.StatusNotFound, codeManifestUnknown)
}

// TestVirtualSkipsFailingMember checks that a member that cannot be
// reached is skipped and counted, that cached content is still served,
// and that a request fails only if no member answered.
func TestVirtualSkipsFailingMember(t *testing.T) {
	ve := newVirtualEnv(t)
	nginx := ve.hub.PutImage("library/nginx", "1.27", []byte("nginx layer"))
	tool := ve.ghcr.PutImage("org/tool", "v2", []byte("tool layer"))
	ve.pullImage("all/library/nginx", "1.27", nginx)

	ve.hub.SetDown(true)
	ve.pullImage("all/org/tool", "v2", tool)
	if got := ve.metric(`flint_virtual_member_skips_total{repository="all",member="hub"}`); got == "" || got == "0" {
		t.Errorf("hub's failure is not counted: %q", got)
	}
	// Offline: the cached image is still served.
	ve.ghcr.SetDown(true)
	ve.h = ve.newHandler()
	ve.pullImage("all/library/nginx", "1.27", nginx)
	ve.pullImage("all/org/tool", tool.Digest, tool)
	if got, _ := ve.tags("all/library/nginx/tags/list"); !slices.Equal(got, []string{"1.27"}) {
		t.Errorf("offline tags = %v", got)
	}
	// With nothing cached and every proxy down, the failure is the answer,
	// except for tag listings, which a proxy answers from its cached tags.
	w := ve.do("GET", "/v2/all/library/redis/manifests/7", nil)
	want(t, w, http.StatusServiceUnavailable, codeUnavailable)
	if w.Header().Get("Retry-After") == "" {
		t.Error("the failure has no Retry-After")
	}
	want(t, ve.do("GET", "/v2/all/library/redis/tags/list", nil), http.StatusNotFound, codeNameUnknown)
}

// TestVirtualPublish checks that pushes and deletes go to the publishTo
// member, authorized through the virtual repository, with locations that
// name it, and are refused without a publishTo or when its filters do not
// admit the name.
func TestVirtualPublish(t *testing.T) {
	ve := newVirtualEnv(t)
	img := newImage("pushed", nil)

	// A chunked upload: the session's location stays in the virtual
	// repository.
	w := ve.do("POST", "/v2/all/team/app/blobs/uploads/", nil)
	want(t, w, http.StatusAccepted, "")
	loc := w.Header().Get("Location")
	if !strings.HasPrefix(loc, "/v2/all/team/app/blobs/uploads/") {
		t.Fatalf("upload location %q", loc)
	}
	w = ve.do("PATCH", loc, img.config)
	want(t, w, http.StatusAccepted, "")
	w = ve.do("PUT", w.Header().Get("Location")+"?digest="+blob.FromBytes(img.config).String(), nil)
	want(t, w, http.StatusCreated, "")
	if got := w.Header().Get("Location"); got != "/v2/all/team/app/blobs/"+blob.FromBytes(img.config).String() {
		t.Errorf("blob location %q", got)
	}
	ve.pushBlob("all/team/app", img.layer)
	w = ve.do("PUT", "/v2/all/team/app/manifests/v1", img.manifest, "Content-Type", mtOCIManifest)
	want(t, w, http.StatusCreated, "")
	if got := w.Header().Get("Location"); got != "/v2/all/team/app/manifests/"+img.digest.String() {
		t.Errorf("manifest location %q", got)
	}
	ve.pullLocal("local/team/app", "v1", img)
	ve.pullLocal("all/team/app", "v1", img)
	calls := ve.vauth.virtualCalls()
	if len(calls) == 0 || calls[0] != "all/team/app local/team/app pull,push" {
		t.Errorf("virtual authorizations = %v", calls)
	}

	// A cross-repository mount from a name in the virtual repository.
	layer := blob.FromBytes(img.layer)
	w = ve.do("POST", "/v2/all/team/copy/blobs/uploads/?mount="+layer.String()+"&from=all/team/app", nil)
	want(t, w, http.StatusCreated, "")
	if got := w.Header().Get("Location"); got != "/v2/all/team/copy/blobs/"+layer.String() {
		t.Errorf("mount location %q", got)
	}
	want(t, ve.do("GET", "/v2/local/team/copy/blobs/"+layer.String(), nil), http.StatusOK, "")
	// A blob the source name does not hold is not mounted.
	other := blob.FromBytes([]byte("not there"))
	want(t, ve.do("POST", "/v2/all/team/copy/blobs/uploads/?mount="+other.String()+"&from=all/team/app", nil), http.StatusAccepted, "")

	// Deletes go to publishTo too.
	want(t, ve.do("DELETE", "/v2/all/team/app/manifests/v1", nil), http.StatusAccepted, "")
	want(t, ve.do("GET", "/v2/local/team/app/manifests/v1", nil), http.StatusNotFound, codeManifestUnknown)
	if calls := ve.vauth.virtualCalls(); !slices.Contains(calls, "all/team/app local/team/app delete") {
		t.Errorf("delete authorizations = %v", calls)
	}

	// A refused authorization stops the push.
	ve.vauth.vdeny = func(string, string, []string) bool { return true }
	want(t, ve.do("PUT", "/v2/all/team/app/manifests/v2", img.manifest, "Content-Type", mtOCIManifest), http.StatusUnauthorized, "")
	ve.vauth.vdeny = nil
	ve.vauth.virtualCalls()

	// Without publishTo, pushes and deletes are not allowed.
	w = ve.do("PUT", "/v2/ro/team/app/manifests/v1", img.manifest, "Content-Type", mtOCIManifest)
	want(t, w, http.StatusMethodNotAllowed, codeUnsupported)
	if w.Header().Get("Allow") != "GET, HEAD" || !strings.Contains(errorMessage(t, w), "local") {
		t.Errorf("refused push: Allow %q, %s", w.Header().Get("Allow"), w.Body)
	}
	want(t, ve.do("POST", "/v2/ro/team/app/blobs/uploads/", nil), http.StatusMethodNotAllowed, codeUnsupported)
	want(t, ve.do("DELETE", "/v2/ro/team/app/blobs/"+layer.String(), nil), http.StatusMethodNotAllowed, codeUnsupported)
	if calls := ve.vauth.virtualCalls(); len(calls) != 0 {
		t.Errorf("refused pushes were authorized: %v", calls)
	}
	// A name publishTo's filters do not admit is refused.
	w = ve.do("POST", "/v2/filtered/library/app/blobs/uploads/", nil)
	want(t, w, http.StatusForbidden, codeDenied)
	if !strings.Contains(errorMessage(t, w), `include filter ["team/*"]`) {
		t.Errorf("filter refusal: %s", w.Body)
	}
	want(t, ve.do("POST", "/v2/filtered/team/app/blobs/uploads/", nil), http.StatusAccepted, "")
	// Methods no repository serves are 405 as usual.
	want(t, ve.do("PATCH", "/v2/all/team/app/manifests/v1", nil), http.StatusMethodNotAllowed, codeUnsupported)
}

// TestVirtualAuthorizerFallback checks that with an Authorizer that does
// not implement VirtualAuthorizer, a push through a virtual repository is
// authorized with pull on its name and push on publishTo's.
func TestVirtualAuthorizerFallback(t *testing.T) {
	e := newEnv(t)
	repos := append(slices.Clone(testRepos), config.Repository{Name: "all", Format: config.FormatOCI, Type: config.TypeVirtual,
		Virtual: &config.Virtual{Members: config.Members("hosted", "other"), PublishTo: "hosted"}})
	h, err := New(Options{Meta: e.meta, Blobs: e.blobs, Repositories: repos, Authorizer: e.auth, Logger: quiet})
	if err != nil {
		t.Fatal(err)
	}
	e.h = h
	e.auth.reset()
	want(t, e.do("POST", "/v2/all/app/blobs/uploads/", nil), http.StatusAccepted, "")
	if got := e.auth.reset(); !slices.Equal(got, []authCall{{"all/app", "pull"}, {"hosted/app", "push"}}) {
		t.Errorf("authorizations = %v", got)
	}
	e.auth.deny = func(repo string, _ []string) bool { return repo == "hosted/app" }
	want(t, e.do("POST", "/v2/all/app/blobs/uploads/", nil), http.StatusUnauthorized, "")
	// Pulls need pull on the virtual repository only.
	e.auth.reset()
	e.do("GET", "/v2/all/app/tags/list", nil)
	if got := e.auth.reset(); !slices.Equal(got, []authCall{{"all/app", "pull"}}) {
		t.Errorf("pull authorizations = %v", got)
	}
}

// TestVirtualNS checks containerd's ns parameter: a request naming a
// registry is answered by the proxy members that mirror it only.
func TestVirtualNS(t *testing.T) {
	ve := newVirtualEnv(t)
	fromHub := ve.hub.PutImage("library/alpine", "3.20", []byte("hub alpine"))
	fromGHCR := ve.ghcr.PutImage("library/alpine", "3.20", []byte("ghcr alpine"))
	local := newImage("local alpine", nil)
	ns := func(u string) string {
		pu, err := url.Parse(u)
		if err != nil {
			t.Fatal(err)
		}
		return pu.Host
	}

	ve.pullImage("all/library/alpine", "3.20?ns="+ns(ve.ghcr.URL), fromGHCR)
	ve.pullImage("all/library/alpine", "3.20?ns="+ns(ve.hub.URL), fromHub)
	ve.pullImage("all/library/alpine", "3.20", fromHub)
	if got, _ := ve.tags("all/library/alpine/tags/list?ns=" + ns(ve.ghcr.URL)); !slices.Equal(got, []string{"3.20"}) {
		t.Errorf("tags with ns = %v", got)
	}
	// Blobs follow the registry too: hub holds none of ghcr's.
	ghcrLayer := fromGHCR.Layers[0]
	want(t, ve.do("GET", "/v2/all/library/alpine/blobs/"+ghcrLayer+"?ns="+ns(ve.hub.URL), nil), http.StatusNotFound, codeBlobUnknown)

	// A registry no member mirrors is not found, so containerd tries its
	// next host, and the hosted member does not answer for a registry.
	w := ve.do("GET", "/v2/all/library/alpine/manifests/3.20?ns=quay.io", nil)
	want(t, w, http.StatusNotFound, codeNameUnknown)
	if !strings.Contains(errorMessage(t, w), "quay.io") {
		t.Errorf("unknown ns: %s", w.Body)
	}
	want(t, ve.pushImage("local/team/app", "v1", local), http.StatusCreated, "")
	want(t, ve.do("GET", "/v2/all/team/app/manifests/v1?ns="+ns(ve.hub.URL), nil), http.StatusNotFound, codeManifestUnknown)
	ve.pullLocal("all/team/app", "v1", local)
	// Filters still apply.
	want(t, ve.do("GET", "/v2/filtered/team/x/manifests/v1?ns="+ns(ve.hub.URL), nil), http.StatusNotFound, codeNameUnknown)
}

func TestMirrors(t *testing.T) {
	newProxy := func(u string) *proxyRepo {
		p, err := newProxyRepo(config.Repository{Name: "p", Proxy: &config.Proxy{URL: u}}, upstream.Options{})
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	tests := []struct {
		url, ns string
		want    bool
	}{
		{"https://registry-1.docker.io", "docker.io", true},
		{"https://registry-1.docker.io", "Docker.IO", true},
		{"https://registry-1.docker.io", "index.docker.io", true},
		{"https://registry-1.docker.io", "registry-1.docker.io", true},
		{"https://registry-1.docker.io", "ghcr.io", false},
		{"https://ghcr.io", "ghcr.io", true},
		{"https://ghcr.io", "docker.io", false},
		{"https://ghcr.io:443", "ghcr.io", true},
		{"https://quay.io", "quay.io", true},
		{"https://registry.example.com:5000", "registry.example.com:5000", true},
		{"https://registry.example.com:5000", "registry.example.com", false},
	}
	for _, tt := range tests {
		if got := newProxy(tt.url).mirrors(tt.ns); got != tt.want {
			t.Errorf("proxy of %s mirrors %s = %v, want %v", tt.url, tt.ns, got, tt.want)
		}
	}
}

// TestVirtualReferrers checks that referrers come from the member that
// holds the subject manifest.
func TestVirtualReferrers(t *testing.T) {
	ve := newVirtualEnv(t)
	subject := newImage("subject", nil)
	want(t, ve.pushImage("all/team/app", "v1", subject), http.StatusCreated, "")
	sig := newImage("signature", map[string]any{"artifactType": "application/example.sig",
		"subject": desc(mtOCIManifest, subject.manifest)})
	want(t, ve.pushImage("all/team/app", sig.digest.String(), sig), http.StatusCreated, "")

	if got := ve.referrers("all/team/app/referrers/" + subject.digest.String()); !slices.Equal(got, []string{sig.digest.String()}) {
		t.Errorf("hosted referrers = %v", got)
	}
	if got := ve.referrers("all/team/app/referrers/" + blob.FromBytes([]byte("none")).String()); len(got) != 0 {
		t.Errorf("referrers of an unknown manifest = %v", got)
	}

	// A proxy member serves its upstream's referrers once it is found to
	// hold the subject.
	ve.ghcr.Referrers = true
	img := ve.ghcr.PutImage("org/tool", "v1", []byte("tool"))
	sigBody := mustJSON(map[string]any{"schemaVersion": 2, "mediaType": mtOCIManifest, "artifactType": "application/example.sig",
		"config":  map[string]any{"mediaType": "application/vnd.oci.empty.v1+json", "digest": ve.ghcr.PutBlob("org/tool", []byte("{}")), "size": 2},
		"layers":  []any{},
		"subject": map[string]any{"mediaType": mtOCIManifest, "digest": img.Digest, "size": len(img.Manifest)}})
	sigDigest := ve.ghcr.PutManifest("org/tool", "", mtOCIManifest, sigBody)
	if got := ve.referrers("all/org/tool/referrers/" + img.Digest); !slices.Equal(got, []string{sigDigest}) {
		t.Errorf("proxy referrers = %v", got)
	}
	if ve.hub.Count("GET", "referrers") != 0 {
		t.Error("hub was asked for referrers of a manifest it does not hold")
	}
}

// TestVirtualPushReusesMemberBlobs checks a push through a virtual
// repository under a name an upstream has: a blob's HEAD asks no
// upstream, so it reports only blobs a member holds, and a manifest that
// references a blob a proxy member holds under the name has it linked
// into the publishTo member.
func TestVirtualPushReusesMemberBlobs(t *testing.T) {
	ve := newVirtualEnv(t)
	base := ve.hub.PutImage("library/alpine", "3.20", []byte("alpine base layer"))
	other := ve.hub.PutImage("library/redis", "7", []byte("redis layer"))

	// A blob the upstream has but no member holds: HEAD says not found
	// without asking the upstream, and GET fetches it.
	want(t, ve.do("HEAD", "/v2/all/library/redis/blobs/"+other.Layers[0], nil), http.StatusNotFound, "")
	if n := len(ve.hub.Requests()); n != 0 {
		t.Errorf("a HEAD of a blob asked the upstream: %v", ve.hub.Requests())
	}
	want(t, ve.do("GET", "/v2/all/library/redis/blobs/"+other.Layers[0], nil), http.StatusOK, "")

	// Once pulled, the base image's layer is held by hub, and a push of
	// an image built on it needs only its own config.
	ve.pullImage("all/library/alpine", "3.20", base)
	layer := base.Layers[0]
	want(t, ve.do("HEAD", "/v2/all/library/alpine/blobs/"+layer, nil), http.StatusOK, "")
	cfg := []byte(`{"architecture":"amd64","os":"linux","custom":true}`)
	ve.pushBlob("all/library/alpine", cfg)
	manifest := mustJSON(map[string]any{"schemaVersion": 2, "mediaType": mtOCIManifest,
		"config": desc("application/vnd.oci.image.config.v1+json", cfg),
		"layers": []any{map[string]any{"mediaType": upstreamtest.MediaTypeLayer, "digest": layer, "size": len(base.Blobs[layer])}}})
	want(t, ve.do("PUT", "/v2/all/library/alpine/manifests/custom", manifest, "Content-Type", mtOCIManifest), http.StatusCreated, "")
	ve.pull("local/library/alpine", "custom", manifest, map[string][]byte{layer: base.Blobs[layer], blob.FromBytes(cfg).String(): cfg})
	// The hosted member now owns the name.
	ve.pull("all/library/alpine", "custom", manifest, map[string][]byte{layer: base.Blobs[layer]})
	want(t, ve.do("GET", "/v2/all/library/alpine/manifests/3.20", nil), http.StatusNotFound, codeManifestUnknown)

	// A blob no member holds is still missing.
	missing := []byte("never uploaded")
	manifest = mustJSON(map[string]any{"schemaVersion": 2, "mediaType": mtOCIManifest,
		"config": desc("application/vnd.oci.image.config.v1+json", cfg),
		"layers": []any{desc(upstreamtest.MediaTypeLayer, missing)}})
	want(t, ve.do("PUT", "/v2/all/library/alpine/manifests/broken", manifest, "Content-Type", mtOCIManifest), http.StatusBadRequest, codeManifestBlobUnknown)
}

// TestVirtualSignUpstreamImage checks the sequence of signing an upstream
// image through a virtual repository, as cosign or oras attach do with
// the referrers API: the signature lands in the publishTo member without
// making it own the name, so the image is still pulled from the upstream,
// by tag and by digest, and the referrers listing through the virtual
// repository has the signature with the upstream's referrers.
func TestVirtualSignUpstreamImage(t *testing.T) {
	ve := newVirtualEnv(t)
	ve.hub.Referrers = true
	img := ve.hub.PutImage("library/nginx", "1.27", []byte("nginx layer"))
	ve.pullImage("all/library/nginx", "1.27", img)

	subject := map[string]any{"mediaType": upstreamtest.MediaTypeManifest, "digest": img.Digest, "size": len(img.Manifest)}
	upstreamSig := ve.hub.PutManifest("library/nginx", "", mtOCIManifest, mustJSON(map[string]any{
		"schemaVersion": 2, "mediaType": mtOCIManifest, "artifactType": "application/example.att",
		"config":  map[string]any{"mediaType": "application/vnd.oci.empty.v1+json", "digest": ve.hub.PutBlob("library/nginx", []byte("{}")), "size": 2},
		"layers":  []any{},
		"subject": subject}))
	sig := newImage("signature", map[string]any{"artifactType": "application/example.sig", "subject": subject})
	w := ve.pushImage("all/library/nginx", sig.digest.String(), sig)
	want(t, w, http.StatusCreated, "")
	if w.Header().Get("OCI-Subject") != img.Digest {
		t.Errorf("OCI-Subject = %q, want %s", w.Header().Get("OCI-Subject"), img.Digest)
	}
	want(t, ve.do("HEAD", "/v2/local/library/nginx/manifests/"+sig.digest.String(), nil), http.StatusOK, "")

	ve.pullImage("all/library/nginx", "1.27", img)
	ve.pullImage("all/library/nginx", img.Digest, img)
	if got, _ := ve.tags("all/library/nginx/tags/list"); !slices.Equal(got, []string{"1.27"}) {
		t.Errorf("tags = %v, want the upstream's", got)
	}
	got := ve.referrers("all/library/nginx/referrers/" + img.Digest)
	if !slices.Equal(got, []string{sig.digest.String(), upstreamSig}) {
		t.Errorf("referrers = %v, want the pushed signature, then the upstream's %s", got, upstreamSig)
	}
	w = ve.do("GET", "/v2/all/library/nginx/referrers/"+img.Digest+"?artifactType=application/example.sig", nil)
	want(t, w, http.StatusOK, "")
	if w.Header().Get("OCI-Filters-Applied") != "artifactType" || !strings.Contains(w.Body.String(), sig.digest.String()) ||
		strings.Contains(w.Body.String(), upstreamSig) {
		t.Errorf("filtered referrers %v: %s", w.Header(), w.Body)
	}

	// A first-party image of the name, which has no subject, makes the
	// hosted member own it.
	local := newImage("first-party", nil)
	want(t, ve.pushImage("all/library/nginx", "custom", local), http.StatusCreated, "")
	want(t, ve.do("GET", "/v2/all/library/nginx/manifests/1.27", nil), http.StatusNotFound, codeManifestUnknown)
}

// TestVirtualSignUpstreamImageTagSchema checks the sequence of signing an
// upstream image through a virtual repository as cosign does by default,
// with a manifest without a subject tagged sha256-<hex>.sig: the
// signature lands in the publishTo member without making it own the name,
// so the image is still pulled from the upstream, by tag and by digest,
// and the signature's tag is pulled from the publishTo member.
func TestVirtualSignUpstreamImageTagSchema(t *testing.T) {
	ve := newVirtualEnv(t)
	img := ve.hub.PutImage("library/nginx", "1.27", []byte("nginx layer"))
	ve.pullImage("all/library/nginx", "1.27", img)

	sigTag := strings.Replace(img.Digest, ":", "-", 1) + ".sig"
	sig := newImage("cosign signature", nil)
	want(t, ve.pushImage("all/library/nginx", sigTag, sig), http.StatusCreated, "")
	ve.pullLocal("local/library/nginx", sigTag, sig)

	ve.pullImage("all/library/nginx", "1.27", img)
	ve.pullImage("all/library/nginx", img.Digest, img)
	ve.pullLocal("all/library/nginx", sigTag, sig)
	if got, _ := ve.tags("all/library/nginx/tags/list"); !slices.Equal(got, []string{"1.27", sigTag}) {
		t.Errorf("tags = %v, want the upstream's and the signature's", got)
	}

	// The same signature under any other tag makes the hosted member own
	// the name, as does a tag that only resembles the schema.
	for _, tag := range []string{"sha256-" + strings.Repeat("A", 64) + ".sig", "signed"} {
		ve := newVirtualEnv(t)
		img := ve.hub.PutImage("library/nginx", "1.27", []byte("nginx layer"))
		ve.pullImage("all/library/nginx", "1.27", img)
		want(t, ve.pushImage("all/library/nginx", sigTag, sig), http.StatusCreated, "")
		want(t, ve.do("PUT", "/v2/all/library/nginx/manifests/"+tag, sig.manifest, "Content-Type", mtOCIManifest), http.StatusCreated, "")
		if w := ve.do("GET", "/v2/all/library/nginx/manifests/1.27", nil); w.Code != http.StatusNotFound {
			t.Errorf("with the signature also tagged %s, the upstream image was served: %d", tag, w.Code)
		}
	}
}

// putUpstreamIndex stores a two-platform image index of name in the hub
// upstream, tagged tag, and returns it with its platform images.
func (ve *virtualEnv) putUpstreamIndex(name, tag string) ([]byte, []upstreamtest.Image) {
	ve.t.Helper()
	var platforms []upstreamtest.Image
	var manifests []any
	for _, arch := range []string{"amd64", "arm64"} {
		img := ve.hub.PutImage(name, "", []byte(name+" layer for "+arch))
		platforms = append(platforms, img)
		d := desc(upstreamtest.MediaTypeManifest, img.Manifest)
		d["platform"] = map[string]any{"os": "linux", "architecture": arch}
		manifests = append(manifests, d)
	}
	index := mustJSON(map[string]any{"schemaVersion": 2, "mediaType": mtOCIIndex, "manifests": manifests})
	ve.hub.PutManifest(name, tag, upstreamtest.MediaTypeIndex, index)
	return index, platforms
}

// TestVirtualPushUpstreamIndex checks a push through a virtual repository
// of a multi-platform index whose platform images a proxy member holds
// under the name, as crane copy does to vendor an upstream image under
// its own name and crane tag or docker buildx imagetools create do to
// retag it: the client pushes only the index, having been told the
// platform images exist, and they are linked into the publishTo member
// with their blobs.
func TestVirtualPushUpstreamIndex(t *testing.T) {
	for _, tag := range []string{"1.27", "pinned"} {
		t.Run(tag, func(t *testing.T) {
			ve := newVirtualEnv(t)
			index, platforms := ve.putUpstreamIndex("library/nginx", "1.27")
			ve.pull("all/library/nginx", "1.27", index, nil)
			for _, img := range platforms {
				ve.pullImage("all/library/nginx", img.Digest, img)
				want(t, ve.do("HEAD", "/v2/all/library/nginx/manifests/"+img.Digest, nil), http.StatusOK, "")
			}

			want(t, ve.do("PUT", "/v2/all/library/nginx/manifests/"+tag, index, "Content-Type", mtOCIIndex), http.StatusCreated, "")
			ve.pull("local/library/nginx", tag, index, nil)
			for _, img := range platforms {
				ve.pullImage("local/library/nginx", img.Digest, img)
			}
			ve.pull("all/library/nginx", tag, index, nil)
		})
	}

	// As crane copy pushes an image never pulled before, checking for
	// each platform image through the virtual repository, which caches
	// only its manifest in the proxy member: the platform images' blobs
	// are fetched into the proxy member as a pull would, and linked.
	ve := newVirtualEnv(t)
	index, platforms := ve.putUpstreamIndex("library/nginx", "1.27")
	for _, img := range platforms {
		want(t, ve.do("HEAD", "/v2/all/library/nginx/manifests/"+img.Digest, nil), http.StatusOK, "")
	}
	if n := ve.hub.Count("GET", "/blobs/"); n != 0 {
		t.Fatalf("checking for the platform images fetched %d blobs", n)
	}
	want(t, ve.do("PUT", "/v2/all/library/nginx/manifests/1.27", index, "Content-Type", mtOCIIndex), http.StatusCreated, "")
	ve.pull("local/library/nginx", "1.27", index, nil)
	for _, img := range platforms {
		ve.pullImage("local/library/nginx", img.Digest, img)
		ve.pullImage("hub/library/nginx", img.Digest, img)
	}
}

// TestVirtualPushUpstreamIndexRefused checks that a push of an index
// through a virtual repository is refused, linking nothing into the
// publishTo member, when a platform image's blob cannot be fetched from
// the upstream or a platform image is held by no member: the publishTo
// member does not come to own the name, so the upstream image is still
// served.
func TestVirtualPushUpstreamIndexRefused(t *testing.T) {
	for _, tc := range []struct {
		name   string
		break_ func(ve *virtualEnv, img upstreamtest.Image)
	}{
		{"corrupt", func(ve *virtualEnv, img upstreamtest.Image) { ve.hub.Corrupt(img.Layers[0]) }},
		{"not found", func(ve *virtualEnv, img upstreamtest.Image) {
			ve.hub.SetStatus(func(r *http.Request) int {
				if strings.HasSuffix(r.URL.Path, "/blobs/"+img.Layers[0]) {
					return http.StatusNotFound
				}
				return 0
			})
		}},
		{"unavailable", func(ve *virtualEnv, img upstreamtest.Image) { ve.hub.SetDown(true) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ve := newVirtualEnv(t)
			index, platforms := ve.putUpstreamIndex("library/nginx", "1.27")
			ve.pull("all/library/nginx", "1.27", index, nil)
			ve.pullImage("all/library/nginx", platforms[0].Digest, platforms[0])
			want(t, ve.do("HEAD", "/v2/all/library/nginx/manifests/"+platforms[1].Digest, nil), http.StatusOK, "")
			tc.break_(ve, platforms[1])

			w := ve.do("PUT", "/v2/all/library/nginx/manifests/1.27", index, "Content-Type", mtOCIIndex)
			want(t, w, http.StatusBadRequest, codeManifestBlobUnknown)
			msg := errorMessage(t, w)
			if !strings.Contains(msg, platforms[1].Layers[0]) && !strings.Contains(msg, platforms[1].Config) {
				t.Errorf("the refusal does not name the blob: %s", msg)
			}
			want(t, ve.do("GET", "/v2/local/library/nginx/tags/list", nil), http.StatusNotFound, codeNameUnknown)
			ve.hub.SetDown(false)
			ve.hub.SetStatus(nil)
			ve.pull("all/library/nginx", "1.27", index, nil)
		})
	}

	// A platform image no member holds: the push reports it, and the other
	// platform image, which the proxy member holds, is not linked either.
	ve := newVirtualEnv(t)
	index, platforms := ve.putUpstreamIndex("library/nginx", "1.27")
	ve.pull("all/library/nginx", "1.27", index, nil)
	ve.pullImage("all/library/nginx", platforms[0].Digest, platforms[0])
	want(t, ve.do("PUT", "/v2/all/library/nginx/manifests/1.27", index, "Content-Type", mtOCIIndex), http.StatusBadRequest, codeManifestBlobUnknown)
	want(t, ve.do("GET", "/v2/local/library/nginx/tags/list", nil), http.StatusNotFound, codeNameUnknown)
	ve.pull("all/library/nginx", "1.27", index, nil)
}

// TestVirtualPushAfterOwnership checks a multi-platform push through a
// virtual repository, as docker buildx makes it, under a name a proxy
// member serves: once platform A's manifest lands in the publishTo
// member, which then owns the name, platform B's manifest may still use
// the blobs the proxy member holds under it, which the client was told
// exist before.
func TestVirtualPushAfterOwnership(t *testing.T) {
	ve := newVirtualEnv(t)
	base := ve.hub.PutImage("library/nginx", "1.27", []byte("nginx base layer"))
	ve.pullImage("all/library/nginx", "1.27", base)
	layer := base.Layers[0]
	want(t, ve.do("HEAD", "/v2/all/library/nginx/blobs/"+layer, nil), http.StatusOK, "")

	a := newImage("platform a", nil)
	want(t, ve.pushImage("all/library/nginx", a.digest.String(), a), http.StatusCreated, "")
	want(t, ve.do("GET", "/v2/all/library/nginx/manifests/1.27", nil), http.StatusNotFound, codeManifestUnknown)

	cfg := []byte(`{"architecture":"arm64","os":"linux"}`)
	ve.pushBlob("all/library/nginx", cfg)
	b := mustJSON(map[string]any{"schemaVersion": 2, "mediaType": mtOCIManifest,
		"config": desc("application/vnd.oci.image.config.v1+json", cfg),
		"layers": []any{map[string]any{"mediaType": upstreamtest.MediaTypeLayer, "digest": layer, "size": len(base.Blobs[layer])}}})
	bDigest := blob.FromBytes(b).String()
	want(t, ve.do("PUT", "/v2/all/library/nginx/manifests/"+bDigest, b, "Content-Type", mtOCIManifest), http.StatusCreated, "")
	index := mustJSON(map[string]any{"schemaVersion": 2, "mediaType": mtOCIIndex,
		"manifests": []any{desc(mtOCIManifest, a.manifest), desc(mtOCIManifest, b)}})
	want(t, ve.do("PUT", "/v2/all/library/nginx/manifests/multi", index, "Content-Type", mtOCIIndex), http.StatusCreated, "")
	ve.pull("all/library/nginx", bDigest, b, map[string][]byte{layer: base.Blobs[layer], blob.FromBytes(cfg).String(): cfg})
	ve.pull("all/library/nginx", "multi", index, nil)
}
