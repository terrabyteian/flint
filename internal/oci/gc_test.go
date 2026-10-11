package oci

import (
	"bytes"
	"context"
	"fmt"
	"math/rand/v2"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/terrabyteian/flint/internal/blob"
	"github.com/terrabyteian/flint/internal/fsys"
	"github.com/terrabyteian/flint/internal/gc"
	"github.com/terrabyteian/flint/internal/gc/gctest"
	"github.com/terrabyteian/flint/internal/meta"
	"github.com/terrabyteian/flint/internal/metrics"
)

// past is how far the clock moves to take content past the grace period.
const past = gc.DefaultGracePeriod + time.Minute

// syncClock is a settable clock, safe for concurrent use.
type syncClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *syncClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *syncClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// gcEnv is an env whose handler, blob store, and garbage collector share
// one clock.
type gcEnv struct {
	*env
	clock *syncClock
	gc    *gc.Collector

	hookMu sync.Mutex
	hook   func(gc.Step)
}

func newGCEnv(t *testing.T) *gcEnv {
	t.Helper()
	fs := fsys.NewMem()
	ge := &gcEnv{clock: &syncClock{t: time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)}}
	ms, err := meta.Open("/data/meta", meta.Options{FS: fs, Logger: quiet})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ms.Close() })
	bs, err := blob.NewFS("/data", blob.Options{FS: fs, Now: ge.clock.now})
	if err != nil {
		t.Fatal(err)
	}
	ge.env = &env{t: t, meta: ms, blobs: bs, auth: &catalogAuth{visible: func(string) bool { return true }}, reg: metrics.NewRegistry()}
	ge.h, err = New(Options{Meta: ms, Blobs: bs, Repositories: testRepos, Authorizer: ge.auth,
		Logger: quiet, Metrics: ge.reg, Now: ge.clock.now})
	if err != nil {
		t.Fatal(err)
	}
	ge.gc = newCollector(t, ms, bs, ge.clock.now, ge.callHook)
	return ge
}

// newCollector returns a garbage collector with the OCI marker.
func newCollector(t *testing.T, ms meta.Store, bs blob.Store, now func() time.Time, hook func(gc.Step)) *gc.Collector {
	t.Helper()
	c, err := gc.New(gc.Options{Meta: ms, Blobs: bs, Markers: []gc.Marker{GCMarker()}, Logger: quiet, Now: now, Hook: hook})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	return c
}

func (ge *gcEnv) callHook(s gc.Step) {
	ge.hookMu.Lock()
	h := ge.hook
	ge.hookMu.Unlock()
	if h != nil {
		h(s)
	}
}

func (ge *gcEnv) setHook(h func(gc.Step)) {
	ge.hookMu.Lock()
	defer ge.hookMu.Unlock()
	ge.hook = h
}

// collect runs the garbage collector and checks that it succeeded.
func collect(t *testing.T, c *gc.Collector) *gc.Report {
	t.Helper()
	r, err := c.Run(context.Background(), gc.RunOptions{})
	if err != nil || r.State != gc.StateSucceeded {
		t.Fatalf("garbage collection = %+v, %v", r, err)
	}
	return r
}

func stored(t *testing.T, bs blob.Store, d blob.Digest) bool {
	t.Helper()
	_, err := bs.Stat(context.Background(), d)
	return err == nil
}

// checkReferencedStored fails the test unless the OCI marker covers every
// record and every blob the metadata references is stored.
func checkReferencedStored(t *testing.T, ms meta.Store, bs blob.Store) {
	t.Helper()
	gctest.CheckStored(t, ms, bs, GCMarker())
}

// pullImage pulls an image by ref and checks every byte.
func (e *env) pullImage(name, ref string, img image) {
	e.t.Helper()
	if err := e.checkPull(name, ref, img); err != nil {
		e.t.Fatal(err)
	}
}

// checkPull pulls an image by ref and reports what differs.
func (e *env) checkPull(name, ref string, img image) error {
	w := e.do("GET", "/v2/"+name+"/manifests/"+ref, nil)
	if w.Code != http.StatusOK || !bytes.Equal(w.Body.Bytes(), img.manifest) {
		return fmt.Errorf("pulling the manifest of %s:%s = %d %.200s", name, ref, w.Code, w.Body)
	}
	for _, b := range [][]byte{img.config, img.layer} {
		d := blob.FromBytes(b)
		w := e.do("GET", "/v2/"+name+"/blobs/"+d.String(), nil)
		if w.Code != http.StatusOK || !bytes.Equal(w.Body.Bytes(), b) {
			return fmt.Errorf("pulling blob %s of %s:%s = %d %.200s", d, name, ref, w.Code, w.Body)
		}
	}
	return nil
}

// TestGCMarkerCoversEveryRecord checks that the OCI marker covers every
// record the OCI handler writes, in hosted and size-limited proxy
// repositories, so garbage collection does not refuse to run.
func TestGCMarkerCoversEveryRecord(t *testing.T) {
	pe := newProxyEnv(t, 1<<30)
	img := pe.up.PutImage("app", "v1", []byte("layer"))
	pe.pull("small/app", "v1", img)
	pe.pull("hub/app", "v1", img)
	if err := pe.h.FlushPullTimes(context.Background()); err != nil {
		t.Fatal(err)
	}
	e := pe.env
	local := newImage("local", nil)
	want(t, e.pushImage("hosted/app", "v1", local), http.StatusCreated, "")
	sig := newImage("sig", map[string]any{"subject": desc(mtOCIManifest, local.manifest)})
	want(t, e.pushImage("hosted/app", sig.digest.String(), sig), http.StatusCreated, "")
	e.startSession("hosted/app")
	keys := map[string]bool{}
	v := e.meta.View()
	v.Scan(nil, nil, func(k []byte, _ meta.Record) bool {
		keys[string(k[:bytes.IndexByte(k[4:], 0)+5])] = true
		return true
	})
	v.Release()
	for _, ns := range []string{nsBlob, nsManifest, nsTag, nsReferrer, nsUpload, nsPulled} {
		if !keys[ns] {
			t.Errorf("the test wrote no %q keys", ns)
		}
	}
	refs := gctest.CheckStored(t, e.meta, e.blobs, GCMarker())
	distinct := map[blob.Digest]bool{}
	for _, d := range refs {
		distinct[d] = true
	}
	// The proxied image's manifest, config, and layer; the local image's;
	// and the signature's.
	if len(distinct) != 9 {
		t.Errorf("%d distinct blobs referenced, want 9", len(distinct))
	}
	c := newCollector(t, e.meta, e.blobs, pe.now, nil)
	if r, err := c.Run(context.Background(), gc.RunOptions{DryRun: true}); err != nil || r.State != gc.StateSucceeded ||
		r.Referenced != 9 || r.Unreferenced.Blobs != 0 {
		t.Fatalf("dry run = %+v, %v", r, err)
	}
}

func TestGCMarkerRefs(t *testing.T) {
	d1 := blob.FromBytes([]byte("one"))
	d2 := blob.FromBytes([]byte("two"))
	d3 := blob.FromBytes([]byte("three"))
	rn := &repoName{repo: "hosted", name: "team/app"}
	m := manifestRecord{MediaType: mtOCIManifest, Size: 10, Subject: d3,
		Refs: []manifestRef{{refBlob, d2}, {refManifest, d3}}}
	marker := GCMarker()
	for name, tt := range map[string]struct {
		f    gc.MarkFunc
		k, v []byte
		want []blob.Digest
	}{
		"blob link":       {keyDigestRefs, blobKey(rn, d1), encodeBlobLink(3), []blob.Digest{d1}},
		"manifest":        {manifestRefs, manifestKey(rn, d1), m.encode(), []blob.Digest{d1, d2, d3}},
		"tag":             {tagRefs, tagKey(rn, "v1"), encodeTag(d2), []blob.Digest{d2}},
		"referrer":        {keyDigestRefs, referrerKey(rn, d3, d1), newEnc(), []blob.Digest{d1}},
		"no digest":       {keyDigestRefs, []byte(nsBlob + "hosted\x00app\x00sha256:zz"), encodeBlobLink(3), nil},
		"bad manifest":    {manifestRefs, manifestKey(rn, d1), []byte{9}, nil},
		"bad tag":         {tagRefs, tagKey(rn, "v1"), []byte{recordFormat, 1}, nil},
		"manifest no key": {manifestRefs, []byte(nsManifest + "x"), m.encode(), nil},
	} {
		ds, err := tt.f(tt.k, tt.v)
		var got []string
		for _, d := range ds {
			got = append(got, d.String())
		}
		if tt.want == nil {
			if err == nil {
				t.Errorf("%s: no error", name)
			}
			continue
		}
		var want []string
		for _, d := range tt.want {
			want = append(want, d.String())
		}
		if err != nil || strings.Join(got, " ") != strings.Join(want, " ") {
			t.Errorf("%s: refs %v, %v; want %v", name, got, err, want)
		}
	}
	for _, ns := range []string{nsUpload, nsPulled} {
		if f, ok := marker[ns]; !ok || f != nil {
			t.Errorf("the marker registers %q as %v, want a prefix that references nothing", ns, ok)
		}
	}
	if marker[nsBlob] == nil || marker[nsManifest] == nil || marker[nsTag] == nil || marker[nsReferrer] == nil {
		t.Error("the marker lacks a function for a record that references blobs")
	}
}

// TestGCEndToEnd pushes images, deletes some of them, collects garbage,
// and checks that only unreferenced blobs past the grace period are gone
// and every image still referenced pulls.
func TestGCEndToEnd(t *testing.T) {
	ge := newGCEnv(t)
	a := newImage("a", nil)
	b := newImage("b", nil)
	shared := newImage("shared", nil)
	// b and shared in two repository names, a in one.
	want(t, ge.pushImage("hosted/app", "a", a), http.StatusCreated, "")
	want(t, ge.pushImage("hosted/app", "b", b), http.StatusCreated, "")
	want(t, ge.pushImage("hosted/app", "shared", shared), http.StatusCreated, "")
	want(t, ge.pushImage("other/copy", "shared", shared), http.StatusCreated, "")
	sig := newImage("signature", map[string]any{"subject": desc(mtOCIManifest, b.manifest)})
	want(t, ge.pushImage("hosted/app", sig.digest.String(), sig), http.StatusCreated, "")
	orphan := ge.pushBlob("hosted/app", []byte("pushed, never used"))

	// Delete image a, and its blobs' links; delete the orphan's link;
	// delete shared in hosted/app only.
	want(t, ge.do("DELETE", "/v2/hosted/app/manifests/"+a.digest.String(), nil), http.StatusAccepted, "")
	for _, c := range [][]byte{a.config, a.layer} {
		want(t, ge.do("DELETE", "/v2/hosted/app/blobs/"+blob.FromBytes(c).String(), nil), http.StatusAccepted, "")
	}
	want(t, ge.do("DELETE", "/v2/hosted/app/blobs/"+orphan.String(), nil), http.StatusAccepted, "")
	want(t, ge.do("DELETE", "/v2/hosted/app/manifests/"+shared.digest.String(), nil), http.StatusAccepted, "")

	ge.clock.advance(past)
	young := ge.pushBlob("hosted/app", []byte("young, unlinked"))
	want(t, ge.do("DELETE", "/v2/hosted/app/blobs/"+young.String(), nil), http.StatusAccepted, "")

	r := collect(t, ge.gc)
	gone := []blob.Digest{a.digest, blob.FromBytes(a.config), blob.FromBytes(a.layer), orphan}
	for _, d := range gone {
		if stored(t, ge.blobs, d) {
			t.Errorf("blob %s survived", d)
		}
	}
	if r.Deleted.Blobs != int64(len(gone)) || r.InGracePeriod.Blobs != 1 || !stored(t, ge.blobs, young) {
		t.Errorf("report = %+v", r)
	}
	// Everything still referenced pulls: b, its signature, and shared in
	// the other name; shared's blobs also stay linked in hosted/app.
	ge.pullImage("hosted/app", "b", b)
	ge.pullImage("hosted/app", sig.digest.String(), sig)
	ge.pullImage("other/copy", "shared", shared)
	w := ge.do("GET", "/v2/hosted/app/referrers/"+b.digest.String(), nil)
	want(t, w, http.StatusOK, "")
	if !strings.Contains(w.Body.String(), sig.digest.String()) {
		t.Errorf("referrers of b lack the signature: %s", w.Body)
	}
	want(t, ge.do("GET", "/v2/hosted/app/manifests/a", nil), http.StatusNotFound, codeManifestUnknown)
	checkReferencedStored(t, ge.meta, ge.blobs)

	// Deleting b leaves its signature, whose subject need not exist; the
	// signature keeps its own blobs, not b's.
	want(t, ge.do("DELETE", "/v2/hosted/app/manifests/"+b.digest.String(), nil), http.StatusAccepted, "")
	for _, c := range [][]byte{b.config, b.layer} {
		want(t, ge.do("DELETE", "/v2/hosted/app/blobs/"+blob.FromBytes(c).String(), nil), http.StatusAccepted, "")
	}
	collect(t, ge.gc)
	for _, d := range []blob.Digest{b.digest, blob.FromBytes(b.config), blob.FromBytes(b.layer)} {
		if stored(t, ge.blobs, d) {
			t.Errorf("blob %s of the deleted image b survived", d)
		}
	}
	ge.pullImage("hosted/app", sig.digest.String(), sig)
	checkReferencedStored(t, ge.meta, ge.blobs)

	// A deleted manifest's bytes come back with a push of it.
	want(t, ge.pushImage("hosted/app", "a", a), http.StatusCreated, "")
	ge.pullImage("hosted/app", "a", a)
}

// garbage stores content as an unreferenced blob past the grace period:
// pushed to name, then its link deleted, then the clock advanced.
func (ge *gcEnv) garbage(name string, content []byte) blob.Digest {
	ge.t.Helper()
	d := ge.pushBlob(name, content)
	want(ge.t, ge.do("DELETE", "/v2/"+name+"/blobs/"+d.String(), nil), http.StatusAccepted, "")
	ge.clock.advance(past)
	return d
}

// pauseLink makes the next link batch of d wait, after reading its view,
// until release is closed; viewed is closed when it waits.
func (ge *gcEnv) pauseLink(d blob.Digest) (viewed, release chan struct{}) {
	viewed, release = make(chan struct{}), make(chan struct{})
	var once sync.Once
	ge.h.linkHook = func(ds []blob.Digest) {
		for _, x := range ds {
			if x == d {
				once.Do(func() {
					close(viewed)
					<-release
				})
			}
		}
	}
	return viewed, release
}

// TestGCUploadRace interleaves an upload of a doomed blob with a sweep:
// the upload reads its view before the start batch and commits after it,
// so its link fails with a retryable error, and the blob is deleted. A
// retry after the sweep stores and links the blob again.
func TestGCUploadRace(t *testing.T) {
	ge := newGCEnv(t)
	content := []byte("re-pushed content")
	d := ge.garbage("hosted/app", content)
	viewed, release := ge.pauseLink(d)
	resp := make(chan int, 1)
	ge.setHook(func(s gc.Step) {
		switch s {
		case gc.StepScanned:
			go func() {
				resp <- ge.do("POST", "/v2/hosted/app/blobs/uploads/?digest="+d.String(), content).Code
			}()
			<-viewed
		case gc.StepDoomed:
			close(release)
			if code := <-resp; code != http.StatusServiceUnavailable {
				t.Errorf("upload across the start batch = %d, want 503", code)
			}
		}
	})
	r := collect(t, ge.gc)
	if r.Deleted.Blobs != 1 || stored(t, ge.blobs, d) {
		t.Fatalf("report = %+v", r)
	}
	want(t, ge.do("GET", "/v2/hosted/app/blobs/"+d.String(), nil), http.StatusNotFound, codeBlobUnknown)
	ge.h.linkHook = nil
	ge.pushBlob("hosted/app", content)
	if w := ge.do("GET", "/v2/hosted/app/blobs/"+d.String(), nil); w.Code != 200 || w.Body.String() != string(content) {
		t.Fatalf("pull after the retried upload = %d", w.Code)
	}
	checkReferencedStored(t, ge.meta, ge.blobs)
}

// TestGCUploadBeforeStartBatch keeps a doomed blob that an upload linked
// before the start batch.
func TestGCUploadBeforeStartBatch(t *testing.T) {
	ge := newGCEnv(t)
	content := []byte("re-pushed content")
	d := ge.garbage("hosted/app", content)
	ge.setHook(func(s gc.Step) {
		if s == gc.StepScanned {
			ge.pushBlob("hosted/app", content)
		}
	})
	r := collect(t, ge.gc)
	if r.Deleted.Blobs != 0 || r.Kept.Blobs != 1 || !stored(t, ge.blobs, d) {
		t.Fatalf("report = %+v", r)
	}
	want(t, ge.do("GET", "/v2/hosted/app/blobs/"+d.String(), nil), http.StatusOK, "")
}

// TestGCMountRace interleaves cross-repository mounts of a doomed blob
// with a sweep. The source re-links the blob before the start batch, so
// the sweep keeps it; mounts that read their view after the start batch,
// or before it and commit after it, fall back to a normal upload.
func TestGCMountRace(t *testing.T) {
	ge := newGCEnv(t)
	content := []byte("mounted content")
	d := ge.garbage("hosted/src", content)
	mount := func(dst string) int {
		return ge.do("POST", "/v2/"+dst+"/blobs/uploads/?mount="+d.String()+"&from=hosted/src", nil).Code
	}
	var release chan struct{}
	resp := make(chan int, 1)
	ge.setHook(func(s gc.Step) {
		switch s {
		case gc.StepScanned:
			ge.pushBlob("hosted/src", content) // linked before the start batch
			var viewed chan struct{}
			viewed, release = ge.pauseLink(d)
			go func() { resp <- mount("hosted/across") }()
			<-viewed
		case gc.StepDoomed:
			close(release)
			if code := <-resp; code != http.StatusAccepted {
				t.Errorf("mount across the start batch = %d, want 202, a fallback to an upload", code)
			}
			ge.h.linkHook = nil
			if code := mount("hosted/during"); code != http.StatusAccepted {
				t.Errorf("mount during the round = %d, want 202, a fallback to an upload", code)
			}
		}
	})
	r := collect(t, ge.gc)
	if r.Deleted.Blobs != 0 || r.Kept.Blobs != 1 || !stored(t, ge.blobs, d) {
		t.Fatalf("report = %+v", r)
	}
	for _, name := range []string{"hosted/across", "hosted/during"} {
		want(t, ge.do("GET", "/v2/"+name+"/blobs/"+d.String(), nil), http.StatusNotFound, codeBlobUnknown)
	}
	if code := mount("hosted/after"); code != http.StatusCreated {
		t.Errorf("mount after the sweep = %d, want 201", code)
	}
	checkReferencedStored(t, ge.meta, ge.blobs)
}

// TestGCManifestRace pushes a deleted manifest again while a sweep dooms
// its bytes: the push fails with a retryable error and succeeds after.
func TestGCManifestRace(t *testing.T) {
	ge := newGCEnv(t)
	img := newImage("m", nil)
	want(t, ge.pushImage("hosted/app", "v1", img), http.StatusCreated, "")
	want(t, ge.do("DELETE", "/v2/hosted/app/manifests/"+img.digest.String(), nil), http.StatusAccepted, "")
	ge.clock.advance(past)
	put := func() int {
		return ge.do("PUT", "/v2/hosted/app/manifests/v1", img.manifest, "Content-Type", mtOCIManifest).Code
	}
	ge.setHook(func(s gc.Step) {
		if s == gc.StepVerified {
			if code := put(); code != http.StatusServiceUnavailable {
				t.Errorf("manifest push during the round = %d, want 503", code)
			}
		}
	})
	r := collect(t, ge.gc)
	if r.Deleted.Blobs != 1 || stored(t, ge.blobs, img.digest) {
		t.Fatalf("report = %+v", r)
	}
	if code := put(); code != http.StatusCreated {
		t.Fatalf("manifest push after the sweep = %d", code)
	}
	ge.pullImage("hosted/app", "v1", img)
}

// TestGCProxyRace interleaves a proxy pull of a stored, doomed blob with a
// sweep: the proxy's link fails, so the pull serves the stored copy
// without linking it, the sweep deletes the blob, and the next pull
// fetches it from the upstream again.
func TestGCProxyRace(t *testing.T) {
	pe := newProxyEnv(t, 0)
	img := pe.up.PutImage("app", "v1", []byte("proxied layer"))
	layer := digestOf(t, img.Layers[0])
	// The layer is stored, unreferenced and old, as if pushed elsewhere
	// and deleted.
	pe.do("POST", "/v2/hosted/x/blobs/uploads/?digest="+layer.String(), img.Blobs[img.Layers[0]])
	want(t, pe.do("DELETE", "/v2/hosted/x/blobs/"+layer.String(), nil), http.StatusAccepted, "")
	pe.advance(past)

	var mu sync.Mutex
	var hook func(gc.Step)
	c := newCollector(t, pe.meta, pe.blobs, pe.now, func(s gc.Step) {
		mu.Lock()
		h := hook
		mu.Unlock()
		if h != nil {
			h(s)
		}
	})
	viewed, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	pe.h.linkHook = func(ds []blob.Digest) {
		if ds[0] == layer {
			once.Do(func() {
				close(viewed)
				<-release
			})
		}
	}
	resp := make(chan int, 1)
	mu.Lock()
	hook = func(s gc.Step) {
		switch s {
		case gc.StepScanned:
			go func() {
				w := pe.do("GET", "/v2/hub/app/blobs/"+layer.String(), nil)
				if !bytes.Equal(w.Body.Bytes(), img.Blobs[img.Layers[0]]) {
					w.Code = -w.Code
				}
				resp <- w.Code
			}()
			<-viewed
		case gc.StepDoomed:
			close(release)
			if code := <-resp; code != http.StatusOK {
				t.Errorf("proxy pull across the start batch = %d, want 200 with the layer", code)
			}
		}
	}
	mu.Unlock()
	r := collect(t, c)
	if r.Deleted.Blobs != 1 || stored(t, pe.blobs, layer) || pe.linked(blobKey(pe.rn("hub/app"), layer)) {
		t.Fatalf("report = %+v", r)
	}
	pe.h.linkHook = nil
	pe.pull("hub/app", "v1", img)
	if !stored(t, pe.blobs, layer) || !pe.linked(blobKey(pe.rn("hub/app"), layer)) {
		t.Fatal("the pull after the sweep did not cache the layer")
	}
	mu.Lock()
	hook = nil
	mu.Unlock()
	pe.advance(past)
	if r := collect(t, c); r.Deleted.Blobs != 0 {
		t.Errorf("a sweep deleted cached content: %+v", r)
	}
	pe.pull("hub/app", "v1", img)
	checkReferencedStored(t, pe.meta, pe.blobs)
}

// TestGCProxyEviction reclaims the bytes of content a size-limited proxy
// repository evicted, and only those.
func TestGCProxyEviction(t *testing.T) {
	pe := newProxyEnv(t, 2500)
	var layers []blob.Digest
	var data [][]byte
	for _, s := range []string{"a", "b", "c"} {
		b := bytes.Repeat([]byte(s), 1000)
		data = append(data, b)
		layers = append(layers, digestOf(t, pe.up.PutBlob("app", b)))
	}
	for i, d := range layers {
		pe.get("/v2/small/app/blobs/"+d.String(), data[i])
		pe.settle()
		pe.advance(time.Minute)
	}
	if err := pe.h.Evict(context.Background()); err != nil {
		t.Fatal(err)
	}
	pe.advance(past)
	c := newCollector(t, pe.meta, pe.blobs, pe.now, nil)
	r := collect(t, c)
	if r.Deleted != (gc.Count{Blobs: 1, Bytes: 1000}) || stored(t, pe.blobs, layers[0]) ||
		!stored(t, pe.blobs, layers[1]) || !stored(t, pe.blobs, layers[2]) {
		t.Fatalf("report = %+v", r)
	}
	checkReferencedStored(t, pe.meta, pe.blobs)
	// Evicted content is fetched again.
	pe.get("/v2/small/app/blobs/"+layers[0].String(), data[0])
}

// TestGCStress runs pushes, deletes, mounts, and pulls in several
// repositories while sweeps run back to back with the clock racing ahead,
// and checks that every blob the metadata references is stored after
// each sweep and that every image a client pushed and did not delete
// pulls.
func TestGCStress(t *testing.T) {
	ge := newGCEnv(t)
	const workers = 4
	iters := 400
	if testing.Short() {
		iters = 100
	}
	// Each worker pushes its own images and two that all of them share,
	// so content often becomes garbage, and mounts sometimes find it.
	images := func(w int) []image {
		out := []image{newImage("shared 0", nil), newImage("shared 1", nil)}
		for i := range 4 {
			out = append(out, newImage(fmt.Sprintf("worker %d image %d", w, i), nil))
		}
		return out
	}
	ctx, stop := context.WithCancel(context.Background())
	var gcDone sync.WaitGroup
	var sweeps, reclaimed int64
	var retries atomic.Int64
	gcDone.Go(func() {
		for ctx.Err() == nil {
			ge.clock.advance(gc.DefaultGracePeriod / 2)
			r, err := ge.gc.Run(context.Background(), gc.RunOptions{})
			if err != nil || r.State != gc.StateSucceeded {
				t.Errorf("sweep = %+v, %v", r, err)
				return
			}
			sweeps++
			reclaimed += r.Deleted.Blobs
			checkReferencedStored(t, ge.meta, ge.blobs)
		}
	})
	var wg sync.WaitGroup
	for w := range workers {
		rng := rand.New(rand.NewPCG(uint64(w), 1))
		name := fmt.Sprintf("hosted/w%d", w)
		images := images(w)
		wg.Go(func() {
			pushed := map[int]bool{} // images pushed and not deleted since
			for range iters {
				i := rng.IntN(len(images))
				img := images[i]
				switch rng.IntN(4) {
				case 0, 1:
					// Push, as clients do: blobs (or a mount), then the
					// manifest; a 503 means retry later.
					if rng.IntN(2) == 0 {
						src := fmt.Sprintf("hosted/w%d", rng.IntN(workers))
						ge.do("POST", "/v2/"+name+"/blobs/uploads/?mount="+blob.FromBytes(img.layer).String()+"&from="+src, nil)
					}
					ok := true
					for _, b := range [][]byte{img.config, img.layer} {
						d := blob.FromBytes(b)
						if ge.do("HEAD", "/v2/"+name+"/blobs/"+d.String(), nil).Code == http.StatusOK {
							continue
						}
						if code := ge.do("POST", "/v2/"+name+"/blobs/uploads/?digest="+d.String(), b).Code; code != http.StatusCreated {
							if code != http.StatusServiceUnavailable {
								t.Errorf("blob push = %d", code)
							}
							retries.Add(1)
							ok = false
						}
					}
					if !ok {
						continue
					}
					code := ge.do("PUT", "/v2/"+name+"/manifests/v"+fmt.Sprint(i), img.manifest, "Content-Type", mtOCIManifest).Code
					switch code {
					case http.StatusCreated:
						pushed[i] = true
					case http.StatusServiceUnavailable:
						retries.Add(1)
					default:
						t.Errorf("manifest push = %d", code)
					}
				case 2:
					// Delete the image and its blob links.
					code := ge.do("DELETE", "/v2/"+name+"/manifests/"+img.digest.String(), nil).Code
					if code == http.StatusAccepted || code == http.StatusNotFound {
						delete(pushed, i)
					}
					for _, b := range [][]byte{img.config, img.layer} {
						ge.do("DELETE", "/v2/"+name+"/blobs/"+blob.FromBytes(b).String(), nil)
					}
				case 3:
					for j := range pushed {
						if err := ge.checkPull(name, "v"+fmt.Sprint(j), images[j]); err != nil {
							t.Error(err)
						}
					}
				}
			}
			for j := range pushed {
				if err := ge.checkPull(name, "v"+fmt.Sprint(j), images[j]); err != nil {
					t.Error(err)
				}
			}
		})
	}
	wg.Wait()
	stop()
	gcDone.Wait()
	t.Logf("%d sweeps reclaimed %d blobs; %d pushes were told to retry", sweeps, reclaimed, retries.Load())
	if reclaimed == 0 {
		t.Error("the sweeps reclaimed nothing")
	}
	collect(t, ge.gc)
	checkReferencedStored(t, ge.meta, ge.blobs)
}
