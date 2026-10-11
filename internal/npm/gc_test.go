package npm

import (
	"context"
	"encoding/base64"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/terrabyteian/flint/internal/blob"
	"github.com/terrabyteian/flint/internal/gc"
	"github.com/terrabyteian/flint/internal/gc/gctest"
	"github.com/terrabyteian/flint/internal/meta"
	"github.com/terrabyteian/flint/internal/upstream"
)

// TestGCMarker writes every kind of npm record and checks that the marker
// covers them all and marks exactly the blobs that live records link: a
// live version's manifest, tarball, and provenance bundle, and the
// readme, but not an unpublished version's.
func TestGCMarker(t *testing.T) {
	e := newEnv(t)
	statement := `{"predicateType": "https://slsa.dev/provenance/v1"}`
	bundle := `{"dsseEnvelope": {"payload": "` + base64.StdEncoding.EncodeToString([]byte(statement)) + `"}}`
	kept := newPkg("p", "1.0.0")
	kept.readme = "# p"
	kept.attachments = map[string]string{"p-1.0.0.sigstore": bundle}
	dropped := newPkg("p", "2.0.0")
	dropped.tags = []string{"next"}
	e.publish("local", kept, http.StatusOK)
	e.publish("local", dropped, http.StatusOK)
	e.expect("DELETE", "/npm/local/p/-/p-2.0.0.tgz/-rev/"+e.rawPackument("local", "p")["_rev"].(string), nil, http.StatusOK)

	v := e.meta.View()
	defer v.Release()
	for _, ns := range []string{nsPkg, nsVersion} {
		found := false
		v.Scan([]byte(ns), nil, func([]byte, meta.Record) bool { found = true; return false })
		if !found {
			t.Errorf("the test writes no record under %q", ns)
		}
	}
	rec, _ := v.Get(versionKey("local", "p", "1.0.0"))
	vr, err := decodeVersion(rec.Value)
	if err != nil {
		t.Fatal(err)
	}
	if rec, _ := v.Get(versionKey("local", "p", "2.0.0")); rec.Value == nil {
		t.Fatal("no tombstone")
	} else if tomb, err := decodeVersion(rec.Value); err != nil || tomb.Kind != kindTombstone {
		t.Fatalf("2.0.0 is %+v, %v", tomb, err)
	}

	want := []blob.Digest{blob.FromBytes(kept.tarball), vr.Manifest, blob.FromBytes([]byte(bundle)), blob.FromBytes([]byte("# p"))}
	got := map[blob.Digest]bool{}
	for _, d := range gctest.CheckStored(t, e.meta, e.blobs, GCMarker()) {
		got[d] = true
	}
	if len(got) != len(want) {
		t.Errorf("marked %v, want %v", got, want)
	}
	for _, d := range want {
		if !got[d] {
			t.Errorf("%s is not marked", d)
		}
	}
	if got[blob.FromBytes(dropped.tarball)] {
		t.Error("an unpublished version's tarball is marked")
	}

	// References, which backups check, reports the same blobs.
	var refs []blob.Digest
	if err := References(v, func(d blob.Digest) error { refs = append(refs, d); return nil }); err != nil {
		t.Fatal(err)
	}
	slices.SortFunc(refs, func(a, b blob.Digest) int { return strings.Compare(a.String(), b.String()) })
	refs = slices.Compact(refs)
	if len(refs) != len(want) {
		t.Errorf("References %v, want %v", refs, want)
	}
	for _, d := range refs {
		if !got[d] {
			t.Errorf("References reports %s, which the marker does not", d)
		}
	}
}

// TestGCMarkerProxy writes every kind of record proxy and virtual npm
// repositories write, which are the shared proxy cache's, and checks that
// the npm marker with the proxy cache's covers them all and marks every
// cached packument, document, and tarball.
func TestGCMarkerProxy(t *testing.T) {
	e := newEnv(t)
	e.up.add("left-pad", "1.0.0", nil)
	e.up.add("@acme/lib", "1.0.0", nil)
	e.publish("local", newPkg("p", "1.0.0"), http.StatusOK)
	e.packument("remote", "left-pad", false)
	for _, repo := range []string{"remote", "small", "all"} {
		e.expect("GET", "/npm/"+repo+"/left-pad/-/left-pad-1.0.0.tgz", nil, http.StatusOK)
	}
	e.expect("GET", "/npm/exposed/@acme/lib", nil, http.StatusOK)
	e.expect("GET", "/npm/all/-/npm/v1/keys", nil, http.StatusOK)
	e.expect("GET", "/npm/remote/-/npm/v1/attestations/left-pad@1.0.0", nil, http.StatusOK)
	e.settle()
	if err := e.h.FlushPullTimes(context.Background()); err != nil {
		t.Fatal(err)
	}

	v := e.meta.View()
	defer v.Release()
	for _, ns := range []string{nsPkg, nsVersion, upstream.NSDoc, upstream.NSFile, upstream.NSPulled} {
		found := false
		v.Scan([]byte(ns), nil, func([]byte, meta.Record) bool { found = true; return false })
		if !found {
			t.Errorf("the test writes no record under %q", ns)
		}
	}
	var want []blob.Digest
	for _, k := range []string{packumentKey("left-pad", true), packumentKey("left-pad", false), packumentKey("@acme/lib", false),
		"keys", "attestations/left-pad@1.0.0"} {
		rec, ok := v.Get(upstream.DocKey("remote", k))
		if !ok {
			t.Fatalf("document %s is not cached", k)
		}
		d, err := upstream.DecodeDocRecord(rec.Value)
		if err != nil {
			t.Fatalf("document %s: %v", k, err)
		}
		want = append(want, d.Digest)
	}
	for _, repo := range []string{"remote", "small"} {
		if !e.has(upstream.FileKey(repo, "left-pad/-/left-pad-1.0.0.tgz")) {
			t.Errorf("the tarball is not cached in %s", repo)
		}
	}
	want = append(want, blob.FromBytes(tarballOf("left-pad", "1.0.0")))
	got := map[blob.Digest]bool{}
	for _, d := range gctest.CheckStored(t, e.meta, e.blobs, GCMarker(), upstream.Marks) {
		got[d] = true
	}
	for _, d := range want {
		if !got[d] {
			t.Errorf("%s is not marked", d)
		}
	}
}

// TestGCMarkerUnreadable checks that a record under any npm prefix that
// the marker cannot read makes a run refuse to delete anything, and that
// References fails on it.
func TestGCMarkerUnreadable(t *testing.T) {
	for ns := range GCMarker() {
		for _, value := range [][]byte{nil, {recordFormat, 0xff}, {recordFormat + 1}} {
			t.Run(ns, func(t *testing.T) {
				e := newEnv(t)
				var b meta.Batch
				b.Put(key(ns, "local", "x"), value)
				if _, err := e.meta.Commit(context.Background(), &b); err != nil {
					t.Fatal(err)
				}
				v := e.meta.View()
				defer v.Release()
				_, problems, err := gc.CheckMarker(v, GCMarker())
				if err != nil || len(problems) == 0 {
					t.Errorf("an unreadable record %x: problems %q, err %v", value, problems, err)
				}
				if err := References(v, func(blob.Digest) error { return nil }); err == nil {
					t.Errorf("References read the unreadable record %x", value)
				}
			})
		}
	}
}

// TestRecordsRoundTrip checks that records decode to what was encoded.
func TestRecordsRoundTrip(t *testing.T) {
	d := blob.FromBytes([]byte("x"))
	p := &pkgRecord{Created: e2eTime(1), Modified: e2eTime(2), Tags: []distTag{{"latest", "1.0.0"}, {"next", "2.0.0-rc.1"}},
		Readme: d, ReadmeSize: 1, ReadmeFilename: "README.md"}
	got, err := decodePkg(p.encode())
	if err != nil || !got.Created.Equal(p.Created) || !slices.Equal(got.Tags, p.Tags) || got.Readme != d || got.ReadmeFilename != "README.md" {
		t.Errorf("package record %+v, %v", got, err)
	}
	for _, vr := range []*versionRecord{
		{Kind: kindLive, Manifest: d, ManifestSize: 1, Tarball: d, Size: 1, SHA512: make([]byte, 64), SHA1: make([]byte, 20),
			Published: e2eTime(3), Deprecated: "old", Provenance: d, ProvenanceSize: 1, PredicateType: "t"},
		{Kind: kindLive, Tarball: d, Size: 1},
		{Kind: kindTombstone, Published: e2eTime(3), Unpublished: e2eTime(4)},
	} {
		got, err := decodeVersion(vr.encode())
		if err != nil || got.Kind != vr.Kind || got.Tarball != vr.Tarball || got.Deprecated != vr.Deprecated ||
			got.Provenance != vr.Provenance || !got.Published.Equal(vr.Published) || !got.Unpublished.Equal(vr.Unpublished) {
			t.Errorf("version record %+v: %+v, %v", vr, got, err)
		}
	}
	if _, err := decodeVersion([]byte{recordFormat, 9}); err == nil {
		t.Error("an unknown kind decodes")
	}
	if _, err := decodePkg(append(p.encode(), 0)); err == nil {
		t.Error("trailing bytes decode")
	}
}
