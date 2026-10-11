package upstream_test

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/terrabyteian/flint/internal/blob"
	"github.com/terrabyteian/flint/internal/meta"
	"github.com/terrabyteian/flint/internal/upstream"
)

func TestNegativeCache(t *testing.T) {
	clock := &fakeClock{t: time.Unix(1700000000, 0)}
	n := upstream.NewNegativeCache(clock.Now)
	known := func(k string) bool { ok, _ := n.Known(k); return ok }
	n.Remember("r\x00a", false, time.Minute)
	n.Remember("r\x00gone", true, time.Minute)
	n.Remember("r\x00off", false, 0) // a zero window remembers nothing
	if !known("r\x00a") || known("r\x00b") || known("r\x00off") {
		t.Fatal("Known after Remember")
	}
	if _, gone := n.Known("r\x00a"); gone {
		t.Error("a 404 remembered as gone")
	}
	if ok, gone := n.Known("r\x00gone"); !ok || !gone {
		t.Error("a 410 not remembered as gone")
	}
	clock.Add(59 * time.Second)
	if !known("r\x00a") {
		t.Error("forgotten within the window")
	}
	clock.Add(time.Second)
	if known("r\x00a") {
		t.Error("remembered after the window")
	}
	n.Remember("r\x00x", false, time.Minute)
	n.Remember("r\x00y", false, time.Hour)
	clock.Add(2 * time.Minute)
	n.Prune()
	if n.Len() != 1 || !known("r\x00y") {
		t.Errorf("after Prune: %d entries", n.Len())
	}
}

// testView is a meta.View over a map, for References and Marks.
type testView struct {
	keys [][]byte
	vals map[string][]byte
}

func (v *testView) Get(k []byte) (meta.Record, bool) {
	b, ok := v.vals[string(k)]
	return meta.Record{Value: b, Version: 1}, ok
}

func (v *testView) Scan(prefix, after []byte, fn func(k []byte, r meta.Record) bool) {
	for _, k := range v.keys {
		if bytes.HasPrefix(k, prefix) && (after == nil || bytes.Compare(k, after) > 0) {
			if !fn(k, meta.Record{Value: v.vals[string(k)], Version: 1}) {
				return
			}
		}
	}
}

func (v *testView) Seq() meta.Seq { return 1 }
func (v *testView) Release()      {}

func TestRecordsAndMarks(t *testing.T) {
	dDoc, dFile := blob.FromBytes([]byte("doc")), blob.FromBytes([]byte("file"))
	now := time.Unix(1700000000, 5).UTC()
	doc := &upstream.DocRecord{Digest: dDoc, Size: 3, ContentType: "application/json", ETag: `"e"`,
		LastModified: "Mon, 02 Jan 2006 15:04:05 GMT", URL: "https://up.example/x", Fetched: now}
	file := &upstream.FileRecord{Digest: dFile, Size: 4, ContentType: "application/java-archive",
		Sums: upstream.Sums{upstream.SHA1: bytes.Repeat([]byte{1}, 20), upstream.MD5: bytes.Repeat([]byte{2}, 16)}, Fetched: now}
	docVal, fileVal := upstream.EncodeDocRecord(doc), upstream.EncodeFileRecord(file)
	if got, err := upstream.DecodeDocRecord(docVal); err != nil || *got != *doc {
		t.Errorf("doc record round trip: %+v, %v", got, err)
	}
	got, err := upstream.DecodeFileRecord(fileVal)
	if err != nil || got.Digest != file.Digest || got.Size != file.Size || got.ContentType != file.ContentType ||
		!got.Fetched.Equal(now) || len(got.Sums) != 2 || got.Sums.Hex(upstream.SHA1) != file.Sums.Hex(upstream.SHA1) {
		t.Errorf("file record round trip: %+v, %v", got, err)
	}
	for _, bad := range [][]byte{nil, {9}, append(bytes.Clone(docVal), 0), docVal[:len(docVal)-1]} {
		if _, err := upstream.DecodeDocRecord(bad); !errors.Is(err, upstream.ErrBadRecord) {
			t.Errorf("DecodeDocRecord(%x) = %v", bad, err)
		}
		if _, err := upstream.DecodeFileRecord(bad); err == nil {
			t.Errorf("DecodeFileRecord(%x) accepted", bad)
		}
	}
	// The marks cover every key family, and report each record's blob.
	keys := map[string][]byte{
		string(upstream.DocKey("r", "pkg")):        docVal,
		string(upstream.FileKey("r", "a/b.jar")):   fileVal,
		upstream.NSPulled + "file\x00r\x00a/b.jar": upstream.EncodePulled(5),
	}
	v := &testView{vals: keys}
	for k := range keys {
		v.keys = append(v.keys, []byte(k))
	}
	for k, val := range keys {
		var mark func(key, value []byte) ([]blob.Digest, error)
		found := false
		for pfx, m := range upstream.Marks {
			if bytes.HasPrefix([]byte(k), []byte(pfx)) {
				mark, found = m, true
			}
		}
		if !found {
			t.Fatalf("no mark covers %q", k)
		}
		if mark == nil {
			continue
		}
		ds, err := mark([]byte(k), val)
		if err != nil || len(ds) != 1 || (ds[0] != dDoc && ds[0] != dFile) {
			t.Errorf("mark(%q) = %v, %v", k, ds, err)
		}
	}
	refs := map[blob.Digest]int{}
	if err := upstream.References(v, func(d blob.Digest) error { refs[d]++; return nil }); err != nil {
		t.Fatal(err)
	}
	if len(refs) != 2 || refs[dDoc] != 1 || refs[dFile] != 1 {
		t.Errorf("References = %v", refs)
	}
	v.vals[string(upstream.FileKey("r", "a/b.jar"))] = []byte{9}
	if err := upstream.References(v, func(blob.Digest) error { return nil }); !errors.Is(err, upstream.ErrBadRecord) {
		t.Errorf("References over a bad record: %v", err)
	}
	if p, err := upstream.DecodePulled(upstream.EncodePulled(1700000000)); err != nil || p != 1700000000 {
		t.Errorf("pulled round trip: %d, %v", p, err)
	}
}
