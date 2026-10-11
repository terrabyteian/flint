package oci

import (
	"errors"
	"testing"

	"github.com/terrabyteian/flint/internal/blob"
)

func TestReferences(t *testing.T) {
	e := newEnv(t)
	a, b := newImage("a", nil), newImage("b", nil)
	want(t, e.pushImage("hosted/app", "v1", a), 201, "")
	want(t, e.pushImage("other/app", "v1", a), 201, "")
	want(t, e.pushImage("hosted/app", "v2", b), 201, "")
	loose := e.pushBlob("hosted/loose", []byte("loose"))

	v := e.meta.View()
	defer v.Release()
	got := map[blob.Digest]int{}
	if err := References(v, func(d blob.Digest) error { got[d]++; return nil }); err != nil {
		t.Fatal(err)
	}
	wantRefs := map[blob.Digest]int{loose: 1}
	for _, img := range []image{a, a, b} {
		for _, c := range [][]byte{img.config, img.layer} {
			wantRefs[blob.FromBytes(c)]++
		}
		wantRefs[img.digest]++
	}
	if len(got) != len(wantRefs) {
		t.Fatalf("got %d digests, want %d", len(got), len(wantRefs))
	}
	for d, n := range wantRefs {
		if got[d] != n {
			t.Errorf("%s reported %d times, want %d", d, got[d], n)
		}
	}

	stop := errors.New("stop")
	var seen []blob.Digest
	err := References(v, func(d blob.Digest) error { seen = append(seen, d); return stop })
	if !errors.Is(err, stop) || len(seen) != 1 || got[seen[0]] == 0 {
		t.Fatalf("stopping: err %v after %d calls", err, len(seen))
	}
}
