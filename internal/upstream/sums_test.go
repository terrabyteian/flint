package upstream_test

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/terrabyteian/flint/internal/blob"
	"github.com/terrabyteian/flint/internal/upstream"
)

// goModule is a module zip and go.mod whose h1: hashes the go command
// computed (go mod download -json from a file:// GOPROXY).
var goModule = struct {
	mod     string
	files   [][2]string
	zipH1   string
	goModH1 string
}{
	mod: "module example.com/m\n\ngo 1.21\n",
	files: [][2]string{
		{"example.com/m@v1.0.0/go.mod", "module example.com/m\n\ngo 1.21\n"},
		{"example.com/m@v1.0.0/m.go", "package m\n\nconst X = 1\n"},
		{"example.com/m@v1.0.0/sub/b.txt", "hello\n"},
	},
	zipH1:   "h1:Uy6OEW1xuiaibt3BqXdyuoqAAROLqn2vu3LZJDQyLcs=",
	goModH1: "h1:ONeDgCa5UF/jJRjGzpOKmUiezgFEk4IPFZ96frvroW0=",
}

// moduleZip builds the module zip, its files in the order given.
func moduleZip(t *testing.T, files [][2]string) []byte {
	t.Helper()
	var b bytes.Buffer
	z := zip.NewWriter(&b)
	for _, f := range files {
		w, err := z.Create(f[0])
		if err != nil {
			t.Fatal(err)
		}
		io.WriteString(w, f[1])
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func TestGoH1(t *testing.T) {
	if got := upstream.GoModH1([]byte(goModule.mod)); got != goModule.goModH1 {
		t.Errorf("GoModH1 = %s, want %s", got, goModule.goModH1)
	}
	// The hash does not depend on the order of the zip's entries.
	rev := [][2]string{goModule.files[2], goModule.files[0], goModule.files[1]}
	for _, files := range [][][2]string{goModule.files, rev} {
		z := moduleZip(t, files)
		got, err := upstream.GoZipH1(bytes.NewReader(z), int64(len(z)))
		if err != nil || got != goModule.zipH1 {
			t.Errorf("GoZipH1 = %s, %v, want %s", got, err, goModule.zipH1)
		}
	}
	z := moduleZip(t, append([][2]string{{"example.com/m@v1.0.0/extra", "x"}}, goModule.files...))
	if err := upstream.CheckGoZipH1(goModule.zipH1)(ctx, bytes.NewReader(z), int64(len(z))); !errors.Is(err, upstream.ErrDigestMismatch) {
		t.Errorf("a zip with an extra file: %v, want ErrDigestMismatch", err)
	}
	if err := upstream.CheckGoZipH1(goModule.zipH1)(ctx, strings.NewReader("not a zip"), 9); !errors.Is(err, upstream.ErrDigestMismatch) {
		t.Errorf("not a zip: %v, want ErrDigestMismatch", err)
	}
	mod := []byte(goModule.mod)
	if err := upstream.CheckGoModH1(goModule.goModH1)(ctx, bytes.NewReader(mod), int64(len(mod))); err != nil {
		t.Errorf("CheckGoModH1: %v", err)
	}
	if err := upstream.CheckGoModH1(goModule.goModH1)(ctx, strings.NewReader("module x\n"), 9); !errors.Is(err, upstream.ErrDigestMismatch) {
		t.Errorf("another go.mod: %v, want ErrDigestMismatch", err)
	}
}

func TestParseIntegrity(t *testing.T) {
	data := []byte("tarball")
	s512 := sha512.Sum512(data)
	s1 := sha1.Sum(data)
	b64 := base64.StdEncoding.EncodeToString
	for _, tc := range []struct {
		in   string
		alg  string
		want []byte
	}{
		{"sha512-" + b64(s512[:]), upstream.SHA512, s512[:]},
		{"sha1-" + b64(s1[:]) + " sha512-" + b64(s512[:]), upstream.SHA512, s512[:]},
		{"sha1-" + b64(s1[:]), upstream.SHA1, s1[:]},
		{"sha512-" + b64(s512[:]) + "?opt", upstream.SHA512, s512[:]},
		{"sha512-short", "", nil},
		{"md5-" + b64(s1[:]), "", nil},
		{"", "", nil},
	} {
		alg, sum, ok := upstream.ParseIntegrity(tc.in)
		if alg != tc.alg || !bytes.Equal(sum, tc.want) || ok != (tc.alg != "") {
			t.Errorf("ParseIntegrity(%q) = %q, %x, %v; want %q, %x", tc.in, alg, sum, ok, tc.alg, tc.want)
		}
	}
}

// pathSource returns a Source serving data, announcing size.
func pathSource(data []byte, size int64) upstream.Source {
	return func(context.Context) (io.ReadCloser, int64, error) {
		return io.NopCloser(bytes.NewReader(data)), size, nil
	}
}

func TestFetchPathVerifies(t *testing.T) {
	data := bytes.Repeat([]byte("artifact "), 50000)
	s1, s512 := sha1.Sum(data), sha512.Sum512(data)
	git := sha1.New()
	fmt.Fprintf(git, "blob %d\x00", len(data))
	git.Write(data)
	gitSum := git.Sum(nil)
	sha := sha256.Sum256(data)
	bad := bytes.Repeat([]byte{1}, 64)
	z := moduleZip(t, goModule.files)
	zsha := sha256.Sum256(z)
	for _, tc := range []struct {
		name   string
		data   []byte
		size   int64
		expect upstream.Expect
		ok     bool
	}{
		{"sha1", data, -1, upstream.Expect{Size: -1, Sums: upstream.Sums{upstream.SHA1: s1[:]}}, true},
		{"sha512 and size", data, int64(len(data)), upstream.Expect{Size: int64(len(data)), Sums: upstream.Sums{upstream.SHA512: s512[:]}}, true},
		{"git blob", data, -1, upstream.Expect{Size: int64(len(data)), Sums: upstream.Sums{upstream.GitSHA1: gitSum}}, true},
		{"sha256", data, -1, upstream.Expect{Size: -1, SHA256: hex.EncodeToString(sha[:])}, true},
		{"nothing expected", data, -1, upstream.Expect{Size: -1}, true},
		{"go h1", z, int64(len(z)), upstream.Expect{Size: -1, Check: upstream.CheckGoZipH1(goModule.zipH1)}, true},
		{"sha1 mismatch", data, -1, upstream.Expect{Size: -1, Sums: upstream.Sums{upstream.SHA1: bad[:20]}}, false},
		{"sha512 mismatch", data, -1, upstream.Expect{Size: -1, Sums: upstream.Sums{upstream.SHA512: bad}}, false},
		{"one of two mismatches", data, -1, upstream.Expect{Size: -1, Sums: upstream.Sums{upstream.SHA1: s1[:], upstream.SHA512: bad}}, false},
		{"sha256 mismatch", data, -1, upstream.Expect{Size: -1, SHA256: hex.EncodeToString(zsha[:])}, false},
		{"size mismatch", data, -1, upstream.Expect{Size: int64(len(data)) - 1}, false},
		{"announced size mismatch", data, int64(len(data)), upstream.Expect{Size: int64(len(data)) + 1}, false},
		{"go h1 mismatch", data, -1, upstream.Expect{Size: -1, Check: upstream.CheckGoZipH1(goModule.zipH1)}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := newStore(t)
			f := upstream.NewFetcher(store, 0)
			tc.expect.Compute = []string{upstream.MD5}
			var res upstream.PathResult
			var doneErr error
			fe, _ := f.FetchPath("k", "path/to/file", tc.expect, pathSource(tc.data, tc.size),
				func(_ context.Context, r upstream.PathResult, err error) { res, doneErr = r, err })
			var out bytes.Buffer
			n, err := fe.Stream(ctx, &out)
			fe.Release()
			want := blob.FromBytes(tc.data)
			_, statErr := store.Stat(ctx, want)
			if !tc.ok {
				if !errors.Is(err, upstream.ErrDigestMismatch) || !errors.Is(doneErr, upstream.ErrDigestMismatch) {
					t.Fatalf("Stream: %v; done: %v; want ErrDigestMismatch", err, doneErr)
				}
				// No client receives the whole content, and it never
				// enters the blob store.
				if n >= int64(len(tc.data)) {
					t.Errorf("streamed all %d bytes of content that failed verification", n)
				}
				if !errors.Is(statErr, blob.ErrNotFound) {
					t.Errorf("content that failed verification was stored: %v", statErr)
				}
				return
			}
			if err != nil || doneErr != nil || !bytes.Equal(out.Bytes(), tc.data) {
				t.Fatalf("Stream: %d bytes, %v; done: %v", out.Len(), err, doneErr)
			}
			if res.Info.Digest != want || res.Info.Size != int64(len(tc.data)) || statErr != nil {
				t.Errorf("committed %+v, %v; want %s", res.Info, statErr, want)
			}
			wantMD5 := md5.Sum(tc.data)
			if !bytes.Equal(res.Sums[upstream.MD5], wantMD5[:]) {
				t.Errorf("computed md5 %x, want %x", res.Sums[upstream.MD5], wantMD5)
			}
			for alg, sum := range tc.expect.Sums {
				if !bytes.Equal(res.Sums[alg], sum) {
					t.Errorf("result %s = %x, want %x", alg, res.Sums[alg], sum)
				}
			}
		})
	}

}

func TestFetchPathBadExpect(t *testing.T) {
	f := upstream.NewFetcher(newStore(t), 0)
	for _, e := range []upstream.Expect{
		{Size: -1, Sums: upstream.Sums{"crc32": {1}}},
		{Size: -1, Sums: upstream.Sums{upstream.GitSHA1: make([]byte, 20)}}, // needs the size
		{Size: -1, SHA256: "nothex"},
	} {
		fe, _ := f.FetchPath("k", "p", e, pathSource([]byte("x"), 1), func(context.Context, upstream.PathResult, error) {})
		if _, err := fe.Wait(ctx); err == nil {
			t.Errorf("FetchPath accepted %+v", e)
		}
		fe.Release()
	}
}
