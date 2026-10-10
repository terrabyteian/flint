package blob

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

var benchSizes = []int{64 << 10, 1 << 20, 16 << 20}

func sizeName(n int) string {
	if n >= 1<<20 {
		return fmt.Sprintf("%dMiB", n>>20)
	}
	return fmt.Sprintf("%dKiB", n>>10)
}

// benchStore returns a store on the real filesystem, so fsync costs count.
func benchStore(b *testing.B) Store {
	b.Helper()
	s, err := NewFS(b.TempDir(), Options{})
	if err != nil {
		b.Fatal(err)
	}
	return s
}

// BenchmarkUpload measures a whole monolithic upload of new content: stream
// into the staged file while hashing, then verify, fsync, rename, and sync
// the fan-out directory.
func BenchmarkUpload(b *testing.B) {
	for _, size := range benchSizes {
		b.Run(sizeName(size), func(b *testing.B) {
			s := benchStore(b)
			data := bytes.Repeat([]byte{0xa5}, size)
			b.SetBytes(int64(size))
			var n uint64
			for b.Loop() {
				n++
				binary.BigEndian.PutUint64(data, n) // new content every time
				u, err := s.NewUpload(ctx)
				if err != nil {
					b.Fatal(err)
				}
				if _, err := io.Copy(u, bytes.NewReader(data)); err != nil {
					b.Fatal(err)
				}
				if _, err := u.Commit(ctx, Digest{}); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkUploadParallel measures concurrent uploads of new 1 MiB blobs.
func BenchmarkUploadParallel(b *testing.B) {
	s := benchStore(b)
	const size = 1 << 20
	b.SetBytes(size)
	var n atomic.Uint64
	b.RunParallel(func(pb *testing.PB) {
		data := bytes.Repeat([]byte{0x5a}, size)
		for pb.Next() {
			binary.BigEndian.PutUint64(data, n.Add(1))
			u, err := s.NewUpload(ctx)
			if err != nil {
				b.Fatal(err)
			}
			if _, err := io.Copy(u, bytes.NewReader(data)); err != nil {
				b.Fatal(err)
			}
			if _, err := u.Commit(ctx, Digest{}); err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkUploadExisting measures an upload of content the store already
// has: hashing plus the existence check, with no data fsync.
func BenchmarkUploadExisting(b *testing.B) {
	s := benchStore(b)
	data := bytes.Repeat([]byte{0x3c}, 1<<20)
	b.SetBytes(int64(len(data)))
	for b.Loop() {
		u, _ := s.NewUpload(ctx)
		io.Copy(u, bytes.NewReader(data))
		if _, err := u.Commit(ctx, Digest{}); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkRead measures opening a blob and reading it to the end.
func BenchmarkRead(b *testing.B) {
	for _, size := range benchSizes {
		b.Run(sizeName(size), func(b *testing.B) {
			s := benchStore(b)
			info := benchPut(b, s, size)
			b.SetBytes(int64(size))
			for b.Loop() {
				r, err := s.Open(ctx, info.Digest)
				if err != nil {
					b.Fatal(err)
				}
				if _, err := io.Copy(io.Discard, r); err != nil {
					b.Fatal(err)
				}
				r.Close()
			}
		})
	}
}

// BenchmarkServe measures the read path as the HTTP layer will use it:
// Open, then http.ServeContent over plain HTTP/1.1, where net/http can
// send the *os.File with sendfile.
func BenchmarkServe(b *testing.B) {
	for _, size := range benchSizes {
		b.Run(sizeName(size), func(b *testing.B) {
			s := benchStore(b)
			info := benchPut(b, s, size)
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				r, err := s.Open(req.Context(), info.Digest)
				if err != nil {
					http.Error(w, err.Error(), http.StatusNotFound)
					return
				}
				defer r.Close()
				http.ServeContent(w, req, "", info.ModTime, r)
			}))
			defer srv.Close()
			client := srv.Client()
			b.SetBytes(int64(size))
			for b.Loop() {
				resp, err := client.Get(srv.URL)
				if err != nil {
					b.Fatal(err)
				}
				n, err := io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				if err != nil || n != int64(size) {
					b.Fatalf("read %d bytes, %v", n, err)
				}
			}
		})
	}
}

func BenchmarkStat(b *testing.B) {
	s := benchStore(b)
	info := benchPut(b, s, 1024)
	for b.Loop() {
		if _, err := s.Stat(ctx, info.Digest); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkParseDigest(b *testing.B) {
	str := FromBytes([]byte("x")).String()
	for b.Loop() {
		if _, err := ParseDigest(str); err != nil {
			b.Fatal(err)
		}
	}
}

func benchPut(b *testing.B, s Store, size int) Info {
	b.Helper()
	u, err := s.NewUpload(ctx)
	if err != nil {
		b.Fatal(err)
	}
	u.Write(bytes.Repeat([]byte{0x77}, size))
	info, err := u.Commit(ctx, Digest{})
	if err != nil {
		b.Fatal(err)
	}
	return info
}
