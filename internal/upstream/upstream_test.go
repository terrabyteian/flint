package upstream_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/terrabyteian/flint/internal/blob"
	"github.com/terrabyteian/flint/internal/fsys"
	"github.com/terrabyteian/flint/internal/upstream"
	"github.com/terrabyteian/flint/internal/upstream/upstreamtest"
)

var quiet = slog.New(slog.DiscardHandler)

var ctx = context.Background()

func newClient(t *testing.T, url string, opts upstream.Options) *upstream.Client {
	t.Helper()
	opts.URL = url
	opts.Logger = quiet
	if opts.Backoff == 0 {
		opts.Backoff = time.Millisecond
	}
	c, err := upstream.New(opts)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func mustDigest(t *testing.T, s string) blob.Digest {
	t.Helper()
	d, err := blob.ParseDigest(s)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestNewRejectsBadSettings(t *testing.T) {
	for _, u := range []string{"", "ftp://x", "https://", "::"} {
		if _, err := upstream.New(upstream.Options{URL: u}); err == nil {
			t.Errorf("New(%q) succeeded", u)
		}
	}
	_, err := upstream.New(upstream.Options{URL: "https://x", Username: "u", PasswordFile: filepath.Join(t.TempDir(), "missing")})
	if err == nil || !strings.Contains(err.Error(), "password file") {
		t.Errorf("New with a missing password file: %v", err)
	}
}

func TestAnonymousTokenFlow(t *testing.T) {
	reg := upstreamtest.New(t)
	img := reg.PutImage("library/alpine", "3", []byte("layer"))
	c := newClient(t, reg.URL, upstream.Options{})
	for range 3 {
		m, err := c.GetManifest(ctx, "library/alpine", "3")
		if err != nil {
			t.Fatal(err)
		}
		if m.Digest.String() != img.Digest || !bytes.Equal(m.Body, img.Manifest) || m.MediaType != upstreamtest.MediaTypeManifest {
			t.Fatalf("got %+v", m.Descriptor)
		}
	}
	// One challenge, one token, then the cached token serves every request.
	if n := reg.Count("GET", "/token"); n != 1 {
		t.Errorf("fetched %d tokens, want 1", n)
	}
	if n := reg.Count("GET", "/manifests/3"); n != 4 {
		t.Errorf("sent %d manifest requests, want 4 (one challenged)", n)
	}
	// Another repository needs a token of its own scope.
	reg.PutImage("library/busybox", "1")
	if _, err := c.GetManifest(ctx, "library/busybox", "1"); err != nil {
		t.Fatal(err)
	}
	if n := reg.Count("GET", "/token"); n != 2 {
		t.Errorf("fetched %d tokens, want 2", n)
	}
}

func TestCredentialedTokenFlow(t *testing.T) {
	reg := upstreamtest.New(t)
	reg.Username, reg.Password = "bot", "s3cret"
	reg.PutImage("team/app", "v1")
	pwFile := filepath.Join(t.TempDir(), "password")
	if err := os.WriteFile(pwFile, []byte("wrong\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c := newClient(t, reg.URL, upstream.Options{Username: "bot", PasswordFile: pwFile})
	_, err := c.GetManifest(ctx, "team/app", "v1")
	if !errors.Is(err, upstream.ErrDenied) {
		t.Fatalf("with a wrong password: %v, want ErrDenied", err)
	}
	if strings.Contains(err.Error(), "wrong") {
		t.Errorf("the error reveals the password: %v", err)
	}
	if c.Offline() {
		t.Error("a refused token marked the upstream offline")
	}
	// The password file is read again, so a rotated secret works at once.
	if err := os.WriteFile(pwFile, []byte("s3cret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := c.GetManifest(ctx, "team/app", "v1"); err != nil {
		t.Fatalf("with the right password: %v", err)
	}
	// Anonymous clients are refused.
	anon := newClient(t, reg.URL, upstream.Options{})
	if _, err := anon.GetManifest(ctx, "team/app", "v1"); !errors.Is(err, upstream.ErrDenied) {
		t.Errorf("anonymous: %v, want ErrDenied", err)
	}
}

func TestBasicChallenge(t *testing.T) {
	pwFile := filepath.Join(t.TempDir(), "password")
	os.WriteFile(pwFile, []byte("pw"), 0o600)
	var authz []string
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		authz = append(authz, r.Header.Get("Authorization"))
		mu.Unlock()
		if u, p, ok := r.BasicAuth(); !ok || u != "me" || p != "pw" {
			w.Header().Set("WWW-Authenticate", `Basic realm="registry"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Length", "3")
	}))
	defer srv.Close()
	d := mustDigest(t, upstreamtest.Digest([]byte("abc")))
	c := newClient(t, srv.URL, upstream.Options{Username: "me", PasswordFile: pwFile})
	if size, err := c.HeadBlob(ctx, "x", d); err != nil || size != 3 {
		t.Fatalf("HeadBlob = %d, %v", size, err)
	}
	if len(authz) != 2 || authz[0] != "" || !strings.HasPrefix(authz[1], "Basic ") {
		t.Errorf("Authorization headers sent: %q", authz)
	}
	anon := newClient(t, srv.URL, upstream.Options{})
	if _, err := anon.HeadBlob(ctx, "x", d); !errors.Is(err, upstream.ErrDenied) {
		t.Errorf("anonymous against Basic: %v, want ErrDenied", err)
	}
}

func TestInsecureRealmRefused(t *testing.T) {
	var tokenRequests atomic.Int32
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenRequests.Add(1)
		io.WriteString(w, `{"token":"t"}`)
	}))
	defer plain.Close()
	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="`+plain.URL+`/token",service="x"`)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer tlsSrv.Close()
	c := newClient(t, tlsSrv.URL, upstream.Options{HTTPClient: tlsSrv.Client()})
	_, err := c.GetManifest(ctx, "a", "b")
	if !errors.Is(err, upstream.ErrDenied) || !strings.Contains(err.Error(), "not https") {
		t.Errorf("err = %v, want a refused realm", err)
	}
	if tokenRequests.Load() != 0 {
		t.Error("asked a plain-HTTP realm for a token of an HTTPS registry")
	}
}

func TestStatusErrors(t *testing.T) {
	reg := upstreamtest.New(t)
	reg.PutImage("a", "v1")
	c := newClient(t, reg.URL, upstream.Options{})
	if _, err := c.GetManifest(ctx, "a", "missing"); !errors.Is(err, upstream.ErrNotFound) {
		t.Errorf("missing tag: %v, want ErrNotFound", err)
	}
	reg.SetStatus(func(r *http.Request) int {
		if strings.Contains(r.URL.Path, "/manifests/") {
			return http.StatusBadRequest
		}
		return 0
	})
	_, err := c.GetManifest(ctx, "a", "v1")
	var ue *upstream.Error
	if !errors.As(err, &ue) || ue.Status != http.StatusBadRequest || errors.Is(err, upstream.ErrUnavailable) {
		t.Errorf("400: %v", err)
	}
	if n := reg.Count("GET", "/manifests/v1"); n != 1 { // the token is cached already
		t.Errorf("a 400 was retried: %d requests", n)
	}
	if c.Offline() {
		t.Error("a 400 marked the upstream offline")
	}
}

func TestRetriesAndOffline(t *testing.T) {
	reg := upstreamtest.New(t)
	reg.PutImage("a", "v1")
	now := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	var mu sync.Mutex
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	c := newClient(t, reg.URL, upstream.Options{Attempts: 3, OfflineFor: 30 * time.Second, Now: clock})
	if _, err := c.HeadManifest(ctx, "a", "v1"); err != nil { // fetch a token first
		t.Fatal(err)
	}

	// Two transient failures, then success: the request succeeds.
	var failures atomic.Int32
	failures.Store(2)
	reg.SetStatus(func(r *http.Request) int {
		if failures.Add(-1) >= 0 {
			return http.StatusServiceUnavailable
		}
		return 0
	})
	before := reg.Count("HEAD", "/manifests/v1")
	if _, err := c.HeadManifest(ctx, "a", "v1"); err != nil {
		t.Fatalf("after two 503s: %v", err)
	}
	if n := reg.Count("HEAD", "/manifests/v1") - before; n != 3 {
		t.Errorf("sent %d requests, want 3", n)
	}

	// A rate limit with a long Retry-After is not retried.
	reg.SetStatus(nil)
	limited := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "60")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer limited.Close()
	lc := newClient(t, limited.URL, upstream.Options{Attempts: 5})
	var limitedRequests atomic.Int32
	limited.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		limitedRequests.Add(1)
		w.Header().Set("Retry-After", "60")
		w.WriteHeader(http.StatusTooManyRequests)
	})
	if _, err := lc.HeadBlob(ctx, "a", mustDigest(t, upstreamtest.Digest(nil))); !errors.Is(err, upstream.ErrUnavailable) {
		t.Errorf("rate limited: %v, want ErrUnavailable", err)
	}
	if n := limitedRequests.Load(); n != 1 {
		t.Errorf("a rate limit with a long Retry-After was retried: %d requests", n)
	}

	// Down: every attempt fails, and the upstream is marked offline.
	reg.SetDown(true)
	before = len(reg.Requests())
	_, err := c.HeadManifest(ctx, "a", "v1")
	if !errors.Is(err, upstream.ErrUnavailable) {
		t.Fatalf("down: %v, want ErrUnavailable", err)
	}
	// net/http itself may resend a request whose reused connection
	// dropped, so count at least one request per attempt.
	if n := len(reg.Requests()) - before; n < 3 || n > 6 {
		t.Errorf("sent %d requests to a down upstream, want 3 attempts", n)
	}
	if !c.Offline() {
		t.Error("not offline after the upstream went down")
	}
	mu.Lock()
	now = now.Add(31 * time.Second)
	mu.Unlock()
	if c.Offline() {
		t.Error("still offline after OfflineFor")
	}
	// A success clears the offline mark at once.
	c.HeadManifest(ctx, "a", "v1")
	if !c.Offline() {
		t.Fatal("not offline after another failure")
	}
	reg.SetDown(false)
	if _, err := c.HeadManifest(ctx, "a", "v1"); err != nil || c.Offline() {
		t.Errorf("after the upstream came back: %v, offline %v", err, c.Offline())
	}

	// A cancelled context ends retries at once.
	reg.SetDown(true)
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := c.HeadManifest(cctx, "a", "v1"); !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled: %v", err)
	}
}

func TestManifestVerification(t *testing.T) {
	reg := upstreamtest.New(t)
	img := reg.PutImage("a", "v1")
	c := newClient(t, reg.URL, upstream.Options{})
	if _, err := c.GetManifest(ctx, "a", img.Digest); err != nil {
		t.Fatal(err)
	}
	reg.Corrupt(img.Digest)
	// By digest, the body must hash to the reference.
	if _, err := c.GetManifest(ctx, "a", img.Digest); !errors.Is(err, upstream.ErrDigestMismatch) {
		t.Errorf("corrupt by digest: %v, want ErrDigestMismatch", err)
	}
	// By tag, it must hash to the digest the upstream announces.
	if _, err := c.GetManifest(ctx, "a", "v1"); !errors.Is(err, upstream.ErrDigestMismatch) {
		t.Errorf("corrupt by tag: %v, want ErrDigestMismatch", err)
	}
	if _, err := c.GetManifest(ctx, "a", "sha256:nope"); err == nil {
		t.Error("an invalid digest reference was sent")
	}
}

func TestHeadManifest(t *testing.T) {
	reg := upstreamtest.New(t)
	img := reg.PutImage("a", "v1")
	c := newClient(t, reg.URL, upstream.Options{})
	desc, err := c.HeadManifest(ctx, "a", "v1")
	if err != nil || desc.Digest.String() != img.Digest || desc.Size != int64(len(img.Manifest)) {
		t.Fatalf("HeadManifest = %+v, %v", desc, err)
	}
	if n := reg.Count("GET", "/manifests/"); n != 0 {
		t.Errorf("HeadManifest sent %d GETs", n)
	}
	reg.NoHeadDigest = true
	if _, err := c.HeadManifest(ctx, "a", "v1"); !errors.Is(err, upstream.ErrNoDigest) {
		t.Errorf("without a digest header: %v, want ErrNoDigest", err)
	}
}

func TestParseChallenge(t *testing.T) {
	// Exercised through the client: each header must lead to a token
	// request carrying the realm's service and scope.
	for _, tc := range []struct{ header, wantQuery string }{
		{`Bearer realm="%s",service="svc",scope="repository:a:pull"`, "scope=repository%3Aa%3Apull&service=svc"},
		{`Bearer realm=%s, service=svc`, "scope=repository%3Aa%3Apull&service=svc"},
		{`Basic realm="x", Bearer realm="%s",service="s\"q"`, "scope=repository%3Aa%3Apull&service=s%22q"},
		{`BEARER REALM="%s"`, "scope=repository%3Aa%3Apull"},
	} {
		var got atomic.Value
		var srv *httptest.Server
		srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/token" {
				got.Store(r.URL.RawQuery)
				io.WriteString(w, `{"access_token":"t","expires_in":1}`)
				return
			}
			if r.Header.Get("Authorization") == "Bearer t" {
				w.Header().Set("Content-Length", "0")
				return
			}
			w.Header().Set("WWW-Authenticate", strings.Replace(tc.header, "%s", srv.URL+"/token", 1))
			w.WriteHeader(http.StatusUnauthorized)
		}))
		c := newClient(t, srv.URL, upstream.Options{})
		_, err := c.HeadBlob(ctx, "a", mustDigest(t, upstreamtest.Digest(nil)))
		srv.Close()
		if err != nil {
			t.Errorf("%s: %v", tc.header, err)
			continue
		}
		if q, _ := got.Load().(string); q != tc.wantQuery {
			t.Errorf("%s: token query %q, want %q", tc.header, q, tc.wantQuery)
		}
	}
}

// chunkReader returns its data a few bytes at a time.
type chunkReader struct{ data []byte }

func (r *chunkReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, io.EOF
	}
	n := copy(p[:min(len(p), 7)], r.data)
	r.data = r.data[n:]
	return n, nil
}

// failingReader fails with err after its data.
type failingReader struct {
	data []byte
	err  error
}

func (r *failingReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, r.err
	}
	n := copy(p, r.data)
	r.data = r.data[n:]
	return n, nil
}

func TestCopyVerified(t *testing.T) {
	data := bytes.Repeat([]byte("0123456789abcdef"), 20000) // several chunks
	d := mustDigest(t, upstreamtest.Digest(data))
	for _, tc := range []struct {
		name    string
		r       io.Reader
		size    int64
		wantErr error // nil means the whole content is copied
	}{
		{"good", bytes.NewReader(data), int64(len(data)), nil},
		{"good unknown size", &chunkReader{data}, -1, nil},
		{"empty", bytes.NewReader(nil), 0, upstream.ErrDigestMismatch},
		{"corrupt", bytes.NewReader(append(bytes.Clone(data[:len(data)-1]), 'x')), int64(len(data)), upstream.ErrDigestMismatch},
		{"too long", bytes.NewReader(append(bytes.Clone(data), 'x')), int64(len(data)), upstream.ErrDigestMismatch},
		{"truncated", bytes.NewReader(data[:len(data)-1]), int64(len(data)), io.ErrUnexpectedEOF},
		{"reader's own unexpected EOF", &failingReader{data, io.ErrUnexpectedEOF}, -1, upstream.ErrUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			n, err := upstream.CopyVerified(&out, upstream.NewVerifier(tc.r, d, tc.size))
			if tc.wantErr == nil {
				if err != nil || n != int64(len(data)) || !bytes.Equal(out.Bytes(), data) {
					t.Fatalf("copied %d bytes, %v", n, err)
				}
				return
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
			// The client never receives the whole content.
			if int64(out.Len()) != n || out.Len() >= len(data) {
				t.Errorf("wrote %d of %d bytes of failed content", out.Len(), len(data))
			}
		})
	}
}

func TestGroup(t *testing.T) {
	var g upstream.Group[int]
	var calls atomic.Int32
	release := make(chan struct{})
	var wg sync.WaitGroup
	results := make([]int, 10)
	for i := range results {
		wg.Go(func() {
			v, err := g.Do(ctx, "k", func(context.Context) (int, error) {
				calls.Add(1)
				<-release
				return 42, nil
			})
			if err != nil {
				t.Error(err)
			}
			results[i] = v
		})
	}
	time.Sleep(20 * time.Millisecond)
	close(release)
	wg.Wait()
	if calls.Load() != 1 {
		t.Errorf("%d calls, want 1", calls.Load())
	}
	for _, v := range results {
		if v != 42 {
			t.Errorf("result %d", v)
		}
	}
	// A caller that gives up does not cancel the call for the others.
	block := make(chan struct{})
	cctx, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() {
		_, err := g.Do(cctx, "j", func(c context.Context) (int, error) {
			<-block
			return 1, c.Err()
		})
		done <- err
	}()
	time.Sleep(10 * time.Millisecond)
	waiter := make(chan int, 1)
	go func() {
		v, _ := g.Do(ctx, "j", func(context.Context) (int, error) { return 2, nil })
		waiter <- v
	}()
	time.Sleep(10 * time.Millisecond)
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled caller: %v", err)
	}
	close(block)
	if v := <-waiter; v != 1 {
		t.Errorf("the other caller got %d, want the running call's 1", v)
	}
}

func newStore(t *testing.T) blob.Store {
	t.Helper()
	s, err := blob.NewFS("/data", blob.Options{FS: fsys.NewMem()})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestFetcherDedupAndStream(t *testing.T) {
	reg := upstreamtest.New(t)
	data := bytes.Repeat([]byte("layer!"), 100000)
	ds := reg.PutBlob("a", data)
	d := mustDigest(t, ds)
	release := reg.Stall(ds)
	c := newClient(t, reg.URL, upstream.Options{})
	store := newStore(t)
	f := upstream.NewFetcher(store, 0)

	var opens, dones atomic.Int32
	open := func(ctx context.Context) (io.ReadCloser, int64, error) {
		opens.Add(1)
		return c.GetBlob(ctx, "a", d)
	}
	done := func(_ context.Context, info blob.Info, err error) {
		dones.Add(1)
		if err != nil || info.Size != int64(len(data)) {
			t.Errorf("done(%+v, %v)", info, err)
		}
	}
	const clients = 8
	outs := make([]*syncBuffer, clients)
	var wg sync.WaitGroup
	var joined atomic.Int32
	started := make(chan struct{}, clients)
	for i := range clients {
		outs[i] = &syncBuffer{}
		fe, j := f.Fetch("a@"+ds, d, open, done)
		if j {
			joined.Add(1)
		}
		wg.Go(func() {
			defer fe.Release()
			size, err := fe.Wait(ctx)
			if err != nil || size != int64(len(data)) {
				t.Errorf("Wait = %d, %v", size, err)
			}
			started <- struct{}{}
			if _, err := fe.Stream(ctx, outs[i]); err != nil {
				t.Error(err)
			}
		})
	}
	for range clients {
		<-started
	}
	// While the upstream holds back the last byte, the clients receive
	// everything but the final byte, and nothing is committed yet.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if len(outs[0].Bytes()) > 0 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if _, err := store.Stat(ctx, d); !errors.Is(err, blob.ErrNotFound) {
		t.Errorf("the blob is visible before it is complete: %v", err)
	}
	release()
	wg.Wait()
	if opens.Load() != 1 || dones.Load() != 1 || joined.Load() != clients-1 {
		t.Errorf("opens=%d dones=%d joined=%d, want 1, 1, %d", opens.Load(), dones.Load(), joined.Load(), clients-1)
	}
	for i, out := range outs {
		if !bytes.Equal(out.Bytes(), data) {
			t.Errorf("client %d received %d bytes", i, out.Len())
		}
	}
	if n := reg.Count("GET", "/blobs/"); n != 2 { // one challenged
		t.Errorf("%d upstream blob requests, want 2", n)
	}
	if info, err := store.Stat(ctx, d); err != nil || info.Size != int64(len(data)) {
		t.Errorf("stored blob: %+v, %v", info, err)
	}
	// Once done, a new call starts a new fetch.
	fe, j := f.Fetch("a@"+ds, d, open, func(context.Context, blob.Info, error) {})
	fe.Wait(ctx)
	fe.Release()
	if j {
		t.Error("joined a finished fetch")
	}
}

// syncBuffer is a bytes.Buffer safe for concurrent use.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.Write(p)
}

func (b *syncBuffer) Bytes() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return bytes.Clone(b.b.Bytes())
}

func (b *syncBuffer) Len() int { return len(b.Bytes()) }

func TestFetcherDigestMismatch(t *testing.T) {
	reg := upstreamtest.New(t)
	data := bytes.Repeat([]byte("x"), 300000)
	ds := reg.PutBlob("a", data)
	d := mustDigest(t, ds)
	reg.Corrupt(ds)
	c := newClient(t, reg.URL, upstream.Options{})
	store := newStore(t)
	f := upstream.NewFetcher(store, 0)
	var doneErr error
	fe, _ := f.Fetch(ds, d, func(ctx context.Context) (io.ReadCloser, int64, error) {
		return c.GetBlob(ctx, "a", d)
	}, func(_ context.Context, _ blob.Info, err error) { doneErr = err })
	defer fe.Release()
	var out bytes.Buffer
	n, err := fe.Stream(ctx, &out)
	if !errors.Is(err, upstream.ErrDigestMismatch) || !errors.Is(doneErr, upstream.ErrDigestMismatch) {
		t.Fatalf("Stream: %v; done: %v; want ErrDigestMismatch", err, doneErr)
	}
	if n >= int64(len(data)) || int64(out.Len()) != n {
		t.Errorf("streamed %d of %d bytes of a corrupt blob", n, len(data))
	}
	if _, err := store.Stat(ctx, d); !errors.Is(err, blob.ErrNotFound) {
		t.Errorf("a corrupt blob was stored: %v", err)
	}
}

func TestFetcherErrors(t *testing.T) {
	store := newStore(t)
	f := upstream.NewFetcher(store, 50*time.Millisecond)
	d := mustDigest(t, upstreamtest.Digest([]byte("abc")))
	boom := errors.New("boom")
	fe, _ := f.Fetch("k", d, func(context.Context) (io.ReadCloser, int64, error) { return nil, 0, boom },
		func(context.Context, blob.Info, error) {})
	if _, err := fe.Wait(ctx); !errors.Is(err, boom) {
		t.Errorf("Wait = %v, want the open error", err)
	}
	if _, err := fe.Stream(ctx, io.Discard); !errors.Is(err, boom) {
		t.Errorf("Stream = %v, want the open error", err)
	}
	fe.Release()

	// An upstream that stops sending fails the fetch after the idle timeout.
	pr, pw := io.Pipe()
	defer pw.Close()
	pw2 := make(chan struct{})
	go func() { pw.Write([]byte("a")); close(pw2) }()
	fe, _ = f.Fetch("k2", d, func(ctx context.Context) (io.ReadCloser, int64, error) {
		// Like an HTTP response body, the pipe fails once ctx is cancelled.
		context.AfterFunc(ctx, func() { pr.CloseWithError(ctx.Err()) })
		return pr, 3, nil
	}, func(context.Context, blob.Info, error) {})
	defer fe.Release()
	<-pw2
	if _, err := fe.Stream(ctx, io.Discard); !errors.Is(err, upstream.ErrUnavailable) {
		t.Errorf("stalled upstream: %v, want ErrUnavailable", err)
	}
}

func TestSpace(t *testing.T) {
	var mu sync.Mutex
	free, total := uint64(1000), uint64(10000)
	var failing error
	statfs := func(string) (uint64, uint64, error) {
		mu.Lock()
		defer mu.Unlock()
		return free, total, failing
	}
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	advance := func() { mu.Lock(); now = now.Add(2 * time.Second); mu.Unlock() }
	set := func(f uint64, err error) { mu.Lock(); free, failing = f, err; mu.Unlock(); advance() }
	s := upstream.NewSpace(upstream.SpaceOptions{Path: "/data", Statfs: statfs, Now: clock, Logger: quiet,
		MinFree: func(total uint64) uint64 { return total / 20 }}) // 500 of 10000

	rel1, ok := s.Reserve(300)
	if !ok || s.Pressure() {
		t.Fatal("300 of 1000 free bytes refused")
	}
	// 1000 free - 300 reserved - 500 threshold leaves 200.
	if _, ok := s.Reserve(201); ok {
		t.Error("a reservation past the threshold was granted")
	}
	if s.Pressure() {
		t.Error("one large blob that does not fit put the disk under pressure")
	}
	rel2, ok := s.Reserve(200)
	if !ok {
		t.Error("200 bytes refused")
	}
	rel1()
	rel1() // releasing twice is harmless
	if _, ok := s.Reserve(300); !ok {
		t.Error("released space not available again")
	}
	rel2()

	set(400, nil) // below the threshold
	if _, ok := s.Reserve(0); ok || !s.Pressure() {
		t.Error("caching allowed below the threshold")
	}
	if s.Free() != 400 {
		t.Errorf("Free() = %d", s.Free())
	}
	set(5000, nil)
	if _, ok := s.Reserve(0); !ok || s.Pressure() {
		t.Error("still under pressure after space was freed")
	}
	// A failed measurement does not stop caching.
	set(0, errors.New("statfs failed"))
	if _, ok := s.Reserve(100); !ok || s.Pressure() {
		t.Error("caching stopped because free space could not be measured")
	}

	// Run measures periodically, so pressure shows without fetches.
	set(100, nil)
	rctx, cancel := context.WithCancel(ctx)
	runDone := make(chan struct{})
	go func() { s.Run(rctx, time.Millisecond); close(runDone) }()
	deadline := time.Now().Add(5 * time.Second)
	for !s.Pressure() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	cancel()
	<-runDone
	if !s.Pressure() {
		t.Error("Run did not notice the pressure")
	}
}

func TestSpaceOnThisPlatform(t *testing.T) {
	s := upstream.NewSpace(upstream.SpaceOptions{Path: t.TempDir(), Logger: quiet})
	if _, ok := s.Reserve(1); !ok {
		t.Error("caching refused with no threshold")
	}
}
