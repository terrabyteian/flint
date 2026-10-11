package upstream

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/terrabyteian/flint/internal/blob"
)

// DefaultIdleTimeout is how long a fetch waits for the next bytes from
// the upstream before it gives up.
const DefaultIdleTimeout = 2 * time.Minute

// Source opens upstream content for a fetch: its body, which the fetch
// closes, and its size, or -1 if unknown.
type Source func(ctx context.Context) (body io.ReadCloser, size int64, err error)

// Fetcher downloads blobs from upstreams into a blob store, once per
// digest however many clients ask for it at the same time, and streams
// each blob to every client while it arrives. It also fetches content
// by path, whose sha256 digest is not known in advance (FetchPath): the
// blob store computes it while staging, and the format's Expect is
// verified before the blob is committed.
//
// A fetch runs in its own goroutine, independent of the requests that
// read it: a client that disconnects does not stop it, so the blob is
// cached for the next one. Clients read the bytes the fetch has staged
// so far from the blob store's upload, at their own pace; the final
// bytes are released only after the blob store has verified the digest,
// so no client receives the whole of a corrupted blob.
type Fetcher struct {
	blobs blob.Store
	idle  time.Duration

	mu     sync.Mutex
	active map[string]*Fetch
}

// NewFetcher returns a Fetcher writing to blobs, whose uploads must
// implement blob.StagedOpener. A fetch fails if the upstream sends
// nothing for idleTimeout; zero means DefaultIdleTimeout.
func NewFetcher(blobs blob.Store, idleTimeout time.Duration) *Fetcher {
	if idleTimeout <= 0 {
		idleTimeout = DefaultIdleTimeout
	}
	return &Fetcher{blobs: blobs, idle: idleTimeout, active: map[string]*Fetch{}}
}

// Active returns the number of fetches in progress.
func (f *Fetcher) Active() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.active)
}

// Fetch states.
const (
	fetchRunning = iota
	fetchVerified
	fetchFailed
)

// Fetch is one blob being fetched into the blob store.
type Fetch struct {
	key       string
	label     string        // what is fetched, for messages: the digest or the path
	d         blob.Digest   // the digest, or zero if it is not known in advance
	expect    *Expect       // what content fetched by path must match, or nil
	sums      Sums          // the digests computed for expect, once verified
	ctype     string        // the media type a PathSource reported
	ready     chan struct{} // closed once the size is known or the fetch failed
	readyOnce sync.Once

	mu      sync.Mutex
	size    int64 // -1 if unknown
	written int64
	state   int
	err     error
	changed chan struct{} // closed and replaced whenever the above change
	r       blob.StagedReader
	refs    int // holders: the fetch's goroutine and each caller of Fetcher.Fetch
}

// Fetch returns the fetch of blob d under key in progress, or starts one
// that reads the content from open; joined reports whether it joined one
// in progress. The key names where the content comes from, such as the
// upstream repository, as well as the digest: only requests that the
// same upstream would answer may share a fetch. The caller must call Release when it is done with the
// fetch. done is called once, in the fetch's goroutine, after the blob
// has been committed (with its Info) or the fetch has failed (with the
// error), and before a later call can start another fetch of d: a proxy
// links the blob in its metadata there, so that later requests find it.
func (f *Fetcher) Fetch(key string, d blob.Digest, open Source, done func(ctx context.Context, info blob.Info, err error)) (fe *Fetch, joined bool) {
	return f.start(&Fetch{key: key, label: d.String(), d: d}, open, func(ctx context.Context, r PathResult, err error) {
		done(ctx, r.Info, err)
	})
}

// PathResult is the outcome of a fetch by path: the committed blob and
// the digests computed for the Expect.
type PathResult struct {
	Info blob.Info
	Sums Sums
	// ContentType is the media type the PathSource reported.
	ContentType string
}

// FetchPath is Fetch for content whose sha256 digest is not known in
// advance, such as a file a path-addressed proxy caches: the blob store
// computes the digest while staging, the digests and Check of e are
// verified once the content has arrived, and only content that passes is
// committed, so content that fails never enters the blob store and no
// client receives its final byte. label names the content in messages,
// such as its path. done receives the committed blob and the digests
// computed for e; an Expect naming an unknown algorithm fails the fetch.
func (f *Fetcher) FetchPath(key, label string, e Expect, open PathSource, done func(ctx context.Context, r PathResult, err error)) (fe *Fetch, joined bool) {
	nf := &Fetch{key: key, label: label, expect: &e}
	src := func(ctx context.Context) (io.ReadCloser, int64, error) {
		body, size, ct, err := open(ctx)
		if err == nil {
			nf.mu.Lock()
			nf.ctype = ct
			nf.mu.Unlock()
		}
		return body, size, err
	}
	return f.start(nf, src, done)
}

// PathSource is a Source that also reports the content's media type,
// such as the upstream's Content-Type.
type PathSource func(ctx context.Context) (body io.ReadCloser, size int64, contentType string, err error)

// ContentType returns the media type the PathSource of a fetch by path
// reported, once Wait has returned without an error.
func (fe *Fetch) ContentType() string {
	fe.mu.Lock()
	defer fe.mu.Unlock()
	return fe.ctype
}

// start joins the fetch in progress under nf's key or starts nf.
func (f *Fetcher) start(nf *Fetch, open Source, done func(context.Context, PathResult, error)) (fe *Fetch, joined bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if fe := f.active[nf.key]; fe != nil {
		fe.mu.Lock()
		fe.refs++
		fe.mu.Unlock()
		return fe, true
	}
	fe = nf
	fe.ready, fe.size, fe.changed, fe.refs = make(chan struct{}), -1, make(chan struct{}), 2
	f.active[fe.key] = fe
	go f.run(fe, open, done)
	return fe, false
}

// run performs a fetch.
func (f *Fetcher) run(fe *Fetch, open Source, done func(context.Context, PathResult, error)) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	info, err := f.download(ctx, cancel, fe, open)
	if err != nil {
		fe.finish(fetchFailed, err)
	} else {
		fe.finish(fetchVerified, nil)
	}
	done(ctx, PathResult{Info: info, Sums: fe.sums, ContentType: fe.ContentType()}, err)
	f.mu.Lock()
	delete(f.active, fe.key)
	f.mu.Unlock()
	fe.Release()
}

// download copies the upstream content into a new upload and commits it.
func (f *Fetcher) download(ctx context.Context, cancel func(), fe *Fetch, open Source) (blob.Info, error) {
	// A watchdog cancels the fetch when the upstream stalls.
	watchdog := time.AfterFunc(f.idle, cancel)
	defer watchdog.Stop()
	want := fe.d
	var hs *hashers
	if e := fe.expect; e != nil {
		var err error
		if hs, err = newHashers(e); err != nil {
			return blob.Info{}, err
		}
		if e.SHA256 != "" {
			if want, err = blob.ParseDigest("sha256:" + e.SHA256); err != nil {
				return blob.Info{}, fmt.Errorf("upstream: the expected sha256 of %s: %w", fe.label, err)
			}
		}
	}
	body, size, err := open(withWatchdog(ctx, watchdog, f.idle))
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return blob.Info{}, fmt.Errorf("%w: no answer from the upstream for %v while fetching %s", ErrUnavailable, f.idle, fe.label)
		}
		return blob.Info{}, err
	}
	defer body.Close()
	if e := fe.expect; e != nil && e.Size >= 0 {
		if size >= 0 && size != e.Size {
			return blob.Info{}, fmt.Errorf("%w: the upstream announced %d bytes of %s, want %d", ErrDigestMismatch, size, fe.label, e.Size)
		}
		size = e.Size
	}
	up, err := f.blobs.NewUpload(ctx)
	if err != nil {
		return blob.Info{}, err
	}
	so, ok := up.(blob.StagedOpener)
	var r blob.StagedReader
	if ok {
		r, err = so.OpenStaged()
	} else {
		err = errors.New("upstream: the blob store cannot stream staged uploads")
	}
	if err != nil {
		up.Cancel()
		return blob.Info{}, err
	}
	fe.mu.Lock()
	fe.size, fe.r = size, r
	fe.mu.Unlock()
	fe.markReady()

	buf := make([]byte, copyChunk*4)
	for {
		watchdog.Reset(f.idle)
		n, rerr := body.Read(buf)
		if n > 0 {
			if _, err := up.Write(buf[:n]); err != nil {
				up.Cancel()
				return blob.Info{}, err
			}
			if hs != nil {
				hs.Write(buf[:n])
			}
			if size >= 0 && up.Size() > size {
				up.Cancel()
				return blob.Info{}, fmt.Errorf("%w: more than the %d bytes announced for %s", ErrDigestMismatch, size, fe.label)
			}
			fe.progress(up.Size())
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			up.Cancel()
			if ctx.Err() != nil {
				return blob.Info{}, fmt.Errorf("%w: no data from the upstream for %v while fetching %s", ErrUnavailable, f.idle, fe.label)
			}
			return blob.Info{}, fmt.Errorf("%w: reading %s: %v", ErrUnavailable, fe.label, rerr)
		}
	}
	if size >= 0 && up.Size() != size {
		up.Cancel()
		return blob.Info{}, fmt.Errorf("%w: %s ended after %d of %d bytes", ErrUnavailable, fe.label, up.Size(), size)
	}
	watchdog.Stop()
	if hs != nil {
		// Verified before the commit: content that fails never enters
		// the blob store, and the final byte stays held back meanwhile.
		sums, err := hs.verify(fe.expect, fe.label)
		if err == nil && fe.expect.Check != nil {
			err = fe.expect.Check(ctx, r, up.Size())
		}
		if err != nil {
			up.Cancel()
			return blob.Info{}, err
		}
		fe.mu.Lock()
		fe.sums = sums
		fe.mu.Unlock()
	}
	info, err := up.Commit(ctx, want)
	if errors.Is(err, blob.ErrDigestMismatch) {
		err = fmt.Errorf("%w: %v", ErrDigestMismatch, err)
	}
	return info, err
}

// progress records that n bytes are staged.
func (fe *Fetch) progress(n int64) {
	fe.mu.Lock()
	fe.written = n
	close(fe.changed)
	fe.changed = make(chan struct{})
	fe.mu.Unlock()
}

// finish records the fetch's outcome. A fetch that failed before the
// upstream answered becomes ready only now, so Wait reports the failure.
func (fe *Fetch) finish(state int, err error) {
	fe.mu.Lock()
	fe.state, fe.err = state, err
	close(fe.changed)
	fe.changed = make(chan struct{})
	fe.mu.Unlock()
	fe.markReady()
}

func (fe *Fetch) markReady() { fe.readyOnce.Do(func() { close(fe.ready) }) }

// Release drops the caller's reference to the fetch. The staged bytes
// are closed when the fetch and every caller are done with them.
func (fe *Fetch) Release() {
	fe.mu.Lock()
	defer fe.mu.Unlock()
	fe.refs--
	if fe.refs == 0 && fe.r != nil {
		fe.r.Close()
	}
}

// Wait waits until the upstream has answered and returns the blob's size,
// or -1 if the upstream did not say, or the error that failed the fetch.
func (fe *Fetch) Wait(ctx context.Context) (int64, error) {
	select {
	case <-fe.ready:
	case <-ctx.Done():
		return 0, ctx.Err()
	}
	fe.mu.Lock()
	defer fe.mu.Unlock()
	if fe.state == fetchFailed {
		return 0, fe.err
	}
	return fe.size, nil
}

// Stream writes the blob to w as it arrives and returns the bytes
// written. It holds back the final byte until the blob store has verified
// the digest. If the fetch fails, Stream returns its error, having
// written only part of the blob; the caller must then abort the response
// so the client cannot take it for a whole one. The caller must hold its
// reference to the fetch until Stream returns.
func (fe *Fetch) Stream(ctx context.Context, w io.Writer) (int64, error) {
	if _, err := fe.Wait(ctx); err != nil {
		return 0, err
	}
	fe.mu.Lock()
	r := fe.r
	fe.mu.Unlock()
	buf := make([]byte, copyChunk)
	var off int64
	for {
		fe.mu.Lock()
		written, state, err, changed := fe.written, fe.state, fe.err, fe.changed
		fe.mu.Unlock()
		if state == fetchFailed {
			return off, err
		}
		limit := written
		if state == fetchRunning {
			limit-- // the final byte waits for verification
		}
		if off < limit {
			n, err := r.ReadAt(buf[:min(int64(len(buf)), limit-off)], off)
			if n > 0 {
				m, werr := w.Write(buf[:n])
				off += int64(m)
				if werr != nil {
					return off, werr
				}
			}
			if err != nil && err != io.EOF {
				return off, err
			}
			continue
		}
		if state == fetchVerified {
			return off, nil
		}
		select {
		case <-changed:
		case <-ctx.Done():
			return off, ctx.Err()
		}
	}
}
