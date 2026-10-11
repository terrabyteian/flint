package gc

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/terrabyteian/flint/internal/blob"
	"github.com/terrabyteian/flint/internal/fsys"
	"github.com/terrabyteian/flint/internal/meta"
	"github.com/terrabyteian/flint/internal/metrics"
)

// The test format's metadata keys:
//
//	t\0link\0<digest>   links a blob
//	t\0ref\0<name>      references the digests in its value, separated by spaces
//	t\0meta\0<name>     references nothing
const (
	linkPrefix = "t\x00link\x00"
	refPrefix  = "t\x00ref\x00"
	metaPrefix = "t\x00meta\x00"
)

var testMarker = Marker{
	linkPrefix: func(key, _ []byte) ([]blob.Digest, error) {
		d, err := blob.ParseDigest(string(key[len(linkPrefix):]))
		if err != nil {
			return nil, err
		}
		return []blob.Digest{d}, nil
	},
	refPrefix: func(_, value []byte) ([]blob.Digest, error) {
		var out []blob.Digest
		for _, f := range strings.Fields(string(value)) {
			d, err := blob.ParseDigest(f)
			if err != nil {
				return nil, err
			}
			out = append(out, d)
		}
		return out, nil
	},
	metaPrefix: nil,
}

func linkKey(d blob.Digest) []byte { return []byte(linkPrefix + d.String()) }

// clock is a settable clock, safe for concurrent use.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// logBuffer collects log output, safe for concurrent use.
type logBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *logBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *logBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

// env is a Collector over in-memory stores and the test format.
type env struct {
	t     *testing.T
	fs    *fsys.Mem
	meta  meta.Store
	blobs blob.Store
	clock *clock
	logs  *logBuffer
	reg   *metrics.Registry
	c     *Collector

	hookMu sync.Mutex
	hook   func(Step)
}

func newTestEnv(t *testing.T, mod func(*Options)) *env {
	t.Helper()
	e := &env{t: t, fs: fsys.NewMem(), clock: &clock{t: time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)}}
	e.open(mod)
	return e
}

// open opens the stores on e.fs and a new Collector over them.
func (e *env) open(mod func(*Options)) {
	t := e.t
	t.Helper()
	e.logs = &logBuffer{}
	logger := slog.New(slog.NewTextHandler(e.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	ms, err := meta.Open("/data/meta", meta.Options{FS: e.fs, Logger: logger})
	if err != nil {
		t.Fatal(err)
	}
	bs, err := blob.NewFS("/data", blob.Options{FS: e.fs, Now: e.clock.now})
	if err != nil {
		t.Fatal(err)
	}
	e.meta, e.blobs, e.reg = ms, bs, metrics.NewRegistry()
	opts := Options{
		Meta: ms, Blobs: bs, Markers: []Marker{testMarker}, Logger: logger, Metrics: e.reg, Now: e.clock.now,
		Hook: func(s Step) {
			e.hookMu.Lock()
			h := e.hook
			e.hookMu.Unlock()
			if h != nil {
				h(s)
			}
		},
	}
	if mod != nil {
		mod(&opts)
	}
	if e.c, err = New(opts); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		e.c.Close()
		ms.Close()
	})
}

func (e *env) setHook(h func(Step)) {
	e.hookMu.Lock()
	defer e.hookMu.Unlock()
	e.hook = h
}

// put stores content in the blob store, committed now.
func (e *env) put(content string) blob.Digest {
	e.t.Helper()
	d, err := putBlob(e.blobs, content)
	if err != nil {
		e.t.Fatal(err)
	}
	return d
}

func putBlob(bs blob.Store, content string) (blob.Digest, error) {
	up, err := bs.NewUpload(context.Background())
	if err != nil {
		return blob.Digest{}, err
	}
	if _, err := up.Write([]byte(content)); err != nil {
		up.Cancel()
		return blob.Digest{}, err
	}
	info, err := up.Commit(context.Background(), blob.Digest{})
	return info.Digest, err
}

// commit commits a batch built by f.
func (e *env) commit(f func(b *meta.Batch)) {
	e.t.Helper()
	var b meta.Batch
	f(&b)
	if _, err := e.meta.Commit(context.Background(), &b); err != nil {
		e.t.Fatal(err)
	}
}

// link stores content and links it as the test format's link batch does:
// read a view and apply Guard, commit the upload (the existence check),
// then commit the batch, rebuilding it from a new view if a precondition
// fails. stage, if set, is called after the view is read ("viewed") and
// after the upload is committed ("stored").
func link(ms meta.Store, bs blob.Store, content string, stage func(string)) error {
	d := blob.FromBytes([]byte(content))
	for range 4 {
		v := ms.View()
		var b meta.Batch
		err := Guard(v, &b, d)
		v.Release()
		if err != nil {
			return err
		}
		b.Put(linkKey(d), nil)
		if stage != nil {
			stage("viewed")
		}
		if _, err := putBlob(bs, content); err != nil {
			return err
		}
		if stage != nil {
			stage("stored")
		}
		_, err = ms.Commit(context.Background(), &b)
		if !errors.Is(err, meta.ErrConflict) {
			return err
		}
	}
	return errors.New("link: gave up after repeated conflicts")
}

func (e *env) link(content string) blob.Digest {
	e.t.Helper()
	if err := link(e.meta, e.blobs, content, nil); err != nil {
		e.t.Fatal(err)
	}
	return blob.FromBytes([]byte(content))
}

func (e *env) unlink(d blob.Digest) {
	e.t.Helper()
	e.commit(func(b *meta.Batch) { b.Delete(linkKey(d)) })
}

// ref writes a record that references ds without linking them.
func (e *env) ref(name string, ds ...blob.Digest) {
	e.t.Helper()
	var parts []string
	for _, d := range ds {
		parts = append(parts, d.String())
	}
	e.commit(func(b *meta.Batch) { b.Put([]byte(refPrefix+name), []byte(strings.Join(parts, " "))) })
}

func (e *env) unref(name string) {
	e.t.Helper()
	e.commit(func(b *meta.Batch) { b.Delete([]byte(refPrefix + name)) })
}

func (e *env) exists(d blob.Digest) bool {
	e.t.Helper()
	_, err := e.blobs.Stat(context.Background(), d)
	if err != nil && !errors.Is(err, blob.ErrNotFound) {
		e.t.Fatal(err)
	}
	return err == nil
}

// run runs the collector and returns its report.
func (e *env) run(dryRun bool) *Report {
	e.t.Helper()
	r, err := e.c.Run(context.Background(), RunOptions{DryRun: dryRun, Actor: "tester"})
	if err != nil {
		e.t.Fatal(err)
	}
	return r
}

// doomed returns the digests in the doomed set.
func doomed(ms meta.Store) []string {
	var out []string
	v := ms.View()
	defer v.Release()
	v.Scan([]byte(DoomedPrefix), nil, func(k []byte, _ meta.Record) bool {
		out = append(out, string(k[len(DoomedPrefix):]))
		return true
	})
	return out
}

// epochVersion returns the version of the GC epoch key.
func epochVersion(ms meta.Store) meta.Seq {
	v := ms.View()
	defer v.Release()
	r, _ := v.Get([]byte(EpochKey))
	return r.Version
}

// checkReferencedExist fails the test if a blob that the current
// metadata references is missing from the blob store.
func checkReferencedExist(t *testing.T, ms meta.Store, bs blob.Store) {
	t.Helper()
	v := ms.View()
	defer v.Release()
	refs, problems, err := CheckMarker(v, testMarker)
	if err != nil || problems != nil {
		t.Fatalf("CheckMarker: %v %v", problems, err)
	}
	for _, d := range refs {
		if _, err := bs.Stat(context.Background(), d); err != nil {
			t.Errorf("referenced blob %s: %v", d, err)
		}
	}
}

// metric returns the line of the metrics exposition that starts with
// sample, or "".
func (e *env) metric(sample string) string {
	var buf bytes.Buffer
	e.reg.WriteTo(&buf)
	for line := range strings.SplitSeq(buf.String(), "\n") {
		if strings.HasPrefix(line, sample+" ") {
			return line
		}
	}
	return ""
}

func counts(c Count) string { return fmt.Sprintf("%d/%d", c.Blobs, c.Bytes) }
