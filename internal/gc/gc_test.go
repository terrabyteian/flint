package gc

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/terrabyteian/flint/internal/blob"
	"github.com/terrabyteian/flint/internal/fsys"
	"github.com/terrabyteian/flint/internal/meta"
)

// TestSweep deletes exactly the blobs that nothing references and whose
// grace period is over, and records the run.
func TestSweep(t *testing.T) {
	e := newTestEnv(t, nil)
	linked := e.link("linked")
	viaRef := e.put("referenced by a record")
	e.ref("r", viaRef)
	garbage := e.put("garbage")
	unlinked := e.link("unlinked later")
	e.unlink(unlinked)
	e.commit(func(b *meta.Batch) { b.Put([]byte(metaPrefix+"x"), []byte("not a digest")) })
	e.clock.advance(DefaultGracePeriod + time.Second)
	young := e.put("young garbage")
	epoch := epochVersion(e.meta)

	r := e.run(false)
	if r.State != StateSucceeded || r.DryRun || r.Actor != "tester" || r.Trigger != TriggerAPI || r.Finished.IsZero() {
		t.Fatalf("report = %+v", r)
	}
	for _, d := range []blob.Digest{linked, viaRef, young} {
		if !e.exists(d) {
			t.Errorf("blob %s was deleted", d)
		}
	}
	for _, d := range []blob.Digest{garbage, unlinked} {
		if e.exists(d) {
			t.Errorf("blob %s was not deleted", d)
		}
	}
	size := int64(len("garbage") + len("unlinked later"))
	if r.Referenced != 2 || r.Stored.Blobs != 5 || r.Unreferenced.Blobs != 3 || r.InGracePeriod.Blobs != 1 ||
		r.Kept.Blobs != 0 || r.Deleted != (Count{2, size}) || r.GracePeriod != "24h0m0s" {
		t.Errorf("report counts = %+v", r)
	}
	if d := doomed(e.meta); len(d) != 0 {
		t.Errorf("doomed set left behind: %v", d)
	}
	if epochVersion(e.meta) == epoch {
		t.Error("the sweep did not change the GC epoch")
	}
	for _, want := range []string{"garbage collection started", "garbage collection deleted a blob", garbage.String(),
		unlinked.String(), "garbage collection finished"} {
		if !strings.Contains(e.logs.String(), want) {
			t.Errorf("log lacks %q:\n%s", want, e.logs)
		}
	}
	for sample, want := range map[string]string{
		`flint_gc_runs_total{mode="sweep",result="succeeded"}`: "1",
		"flint_gc_reclaimed_blobs_total":                       "2",
		"flint_gc_reclaimed_bytes_total":                       "21",
		"flint_gc_running":                                     "0",
		`flint_gc_duration_seconds_count{mode="sweep"}`:        "1",
		"flint_gc_last_success_timestamp_seconds":              strconv.FormatFloat(float64(r.Finished.Unix()), 'g', -1, 64),
	} {
		if got := e.metric(sample); got != sample+" "+want {
			t.Errorf("metric %s = %q, want %s", sample, got, want)
		}
	}

	st := e.c.Status()
	if st.Running != nil || st.Last == nil || st.Last.State != StateSucceeded || st.GracePeriod != "24h0m0s" || st.NextRun != nil {
		t.Errorf("status = %+v", st)
	}

	// Nothing is left to delete.
	if r := e.run(false); r.State != StateSucceeded || r.Deleted.Blobs != 0 || r.Unreferenced.Blobs != 1 {
		t.Errorf("second run = %+v", r)
	}
}

// TestDryRun reports what a sweep would delete and changes nothing.
func TestDryRun(t *testing.T) {
	e := newTestEnv(t, nil)
	e.link("linked")
	garbage := e.put("garbage")
	e.clock.advance(DefaultGracePeriod + time.Second)
	seq := e.meta.Stats().Seq

	r := e.run(true)
	if r.State != StateSucceeded || !r.DryRun || r.Deleted != (Count{1, 7}) || len(r.Blobs) != 1 ||
		r.Blobs[0].Digest != garbage.String() || r.Blobs[0].Size != 7 || r.BlobsTruncated {
		t.Fatalf("dry run report = %+v", r)
	}
	if !e.exists(garbage) {
		t.Error("a dry run deleted a blob")
	}
	if got := e.meta.Stats().Seq; got != seq {
		t.Errorf("a dry run wrote metadata: sequence %d, then %d", seq, got)
	}
	if got := e.metric(`flint_gc_runs_total{mode="dry_run",result="succeeded"}`); !strings.HasSuffix(got, " 1") {
		t.Errorf("dry run metric = %q", got)
	}
	if got := e.metric("flint_gc_last_success_timestamp_seconds"); got != "flint_gc_last_success_timestamp_seconds 0" {
		t.Errorf("a dry run set the last success time: %q", got)
	}
}

// TestDryRunListBound lists at most maxListed blobs.
func TestDryRunListBound(t *testing.T) {
	e := newTestEnv(t, nil)
	for i := range maxListed + 3 {
		e.put("garbage " + strings.Repeat("x", i))
	}
	e.clock.advance(DefaultGracePeriod + time.Second)
	r := e.run(true)
	if len(r.Blobs) != maxListed || !r.BlobsTruncated || r.Deleted.Blobs != maxListed+3 {
		t.Errorf("listed %d of %d, truncated %v", len(r.Blobs), r.Deleted.Blobs, r.BlobsTruncated)
	}
}

// TestRefuseUnclaimedKeys refuses to delete anything while the metadata
// holds keys under no registered prefix, as a format that forgot to register would
// leave, and deletes again once the keys are gone.
func TestRefuseUnclaimedKeys(t *testing.T) {
	e := newTestEnv(t, nil)
	garbage := e.put("garbage")
	e.commit(func(b *meta.Batch) {
		b.Put([]byte("pypi\x00file\x00repo\x00a.whl"), []byte("record"))
		b.Put([]byte("pypi\x00file\x00repo\x00b.whl"), []byte("record"))
		b.Put([]byte("t\x00other\x00x"), nil)
		b.Put([]byte("orphan"), nil)
	})
	e.clock.advance(DefaultGracePeriod + time.Second)
	seq := e.meta.Stats().Seq

	for _, dry := range []bool{true, false} {
		r := e.run(dry)
		if r.State != StateRefused || r.Deleted.Blobs != 0 || r.Unreferenced.Blobs != 1 {
			t.Fatalf("dry run %v: report = %+v", dry, r)
		}
		refused := strings.Join(r.Refused, "\n")
		for _, want := range []string{`2 metadata keys starting "pypi\x00file\x00"`, `"t\x00other\x00"`, `"orphan"`,
			"are under no prefix registered"} {
			if !strings.Contains(refused, want) {
				t.Errorf("dry run %v: refusal %q lacks %q", dry, refused, want)
			}
		}
		if !e.exists(garbage) {
			t.Fatalf("dry run %v: a refused run deleted a blob", dry)
		}
	}
	if !strings.Contains(e.logs.String(), "garbage collection refused to delete anything") {
		t.Errorf("no refusal log:\n%s", e.logs)
	}
	if got := e.metric(`flint_gc_runs_total{mode="sweep",result="refused"}`); !strings.HasSuffix(got, " 1") {
		t.Errorf("refusal metric = %q", got)
	}
	// A refused run writes only its report.
	if got := e.meta.Stats().Seq; got != seq+1 {
		t.Errorf("a refused run committed %d batches, want only its report", got-seq)
	}

	e.commit(func(b *meta.Batch) {
		b.Delete([]byte("pypi\x00file\x00repo\x00a.whl"))
		b.Delete([]byte("pypi\x00file\x00repo\x00b.whl"))
		b.Delete([]byte("t\x00other\x00x"))
		b.Delete([]byte("orphan"))
	})
	if r := e.run(false); r.State != StateSucceeded || r.Deleted.Blobs != 1 || e.exists(garbage) {
		t.Errorf("run after the unclaimed keys went: %+v", r)
	}
}

// TestRefuseUnreadableRecords refuses to delete anything while a record
// its mark function cannot read is present.
func TestRefuseUnreadableRecords(t *testing.T) {
	e := newTestEnv(t, nil)
	garbage := e.put("garbage")
	e.ref("bad", garbage)
	e.commit(func(b *meta.Batch) { b.Put([]byte(refPrefix+"bad"), []byte("sha256:nothex")) })
	e.clock.advance(DefaultGracePeriod + time.Second)
	r := e.run(false)
	if r.State != StateRefused || !e.exists(garbage) || len(r.Refused) != 1 ||
		!strings.Contains(r.Refused[0], "1 metadata records cannot be read") || !strings.Contains(r.Refused[0], `key "t\x00ref\x00bad"`) {
		t.Errorf("report = %+v", r)
	}
}

// TestRefuseUnclaimedKeysDuringRound refuses a round whose check finds
// keys under no registered prefix, written after the run marked its view.
func TestRefuseUnclaimedKeysDuringRound(t *testing.T) {
	e := newTestEnv(t, nil)
	garbage := e.put("garbage")
	e.clock.advance(DefaultGracePeriod + time.Second)
	e.setHook(func(s Step) {
		if s == StepDoomed {
			e.commit(func(b *meta.Batch) { b.Put([]byte("new\x00format\x00x"), nil) })
		}
	})
	r := e.run(false)
	if r.State != StateRefused || !e.exists(garbage) || len(doomed(e.meta)) != 0 {
		t.Errorf("report = %+v, doomed %v", r, doomed(e.meta))
	}
}

func TestMarkerRegistry(t *testing.T) {
	for _, ms := range [][]Marker{
		{{"a\x00": nil}, {"a\x00b\x00": nil}},
		{{"a\x00b": nil, "a\x00a": nil, "a\x00": nil}},
		{{"x": nil}, {"x": nil}},
		{{"": nil}},
		{{"gc\x00": nil}},
		{{EpochKey: nil}},
	} {
		if _, err := newRegistry(ms); err == nil {
			t.Errorf("newRegistry(%v) accepted overlapping or empty prefixes", ms)
		}
	}
	for key, want := range map[string]string{
		"pypi\x00file\x00repo\x00a.whl": "pypi\x00file\x00", "pypi\x00x": "pypi\x00", "plain": "plain",
		strings.Repeat("y", 100): strings.Repeat("y", 64),
	} {
		if got := keyFamily([]byte(key)); got != want {
			t.Errorf("keyFamily(%q) = %q, want %q", key, got, want)
		}
	}
}

// TestCheckMarker marks the keys under registered prefixes and reports
// every key between, before, and after them.
func TestCheckMarker(t *testing.T) {
	e := newTestEnv(t, nil)
	d1, d2 := blob.FromBytes([]byte("1")), blob.FromBytes([]byte("2"))
	e.commit(func(b *meta.Batch) {
		for _, k := range []string{
			"a", "s\x00", "s\x00a", "s\x00b\x00", "s\x00bb", "s\x00c\x00", "s\x00c", "s\x00c\x01", "s\x00d",
			"t\x00", "t\x00links", "u", "\xff\xff",
		} {
			b.Put([]byte(k), nil)
		}
		b.Put([]byte("s\x00b\x00x"), []byte(d1.String()))
		b.Put([]byte("s\x00b\x00y"), []byte(d2.String()))
		b.Put([]byte("s\x00c\x00x"), []byte(d1.String()))
		b.Put(linkKey(d2), nil)
		b.Put([]byte(EpochKey), encodeEpoch(1))
	})
	ref := func(_, value []byte) ([]blob.Digest, error) {
		if len(value) == 0 {
			return nil, nil
		}
		d, err := blob.ParseDigest(string(value))
		return []blob.Digest{d}, err
	}
	v := e.meta.View()
	defer v.Release()
	refs, problems, err := CheckMarker(v, Marker{"s\x00b\x00": ref, "s\x00c\x00": ref}, Marker{linkPrefix: testMarker[linkPrefix]})
	if err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprint(refs); got != fmt.Sprint([]blob.Digest{d1, d2, d1, d2}) {
		t.Errorf("refs = %v", refs)
	}
	want := []string{
		`1 metadata keys starting "a"`, `6 metadata keys starting "s\x00"`, `2 metadata keys starting "t\x00"`,
		`1 metadata keys starting "u"`, `1 metadata keys starting "\xff\xff"`,
	}
	if len(problems) != len(want) {
		t.Errorf("problems:\n%s", strings.Join(problems, "\n"))
	}
	for i, w := range want {
		if i < len(problems) && !strings.HasPrefix(problems[i], w+" are under no prefix registered") {
			t.Errorf("problem %d = %q, want %s", i, problems[i], w)
		}
	}

	if _, _, err := CheckMarker(v, Marker{"s": nil}, Marker{"s\x00": nil}); err == nil {
		t.Error("CheckMarker accepted overlapping prefixes")
	}
}

func TestGracePeriodOption(t *testing.T) {
	e := newTestEnv(t, nil)
	if _, err := New(Options{Meta: e.meta, Blobs: e.blobs, GracePeriod: MinGracePeriod - time.Second}); err == nil {
		t.Error("New accepted a grace period below the minimum")
	}
	if _, err := New(Options{Meta: e.meta}); err == nil {
		t.Error("New accepted no blob store")
	}
	c, err := New(Options{Meta: e.meta, Blobs: e.blobs, GracePeriod: MinGracePeriod})
	if err != nil || c.GracePeriod() != MinGracePeriod {
		t.Fatalf("New at the minimum grace period = %v", err)
	}
	c.Close()
	if e.c.GracePeriod() != DefaultGracePeriod {
		t.Errorf("default grace period = %s", e.c.GracePeriod())
	}
}

// TestGracePeriod keeps an unreferenced blob until its grace period is
// over, measured from its commit.
func TestGracePeriod(t *testing.T) {
	e := newTestEnv(t, func(o *Options) { o.GracePeriod = 2 * time.Hour })
	d := e.put("garbage")
	e.clock.advance(2 * time.Hour)
	if r := e.run(false); r.Deleted.Blobs != 0 || r.InGracePeriod.Blobs != 1 || !e.exists(d) {
		t.Fatalf("at the end of the grace period: %+v", r)
	}
	e.clock.advance(time.Second)
	if r := e.run(false); r.Deleted.Blobs != 1 || e.exists(d) {
		t.Fatalf("after the grace period: %+v", r)
	}
}

// TestRounds sweeps in rounds of at most RoundSize blobs, each with its
// own epoch and doomed set.
func TestRounds(t *testing.T) {
	e := newTestEnv(t, func(o *Options) { o.RoundSize = 2 })
	var all []blob.Digest
	for i := range 5 {
		all = append(all, e.put("garbage "+string(rune('a'+i))))
	}
	keep := e.link("kept")
	e.clock.advance(DefaultGracePeriod + time.Second)
	var steps []Step
	var doomedSizes []int
	e.setHook(func(s Step) {
		steps = append(steps, s)
		if s == StepDoomed {
			doomedSizes = append(doomedSizes, len(doomed(e.meta)))
		}
	})
	before := epochVersion(e.meta)
	r := e.run(false)
	if r.State != StateSucceeded || r.Deleted.Blobs != 5 || !e.exists(keep) {
		t.Fatalf("report = %+v", r)
	}
	for _, d := range all {
		if e.exists(d) {
			t.Errorf("blob %s survived", d)
		}
	}
	wantSteps := []Step{StepMarked, StepScanned}
	for range 3 {
		wantSteps = append(wantSteps, StepDoomed, StepViewed, StepVerified, StepDeleted)
	}
	if !slices.Equal(steps, wantSteps) || !slices.Equal(doomedSizes, []int{2, 2, 1}) {
		t.Errorf("steps %v with doomed sets %v", steps, doomedSizes)
	}
	if epochVersion(e.meta) == before {
		t.Error("the epoch did not change")
	}
}

// TestDoomBatches writes a large round's doomed set in several batches,
// the last of which changes the epoch.
func TestDoomBatches(t *testing.T) {
	e := newTestEnv(t, nil)
	n := doomBatch + 10
	for i := range n {
		e.put("garbage " + strings.Repeat("y", i))
	}
	e.clock.advance(DefaultGracePeriod + time.Second)
	var epochAtDoom, lastSeq meta.Seq
	e.setHook(func(s Step) {
		if s == StepDoomed {
			epochAtDoom, lastSeq = epochVersion(e.meta), e.meta.Stats().Seq
			if got := len(doomed(e.meta)); got != n {
				t.Errorf("doomed %d blobs, want %d", got, n)
			}
		}
	})
	seq := e.meta.Stats().Seq
	if r := e.run(false); r.Deleted.Blobs != int64(n) {
		t.Fatalf("report = %+v", r)
	}
	if lastSeq-seq != 2 || epochAtDoom != lastSeq {
		t.Errorf("dooming took %d batches, the epoch changed in batch %d; want 2, the last", lastSeq-seq, epochAtDoom-seq)
	}
}

// TestPinnedViews keeps blobs that a pinned view references, such as a
// running backup's, after the live metadata stopped referencing them.
func TestPinnedViews(t *testing.T) {
	e := newTestEnv(t, nil)
	d := e.link("backed up")
	pin := e.meta.PinView()
	e.unlink(d)
	e.clock.advance(DefaultGracePeriod + time.Second)

	r := e.run(true)
	if r.Deleted.Blobs != 0 || r.Kept.Blobs != 1 || r.PinnedViews != 1 {
		t.Errorf("dry run with a pinned view = %+v", r)
	}
	r = e.run(false)
	if r.Deleted.Blobs != 0 || r.Kept != (Count{1, 9}) || r.PinnedViews != 1 || !e.exists(d) {
		t.Fatalf("run with a pinned view = %+v", r)
	}
	pin.Release()
	if r := e.run(false); r.Deleted.Blobs != 1 || e.exists(d) {
		t.Errorf("run after the pin was released = %+v", r)
	}
}

// TestViewPinnedDuringRound keeps a doomed blob that a view pinned after
// the start batch, but before the round's own view, references.
func TestViewPinnedDuringRound(t *testing.T) {
	e := newTestEnv(t, nil)
	d := e.put("relinked")
	e.clock.advance(DefaultGracePeriod + time.Second)
	var pin meta.View
	e.setHook(func(s Step) {
		switch s {
		case StepScanned:
			// Linked after marking, before the start batch: the link is
			// allowed, and d is doomed all the same.
			e.link("relinked")
		case StepDoomed:
			// A backup pins the state with the link, then the link is
			// deleted before the round takes its view.
			pin = e.meta.PinView()
			e.unlink(d)
		}
	})
	r := e.run(false)
	if r.Deleted.Blobs != 0 || r.Kept.Blobs != 1 || !e.exists(d) {
		t.Fatalf("report = %+v", r)
	}
	pin.Release()
}

// TestViewPinnedWhileChecking keeps a doomed blob that a view pinned
// while the round checks its views references: the round reads the
// pinned views after taking its own view, so such a pin follows that
// view, which holds the same references.
func TestViewPinnedWhileChecking(t *testing.T) {
	e := newTestEnv(t, nil)
	d := e.put("relinked")
	e.clock.advance(DefaultGracePeriod + time.Second)
	var pin meta.View
	e.setHook(func(s Step) {
		switch s {
		case StepScanned:
			e.link("relinked")
		case StepViewed:
			pin = e.meta.PinView()
			e.unlink(d)
		}
	})
	e.run(false)
	defer pin.Release()
	// Every blob the pinned view references, as a backup would copy
	// them, still exists.
	refs, _, err := CheckMarker(pin, testMarker)
	if err != nil || len(refs) != 1 {
		t.Fatalf("pinned view references %v, %v", refs, err)
	}
	for _, d := range refs {
		if !e.exists(d) {
			t.Errorf("blob %s, which a pinned view references, was deleted", d)
		}
	}
}

// TestLinkBeforeStartBatch keeps a doomed blob linked between marking and
// the start batch: the round's view holds the link.
func TestLinkBeforeStartBatch(t *testing.T) {
	e := newTestEnv(t, nil)
	d := e.put("content")
	e.clock.advance(DefaultGracePeriod + time.Second)
	e.setHook(func(s Step) {
		if s == StepScanned {
			if err := link(e.meta, e.blobs, "content", nil); err != nil {
				t.Errorf("link before the start batch: %v", err)
			}
		}
	})
	r := e.run(false)
	if r.Deleted.Blobs != 0 || r.Kept.Blobs != 1 || !e.exists(d) {
		t.Fatalf("report = %+v", r)
	}
	checkReferencedExist(t, e.meta, e.blobs)
}

// TestLinkAcrossStartBatch fails a link that read its view before the
// start batch and commits after it: its precondition fails, and the
// retry sees the doomed entry. The blob is deleted, and the link works
// once the sweep is over, storing the blob again.
func TestLinkAcrossStartBatch(t *testing.T) {
	e := newTestEnv(t, nil)
	d := e.put("content")
	e.clock.advance(DefaultGracePeriod + time.Second)
	linkErr := make(chan error, 1)
	e.setHook(func(s Step) {
		if s != StepScanned {
			return
		}
		viewed, proceed := make(chan struct{}), make(chan struct{})
		go func() {
			linkErr <- link(e.meta, e.blobs, "content", func(stage string) {
				if stage == "viewed" {
					select {
					case <-viewed:
					default:
						close(viewed)
						<-proceed // the sweep commits its start batch now
					}
				}
			})
		}()
		<-viewed
		e.setHook(func(s Step) {
			if s == StepDoomed {
				close(proceed)
				// The link's commit fails, its retry sees d doomed.
				if err := <-linkErr; !errors.Is(err, ErrDoomed) {
					t.Errorf("link across the start batch = %v, want ErrDoomed", err)
				}
			}
		})
	})
	r := e.run(false)
	if r.Deleted.Blobs != 1 || e.exists(d) {
		t.Fatalf("report = %+v", r)
	}
	v := e.meta.View()
	_, linked := v.Get(linkKey(d))
	v.Release()
	if linked {
		t.Fatal("the failed link was committed")
	}
	if err := link(e.meta, e.blobs, "content", nil); err != nil || !e.exists(d) {
		t.Fatalf("link after the sweep = %v", err)
	}
	checkReferencedExist(t, e.meta, e.blobs)
}

// TestLinkDuringRound fails a link that reads its view after the start
// batch: the digest is doomed in it.
func TestLinkDuringRound(t *testing.T) {
	for _, step := range []Step{StepDoomed, StepVerified, StepDeleted} {
		t.Run(string(step), func(t *testing.T) {
			e := newTestEnv(t, nil)
			d := e.put("content")
			other := e.put("other garbage")
			e.clock.advance(DefaultGracePeriod + time.Second)
			e.setHook(func(s Step) {
				if s == step {
					if err := link(e.meta, e.blobs, "content", nil); !errors.Is(err, ErrDoomed) {
						t.Errorf("link at step %s = %v, want ErrDoomed", step, err)
					}
					// A blob the round does not doom links as usual.
					if err := link(e.meta, e.blobs, "fresh", nil); err != nil {
						t.Errorf("link of another blob at step %s = %v", step, err)
					}
				}
			})
			r := e.run(false)
			if r.Deleted.Blobs != 2 || e.exists(d) || e.exists(other) {
				t.Fatalf("report = %+v", r)
			}
			checkReferencedExist(t, e.meta, e.blobs)
		})
	}
}

// TestRefWithoutLink keeps a blob that a record references through a
// required link, written after the start batch: the reference needs no
// Guard of its own, because the link it requires keeps the blob.
func TestRefWithoutLink(t *testing.T) {
	e := newTestEnv(t, nil)
	layer := e.link("layer")
	garbage := e.put("garbage")
	e.clock.advance(DefaultGracePeriod + time.Second)
	e.setHook(func(s Step) {
		if s != StepDoomed {
			return
		}
		// A manifest-like record that references the layer, requiring
		// its link unchanged, then the link is deleted.
		v := e.meta.View()
		rec, _ := v.Get(linkKey(layer))
		v.Release()
		e.commit(func(b *meta.Batch) {
			b.Require(linkKey(layer), rec.Version)
			b.Put([]byte(refPrefix+"manifest"), []byte(layer.String()))
		})
		e.unlink(layer)
	})
	r := e.run(false)
	if !e.exists(layer) || e.exists(garbage) || r.Deleted.Blobs != 1 {
		t.Fatalf("report = %+v", r)
	}
	checkReferencedExist(t, e.meta, e.blobs)
}

// TestOneRunAtATime refuses a second run while one is in progress.
func TestOneRunAtATime(t *testing.T) {
	e := newTestEnv(t, nil)
	e.put("garbage")
	e.clock.advance(DefaultGracePeriod + time.Second)
	paused, resume := make(chan struct{}), make(chan struct{})
	e.setHook(func(s Step) {
		if s == StepScanned {
			close(paused)
			<-resume
		}
	})
	started, err := e.c.Start(RunOptions{Actor: "alice"})
	if err != nil || started.State != StateRunning || started.Actor != "alice" {
		t.Fatalf("Start = %+v, %v", started, err)
	}
	<-paused
	if _, err := e.c.Run(context.Background(), RunOptions{DryRun: true}); !errors.Is(err, ErrRunning) {
		t.Errorf("Run during a run = %v", err)
	}
	if _, err := e.c.Start(RunOptions{}); !errors.Is(err, ErrRunning) {
		t.Errorf("Start during a run = %v", err)
	}
	st := e.c.Status()
	if st.Running == nil || st.Running.Phase != PhaseSweeping || st.Running.Stored.Blobs != 1 {
		t.Errorf("status during a run = %+v", st.Running)
	}
	if got := e.metric("flint_gc_running"); got != "flint_gc_running 1" {
		t.Errorf("running metric = %q", got)
	}
	close(resume)
	if err := e.c.Wait(context.Background()); err != nil {
		t.Fatal(err)
	}
	st = e.c.Status()
	if st.Running != nil || st.Last == nil || st.Last.Deleted.Blobs != 1 || st.Last.Actor != "alice" {
		t.Errorf("status after the run = %+v", st)
	}
}

// TestCancel ends a cancelled run without deleting more, and clears its
// doomed set.
func TestCancel(t *testing.T) {
	e := newTestEnv(t, nil)
	d := e.put("garbage")
	e.clock.advance(DefaultGracePeriod + time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	e.setHook(func(s Step) {
		if s == StepVerified {
			cancel()
		}
	})
	r, err := e.c.Run(ctx, RunOptions{})
	if err != nil || r.State != StateCancelled || !e.exists(d) || len(doomed(e.meta)) != 0 {
		t.Fatalf("cancelled run = %+v, %v; doomed %v", r, err, doomed(e.meta))
	}
	e.setHook(nil)
	if r := e.run(false); r.Deleted.Blobs != 1 {
		t.Errorf("run after the cancelled one = %+v", r)
	}
}

// TestClose cancels a background run and refuses later runs.
func TestClose(t *testing.T) {
	e := newTestEnv(t, nil)
	e.put("garbage")
	e.clock.advance(DefaultGracePeriod + time.Second)
	paused := make(chan struct{})
	e.setHook(func(s Step) {
		if s == StepDoomed {
			close(paused)
			<-e.c.ctx.Done()
		}
	})
	if _, err := e.c.Start(RunOptions{}); err != nil {
		t.Fatal(err)
	}
	<-paused
	e.c.Close()
	if st := e.c.Status(); st.Last == nil || st.Last.State != StateCancelled || len(doomed(e.meta)) != 0 {
		t.Errorf("after Close: %+v, doomed %v", st.Last, doomed(e.meta))
	}
	if _, err := e.c.Start(RunOptions{}); !errors.Is(err, ErrClosed) {
		t.Errorf("Start after Close = %v", err)
	}
}

// TestDeleteFailure reports blobs it could not delete, deletes the rest,
// and clears the doomed set.
func TestDeleteFailure(t *testing.T) {
	e := newTestEnv(t, nil)
	stuck := e.put("stuck")
	gone := e.put("gone")
	e.clock.advance(DefaultGracePeriod + time.Second)
	e.fs.SetFault(func(op fsys.Op, name string) error {
		if op == fsys.OpRemove && strings.HasSuffix(name, stuck.Hex()) {
			return errors.New("injected remove failure")
		}
		return nil
	})
	r := e.run(false)
	e.fs.SetFault(nil)
	if r.State != StateFailed || r.Deleted.Blobs != 1 || len(r.Errors) != 1 || !strings.Contains(r.Errors[0], "injected") ||
		!e.exists(stuck) || e.exists(gone) || len(doomed(e.meta)) != 0 {
		t.Fatalf("report = %+v", r)
	}
	if got := e.metric(`flint_gc_runs_total{mode="sweep",result="failed"}`); !strings.HasSuffix(got, " 1") {
		t.Errorf("failure metric = %q", got)
	}
	if r := e.run(false); r.State != StateSucceeded || r.Deleted.Blobs != 1 {
		t.Errorf("retry = %+v", r)
	}
}

// TestBlobGoneMeanwhile ignores a doomed blob that is already gone.
func TestBlobGoneMeanwhile(t *testing.T) {
	e := newTestEnv(t, nil)
	d := e.put("garbage")
	e.clock.advance(DefaultGracePeriod + time.Second)
	e.setHook(func(s Step) {
		if s == StepVerified {
			if err := e.blobs.Delete(context.Background(), d); err != nil {
				t.Error(err)
			}
		}
	})
	if r := e.run(false); r.State != StateSucceeded || r.Deleted.Blobs != 0 {
		t.Errorf("report = %+v", r)
	}
}

// TestReportPersisted keeps the last report across a restart, for the
// status and the schedule; dry runs are not kept.
func TestReportPersisted(t *testing.T) {
	e := newTestEnv(t, nil)
	e.put("garbage")
	e.clock.advance(DefaultGracePeriod + time.Second)
	r := e.run(false)
	e.run(true)
	e.c.Close()
	e.meta.Close()
	e.fs = e.fs.Restart(nil)
	e.open(nil)
	st := e.c.Status()
	if st.Last == nil || st.Last.DryRun || !st.Last.Started.Equal(r.Started) || st.Last.Deleted != r.Deleted {
		t.Fatalf("status after a restart = %+v", st.Last)
	}
	if got := e.metric("flint_gc_last_success_timestamp_seconds"); got == "flint_gc_last_success_timestamp_seconds 0" {
		t.Error("the last success time was not restored")
	}
	if e.c.lastSweep != r.Started {
		t.Errorf("last sweep = %v, want %v", e.c.lastSweep, r.Started)
	}
}

// TestRecoverDoomedSet clears a doomed set an interrupted run left behind,
// so links of those blobs work again.
func TestRecoverDoomedSet(t *testing.T) {
	e := newTestEnv(t, nil)
	d := e.put("content")
	e.commit(func(b *meta.Batch) {
		b.Put(DoomedKey(d), []byte{recordFormat})
		b.Put([]byte(EpochKey), encodeEpoch(1))
	})
	if err := link(e.meta, e.blobs, "content", nil); !errors.Is(err, ErrDoomed) {
		t.Fatalf("link of a doomed blob = %v", err)
	}
	e.c.Close()
	e.meta.Close()
	e.fs = e.fs.Restart(nil)
	e.open(nil)
	if got := doomed(e.meta); len(got) != 0 {
		t.Fatalf("doomed set after New: %v", got)
	}
	if !strings.Contains(e.logs.String(), "cleared the doomed set of an interrupted garbage collection run") {
		t.Errorf("no recovery log:\n%s", e.logs)
	}
	if err := link(e.meta, e.blobs, "content", nil); err != nil {
		t.Fatalf("link after recovery = %v", err)
	}
}

func TestGuard(t *testing.T) {
	e := newTestEnv(t, nil)
	d := blob.FromBytes([]byte("x"))
	other := blob.FromBytes([]byte("y"))

	// Without an epoch, the batch requires it absent.
	v := e.meta.View()
	var b meta.Batch
	if err := Guard(v, &b, d); err != nil {
		t.Fatal(err)
	}
	v.Release()
	e.commit(func(b *meta.Batch) { b.Put([]byte(EpochKey), encodeEpoch(1)) })
	if _, err := e.meta.Commit(context.Background(), &b); !errors.Is(err, meta.ErrConflict) {
		t.Errorf("a batch guarded before the epoch existed = %v", err)
	}

	e.commit(func(b *meta.Batch) { b.Put(DoomedKey(d), []byte{recordFormat}) })
	v = e.meta.View()
	defer v.Release()
	if err := Guard(v, new(meta.Batch), other, d); !errors.Is(err, ErrDoomed) || !strings.Contains(err.Error(), d.String()) {
		t.Errorf("Guard of a doomed digest = %v", err)
	}
	if err := Guard(v, new(meta.Batch), other); err != nil {
		t.Errorf("Guard of a digest that is not doomed = %v", err)
	}
}

func TestEpochEncoding(t *testing.T) {
	for _, n := range []uint64{0, 1, 300, 1 << 40} {
		if got := decodeEpoch(encodeEpoch(n)); got != n {
			t.Errorf("epoch %d decoded as %d", n, got)
		}
	}
	for _, v := range [][]byte{nil, {1}, {2, 5}} {
		if got := decodeEpoch(v); got != 0 {
			t.Errorf("decodeEpoch(%v) = %d", v, got)
		}
	}
}
