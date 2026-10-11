package audit

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/terrabyteian/flint/internal/meta"
)

// Filter selects audit records. The zero Filter selects every record.
type Filter struct {
	// After selects records of batches after this sequence number.
	After meta.Seq
	// Since and Until, if set, select records committed at or after
	// Since and before Until.
	Since, Until time.Time
	// Actor, if set, selects records whose actor is this principal: a
	// user name matches the user's changes, made with a password or with
	// any of the user's API tokens; meta.ActorSystem and
	// meta.ActorAnonymous match themselves.
	Actor string
	// Action, if set, selects records whose action is this action or
	// starts with it followed by ".": "oci.manifest" selects
	// "oci.manifest.push" and "oci.manifest.delete".
	Action string
	// Target, if set, selects records whose target starts with it.
	Target string
}

// Match reports whether r passes f.
func (f *Filter) Match(r *Record) bool {
	switch {
	case r.Seq <= f.After,
		!f.Since.IsZero() && r.Time.Before(f.Since),
		!f.Until.IsZero() && !r.Time.Before(f.Until),
		f.Actor != "" && r.Actor != f.Actor && !strings.HasPrefix(r.Actor, f.Actor+" ("),
		f.Action != "" && r.Action != f.Action && !strings.HasPrefix(r.Action, f.Action+"."),
		!strings.HasPrefix(r.Target, f.Target):
		return false
	}
	return true
}

// Scan calls fn, in sequence order, for each durable record that f
// selects, until fn returns false. The record's keys are valid only
// during the call. Records written after Scan starts may be left out.
//
// Segments are skipped by their file modification times and first
// records' commit times, which assumes the server's clock does not go
// back; a record committed while it did may be left out of a time range.
func (l *Log) Scan(ctx context.Context, f Filter, fn func(*Record) bool) error {
	l.mu.Lock()
	segs := slices.Clone(l.segs)
	l.mu.Unlock()
	// Start in the segment that holds the batch after f.After.
	i, found := slices.BinarySearchFunc(segs, f.After+1, func(sg segment, s meta.Seq) int {
		return cmp.Compare(sg.first, s)
	})
	if !found && i > 0 {
		i--
	}
	for j, sg := range segs[i:] {
		active := i+j == len(segs)-1
		if !f.Since.IsZero() && !active {
			// A sealed segment was last written after its newest record
			// was committed.
			info, err := l.fs.Stat(sg.path)
			if errors.Is(err, os.ErrNotExist) {
				continue // deleted by retention meanwhile
			}
			if err != nil {
				return err
			}
			if info.ModTime().Before(f.Since) {
				continue
			}
		}
		more, err := l.scanSegment(ctx, sg, &f, fn)
		if err != nil || !more {
			return err
		}
	}
	return nil
}

// scanSegment scans segment sg up to its durable size. It returns false
// once fn has asked to stop or no later segment can match.
func (l *Log) scanSegment(ctx context.Context, sg segment, f *Filter, fn func(*Record) bool) (bool, error) {
	file, err := l.fs.Open(sg.path)
	if errors.Is(err, os.ErrNotExist) {
		return true, nil // deleted by retention meanwhile
	}
	if err != nil {
		return false, err
	}
	defer file.Close()
	var hdr [segHeaderSize]byte
	if _, err := io.ReadFull(file, hdr[:]); err != nil {
		return false, &CorruptionError{Path: sg.path, Reason: fmt.Sprintf("reading the header: %v", err)}
	}
	if first, err := parseSegHeader(hdr[:]); err != nil || first != sg.first {
		return false, &CorruptionError{Path: sg.path, Reason: "bad segment header"}
	}
	rr := newRecordReader(file, sg.size)
	for n := 0; ; n++ {
		at := rr.off
		rec, err := rr.next()
		if err == io.EOF {
			return true, nil
		}
		if errors.Is(err, errBadRecord) {
			return false, &CorruptionError{Path: sg.path, Offset: at, Reason: err.Error()}
		}
		if err != nil {
			return false, err
		}
		if n%256 == 0 {
			if err := ctx.Err(); err != nil {
				return false, err
			}
		}
		if !f.Until.IsZero() && !rec.Time.Before(f.Until) && n == 0 {
			// This segment, and every later one, starts at or after Until.
			return false, nil
		}
		if f.Match(&rec) && !fn(&rec) {
			return false, nil
		}
	}
}
