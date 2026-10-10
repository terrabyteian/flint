package meta

import (
	"bufio"
	"cmp"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math/rand/v2"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/terrabyteian/flint/internal/fsys"
)

// segment is a log segment file.
type segment struct {
	first Seq // sequence number of its first record
	path  string
	size  int64
}

func segName(first Seq) string { return fmt.Sprintf("%020d.log", first) }

// parseSeqName parses "<20 digits><suffix>".
func parseSeqName(name, suffix string) (Seq, bool) {
	digits, ok := strings.CutSuffix(name, suffix)
	if !ok || len(digits) != 20 {
		return 0, false
	}
	n, err := strconv.ParseUint(digits, 10, 64)
	if err != nil {
		return 0, false
	}
	return Seq(n), true
}

func (s *store) listSegments() ([]segment, error) {
	ents, err := s.fs.ReadDir(s.walDir)
	if err != nil {
		return nil, err
	}
	var segs []segment
	for _, e := range ents {
		first, ok := parseSeqName(e.Name(), ".log")
		if !ok || e.IsDir() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			return nil, err
		}
		segs = append(segs, segment{first: first, path: filepath.Join(s.walDir, e.Name()), size: info.Size()})
	}
	slices.SortFunc(segs, func(a, b segment) int { return cmp.Compare(a.first, b.first) })
	return segs, nil
}

func (s *store) readFile(path string) ([]byte, error) {
	f, err := s.fs.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(f)
}

// createSegment creates a durable, empty segment whose first record will be first.
func (s *store) createSegment(first Seq) (fsys.File, segment, uint32, error) {
	path := filepath.Join(s.walDir, segName(first))
	f, err := s.fs.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|os.O_APPEND, 0o644)
	if err != nil {
		return nil, segment{}, 0, err
	}
	salt := rand.Uint32()
	_, err = f.Write(appendSegHeader(nil, segHeader{first: first, salt: salt}))
	if err == nil {
		err = f.Sync()
	}
	if err == nil {
		err = s.fs.SyncDir(s.walDir)
	}
	if err != nil {
		f.Close()
		return nil, segment{}, 0, err
	}
	return f, segment{first: first, path: path, size: segHeaderSize}, salt, nil
}

// recovered is the result of replaying the log at startup.
type recovered struct {
	segs   []segment // every segment on disk, in order
	last   Seq       // last sequence number in the log
	salt   uint32    // salt of the last segment
	active bool      // whether segs' last segment can take appends
}

// recoverLog validates the log from the segment holding snap+1 to the end,
// applies every record after snap to x, and repairs a torn final group
// commit. acked is the highest sequence number known to have been
// acknowledged by durable state other than the log (the snapshot and
// consumer checkpoints). floor is the lowest sequence number some reader
// still needs. See the package documentation for the rules.
func (s *store) recoverLog(x *txn, snap, acked, floor Seq) (recovered, error) {
	segs, err := s.listSegments()
	if err != nil {
		return recovered{}, err
	}
	if len(segs) == 0 {
		if snap > 0 {
			return recovered{}, &CorruptionError{Path: s.walDir, Reason: fmt.Sprintf("no log segments, but the snapshot is at %d", snap)}
		}
		return recovered{}, nil
	}
	if segs[0].first > floor+1 {
		return recovered{}, &CorruptionError{Path: segs[0].path, Reason: fmt.Sprintf("log starts at %d, but batch %d is still needed", segs[0].first, floor+1)}
	}
	// Replay starts at the last segment holding snap+1.
	start := 0
	for i, sg := range segs {
		if sg.first <= snap+1 {
			start = i
		}
	}
	expect := segs[start].first
	var r recovered
	for i := start; i < len(segs); i++ {
		sg := segs[i]
		final := i == len(segs)-1
		if sg.first != expect {
			return recovered{}, &CorruptionError{Path: sg.path, Reason: fmt.Sprintf("gap in the log: segment starts at %d, want %d", sg.first, expect)}
		}
		data, err := s.readFile(sg.path)
		if err != nil {
			return recovered{}, err
		}
		h, herr := parseSegHeader(data)
		if herr != nil {
			// A segment's header is synced before any record is written to
			// it, so a bad header on a segment holding no more than a header
			// is a torn segment creation.
			if final && len(data) <= segHeaderSize {
				s.log.Warn("meta: removing torn log segment", "path", sg.path, "size", len(data))
				if err := s.fs.Remove(sg.path); err != nil {
					return recovered{}, err
				}
				if err := s.fs.SyncDir(s.walDir); err != nil {
					return recovered{}, err
				}
				segs = segs[:i]
				break
			}
			return recovered{}, &CorruptionError{Path: sg.path, Reason: herr.Error()}
		}
		if h.first != sg.first {
			return recovered{}, &CorruptionError{Path: sg.path, Reason: fmt.Sprintf("segment header says it starts at %d", h.first)}
		}
		end, next, err := scanSegment(sg.path, data, h, func(hd recHead, body []byte) error {
			if hd.seq <= snap {
				return nil
			}
			e, err := decodeBody(body)
			if err != nil {
				return err
			}
			applyOps(x, e.Ops, hd.seq)
			return nil
		})
		if err != nil {
			return recovered{}, err
		}
		if end < int64(len(data)) {
			if !final {
				return recovered{}, &CorruptionError{Path: sg.path, Offset: end, Reason: fmt.Sprintf("bad record %d in a segment that later segments follow", next)}
			}
			if next <= acked {
				return recovered{}, &CorruptionError{Path: sg.path, Offset: end, Reason: fmt.Sprintf("bad record %d, which a snapshot or consumer checkpoint shows was acknowledged", next)}
			}
			if off, ok := laterGroup(data, h.salt, end, next); ok {
				return recovered{}, &CorruptionError{Path: sg.path, Offset: end, Reason: fmt.Sprintf("bad record %d is followed by an intact record of a later group commit at offset %d", next, off)}
			}
			s.log.Warn("meta: discarding torn final group commit", "path", sg.path, "offset", end, "bytes", int64(len(data))-end, "seq", next)
			if err := s.truncate(sg.path, end); err != nil {
				return recovered{}, err
			}
		}
		segs[i].size = end
		expect = next
		r.salt = h.salt
		r.active = true
	}
	r.segs = segs
	r.last = expect - 1
	if r.last < snap {
		return recovered{}, &CorruptionError{Path: s.walDir, Reason: fmt.Sprintf("log ends at %d, before the snapshot at %d", r.last, snap)}
	}
	return r, nil
}

func (s *store) truncate(path string, size int64) error {
	f, err := s.fs.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	err = f.Truncate(size)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

// scanSegment validates the records of a segment, calling fn for each in
// order. It returns the offset just past the last intact record and the
// sequence number expected next. If the offset is short of len(data), the
// rest does not start with an intact record. An intact record out of
// sequence, or one that does not decode, is a corruption error.
func scanSegment(path string, data []byte, h segHeader, fn func(recHead, []byte) error) (int64, Seq, error) {
	off := segHeaderSize
	expect := h.first
	for off < len(data) {
		rec, ok := recordAt(data, off, h.salt)
		if !ok {
			break
		}
		hd, ok := parseHead(rec[frameSize:])
		if !ok {
			return 0, 0, &CorruptionError{Path: path, Offset: int64(off), Reason: "intact record with an unreadable header"}
		}
		if hd.seq != expect {
			return 0, 0, &CorruptionError{Path: path, Offset: int64(off), Reason: fmt.Sprintf("record %d out of sequence, want %d", hd.seq, expect)}
		}
		if err := fn(hd, rec[frameSize:]); err != nil {
			return 0, 0, &CorruptionError{Path: path, Offset: int64(off), Reason: err.Error()}
		}
		off += len(rec)
		expect++
	}
	return int64(off), expect, nil
}

// recordAt returns the intact record at off, if there is one.
func recordAt(data []byte, off int, salt uint32) ([]byte, bool) {
	if len(data)-off < frameSize {
		return nil, false
	}
	n := frameLen(data[off:])
	if n < 0 || n > len(data)-off-frameSize {
		return nil, false
	}
	rec := data[off : off+frameSize+n]
	if !checkRecord(salt, rec) {
		return nil, false
	}
	return rec, true
}

// laterGroup reports whether an intact record of a group commit after the
// one holding record next appears at or after off, or an intact record
// that cannot belong to the final group commit at all. It returns the
// offset of the first such record.
//
// Record next belongs to a group that starts at or before next, so any
// record whose group starts after next was written by a later group
// commit, which the writer starts only after the earlier one's fsync
// succeeded.
func laterGroup(data []byte, salt uint32, off int64, next Seq) (int64, bool) {
	for p := int(off) + 1; p+frameSize+minBodySize <= len(data); p++ {
		// Cheap filters first; the checksum is the expensive part.
		if frameLen(data[p:]) < 0 {
			continue
		}
		hd, ok := parseHead(data[p+frameSize:])
		if !ok {
			continue
		}
		rec, ok := recordAt(data, p, salt)
		if !ok {
			continue
		}
		if hd.group > next || hd.seq < next {
			return int64(p), true
		}
		p += len(rec) - 1
	}
	return 0, false
}

func applyOps(x *txn, ops []Op, seq Seq) {
	for _, op := range ops {
		if op.Delete {
			x.delete(op.Key)
		} else {
			x.put(op.Key, op.Value, seq)
		}
	}
}

// logReader streams the records of one segment.
type logReader struct {
	path string
	r    *bufio.Reader
	f    io.Closer
	h    segHeader
	off  int64
	buf  []byte
}

func (s *store) openLogReader(sg segment) (*logReader, error) {
	f, err := s.fs.Open(sg.path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%w: segment %s", ErrCompacted, sg.path)
	}
	if err != nil {
		return nil, err
	}
	lr := &logReader{path: sg.path, r: bufio.NewReaderSize(f, 256<<10), f: f}
	var hdr [segHeaderSize]byte
	if _, err := io.ReadFull(lr.r, hdr[:]); err != nil {
		f.Close()
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			return nil, &CorruptionError{Path: sg.path, Reason: "short segment header"}
		}
		return nil, err
	}
	if lr.h, err = parseSegHeader(hdr[:]); err != nil {
		f.Close()
		return nil, &CorruptionError{Path: sg.path, Reason: err.Error()}
	}
	if lr.h.first != sg.first {
		f.Close()
		return nil, &CorruptionError{Path: sg.path, Reason: fmt.Sprintf("segment header says it starts at %d", lr.h.first)}
	}
	lr.off = segHeaderSize
	return lr, nil
}

// next returns the next record's body, which is valid until the next call,
// or io.EOF at a clean end of the segment.
func (lr *logReader) next() (recHead, []byte, error) {
	var frame [frameSize]byte
	if _, err := io.ReadFull(lr.r, frame[:]); err != nil {
		if err == io.EOF {
			return recHead{}, nil, io.EOF
		}
		if err != io.ErrUnexpectedEOF {
			return recHead{}, nil, err
		}
		return recHead{}, nil, lr.corrupt("truncated record frame")
	}
	n := frameLen(frame[:])
	if n < 0 {
		return recHead{}, nil, lr.corrupt("bad record length")
	}
	if cap(lr.buf) < frameSize+n {
		lr.buf = make([]byte, frameSize+n)
	}
	rec := lr.buf[:frameSize+n]
	copy(rec, frame[:])
	if _, err := io.ReadFull(lr.r, rec[frameSize:]); err != nil {
		if err != io.EOF && err != io.ErrUnexpectedEOF {
			return recHead{}, nil, err
		}
		return recHead{}, nil, lr.corrupt("truncated record")
	}
	if !checkRecord(lr.h.salt, rec) {
		return recHead{}, nil, lr.corrupt("record checksum mismatch")
	}
	hd, ok := parseHead(rec[frameSize:])
	if !ok {
		return recHead{}, nil, lr.corrupt("unreadable record header")
	}
	lr.off += int64(len(rec))
	return hd, rec[frameSize:], nil
}

func (lr *logReader) corrupt(reason string) error {
	return &CorruptionError{Path: lr.path, Offset: lr.off, Reason: reason}
}

func (lr *logReader) close() { lr.f.Close() }
