package meta

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Snapshot file format:
//
//	header: magic "flintsnp" | format uint32 | reserved uint32 | seq uint64 | crc uint32
//	blocks: length uint32 | crc uint32 | entries (length bytes), ending with an empty block
//	trailer: entry count uint64 | crc uint32
//
// Each entry is uvarint(length) followed by the index's own entry encoding
// (key, version, value), in strictly increasing key order. Every crc is
// CRC-32C of the bytes before it in the same part.

const (
	snapMagic      = "flintsnp"
	snapFormat     = 1
	snapHeaderSize = 28
	snapBlockSize  = 256 << 10
	// A block is flushed once it reaches snapBlockSize, so it holds at most
	// that much plus one entry: a length prefix, a key length, a key and
	// value that fit in one record body, and a version.
	maxSnapEntry = 2*binary.MaxVarintLen64 + maxBodySize + 8
	maxSnapBlock = snapBlockSize + maxSnapEntry
)

func snapName(seq Seq) string { return fmt.Sprintf("%020d.snap", seq) }

var errStopped = errors.New("meta: snapshot stopped by Close")

// writeSnapshot writes t as of seq to w. It returns errStopped if stop is
// closed first.
func writeSnapshot(w io.Writer, t tree, seq Seq, stop <-chan struct{}) error {
	hdr := make([]byte, 0, snapHeaderSize)
	hdr = append(hdr, snapMagic...)
	hdr = binary.LittleEndian.AppendUint32(hdr, snapFormat)
	hdr = binary.LittleEndian.AppendUint32(hdr, 0)
	hdr = binary.LittleEndian.AppendUint64(hdr, uint64(seq))
	hdr = binary.LittleEndian.AppendUint32(hdr, crc32.Checksum(hdr, castagnoli))
	if _, err := w.Write(hdr); err != nil {
		return err
	}
	block := make([]byte, frameSize, snapBlockSize+frameSize)
	flush := func() error {
		n := len(block) - frameSize
		binary.LittleEndian.PutUint32(block, uint32(n))
		binary.LittleEndian.PutUint32(block[4:], crc32.Checksum(block[frameSize:], castagnoli))
		_, err := w.Write(block)
		block = block[:frameSize]
		return err
	}
	var count uint64
	var err error
	t.root.walk(func(e []byte) bool {
		block = binary.AppendUvarint(block, uint64(len(e)))
		block = append(block, e...)
		count++
		if len(block) >= snapBlockSize {
			select {
			case <-stop:
				err = errStopped
				return false
			default:
			}
			err = flush()
		}
		return err == nil
	})
	if err != nil {
		return err
	}
	if len(block) > frameSize {
		if err := flush(); err != nil {
			return err
		}
	}
	if err := flush(); err != nil { // the empty end block
		return err
	}
	tr := binary.LittleEndian.AppendUint64(nil, count)
	tr = binary.LittleEndian.AppendUint32(tr, crc32.Checksum(tr, castagnoli))
	_, err = w.Write(tr)
	return err
}

// walk calls fn with each encoded entry in order until fn returns false.
func (n *node) walk(fn func(e []byte) bool) bool {
	if n.isLeaf() {
		for i := range n.len() {
			if !fn(n.entry(i)) {
				return false
			}
		}
		return true
	}
	for _, c := range n.children {
		if !c.walk(fn) {
			return false
		}
	}
	return true
}

// readSnapshot loads the snapshot at path, which must be for seq.
func (s *store) readSnapshot(path string, seq Seq) (tree, error) {
	f, err := s.fs.Open(path)
	if err != nil {
		return tree{}, err
	}
	defer f.Close()
	t, _, err := decodeSnapshot(f, path, seq, true)
	return t, err
}

// decodeSnapshot reads and validates a snapshot from r, naming path in
// its errors. With check set, the snapshot must be for seq.
func decodeSnapshot(rd io.Reader, path string, seq Seq, check bool) (tree, Seq, error) {
	r := bufio.NewReaderSize(rd, 1<<20)
	var off int64
	var ioErr error
	bad := func(reason string) error {
		if ioErr != nil {
			return ioErr
		}
		return &CorruptionError{Path: path, Offset: off, Reason: reason}
	}
	readFull := func(p []byte) error {
		_, err := io.ReadFull(r, p)
		if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
			ioErr = err
		}
		return err
	}
	hdr := make([]byte, snapHeaderSize)
	if err := readFull(hdr); err != nil {
		return tree{}, 0, bad("short snapshot header")
	}
	got := Seq(binary.LittleEndian.Uint64(hdr[16:]))
	switch {
	case string(hdr[:8]) != snapMagic:
		return tree{}, 0, bad("bad snapshot magic")
	case crc32.Checksum(hdr[:24], castagnoli) != binary.LittleEndian.Uint32(hdr[24:]):
		return tree{}, 0, bad("snapshot header checksum mismatch")
	case binary.LittleEndian.Uint32(hdr[8:]) != snapFormat:
		return tree{}, 0, bad("unsupported snapshot format")
	case check && got != seq:
		return tree{}, 0, bad(fmt.Sprintf("snapshot header says seq %d", got))
	}
	off = snapHeaderSize
	b := newBuilder()
	var buf []byte
	for {
		var frame [frameSize]byte
		if err := readFull(frame[:]); err != nil {
			return tree{}, 0, bad("truncated snapshot block")
		}
		n := int(binary.LittleEndian.Uint32(frame[:]))
		if n > maxSnapBlock {
			return tree{}, 0, bad("bad snapshot block length")
		}
		if cap(buf) < n {
			buf = make([]byte, n)
		}
		buf = buf[:n]
		if err := readFull(buf); err != nil {
			return tree{}, 0, bad("truncated snapshot block")
		}
		if crc32.Checksum(buf, castagnoli) != binary.LittleEndian.Uint32(frame[4:]) {
			return tree{}, 0, bad("snapshot block checksum mismatch")
		}
		if n == 0 {
			break
		}
		for p := buf; len(p) > 0; {
			l, w := binary.Uvarint(p)
			if w <= 0 || l > uint64(len(p)-w) || !b.addEntry(p[w:w+int(l)]) {
				return tree{}, 0, bad("bad snapshot entry")
			}
			p = p[w+int(l):]
		}
		off += int64(frameSize + n)
	}
	off += frameSize
	tr := make([]byte, 12)
	if err := readFull(tr); err != nil {
		return tree{}, 0, bad("truncated snapshot trailer")
	}
	if crc32.Checksum(tr[:8], castagnoli) != binary.LittleEndian.Uint32(tr[8:]) || binary.LittleEndian.Uint64(tr) != uint64(b.count) {
		return tree{}, 0, bad("snapshot trailer mismatch")
	}
	if _, err := r.ReadByte(); err != io.EOF {
		if err != nil {
			return tree{}, 0, err
		}
		return tree{}, 0, bad("trailing bytes after snapshot")
	}
	return b.finish(), got, nil
}

type snapFile struct {
	seq  Seq
	path string
}

// listSnapshots returns the snapshots, newest first, and removes leftover
// temporary files.
func (s *store) listSnapshots() ([]snapFile, error) {
	ents, err := s.fs.ReadDir(s.snapDir)
	if err != nil {
		return nil, err
	}
	var snaps []snapFile
	for _, e := range ents {
		name := e.Name()
		if strings.HasSuffix(name, ".tmp") {
			if err := s.fs.Remove(filepath.Join(s.snapDir, name)); err != nil {
				return nil, err
			}
			continue
		}
		if seq, ok := parseSeqName(name, ".snap"); ok {
			snaps = append([]snapFile{{seq: seq, path: filepath.Join(s.snapDir, name)}}, snaps...)
		}
	}
	return snaps, nil
}

// loadSnapshot loads the newest valid snapshot. A snapshot that fails
// validation is skipped with a warning; the caller reports it if the log
// cannot make up for it.
func (s *store) loadSnapshot() (tree, Seq, error) {
	snaps, err := s.listSnapshots()
	if err != nil {
		return tree{}, 0, err
	}
	var skipped error
	for _, sn := range snaps {
		t, err := s.readSnapshot(sn.path, sn.seq)
		if err == nil {
			return t, sn.seq, skipped
		}
		if !errors.Is(err, ErrCorrupt) {
			return tree{}, 0, err
		}
		s.log.Warn("meta: skipping invalid snapshot", "path", sn.path, "err", err)
		skipped = errors.Join(skipped, err)
	}
	return emptyTree(), 0, skipped
}

// snapshot writes a snapshot of the latest fsynced state and then deletes
// what it makes unnecessary.
func (s *store) snapshot() error {
	s.snapMu.Lock()
	defer s.snapMu.Unlock()
	p := s.state.Load()
	s.mu.Lock()
	have := s.snapSeq
	s.mu.Unlock()
	if p.seq > have {
		if err := s.writeSnapshotFile(p.t, p.seq); err != nil {
			if !errors.Is(err, errStopped) {
				s.snapErrors.Add(1)
				s.log.Error("meta: snapshot failed", "seq", p.seq, "err", err)
			}
			return err
		}
		s.snapshots.Add(1)
		s.mu.Lock()
		s.snapSeq = p.seq
		s.mu.Unlock()
		s.removeOldSnapshots(p.seq)
	}
	return s.retain()
}

func (s *store) writeSnapshotFile(t tree, seq Seq) error {
	final := filepath.Join(s.snapDir, snapName(seq))
	tmp := final + ".tmp"
	f, err := s.fs.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	w := bufio.NewWriterSize(f, 1<<20)
	err = writeSnapshot(w, t, seq, s.stop)
	if err == nil {
		err = w.Flush()
	}
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = s.fs.Rename(tmp, final)
	}
	if err == nil {
		err = s.fs.SyncDir(s.snapDir)
	}
	if err != nil {
		s.fs.Remove(tmp)
	}
	return err
}

// removeOldSnapshots deletes snapshots older than keep. Failures are only
// logged: an old snapshot left behind is harmless.
func (s *store) removeOldSnapshots(keep Seq) {
	snaps, err := s.listSnapshots()
	if err != nil {
		s.log.Warn("meta: listing snapshots", "err", err)
		return
	}
	removed := false
	for _, sn := range snaps {
		if sn.seq < keep {
			if err := s.fs.Remove(sn.path); err != nil {
				s.log.Warn("meta: removing old snapshot", "path", sn.path, "err", err)
				continue
			}
			removed = true
		}
	}
	if removed {
		if err := s.fs.SyncDir(s.snapDir); err != nil {
			s.log.Warn("meta: syncing snapshot directory", "err", err)
		}
	}
}
