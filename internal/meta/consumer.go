package meta

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// A consumer's checkpoint file, meta/consumers/<name>, holds
//
//	magic "flintcp1" | seq uint64 | crc uint32
//
// It is replaced atomically: written to <name>.tmp, fsynced, renamed, and
// the directory fsynced.

const (
	cpMagic = "flintcp1"
	cpSize  = 20
)

func validConsumerName(name string) bool {
	if name == "" || len(name) > 64 {
		return false
	}
	for i, c := range name {
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case (c == '-' || c == '_' || c == '.') && i > 0:
		default:
			return false
		}
	}
	return true
}

func (s *store) loadConsumers() (map[string]Seq, error) {
	ents, err := s.fs.ReadDir(s.consDir)
	if err != nil {
		return nil, err
	}
	cons := map[string]Seq{}
	for _, e := range ents {
		name := e.Name()
		path := filepath.Join(s.consDir, name)
		if strings.HasSuffix(name, ".tmp") {
			if err := s.fs.Remove(path); err != nil {
				return nil, err
			}
			continue
		}
		if !validConsumerName(name) {
			continue
		}
		data, err := s.readFile(path)
		if err != nil {
			return nil, err
		}
		if len(data) != cpSize || string(data[:8]) != cpMagic || crc32.Checksum(data[:16], castagnoli) != binary.LittleEndian.Uint32(data[16:]) {
			return nil, &CorruptionError{Path: path, Reason: "bad consumer checkpoint"}
		}
		cons[name] = Seq(binary.LittleEndian.Uint64(data[8:]))
	}
	return cons, nil
}

func (s *store) writeCheckpoint(name string, seq Seq) error {
	data := append([]byte(cpMagic), binary.LittleEndian.AppendUint64(nil, uint64(seq))...)
	data = binary.LittleEndian.AppendUint32(data, crc32.Checksum(data, castagnoli))
	final := filepath.Join(s.consDir, name)
	tmp := final + ".tmp"
	f, err := s.fs.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
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
		err = s.fs.SyncDir(s.consDir)
	}
	return err
}

func (s *store) RegisterConsumer(name string) (Seq, error) {
	if !validConsumerName(name) {
		return 0, fmt.Errorf("meta: invalid consumer name %q", name)
	}
	s.consMu.Lock()
	defer s.consMu.Unlock()
	s.mu.Lock()
	cp, ok := s.consumers[name]
	closed := s.closed
	s.mu.Unlock()
	switch {
	case closed:
		return 0, ErrClosed
	case ok:
		return cp, nil
	}
	// Hold the new checkpoint as a lease while it is written, so retention
	// cannot delete what the consumer starts from.
	s.mu.Lock()
	cp = s.state.Load().seq
	l := &lease{after: cp}
	s.leases[l] = struct{}{}
	s.mu.Unlock()
	defer s.releaseLease(l)
	if err := s.writeCheckpoint(name, cp); err != nil {
		return 0, err
	}
	s.mu.Lock()
	s.consumers[name] = cp
	s.mu.Unlock()
	return cp, nil
}

func (s *store) UnregisterConsumer(name string) error {
	s.consMu.Lock()
	defer s.consMu.Unlock()
	s.mu.Lock()
	_, ok := s.consumers[name]
	closed := s.closed
	s.mu.Unlock()
	switch {
	case closed:
		return ErrClosed
	case !ok:
		return ErrUnknownConsumer
	}
	// The removal must be durable before retention stops counting the
	// consumer, or a crash could bring it back with its segments gone.
	if err := s.fs.Remove(filepath.Join(s.consDir, name)); err != nil {
		return err
	}
	if err := s.fs.SyncDir(s.consDir); err != nil {
		return err
	}
	s.mu.Lock()
	delete(s.consumers, name)
	s.mu.Unlock()
	s.kickMaintenance()
	return nil
}

func (s *store) Checkpoint(name string, seq Seq) error {
	s.consMu.Lock()
	defer s.consMu.Unlock()
	s.mu.Lock()
	cp, ok := s.consumers[name]
	closed := s.closed
	s.mu.Unlock()
	switch {
	case closed:
		return ErrClosed
	case !ok:
		return ErrUnknownConsumer
	case seq < cp:
		return fmt.Errorf("meta: checkpoint of %q would move back from %d to %d", name, cp, seq)
	case seq > s.state.Load().seq:
		return fmt.Errorf("meta: checkpoint of %q at %d is past the latest batch %d", name, seq, s.state.Load().seq)
	case seq == cp:
		return nil
	}
	if err := s.writeCheckpoint(name, seq); err != nil {
		return err
	}
	s.mu.Lock()
	s.consumers[name] = seq
	s.mu.Unlock()
	s.kickMaintenance()
	return nil
}

// lease keeps the log after a sequence number from being deleted while a
// reader needs it.
type lease struct{ after Seq }

func (s *store) releaseLease(l *lease) {
	s.mu.Lock()
	delete(s.leases, l)
	s.mu.Unlock()
}

func (s *store) ReadLog(ctx context.Context, after Seq, fn func(Entry) error) error {
	end := s.state.Load().seq
	if after >= end {
		return nil
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return ErrClosed
	}
	segs := append([]segment(nil), s.segs...)
	l := &lease{after: after}
	s.leases[l] = struct{}{}
	s.mu.Unlock()
	defer s.releaseLease(l)

	i := sort.Search(len(segs), func(i int) bool { return segs[i].first > after+1 }) - 1
	if i < 0 {
		return fmt.Errorf("%w: batch %d", ErrCompacted, after+1)
	}
	expect := segs[i].first
	for ; i < len(segs); i++ {
		if segs[i].first != expect {
			return &CorruptionError{Path: segs[i].path, Reason: fmt.Sprintf("gap in the log: segment starts at %d, want %d", segs[i].first, expect)}
		}
		lr, err := s.openLogReader(segs[i])
		if err != nil {
			return err
		}
		for {
			hd, body, err := lr.next()
			if err == io.EOF {
				break
			}
			if err != nil {
				lr.close()
				return err
			}
			if hd.seq != expect {
				lr.close()
				return &CorruptionError{Path: lr.path, Offset: lr.off, Reason: fmt.Sprintf("record %d out of sequence, want %d", hd.seq, expect)}
			}
			expect++
			if hd.seq <= after {
				continue
			}
			if err := ctx.Err(); err != nil {
				lr.close()
				return err
			}
			e, err := decodeBody(append([]byte(nil), body...))
			if err != nil {
				lr.close()
				return &CorruptionError{Path: lr.path, Offset: lr.off, Reason: err.Error()}
			}
			if err := fn(e); err != nil {
				lr.close()
				return err
			}
			if hd.seq == end {
				lr.close()
				return nil
			}
		}
		lr.close()
	}
	return &CorruptionError{Path: s.walDir, Reason: fmt.Sprintf("log ends at %d, before batch %d", expect-1, end)}
}

// retain deletes the log segments that the latest snapshot, every
// consumer, and every running reader are past. The active segment is never
// deleted.
func (s *store) retain() error {
	s.mu.Lock()
	floor := s.snapSeq
	for _, cp := range s.consumers {
		floor = min(floor, cp)
	}
	for l := range s.leases {
		floor = min(floor, l.after)
	}
	n := 0
	for n < len(s.segs)-1 && s.segs[n+1].first-1 <= floor {
		n++
	}
	doomed := append([]segment(nil), s.segs[:n]...)
	s.segs = append(s.segs[:0:0], s.segs[n:]...)
	s.mu.Unlock()
	if n == 0 {
		return nil
	}
	var errs []error
	for _, sg := range doomed {
		if err := s.fs.Remove(sg.path); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, err)
		}
	}
	if err := s.fs.SyncDir(s.walDir); err != nil {
		errs = append(errs, err)
	}
	if err := errors.Join(errs...); err != nil {
		s.log.Warn("meta: deleting old log segments", "err", err)
		return err
	}
	return nil
}
