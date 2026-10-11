package meta

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/terrabyteian/flint/internal/fsys"
)

// errForeignView means a view did not come from this package.
var errForeignView = errors.New("meta: view is not from a meta store or snapshot")

// WriteSnapshot writes v to w in the snapshot file format the store uses
// for its own snapshots, so a backup holds the store's state as of v.
// ReadSnapshot reads it back, and Restore turns it into a store.
func WriteSnapshot(w io.Writer, v View) error {
	vv, ok := v.(*view)
	if !ok {
		return errForeignView
	}
	return writeSnapshot(w, vv.t, vv.seq, nil)
}

// ReadSnapshot reads a snapshot written by WriteSnapshot, validating every
// checksum, and returns a view of its state, held in memory. name labels
// corruption errors. Releasing the view frees nothing; it is garbage
// collected like any value.
func ReadSnapshot(r io.Reader, name string) (View, error) {
	t, seq, err := decodeSnapshot(r, name, 0, false)
	if err != nil {
		return nil, err
	}
	return &view{t: t, seq: seq}, nil
}

// Restore creates a store in dir whose state is exactly v's, including
// every record's version, as Open will load it: it writes v as the
// store's snapshot and starts an empty log at the sequence number after
// v's, making each step durable. dir must not hold a store yet. A Restore
// that fails part way leaves files behind, which the caller removes before
// trying again. Only opts.FS is used.
func Restore(dir string, v View, opts Options) error {
	vv, ok := v.(*view)
	if !ok {
		return errForeignView
	}
	s := &store{
		fs:      opts.FS,
		walDir:  filepath.Join(dir, "wal"),
		snapDir: filepath.Join(dir, "snapshots"),
		consDir: filepath.Join(dir, "consumers"),
		stop:    make(chan struct{}),
	}
	if s.fs == nil {
		s.fs = fsys.OS
	}
	for _, d := range []string{s.walDir, s.snapDir, s.consDir} {
		ents, err := s.fs.ReadDir(d)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if len(ents) > 0 {
			return fmt.Errorf("meta: %s is not empty; restore needs a new store", d)
		}
	}
	if err := s.mkdirs(dir); err != nil {
		return err
	}
	if err := s.writeSnapshotFile(vv.t, vv.seq); err != nil {
		return err
	}
	f, _, _, err := s.createSegment(vv.seq + 1)
	if err != nil {
		return err
	}
	return f.Close()
}
