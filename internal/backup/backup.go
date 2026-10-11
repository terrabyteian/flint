// Package backup writes consistent, incremental backups of a flint data
// directory to another directory, verifies them, and restores them into a
// new data directory. docs/backup.md describes how to operate it.
//
// # Layout
//
// A backup directory holds any number of backups that share one
// content-addressed blob store:
//
//	LOCK                         flock held while a backup writes here
//	blobs/sha256/<2 hex>/<64 hex> every blob of every backup, stored once
//	uploads/                     blob copies in progress
//	backups/<id>/metadata.snap   the metadata store's state, in its snapshot format
//	backups/<id>/blobs           the blobs the backup needs: "<digest> <size>" lines
//	backups/<id>/backup.json     the completion record, written last
//
// The blob store is the one the server uses (blob.NewFS), so a copied blob
// is verified against its digest and made durable before it counts, and a
// blob already present from an earlier backup is not copied again.
//
// # Consistency
//
// A backup pins a metadata view with the garbage collector
// (meta.Store.PinView) and holds it until it finishes, so no blob the view
// references is deleted while the backup runs. It writes the view as the
// metadata snapshot, then copies every blob in the data directory that the
// backup directory lacks: every blob the view references was committed
// before the view was taken, so the walk sees it. A blob that disappears
// during the walk was unreferenced and is skipped. Finally it checks that
// every blob the view references, as the format packages report them, is
// in the backup; one that is not fails the backup, since the data
// directory itself has lost it.
//
// # Crash safety
//
// backup.json is written to a temporary file, synced, and renamed into
// place only after the snapshot, the blob list, every blob, and the
// directory entries naming them are durable. A backup without it is
// incomplete: List reports it as such, and Verify and Restore refuse it.
// An interrupted backup's directory is left for the operator to remove;
// nothing is deleted silently.
package backup

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/terrabyteian/flint/internal/blob"
	"github.com/terrabyteian/flint/internal/fsys"
	"github.com/terrabyteian/flint/internal/meta"
)

// File names in a backup directory.
const (
	lockFile     = "LOCK"
	backupsDir   = "backups"
	snapshotFile = "metadata.snap"
	blobListFile = "blobs"
	recordFile   = "backup.json"
)

// recordFormat is the format version of backup.json and the files it
// describes.
const recordFormat = 1

// References calls fn with each blob a metadata view references. Each
// format package that stores blobs provides one, such as oci.References.
// A digest may be reported more than once.
type References func(v meta.View, fn func(blob.Digest) error) error

// Record is a complete backup's backup.json.
type Record struct {
	// Format is the backup format version.
	Format int `json:"format"`
	// ID names the backup: its directory under backups/.
	ID string `json:"id"`
	// FlintVersion is the version of flint that wrote the backup.
	FlintVersion string `json:"flintVersion"`
	// Sequence is the metadata sequence number the backup holds.
	Sequence uint64 `json:"sequence"`
	// Started and Finished bound when the backup ran.
	Started  time.Time `json:"started"`
	Finished time.Time `json:"finished"`
	// Records is the number of metadata records.
	Records int `json:"records"`
	// Blobs and Bytes count the blobs the backup holds.
	Blobs int64 `json:"blobs"`
	Bytes int64 `json:"bytes"`
	// CopiedBlobs and CopiedBytes count the blobs this backup copied;
	// the rest were already present from earlier backups.
	CopiedBlobs int64 `json:"copiedBlobs"`
	CopiedBytes int64 `json:"copiedBytes"`
	// Snapshot and BlobList describe metadata.snap and blobs.
	Snapshot FileSum `json:"snapshot"`
	BlobList FileSum `json:"blobList"`
}

// FileSum is a file's size and SHA-256 digest.
type FileSum struct {
	Size   int64       `json:"size"`
	Digest blob.Digest `json:"digest"`
}

// Entry is a backup found in a backup directory.
type Entry struct {
	ID string
	// Record is the completion record, or nil if the backup is incomplete.
	Record *Record
	// Err explains why a backup with a completion record cannot be read.
	Err error
}

// Complete reports whether the backup finished.
func (e Entry) Complete() bool { return e.Record != nil }

// List returns the backups in dir, oldest first. fsy nil means fsys.OS.
func List(fsy fsys.FS, dir string) ([]Entry, error) {
	if fsy == nil {
		fsy = fsys.OS
	}
	ents, err := fsy.ReadDir(filepath.Join(dir, backupsDir))
	if errors.Is(err, fs.ErrNotExist) {
		if _, serr := fsy.Stat(dir); serr != nil {
			return nil, serr
		}
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []Entry
	for _, e := range ents {
		if !e.IsDir() || !validID(e.Name()) {
			continue
		}
		en := Entry{ID: e.Name()}
		en.Record, en.Err = readRecord(fsy, dir, e.Name())
		if errors.Is(en.Err, fs.ErrNotExist) {
			en.Err = nil
		}
		out = append(out, en)
	}
	return out, nil
}

// find returns the complete backup id in dir, or the latest complete one
// if id is empty.
func find(fsy fsys.FS, dir, id string) (*Record, error) {
	if id != "" {
		if !validID(id) {
			return nil, fmt.Errorf("%q is not a backup ID", id)
		}
		rec, err := readRecord(fsy, dir, id)
		if errors.Is(err, fs.ErrNotExist) {
			if _, serr := fsy.Stat(filepath.Join(dir, backupsDir, id)); serr == nil {
				return nil, fmt.Errorf("backup %s is incomplete: it was interrupted before it finished", id)
			}
			return nil, fmt.Errorf("backup %s not found in %s", id, dir)
		}
		return rec, err
	}
	ents, err := List(fsy, dir)
	if err != nil {
		return nil, err
	}
	for _, e := range slices.Backward(ents) {
		if e.Err != nil {
			return nil, fmt.Errorf("backup %s: %w", e.ID, e.Err)
		}
		if e.Complete() {
			return e.Record, nil
		}
	}
	return nil, fmt.Errorf("no complete backup in %s", dir)
}

func readRecord(fsy fsys.FS, dir, id string) (*Record, error) {
	f, err := fsy.Open(filepath.Join(dir, backupsDir, id, recordFile))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 1<<20))
	if err != nil {
		return nil, err
	}
	var rec Record
	if err := json.Unmarshal(b, &rec); err != nil {
		return nil, fmt.Errorf("reading %s: %w", recordFile, err)
	}
	switch {
	case rec.Format != recordFormat:
		return nil, fmt.Errorf("%s has format %d; this flint reads format %d", recordFile, rec.Format, recordFormat)
	case rec.ID != id:
		return nil, fmt.Errorf("%s names backup %q, not %q", recordFile, rec.ID, id)
	case rec.Snapshot.Digest.IsZero() || rec.BlobList.Digest.IsZero():
		return nil, fmt.Errorf("%s is missing file digests", recordFile)
	}
	return &rec, nil
}

// idLayout formats a backup ID's time part; the ID adds the sequence number.
const idLayout = "20060102T150405.000Z"

func newID(t time.Time, seq meta.Seq) string {
	return fmt.Sprintf("%s-%d", t.UTC().Format(idLayout), seq)
}

// validID reports whether s has the form newID produces, so an ID from a
// request or the command line never names a path outside backups/.
func validID(s string) bool {
	ts, seq, ok := strings.Cut(s, "-")
	if !ok || seq == "" || strings.Trim(seq, "0123456789") != "" {
		return false
	}
	_, err := time.Parse(idLayout, ts)
	return err == nil
}

// writeFileAtomic writes data to dir/name through a synced temporary file
// and a rename, then syncs dir.
func writeFileAtomic(fsy fsys.FS, dir, name string, data []byte) error {
	tmp := filepath.Join(dir, name+".tmp")
	f, err := fsy.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
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
		err = fsy.Rename(tmp, filepath.Join(dir, name))
	}
	if err == nil {
		err = fsy.SyncDir(dir)
	}
	return err
}
