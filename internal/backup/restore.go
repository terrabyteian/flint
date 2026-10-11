package backup

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path/filepath"

	"github.com/terrabyteian/flint/internal/blob"
	"github.com/terrabyteian/flint/internal/fsys"
	"github.com/terrabyteian/flint/internal/meta"
)

// RestoreMarker is the file Restore keeps in a data directory until the
// restore is complete. flint serve refuses to start while it exists, so
// an interrupted restore is never served as if it were the whole
// registry.
const RestoreMarker = "RESTORE-INCOMPLETE"

// Restore restores a complete backup from the backup directory dir into
// dataDir, which must not exist or hold nothing but a LOCK file and a
// lost+found directory, as on a new ext4 volume. A caller that creates
// dataDir first, to lock it, creates it with [MkdirDurable]. It
// checks the backup as Verify does, and each blob's digest as it copies
// it; a backup with problems is not restored, and the report says why.
// The restored data directory holds the backed-up metadata and blobs;
// flint generates a new token-signing key when it first starts on it.
func Restore(ctx context.Context, dir, dataDir string, opts VerifyOptions) (*Report, error) {
	fsy := opts.FS
	if fsy == nil {
		fsy = fsys.OS
	}
	ents, err := fsy.ReadDir(dataDir)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	for _, e := range ents {
		if e.Name() != lockFile && (e.Name() != "lost+found" || !e.IsDir()) {
			return nil, fmt.Errorf("the data directory %s is not empty; restore needs a new or empty one", dataDir)
		}
	}
	rep, v, blobs, err := open(ctx, fsy, dir, opts)
	if err != nil {
		return nil, err
	}
	if rep.NProblems > 0 {
		return rep, rep.Err()
	}

	if err := MkdirDurable(fsy, dataDir, 0o750); err != nil {
		return nil, err
	}
	if err := writeFileAtomic(fsy, dataDir, RestoreMarker,
		[]byte("flint restore of backup "+rep.Record.ID+" did not finish; remove this data directory and restore again\n")); err != nil {
		return nil, err
	}
	dst, err := blob.NewFS(dataDir, blob.Options{FS: fsy})
	if err != nil {
		return nil, err
	}
	var nb, nbytes int64
	for _, b := range blobs {
		if err := restoreBlob(ctx, fsy, dir, dst, b); err != nil {
			return nil, err
		}
		nb++
		nbytes += b.size
		if opts.Progress != nil {
			opts.Progress(nb, nbytes)
		}
	}
	if err := meta.Restore(filepath.Join(dataDir, "meta"), v, meta.Options{FS: fsy}); err != nil {
		return nil, fmt.Errorf("restoring the metadata: %w", err)
	}
	if err := fsy.Remove(filepath.Join(dataDir, RestoreMarker)); err != nil {
		return nil, err
	}
	if err := fsy.SyncDir(dataDir); err != nil {
		return nil, err
	}
	return rep, nil
}

// restoreBlob copies blob b from the backup directory dir into dst,
// which verifies its digest and makes it durable.
func restoreBlob(ctx context.Context, fsy fsys.FS, dir string, dst blob.Store, b listed) error {
	r, err := fsy.Open(blobPath(dir, b.d))
	if errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("blob %s is missing from the backup", b.d)
	}
	if err != nil {
		return err
	}
	defer r.Close()
	up, err := dst.NewUpload(ctx)
	if err != nil {
		return err
	}
	if _, err := io.Copy(up, r); err != nil {
		up.Cancel()
		return fmt.Errorf("restoring blob %s: %w", b.d, err)
	}
	info, err := up.Commit(ctx, b.d)
	if errors.Is(err, blob.ErrDigestMismatch) {
		return fmt.Errorf("blob %s in the backup is corrupt: its content does not match its digest", b.d)
	}
	if err != nil {
		return fmt.Errorf("restoring blob %s: %w", b.d, err)
	}
	if info.Size != b.size {
		return fmt.Errorf("blob %s in the backup has %d bytes, want %d", b.d, info.Size, b.size)
	}
	return nil
}
