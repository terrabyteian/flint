package backup

import (
	"bufio"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/terrabyteian/flint/internal/blob"
	"github.com/terrabyteian/flint/internal/fsys"
	"github.com/terrabyteian/flint/internal/meta"
)

// VerifyOptions configures Verify and Restore.
type VerifyOptions struct {
	// FS is the filesystem of the backup directory, and of the data
	// directory for Restore; nil means fsys.OS.
	FS fsys.FS
	// ID is the backup to use; empty means the latest complete one.
	ID string
	// References report the blobs each format package's records
	// reference; every one must be in the backup.
	References []References
	// Progress, if set, is called after each blob is checked or copied.
	Progress func(blobs, bytes int64)
}

// Report describes a verified backup.
type Report struct {
	Record *Record
	// Problems lists what is wrong with the backup, at most a few dozen;
	// NProblems counts them all. A backup with problems cannot be
	// restored.
	Problems  []string
	NProblems int
}

// maxProblems bounds Report.Problems.
const maxProblems = 50

func (r *Report) problem(format string, args ...any) {
	r.NProblems++
	if len(r.Problems) < maxProblems {
		r.Problems = append(r.Problems, fmt.Sprintf(format, args...))
	}
}

// Err returns an error summarizing the problems, or nil.
func (r *Report) Err() error {
	if r.NProblems == 0 {
		return nil
	}
	msg := fmt.Sprintf("backup %s has %d problems: %s", r.Record.ID, r.NProblems, strings.Join(r.Problems, "; "))
	if r.NProblems > len(r.Problems) {
		msg += "; ..."
	}
	return errors.New(msg)
}

// listed is a blob named in a backup's blob list.
type listed struct {
	d    blob.Digest
	size int64
}

// Verify checks a complete backup in dir without changing it: the
// metadata snapshot and blob list match their recorded digests, the
// snapshot is intact, every listed blob is present with the content its
// digest names, and every blob the metadata references is listed. Problems
// with the backup's contents are in the report; the error is for a backup
// that cannot be found or read at all.
func Verify(ctx context.Context, dir string, opts VerifyOptions) (*Report, error) {
	fsy := opts.FS
	if fsy == nil {
		fsy = fsys.OS
	}
	rep, _, blobs, err := open(ctx, fsy, dir, opts)
	if err != nil || rep.NProblems > 0 {
		return rep, err
	}
	var nb, nbytes int64
	for _, b := range blobs {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if err := checkBlob(fsy, dir, b); err != nil {
			rep.problem("%v", err)
		}
		nb++
		nbytes += b.size
		if opts.Progress != nil {
			opts.Progress(nb, nbytes)
		}
	}
	return rep, nil
}

// checkBlob reads blob b in the backup directory dir and checks its size
// and digest.
func checkBlob(fsy fsys.FS, dir string, b listed) error {
	r, err := fsy.Open(blobPath(dir, b.d))
	if errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("blob %s is missing", b.d)
	}
	if err != nil {
		return err
	}
	defer r.Close()
	h := sha256.New()
	n, err := io.Copy(h, r)
	switch {
	case err != nil:
		return fmt.Errorf("reading blob %s: %w", b.d, err)
	case n != b.size:
		return fmt.Errorf("blob %s has %d bytes, want %d", b.d, n, b.size)
	case fmt.Sprintf("%x", h.Sum(nil)) != b.d.Hex():
		return fmt.Errorf("blob %s is corrupt: its content does not match its digest", b.d)
	}
	return nil
}

// open finds the backup opts.ID in dir and checks its metadata snapshot,
// blob list, and references, returning the snapshot's view and the blob
// list. Problems found go in the report, and leave the view nil.
func open(ctx context.Context, fsy fsys.FS, dir string, opts VerifyOptions) (*Report, meta.View, []listed, error) {
	rec, err := find(fsy, dir, opts.ID)
	if err != nil {
		return nil, nil, nil, err
	}
	rep := &Report{Record: rec}
	bdir := filepath.Join(dir, backupsDir, rec.ID)
	snapPath := filepath.Join(bdir, snapshotFile)
	if err := checkSum(fsy, snapPath, rec.Snapshot); err != nil {
		rep.problem("%v", err)
	}
	listPath := filepath.Join(bdir, blobListFile)
	if err := checkSum(fsy, listPath, rec.BlobList); err != nil {
		rep.problem("%v", err)
	}
	if rep.NProblems > 0 {
		return rep, nil, nil, nil
	}

	f, err := fsy.Open(snapPath)
	if err != nil {
		return nil, nil, nil, err
	}
	v, err := meta.ReadSnapshot(f, snapPath)
	f.Close()
	if err != nil {
		rep.problem("%v", err)
		return rep, nil, nil, nil
	}
	if uint64(v.Seq()) != rec.Sequence {
		rep.problem("the metadata snapshot is at sequence %d, want %d", v.Seq(), rec.Sequence)
	}

	blobs, err := readList(fsy, listPath)
	if err != nil {
		rep.problem("%v", err)
		return rep, nil, nil, nil
	}
	have := make(map[blob.Digest]struct{}, len(blobs))
	var bytes int64
	for _, b := range blobs {
		have[b.d] = struct{}{}
		bytes += b.size
	}
	if int64(len(blobs)) != rec.Blobs || bytes != rec.Bytes {
		rep.problem("the blob list holds %d blobs of %d bytes, want %d of %d", len(blobs), bytes, rec.Blobs, rec.Bytes)
	}
	for _, refs := range opts.References {
		err := refs(v, func(d blob.Digest) error {
			if _, ok := have[d]; !ok {
				have[d] = struct{}{} // report it once
				rep.problem("the metadata references blob %s, which the backup does not hold", d)
			}
			return ctx.Err()
		})
		if err != nil {
			return nil, nil, nil, err
		}
	}
	if rep.NProblems > 0 {
		return rep, nil, nil, nil
	}
	return rep, v, blobs, nil
}

// checkSum checks that path has the recorded size and digest.
func checkSum(fsy fsys.FS, path string, want FileSum) error {
	f, err := fsy.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("%s is missing", filepath.Base(path))
	}
	if err != nil {
		return err
	}
	defer f.Close()
	s := &summer{h: sha256.New()}
	if _, err := io.Copy(s, f); err != nil {
		return fmt.Errorf("reading %s: %w", filepath.Base(path), err)
	}
	if got := s.sum(); got != want {
		return fmt.Errorf("%s is corrupt: it has %d bytes with digest %s, want %d bytes with digest %s",
			filepath.Base(path), got.Size, got.Digest, want.Size, want.Digest)
	}
	return nil
}

// readList parses a blob list.
func readList(fsy fsys.FS, path string) ([]listed, error) {
	f, err := fsy.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []listed
	sc := bufio.NewScanner(f)
	for line := 1; sc.Scan(); line++ {
		ds, ss, ok := strings.Cut(sc.Text(), " ")
		d, derr := blob.ParseDigest(ds)
		size, serr := strconv.ParseInt(ss, 10, 64)
		if !ok || derr != nil || serr != nil || size < 0 {
			return nil, fmt.Errorf("%s line %d is malformed", filepath.Base(path), line)
		}
		out = append(out, listed{d, size})
	}
	return out, sc.Err()
}

// blobPath returns where the backup directory dir stores blob d, the
// blob store's layout.
func blobPath(dir string, d blob.Digest) string {
	return filepath.Join(dir, "blobs", "sha256", d.Hex()[:2], d.Hex())
}
