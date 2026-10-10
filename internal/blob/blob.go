// Package blob is flint's content-addressed blob store.
//
// A blob is a sequence of bytes stored under its sha256 digest, exactly once
// however many repositories reference it. The store holds bytes only: which
// repository may see a blob is recorded by link records in the metadata
// store, which this package does not know about.
//
// Writes are staged uploads that hash their bytes as they arrive. Commit
// verifies the digest, makes the blob durable, and only then makes it
// visible, so a visible blob is always complete and matches its name, even
// after a crash.
package blob

import (
	"context"
	"errors"
	"io"
	"time"
)

// Errors returned by stores.
var (
	// ErrNotFound means no committed blob has the digest.
	ErrNotFound = errors.New("blob: not found")
	// ErrDigestMismatch means an upload's content does not hash to the
	// digest its client claimed. The upload is discarded.
	ErrDigestMismatch = errors.New("blob: digest mismatch")
	// ErrUploadUnknown means no suspended upload has the ID, or its staged
	// state did not survive intact.
	ErrUploadUnknown = errors.New("blob: unknown upload")
	// ErrUploadBusy means the upload is open elsewhere in this process,
	// such as by a concurrent request for the same upload.
	ErrUploadBusy = errors.New("blob: upload in use")
	// ErrUploadClosed means the upload was already committed, suspended,
	// or cancelled.
	ErrUploadClosed = errors.New("blob: upload closed")
)

// Store is a content-addressed blob store.
type Store interface {
	// NewUpload starts an upload whose bytes are hashed as they are written.
	NewUpload(ctx context.Context) (Upload, error)
	// ResumeUpload reopens a suspended upload, e.g. for the next chunk of an
	// OCI chunked upload. It returns ErrUploadUnknown if there is no such
	// upload and ErrUploadBusy if it is already open.
	ResumeUpload(ctx context.Context, id string) (Upload, error)
	// Open returns the blob's content. The filesystem store returns an *os.File.
	Open(ctx context.Context, d Digest) (Reader, error)
	// Stat describes a committed blob.
	Stat(ctx context.Context, d Digest) (Info, error)
	// Delete removes a blob. Only garbage collection calls it.
	Delete(ctx context.Context, d Digest) error
	// Walk calls fn for every committed blob, for the GC sweep and backup.
	// It stops at the first error fn returns and returns it.
	Walk(ctx context.Context, fn func(Info) error) error
	// PurgeUploads removes abandoned uploads: those left by an earlier
	// process that were never suspended, and suspended uploads last
	// suspended before the given time. Uploads open in this process are
	// never removed. It returns the number of uploads removed.
	PurgeUploads(ctx context.Context, before time.Time) (int, error)
}

// Upload is an in-progress, hashed, staged write.
// An Upload is not safe for concurrent use.
type Upload interface {
	io.Writer
	ID() string
	// Size returns the number of bytes staged so far.
	Size() int64
	// Commit verifies that the content hashes to want (the zero Digest accepts any),
	// makes the blob durable and visible under its digest, and ends the upload.
	// If the blob already exists, the staged data is discarded.
	// On ErrDigestMismatch, or any other error, the upload is discarded.
	Commit(ctx context.Context, want Digest) (Info, error)
	// Suspend makes the staged bytes and the hash state durable and closes
	// the upload so ResumeUpload can continue it, also after a crash.
	// If Suspend fails, the upload is discarded.
	Suspend() error
	// Cancel discards the upload.
	Cancel() error
}

// Reader reads a committed blob.
type Reader interface {
	io.ReadSeekCloser
}

// Info describes a committed blob.
type Info struct {
	Digest  Digest
	Size    int64
	ModTime time.Time // commit time; GC uses it for the grace period
}
