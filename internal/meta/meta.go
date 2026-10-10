package meta

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/terrabyteian/flint/internal/fsys"
)

// Seq is a log sequence number. Sequence numbers start at 1 and increase by
// one per committed batch.
type Seq uint64

// Store is the metadata store.
type Store interface {
	// Commit applies b atomically. It returns only after b's log record is fsynced.
	// If a precondition fails, nothing is applied and the error is ErrConflict.
	// If ctx is done before b is written, nothing is applied and the error is ctx's.
	// After a log write or fsync failure the error is ErrPoisoned, and also
	// ErrUnknownOutcome for the batches that were part of the failed write.
	Commit(ctx context.Context, b *Batch) (Seq, error)

	// View returns a consistent read-only view as of the latest fsynced batch.
	// Views are cheap; they must be released.
	View() View
	// PinView is View, and also registers the view as pinned until it is
	// released, in one step. Garbage collection reads the pinned views.
	PinView() View
	// PinnedViews returns a new view on each currently pinned view, oldest first.
	// The caller must release each returned view.
	PinnedViews() []View

	// RegisterConsumer registers a durable log consumer under name, or reopens it,
	// and returns its checkpoint. Log segments above its checkpoint are kept.
	// A new consumer starts at the latest fsynced batch.
	RegisterConsumer(name string) (Seq, error)
	// UnregisterConsumer removes a consumer so it no longer holds segments back.
	UnregisterConsumer(name string) error
	// Checkpoint durably records that consumer name has processed every batch up to and including s.
	// The consumer must have made its output for those batches durable first.
	Checkpoint(name string, s Seq) error
	// ReadLog calls fn, in order, for each fsynced batch with a sequence number greater than after.
	// It stops at the latest batch fsynced when it was called.
	ReadLog(ctx context.Context, after Seq, fn func(Entry) error) error

	// Snapshot writes a snapshot of the latest fsynced state now and
	// deletes the log segments it makes unnecessary. Snapshots also run in
	// the background as the log grows.
	Snapshot() error
	// Stats reports counters and health for metrics.
	Stats() Stats

	// Close flushes and closes the log. Pending commits fail with ErrClosed.
	Close() error
}

// Entry is one committed batch as read back from the log.
type Entry struct {
	Seq    Seq
	Time   time.Time // wall-clock commit time, for display only
	Origin Origin
	Ops    []Op
}

// Op is one operation in a committed batch.
type Op struct {
	Delete bool
	Key    []byte
	Value  []byte // nil for a delete
}

// View is a consistent, read-only, point-in-time view of the store.
type View interface {
	Seq() Seq
	Get(key []byte) (Record, bool)
	// Scan calls fn for each key with the given prefix in byte order,
	// starting after the key after (or at the start if after is nil),
	// until fn returns false. Keys passed to fn are owned by the store.
	Scan(prefix, after []byte, fn func(key []byte, r Record) bool)
	// Release releases the view. Using a view after releasing it is a bug.
	Release()
}

// Record is a stored value. Value is owned by the store and must not be modified.
type Record struct {
	Value   []byte
	Version Seq // the sequence number of the batch that last wrote the key
}

// Origin describes the actor, action, and target behind a batch.
// It must not contain secrets: it is kept in the audit stream.
type Origin struct {
	Actor  string // user or token identity, or "system"
	Action string // e.g. "oci.tag.put"
	Target string // affected resources, human-readable, e.g. "repo/name:tag", "pkg/file.whl", "user alice"
}

// Stats is a point-in-time report of the store's counters and health.
type Stats struct {
	Seq            Seq    // latest fsynced batch
	Keys           int    // live keys
	Commits        uint64 // batches committed since Open
	Conflicts      uint64 // batches rejected by a precondition since Open
	GroupCommits   uint64 // log writes, each followed by one fsync, since Open
	Segments       int    // log segments on disk
	LogBytes       int64  // bytes in log segments on disk
	SnapshotSeq    Seq    // sequence number of the latest snapshot, 0 if none
	Snapshots      uint64 // snapshots written since Open
	SnapshotErrors uint64 // failed snapshot attempts since Open
	PinnedViews    int
	// Poisoned is the log write or fsync failure that made the store reject
	// writes, or nil. The store stays readable and ready while poisoned.
	Poisoned error
}

// Options configures a store. The zero value is valid.
type Options struct {
	// FS is the filesystem; nil means fsys.OS.
	FS fsys.FS
	// SegmentSize is the size at which the log rotates to a new segment.
	// Default 64 MiB.
	SegmentSize int64
	// SnapshotBytes is how many bytes of log a background snapshot is
	// written after; negative disables background snapshots. Default 128 MiB.
	SnapshotBytes int64
	// MaxBatchBytes caps the encoded size of one batch. Default 16 MiB, at most 1 GiB.
	MaxBatchBytes int
	// Logger receives fault and maintenance logs; nil means slog.Default().
	Logger *slog.Logger
	// Now is the commit-time clock, for display only; nil means time.Now.
	Now func() time.Time
}

var (
	// ErrConflict means a precondition failed and nothing was applied.
	ErrConflict = errors.New("meta: precondition failed")
	// ErrClosed means the store is closed.
	ErrClosed = errors.New("meta: store closed")
	// ErrUnknownConsumer means no consumer is registered under the name.
	ErrUnknownConsumer = errors.New("meta: unknown consumer")
	// ErrPoisoned means a log write or fsync failed, so the store rejects
	// writes until it is reopened. Reads keep working.
	ErrPoisoned = errors.New("meta: log write failed; store rejects writes until restarted")
	// ErrUnknownOutcome means the batch was part of a log write that failed:
	// it may or may not be present after a restart.
	ErrUnknownOutcome = errors.New("meta: outcome unknown")
	// ErrCorrupt matches every CorruptionError.
	ErrCorrupt = errors.New("meta: corrupt")
	// ErrCompacted means ReadLog asked for batches whose log segments are
	// already deleted.
	ErrCompacted = errors.New("meta: log entries already deleted")
	// ErrBatchTooLarge means the encoded batch exceeds Options.MaxBatchBytes.
	ErrBatchTooLarge = errors.New("meta: batch too large")
)

// CorruptionError reports corrupt or missing data found at startup or by
// ReadLog. It names the file and the byte offset of the problem.
type CorruptionError struct {
	Path   string
	Offset int64
	Reason string
}

func (e *CorruptionError) Error() string {
	return fmt.Sprintf("meta: corrupt data in %s at offset %d: %s", e.Path, e.Offset, e.Reason)
}

// Is makes errors.Is(err, ErrCorrupt) true.
func (e *CorruptionError) Is(target error) bool { return target == ErrCorrupt }

// writeFailure is returned for the batches of a failed log write.
type writeFailure struct{ cause error }

func (e *writeFailure) Error() string {
	return fmt.Sprintf("meta: log write failed, outcome unknown: %v", e.cause)
}

func (e *writeFailure) Is(target error) bool {
	return target == ErrUnknownOutcome || target == ErrPoisoned
}

func (e *writeFailure) Unwrap() error { return e.cause }

// poisonedError is returned for batches rejected because the store is poisoned.
type poisonedError struct{ cause error }

func (e *poisonedError) Error() string {
	return fmt.Sprintf("%v: %v", ErrPoisoned, e.cause)
}

func (e *poisonedError) Is(target error) bool { return target == ErrPoisoned }

func (e *poisonedError) Unwrap() error { return e.cause }
