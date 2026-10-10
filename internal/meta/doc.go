// Package meta is flint's metadata store: an ordered key-value map in which
// every change is a durable, sequenced log entry. It is a hand-written
// write-ahead log, an in-memory copy-on-write index, and background
// snapshots. docs/design.md states the guarantees; this comment describes
// the algorithms that meet them.
//
// # Files
//
// The store lives in one directory, normally <data>/meta:
//
//	wal/<first seq>.log        log segments, named by their first sequence number
//	snapshots/<seq>.snap       the latest index snapshot, named by its last sequence number
//	consumers/<name>           durable checkpoint of each registered log consumer
//
// Names use 20 zero-padded digits so they sort numerically. A segment
// starts with a header holding its first sequence number and a random
// 32-bit salt, then holds framed records: a length, a CRC-32C, and a body
// with the record format version, the sequence number, the offset back to
// the first record of its group commit, the wall-clock commit time, the
// origin, and the operations. The checksum is seeded with the segment's
// salt. record.go and snapshot.go give the exact layouts.
//
// # Commits and group commit
//
// One writer goroutine owns the log. Commit queues the batch and waits. The
// writer takes every queued batch (up to 8 MiB of them), and for each, in
// queue order, checks its preconditions against the state that includes the
// earlier batches of the same round, assigns the next sequence number, and
// applies it to a private copy of the index. It writes all of the round's
// records with one write and issues one fsync. Only then does it publish
// the new index, so views see only fsynced batches, and answer the
// commits. A batch whose precondition fails is answered with ErrConflict
// after the same fsync, so the state that refused it is durable.
//
// A Commit whose context ends while its batch is still queued withdraws it
// and returns the context's error; once the writer has taken the batch, the
// commit waits for the round to finish, so a context error always means
// nothing was applied.
//
// # Index and views
//
// The index is a copy-on-write B+tree. A published tree is never changed:
// the writer clones each node on the path it modifies, except nodes it
// created in the current round, which it changes in place. A view is a
// root pointer and a sequence number, so it is consistent, costs no locks,
// and never blocks the writer. Leaves pack their entries (key, version,
// value) into one byte slice with an offset table, so a leaf costs two
// pointers however many records it holds, which keeps garbage-collector
// scanning cheap. Values handed to readers are capped subslices of a
// published leaf.
//
// PinView takes a view and registers it as pinned in one step, under the
// same lock PinnedViews reads, so garbage collection sees every view pinned
// before it asks.
//
// # Log rotation
//
// Before a round, if the active segment has reached Options.SegmentSize,
// the writer creates the next segment, named by the next sequence number:
// it writes the header, fsyncs the file, and fsyncs the wal directory, all
// before any record goes into it. The previous segment was fully fsynced
// by the previous round. A segment can therefore exceed SegmentSize by one
// round.
//
// # Recovery
//
// Open loads the consumer checkpoints, then the newest snapshot that
// validates, then replays the log from the segment holding the first
// sequence number after the snapshot. Every record from there to the end
// of the log is checked: segments must follow each other without gaps,
// sequence numbers must be consecutive, and every record must have a valid
// checksum and decode.
//
// The only damage recovery repairs is in the final group-commit write,
// identified as follows. Records are written one group commit at a time,
// and the writer starts a group only after the previous group's fsync
// succeeded. Each record names the first sequence number of its group. So
// when the record expected next, E, is bad at offset X, recovery scans the
// rest of the segment, at every byte offset, for an intact record:
//
//   - If an intact record's group starts after E, a later group commit was
//     written after the group holding E was fsynced, so E was acknowledged:
//     startup fails with a CorruptionError naming the segment and X.
//   - If the bad record is in a segment that later segments follow, the
//     same reasoning applies (rotation happens only after an fsync), and
//     startup fails.
//   - If a snapshot or a consumer checkpoint covers E, E was fsynced:
//     startup fails.
//   - Otherwise the damage is confined to the final group-commit write,
//     which may have been torn by a crash before its fsync. Recovery
//     truncates the segment at X, fsyncs it, and continues. Complete
//     records of the final group before X are kept: each is a whole batch,
//     and none was acknowledged, so keeping them is as correct as dropping
//     them.
//
// The salt makes the scan safe against stored values that contain
// well-formed records: without the segment's secret salt, a forged record
// fails its checksum, so a value cannot turn a torn tail into a startup
// failure. A final segment whose header is invalid and which holds no
// more than a header's bytes is a torn segment creation and is removed;
// one holding more is corrupt, because headers are fsynced before records.
//
// As in any write-ahead log without a second fsync per write, rot that
// destroys every record from some point to the end of the log, leaving no
// intact record of a later group, cannot be told apart from an unsynced
// final write, unless a snapshot or checkpoint covers it.
//
// After replay the log must reach the snapshot's sequence number, and the
// oldest segment must start at or before the oldest batch a consumer still
// needs; otherwise startup fails. A snapshot that fails validation is
// skipped with a warning and the next older one is tried; if the log
// cannot make up the difference, startup fails with both errors.
//
// # Snapshots
//
// A background goroutine writes a snapshot after Options.SnapshotBytes of
// log, and Snapshot writes one on demand. A snapshot is taken from a view,
// so writers continue meanwhile. It is written to a temporary file,
// fsynced, renamed into place, and the directory fsynced; then older
// snapshots are deleted. Leftover temporary files are removed at startup.
//
// # Retention
//
// The retention floor is the minimum of the latest snapshot's sequence
// number, every registered consumer's checkpoint, and the start of every
// ReadLog in progress. A segment is deleted when the next segment starts
// at or below floor+1, so every batch it holds is at or below the floor.
// The active segment is never deleted. Deletions are followed by a
// directory fsync. A new consumer starts at the latest fsynced batch.
// Checkpoints and registrations are written to a temporary file, fsynced,
// renamed, and the directory fsynced before they count, and an
// unregistration is made durable before the consumer stops holding
// segments, so a crash cannot bring back a consumer whose segments are
// gone.
//
// # Write failures
//
// If a log write or fsync fails, or a new segment cannot be created, the
// store is poisoned: the batches of the failed write get an error matching
// both ErrUnknownOutcome and ErrPoisoned (their records may or may not be
// on disk), and every later Commit gets ErrPoisoned with the cause. The
// writer never writes to the log again, because after a failed fsync the
// kernel may have dropped the dirty pages. Views keep serving the last
// fsynced state, snapshots continue, the store stays ready, and the fault
// is logged once and reported by Stats().Poisoned. Reopening the store
// after fixing the cause recovers: a partial final write is discarded as a
// torn tail.
//
// # Testing
//
// The tests run the store on fsys.Mem, which discards unsynced data on a
// simulated power loss, and crash it at random filesystem operations,
// including during recovery, under concurrent writers, compare-and-swap
// counters, and a checkpointing consumer; after each restart every
// acknowledged write must be present and no batch partly visible. Removing
// any of the log, segment, snapshot, or checkpoint fsyncs makes these tests
// fail. TestProcessKill does the same with SIGKILL against a child process
// on the real filesystem. -meta.crash-iters sets the number of iterations;
// -short runs fewer.
//
// # Performance
//
// BenchmarkCommit on an Apple M5 Pro with APFS, whose fsync (F_FULLFSYNC)
// takes about 3 ms: one writer commits about 320 batches a second; 16
// writers share each fsync 8 ways for about 2,400 a second; 128 writers
// share it about 65 ways for about 17,000 a second at a p99 latency of
// 11 ms. Without fsync the commit path costs 2 to 5 µs of CPU per batch.
//
// BenchmarkIndexMemory: records shaped like OCI blob links (about 104-byte
// keys, 48-byte values) take 184 bytes of heap each when loaded from a
// snapshot and 198 bytes when built by live commits, which is 32 to 46
// bytes of overhead per record beyond the key and value bytes. Ten million
// such records need about 2 GB of live heap, so the design target of about
// 10 million records in 2 to 4 GB holds for records of this size, provided
// the garbage collector's headroom is bounded (GOGC or GOMEMLIMIT), since
// by default the heap may grow to twice the live size between collections.
// Larger values scale the figure with their size.
package meta
