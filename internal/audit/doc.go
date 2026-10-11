// Package audit keeps flint's audit log: a record of every change to the
// metadata store, derived from the write-ahead log's batch origins.
// docs/design.md states what it guarantees; this comment describes how.
//
// # Records
//
// The audit log is a durable consumer of the metadata log
// (meta.Store.RegisterConsumer, ReadLog, and Checkpoint). For each
// committed batch it writes one record: the batch's sequence number, its
// commit time, its origin (actor, action, and target), and the keys it
// wrote or deleted. A record has no field for a value, and the encoder
// reads only keys and the origin, so password hashes, token hashes, and
// every other stored value never reach the stream. Origins must not
// contain secrets, as meta.Origin requires.
//
// # Files
//
// The stream lives in its own directory, normally <data>/audit, so its
// history never depends on how long the metadata log keeps its segments:
//
//	<first seq>.audit   append-only segments, named by the first batch they hold
//
// Names use 20 zero-padded digits so they sort numerically. A segment
// starts with a checksummed header naming its first sequence number, then
// holds framed records, each with a length and a CRC-32C. format.go gives
// the exact layout. Sequence numbers increase through the stream; they
// may skip batches that were never audited, such as those committed
// before the audit log first started, which starts at the batch the
// metadata store had then.
//
// # Writing and checkpoints
//
// Run polls the metadata store and catches up: it reads the batches after
// the last durable record, appends their records, fsyncs the segment, and
// only then checkpoints the consumer, so the metadata store keeps every
// log segment holding a batch whose record might not be durable. Sync
// does the same on demand; the query API calls it so reads see the
// latest changes. A rotation fsyncs the old segment, then creates the new
// one, fsyncs its header, and fsyncs the directory before any record goes
// into it. Segments rotate by size (64 MiB, or a quarter of MaxSize if
// smaller) and after a day of commit times (or a quarter of MaxAge if
// shorter), so that retention deletes records close to its limits.
//
// # Recovery
//
// Open registers the consumer, which returns its checkpoint, and reads
// the active (last) segment. Every record up to the checkpoint was
// durable before the checkpoint was written. A bad record after the
// checkpoint is a write a crash tore before its fsync: the segment is
// truncated there, and the batches it held are read again from the
// metadata log, which kept them. A bad record at or before the checkpoint
// is corruption of acknowledged records, and Open fails with a
// CorruptionError naming the file and offset. A final segment whose header
// is incomplete is a torn creation and is removed. Records past the
// checkpoint that survived are kept, and catching up resumes after the
// later of them and the checkpoint, so after a crash no record is lost or
// written twice.
//
// If a write or fsync fails, the catch-up stops without checkpointing and
// the fault is logged and reported by the flint_audit_failing metric. The
// next attempt reopens the active segment and truncates it to the size
// last fsynced, since after a failed fsync nothing written since can be
// trusted to be on disk, then writes the records again. Meanwhile the
// metadata store keeps the log segments the audit log has not
// checkpointed.
//
// # Retention
//
// By default records are kept forever. Options.MaxAge and Options.MaxSize
// delete whole segments, oldest first, never the active one: by age when a
// sealed segment's modification time, the time of its newest record, is
// older than MaxAge, and by size while the stream is larger than MaxSize.
// With MaxAge, retention also seals an active segment whose records span
// the segment age, so a quiet registry's records age out too. Retention
// runs after each rotation, and hourly or every segment age if shorter.
//
// # Reading
//
// Scan reads records in sequence order, up to the size of each segment
// that is durable, filtered by sequence number, commit time, actor,
// action, and target. Register serves the admin API's query and JSON-lines
// export endpoints, for administrators only.
package audit
