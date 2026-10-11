# flint design

This document describes what flint is, the decisions that shape it, and how its parts fit together.
It is the reference for contributors: read it before changing storage, metadata, auth, or the dependency rule.
When a decision here changes, update this document in the same pull request.

## Goals

flint is a self-hosted artifact registry, built from scratch.

- Serve container images and OCI artifacts, Python packages, and the other popular package formats from one server.
- Host first-party artifacts and cache upstream registries (Docker Hub, ghcr.io, quay.io, PyPI) behind the same endpoint.
- Be efficient: one static binary plus a data directory, low memory per artifact, streaming I/O, and zero-copy `sendfile` reads over plain HTTP/1.1 (for example behind a TLS-terminating trusted proxy).
- Be safe with data: an acknowledged write survives a crash, and nothing is ever deleted silently.
- Be product quality. flint starts as a personal homelab registry, but its design must hold up for an open-source product used by large-ish enterprises: multi-terabyte storage and a few hundred concurrent clients on one server.

## Non-goals

- **Migration from other registries.** flint is a fresh build; there is no import tool.
- **Multi-server high availability in v1.** v1 is a single server. The data layout and metadata store are designed so HA can be added later without a data migration (see [High availability later](#high-availability-later)).
- **Every package format in v1.** v1.0 supports OCI/Docker, PyPI, and a first wave of further formats on the same storage, metadata, and repository core: npm, Maven, Go modules (proxy and virtual), Cargo, generic files, and the classic Helm repository view. A first-wave format that is not ready when the rest of v1.0 is ships in v1.1. NuGet and Terraform come next. Hosted Go modules are deferred: the go command has no publish, and private modules are usually served from version control.
- **Docker image manifest schema 1.** It is deprecated and unsupported.
- **PyPI XML-RPC search.** PyPI itself disabled it; flint will never implement it.
- **Hand-written SAML.** Enterprises that need SAML put an OIDC bridge such as Keycloak or Dex in front (see [Auth and permissions](#auth-and-permissions)).
- **Enterprise features before they are needed.** LDAP, quotas, and similar features get design hooks now and are built when someone needs them.

## The zero-dependency rule

flint is written in Go and builds with **only the Go standard library**.
There are no third-party modules, and `golang.org/x/...` modules count as third-party.
`go.mod` has no `require` directives and the repository has no `go.sum`.
CI enforces this with `scripts/check-deps.sh` (see [CONTRIBUTING.md](../CONTRIBUTING.md)).

The runtime has the same rule: flint is one static binary (`CGO_ENABLED=0`) plus a data directory.
It needs no Postgres, Redis, or object store.

Why:

- **An artifact registry is a supply-chain component.** Every build in an organization pulls through it, so a compromised dependency of the registry compromises everything downstream. With no dependencies, the attack surface is flint's code plus the Go standard library, which is widely reviewed and released with security fixes.
- **Auditability.** A reviewer can read everything that ships.
- **Operations.** A single static binary deploys anywhere, runs in a `FROM scratch` image, and has no service to keep alive beside it.
- **Longevity.** No dependency can be abandoned, relicensed, or break its API under us.

The cost is that flint hand-writes what libraries usually provide: the write-ahead log and index, JWT signing and verification, OIDC discovery, Prometheus text exposition, and later S3 SigV4.
The Go standard library makes this cost acceptable: it ships a production HTTP/1.1 and HTTP/2 server and client, TLS, X.509, the needed cryptography (SHA-256, HMAC, RSA, ECDSA, Ed25519, PBKDF2), `encoding/json`, `html/template`, and `log/slog`.
Correctness of the hand-written protocol code is checked against real clients and official conformance suites in CI.

Test harnesses are exempt because they never ship in the binary.
CI may run real clients (docker, crane, oras, pip, uv, twine) and the official OCI distribution conformance suite against a running flint.

### Why Go over Rust

Both were viable.
Go won because of the zero-dependency rule.
Rust's standard library has no HTTP, TLS, or cryptography, so zero-dependency Rust would mean hand-writing TLS, which is unacceptable for a security-sensitive server.
Go's standard library covers the whole protocol stack, cross-compiles static binaries trivially, and gives `sendfile` reads through plain `io.Copy` on plain HTTP/1.1 connections.
The trade-off is garbage-collector cost for a large in-memory index; the metadata store keeps that in check with compact, pointer-light encodings (see [Metadata store](#metadata-store)).

## Architecture overview

```
              clients: docker, containerd, crane, oras, pip, uv, twine, browsers
                                          |
                                     HTTP(S) server
                     TLS with hot reload, trusted proxies, auth, metrics
                                          |
              +---------------------------+---------------------------+
              |                           |                           |
        OCI distribution             PyPI simple API             UI and admin API
        hosted / proxy repos     hosted / proxy / virtual repos
              |                           |                           |
              +-------------+-------------+-------------+-------------+
                            |                           |
                    metadata store                  blob store
           (write-ahead log + in-memory index      (content-addressed by sha256,
                 + snapshots)                    shared by all repos and formats)
```

Every artifact byte lives in the blob store exactly once, however many repositories and formats reference it.
Everything else (which repository may see which blob, tags, manifests, package files, users, tokens, runtime-created repositories) lives in the metadata store.
The format packages translate protocol requests into blob and metadata operations.

### Data directory layout

```
<data>/
  LOCK                         flock held by the running server; a second process refuses to start
  blobs/sha256/<2 hex>/<64 hex> committed blobs, fanned out by the first two hex characters
  uploads/<id>[.state]         in-progress uploads and their suspended hash state; same filesystem as blobs/
  meta/wal/<seq>.log           write-ahead log segments, named by first sequence number
  meta/snapshots/<seq>.snap    index snapshots, named by the last sequence number they contain
  meta/consumers/<name>        durable checkpoint of each registered log consumer
  auth/token-signing.key       Ed25519 key that signs the Docker token service's bearer tokens, generated on first start
  auth/url-signing.key         HMAC-SHA256 key that signs download URLs, generated on first start
  audit/<seq>.audit            append-only audit stream of batch origins and touched keys, never values; segments named by first sequence number
  RESTORE-INCOMPLETE           present only while flint restore writes the directory; serve refuses to start while it exists
```

Paths contain no node identity, so a later HA deployment can reuse the layout unchanged.

## Blob store

The blob store is a content-addressed store keyed by sha256 digest.
It holds bytes only; it does not know about repositories, formats, or access control.

### Write path

1. A new upload creates a temp file under `uploads/`.
2. Bytes stream into the temp file while a SHA-256 hash is updated incrementally. Nothing is buffered in memory beyond a copy buffer.
3. An upload can span several requests (OCI chunked uploads). Between requests the upload's hash state is persisted with the hash's `encoding.BinaryMarshaler` implementation, so resuming does not re-read the data. Suspending fsyncs the staged bytes before it durably writes the state file (written to a temp file, fsynced, and renamed), so after a crash a state never describes bytes that were lost, and a resumed upload never commits content its hash state did not see. Resuming drops any staged bytes past the size the state records.
4. On commit the computed digest is checked against the digest the client claimed; a mismatch discards the upload.
5. The temp file's modification time is set to the commit time, the file is fsynced, renamed atomically to `blobs/sha256/<ab>/<digest>`, and the fan-out directory is fsynced so the rename is durable. All 256 fan-out directories are created, and their parent fsynced, when the store opens, so commits never create directories.
6. If the blob already exists, the temp file is dropped and the existing blob is reused, after an fsync of its fan-out directory in case a concurrent commit renamed it into place but has not made that durable yet. Identical content is stored once. An existing file whose size does not match is a damaged copy, and the verified upload replaces it.
7. Only after the blob is durable does the caller write the metadata **link record** that makes the blob visible in a repository.

Abandoned uploads are removed by `PurgeUploads`: uploads a previous process left without ever suspending them (they can never be resumed), and suspended uploads not suspended again since a cutoff time. Uploads open in the running process are never removed.

A crash between steps 5 and 7 leaves an unlinked blob.
That is safe: garbage collection reclaims it after its grace period.
A cross-repository blob mount is only step 7: a new link record, no data copied.
Before linking, a mount checks that the blob is linked in the `from` repository and that the caller has read permission on that repository; if either check fails, it falls back to a normal upload, as the OCI spec allows.
Every link batch, whether from an upload or a mount, carries the garbage-collection precondition on the GC epoch: it reads the epoch and the digest's doomed entry from the same view before its blob-existence check (`Upload.Commit` or the mount's source check) and fails if the digest is doomed in that view, as described in [Cleanup and data safety](#cleanup-and-data-safety).

### Read path

1. The caller checks the per-repository link record in the metadata store. A blob that exists only for another repository is a 404: digests are not secrets, and possession of one must not grant access.
2. The blob is opened and streamed. The filesystem store returns the `*os.File` itself, unwrapped, so `net/http`'s copy path can use `sendfile`. That zero-copy path applies only to plain HTTP/1.1, for example when TLS is terminated by a trusted proxy in front of flint. When flint serves TLS itself, or the connection is HTTP/2, blob bytes are read and encrypted in user space.

### Storage interface

The blob store sits behind a small interface.
v1 ships the filesystem implementation; an S3 implementation (hand-written SigV4, multipart uploads, presigned-URL redirects for reads) follows shortly after v1.
S3 redirect support will be an optional extra interface that the read path checks for, so the core interface stays small.

## Metadata store

The metadata store is an ordered key-value map in which every change is a durable, sequenced log entry.
It is a hand-written append-only write-ahead log, an in-memory index, and periodic snapshots.

- **Log.** Each committed batch is one log record: a length, a CRC-32C checksum, the sequence number, a record format version, the wall-clock commit time (for display only, never used for safety), the encoded origin, and the encoded operations. Segments rotate by size.
- **Index.** An in-memory ordered index of all live keys. Ordered iteration serves prefix scans and paginated listings (tags, catalog, package files). The index is copy-on-write (for example a persistent B-tree with path copying), so a read view is a root pointer: views are consistent and cheap, and long scans such as garbage-collection marking or backup never block writers.
- **Snapshots.** In the background, the store writes the index as of some sequence number to a snapshot file. Snapshots hold only the index, not batch origins. Startup loads the latest valid snapshot and replays the log after it.
- **Group commit.** A single writer goroutine appends all pending batches and issues one fsync for them, so concurrent writers share fsync cost.
- **Versioned records.** Log records carry a format version, and values written by format packages start with their own schema version byte, so encodings can evolve while old logs and snapshots still load.
- **Preconditions.** A batch can require that a key is absent or still at a given version, and it fails atomically if not. This implements immutable tags, never-reusable PyPI filenames, and safe concurrent updates without locks held across requests.
- **Scale target.** About 10 million records in 2 to 4 GB of RAM. Values use compact binary encodings via `encoding/binary` rather than JSON, and the index avoids per-record pointers where it can to keep garbage-collector scanning cheap.

The store must meet these guarantees:

1. A write is acknowledged only after its log record is fsynced, so acknowledged data survives a crash. Views and snapshots contain only fsynced batches.
2. At startup, a corrupted record followed by any intact record of a later group commit, or a gap in the log, is a startup error naming the segment and offset, never a silent truncation. Only a bad region confined to the final group-commit write may be truncated; as in any write-ahead log without a second fsync, rot confined to that last group cannot be told apart from an unsynced write.
3. A log segment is deleted only once it is covered by the latest snapshot and by the checkpoint of every registered durable consumer (the audit log in M4, Raft replication later). The active segment is never deleted.
4. On a log write or fsync failure the store rejects writes with a clear error, keeps serving reads from fsynced state, stays ready, and reports the fault through a metric and logs. A restart after fixing the cause recovers.
5. The audit stream holds each batch's sequence number, commit time, origin (actor, action, target), and touched keys, never values.

The garbage-collection guarantees are in [Cleanup and data safety](#cleanup-and-data-safety).
The algorithms that meet these guarantees, including how recovery identifies the final group-commit write, are described in the `internal/meta` package documentation and proven by its crash tests.

The store does not interpret keys or values.
Each package owns a key namespace, and keys use `0x00` as a separator so a prefix scan is unambiguous even though OCI repository names contain `/`.
Illustrative v1 key space:

| Key | Value | Owner |
| --- | --- | --- |
| `repo\0<repo>` | repository created at runtime | `internal/repo` |
| `oci\0blob\0<repo>\0<name>\0<digest>` | blob link (blob size, link time) | `internal/oci` |
| `oci\0manifest\0<repo>\0<name>\0<digest>` | manifest record (media type, size, artifact type, subject, annotations, referenced digests, push time) | `internal/oci` |
| `oci\0tag\0<repo>\0<name>\0<tag>` | manifest digest | `internal/oci` |
| `oci\0referrer\0<repo>\0<name>\0<subject>\0<digest>` | referrers index entry: manifest `<digest>` has subject `<subject>` | `internal/oci` |
| `oci\0upload\0<id>` | upload session (repository name, start time) | `internal/oci` |
| `oci\0mgen\0<repo>\0<name>\0` | manifest generation: empty, written by every batch that writes a manifest record in the name | `internal/oci` |
| `oci\0pulled\0blob\0<repo>\0<name>\0<digest>` | last pull of a blob cached by a size-limited proxy repository | `internal/oci` |
| `oci\0pulled\0manifest\0<repo>\0<name>\0<digest>` | last pull of a manifest cached by a size-limited proxy repository | `internal/oci` |
| `pypi\0project\0<repo>\0<project>` | hosted project (name as first uploaded); kept forever, so the repository keeps owning the name | `internal/pypi` |
| `pypi\0file\0<repo>\0<filename>` | hosted file record (digests, metadata blob, yank state), kept as a tombstone after delete; or a file a proxy repository cached | `internal/pypi` |
| `pypi\0index\0<repo>\0<project>\0<filename>` | empty; indexes a hosted project's live files | `internal/pypi` |
| `pypi\0name\0<repo>\0<normalized filename>` | hosted file name as uploaded, by its normalized form; kept forever, so no spelling of the name can be used again | `internal/pypi` |
| `pypi\0metadata\0<repo>\0<filename>` | core-metadata file a proxy repository cached | `internal/pypi` |
| `pypi\0pulled\0file\0<repo>\0<filename>` | last pull of a file cached by a size-limited proxy repository (also `...\0metadata\0...`) | `internal/pypi` |
| `cache\0doc\0<repo>\0<key>` | document a proxy repository cached, such as a PyPI project page (`<key>` is the format's name for it): blob digest of the upstream's bytes, upstream ETag and Last-Modified, content type, URL, fetch time | `internal/upstream` |
| `cache\0file\0<repo>\0<path>` | immutable file a path-addressed proxy repository cached: blob digest, size, content type, the other digests verified or computed | `internal/upstream` |
| `cache\0pulled\0file\0<repo>\0<path>` | last pull of a file cached by a size-limited path-addressed proxy repository | `internal/upstream` |
| `gc\0epoch` | GC epoch counter, incremented by each sweep round's start batch | `internal/gc` |
| `gc\0doomed\0<digest>` | doomed set of the sweep round in progress; cleared when the round ends, and at startup | `internal/gc` |
| `gc\0last` | report of the last garbage-collection run that was not a dry run | `internal/gc` |
| `auth\0user\0<username>` | user record | `internal/auth` |
| `auth\0token\0<token-id>` | token record with hashed secret | `internal/auth` |
| `auth\0usertoken\0<username>\0<token-id>` | empty; indexes a user's tokens | `internal/auth` |

An index on disk can later replace the in-memory one behind the same interface if the record count outgrows RAM.

### High availability later

HA is deferred, but nothing in v1 may block it:

- The metadata log is a sequence of deterministic batches with preconditions. In HA mode, the log becomes a Raft-replicated log: `Commit` proposes the batch, and every node applies committed entries in order to its index. Snapshots become Raft snapshots. Replication registers as a durable log consumer, so the same retention floor keeps segments that a lagging follower still needs.
- Blob storage moves to shared S3 (or replicated filesystems); content addressing makes concurrent writers of the same blob harmless.
- Keys, values, and paths contain no node identity, so a v1 data directory becomes the initial state of a cluster without migration.

## Interfaces for the M0 storage tasks

The metadata store and the blob store are built in parallel as separate M0 tasks, against the interfaces below.
Names and signatures are the starting contract; each task may refine details in its own pull request, updating this section.
Neither package imports the other: the format packages tie them together.

### `internal/meta`

```go
// Seq is a log sequence number. Sequence numbers start at 1 and increase by one per committed batch.
type Seq uint64

// Store is the metadata store.
type Store interface {
	// Commit applies b atomically. It returns only after b's log record is fsynced.
	// If a precondition fails, nothing is applied and the error is ErrConflict.
	Commit(ctx context.Context, b *Batch) (Seq, error)

	// View returns a consistent read-only view as of the latest fsynced batch.
	// Views are cheap; they must be released.
	View() View
	// PinView is View, and also registers the view as pinned until it is released, in one step.
	// Garbage collection reads the pinned views.
	PinView() View
	// PinnedViews returns a new view on each currently pinned view; each must be released.
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
	ReadLog(ctx context.Context, after Seq, fn func(Entry) error) error

	// Snapshot writes a snapshot now and deletes the log segments it makes unnecessary.
	Snapshot() error
	// Stats reports counters and health (including a write failure) for metrics.
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
	// until fn returns false.
	Scan(prefix, after []byte, fn func(key []byte, r Record) bool)
	Release()
}

// Record is a stored value. Value is owned by the store and must not be modified.
type Record struct {
	Value   []byte
	Version Seq // the sequence number of the batch that last wrote the key
}

// Batch is a set of operations committed atomically.
type Batch struct{ /* unexported */ }

func (b *Batch) Put(key, value []byte)
func (b *Batch) Delete(key []byte)
// Require adds a precondition: key must be at version v, where 0 means absent.
func (b *Batch) Require(key []byte, v Seq)
// SetOrigin records who made the change, why, and to what, for the audit log.
func (b *Batch) SetOrigin(o Origin)

// Origin describes the actor, action, and target behind a batch.
// It must not contain secrets: it is kept in the audit stream.
type Origin struct {
	Actor  string // user or token identity, "(system)", or "(anonymous)"
	Action string // e.g. "oci.manifest.push"
	Target string // affected resources, human-readable, e.g. "repo/name:tag", "pkg/file.whl", "user alice"
}

// Open opens or creates the store in dir (the data directory's meta/),
// loading the latest valid snapshot and replaying the log.
// Options sets the filesystem, segment size, snapshot interval, batch size limit, and logger.
func Open(dir string, opts Options) (Store, error)
```

For backups, three functions move a store's state in and out of the snapshot file format, so a backup's metadata is exactly what the store itself would load:

```go
// WriteSnapshot writes v to w in the snapshot file format.
func WriteSnapshot(w io.Writer, v View) error
// ReadSnapshot reads and validates a snapshot and returns an in-memory view of it.
func ReadSnapshot(r io.Reader, name string) (View, error)
// Restore creates a store in dir, which must not hold one, whose state is exactly v's,
// record versions included: it writes v as the store's snapshot and starts an empty log after it.
func Restore(dir string, v View, opts Options) error
```

Errors: `ErrConflict`, `ErrClosed`, `ErrUnknownConsumer`, `ErrUnknownOutcome` and `ErrPoisoned` (a failed log write or fsync), `ErrCompacted` (`ReadLog` asked for deleted segments), `ErrBatchTooLarge`, and `*CorruptionError` (matching `ErrCorrupt`), which names the file and offset of corruption found at startup or by `ReadLog`.

### `internal/blob`

```go
// Digest is a validated content digest. v1 supports only "sha256:<64 lowercase hex>".
type Digest struct{ /* unexported */ }

func ParseDigest(s string) (Digest, error)
func (d Digest) String() string

// Store is a content-addressed blob store.
type Store interface {
	// NewUpload starts an upload whose bytes are hashed as they are written.
	NewUpload(ctx context.Context) (Upload, error)
	// ResumeUpload reopens a suspended upload, e.g. for the next chunk of an OCI chunked upload.
	// It returns ErrUploadUnknown if there is no such upload and ErrUploadBusy if it is already open.
	ResumeUpload(ctx context.Context, id string) (Upload, error)
	// Open returns the blob's content. The filesystem store returns an *os.File.
	Open(ctx context.Context, d Digest) (Reader, error)
	Stat(ctx context.Context, d Digest) (Info, error)
	// Delete removes a blob. Only garbage collection calls it.
	Delete(ctx context.Context, d Digest) error
	// Walk calls fn for every committed blob, for the GC sweep and backup.
	Walk(ctx context.Context, fn func(Info) error) error
	// PurgeUploads removes abandoned uploads: those left by an earlier process that were
	// never suspended, and those last suspended before the given time. Uploads open in
	// this process are never removed. It returns the number of uploads removed.
	PurgeUploads(ctx context.Context, before time.Time) (int, error)
}

// Upload is an in-progress, hashed, staged write.
type Upload interface {
	io.Writer
	ID() string
	Size() int64
	// Commit verifies that the content hashes to want (the zero Digest accepts any),
	// makes the blob durable and visible under its digest, and ends the upload.
	// If the blob already exists, the staged data is discarded.
	Commit(ctx context.Context, want Digest) (Info, error)
	// Suspend makes the staged bytes and the hash state durable and closes the upload
	// so ResumeUpload can continue it, also after a crash.
	Suspend() error
	// Cancel discards the upload.
	Cancel() error
}

// StagedOpener is implemented by uploads whose staged bytes other goroutines
// can read while the upload is still being written, so a caching proxy can
// stream a blob to its clients as it arrives from upstream. The filesystem
// store's uploads implement it.
type StagedOpener interface {
	// OpenStaged opens the staged bytes, including those written later.
	// The reader stays valid after the upload commits or is cancelled.
	OpenStaged() (StagedReader, error)
}

// StagedReader reads an upload's staged bytes; it is safe for concurrent use.
type StagedReader interface {
	io.ReaderAt
	io.Closer
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

// Options configures a filesystem store. The zero value uses the os package and time.Now.
type Options struct {
	FS  fsys.FS          // the filesystem; nil means fsys.OS
	Now func() time.Time // the source of commit times; nil means time.Now
}

// NewFS returns a filesystem Store rooted at dir, normally the data directory.
func NewFS(dir string, opts Options) (Store, error)
```

`ParseDigest` follows the OCI digest grammar: a well-formed digest with any algorithm other than sha256 is `ErrDigestUnsupported`, and anything else that is not `sha256:` plus 64 lowercase hex characters is `ErrDigestInvalid`.
`FromBytes` computes a digest, and `Hex` and `IsZero` complete the type; digests are comparable with `==`, and marshal as text (JSON strings) in their string form.

Errors: `ErrNotFound`, `ErrDigestMismatch`, `ErrDigestInvalid`, `ErrDigestUnsupported`, `ErrUploadUnknown`, `ErrUploadBusy` (the upload is open in another request), and `ErrUploadClosed` (the upload was already committed, suspended, or cancelled).
Any failed `Commit` or `Suspend` discards the upload.

### Crash testing

Both stores ship crash tests in M0.
They must prove the durability contract: a write is acknowledged only after it is fsynced, so it survives a power loss.

- **Filesystem interface.** The write-ahead log and the blob store perform every file operation through a small internal filesystem interface, `internal/fsys`: the write path (create, write, fsync, rename, directory fsync, remove, mkdir, and setting a modification time) and everything recovery, reopen, and reads use (open for read, read, list a directory, stat, truncate), so log and snapshot loading, blob `Walk`, `Stat`, and `Open` all see the same filesystem. Production implements it with the `os` package (`fsys.OS`), and its open returns the `*os.File` itself, which the blob store's `Open` hands out unwrapped, so `sendfile` is unaffected.
- **Simulated power loss.** Tests add a strict in-memory implementation of that interface (`fsys.Mem`). On a simulated crash it discards every write not yet fsynced (or keeps an arbitrary subset of unsynced pages), and every create, rename, remove, or mkdir whose parent directory was not fsynced afterwards. It can crash after a chosen number of mutating operations and inject a failure into any operation. Crash tests run the stores against it under concurrent load, crash at random points, reopen against the simulated post-crash state, and check that every acknowledged write is present and no partial state is visible. A missing file or directory fsync fails these tests.
- **Process crashes.** The tests also run each store in a child process, kill it with SIGKILL at random points under concurrent load, reopen it, and apply the same checks. The kernel page cache survives SIGKILL, so these tests cover process-level crashes and recovery logic, not missing fsyncs.
- **Fault injection.** Tests cover short writes, failed fsyncs, torn log tails, and corrupted acknowledged records. A failed log write or fsync must make later writes fail while views keep serving, and a corrupted acknowledged record followed by later group commits must fail startup with the corruption error.

Power-cut testing on a VM or with dm-flakey is out of scope for now.

## Interfaces for the M1 OCI and auth tasks

`internal/oci` and `internal/auth` are built in parallel as separate M1 tasks.
`internal/oci` consumes authorization through this interface, which `internal/auth` implements, including the optional `CatalogAuthorizer`; `flint serve` wires `internal/auth`'s service in. `oci.AllowAll` remains for tests.

```go
// Authorizer decides whether a request may act on a repository.
// repo is the full repository name as addressed, such as "docker-local/team/app";
// its first path component is the configured repository that permissions apply to.
// actions are "pull", "push", and "delete"; pushes ask for pull and push together.
// The base check, GET /v2/, asks with an empty repo and no actions.
// A false return means Authorize has written the response: a 401 with a
// Docker-compatible WWW-Authenticate Bearer challenge naming the scope
// (repository:docker-local/team/app:pull,push), or a 403.
type Authorizer interface {
	Authorize(w http.ResponseWriter, r *http.Request, repo string, actions ...string) bool
}

// CatalogAuthorizer is optional. Without it, GET /v2/_catalog is not served.
// AuthorizeCatalog writes the response when it returns false; visible filters
// the listed repository names.
type CatalogAuthorizer interface {
	AuthorizeCatalog(w http.ResponseWriter, r *http.Request) (visible func(repo string) bool, ok bool)
}
```

Deletes ask for `delete`, which only admins hold.
A cross-repository mount asks, with a response writer it discards, whether the caller may pull from the source; if not, it falls back to a normal upload.
`oci.Options.Actor` names the principal recorded in batch origins for the audit log: `internal/auth` records the principal it admitted in the request's context, and names it as the user, the user and API token, or `(anonymous)`.

## Interfaces for the M4 garbage collector

Every package that writes metadata tells the garbage collector what its records reference, and every batch that makes a blob visible carries the collector's precondition:

```go
// MarkFunc returns the digests of the blobs a metadata record references.
// An error means the record cannot be read.
type MarkFunc func(key, value []byte) ([]blob.Digest, error)

// Marker maps every metadata key prefix a package owns to the function
// that reads its records, or nil if they reference no blobs.
type Marker map[string]MarkFunc

// Guard reads the GC epoch and the digests' doomed entries from v, fails
// with ErrDoomed if one is doomed, and makes b require the epoch unchanged.
func Guard(v meta.View, b *meta.Batch, ds ...blob.Digest) error
```

- **Registration.** `flint serve` gives the collector the `Marker` of every package that writes metadata (`oci.GCMarker`, `pypi.GCMarker`, `upstream.Marks` for the proxy cache the formats share, `auth.GCMarker`; later formats add theirs). No prefix may start with another. The collector knows no format's encodings: it only calls the functions.
- **Unknown records stop deletion.** Marking scans the keys under the registered prefixes, and also the keys between them. A live key under no registered prefix, or a record its function cannot read, makes the run refuse to delete anything and report the key family (the key up to its second separator, such as `pypi\0file\0`), so a format that forgot to register can never lose data.
- **Proof in tests.** A format's tests write every kind of record the format can, then call `gctest.CheckMarked` or `gctest.CheckStored`, which fail on any key or record the format's marker does not cover.
- **Links.** A batch that makes a blob visible calls `Guard` with a view it read before its blob-existence check, and fails with a retryable error on `ErrDoomed`. A record that references a blob without linking it, such as a manifest listing its layers, instead requires, at the version it read, a record that references the blob and was written under the same rules, such as the layer's link.

## Package layout

Packages are created when there is code for them; this is the target layout, not a list of placeholders.

| Package | Responsibility |
| --- | --- |
| `cmd/flint` | The binary: `serve`, `backup`, `restore`, `version`, and admin subcommands. Wiring only. |
| `internal/meta` | Write-ahead-log metadata store, index, snapshots. |
| `internal/blob` | Digest type, blob store interface, filesystem implementation (S3 later). |
| `internal/config` | JSON config loading and validation. |
| `internal/server` | HTTP server, routing, TLS with hot reload, trusted-proxy handling, health endpoints. |
| `internal/repo` | Repository model (hosted, proxy, virtual), config-declared and runtime-created repositories: the virtual repository rules for every format (member order and filters, dependency-confusion protection, skipping failing members, `publishTo`), the `/<format>/<repo>/` layout, and the immutable-name rule. |
| `internal/auth` | Users, API tokens, Docker bearer-token service, OIDC, permission checks. |
| `internal/oci` | OCI distribution API: hosted and proxy repositories, referrers. |
| `internal/pypi` | PyPI simple API, JSON API, uploads: hosted, proxy, and virtual repositories. |
| `internal/upstream` | Shared upstream client and caching-proxy pieces: credentials, retries, offline fallback, the fetch policy and concurrency cap, revalidation windows, the shared fetcher with its verifier hook, the document cache, the path-cache engine, the negative cache, free-space watcher, size limits, and proxy metrics. |
| `internal/hostpattern` | The `proxy.allowHosts` host patterns, parsed alike by configuration validation and the upstream fetch policy. |
| `internal/metrics` | Prometheus text exposition. |
| `internal/gc` | Online mark-and-sweep garbage collection (M4). Since M3 it holds the GC keys and the precondition every link batch carries, which every format shares. |
| `internal/blake2b` | BLAKE2b, hand-written, for the BLAKE2b-256 digests PyPI clients send and PyPI's JSON API reports. |
| `internal/backup` | Consistent, incremental backup to a directory; verify and restore. |
| `internal/flock` | Exclusive file locks on the data and backup directories. |
| `internal/audit` | Audit log: a durable log consumer writing batch origins and touched keys to its own stream, and the admin API that reads it. |
| `internal/ui` | Server-rendered UI templates and static assets. |
| `deploy/helm/flint` | Helm chart. |

Everything is under `internal/` until a stable public Go API is a deliberate decision.

## Repository types

OCI and PyPI have hosted and caching-proxy repositories, and PyPI virtual repositories; the formats that follow build on the same [repository model](#repository-model).
Each repository has a name, and clients address it by a path prefix: an image reference such as `host/<repo>/library/nginx` for OCI, and a per-repository index URL for PyPI.
For OCI, the first path component of a repository name is the configured repository and the rest, at least one component, is an image name below it: `docker-local/team/app` is image `team/app` in repository `docker-local`, served at `/v2/docker-local/team/app/...`.
Repository names are unique across formats, so permissions and metrics name a repository unambiguously.

For PyPI, each repository is served under `/pypi/<repo>/`, following the layout of pypi.org, whose index is at `/simple/` and JSON API at `/pypi/<name>/json`:

| URL | Serves |
| --- | --- |
| `/pypi/<repo>/simple/` | root index (PEP 503 HTML or PEP 691 JSON) |
| `/pypi/<repo>/simple/<project>/` | project page; other spellings of the name redirect to the PEP 503 normalized one |
| `/pypi/<repo>/files/<project>/<filename>` | distribution file |
| `/pypi/<repo>/files/<project>/<filename>.metadata` | core-metadata file (PEP 658, PEP 714) |
| `/pypi/<repo>/legacy/` | upload, with the legacy API of twine and uv publish; hosted repositories only |
| `/pypi/<repo>/pypi/<project>/json`, `/pypi/<repo>/pypi/<project>/<version>/json` | JSON API |

Pages link files relatively (`../../files/<project>/<filename>`), so they do not depend on the host name a client used and can be cached as they are; only the JSON API, whose URLs are absolute as on PyPI, uses the request's scheme and host.
Every format lives under its own path prefix (`/v2/`, `/pypi/`), so the formats that follow PyPI (npm, Maven, Go modules, Cargo) get their own prefixes on the same server; [Repository model](#repository-model) states the rule.
The admin API's PyPI endpoints, which yank, unyank, and delete, are under `/api/v1/pypi/<repo>/`.

### Hosted

Clients push and pull first-party artifacts.
Docker tags are mutable by default; a per-repository immutable-tags setting makes a pushed tag permanent: it can be neither moved to another manifest nor deleted, and a manifest it points to cannot be deleted. Turning the setting off is the escape hatch for removing an image that must not stay.
PyPI filenames are never reusable, even after the file is deleted: a deleted file leaves a tombstone, because a re-uploaded file with different content under the same name breaks hash-pinned installs.
Names are compared in normalized form, the project name normalized with `_` (PEP 625 and the wheel file name specification) and the version canonical (PEP 440), so `Foo-1.0.tar.gz`, `foo-1.0.tar.gz`, and `foo-1.0.0.tar.gz` are one name: a `pypi\0name` record, kept forever, claims each normalized name for the spelling first uploaded. As on PyPI, a release has at most one source distribution.
The upload batch requires the file record and the name record to be absent, and an sdist upload also the project record unchanged, so of concurrent uploads under one name, or of two sdists of a release, exactly one wins; uploading the very same file again succeeds without a change, as on PyPI, so retries are harmless.
A tombstone keeps only the project, version, and deletion time, no digest, so garbage collection reclaims the file's bytes.
Hosted PyPI uploads verify the sha256, MD5, and BLAKE2b-256 digests the client sends, and store the file's core metadata (a wheel's `METADATA`, a source distribution's `PKG-INFO`) as its own blob, served as the PEP 658 metadata file where it is reliable.
Deletes are admin-only, hide the artifact immediately, and leave space reclamation to garbage collection.

Hosted repositories **never auto-delete untagged manifests.**
Deployments that pin images by digest (`image@sha256:...`) reference manifests no tag points at; deleting them would break running workloads on their next pull.
Only explicit retention policies delete, and those are opt-in (see [Cleanup and data safety](#cleanup-and-data-safety)).

### Caching proxy

A proxy repository fronts one upstream (Docker Hub, ghcr.io, quay.io, PyPI, or another registry), with optional upstream credentials.

- Digest-addressed content (blobs, manifests by digest, package files) is immutable and is **cached forever**.
- Mutable lookups (tags, package listings) are revalidated upstream after a short TTL. For Docker Hub, revalidation uses `HEAD` requests on manifests, which do not count against its pull rate limit.
- When the upstream is unreachable, the cached copy is served.

The cache keeps everything forever by default.
Upstream content disappears (deleted images, yanked tags, rate limits, outages), and a registry that evicts it can break a build that worked yesterday; disk is cheaper than that.
A size cap is available per proxy repository, opt-in.
When the disk is nearly full, new content stops being cached and is passed through from the upstream, cached content keeps serving, and an alert is raised.
flint never deletes cached content silently to make room.

For containers, a Docker Hub proxy is addressable by path prefix (`host/dockerhub/library/nginx`) and works as a containerd registry mirror.
Other upstreams (ghcr.io, quay.io) are further proxy repositories.
OCI virtual repositories, which put several registries behind one path, are planned for v1.0 on the shared virtual repository model.

Every format's proxy is built on the shared proxy core in `internal/upstream`, which guarantees:

- **Upstream outcomes.** Content the upstream answers is not found (`404` or `410`) or denied is answered `404` (`410` where the protocol distinguishes it), even if cached; what is cached for the name stays cached. An upstream that cannot be reached, or whose answer cannot be used, has the cached copy served. A refusal of flint's own credentials counts as the upstream being unreachable.
- **Documents.** Mutable upstream documents (package listings, version lists, index files) are kept in the blob store under a `cache\0doc` record, never only in memory, and streamed into it as they arrive. A document is served for the repository's revalidation window after the upstream last confirmed it, then revalidated with a conditional request (`If-None-Match`, `If-Modified-Since`); a `304` only refreshes the confirmation, which is kept in memory, and because the ETag is durable the first revalidation after a restart is a `304`, not a refetch. A document the format cannot read never replaces the cached one. Upstream bytes are stored verbatim: a document that must be rewritten (links pointing at flint) or filtered is derived when served, the derived copy is cached in memory by the stored copy's digest and the derivation within a size budget, and a document larger than a quarter of the budget is streamed through the rewriter instead of being held. Replacing a stored copy only relinks the record; garbage collection reclaims the old blob. A document that cannot be stored, such as under disk pressure, is served from memory but not marked confirmed.
- **Verification.** Content fetched by path, whose sha256 digest is not known in advance, is hashed while it is staged, and the format's verifier (sha512, sha1, md5, a git blob id, the Go `h1:` tree hash computed from the staged zip, or any other check of the staged bytes) runs before the content is committed and before any client receives its final byte. Content that fails never enters the blob store or the cache; this extends the OCI proxy's digest guarantee to every format, which matters because cached content is kept forever. Other digests a format serves are computed in the same pass, never by reading a blob again.
- **Path-addressed proxies.** One engine serves the formats whose clients name content by path: the format classifies each request as immutable (fetched once, verified, cached forever under a `cache\0file` record with its digest, size, content type, and other digests), mutable (a document, as above), or pass-through (never cached).
- **A proxy serves only what its own upstream vouched for.** Path-addressed and PyPI proxies serve only bytes their own upstream sent them: content is fetched and recorded for the repository even when the same bytes are stored for another, since a digest is not a secret. The OCI proxy links a blob already stored for another repository only after its upstream confirms with `HEAD` that it serves that digest, and size, under the requested name.
- **Negative caching.** A path-addressed proxy remembers an upstream not-found answer in memory for a minute per repository, so build tools probing for content that does not exist cost one upstream request per window.
- **Upstream concurrency.** Each proxy repository has at most `proxy.maxConcurrent` (default 64) requests in flight to its upstream, each until its response has been read; further requests wait, so a burst of client requests cannot turn into a rate-limit ban.
- **Fetch policy.** A proxy repository fetches only from its upstream's host and the hosts its format allows for that upstream (any public host for OCI blob redirects and token services, as the distribution protocol allows; `files.pythonhosted.org` for pypi.org), plus `proxy.allowHosts`; redirects are followed only to allowed hosts. flint refuses to connect to loopback, link-local, private, shared (`100.64.0.0/10`), and unspecified (`0.0.0.0/8`) addresses, and to IPv6 addresses embedding one (NAT64, 6to4), for any host except those the configuration names (the upstream URL's host and `proxy.allowHosts`); the check runs on the resolved address at dial time, so upstream metadata can never steer flint at internal services. Credentials are sent only to the configured upstream host. Anyone who may read a proxy repository can read what its upstream account can read.
- **Disk pressure and size limits** apply to every format: content that would bring the free space below `proxyCache.minFreeSpace`, or does not fit a repository's opt-in `sizeLimit`, is passed through, still verified, and the size limit evicts the least recently pulled items by deleting their records, with pull times saved in periodic batches.

How the OCI proxy meets these rules (M2):

- **Shared upstream client.** `internal/upstream` holds what every format's proxies share: the registry token handshake (anonymous or with credentials read from a file at each authentication, never logged), retries with backoff for transient failures, and an offline mark: after a request fails for good, the upstream counts as offline for 30 seconds, during which lookups that have a cached copy serve it without asking. A request the fetch policy refuses is neither retried nor marks the upstream offline. It also holds the fetcher, the free-space monitor, and a group that collapses concurrent identical lookups, so a stale tag pulled by many clients at once costs one revalidation.
- **Same storage as hosted.** Cached content is stored in the one blob store and linked to the proxy repository with the same `oci\0blob`, `oci\0manifest`, `oci\0tag`, and `oci\0referrer` records hosted repositories use, under the same garbage-collection precondition, so garbage collection marks cached content like any other. A blob already stored for another repository is linked only after the upstream confirms with `HEAD` that it has the blob under the requested name, since a digest is not a secret.
- **Tags.** The revalidation window is per repository (`revalidateAfter`, default 5 minutes). When the upstream last confirmed a tag is kept in memory only, so after a restart each tag is revalidated on its first pull. A tag the upstream cannot be reached to confirm (network errors, timeouts, `5xx`, `429`) keeps being served from the cache; a tag the upstream answers is not found or denied is answered `404`, even if cached, while a refusal of flint's own credentials or an unusable authentication challenge counts as the upstream being unreachable. Tag listings and referrers come from the upstream, kept in memory for the window, with the cached tags and referrers as the fallback when the upstream cannot be reached; a tag listing the upstream answers is not found or denied is answered `404`, and an upstream without the referrers API is answered from the cached referrers.
- **Fetching.** A blob that is not cached is fetched once however many clients ask for it at the same time: the fetch writes it to a blob store upload, and every client streams the upload's staged bytes as they arrive (`blob.StagedOpener`), at its own pace. The fetch runs independently of the requests, so a client that disconnects does not cancel it, and stalls are bounded by an idle timeout. The upload verifies the digest at commit, and clients receive the final byte only after that, so no client gets the whole of a blob that fails verification and it never enters the cache. Manifests are verified before they are served. Content passed through without caching is verified the same way while it streams.
- **Disk pressure.** Free space on the data directory's filesystem is measured with `statfs` (`proxyCache.minFreeSpace`, default 5% of the filesystem). Fetches reserve the size of what they are about to store, so concurrent fetches cannot overrun the threshold together. Content that would cross it is passed through; entering and leaving that state is logged, and the `flint_proxy_disk_pressure` gauge is the alert.
- **Size limit.** With `sizeLimit`, the repository's cached items (each blob link and manifest record, with its size) and their last-pull times are held in memory. Pull times are saved in periodic batches (`oci\0pulled\0...`, every minute), never one metadata write per pull. Over the limit, the least recently pulled items are evicted by deleting their records (a manifest's tags and referrers entry with it), each batch requiring the records unchanged so a concurrent re-cache is not lost. As for any delete, garbage collection reclaims the bytes later. Content larger than the limit is passed through.
- **Read-only.** Proxy repositories refuse pushes and deletes. Pulls use the same permission model as hosted repositories; with anonymous pull, a client pulls without a token, which is how containerd mirrors reach flint. containerd's `ns` query parameter is ignored: the repository in the path decides the upstream.

How the PyPI proxy meets the same rules (M3), with the same shared pieces:

- **Project pages are documents.** A page is fetched from the configured simple index URL, asking for PEP 691 JSON and reading PEP 503 HTML too, and kept by the shared document cache under `cache\0doc\0<repo>\0<project>`, verbatim with the URL it came from, so relative links resolve; it is read into flint's own form, with links pointing back at flint, when served, and decoded pages are kept in a small in-memory cache keyed by their digest, which never goes stale. Revalidation, outages, not-found answers, and disk pressure follow the document rules above. Page records of earlier versions (`pypi\0page`) are deleted at startup; their pages are fetched again when next asked for.
- **A page lists only its own project's files.** An upstream entry whose file name does not belong to the project is dropped, and cached file and core-metadata records name the project they were cached for, so a page of one project cannot stand in for another project's cached files.
- **Files are digest-addressed content.** The page names each file's sha256 digest, which is the blob store's digest, so a file is fetched once through the shared fetcher from where the page links, within the fetch policy (often another host, which never gets the upstream credentials), verified at commit, cached forever, and linked with a `pypi\0file` record under the GC precondition. A proxy repository serves only bytes its own upstream sent it: a file is fetched even when a blob with its digest is already stored for another repository, since a digest is not a secret and a page can name any digest; the content-addressed blob store still stores the bytes once. A file whose entry has no sha256 digest cannot be verified and is passed through without being cached. Core-metadata files are fetched, verified against the page's metadata digest, and cached the same way, under the same rule.
- **Disk pressure and size limits** use the shared free-space watcher and size-limit tracker; files and metadata files count against a size limit, pages do not.

### Virtual

A virtual repository serves one merged view over an ordered list of hosted and proxy repositories of its format, so clients need a single URL.
v1 has virtual repositories for PyPI, and OCI and the first-wave formats build on the same model.
The rules are format-agnostic and live in `internal/repo`; each format decides what owning a name means, how names are normalized, and how members' answers merge.

- **Members and filters.** Each member may carry `include` and `exclude` package-name patterns, in which `*` matches any run of characters, as in permission grants. A member is consulted for a name only if the name matches one of its include patterns (any name when it has none) and none of its exclude patterns. Names and patterns are compared after the format's normalization (PEP 503 for PyPI; the exact name for npm, `groupId:artifactId` for Maven, the module path for Go, lowercase with `-` and `_` equal for Cargo).
- **Dependency-confusion protection**, on by default: if a hosted member that the filters admit owns a name, only hosted members are consulted for it, so upstream versions of a name a hosted member owns are never served, and the proxies are not even asked. A hosted member owns a name it holds published, yanked or deprecated, or as a tombstone. Filters close the gap ownership alone leaves, such as an internal name not published yet: an exclude pattern for every internal scope, group, or prefix on the proxy members keeps a public package under that name out.
- **Merging.** Otherwise members are consulted in order. Listings merge by union, and where members have the same version or file, the first member's wins, files and metadata alike; a file is served from the member whose listing supplied it. Pointers a format defines (npm dist-tags, Go `@latest`) come from the first member that has the name; pointers a format computes (Maven `latest` and `release`) are computed from the merged listing.
- **Failing members.** A member that fails, such as a proxy whose upstream cannot be reached with nothing cached, is skipped: the response is built from the other members, the skip is logged, and `flint_virtual_member_skips_total` counts it. The request fails only if no member could answer.
- **Publishing.** An optional `publishTo` names one hosted member that receives what clients publish to the virtual repository, so one URL serves both install and publish. Without it, a virtual repository refuses publishes, naming its hosted members.
- **Permissions.** Reading through a virtual repository needs `read` on it only; members' permissions are not consulted. Publishing through it needs the permissions publishing to its `publishTo` member needs.

For PyPI:

- A hosted repository owns a project from the first upload of one of its files; the `pypi\0project` record is kept forever, so deleting every file does not hand the name back to the upstream.
- A project page merges the pages of the members that may serve it by file name, the first member's file winning, and the virtual repository's file URLs resolve to that member. The JSON API merges the same way, and the root index lists the projects each member's filters admit.

## Repository model

- **URL layout.** Every format but OCI serves a repository at `/<format>/<repo>/`, such as `/pypi/<repo>/` and later `/npm/<repo>/`, `/maven/<repo>/`, `/go/<repo>/`, `/cargo/<repo>/`, and `/generic/<repo>/`. OCI stays at `/v2/<repo>/...`, which its protocol fixes. A request whose format segment does not match the repository's format is a `404`. The format segment keeps repository names from colliding with flint's own paths (`/v2/`, `/api/`, `/auth/`, `/metrics`, `/healthz`, `/readyz`, `/.well-known/`, the UI) and lets the server dispatch without a lookup. Repository names stay one namespace across formats, so a permission grant addresses one name.
- **Formats and settings.** The configuration accepts a format once flint serves it, with the repository types that format supports. A format with settings of its own has a settings object named after it, such as `"maven": {...}`, allowed only on repositories of that format and validated as strictly as the rest of the file.
- **Public URL.** An optional top-level `publicURL` is the base of every absolute URL flint writes into the metadata it serves (the PyPI JSON API today; npm tarball URLs, Cargo's `config.json`, and NuGet's service index later), so clients that store those URLs, as in lockfiles, see one stable URL however they reached flint. Without it, absolute URLs are built from the request's scheme and host as seen through trusted proxies. Where a protocol allows relative URLs (PyPI pages, Helm indexes), flint writes relative ones. Upstream bytes are stored verbatim and rewritten when served, so changing `publicURL` needs no cache flush.
- **Immutable names.** A published version or file never changes. Path-shaped formats (Maven, generic files) accept an upload of identical content to a published name again without a change, because build tools retry individual file uploads, and refuse different content with `409`. Publish-shaped formats (npm, Cargo, PyPI, NuGet) refuse a duplicate version, as their public registries do (PyPI accepts the very same file again, as PyPI does). Deleting an immutable name leaves a tombstone, and the name is never usable again, not even with identical content; this is PyPI's rule for file names, applied to every format.

## Spec coverage

### OCI and Docker

- OCI Distribution Spec v1.1, passing the official conformance suite: pulls, pushes (monolithic, chunked, and streamed uploads), cross-repository blob mount, deletes, and paginated tag and catalog listings.
- The referrers API, including the `subject` field on pushed manifests.
- Docker image manifest v2 schema 2 and manifest lists; OCI image manifests and indexes; multi-arch images.
- Arbitrary OCI artifacts, such as Helm charts and signatures, by media type.
- A classic Helm chart repository view (`index.yaml` and chart archives) at `/helm/<repo>/` over the charts pushed with `helm push` to a hosted repository with `helmIndex`. Nothing is stored for it: the index is derived from the tags and manifest records, written as JSON (which Helm reads as JSON or, before 3.17, as YAML, so flint needs no YAML code), and cached in memory until a tag in the view changes.
- Not supported: Docker schema 1.

### PyPI

- Simple repository API: PEP 503 (HTML) and PEP 691 (JSON), with content negotiation.
- PEP 658 and PEP 714 core-metadata files served alongside distributions.
- PEP 592 yanking.
- PEP 700 fields (versions, file sizes, upload times).
- The legacy upload API used by `twine upload` and `uv publish`.
- The JSON API at `/pypi/<name>/json` (per repository, `/pypi/<repo>/pypi/<name>/json`), with `info` from the core metadata of the latest release.
- Deferred: trusted publishing and PEP 740 attestations. Never: XML-RPC search.

## Auth and permissions

- **Identities.** Local users with passwords and groups, and OIDC login, in v1. LDAP is deferred. Passwords are hashed with PBKDF2-HMAC-SHA256 (`crypto/pbkdf2`) at a high iteration count, since bcrypt and Argon2 live outside the standard library.
- **API tokens.** Random, high-entropy secrets, shown once and stored only as a SHA-256 hash. Tokens can be given an expiry and carry a subset of their owner's permissions, never more: on each use the owner's current role is capped by the token's scopes.
- **Docker clients.** A built-in bearer-token service implements the Docker token authentication flow, issuing short-lived JWTs scoped to repositories and actions (pull, push, delete). The JWTs are hand-written and signed with an Ed25519 key generated on first start and kept in the data directory. Each registry request also checks the subject's current permissions, so deleting a user or revoking a token takes effect before the JWT expires.
- **PyPI clients.** HTTP basic auth with the `__token__` username convention and an API token as the password, or a user name and its password or token. `internal/pypi` consumes it through `Permit(r, repo, actions...)`, which `internal/auth` implements: it answers as an HTTP status, and the PyPI handler writes the response with a `Basic` challenge.
- **Other package clients.** An API token is also accepted as `Authorization: Bearer <token>` (told apart from the token service's JWTs by its `flint_` prefix), as `Authorization: <token>` with no scheme, and in `X-NuGet-ApiKey`. Each route family challenges in its clients' style: Docker `Bearer` for `/v2/`, `Basic realm="flint"`, Cargo's `login_url`, or a plain `401`. A client's login command can mint an owned, named API token that expires after `auth.loginTokenTTL`. Clients that send no credentials for downloads get signed URLs: an HMAC-SHA256 over the path, an expiry, and the requesting principal, valid until the expiry and only while that principal may still read the repository. Reading through a virtual repository needs `read` on it only; publishing through it needs `write` on its `publishTo` member.
- **Permissions.** Per-repository roles (`read` < `write` < `delete` < `admin`) are granted to users or groups. Grants can target a pattern such as `team-a-*`. One global `admin` role administers everything. Anonymous pull is a per-repository setting, off by default.
- **First administrator.** Created at startup from a password file named in the configuration when no administrator exists, so Kubernetes can mount it from a Secret.
- **SAML.** Never hand-written. SAML depends on XML signature verification and canonicalization, a long-running source of authentication bypasses even in mature libraries; writing it from scratch would be irresponsible. Enterprises that need SAML run an OIDC bridge such as Keycloak or Dex.
- **Later.** GitHub Actions trusted publishing shortly after v1; LDAP after that.

[auth.md](auth.md) describes the client-visible behavior and the admin API.

## Operations

- **Configuration.** One JSON file. Repositories and permissions declared in config are read-only through the API; repositories created through the API or UI are also allowed and live in the metadata store. Users and tokens are runtime data. The Helm chart renders YAML values to the JSON config.
- **TLS.** Served from certificate files, reloaded when they change. flint is proxy-aware: forwarded headers are trusted only from a configured trusted-proxy list. Built-in ACME comes after v1.
- **UI.** A small server-rendered UI (`html/template` plus hand-written JavaScript, no npm build chain) to browse repositories, tags, packages, layers, and signatures, and to manage one's own tokens. Administration is through the API and config.
- **Observability.** A Prometheus metrics endpoint, structured JSON logs via `log/slog`, and liveness and readiness endpoints. An audit log of every change is derived from the write-ahead log's batch origins: the audit log is a durable log consumer that writes one record per batch to its own append-only stream under `audit/`, never including operation values, so password hashes, token hashes, and other values never reach it (see the metadata store guarantees). It writes and fsyncs records before checkpointing, so the write-ahead log keeps every batch whose record may not be durable, and after a crash it resumes after its last durable record without losing or repeating one. The stream is retained separately (retention configurable by age and size, keep forever by default, deleting whole segments), so audit history never depends on log segment lifetime. Administrators query it, filtered by time, actor, action, and target, and export it as JSON lines through the admin API. OpenTelemetry is deferred.
- **Releases.** Static binaries for linux and darwin on amd64 and arm64; a multi-arch `FROM scratch` image and a Helm chart on `ghcr.io/terrabyteian`; cosign signatures and an SBOM produced in CI. The chart lives in this repository. flint's own image and chart stay on ghcr.io permanently, so a broken flint can always be redeployed without depending on itself.

## Cleanup and data safety

- **Garbage collection** is online mark-and-sweep with no read-only mode. Marking walks a metadata view and collects every referenced digest; sweeping removes blobs that are unmarked and older than a 24-hour grace period. The grace period protects blobs committed but not yet linked, such as in-flight uploads. The sweep uses a GC epoch counter (`gc\0epoch`): its start batch bumps the epoch and records the doomed set (`gc\0doomed\0<digest>`), and its end batch clears the doomed set. Every link batch, from an upload or a mount, reads the epoch and the digest's doomed entry from the same view, commits with a `Require` on that epoch, and fails with a retryable error if the digest is doomed in that view or the precondition fails; a mount then falls back to a normal upload. Two guarantees make a concurrent link and sweep unable to both succeed: the sweep deletes only doomed blobs that are unreferenced in a view taken after its start batch and in every view pinned with the garbage collector (such as a running backup's), and a link reads the epoch and the doomed entry from one view before its blob-existence check (`Upload.Commit` or the mount's source check), so a sweep that starts after that read makes its precondition fail and a sweep already running is caught by the doomed entry in that view. The `internal/gc` package documentation describes the algorithm that meets these guarantees, and its tests, including crash tests and deterministic interleavings of links with sweeps, prove them.
- **Garbage-collection decisions.**
  - The grace period is 24 hours by default, configurable, and never below one hour; it counts from the blob's commit time.
  - A blob is referenced while any record a `Marker` reads names it: in OCI, a blob link, a manifest record (its own bytes, config, layers, and child manifests), a tag, or a referrers entry (not its subject); in PyPI, a hosted file (its bytes and core metadata, but not once it is a tombstone), or a file or core-metadata file a proxy repository cached; in the proxy cache the formats share, a document, such as a PyPI project page, or a file a proxy repository cached.
  - A blob link, in a hosted or proxy repository, is a root only while a manifest stored in its repository name is its blob or lists it (as a config, layer, or child manifest), or its link time, its last read by a blob `HEAD` or `GET`, or the server's start is within the grace period. Reads are kept in memory, not written, so the server's start is their floor. A run first removes the other links, through the `Pruner` the OCI package registers: it finds them in the view it marks, which skips them, and removes each only if it, and its repository name's manifest generation key, are still at the versions it found, and it was not read since; reads wait while a removal commits. Every batch that writes a manifest record writes that generation key without a precondition, so manifest pushes never conflict with each other, while a push and a removal of a link it references cannot both commit: a push after the removal's view changes the key, and one before it requires the link unchanged and fails with `MANIFEST_BLOB_UNKNOWN`. So a manifest delete by any client reclaims the manifest's bytes, and its config and layers once nothing else uses them. Removing a link only takes a reference away, so it needs no epoch precondition; blobs are deleted only by the sweep. A link written before link times were recorded counts as past the grace period.
  - A sweep runs in rounds of at most 50,000 doomed blobs. A round writes its doomed set in batches, the last of which increments the epoch and is the round's start batch; it then takes a view and only after that reads the pinned views, so a view pinned meanwhile follows that view and holds no reference to a doomed blob that view lacks.
  - A doomed set left by a crash is cleared at startup and before every run, without deleting more; the next run starts over.
  - One run at a time, started through the admin API (`flint gc`) or by `gc.interval`, which counts from the start of the previous run; the last run's report is kept in the metadata, so the schedule survives restarts. A dry run writes and deletes nothing and reports what it would delete.
  - Every deleted blob and removed link is logged. A run that cannot finish clears its doomed set and reports what it deleted.
  - A proxy pull that finds the stored copy of a blob doomed serves it without linking it, and fetches it again next time; a mount falls back to an upload, and other links fail with `503` and `Retry-After`.
  - Abandoned upload sessions and staged upload data are removed by the upload expiry, 24 hours after the session started or the data was last written, not by garbage collection.
- **Deletes** hide immediately in metadata; garbage collection reclaims space later.
- **Retention policies** (for example, keep the last N tags matching a pattern, or delete untagged manifests older than X) are designed now and built shortly after v1. They are the only mechanism that deletes untagged manifests in hosted repositories.
- **Backup** is a built-in v1 command: it writes a consistent metadata snapshot plus every blob not already present in the target directory, so repeated backups are incremental. Backup takes and pins its metadata view with the garbage collector in one step and holds it until it finishes copying, so the sweep's deletion check covers it and every blob its snapshot references is still present when it is copied. [backup.md](backup.md) is the operator's guide; the decisions behind it:
  - **It runs in the server.** Only the live process can pin a view with the garbage collector, so a backup is started through the admin API (`POST /api/v1/backup`, global admin), which `flint backup` drives and waits on. The target is `backup.directory` from the configuration, never a path in the request, so an admin token cannot make the server write elsewhere. One backup runs at a time, and a `LOCK` file in the target keeps out another process.
  - **The target is a content-addressed blob store** (`internal/blob`'s filesystem layout) shared by every backup in it, plus `backups/<id>/` holding the metadata snapshot (`meta.WriteSnapshot` of the pinned view), the list of blobs the backup needs, and `backup.json`. Copies go through blob store uploads, so each is verified against its digest and fsynced before it counts. `backup.json` records the digests of the other two files and is renamed into place, then its directory fsynced, only after everything else is durable, so an interrupted backup never looks complete. Nothing is deleted from the target, not even incomplete backups.
  - **It copies every blob in the data directory**, not only those it can tell are referenced, so a backup never depends on every format package reporting its references correctly: every blob the view references was committed before the view was taken, so the blob walk finds it, and a blob that disappears during the walk was unreferenced. Each format package also reports the blobs its records reference (`oci.References`, `pypi.References`), and the backup fails if one is missing.
  - **Restore** (`flint restore`) writes a backup into a new, empty data directory with `meta.Restore`, re-verifying every blob as it copies it, behind a `RESTORE-INCOMPLETE` marker that `flint serve` refuses. The restored store keeps every record's version and continues the log after the backup's sequence number. `flint backup verify` checks a backup the same way without restoring it.
  - **Secrets.** A backup holds the metadata, including password and API token hashes, but not the signing keys: a restored server generates new ones, which only invalidates bearer tokens and signed URLs that live minutes anyway, so backups never contain private key material. The configuration file and the files it names (TLS keys, the bootstrap password, upstream credentials) belong to the deployment and are not backed up either.

## Roadmap

| Milestone | Scope |
| --- | --- |
| M0 foundation | This design document, Go module, CI, write-ahead-log metadata store, blob store, crash tests. |
| M1 hosted OCI | Hosted OCI repositories passing the conformance suite, local users and tokens, Docker token auth, metrics and logs, image and chart on ghcr.io, first homelab deployment. |
| M2 container proxy | Docker Hub proxy and containerd mirror. |
| M3 PyPI | PyPI hosted, proxy, and merged virtual index. |
| M4 | Garbage collection, backup, UI, audit log, OIDC. |
| v1.0 | M4 plus the first wave of formats on the shared format core: npm, Maven, Go modules (proxy and virtual), Cargo, generic files, the classic Helm view, and OCI virtual repositories; tagged v1.0. A first-wave format not ready when the rest is ships in v1.1. |
| v1.1 | First-wave formats that missed v1.0; then NuGet and Terraform. |
| After v1 | S3 storage, retention policies, trusted publishing, ACME, LDAP, then multi-server HA. |
