# flint design

This document describes what flint is, the decisions that shape it, and how its parts fit together.
It is the reference for contributors: read it before changing storage, metadata, auth, or the dependency rule.
When a decision here changes, update this document in the same pull request.

## Goals

flint is an artifact registry: a self-hosted replacement for JFrog Artifactory, built from scratch.

- Serve container images and OCI artifacts, and Python packages, from one server.
- Host first-party artifacts and cache upstream registries (Docker Hub, ghcr.io, quay.io, PyPI) behind the same endpoint.
- Be efficient: one static binary plus a data directory, low memory per artifact, streaming I/O, zero-copy reads.
- Be safe with data: an acknowledged write survives a crash, and nothing is ever deleted silently.
- Be product quality. flint starts as a personal homelab registry, but its design must hold up for an open-source product used by large-ish enterprises: multi-terabyte storage and a few hundred concurrent clients on one server.

## Non-goals

- **Migration from Artifactory.** flint is a fresh build; there is no import tool.
- **Multi-server high availability in v1.** v1 is a single server. The data layout and metadata store are designed so HA can be added later without a data migration (see [High availability later](#high-availability-later)).
- **Every package format.** v1 supports OCI/Docker and PyPI. Other formats come later, on the same storage and metadata core.
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
Go's standard library covers the whole protocol stack, cross-compiles static binaries trivially, and gives `sendfile` reads through plain `io.Copy`.
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
  uploads/                     in-progress uploads; must be on the same filesystem as blobs/
  meta/wal/<seq>.log           write-ahead log segments, named by first sequence number
  meta/snapshots/<seq>.snap    index snapshots, named by the last sequence number they contain
```

Paths contain no node identity, so a later HA deployment can reuse the layout unchanged.

## Blob store

The blob store is a content-addressed store keyed by sha256 digest.
It holds bytes only; it does not know about repositories, formats, or access control.

### Write path

1. A new upload creates a temp file under `uploads/`.
2. Bytes stream into the temp file while a SHA-256 hash is updated incrementally. Nothing is buffered in memory beyond a copy buffer.
3. An upload can span several requests (OCI chunked uploads). Between requests the upload's hash state is persisted with the hash's `encoding.BinaryMarshaler` implementation, so resuming does not re-read the data.
4. On commit the computed digest is checked against the digest the client claimed; a mismatch discards the upload.
5. The temp file is fsynced, renamed atomically to `blobs/sha256/<ab>/<digest>`, and the fan-out directory is fsynced so the rename is durable.
6. If the blob already exists, the temp file is dropped and the existing blob is reused. Identical content is stored once.
7. Only after the blob is durable does the caller write the metadata **link record** that makes the blob visible in a repository.

A crash between steps 5 and 7 leaves an unlinked blob.
That is safe: garbage collection reclaims it after its grace period.
A cross-repository blob mount is only step 7: a new link record, no data copied.

### Read path

1. The caller checks the per-repository link record in the metadata store. A blob that exists only for another repository is a 404: digests are not secrets, and possession of one must not grant access.
2. The blob is opened and streamed. The filesystem store returns the `*os.File` itself, unwrapped, so `net/http`'s copy path can use `sendfile` and bytes never pass through user space.

### Storage interface

The blob store sits behind a small interface.
v1 ships the filesystem implementation; an S3 implementation (hand-written SigV4, multipart uploads, presigned-URL redirects for reads) follows shortly after v1.
S3 redirect support will be an optional extra interface that the read path checks for, so the core interface stays small.

## Metadata store

The metadata store is an ordered key-value map in which every change is a durable, sequenced log entry.
It is a hand-written append-only write-ahead log, an in-memory index, and periodic snapshots.

- **Log.** Each committed batch is one log record: a length, a CRC-32C checksum, the sequence number, a record format version, and the encoded operations. Segments rotate by size.
- **Index.** An in-memory ordered index of all live keys. Ordered iteration serves prefix scans and paginated listings (tags, catalog, package files). The index is copy-on-write (for example a persistent B-tree with path copying), so a read view is a root pointer: views are consistent and cheap, and long scans such as garbage-collection marking or backup never block writers.
- **Snapshots.** In the background, the store writes the index as of some sequence number to a temp file, fsyncs it, and renames it into place. Log segments wholly covered by the latest snapshot are then deleted.
- **Startup.** Load the latest valid snapshot, then replay the log after its sequence number. A torn record at the log's tail (a crash mid-write) fails its checksum and is truncated; it was never acknowledged.
- **Durability and group commit.** A commit returns only after its log record is fsynced. A single writer goroutine drains all pending batches, appends them, issues one fsync, then acknowledges them all, so concurrent writers share fsync cost.
- **Versioned records.** Log records carry a format version, and values written by format packages start with their own schema version byte, so encodings can evolve while old logs and snapshots still load.
- **Preconditions.** A batch can require that a key is absent or still at a given version, and it fails atomically if not. This implements immutable tags, never-reusable PyPI filenames, and safe concurrent updates without locks held across requests.
- **Scale target.** About 10 million records in 2 to 4 GB of RAM. Values use compact binary encodings via `encoding/binary` rather than JSON, and the index avoids per-record pointers where it can to keep garbage-collector scanning cheap.

The store does not interpret keys or values.
Each package owns a key namespace, and keys use `0x00` as a separator so a prefix scan is unambiguous even though OCI repository names contain `/`.
Illustrative v1 key space:

| Key | Value | Owner |
| --- | --- | --- |
| `repo\0<repo>` | repository created at runtime | `internal/repo` |
| `oci\0blob\0<repo>\0<name>\0<digest>` | blob link | `internal/oci` |
| `oci\0manifest\0<repo>\0<name>\0<digest>` | manifest record (media type, size, subject, referenced digests) | `internal/oci` |
| `oci\0tag\0<repo>\0<name>\0<tag>` | manifest digest | `internal/oci` |
| `pypi\0file\0<repo>\0<filename>` | file record, kept as a tombstone after delete | `internal/pypi` |
| `auth\0user\0<username>` | user record | `internal/auth` |
| `auth\0token\0<token-id>` | token record with hashed secret | `internal/auth` |

An index on disk can later replace the in-memory one behind the same interface if the record count outgrows RAM.

### High availability later

HA is deferred, but nothing in v1 may block it:

- The metadata log is a sequence of deterministic batches with preconditions. In HA mode, the log becomes a Raft-replicated log: `Commit` proposes the batch, and every node applies committed entries in order to its index. Snapshots become Raft snapshots.
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

	// View returns a consistent read-only view as of the latest committed batch.
	// Views are cheap; they must be released.
	View() View

	// Close flushes and closes the log. Pending commits fail with ErrClosed.
	Close() error
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
// SetOrigin records who made the change and why; the audit log is derived from it.
func (b *Batch) SetOrigin(o Origin)

// Origin describes the actor and action behind a batch.
type Origin struct {
	Actor  string // user or token identity, or "system"
	Action string // e.g. "oci.tag.put"
	Time   time.Time
}

// Open opens or creates the store in dir, loading the latest snapshot and replaying the log.
func Open(dir string, opts Options) (Store, error)
```

Errors: `ErrConflict`, `ErrClosed`, and a corruption error that names the segment and offset when a record other than the torn tail fails its checksum.

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
	ResumeUpload(ctx context.Context, id string) (Upload, error)
	// Open returns the blob's content. The filesystem store returns an *os.File.
	Open(ctx context.Context, d Digest) (Reader, error)
	Stat(ctx context.Context, d Digest) (Info, error)
	// Delete removes a blob. Only garbage collection calls it.
	Delete(ctx context.Context, d Digest) error
	// Walk calls fn for every committed blob, for the GC sweep and backup.
	Walk(ctx context.Context, fn func(Info) error) error
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
	// Suspend persists the hash state and closes the upload so ResumeUpload can continue it.
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

// NewFS returns a filesystem Store rooted at dir.
func NewFS(dir string) (Store, error)
```

Errors: `ErrNotFound`, `ErrDigestMismatch`, `ErrUploadUnknown`.

### Crash testing

Both stores ship crash tests in M0.
The tests run the store in a child process, kill it with SIGKILL at random points under concurrent load, reopen it, and check that every acknowledged write is present and no partial state is visible.
Fault-injection tests cover short writes, failed fsyncs, and torn log tails.

## Package layout

Packages are created when there is code for them; this is the target layout, not a list of placeholders.

| Package | Responsibility |
| --- | --- |
| `cmd/flint` | The binary: `serve`, `backup`, `version`, and admin subcommands. Wiring only. |
| `internal/meta` | Write-ahead-log metadata store, index, snapshots. |
| `internal/blob` | Digest type, blob store interface, filesystem implementation (S3 later). |
| `internal/config` | JSON config loading and validation. |
| `internal/server` | HTTP server, routing, TLS with hot reload, trusted-proxy handling, health endpoints. |
| `internal/repo` | Repository model (hosted, proxy, virtual), config-declared and runtime-created repositories. |
| `internal/auth` | Users, API tokens, Docker bearer-token service, OIDC, permission checks. |
| `internal/oci` | OCI distribution API: hosted and proxy repositories, referrers. |
| `internal/pypi` | PyPI simple API, JSON API, uploads: hosted, proxy, and virtual repositories. |
| `internal/upstream` | Shared upstream client: credentials, revalidation TTLs, offline fallback. |
| `internal/metrics` | Prometheus text exposition. |
| `internal/gc` | Online mark-and-sweep garbage collection. |
| `internal/backup` | Consistent backup to a directory. |
| `internal/ui` | Server-rendered UI templates and static assets. |
| `deploy/helm/flint` | Helm chart. |

Everything is under `internal/` until a stable public Go API is a deliberate decision.

## Repository types

v1 has hosted and caching-proxy repositories for both formats, plus virtual repositories for PyPI.
Each repository has a name, and clients address it by a path prefix: an image reference such as `host/<repo>/library/nginx` for OCI, and a per-repository index URL for PyPI. The exact URL layout is settled with each format's milestone.

### Hosted

Clients push and pull first-party artifacts.
Docker tags are mutable by default; a per-repository immutable-tags setting makes a pushed tag permanent.
PyPI filenames are never reusable, even after the file is deleted: a deleted file leaves a tombstone, because a re-uploaded file with different content under the same name breaks hash-pinned installs.
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
OCI virtual repositories are deferred; the hosted-plus-proxy pattern covers v1 needs.

### Virtual (PyPI only in v1)

A PyPI virtual repository serves one merged index over an ordered list of hosted and proxy repositories, so `pip` and `uv` need a single index URL.
Dependency-confusion protection is on by default: once a hosted member repository owns a package name, upstream versions of that name are never served through the virtual repository.

## Spec coverage

### OCI and Docker

- OCI Distribution Spec v1.1, passing the official conformance suite: pulls, pushes (monolithic, chunked, and streamed uploads), cross-repository blob mount, deletes, and paginated tag and catalog listings.
- The referrers API, including the `subject` field on pushed manifests.
- Docker image manifest v2 schema 2 and manifest lists; OCI image manifests and indexes; multi-arch images.
- Arbitrary OCI artifacts, such as Helm charts and signatures, by media type.
- Not supported: Docker schema 1.

### PyPI

- Simple repository API: PEP 503 (HTML) and PEP 691 (JSON), with content negotiation.
- PEP 658 and PEP 714 core-metadata files served alongside distributions.
- PEP 592 yanking.
- PEP 700 fields (versions, file sizes, upload times).
- The legacy upload API used by `twine upload` and `uv publish`.
- The JSON API at `/pypi/<name>/json`.
- Deferred: trusted publishing and PEP 740 attestations. Never: XML-RPC search.

## Auth and permissions

- **Identities.** Local users with passwords and groups, and OIDC login, in v1. LDAP is deferred. Passwords are hashed with PBKDF2-HMAC-SHA256 (`crypto/pbkdf2`) at a high iteration count, since bcrypt and Argon2 live outside the standard library.
- **API tokens.** Random, high-entropy secrets, shown once and stored only as a SHA-256 hash. Tokens expire and carry a subset of their owner's permissions, never more.
- **Docker clients.** A built-in bearer-token service implements the Docker token authentication flow, issuing short-lived JWTs scoped to repositories and actions (pull, push, delete).
- **PyPI clients.** HTTP basic auth with the `__token__` username convention and an API token as the password.
- **Permissions.** Per-repository roles (`read`, `write`, `delete`, `admin`) are granted to users or groups. Grants can target a pattern such as `team-a-*`. One global `admin` role administers everything. Anonymous pull is a per-repository setting, off by default.
- **SAML.** Never hand-written. SAML depends on XML signature verification and canonicalization, a long-running source of authentication bypasses even in mature libraries; writing it from scratch would be irresponsible. Enterprises that need SAML run an OIDC bridge such as Keycloak or Dex.
- **Later.** GitHub Actions trusted publishing shortly after v1; LDAP after that.

## Operations

- **Configuration.** One JSON file. Repositories and permissions declared in config are read-only through the API; repositories created through the API or UI are also allowed and live in the metadata store. Users and tokens are runtime data. The Helm chart renders YAML values to the JSON config.
- **TLS.** Served from certificate files, reloaded when they change. flint is proxy-aware: forwarded headers are trusted only from a configured trusted-proxy list. Built-in ACME comes after v1.
- **UI.** A small server-rendered UI (`html/template` plus hand-written JavaScript, no npm build chain) to browse repositories, tags, packages, layers, and signatures, and to manage one's own tokens. Administration is through the API and config.
- **Observability.** A Prometheus metrics endpoint, structured JSON logs via `log/slog`, and liveness and readiness endpoints. An audit log of every change is derived from the write-ahead log's batch origins. OpenTelemetry is deferred.
- **Releases.** Static binaries for linux and darwin on amd64 and arm64; a multi-arch `FROM scratch` image and a Helm chart on `ghcr.io/terrabyteian`; cosign signatures and an SBOM produced in CI. The chart lives in this repository. flint's own image and chart stay on ghcr.io permanently, so a broken flint can always be redeployed without depending on itself.

## Cleanup and data safety

- **Garbage collection** is online mark-and-sweep with no read-only mode. Marking walks a metadata view and collects every referenced digest; sweeping deletes blobs that are unmarked and older than a 24-hour grace period. The grace period protects blobs committed but not yet linked, such as in-flight uploads. A concurrent link of an old, unreferenced blob (a cross-repository mount, or a re-push of identical content) must not race the sweep; metadata preconditions make that safe, for example by having every link batch also write a per-digest key whose version the sweep requires to be unchanged when it marks the blob for deletion.
- **Deletes** hide immediately in metadata; garbage collection reclaims space later.
- **Retention policies** (for example, keep the last N tags matching a pattern, or delete untagged manifests older than X) are designed now and built shortly after v1. They are the only mechanism that deletes untagged manifests in hosted repositories.
- **Backup** is a built-in v1 command: it writes a consistent metadata snapshot plus every blob not already present in the target directory, so repeated backups are incremental.

## Roadmap

| Milestone | Scope |
| --- | --- |
| M0 foundation | This design document, Go module, CI, write-ahead-log metadata store, blob store, crash tests. |
| M1 hosted OCI | Hosted OCI repositories passing the conformance suite, local users and tokens, Docker token auth, metrics and logs, image and chart on ghcr.io, first homelab deployment. |
| M2 container proxy | Docker Hub proxy and containerd mirror. |
| M3 PyPI | PyPI hosted, proxy, and merged virtual index. |
| M4 v1.0 | Garbage collection, backup, UI, audit log, OIDC; tagged v1.0. |
| After v1 | S3 storage, retention policies, trusted publishing, ACME, LDAP, then multi-server HA. |
