# Operations

This page covers running flint once it is installed.
[Configuration](configuration.md) describes the configuration file, logs, and metrics, and [installing with Helm](helm.md) the Kubernetes deployment.

## Audit log

flint records every change to its metadata in an audit log: pushes, tags, and deletes, content cached by proxy repositories, uploads started, cancelled, and expired, and users, groups, and API tokens created, changed, or removed.
Each record says who made the change, what it was, to what, and which metadata keys it wrote or deleted.
It never holds the values written, so password hashes, token hashes, and other stored data never reach it.

The audit log is derived from the metadata store's write-ahead log: every committed change is one log batch, and the audit log writes one record per batch.
It keeps its own append-only files under `<dataDir>/audit/`, so its history does not depend on how long the write-ahead log keeps its segments.
By default it is kept forever.

### Records

| Field | Meaning |
| --- | --- |
| `seq` | The batch's sequence number in the metadata store. Records are in increasing order, and each batch appears once. |
| `time` | When the batch was committed, from the server's clock, in UTC. |
| `actor` | Who made the change: a user name, such as `alice`, for a change made with a password; `alice (token <id>)` for one made with one of the user's API tokens, directly or through a bearer token from the Docker token endpoint; `(anonymous)` for an unauthenticated client, such as a containerd mirror pulling through a proxy repository; or `(system)` for flint's own background work, such as expiring abandoned uploads, and for the first administrator created at startup. User names never contain parentheses, so a user named `system` or `anonymous` is never confused with these. |
| `action` | What the change was, such as `oci.manifest.push`; see below. |
| `target` | What it changed, in a readable form, such as `docker-local/app:v1@sha256:...`, `user alice`, or `token <id> of user alice`. |
| `keys` | The metadata keys the batch wrote (`"op": "put"`) or deleted (`"op": "delete"`), each as its components, such as `["oci", "tag", "docker-local", "app", "v1"]`. A key that is not UTF-8 is shown in hex as `keyHex`. |

Actions:

| Action | Change |
| --- | --- |
| `oci.blob.push`, `oci.blob.mount` | A blob uploaded, or mounted from another repository. |
| `oci.blob.delete` | A blob link deleted. |
| `oci.manifest.push` | A manifest pushed, by tag or digest. |
| `oci.manifest.delete`, `oci.tag.delete` | A manifest deleted by digest with its tags, or a tag deleted. |
| `oci.upload.start`, `oci.upload.cancel` | An upload session started or cancelled. |
| `oci.upload.expire`, `oci.upload.forget` | `(system)`: an abandoned upload session removed. |
| `oci.proxy.cache` | A proxy repository cached content for the client that pulled it. |
| `oci.proxy.pulled`, `oci.proxy.evict` | `(system)`: a size-limited proxy repository saved its pull times (about once a minute while it is pulled from) or evicted content. |
| `pypi.upload` | A file uploaded to a hosted [PyPI repository](pypi.md). |
| `pypi.yank`, `pypi.unyank`, `pypi.delete` | A PyPI release yanked or unyanked, or a release's files or one file deleted. |
| `pypi.proxy.cache` | A PyPI proxy repository cached a project listing or file for the client that fetched it. |
| `pypi.proxy.pulled`, `pypi.proxy.evict` | `(system)`: a size-limited PyPI proxy repository saved its pull times or evicted content. |
| `pypi.proxy.migrate` | `(system)`: project page records of an earlier version removed at startup, once pages moved to the proxy cache every format shares. |
| `generic.upload`, `generic.delete` | A file uploaded to, or deleted from, a hosted [generic files repository](generic.md); in an immutable repository, a delete leaves a tombstone. |
| `generic.proxy.cache` | A generic files proxy repository cached a file, or a newer copy of one it revalidates, for the client that fetched it. |
| `generic.proxy.pulled`, `generic.proxy.evict` | `(system)`: a size-limited generic files proxy repository saved its pull times or evicted files. |
| `auth.user.create`, `auth.user.update`, `auth.user.password`, `auth.user.delete` | A user created, its admin flag or groups changed, its password set, or the user deleted. |
| `auth.group.add`, `auth.group.remove` | A user added to or removed from a group. |
| `auth.token.create`, `auth.token.revoke` | An API token created or revoked. |

Further package formats add their own actions under their own prefix; their proxy repositories record `<format>.proxy.cache`, `<format>.proxy.pulled`, and `<format>.proxy.evict` like the ones above.

The audit log starts with the first batch committed after it first starts, so changes made by a flint version without it are not in it.

### Reading the audit log

The [admin API](auth.md#admin-api) serves the audit log to administrators: a password-authenticated administrator, or an API token created with `"admin": true`.
Other clients get `403`.
Both endpoints take the same filters as query parameters, all optional:

| Parameter | Selects |
| --- | --- |
| `since`, `until` | Records committed at or after `since` and before `until`, as RFC 3339 times such as `2026-10-01T00:00:00Z`. |
| `actor` | Records of one principal: a user name selects the user's changes, made with a password or any of the user's tokens; `alice (token <id>)` selects one token's; `(system)` and `(anonymous)` select themselves. |
| `action` | Records of one action, or of every action under a prefix: `oci.manifest` selects `oci.manifest.push` and `oci.manifest.delete`, and `auth` every user, group, and token change. |
| `target` | Records whose target starts with the value, such as `docker-local/app:` or `user alice`. |
| `after` | Records after this sequence number. |

`GET /api/v1/audit` returns one page of records, oldest first: `limit` records (default 100, at most 1000), and, if more match, `next`, the `after` value that fetches the next page.

```sh
curl -u admin 'https://flint.example.com/api/v1/audit?action=oci.manifest.delete&since=2026-10-01T00:00:00Z'
```

```json
{
  "records": [
    {
      "seq": 48213,
      "time": "2026-10-03T14:02:11.52Z",
      "actor": "alice",
      "action": "oci.manifest.delete",
      "target": "docker-local/app@sha256:6c3c...",
      "keys": [
        {"op": "delete", "key": ["oci", "manifest", "docker-local", "app", "sha256:6c3c..."]},
        {"op": "delete", "key": ["oci", "tag", "docker-local", "app", "v1"]}
      ]
    }
  ],
  "next": 48213
}
```

`GET /api/v1/audit/export` streams every matching record, oldest first, as JSON lines (`application/x-ndjson`), one record per line, for archiving or feeding another system:

```sh
curl -u admin -o audit.jsonl 'https://flint.example.com/api/v1/audit/export?since=2026-10-01T00:00:00Z'
```

If the export fails partway, flint aborts the response instead of ending it cleanly, so a client sees an error rather than a silently shortened file.

Both endpoints first bring the audit log up to date, so a change is visible as soon as the request that made it has finished.
The time filters skip whole files by their times, which assumes the server's clock does not jump backwards; around such a jump, filter by `after` instead.

### Retention

The audit log is kept forever unless `audit.retention` in the [configuration](configuration.md#fields) limits it:

```json
"audit": {
  "retention": {
    "maxAge": "8760h",
    "maxSize": "10GiB"
  }
}
```

Records are deleted a whole file at a time, oldest first.
The audit log writes to a file until it reaches 64 MiB or holds a day of changes, or, if a quarter of `maxSize` or `maxAge` is smaller, that quarter (at least 64 KiB and a minute), and then starts a new one.
Retention runs whenever a new file starts, and every hour or every quarter of `maxAge`, whichever is shorter.

With `maxAge`, a file is deleted once its newest record is older than `maxAge`, so a record is deleted at most about half of `maxAge` after it passes `maxAge`.
The file being written is never deleted, but once its records span the file's time limit, retention closes it and starts a new one even if no change comes, so a quiet registry's records are deleted too.

With `maxSize`, the oldest files are deleted while the audit log is larger, so it stays within about a quarter of `maxSize` of the limit.

### Durability and recovery

The audit log is a durable consumer of the write-ahead log: it reads committed batches, writes their records, fsyncs them, and only then records its checkpoint in the metadata store, which keeps every write-ahead log segment holding a batch past that checkpoint.
It polls for new batches every second.
After a crash or power loss it resumes where its durable records end: a record the crash cut short is dropped and written again from the write-ahead log, so no record is lost or repeated.

If writing the audit log fails, for example because its disk is full, flint keeps serving, logs the error once, sets `flint_audit_failing` to 1, and retries every second; the write-ahead log keeps the batches meanwhile, so nothing is lost, but it grows until the audit log catches up.
Damage to records the audit log had already checkpointed is never repaired silently.
Damage in the file being written stops flint at startup with an error naming the file and offset; move that file aside to start without its records.
Damage in an older file makes the queries that reach it fail, with the file and offset in the log.

The audit files belong to one metadata store.
If the metadata store is restored from an older backup, the audit log is ahead of it and flint refuses to start; move `<dataDir>/audit/` aside, keeping it as the record of what happened before the restore.

After rolling back to a flint version without the audit log, stop flint and delete `<dataDir>/meta/consumers/audit` before starting the older version.
That version keeps honoring the audit log's checkpoint but never advances it, so it never deletes a write-ahead log segment, and disk use and startup time grow without bound.
Upgrading again later registers the audit log anew, starting at the latest batch: changes made while rolled back are not in it, and flint logs a warning naming the missing batches.

### Metrics

| Metric | Meaning |
| --- | --- |
| `flint_audit_sequence` | Sequence number of the latest batch the audit log holds durably. |
| `flint_audit_lag` | Batches committed but not yet in the audit log. It stays near 0; a growing value means the audit log is not keeping up. |
| `flint_audit_failing` | 1 if the latest attempt to write the audit log failed, else 0. Alert on it. |
| `flint_audit_write_errors_total` | Failed audit log writes or fsyncs, each retried. |
| `flint_audit_segments` | Audit log files on disk. |
| `flint_audit_bytes` | Bytes in audit log files on disk. |

```yaml
- alert: FlintAuditLogFailing
  expr: flint_audit_failing == 1
  for: 5m
  annotations:
    summary: flint cannot write its audit log; the metadata write-ahead log is growing until it can.
```
