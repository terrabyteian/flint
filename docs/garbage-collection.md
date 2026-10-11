# Garbage collection

Every artifact byte lives in flint's blob store once, however many repositories use it.
Deleting an image or a blob only hides it: it removes the metadata records that make the content visible, at once, and leaves the bytes in place.
Garbage collection later deletes the blobs that nothing in the metadata references any more, and reclaims their space.
It runs while flint keeps serving pulls and pushes; there is no read-only mode.

[The design](design.md#cleanup-and-data-safety) records the guarantees and how the collector meets them.

## What is kept, and what is reclaimed

A blob is **referenced**, and kept, while any of these records points at it, in any repository:

- a blob link: the blob was pushed to, mounted into, or cached by the repository name, and its link was not deleted;
- a manifest record, which references the manifest's own bytes and every config, layer, and child manifest it lists;
- a tag, which references its manifest;
- a referrers entry, which references the referring manifest (a signature, an SBOM), but not its subject.

Everything else in the blob store is **unreferenced**.
Garbage collection deletes an unreferenced blob once its grace period is over: by default 24 hours after the blob was stored.
The grace period keeps a blob that a push stored a moment ago, but has not linked yet, out of reach.

What a delete reclaims follows from these rules:

| You delete | Garbage collection reclaims |
| --- | --- |
| A manifest by digest (`DELETE /v2/<name>/manifests/<digest>`, `crane delete`, `regctl image delete`) | The manifest's bytes. Its tags and referrers entry go with it. Its config and layers stay linked in the repository name, and stay, until their links are deleted too. |
| A tag | Nothing by itself: the manifest stays, by digest, for deployments that pin it. |
| A blob link (`DELETE /v2/<name>/blobs/<digest>`) | The blob, once no other link or manifest in any repository references it. |
| Content a size-limited proxy repository evicts | The evicted blobs and manifests that nothing else references. |

Hosted repositories never delete untagged manifests on their own; see [the design](design.md#hosted).

Abandoned uploads are not garbage collection's business: every hour, flint ends upload sessions that started more than 24 hours ago and removes staged upload data nothing has written to for 24 hours.

## Running it

Garbage collection runs on the server.
An administrator starts it with `flint gc`, which calls the server's [admin API](auth.md#admin-api), or on a schedule set in the [configuration](configuration.md#garbage-collection).
One run happens at a time.

```sh
# What would a run delete? Changes nothing.
flint gc run -dry-run -url https://registry.example -user admin -password-file -

# Delete, and wait for the report.
flint gc run -url https://registry.example -user admin -password-file -

# The run in progress, the last run, and the schedule.
flint gc status -url https://registry.example -user admin -password-file -
```

`-password-file -` reads the password, or an API token, from standard input; with a token, leave out `-user`, which then defaults to `__token__`, or give the token's owner.
`FLINT_URL`, `FLINT_USER`, and `FLINT_PASSWORD` set the same from the environment, for scripts.
`-json` prints the report as JSON, and `run -detach` starts a run without waiting for it; `flint gc status` shows it.
Interrupting `flint gc run` stops the waiting, not the run.

`flint gc` needs `-url` or `FLINT_URL`, and verifies the server's TLS certificate as any HTTPS client does.

`flint gc run` exits 0 when the run succeeded, and 1 otherwise.

### The report

```
  state:           succeeded
  started:         2026-10-11T03:00:00Z by admin (api)
  finished:        2026-10-11T03:01:12Z, after 1m12.043s
  grace period:    24h0m0s
  referenced:      48211 blobs
  stored:          51022 blobs, 1.8 TiB
  unreferenced:    2811 blobs, 96.2 GiB
  in grace period: 37 blobs, 1.1 GiB
  kept:            2 blobs, 310.0 MiB
  deleted:         2772 blobs, 94.8 GiB
```

| Line | Meaning |
| --- | --- |
| `referenced` | Distinct blobs the metadata references. |
| `stored` | Blobs in the blob store. |
| `unreferenced` | Stored blobs nothing references. |
| `in grace period` | Unreferenced blobs stored within the grace period, which the run keeps. |
| `kept` | Unreferenced blobs past the grace period that the run kept after all: a push linked them again while it ran, or a pinned view, such as a running backup's, references them. |
| `deleted` | Blobs the run deleted. A dry run says `would delete` and lists them, up to 1000. |

A run ends in one of these states:

| State | Meaning |
| --- | --- |
| `succeeded` | The run finished. |
| `refused` | The run deleted nothing, because the metadata holds records whose references it cannot know; `refused` says which. See below. |
| `failed` | Some blobs could not be deleted, or the run could not finish; `error` and `delete error` say why. The report counts the blobs it deleted, and the server log lists each. |
| `cancelled` | flint shut down during the run. |

## Scheduling

```json
{"gc": {"interval": "24h"}}
```

With `gc.interval`, flint starts a run that long after the previous run started, whether that run was scheduled or started by hand.
The time of the last run survives restarts, so a server restarted more often than the interval still collects garbage; a scheduled run never starts within a minute of startup.
Scheduled runs are recorded with the actor `system`.

## How a run stays safe

- **Nothing referenced is deleted.** A run decides what to delete from the metadata, then checks again, after it has announced what it is about to delete, against the latest metadata and every view pinned with the store, such as a running backup's; it deletes only what all of them leave unreferenced.
- **Pushes during a run.** A push of content that the run is deleting at that moment, which only happens to content stored more than the grace period ago and no longer referenced, is refused with `503 UNAVAILABLE` and `Retry-After`, as are a manifest push and a cross-repository mount of it; a mount falls back to a normal upload. Clients retry, and the retry succeeds once the run is past that content. A pull through a proxy repository serves the stored copy and fetches it again next time.
- **Unknown records stop the run.** Every part of flint that writes metadata registers what its records reference with the garbage collector. A record of a kind nobody registered, such as one written by a newer version of flint, or a record that cannot be read, makes the run refuse to delete anything and report it, rather than guess. Upgrade or roll back to a flint that knows the records.
- **Crashes.** A crash during a run leaves no damage: what was deleted was unreferenced, and at the next start flint forgets the run's unfinished work, so pushes of that content work again. The next run reclaims what is left.
- **Nothing silently.** Each run logs its start and its outcome, and each deleted blob is logged with its digest, size, and commit time. The metadata log also records the blobs each run set out to delete, and the report of the last run.

## Monitoring

| Metric | Meaning |
| --- | --- |
| `flint_gc_runs_total{mode, result}` | Runs, by `mode` (`sweep`, `dry_run`) and `result` (`succeeded`, `refused`, `failed`, `cancelled`). |
| `flint_gc_duration_seconds{mode}` | Run durations, as a histogram. |
| `flint_gc_reclaimed_blobs_total`, `flint_gc_reclaimed_bytes_total` | Blobs, and their bytes, that runs deleted. |
| `flint_gc_last_success_timestamp_seconds` | When the last successful run that was not a dry run finished, as a Unix time; 0 if none has. |
| `flint_gc_running` | 1 while a run is in progress. |

With a schedule, alert when collection stops succeeding, for example:

```yaml
- alert: FlintGarbageCollectionStale
  expr: time() - flint_gc_last_success_timestamp_seconds > 3 * 86400
  annotations:
    summary: flint has not collected garbage successfully for three days; see flint gc status.
```

The log lines are `garbage collection started`, `garbage collection deleted a blob`, `garbage collection finished`, `garbage collection refused to delete anything`, and `garbage collection did not finish`.
