# Backups

flint backs itself up while it serves.
A backup is a consistent copy of the metadata store, as of one moment, plus every blob that is not in the backup directory yet, so the first backup copies everything and later ones copy only what is new.
`flint backup verify` checks a backup without restoring it, and `flint restore` turns one into a new data directory.

## Setting up

Name a backup directory in the [configuration](configuration.md):

```json
"backup": {
  "directory": "/var/backups/flint"
}
```

It must be an absolute path outside the data directory.
Put it on other storage than the data, such as a second disk or an NFS share, so that losing one does not lose both; with the [Helm chart](helm.md#backups), `backup.enabled` mounts a volume there.
flint creates the directory if it is missing, and writes to it as its own user.
The filesystem must honor `fsync` and atomic renames, as local filesystems and NFS do; object-store mounts that do not are not supported.
Give each flint server its own backup directory.

## Taking a backup

A backup runs inside the server, which is what lets it take a consistent view of the metadata while clients keep pushing.
Start one through the admin API as an administrator, with `flint backup`:

```sh
# Once: an API token with the admin role, for automation.
curl -u admin https://registry.example/api/v1/tokens -d '{"name": "backup", "admin": true}'

flint backup -url https://registry.example -password-file backup-token
```

```text
backup 20261011T020000.123Z-48211 started at sequence 48211
backup 20261011T020000.123Z-48211 succeeded in 41.2s: 48120 records, 9312 blobs (412.6 GiB), 57 copied (1.3 GiB)
```

`-password-file` holds the token (or, with `-user`, a user's password); one trailing newline is ignored.
`flint backup` waits until the backup finishes and exits 0 if it succeeded and 1 if not, printing the reason; `-no-wait` returns once it has started, `-timeout` bounds the wait, and `-ca-file` adds a certificate authority to trust for `https`.
Only one backup runs at a time: starting another while one runs fails with `409` and the running backup's status.

### The admin API

| Request | Does |
| --- | --- |
| `POST /api/v1/backup` | Start a backup. `202 Accepted` with the backup, in the form of the status's `running`; `409` if one is running; `404` if `backup.directory` is not configured. |
| `GET /api/v1/backup` | The status: the running backup, the last one that finished since the server started, and the last complete one. |

Both need the global admin role, with a password or an API token created with `"admin": true`.
The status looks like this:

```json
{
  "directory": "/var/backups/flint",
  "running": {
    "id": "20261012T020000.087Z-48690",
    "state": "running",
    "phase": "blobs",
    "actor": "admin (token k3vqpmzt5j2xw7ab)",
    "sequence": 48690,
    "started": "2026-10-12T02:00:00.087Z",
    "durationSeconds": 12.5,
    "records": 48601,
    "blobs": 4120,
    "bytes": 201863168000,
    "copiedBlobs": 12,
    "copiedBytes": 402653184
  },
  "lastSuccess": {
    "id": "20261011T020000.123Z-48211",
    "state": "succeeded",
    "sequence": 48211,
    "started": "2026-10-11T02:00:00.123Z",
    "finished": "2026-10-11T02:00:41.323Z",
    "durationSeconds": 41.2,
    "records": 48120,
    "blobs": 9312,
    "bytes": 443034157056,
    "copiedBlobs": 57,
    "copiedBytes": 1395864371
  }
}
```

A running backup's `phase` is `metadata` (writing the metadata snapshot), `blobs` (copying blobs; `blobs` and `bytes` count those done so far), `references` (checking that every referenced blob is in the backup), or `finishing`.
`last` has the same form, with `"state": "failed"` and an `error` when a backup failed.
`lastSuccess` comes from the backup directory when the server starts, so it survives restarts.

## Scheduling

Run `flint backup` on a schedule.
In Kubernetes, a CronJob can run it from the flint image itself; store the admin token in a Secret first:

```sh
kubectl create secret generic flint-backup-token --namespace flint --from-file=token=backup-token
```

```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: flint-backup
  namespace: flint
spec:
  schedule: "0 2 * * *"
  concurrencyPolicy: Forbid
  jobTemplate:
    spec:
      backoffLimit: 2
      template:
        spec:
          restartPolicy: Never
          securityContext:
            runAsNonRoot: true
            runAsUser: 65532
          containers:
            - name: backup
              image: ghcr.io/terrabyteian/flint:v1.0.0
              args: ["backup", "-url", "http://flint.flint.svc:5000", "-password-file", "/etc/flint-backup/token"]
              volumeMounts:
                - name: token
                  mountPath: /etc/flint-backup
                  readOnly: true
          volumes:
            - name: token
              secret:
                secretName: flint-backup-token
```

The job only asks the server to back up, so it needs no volumes besides the token.
Outside Kubernetes, a cron entry or systemd timer running the same command does the job.

## What a backup holds

A backup holds:

- **The whole metadata store** as of one sequence number: tags, manifests, blob links, and referrers; users with their password hashes; API tokens' hashes; upload sessions; and the garbage collector's state.
- **Every blob in the data directory** that existed when the backup reached it: every blob the metadata references, plus unreferenced ones still waiting for garbage collection, which the restored server collects in turn.

It does not hold:

- **The configuration file and the files it names**: TLS certificates and keys, the bootstrap administrator's password file, and proxy repositories' upstream credentials. Keep them where you keep the rest of your deployment's configuration and secrets, such as the Helm values and Kubernetes Secrets.
- **The signing keys** (`auth/token-signing.key` and `auth/url-signing.key`). flint generates new ones when it first starts on a restored data directory, so a backup never contains private key material. The only effect is that bearer tokens issued before the restore, which live five minutes, and [signed download URLs](auth.md#signed-download-urls), which live ten minutes by default, stop working; clients fetch new ones. Users, passwords, and API tokens are in the metadata and work as before.
- **Uploads in progress.** Clients restart them.
- **The history of the metadata log**: a backup holds the state, not the log of changes that led to it.

> **Backups are sensitive.** They hold password hashes, API token hashes, and every artifact, including private ones. Protect the backup directory as you protect the data directory.

## Verifying

```sh
flint backup verify /var/backups/flint                 # the latest complete backup
flint backup verify -backup 20261011T020000.123Z-48211 /var/backups/flint
flint backup list /var/backups/flint
```

`verify` checks, without changing anything, that the backup's metadata snapshot and blob list match the digests recorded when it finished, that the snapshot is intact, that every blob the metadata references is in the backup, and that every blob is present with the content its digest names, reading every byte.
It prints what is wrong and exits 1 if anything is.
Run it now and then on the machine that holds the backups: an incremental backup only checks that a blob it has copied before is still present with the right size, so it does not notice a blob that has rotted in place.

`list` shows every backup with its state: `complete`, or `incomplete` for one that was interrupted.

## Restoring

`flint restore` writes a backup into a new or empty data directory:

```sh
flint restore /var/backups/flint /var/lib/flint-restored
flint restore -backup 20261011T020000.123Z-48211 /var/backups/flint /var/lib/flint-restored
```

It refuses a data directory that holds anything but the `lost+found` directory of a new ext4 volume, so it never mixes a backup with other data, and it takes the data directory's lock, so it cannot run on a directory a server is using.
It checks the backup as `verify` does, and each blob's digest as it copies it; a damaged backup is not restored.
Then start flint with `dataDir` pointing at the restored directory, or move it into place.
The restored server holds exactly the state of the backup, continues its metadata log from the backup's sequence number, and creates new signing keys.

Until a restore has finished, the data directory holds a file named `RESTORE-INCOMPLETE`, and `flint serve` refuses to start on it, so an interrupted restore is never served as if it were the whole registry.
Delete the directory and restore again.

In Kubernetes, restore with the flint image into an empty claim before flint uses it: for example, scale the StatefulSet to zero, run a pod as user 65532 that mounts the backup volume and a new claim and runs `flint restore`, then point `persistence.existingClaim` at the new claim and scale back up.

## Backup directory layout

```
<backup directory>/
  LOCK                           held while a backup writes here
  blobs/sha256/<2 hex>/<64 hex>  every blob of every backup, stored once
  uploads/                       blob copies in progress
  backups/<id>/metadata.snap     the metadata store's state, in its own snapshot format
  backups/<id>/blobs             the blobs this backup needs, one "<digest> <size>" line each
  backups/<id>/backup.json       the completion record, written last
```

A backup's ID is the UTC time it started and its metadata sequence number.
All backups in a directory share its blob store, which is why later backups copy only new blobs.
A copied blob is checked against its digest and synced to disk before it counts.
`backup.json` records the backup's sequence number, counts, and the digests of `metadata.snap` and `blobs`; it is written to a temporary file, synced, and renamed into place only after everything the backup holds is durable, so a backup interrupted by a crash, a restart, or an error never looks complete.

**Removing backups.** Delete `backups/<id>` to remove a backup; flint never deletes backups itself, not even incomplete ones.
Blobs stay in the shared store even when no remaining backup needs them, so to reclaim that space, start a new backup directory now and then, and delete the old one once the new one holds the backups you want to keep.

## Monitoring

| Metric | Meaning |
| --- | --- |
| `flint_backup_running` | 1 while a backup runs. |
| `flint_backup_runs_total{result}` | Finished backups, by result: `success` or `failure`. |
| `flint_backup_copied_bytes_total` | Bytes copied into the backup directory, counted as they are copied. |
| `flint_backup_last_success_timestamp_seconds` | When the last complete backup finished, in Unix seconds; 0 if there is none. |
| `flint_backup_last_success_duration_seconds` | How long it took. |
| `flint_backup_last_success_blobs`, `flint_backup_last_success_bytes` | The blobs it holds. |
| `flint_backup_last_success_copied_blobs`, `flint_backup_last_success_copied_bytes` | The blobs it copied; the rest were already in the backup directory. |

Alert when the last complete backup is too old, which covers failed, missing, and never-scheduled backups alike:

```yaml
- alert: FlintBackupTooOld
  expr: time() - flint_backup_last_success_timestamp_seconds > 26 * 3600
  annotations:
    summary: flint has not completed a backup in over a day.
```

flint logs `backup started`, `backup finished` (with the duration and counts), and `backup failed` (with the error), each with a `backup_id` attribute.

## When a backup fails

- **A blob the metadata references is missing from the data directory.** The backup fails and names the missing digests, because a backup cannot hold what the registry has lost.
- **A blob's content does not match its digest.** The data directory is damaged; the backup fails and names the blob.
- **The server shuts down.** A running backup is cancelled and left incomplete. Start another after the restart.
- **The backup directory fills up or fails.** The backup fails with the error, and the next one picks up where it left off, copying only what is still missing.
