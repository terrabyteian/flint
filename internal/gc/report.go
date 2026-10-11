package gc

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/terrabyteian/flint/internal/blob"
)

// Run states.
const (
	StateRunning   = "running"
	StateSucceeded = "succeeded"
	// StateRefused means the run deleted nothing because the metadata
	// holds keys or records whose references are unknown; Refused says
	// which.
	StateRefused   = "refused"
	StateFailed    = "failed"
	StateCancelled = "cancelled"
)

// Phases of a running run.
const (
	PhaseMarking  = "marking"  // collecting the digests the metadata references
	PhaseScanning = "scanning" // walking the blob store for unreferenced blobs
	PhaseSweeping = "sweeping" // dooming, checking, and deleting unreferenced blobs
)

// Triggers of a run.
const (
	TriggerAPI      = "api"
	TriggerSchedule = "schedule"
)

// Count is a number of blobs and their total size.
type Count struct {
	Blobs int64 `json:"blobs"`
	Bytes int64 `json:"bytes"`
}

func (c *Count) add(size int64) {
	c.Blobs++
	c.Bytes += size
}

// Report describes a garbage-collection run, finished or in progress.
// For a dry run, Deleted counts what the run would have deleted.
type Report struct {
	DryRun  bool   `json:"dryRun"`
	Trigger string `json:"trigger"`
	// Actor is who started the run: a user, or "system" for scheduled runs.
	Actor    string    `json:"actor"`
	State    string    `json:"state"`
	Phase    string    `json:"phase,omitempty"` // while running
	Started  time.Time `json:"started"`
	Finished time.Time `json:"finished,omitzero"`
	// GracePeriod is how long an unreferenced blob was kept after its
	// commit.
	GracePeriod string `json:"gracePeriod"`

	// Referenced is the number of distinct blobs the metadata references.
	Referenced int64 `json:"referenced"`
	// Stored counts the blobs in the blob store.
	Stored Count `json:"stored"`
	// Unreferenced counts the stored blobs the metadata does not
	// reference; InGracePeriod counts those committed within the grace
	// period, which the run keeps.
	Unreferenced  Count `json:"unreferenced"`
	InGracePeriod Count `json:"inGracePeriod"`
	// Kept counts unreferenced blobs past the grace period that the run
	// kept after all, because they were linked again while it ran or a
	// pinned view, such as a running backup's, references them.
	Kept Count `json:"kept"`
	// Pruned counts the expired records the run removed, such as blob
	// links no manifest references, or for a dry run, would have removed.
	Pruned int64 `json:"pruned"`
	// Deleted counts the blobs the run deleted, or for a dry run, would
	// have deleted.
	Deleted Count `json:"deleted"`
	// Failed counts the blobs the run could not delete.
	Failed Count `json:"failed"`
	// PinnedViews is the largest number of pinned views a check read.
	PinnedViews int `json:"pinnedViews"`

	// Refused says why the run deleted nothing, when State is
	// StateRefused.
	Refused []string `json:"refused,omitempty"`
	// Errors lists failures to delete blobs, up to maxErrors; Failed
	// counts them all.
	Errors []string `json:"errors,omitempty"`
	// Error is why the run failed or was cancelled.
	Error string `json:"error,omitempty"`

	// Blobs lists, for a dry run, the blobs it would delete, up to
	// maxListed; BlobsTruncated reports whether there were more.
	Blobs          []BlobInfo `json:"blobs,omitempty"`
	BlobsTruncated bool       `json:"blobsTruncated,omitempty"`
}

// BlobInfo describes a blob in a report.
type BlobInfo struct {
	Digest    string    `json:"digest"`
	Size      int64     `json:"size"`
	Committed time.Time `json:"committed"`
}

func blobInfo(b blob.Info) BlobInfo {
	return BlobInfo{Digest: b.Digest.String(), Size: b.Size, Committed: b.ModTime.UTC()}
}

// Report bounds.
const (
	maxErrors = 10
	maxListed = 1000
)

func (r *Report) addError(size int64, msg string) {
	r.Failed.add(size)
	if len(r.Errors) < maxErrors {
		r.Errors = append(r.Errors, msg)
	}
}

// clone returns a copy of r that shares nothing with it.
func (r *Report) clone() *Report {
	c := *r
	c.Refused = append([]string(nil), r.Refused...)
	c.Errors = append([]string(nil), r.Errors...)
	c.Blobs = append([]BlobInfo(nil), r.Blobs...)
	return &c
}

// encodeReport encodes the report of a run that was not a dry run, for
// gc\0last: the format byte, then JSON.
func encodeReport(r *Report) []byte {
	b, _ := json.Marshal(r)
	return append([]byte{recordFormat}, b...)
}

func decodeReport(b []byte) (*Report, error) {
	if len(b) == 0 || b[0] != recordFormat {
		return nil, errors.New("gc: unknown report format")
	}
	var r Report
	if err := json.Unmarshal(b[1:], &r); err != nil {
		return nil, err
	}
	return &r, nil
}
