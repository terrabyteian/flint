package oci

import (
	"context"
	"time"

	"github.com/terrabyteian/flint/internal/meta"
)

// Upload expiry defaults.
const (
	// UploadMaxAge is how long an upload session lives after it starts.
	UploadMaxAge = 24 * time.Hour
	// JanitorInterval is how often expired uploads are removed.
	JanitorInterval = time.Hour
)

// ExpireUploads ends upload sessions started more than maxAge ago and
// removes the blob store's abandoned uploads: those not suspended since
// then, and those an earlier process left unsuspended.
func (h *Handler) ExpireUploads(ctx context.Context, maxAge time.Duration) error {
	cutoff := h.now().Add(-maxAge)
	var expired [][]byte
	v := h.view()
	v.Scan([]byte(nsUpload), nil, func(key []byte, rec meta.Record) bool {
		u, err := decodeUpload(rec.Value)
		if err != nil || u.Started.Before(cutoff) {
			expired = append(expired, append([]byte(nil), key...))
		}
		return true
	})
	v.Release()
	for len(expired) > 0 {
		chunk := expired[:min(len(expired), 1000)]
		expired = expired[len(chunk):]
		var b meta.Batch
		for _, k := range chunk {
			b.Delete(k)
		}
		b.SetOrigin(meta.Origin{Actor: meta.ActorSystem, Action: "oci.upload.expire",
			Target: "upload sessions started before " + cutoff.UTC().Format(time.RFC3339)})
		if err := h.commit(ctx, &b); err != nil {
			return err
		}
	}
	n, err := h.blobs.PurgeUploads(ctx, cutoff)
	if n > 0 {
		h.log.Info("removed abandoned uploads", "count", n)
	}
	return err
}

// RunJanitor expires uploads now and then every interval until ctx is
// done, logging failures.
func (h *Handler) RunJanitor(ctx context.Context, interval, maxAge time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		if err := h.ExpireUploads(ctx, maxAge); err != nil && ctx.Err() == nil {
			h.log.Warn("expiring uploads", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
