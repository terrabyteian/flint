package oci

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/terrabyteian/flint/internal/blob"
	"github.com/terrabyteian/flint/internal/meta"
)

// maxLinkAttempts bounds how often a link batch is retried after a
// metadata precondition fails.
const maxLinkAttempts = 4

// gcGuard applies the garbage-collection precondition to a batch that
// links digests: it reads the GC epoch and each digest's doomed entry from
// v, fails with errRetry if a digest is doomed, and requires the epoch to
// be unchanged when b commits. The caller must read v before checking that
// the blobs exist, so a sweep that starts after this read fails the
// precondition, and one already running is caught by its doomed entry.
func gcGuard(v meta.View, b *meta.Batch, ds ...blob.Digest) error {
	for _, d := range ds {
		if _, doomed := v.Get(doomedKey(d)); doomed {
			return errRetry
		}
	}
	epoch, _ := v.Get([]byte(gcEpochKey))
	b.Require([]byte(gcEpochKey), epoch.Version) // version 0 requires it absent
	return nil
}

// commitLink commits a batch that makes the blobs ds visible, under the
// garbage-collection precondition. build adds the batch's operations and
// any further preconditions from a fresh view; exists then checks that
// the blobs exist (attempt counts from 0). If a precondition fails, the
// batch is rebuilt from a new view and retried.
func (h *Handler) commitLink(ctx context.Context, ds []blob.Digest,
	build func(v meta.View, b *meta.Batch) error, exists func(attempt int) error) error {
	for attempt := 0; ; attempt++ {
		v := h.view()
		var b meta.Batch
		err := gcGuard(v, &b, ds...)
		if err == nil {
			err = build(v, &b)
		}
		v.Release()
		if err != nil {
			return err
		}
		if err := exists(attempt); err != nil {
			return err
		}
		err = h.commit(ctx, &b)
		if err == nil {
			return nil
		}
		if !errors.Is(err, meta.ErrConflict) {
			return storeError(err)
		}
		h.linkConflicts.Inc()
		if attempt == maxLinkAttempts-1 {
			return errRetry
		}
	}
}

// statExists returns an exists function for commitLink that stats each blob.
func (h *Handler) statExists(ctx context.Context, ds ...blob.Digest) func(int) error {
	return func(int) error {
		for _, d := range ds {
			if _, err := h.blobs.Stat(ctx, d); errors.Is(err, blob.ErrNotFound) {
				return errRetry // swept since it was linked; the client must push it again
			} else if err != nil {
				return err
			}
		}
		return nil
	}
}

// lookupBlob returns the size of blob d as linked in rn.
func (h *Handler) lookupBlob(rn *repoName, d blob.Digest) (int64, meta.Seq, bool, error) {
	v := h.view()
	defer v.Release()
	rec, ok := v.Get(blobKey(rn, d))
	if !ok {
		return 0, 0, false, nil
	}
	size, err := decodeBlobLink(rec.Value)
	return size, rec.Version, true, err
}

func blobUnknown(d blob.Digest) error {
	return newError(http.StatusNotFound, codeBlobUnknown, "blob %s is not known to this repository", d).
		withDetail(map[string]string{"digest": d.String()})
}

// getBlob serves GET and HEAD /v2/<name>/blobs/<digest>.
func (h *Handler) getBlob(w http.ResponseWriter, r *http.Request, rn *repoName, arg string) {
	d, err := parseDigest(arg)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	size, _, ok, err := h.lookupBlob(rn, d)
	if err == nil && !ok {
		err = blobUnknown(d)
	}
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	hd := w.Header()
	hd.Set("Docker-Content-Digest", d.String())
	hd.Set("ETag", `"`+d.String()+`"`)
	hd.Set("Content-Type", "application/octet-stream")
	hd.Set("Cache-Control", "max-age=31536000") // content-addressed: never changes
	if r.Method == http.MethodHead {
		hd.Set("Accept-Ranges", "bytes")
		hd.Set("Content-Length", strconv.FormatInt(size, 10))
		w.WriteHeader(http.StatusOK)
		return
	}
	f, err := h.blobs.Open(r.Context(), d)
	if errors.Is(err, blob.ErrNotFound) {
		h.log.WarnContext(r.Context(), "linked blob is missing from the blob store",
			"repository", rn.full, "digest", d.String())
		err = blobUnknown(d)
	}
	if err != nil {
		hd.Del("ETag")
		hd.Del("Cache-Control")
		h.writeError(w, r, err)
		return
	}
	defer f.Close()
	// The filesystem store returns the *os.File itself, so on plain
	// HTTP/1.1 ServeContent's copy reaches sendfile. It also answers
	// Range and conditional requests.
	http.ServeContent(w, r, "", time.Time{}, f)
}

// deleteBlob serves DELETE /v2/<name>/blobs/<digest>. It removes the link;
// garbage collection reclaims the bytes once nothing links them.
func (h *Handler) deleteBlob(w http.ResponseWriter, r *http.Request, rn *repoName, arg string) {
	d, err := parseDigest(arg)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	_, _, ok, err := h.lookupBlob(rn, d)
	if err == nil && !ok {
		err = blobUnknown(d)
	}
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	var b meta.Batch
	b.Delete(blobKey(rn, d))
	b.SetOrigin(h.origin(r, "oci.blob.delete", rn.full+"@"+d.String()))
	if err := h.commit(r.Context(), &b); err != nil {
		h.writeError(w, r, storeError(err))
		return
	}
	w.Header().Set("Content-Length", "0")
	w.WriteHeader(http.StatusAccepted)
}
