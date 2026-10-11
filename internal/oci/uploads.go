package oci

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/terrabyteian/flint/internal/blob"
	"github.com/terrabyteian/flint/internal/meta"
)

func uploadLocation(rn *repoName, id string) string {
	return "/v2/" + rn.full + "/blobs/uploads/" + id
}

func blobLocation(rn *repoName, d blob.Digest) string {
	return "/v2/" + rn.full + "/blobs/" + d.String()
}

// writeUploadState answers with an upload's location and staged range.
func writeUploadState(w http.ResponseWriter, rn *repoName, id string, size int64, status int) {
	hd := w.Header()
	hd.Set("Location", uploadLocation(rn, id))
	hd.Set("Docker-Upload-UUID", id)
	hd.Set("Range", uploadRange(size))
	hd.Set("Content-Length", "0")
	w.WriteHeader(status)
}

// uploadRange formats the Range header for size staged bytes. An empty
// upload reports 0-0, which clients read as nothing received.
func uploadRange(size int64) string {
	return fmt.Sprintf("0-%d", max(size-1, 0))
}

func writeBlobCreated(w http.ResponseWriter, rn *repoName, d blob.Digest) {
	hd := w.Header()
	hd.Set("Location", blobLocation(rn, d))
	hd.Set("Docker-Content-Digest", d.String())
	hd.Set("Content-Length", "0")
	w.WriteHeader(http.StatusCreated)
}

func uploadUnknown(id string) error {
	return newError(http.StatusNotFound, codeBlobUploadUnknown, "upload %q is not known; start a new upload", abbrev(id))
}

// startUpload serves POST /v2/<name>/blobs/uploads/: a cross-repository
// mount (?mount=&from=), a monolithic upload in one request (?digest=),
// or a new upload session.
func (h *Handler) startUpload(w http.ResponseWriter, r *http.Request, rn *repoName, _ string) {
	ctx := r.Context()
	q := r.URL.Query()
	if mount := q.Get("mount"); mount != "" {
		if h.mount(w, r, rn, mount, q.Get("from")) {
			return
		}
		// Not mountable: fall back to a new upload session, as the spec allows.
	} else if dg := q.Get("digest"); dg != "" {
		d, err := parseDigest(dg)
		if err != nil {
			h.writeError(w, r, err)
			return
		}
		up, err := h.blobs.NewUpload(ctx)
		if err != nil {
			h.writeError(w, r, err)
			return
		}
		if err := h.receive(r, rn, up); err != nil {
			up.Cancel()
			h.writeReceiveError(w, r, rn, "", err)
			return
		}
		if err := h.commitUpload(r, rn, up, d, ""); err != nil {
			h.writeError(w, r, err)
			return
		}
		writeBlobCreated(w, rn, d)
		return
	}

	up, err := h.blobs.NewUpload(ctx)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	id := up.ID()
	// Suspend at once, so the next request can resume the upload, also
	// after a restart.
	if err := up.Suspend(); err != nil {
		h.writeError(w, r, err)
		return
	}
	var b meta.Batch
	rec := uploadRecord{Name: rn.full, Started: h.now()}
	b.Put(uploadKey(id), rec.encode())
	b.SetOrigin(h.origin(r, "oci.upload.start", rn.full))
	if err := h.commit(ctx, &b); err != nil {
		h.discardUpload(id)
		h.writeError(w, r, storeError(err))
		return
	}
	writeUploadState(w, rn, id, 0, http.StatusAccepted)
}

// mount links blob mount from repository from into rn, without copying
// data. It reports whether it answered the request; if not, the caller
// falls back to a normal upload. That happens when from is absent or not
// readable by the caller, the blob is not linked there, or garbage
// collection is reclaiming it.
func (h *Handler) mount(w http.ResponseWriter, r *http.Request, rn *repoName, mount, from string) bool {
	d, err := blob.ParseDigest(mount)
	if err != nil || from == "" {
		return false
	}
	src, err := h.resolve(from)
	if err != nil || !h.auth.Authorize(discardWriter{}, r, src.full, ActionPull) {
		return false
	}
	errNoSource := errors.New("not linked in the source")
	err = h.commitLink(r.Context(), []blob.Digest{d}, func(v meta.View, b *meta.Batch) error {
		rec, ok := v.Get(blobKey(src, d))
		if !ok {
			return errNoSource
		}
		size, _, err := decodeBlobLink(rec.Value)
		if err != nil {
			return err
		}
		b.Put(blobKey(rn, d), encodeBlobLink(size, h.now()))
		b.SetOrigin(h.origin(r, "oci.blob.mount", src.full+"@"+d.String()+" -> "+rn.full))
		return nil
	}, h.statExists(r.Context(), d))
	switch {
	case err == nil:
		writeBlobCreated(w, rn, d)
		return true
	case errors.Is(err, errNoSource), err == errRetry:
		return false
	default:
		h.writeError(w, r, err)
		return true
	}
}

// openUpload resumes upload session id of rn.
func (h *Handler) openUpload(ctx context.Context, rn *repoName, id string) (blob.Upload, error) {
	v := h.view()
	raw, ok := v.Get(uploadKey(id))
	v.Release()
	if !ok {
		return nil, uploadUnknown(id)
	}
	rec, err := decodeUpload(raw.Value)
	if err != nil {
		return nil, err
	}
	if rec.Name != rn.full {
		return nil, uploadUnknown(id)
	}
	up, err := h.blobs.ResumeUpload(ctx, id)
	switch {
	case errors.Is(err, blob.ErrUploadUnknown):
		h.forgetUpload(id)
		return nil, uploadUnknown(id)
	case errors.Is(err, blob.ErrUploadBusy):
		return nil, newError(http.StatusConflict, codeBlobUploadInvalid,
			"upload %s is in use by another request", id)
	}
	return up, err
}

// forgetUpload deletes an upload session's record, as best it can; upload
// expiry removes whatever is left.
func (h *Handler) forgetUpload(id string) {
	var b meta.Batch
	b.Delete(uploadKey(id))
	b.SetOrigin(meta.Origin{Actor: "system", Action: "oci.upload.forget", Target: id})
	h.commit(context.Background(), &b)
}

// discardUpload cancels a suspended upload, as best it can.
func (h *Handler) discardUpload(id string) {
	if up, err := h.blobs.ResumeUpload(context.Background(), id); err == nil {
		up.Cancel()
	}
}

// parseContentRange parses a chunk's Content-Range: "<start>-<end>",
// inclusive, optionally prefixed "bytes " or "bytes=".
func parseContentRange(s string) (start, end int64, ok bool) {
	s = strings.TrimPrefix(strings.TrimPrefix(s, "bytes "), "bytes=")
	a, b, found := strings.Cut(s, "-")
	if !found {
		return 0, 0, false
	}
	start, err1 := strconv.ParseInt(a, 10, 64)
	end, err2 := strconv.ParseInt(b, 10, 64)
	if err1 != nil || err2 != nil || start < 0 || end < start {
		return 0, 0, false
	}
	return start, end, true
}

// receive copies the request body into up. A Content-Range header must
// start at the upload's current size; with one, at most the range's
// length is read. Errors are client errors; a failed write to the upload
// shows when the upload is suspended or committed.
func (h *Handler) receive(r *http.Request, rn *repoName, up blob.Upload) error {
	body := io.Reader(r.Body)
	want := int64(-1)
	if cr := r.Header.Get("Content-Range"); cr != "" {
		start, end, ok := parseContentRange(cr)
		if !ok {
			return newError(http.StatusBadRequest, codeBlobUploadInvalid, "invalid Content-Range %q", abbrev(cr))
		}
		if start != up.Size() {
			return &rangeError{size: up.Size()}
		}
		want = end - start + 1
		if r.ContentLength >= 0 && r.ContentLength != want {
			return newError(http.StatusBadRequest, codeBlobUploadInvalid,
				"Content-Length %d does not match Content-Range %q", r.ContentLength, cr)
		}
		body = io.LimitReader(body, want)
	}
	br := &bodyReader{r: body}
	n, _ := io.Copy(up, br)
	h.uploadBytes.With(rn.repo).Add(float64(n))
	if br.err != nil {
		return newError(http.StatusBadRequest, codeBlobUploadInvalid, "reading the request body: %v", br.err)
	}
	if want >= 0 && n != want {
		return newError(http.StatusBadRequest, codeBlobUploadInvalid,
			"the body has %d bytes, Content-Range announced %d", n, want)
	}
	return nil
}

// rangeError is an out-of-order chunk: 416 with the upload's current range.
type rangeError struct{ size int64 }

func (e *rangeError) Error() string { return "chunk out of order" }

// bodyReader records a request body read error, so it can be told apart
// from a failed write to the upload.
type bodyReader struct {
	r   io.Reader
	err error
}

func (b *bodyReader) Read(p []byte) (int, error) {
	n, err := b.r.Read(p)
	if err != nil && err != io.EOF {
		b.err = err
	}
	return n, err
}

// writeReceiveError answers a failed chunk. The upload, already suspended,
// stays usable: the client can ask for its range and continue.
func (h *Handler) writeReceiveError(w http.ResponseWriter, r *http.Request, rn *repoName, id string, err error) {
	var re *rangeError
	if errors.As(err, &re) {
		if id != "" {
			hd := w.Header()
			hd.Set("Location", uploadLocation(rn, id))
			hd.Set("Docker-Upload-UUID", id)
			hd.Set("Range", uploadRange(re.size))
		}
		h.writeError(w, r, newError(http.StatusRequestedRangeNotSatisfiable, codeBlobUploadInvalid,
			"chunk out of order: the upload has %d bytes, so the next chunk starts at %d", re.size, re.size))
		return
	}
	h.writeError(w, r, err)
}

// patchUpload serves PATCH /v2/<name>/blobs/uploads/<id>: a chunk with a
// Content-Range, or a stream without one.
func (h *Handler) patchUpload(w http.ResponseWriter, r *http.Request, rn *repoName, id string) {
	up, err := h.openUpload(r.Context(), rn, id)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	rerr := h.receive(r, rn, up)
	size := up.Size()
	if err := up.Suspend(); err != nil {
		h.forgetUpload(id)
		h.writeError(w, r, err)
		return
	}
	if rerr != nil {
		h.writeReceiveError(w, r, rn, id, rerr)
		return
	}
	writeUploadState(w, rn, id, size, http.StatusAccepted)
}

// uploadStatus serves GET /v2/<name>/blobs/uploads/<id>.
func (h *Handler) uploadStatus(w http.ResponseWriter, r *http.Request, rn *repoName, id string) {
	up, err := h.openUpload(r.Context(), rn, id)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	size := up.Size()
	if err := up.Suspend(); err != nil {
		h.forgetUpload(id)
		h.writeError(w, r, err)
		return
	}
	writeUploadState(w, rn, id, size, http.StatusNoContent)
}

// cancelUpload serves DELETE /v2/<name>/blobs/uploads/<id>.
func (h *Handler) cancelUpload(w http.ResponseWriter, r *http.Request, rn *repoName, id string) {
	up, err := h.openUpload(r.Context(), rn, id)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	cerr := up.Cancel()
	var b meta.Batch
	b.Delete(uploadKey(id))
	b.SetOrigin(h.origin(r, "oci.upload.cancel", rn.full))
	if err := h.commit(r.Context(), &b); err != nil {
		h.writeError(w, r, storeError(err))
		return
	}
	if cerr != nil {
		h.log.WarnContext(r.Context(), "removing a cancelled upload", "upload", id, "err", cerr)
	}
	w.Header().Set("Content-Length", "0")
	w.WriteHeader(http.StatusNoContent)
}

// finishUpload serves PUT /v2/<name>/blobs/uploads/<id>?digest=: the
// final chunk, if any, and the commit.
func (h *Handler) finishUpload(w http.ResponseWriter, r *http.Request, rn *repoName, id string) {
	d, err := parseDigest(r.URL.Query().Get("digest"))
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	up, err := h.openUpload(r.Context(), rn, id)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	if err := h.receive(r, rn, up); err != nil {
		if serr := up.Suspend(); serr != nil {
			h.forgetUpload(id)
		}
		h.writeReceiveError(w, r, rn, id, err)
		return
	}
	if err := h.commitUpload(r, rn, up, d, id); err != nil {
		h.writeError(w, r, err)
		return
	}
	writeBlobCreated(w, rn, d)
}

// commitUpload commits up as blob d and links it in rn, ending upload
// session id if it is not empty. The upload is closed whatever happens.
func (h *Handler) commitUpload(r *http.Request, rn *repoName, up blob.Upload, d blob.Digest, id string) error {
	ctx := r.Context()
	size := up.Size()
	closed := false
	err := h.commitLink(ctx, []blob.Digest{d}, func(v meta.View, b *meta.Batch) error {
		b.Put(blobKey(rn, d), encodeBlobLink(size, h.now()))
		if id != "" {
			b.Delete(uploadKey(id))
		}
		b.SetOrigin(h.origin(r, "oci.blob.push", rn.full+"@"+d.String()))
		return nil
	}, func(attempt int) error {
		if attempt > 0 {
			return h.statExists(ctx, d)(attempt)
		}
		closed = true
		_, err := up.Commit(ctx, d)
		if errors.Is(err, blob.ErrDigestMismatch) {
			return newError(http.StatusBadRequest, codeDigestInvalid, "%v", err).
				withDetail(map[string]string{"digest": d.String()})
		}
		return err
	})
	if !closed {
		up.Cancel()
	}
	if err != nil && id != "" {
		h.forgetUpload(id)
	}
	return err
}

// discardWriter is a ResponseWriter that drops everything, for asking the
// Authorizer a question without answering the request.
type discardWriter struct{}

func (discardWriter) Header() http.Header         { return http.Header{} }
func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }
func (discardWriter) WriteHeader(int)             {}
