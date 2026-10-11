package generic

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/terrabyteian/flint/internal/blob"
	"github.com/terrabyteian/flint/internal/config"
	"github.com/terrabyteian/flint/internal/gc"
	"github.com/terrabyteian/flint/internal/meta"
	"github.com/terrabyteian/flint/internal/repo"
)

// lookup returns the record of the file at path in hosted repository
// repo, live or a tombstone, or nil.
func (h *Handler) lookup(repoName, p string) (*fileRecord, error) {
	v := h.meta.View()
	defer v.Release()
	rec, ok := v.Get(fileKey(repoName, p))
	if !ok {
		return nil, nil
	}
	f, err := decodeFile(rec.Value)
	if err != nil {
		return nil, fmt.Errorf("generic: file record of %s in %s: %w", p, repoName, err)
	}
	return f, nil
}

// serveFile serves GET and HEAD /generic/<repo>/<path>.
func (h *Handler) serveFile(w http.ResponseWriter, r *http.Request, rp *repository, p string) {
	switch rp.typ {
	case config.TypeHosted:
		f, err := h.lookup(rp.name, p)
		switch {
		case err != nil:
			h.fail(w, r, err)
		case f == nil || f.Kind != kindFile:
			writeError(w, http.StatusNotFound, "%s is not found", abbrev(p))
		case !h.serveBlob(w, r, rp, f):
			writeError(w, http.StatusInternalServerError, "the file cannot be read")
		}
	case config.TypeProxy:
		h.proxyFile(w, r, rp, p)
	default:
		h.virtualFile(w, r, rp, p)
	}
}

// serveBlob serves hosted file f of rp. It reports false, having written
// nothing, if its blob is missing from the blob store.
func (h *Handler) serveBlob(w http.ResponseWriter, r *http.Request, rp *repository, f *fileRecord) bool {
	b, err := h.blobs.Open(r.Context(), f.Digest)
	if errors.Is(err, blob.ErrNotFound) {
		h.log.WarnContext(r.Context(), "a linked blob is missing from the blob store", "digest", f.Digest.String(),
			"repository", rp.name, "path", r.URL.Path)
		return false
	}
	if err != nil {
		h.fail(w, r, err)
		return true
	}
	defer b.Close()
	hd := w.Header()
	setFileHeaders(hd)
	hd.Set("Content-Type", f.ContentType)
	hd.Set("ETag", `"`+f.Digest.String()+`"`)
	sum, _ := hex.DecodeString(f.Digest.Hex())
	hd.Set("Repr-Digest", "sha-256=:"+base64.StdEncoding.EncodeToString(sum)+":")
	hd.Set("X-Checksum-Sha256", f.Digest.Hex())
	switch {
	case rp.overwrite:
		hd.Set("Cache-Control", "no-cache")
	case rp.anonymous:
		hd.Set("Cache-Control", "public, max-age=31536000, immutable")
	default:
		hd.Set("Cache-Control", "private, max-age=31536000, immutable")
	}
	// The filesystem store returns the *os.File itself, so on plain
	// HTTP/1.1 ServeContent's copy reaches sendfile. It also answers
	// Range and conditional requests, and HEAD; Last-Modified lets wget
	// -N skip files it has.
	http.ServeContent(w, r, "", f.Uploaded, b)
	return true
}

// setFileHeaders sets the headers every file download has, from any kind
// of repository: uploaded content never runs as a page of flint's
// origin, and is never sniffed as another type.
func setFileHeaders(hd http.Header) {
	hd.Set("X-Content-Type-Options", "nosniff")
	hd.Set("Content-Security-Policy", "sandbox")
}

// serveUpload serves PUT /generic/<repo>/<path>. An upload to a virtual
// repository with publishTo goes to that hosted member, and needs the
// permission an upload to it directly needs; it is refused if the
// member's filters do not admit the path.
func (h *Handler) serveUpload(w http.ResponseWriter, r *http.Request, rp *repository, p string) {
	var via *repo.Virtual
	switch {
	case rp.typ == config.TypeProxy:
		writeError(w, http.StatusMethodNotAllowed, "repository %s is a read-only proxy of %s; upload to a hosted repository instead",
			rp.name, rp.proxy.base.Redacted())
		return
	case rp.typ == config.TypeVirtual && rp.virtual.PublishTo == "":
		writeError(w, http.StatusMethodNotAllowed,
			"repository %s is a virtual repository without publishTo; upload to one of its hosted members: %s",
			rp.name, strings.Join(rp.virtual.Hosted(), ", "))
		return
	}
	if !h.permit(w, r, rp, ActionPush) {
		return
	}
	if rp.typ == config.TypeVirtual {
		if err := rp.virtual.CheckPublish(p); err != nil {
			writeError(w, http.StatusForbidden, "%v", err)
			return
		}
		via, rp = rp.virtual, h.repos[rp.virtual.PublishTo]
	}
	created, f, err := h.storeUpload(r, rp, p)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	h.uploads.With(rp.name).Inc()
	h.uploadBytes.With(rp.name).Add(float64(f.Size))
	h.log.InfoContext(r.Context(), "generic file uploaded", "repository", rp.name, "path", p,
		"digest", f.Digest.String(), "size", f.Size, "created", created, "via", viaName(via))
	status := http.StatusOK
	if created {
		status = http.StatusCreated
		w.Header().Set("Location", repo.Path(config.FormatGeneric, rp.name)+escapePath(p))
	}
	w.Header().Set("ETag", `"`+f.Digest.String()+`"`)
	writeJSON(w, status, fileInfo(rp.name, p, f))
}

func viaName(v *repo.Virtual) string {
	if v == nil {
		return ""
	}
	return v.Name
}

// storeUpload stores the request body as the file at path p of hosted
// repository rp. It reports whether the path had no live file before,
// and returns the file record as stored or as it already was.
func (h *Handler) storeUpload(r *http.Request, rp *repository, p string) (bool, *fileRecord, error) {
	ctx := r.Context()
	want, err := requestDigest(r.Header)
	if err != nil {
		return false, nil, err
	}
	if !rp.overwrite {
		// Refuse a path that can never be used again, or that holds other
		// content than the client says it sends, before reading the body.
		switch f, err := h.lookup(rp.name, p); {
		case err != nil:
			return false, nil, err
		case f != nil && f.Kind == kindTombstone:
			return false, nil, conflict(p, repo.ErrTombstoned)
		case f != nil && !want.IsZero() && f.Digest != want:
			return false, nil, conflict(p, repo.ErrPublished)
		}
	}
	ct, err := uploadType(r.Header.Get("Content-Type"), p)
	if err != nil {
		return false, nil, err
	}
	up, err := h.blobs.NewUpload(ctx)
	if err != nil {
		return false, nil, err
	}
	if _, err := io.Copy(up, r.Body); err != nil {
		up.Cancel()
		if ctx.Err() != nil {
			return false, nil, ctx.Err()
		}
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			return false, nil, errorf(http.StatusRequestEntityTooLarge, "the file is too large")
		}
		return false, nil, errorf(http.StatusBadRequest, "reading the uploaded file: %v", err)
	}
	info, err := up.Commit(ctx, want)
	if errors.Is(err, blob.ErrDigestMismatch) {
		return false, nil, errorf(http.StatusBadRequest, "the file does not match the digest the request sent: %v", err)
	}
	if err != nil {
		return false, nil, err
	}
	rec := &fileRecord{Kind: kindFile, Digest: info.Digest, Size: info.Size, ContentType: ct, Uploaded: h.now().UTC()}
	k := fileKey(rp.name, p)
	write := func(v meta.View, b *meta.Batch) error {
		if err := gc.Guard(v, b, rec.Digest); err != nil {
			return err
		}
		// The guard's view was read before this check, as it requires.
		if _, err := h.blobs.Stat(ctx, rec.Digest); errors.Is(err, blob.ErrNotFound) {
			return errRetry // swept since it was committed; the client uploads again
		} else if err != nil {
			return err
		}
		b.Put(k, rec.encode())
		b.SetOrigin(h.origin(r, "generic.upload", rp.name+"/"+p))
		return nil
	}
	var created bool
	if rp.overwrite {
		created, rec, err = h.overwrite(ctx, k, rec, write)
	} else {
		var changed bool
		changed, err = repo.Publish(ctx, h.meta, k, rec.Digest, readExisting, write)
		created = changed
		if err == nil && !changed {
			rec, err = h.lookup(rp.name, p)
		}
	}
	switch {
	case errors.Is(err, repo.ErrPublished), errors.Is(err, repo.ErrTombstoned):
		return false, nil, conflict(p, err)
	case errors.Is(err, meta.ErrConflict), errors.Is(err, gc.ErrDoomed):
		return false, nil, errRetry
	case err != nil:
		return false, nil, err
	case rec == nil || rec.Kind != kindFile:
		return false, nil, errRetry // deleted meanwhile
	}
	return created, rec, nil
}

// readExisting decodes a file record for repo.Publish.
func readExisting(value []byte) (repo.Existing, error) {
	f, err := decodeFile(value)
	if err != nil {
		return repo.Existing{}, err
	}
	return repo.Existing{Tombstone: f.Kind == kindTombstone, Digest: f.Digest}, nil
}

// conflict is the response to an upload refused by the immutable-name
// rule.
func conflict(p string, err error) error {
	if errors.Is(err, repo.ErrTombstoned) {
		return errorf(http.StatusConflict, "%s was deleted, and a deleted file's path can never be used again; upload to a new path", abbrev(p))
	}
	return errorf(http.StatusConflict, "%s exists with different content, and files are immutable; upload to a new path", abbrev(p))
}

// maxWriteAttempts bounds how often a batch is retried after a metadata
// precondition fails.
const maxWriteAttempts = 4

// overwrite stores rec under key k of a repository that allows
// overwrites, replacing what is there; an identical live file is left as
// it is. It reports whether there was no live file, and returns the
// record stored, or the one already there.
func (h *Handler) overwrite(ctx context.Context, k []byte, rec *fileRecord, write func(meta.View, *meta.Batch) error) (bool, *fileRecord, error) {
	for attempt := 0; ; attempt++ {
		v := h.meta.View()
		old, ok := v.Get(k)
		created := !ok
		var b meta.Batch
		var err error
		if ok {
			var f *fileRecord
			if f, err = decodeFile(old.Value); err == nil {
				if f.Kind == kindFile && f.Digest == rec.Digest {
					v.Release()
					return false, f, nil
				}
				created = f.Kind != kindFile
			}
		}
		if err == nil {
			b.Require(k, old.Version) // version 0 when absent
			err = write(v, &b)
		}
		v.Release()
		if err == nil {
			_, err = h.meta.Commit(ctx, &b)
		}
		switch {
		case err == nil:
			return created, rec, nil
		case errors.Is(err, meta.ErrConflict) && attempt < maxWriteAttempts-1:
		default:
			return false, nil, err
		}
	}
}

// requestDigest returns the sha256 digest an upload's headers say its
// body has, from Content-Digest (RFC 9530) or X-Checksum-Sha256, or zero
// if they say none.
func requestDigest(hd http.Header) (blob.Digest, error) {
	var d blob.Digest
	if s := strings.TrimSpace(hd.Get("X-Checksum-Sha256")); s != "" {
		var err error
		if d, err = blob.ParseDigest("sha256:" + strings.ToLower(s)); err != nil {
			return blob.Digest{}, errorf(http.StatusBadRequest, "X-Checksum-Sha256 %q is not 64 hex digits", abbrev(s))
		}
	}
	for _, line := range hd.Values("Content-Digest") {
		for item := range strings.SplitSeq(line, ",") {
			alg, val, ok := strings.Cut(strings.TrimSpace(item), "=")
			if !ok {
				return blob.Digest{}, errorf(http.StatusBadRequest, "Content-Digest %q is not alg=:base64:", abbrev(item))
			}
			if !strings.EqualFold(strings.TrimSpace(alg), "sha-256") {
				continue // other algorithms are not checked
			}
			val = strings.TrimSpace(val)
			sum, err := base64.StdEncoding.DecodeString(strings.TrimSuffix(strings.TrimPrefix(val, ":"), ":"))
			if err != nil || len(sum) != 32 || len(val) < 2 || val[0] != ':' || val[len(val)-1] != ':' {
				return blob.Digest{}, errorf(http.StatusBadRequest, "Content-Digest sha-256 %q is not a base64 sha-256 digest between colons", abbrev(val))
			}
			cd, _ := blob.ParseDigest("sha256:" + hex.EncodeToString(sum))
			if !d.IsZero() && d != cd {
				return blob.Digest{}, errorf(http.StatusBadRequest, "Content-Digest and X-Checksum-Sha256 name different digests")
			}
			d = cd
		}
	}
	return d, nil
}

// uploadType returns the content type to store for an upload of path p
// sent with Content-Type ct: ct, unless it is absent or what a client
// sends for a form, in which case the type is inferred from p's
// extension, or application/octet-stream.
func uploadType(ct, p string) (string, error) {
	if ct != "" {
		mt, params, err := mime.ParseMediaType(ct)
		if err != nil {
			return "", errorf(http.StatusBadRequest, "Content-Type %q is not a media type", abbrev(ct))
		}
		switch mt {
		case "application/x-www-form-urlencoded", "multipart/form-data":
			// What curl --data-binary and wget --body-file send by default.
		default:
			return mime.FormatMediaType(mt, params), nil
		}
	}
	if t := mime.TypeByExtension(path.Ext(p)); t != "" {
		return t, nil
	}
	return "application/octet-stream", nil
}

// serveDelete serves DELETE /generic/<repo>/<path>: in an immutable
// repository, the file becomes a tombstone, and its path can never be
// used again; in one that allows overwrites, its record is deleted.
func (h *Handler) serveDelete(w http.ResponseWriter, r *http.Request, rp *repository, p string) {
	if rp.typ != config.TypeHosted {
		writeError(w, http.StatusMethodNotAllowed, "repository %s is a %s repository; delete files from a hosted repository", rp.name, rp.typ)
		return
	}
	if !h.permit(w, r, rp, ActionDelete) {
		return
	}
	k := fileKey(rp.name, p)
	for attempt := 0; ; attempt++ {
		v := h.meta.View()
		old, ok := v.Get(k)
		v.Release()
		var f *fileRecord
		var err error
		if ok {
			f, err = decodeFile(old.Value)
		}
		switch {
		case err != nil:
			h.fail(w, r, err)
			return
		case f == nil || f.Kind != kindFile:
			writeError(w, http.StatusNotFound, "%s is not found", abbrev(p))
			return
		}
		var b meta.Batch
		b.Require(k, old.Version)
		if rp.overwrite {
			b.Delete(k)
		} else {
			b.Put(k, (&fileRecord{Kind: kindTombstone, Deleted: h.now().UTC()}).encode())
		}
		b.SetOrigin(h.origin(r, "generic.delete", rp.name+"/"+p))
		_, err = h.meta.Commit(r.Context(), &b)
		switch {
		case err == nil:
			h.log.InfoContext(r.Context(), "generic file deleted", "repository", rp.name, "path", p, "digest", f.Digest.String())
			w.WriteHeader(http.StatusNoContent)
			return
		case errors.Is(err, meta.ErrConflict) && attempt < maxWriteAttempts-1:
		case errors.Is(err, meta.ErrConflict):
			h.fail(w, r, errRetry)
			return
		default:
			h.fail(w, r, err)
			return
		}
	}
}

// entry is a listing's entry: a file, or a directory, whose name ends
// in "/".
type entry struct {
	Name        string     `json:"name"`
	Type        string     `json:"type"` // "file" or "directory"
	Size        *int64     `json:"size,omitempty"`
	SHA256      string     `json:"sha256,omitempty"`
	ContentType string     `json:"contentType,omitempty"`
	Uploaded    *time.Time `json:"uploaded,omitempty"`
}

func fileEntry(name string, f *fileRecord) entry {
	size, up := f.Size, f.Uploaded
	return entry{Name: name, Type: "file", Size: &size, SHA256: f.Digest.Hex(), ContentType: f.ContentType, Uploaded: &up}
}

// listing is a directory's listing.
type listing struct {
	Repository string  `json:"repository"`
	Path       string  `json:"path"` // "" for the root, else ending in "/"
	Entries    []entry `json:"entries"`
}

// list returns the files and directories directly below dir ("" or
// ending in "/") in hosted repository repoName that admit admits, by
// their full paths; nil admits everything. A directory is listed if it
// has a live file below it.
func list(v meta.View, repoName, dir string, admit func(string) bool) ([]entry, error) {
	pfx := fileKey(repoName, dir)
	out := []entry{}
	var after []byte
	var lastDir string
	var failure error
	for {
		skip := false
		v.Scan(pfx, after, func(k []byte, rec meta.Record) bool {
			rel := string(k[len(pfx):])
			sub, _, isDir := strings.Cut(rel, "/")
			if isDir && sub+"/" == lastDir {
				return true
			}
			f, err := decodeFile(rec.Value)
			if err != nil {
				failure = fmt.Errorf("generic: file record of %s%s in %s: %w", dir, rel, repoName, err)
				return false
			}
			if f.Kind != kindFile || admit != nil && !admit(dir+rel) {
				return true
			}
			if !isDir {
				out = append(out, fileEntry(rel, f))
				return true
			}
			lastDir = sub + "/"
			out = append(out, entry{Name: lastDir, Type: "directory"})
			if admit == nil {
				// Skip the rest of the directory: every path below it
				// sorts before "<sub>/\xff", since UTF-8 has no 0xff.
				after = append(append(bytes.Clone(pfx), lastDir...), 0xff)
				skip = true
				return false
			}
			return true
		})
		if failure != nil || !skip {
			return out, failure
		}
	}
}

// serveListing serves GET and HEAD /generic/<repo>/<dir>/.
func (h *Handler) serveListing(w http.ResponseWriter, r *http.Request, rp *repository, dir string) {
	var entries []entry
	var err error
	v := h.meta.View()
	switch rp.typ {
	case config.TypeHosted:
		entries, err = list(v, rp.name, dir, nil)
	case config.TypeVirtual:
		entries, err = h.virtualListing(v, rp, dir)
	default:
		v.Release()
		writeError(w, http.StatusNotFound, "repository %s is a proxy of %s, whose directory listings are not proxied; request a file",
			rp.name, rp.proxy.base.Redacted())
		return
	}
	v.Release()
	if err != nil {
		h.fail(w, r, err)
		return
	}
	if dir != "" && len(entries) == 0 {
		writeError(w, http.StatusNotFound, "directory %s is not found", abbrev(dir))
		return
	}
	l := listing{Repository: rp.name, Path: dir, Entries: entries}
	var body []byte
	if wantsJSON(r) {
		body, err = json.Marshal(l)
		w.Header().Set("Content-Type", "application/json")
	} else {
		body, err = renderListing(l)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
	}
	if err != nil {
		h.fail(w, r, err)
		return
	}
	hd := w.Header()
	hd.Set("Vary", "Accept")
	hd.Set("Cache-Control", "no-cache")
	hd.Set("X-Content-Type-Options", "nosniff")
	hd.Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		w.Write(body)
	}
}

// wantsJSON reports whether a request's Accept header asks for JSON.
func wantsJSON(r *http.Request) bool {
	for _, part := range r.Header.Values("Accept") {
		for item := range strings.SplitSeq(part, ",") {
			mt, params, err := mime.ParseMediaType(strings.TrimSpace(item))
			if err == nil && mt == "application/json" && params["q"] != "0" {
				return true
			}
		}
	}
	return false
}

// fileInfo describes an uploaded file in an upload's response.
func fileInfo(repoName, p string, f *fileRecord) any {
	return struct {
		Repository  string    `json:"repository"`
		Path        string    `json:"path"`
		SHA256      string    `json:"sha256"`
		Size        int64     `json:"size"`
		ContentType string    `json:"contentType"`
		Uploaded    time.Time `json:"uploaded"`
	}{repoName, p, f.Digest.Hex(), f.Size, f.ContentType, f.Uploaded}
}

// writeJSON writes v as a JSON response.
func writeJSON(w http.ResponseWriter, status int, v any) {
	b, _ := json.Marshal(v)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(b)+1))
	w.WriteHeader(status)
	w.Write(append(b, '\n'))
}
