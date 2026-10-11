package pypi

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/terrabyteian/flint/internal/blob"
	"github.com/terrabyteian/flint/internal/config"
	"github.com/terrabyteian/flint/internal/meta"
)

// serveIndex serves GET /pypi/<repo>/simple/: every project the
// repository has. A proxy repository lists the projects it has cached; a
// virtual repository, those of its members.
func (h *Handler) serveIndex(w http.ResponseWriter, r *http.Request, rp *repository) {
	format, ok := negotiate(r)
	if !ok {
		notAcceptable(w)
		return
	}
	v := h.view()
	names := h.projectNames(v, rp)
	v.Release()
	slices.Sort(names)
	names = slices.Compact(names)
	writePage(w, r, format, renderIndex(names, format))
}

// projectNames returns the normalized names of the projects rp has.
func (h *Handler) projectNames(v meta.View, rp *repository) []string {
	var out []string
	switch rp.typ {
	case config.TypeHosted, config.TypeProxy:
		ns := nsProject
		if rp.typ == config.TypeProxy {
			ns = nsPage
		}
		pfx := key(ns, rp.name, "")
		v.Scan(pfx, nil, func(k []byte, _ meta.Record) bool {
			out = append(out, string(k[len(pfx):]))
			return true
		})
	case config.TypeVirtual:
		for _, m := range rp.virtual.Members {
			if mr := h.repos[m.Name]; mr != nil {
				out = append(out, h.projectNames(v, mr)...)
			}
		}
	}
	return out
}

// serveProject serves GET /pypi/<repo>/simple/<project>/.
func (h *Handler) serveProject(w http.ResponseWriter, r *http.Request, rp *repository, project string) {
	format, ok := negotiate(r)
	if !ok {
		notAcceptable(w)
		return
	}
	p, result, err := h.projectOf(r.Context(), h.actor(r), rp, project)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	if rp.typ == config.TypeProxy {
		h.pm.Requests.With(rp.name, result).Inc()
	}
	writePage(w, r, format, renderProject(p, format))
}

func notAcceptable(w http.ResponseWriter) {
	writeError(w, http.StatusNotAcceptable, "acceptable formats: %s, %s, %s", mtSimpleJSON, mtSimpleHTML, mtHTML)
}

// writePage writes a simple API page with an ETag, so clients that
// revalidate their cached copy, as pip does, get 304 Not Modified when it
// has not changed.
func writePage(w http.ResponseWriter, r *http.Request, format string, body []byte) {
	sum := sha256.Sum256(body)
	hd := w.Header()
	hd.Set("Content-Type", contentType(format))
	hd.Set("Vary", "Accept")
	hd.Set("ETag", `"`+hex.EncodeToString(sum[:16])+`"`)
	hd.Set("Cache-Control", "max-age=0, must-revalidate")
	http.ServeContent(w, r, "", time.Time{}, bytes.NewReader(body))
}

// serveFile serves GET and HEAD /pypi/<repo>/files/<project>/<filename>.
func (h *Handler) serveFile(w http.ResponseWriter, r *http.Request, rp *repository, project, filename string) {
	switch rp.typ {
	case config.TypeHosted:
		v := h.view()
		f, err := hostedFile(v, rp, project, filename)
		v.Release()
		if err != nil {
			h.fail(w, r, err)
			return
		}
		if !h.serveBlob(w, r, f.Digest, f.Size, filename) {
			writeError(w, http.StatusInternalServerError, "the file cannot be read")
		}
	case config.TypeProxy:
		h.proxyFile(w, r, rp, project, filename, nil)
	default:
		f, err := h.virtualFile(r, rp, project, filename)
		if err != nil {
			h.fail(w, r, err)
			return
		}
		if f.src.typ == config.TypeHosted {
			if !h.serveBlob(w, r, f.rec.Digest, f.rec.Size, filename) {
				writeError(w, http.StatusInternalServerError, "the file cannot be read")
			}
			return
		}
		h.proxyFile(w, r, f.src, project, filename, f)
	}
}

// serveMetadata serves GET and HEAD
// /pypi/<repo>/files/<project>/<filename>.metadata.
func (h *Handler) serveMetadata(w http.ResponseWriter, r *http.Request, rp *repository, project, filename string) {
	var f *file
	switch rp.typ {
	case config.TypeHosted:
		v := h.view()
		rec, err := hostedFile(v, rp, project, filename)
		v.Release()
		if err != nil {
			h.fail(w, r, err)
			return
		}
		if !rec.MetaServed {
			writeError(w, http.StatusNotFound, "%s has no core-metadata file", filename)
			return
		}
		if !h.serveBlob(w, r, rec.Meta, rec.MetaSize, filename+".metadata") {
			writeError(w, http.StatusInternalServerError, "the file cannot be read")
		}
		return
	case config.TypeVirtual:
		var err error
		if f, err = h.virtualFile(r, rp, project, filename); err != nil {
			h.fail(w, r, err)
			return
		}
		if f.src.typ == config.TypeHosted {
			h.serveMetadata(w, r, f.src, project, filename)
			return
		}
		rp = f.src
	}
	h.proxyMetadata(w, r, rp, project, filename, f)
}

// serveBlob streams blob d, size bytes, as a download named filename. It
// reports false, having written nothing, if the blob is missing from the
// blob store, so a proxy can fetch it again.
func (h *Handler) serveBlob(w http.ResponseWriter, r *http.Request, d blob.Digest, size int64, filename string) bool {
	var f blob.Reader
	if r.Method != http.MethodHead {
		var err error
		f, err = h.blobs.Open(r.Context(), d)
		if errors.Is(err, blob.ErrNotFound) {
			h.log.WarnContext(r.Context(), "a linked blob is missing from the blob store", "digest", d.String(), "file", filename)
			return false
		}
		if err != nil {
			h.fail(w, r, err)
			return true
		}
		defer f.Close()
	}
	setFileHeaders(w, d.Hex(), filename)
	if r.Method == http.MethodHead {
		w.Header().Set("Accept-Ranges", "bytes")
		w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
		w.WriteHeader(http.StatusOK)
		return true
	}
	// The filesystem store returns the *os.File itself, so on plain
	// HTTP/1.1 ServeContent's copy reaches sendfile. It also answers
	// Range requests, with which pip resumes downloads.
	http.ServeContent(w, r, "", time.Time{}, f)
	return true
}

// setFileHeaders sets the headers of a file download.
func setFileHeaders(w http.ResponseWriter, sha string, filename string) {
	hd := w.Header()
	if strings.HasSuffix(filename, ".metadata") {
		hd.Set("Content-Type", "text/plain; charset=utf-8")
	} else {
		hd.Set("Content-Type", "application/octet-stream")
	}
	if sha != "" {
		hd.Set("ETag", `"sha256:`+sha+`"`)
	}
	// Distribution files never change: a file name is never reused.
	hd.Set("Cache-Control", "public, max-age=31536000, immutable")
	hd.Set("X-Content-Type-Options", "nosniff")
}
