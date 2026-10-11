package cargo

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/terrabyteian/flint/internal/blob"
	"github.com/terrabyteian/flint/internal/config"
	"github.com/terrabyteian/flint/internal/repo"
	"github.com/terrabyteian/flint/internal/server"
)

// indexConfig is an index's config.json.
type indexConfig struct {
	DL           string `json:"dl"`
	API          string `json:"api"`
	AuthRequired bool   `json:"auth-required"`
}

// serveConfig serves GET /cargo/<repo>/config.json: downloads and the web
// API at the repository's own URLs, for every repository type, and
// auth-required unless anyone may pull, so Cargo sends its token with
// every request.
func (h *Handler) serveConfig(w http.ResponseWriter, r *http.Request, rp *repository) {
	api := server.BaseURL(r) + repo.Path(config.FormatCargo, rp.name)
	api = api[:len(api)-1] // without the trailing "/"
	b, _ := json.Marshal(indexConfig{DL: api + "/api/v1/crates", API: api, AuthRequired: !rp.anonymous})
	writeDoc(w, r, b, "application/json", "")
}

// writeDoc writes an index document, with an ETag, the given one or a
// digest of the body, so clients that revalidate their copy, as Cargo
// does, get 304 Not Modified while it has not changed.
func writeDoc(w http.ResponseWriter, r *http.Request, body []byte, contentType, etag string) {
	if etag == "" {
		sum := sha256.Sum256(body)
		etag = `"` + hex.EncodeToString(sum[:16]) + `"`
	}
	hd := w.Header()
	hd.Set("Content-Type", contentType)
	hd.Set("ETag", etag)
	hd.Set("Cache-Control", "max-age=0, must-revalidate")
	http.ServeContent(w, r, "", time.Time{}, bytes.NewReader(body))
}

// serveIndex serves a crate's index file, named by its lowercase name.
func (h *Handler) serveIndex(w http.ResponseWriter, r *http.Request, rp *repository, crate string) {
	switch rp.typ {
	case config.TypeHosted:
		v := h.meta.View()
		es, etag, err := hostedIndex(v, rp, crate)
		v.Release()
		if err != nil {
			h.fail(w, r, err)
			return
		}
		writeDoc(w, r, renderIndex(es), indexType, etag)
	case config.TypeProxy:
		h.proxyIndexFile(w, r, rp, crate)
	default:
		es, err := h.virtualIndex(r.Context(), h.actor(r), rp, crate)
		if err != nil {
			h.fail(w, r, err)
			return
		}
		writeDoc(w, r, renderIndex(es), indexType, "")
	}
}

// indexType is the content type of index files.
const indexType = "text/plain; charset=utf-8"

// indexOf returns the lines of rp's index file for crate, a lowercase
// name, or a 404 error if it has none. For a proxy or virtual repository
// it may ask the upstream.
func (h *Handler) indexOf(r *http.Request, rp *repository, crate string) ([]*entry, error) {
	switch rp.typ {
	case config.TypeHosted:
		v := h.meta.View()
		defer v.Release()
		es, _, err := hostedIndex(v, rp, crate)
		return es, err
	case config.TypeProxy:
		es, _, err := h.proxyIndex(r.Context(), h.actor(r), rp, crate)
		return es, err
	}
	return h.virtualIndex(r.Context(), h.actor(r), rp, crate)
}

// serveDownload serves GET and HEAD of a .crate file.
func (h *Handler) serveDownload(w http.ResponseWriter, r *http.Request, rp *repository, crate, vers string) {
	switch rp.typ {
	case config.TypeHosted:
		v := h.meta.View()
		rec, err := hostedVersion(v, rp, crate, vers)
		v.Release()
		if err != nil {
			h.fail(w, r, err)
			return
		}
		h.serveCrate(w, r, rp, rec.Digest, rec.Size)
	case config.TypeProxy:
		h.proxyDownload(w, r, rp, crate, vers, nil)
	default:
		e, err := h.virtualVersion(r, rp, crate, vers)
		if err != nil {
			h.fail(w, r, err)
			return
		}
		src := h.repos[e.src]
		if e.rec != nil {
			h.serveCrate(w, r, rp, e.rec.Digest, e.rec.Size)
			return
		}
		h.proxyDownload(w, r, src, crate, vers, e)
	}
}

// crateType is the content type of .crate files.
const crateType = "application/gzip"

// serveCrate streams the .crate file in blob d, size bytes, from rp.
func (h *Handler) serveCrate(w http.ResponseWriter, r *http.Request, rp *repository, d blob.Digest, size int64) {
	var f blob.Reader
	if r.Method != http.MethodHead {
		var err error
		f, err = h.blobs.Open(r.Context(), d)
		if errors.Is(err, blob.ErrNotFound) {
			h.log.ErrorContext(r.Context(), "a published .crate file is missing from the blob store", "digest", d.String())
			writeError(w, http.StatusInternalServerError, "the crate cannot be read")
			return
		}
		if err != nil {
			h.fail(w, r, err)
			return
		}
		defer f.Close()
	}
	hd := w.Header()
	hd.Set("Content-Type", crateType)
	hd.Set("ETag", `"`+d.String()+`"`)
	// A published version never changes. Shared caches may keep it only
	// when anyone may download it.
	cc := "private, max-age=31536000, immutable"
	if rp.anonymous {
		cc = "public, max-age=31536000, immutable"
	}
	hd.Set("Cache-Control", cc)
	hd.Set("X-Content-Type-Options", "nosniff")
	if r.Method == http.MethodHead {
		hd.Set("Accept-Ranges", "bytes")
		hd.Set("Content-Length", strconv.FormatInt(size, 10))
		w.WriteHeader(http.StatusOK)
		return
	}
	// The filesystem store returns the *os.File itself, so on plain
	// HTTP/1.1 ServeContent's copy reaches sendfile.
	http.ServeContent(w, r, "", time.Time{}, f)
}

// writeJSON writes v as a JSON response.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	writeJSONTo(w, v)
}

func writeJSONTo(w io.Writer, v any) {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.Encode(v)
}
