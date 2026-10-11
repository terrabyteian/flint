package oci

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/terrabyteian/flint/internal/blob"
	"github.com/terrabyteian/flint/internal/meta"
)

// maxPageSize bounds one page of a tag or catalog listing. A client that
// asks for more, or for no limit, gets pages of this size with a Link
// header to the next one.
const maxPageSize = 1000

// pageParams parses the n and last parameters of a paginated listing.
func pageParams(r *http.Request) (n int, last string, err error) {
	q := r.URL.Query()
	n = maxPageSize
	if s := q.Get("n"); s != "" {
		v, perr := strconv.Atoi(s)
		if perr != nil || v < 0 {
			return 0, "", newError(http.StatusBadRequest, "PAGINATION_NUMBER_INVALID", "n must be a non-negative integer")
		}
		n = min(v, maxPageSize)
	}
	return n, q.Get("last"), nil
}

// writeJSON answers 200 with a JSON body.
func writeJSON(w http.ResponseWriter, contentType string, v any) {
	body, _ := json.Marshal(v)
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(http.StatusOK)
	w.Write(body)
}

// setNextLink sets the Link header to the next page of a listing.
func setNextLink(w http.ResponseWriter, path string, n int, last string) {
	q := url.Values{"n": {strconv.Itoa(n)}, "last": {last}}
	w.Header().Set("Link", fmt.Sprintf(`<%s?%s>; rel="next"`, path, q.Encode()))
}

// listTags serves GET /v2/<name>/tags/list, in lexical order.
func (h *Handler) listTags(w http.ResponseWriter, r *http.Request, rn *repoName, _ string) {
	n, last, err := pageParams(r)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	v := h.view()
	defer v.Release()
	pfx := prefix(nsTag, rn)
	var after []byte
	if last != "" {
		after = append(bytes.Clone(pfx), last...)
	}
	tags := []string{}
	more := false
	if n > 0 {
		v.Scan(pfx, after, func(key []byte, _ meta.Record) bool {
			if len(tags) == n {
				more = true
				return false
			}
			tags = append(tags, string(key[len(pfx):]))
			return true
		})
	}
	if len(tags) == 0 && last == "" && !nameExists(v, rn) {
		h.writeError(w, r, newError(http.StatusNotFound, codeNameUnknown, "repository %s has no manifests", rn.full))
		return
	}
	if more {
		setNextLink(w, "/v2/"+rn.full+"/tags/list", n, tags[len(tags)-1])
	}
	writeJSON(w, "application/json", struct {
		Name string   `json:"name"`
		Tags []string `json:"tags"`
	}{rn.full, tags})
}

// nameExists reports whether rn holds any manifest.
func nameExists(v meta.View, rn *repoName) bool {
	found := false
	v.Scan(prefix(nsManifest, rn), nil, func([]byte, meta.Record) bool {
		found = true
		return false
	})
	return found
}

// catalog serves GET /v2/_catalog: the repository names holding at least
// one manifest that the caller may see.
func (h *Handler) catalog(w http.ResponseWriter, r *http.Request) {
	ca, ok := h.auth.(CatalogAuthorizer)
	if !ok {
		h.writeError(w, r, newError(http.StatusNotFound, codeUnsupported, "the catalog is not available"))
		return
	}
	visible, ok := ca.AuthorizeCatalog(w, r)
	if !ok {
		return
	}
	n, last, err := pageParams(r)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	v := h.view()
	defer v.Release()
	// Manifest keys are ordered by repository, then name, then digest.
	// Each step finds the first manifest after the previous name and
	// skips past the rest of that name's manifests.
	pfx := []byte(nsManifest)
	skip := func(repo, name string) []byte {
		k := append(bytes.Clone(pfx), repo...)
		k = append(k, 0)
		k = append(k, name...)
		return append(k, 0, 0xff) // after every digest of the name
	}
	var after []byte
	if last != "" {
		repo, name, _ := strings.Cut(last, "/")
		after = skip(repo, name)
	}
	names := []string{}
	more := false
	for n > 0 {
		var repo, name string
		found := false
		v.Scan(pfx, after, func(key []byte, _ meta.Record) bool {
			parts := strings.SplitN(string(key[len(pfx):]), "\x00", 3)
			if len(parts) == 3 {
				repo, name, found = parts[0], parts[1], true
			}
			return false
		})
		if !found {
			break
		}
		after = skip(repo, name)
		full := repo + "/" + name
		if h.repos[repo] == nil || !visible(full) {
			continue
		}
		if len(names) == n {
			more = true
			break
		}
		names = append(names, full)
	}
	if more {
		setNextLink(w, "/v2/_catalog", n, names[len(names)-1])
	}
	writeJSON(w, "application/json", struct {
		Repositories []string `json:"repositories"`
	}{names})
}

// listReferrers serves GET /v2/<name>/referrers/<digest>: an image index
// of the manifests whose subject is the digest, optionally filtered by
// ?artifactType=.
func (h *Handler) listReferrers(w http.ResponseWriter, r *http.Request, rn *repoName, arg string) {
	d, err := parseDigest(arg)
	if err != nil {
		h.writeError(w, r, err)
		return
	}
	filter := r.URL.Query().Get("artifactType")
	type referrer struct {
		MediaType    string          `json:"mediaType"`
		Size         int64           `json:"size"`
		Digest       string          `json:"digest"`
		ArtifactType string          `json:"artifactType,omitempty"`
		Annotations  json.RawMessage `json:"annotations,omitempty"`
	}
	refs := []referrer{}
	v := h.view()
	pfx := referrerPrefix(rn, d)
	var failure error
	v.Scan(pfx, nil, func(key []byte, _ meta.Record) bool {
		rd, err := blob.ParseDigest(string(key[len(pfx):]))
		if err != nil {
			failure = err
			return false
		}
		rec, ok := v.Get(manifestKey(rn, rd))
		if !ok {
			return true
		}
		m, err := decodeManifest(rec.Value)
		if err != nil {
			failure = err
			return false
		}
		if filter != "" && m.ArtifactType != filter {
			return true
		}
		refs = append(refs, referrer{
			MediaType:    m.MediaType,
			Size:         m.Size,
			Digest:       rd.String(),
			ArtifactType: m.ArtifactType,
			Annotations:  json.RawMessage(m.Annotations),
		})
		return true
	})
	v.Release()
	if failure != nil {
		h.writeError(w, r, failure)
		return
	}
	if filter != "" {
		w.Header().Set("OCI-Filters-Applied", "artifactType")
	}
	writeJSON(w, mtOCIIndex, struct {
		SchemaVersion int        `json:"schemaVersion"`
		MediaType     string     `json:"mediaType"`
		Manifests     []referrer `json:"manifests"`
	}{2, mtOCIIndex, refs})
}
