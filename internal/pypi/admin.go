package pypi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/terrabyteian/flint/internal/config"
	"github.com/terrabyteian/flint/internal/meta"
	"github.com/terrabyteian/flint/internal/server"
)

// The admin API's PyPI endpoints yank, unyank, and delete files of hosted
// repositories. Like the rest of the admin API, they authenticate with
// HTTP basic credentials and answer JSON. They need the delete role on
// the repository.
//
//	PUT    /api/v1/pypi/{repo}/projects/{project}/releases/{version}/yank   yank a release (PEP 592)
//	DELETE /api/v1/pypi/{repo}/projects/{project}/releases/{version}/yank   unyank it
//	DELETE /api/v1/pypi/{repo}/projects/{project}/releases/{version}        delete a release's files
//	DELETE /api/v1/pypi/{repo}/projects/{project}/files/{filename}          delete one file
//
// A deleted file leaves a tombstone, so its name can never be uploaded
// again: a re-uploaded file with other content under the same name would
// break installs that pin its hash.

const adminPrefix = "/api/v1/pypi/{repo}/projects/{project}/"

// maxAdminBody bounds admin request bodies.
const maxAdminBody = 64 << 10

func (h *Handler) registerAdmin(s interface{ Handle(string, http.Handler) }) {
	s.Handle("PUT "+adminPrefix+"releases/{version}/yank", h.admin("pypi.yank", h.apiYank))
	s.Handle("DELETE "+adminPrefix+"releases/{version}/yank", h.admin("pypi.unyank", h.apiUnyank))
	s.Handle("DELETE "+adminPrefix+"releases/{version}", h.admin("pypi.delete", h.apiDeleteRelease))
	s.Handle("DELETE "+adminPrefix+"files/{filename}", h.admin("pypi.delete", h.apiDeleteFile))
}

// adminHandler serves an admin request for a hosted repository and project.
type adminHandler func(r *http.Request, rp *repository, project string) (any, error)

// admin authenticates and authorizes an admin request, runs f, and writes
// its result: 200 with the JSON f returns, or an error.
func (h *Handler) admin(route string, f adminHandler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		server.SetRoute(r.Context(), "api."+route)
		w.Header().Set("Cache-Control", "no-store")
		rp := h.repos[r.PathValue("repo")]
		if rp == nil {
			writeJSON(w, http.StatusNotFound, apiError{"no PyPI repository is named " + abbrev(r.PathValue("repo"))})
			return
		}
		switch status := h.auth.Permit(r, rp.name, ActionDelete); status {
		case http.StatusOK:
		case http.StatusUnauthorized:
			w.Header().Set("WWW-Authenticate", `Basic realm="flint"`)
			writeJSON(w, status, apiError{"authentication required"})
			return
		case http.StatusForbidden:
			writeJSON(w, status, apiError{"this requires the delete role on repository " + rp.name})
			return
		default:
			writeJSON(w, http.StatusInternalServerError, apiError{"internal error"})
			return
		}
		if rp.typ != config.TypeHosted {
			writeJSON(w, http.StatusMethodNotAllowed, apiError{"repository " + rp.name + " is a " + rp.typ +
				" repository; files can be yanked and deleted only in hosted repositories"})
			return
		}
		project := r.PathValue("project")
		if !ValidProjectName(project) {
			writeJSON(w, http.StatusNotFound, apiError{"project " + abbrev(project) + " is not found"})
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxAdminBody)
		v, err := f(r, rp, Normalize(project))
		if err != nil {
			var he *httpError
			var mbe *http.MaxBytesError
			switch {
			case errors.As(err, &he):
				writeJSON(w, he.status, apiError{he.msg})
			case errors.As(err, &mbe):
				writeJSON(w, http.StatusRequestEntityTooLarge, apiError{"the request body is too large"})
			case errors.Is(err, meta.ErrPoisoned), errors.Is(err, meta.ErrClosed):
				writeJSON(w, http.StatusServiceUnavailable, apiError{"the registry cannot accept writes now"})
			default:
				h.log.ErrorContext(r.Context(), "pypi admin request failed", "path", r.URL.Path, "err", err)
				writeJSON(w, http.StatusInternalServerError, apiError{"internal error"})
			}
			return
		}
		writeJSON(w, http.StatusOK, v)
	})
}

type apiError struct {
	Error string `json:"error"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(v)
}

// filesResult is the response of the yank and delete endpoints: the
// files the request changed.
type filesResult struct {
	Project string   `json:"project"`
	Version string   `json:"version,omitempty"`
	Files   []string `json:"files"`
}

func (h *Handler) apiYank(r *http.Request, rp *repository, project string) (any, error) {
	var req struct {
		Reason string `json:"reason"`
	}
	b, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	if len(bytes.TrimSpace(b)) > 0 {
		dec := json.NewDecoder(bytes.NewReader(b))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&req); err != nil {
			return nil, errorf(http.StatusBadRequest, "invalid JSON body: %v", err)
		}
	}
	return h.changeRelease(r, rp, project, r.PathValue("version"), "pypi.yank", func(f *fileRecord) {
		f.Yanked, f.YankedReason = true, req.Reason
	})
}

func (h *Handler) apiUnyank(r *http.Request, rp *repository, project string) (any, error) {
	return h.changeRelease(r, rp, project, r.PathValue("version"), "pypi.unyank", func(f *fileRecord) {
		f.Yanked, f.YankedReason = false, ""
	})
}

func (h *Handler) apiDeleteRelease(r *http.Request, rp *repository, project string) (any, error) {
	return h.changeRelease(r, rp, project, r.PathValue("version"), "pypi.delete", nil)
}

func (h *Handler) apiDeleteFile(r *http.Request, rp *repository, project string) (any, error) {
	filename := r.PathValue("filename")
	res, err := h.changeFiles(r.Context(), r, rp, project, "pypi.delete", rp.name+"/"+project+"/"+filename,
		func(v meta.View) ([]string, error) {
			if _, err := hostedFile(v, rp, project, filename); err != nil {
				return nil, err
			}
			return []string{filename}, nil
		}, nil)
	if err != nil {
		return nil, err
	}
	return res, nil
}

// changeRelease applies change to every live file of a release, or
// deletes them if change is nil.
func (h *Handler) changeRelease(r *http.Request, rp *repository, project, version, action string, change func(*fileRecord)) (any, error) {
	want := canonicalVersion(version)
	res, err := h.changeFiles(r.Context(), r, rp, project, action, rp.name+"/"+project+"/"+version,
		func(v meta.View) ([]string, error) {
			var names []string
			pfx := indexPrefix(rp.name, project)
			var failure error
			v.Scan(pfx, nil, func(k []byte, _ meta.Record) bool {
				name := string(k[len(pfx):])
				f, err := hostedFile(v, rp, project, name)
				if err != nil {
					failure = err
					return false
				}
				if canonicalVersion(f.Version) == want {
					names = append(names, name)
				}
				return true
			})
			if failure != nil {
				return nil, failure
			}
			if len(names) == 0 {
				return nil, errorf(http.StatusNotFound, "project %s has no release %s", project, version)
			}
			return names, nil
		}, change)
	if err != nil {
		return nil, err
	}
	res.Version = version
	return res, nil
}

// changeFiles applies change to the files that pick chooses from a view,
// or replaces them with tombstones if change is nil, in one batch that
// requires them unchanged, retrying when another change got there first.
// The project record is rewritten too, so the project's serial moves.
func (h *Handler) changeFiles(ctx context.Context, r *http.Request, rp *repository, project, action, target string,
	pick func(meta.View) ([]string, error), change func(*fileRecord)) (*filesResult, error) {
	for attempt := 0; ; attempt++ {
		v := h.view()
		names, err := pick(v)
		var b meta.Batch
		if err == nil {
			pk := projectKey(rp.name, project)
			prec, _ := v.Get(pk)
			b.Require(pk, prec.Version)
			b.Put(pk, prec.Value)
			for _, name := range names {
				fk := fileKey(rp.name, name)
				cur, _ := v.Get(fk)
				var f *fileRecord
				if f, err = decodeFile(cur.Value); err != nil {
					break
				}
				b.Require(fk, cur.Version)
				if change == nil {
					b.Put(fk, (&fileRecord{Kind: kindTombstone, Project: project, Version: f.Version, Deleted: h.now().UTC()}).encode())
					b.Delete(indexKey(rp.name, project, name))
				} else {
					change(f)
					b.Put(fk, f.encode())
				}
			}
			b.SetOrigin(h.origin(r, action, target))
		}
		v.Release()
		if err != nil {
			return nil, err
		}
		_, err = h.meta.Commit(ctx, &b)
		switch {
		case err == nil:
			h.log.InfoContext(ctx, "pypi files changed", "action", action, "repository", rp.name, "project", project,
				"files", strings.Join(names, " "))
			return &filesResult{Project: project, Files: names}, nil
		case errors.Is(err, meta.ErrConflict) && attempt < maxLinkAttempts-1:
		case errors.Is(err, meta.ErrConflict):
			return nil, errRetry
		default:
			return nil, err
		}
	}
}
