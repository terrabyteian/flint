package cargo

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/terrabyteian/flint/internal/config"
	"github.com/terrabyteian/flint/internal/meta"
	"github.com/terrabyteian/flint/internal/server"
)

// The admin API's Cargo endpoint deletes versions of hosted repositories,
// which Cargo's web API cannot do. Like the rest of the admin API, it
// authenticates with HTTP basic credentials, or an API token, and answers
// JSON, with errors as {"error": "..."}. It needs the delete role on the
// repository.
//
//	DELETE /api/v1/cargo/{repo}/crates/{crate}/{version}   delete a version
//
// A deleted version disappears from the index file and can no longer be
// downloaded. It leaves a tombstone, so the version can never be
// published again: a version that came back with other content would
// break every build whose Cargo.lock pins its checksum. Garbage
// collection reclaims the .crate file.

func (h *Handler) registerAdmin(s interface{ Handle(string, http.Handler) }) {
	s.Handle("DELETE /api/v1/cargo/{repo}/crates/{crate}/{version}", http.HandlerFunc(h.apiDelete))
}

// deleteResult is the response of a delete.
type deleteResult struct {
	Crate   string `json:"crate"`
	Version string `json:"version"`
}

func (h *Handler) apiDelete(w http.ResponseWriter, r *http.Request) {
	server.SetRoute(r.Context(), "api.cargo.delete")
	w.Header().Set("Cache-Control", "no-store")
	rp := h.repos[r.PathValue("repo")]
	if rp == nil {
		WriteAdminError(w, r, http.StatusNotFound, "no Cargo repository is named "+quote(r.PathValue("repo")))
		return
	}
	if !h.admin.Authorize(w, r, rp.name, ActionDelete) {
		return
	}
	if rp.typ != config.TypeHosted {
		WriteAdminError(w, r, http.StatusMethodNotAllowed, fmt.Sprintf("repository %s is a %s repository; versions can be deleted only in hosted repositories",
			rp.name, rp.typ))
		return
	}
	crate, vers := r.PathValue("crate"), r.PathValue("version")
	if !validIndexName(crate) {
		WriteAdminError(w, r, http.StatusNotFound, "crate "+quote(crate)+" is not found")
		return
	}
	if err := h.changeVersion(r.Context(), r, rp, crate, vers, "cargo.delete", nil); err != nil {
		var he *httpError
		switch {
		case errors.As(err, &he):
			WriteAdminError(w, r, he.status, he.msg)
		case r.Context().Err() != nil:
		case errors.Is(err, meta.ErrPoisoned), errors.Is(err, meta.ErrClosed):
			WriteAdminError(w, r, http.StatusServiceUnavailable, "the registry cannot accept writes now")
		default:
			h.log.ErrorContext(r.Context(), "cargo admin request failed", "path", r.URL.Path, "err", err)
			WriteAdminError(w, r, http.StatusInternalServerError, "internal error")
		}
		return
	}
	writeJSON(w, http.StatusOK, deleteResult{Crate: crate, Version: vers})
}

// WriteAdminError writes an admin API error, {"error": msg}: the
// WriteError of the admin API's authorizer.
func WriteAdminError(w http.ResponseWriter, _ *http.Request, status int, msg string) {
	writeJSON(w, status, struct {
		Error string `json:"error"`
	}{msg})
}
