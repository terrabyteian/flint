package backup

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/terrabyteian/flint/internal/server"
)

// APIPath is the admin API endpoint for backups: GET reports the Status,
// and POST starts a backup and reports its Run.
const APIPath = "/api/v1/backup"

// Register adds the backup endpoints to srv. admin wraps each in the
// admin API's authentication, requiring the global admin role, and actor
// names the authenticated client. A nil m means backups are not
// configured, which the endpoints answer with 404.
func Register(srv *server.Server, m *Manager, admin func(http.Handler) http.Handler, actor func(*http.Request) string) {
	srv.Handle("GET "+APIPath, admin(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if m == nil {
			notConfigured(w)
			return
		}
		writeJSON(w, http.StatusOK, m.Status())
	})))
	srv.Handle("POST "+APIPath, admin(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if m == nil {
			notConfigured(w)
			return
		}
		run, err := m.Start(actor(r))
		switch {
		case errors.Is(err, ErrRunning):
			writeJSON(w, http.StatusConflict, apiError{Error: err.Error(), Status: ptr(m.Status())})
		case errors.Is(err, ErrClosed):
			writeJSON(w, http.StatusServiceUnavailable, apiError{Error: err.Error()})
		case err != nil:
			writeJSON(w, http.StatusInternalServerError, apiError{Error: err.Error()})
		default:
			writeJSON(w, http.StatusAccepted, run)
		}
	})))
}

type apiError struct {
	Error  string  `json:"error"`
	Status *Status `json:"status,omitempty"`
}

func ptr[T any](v T) *T { return &v }

func notConfigured(w http.ResponseWriter) {
	writeJSON(w, http.StatusNotFound, apiError{Error: "backups are not configured: set backup.directory in the configuration"})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(v)
}
