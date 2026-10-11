package oci

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// Error codes from the OCI distribution spec, plus UNKNOWN and UNAVAILABLE,
// which clients understand as server-side failures.
const (
	codeBlobUnknown         = "BLOB_UNKNOWN"
	codeBlobUploadInvalid   = "BLOB_UPLOAD_INVALID"
	codeBlobUploadUnknown   = "BLOB_UPLOAD_UNKNOWN"
	codeDigestInvalid       = "DIGEST_INVALID"
	codeManifestBlobUnknown = "MANIFEST_BLOB_UNKNOWN"
	codeManifestInvalid     = "MANIFEST_INVALID"
	codeManifestUnknown     = "MANIFEST_UNKNOWN"
	codeNameInvalid         = "NAME_INVALID"
	codeNameUnknown         = "NAME_UNKNOWN"
	codeSizeInvalid         = "SIZE_INVALID"
	codeDenied              = "DENIED"
	codeUnsupported         = "UNSUPPORTED"
	codeUnknown             = "UNKNOWN"
	codeUnavailable         = "UNAVAILABLE"
)

// apiError is one error in a spec-conformant error response.
type apiError struct {
	status  int
	Code    string `json:"code"`
	Message string `json:"message"`
	Detail  any    `json:"detail,omitempty"`
}

func (e *apiError) Error() string { return e.Code + ": " + e.Message }

func newError(status int, code, format string, args ...any) *apiError {
	return &apiError{status: status, Code: code, Message: fmt.Sprintf(format, args...)}
}

// withDetail sets the error's detail and returns the error.
func (e *apiError) withDetail(d any) *apiError {
	e.Detail = d
	return e
}

// writeError writes err as an error response body. An error that is not
// an *apiError is an internal failure: it is logged with the request and
// answered with a generic 500, so internals never reach the client.
func (h *Handler) writeError(w http.ResponseWriter, r *http.Request, err error) {
	ae, ok := err.(*apiError)
	if !ok {
		h.log.ErrorContext(r.Context(), "oci request failed", "method", r.Method, "path", r.URL.Path, "err", err)
		ae = newError(http.StatusInternalServerError, codeUnknown, "internal server error")
	}
	if ae.status == http.StatusServiceUnavailable {
		w.Header().Set("Retry-After", "1")
	}
	body, _ := json.Marshal(struct {
		Errors []*apiError `json:"errors"`
	}{[]*apiError{ae}})
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", fmt.Sprint(len(body)))
	w.WriteHeader(ae.status)
	if r.Method != http.MethodHead {
		w.Write(body)
	}
}
