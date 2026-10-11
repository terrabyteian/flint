package gc

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
)

// The admin API endpoints, which the auth package serves to the global
// admin role (auth.Service.HandleAdmin):
//
//	GET  /api/v1/gc   the Status
//	POST /api/v1/gc   start a run: 202 with its report so far, or 409 if
//	                  one is running; the optional body {"dryRun": true}
//	                  asks for a dry run
const (
	APIPath       = "/api/v1/gc"
	StatusPattern = "GET " + APIPath
	StartPattern  = "POST " + APIPath
)

// apiError is the admin API's error body.
type apiError struct {
	Error string `json:"error"`
}

// HandleStatus serves GET /api/v1/gc.
func (c *Collector) HandleStatus(*http.Request, string) (int, any) {
	return http.StatusOK, c.Status()
}

// StartRequest is the body of POST /api/v1/gc.
type StartRequest struct {
	DryRun bool `json:"dryRun"`
}

// HandleStart serves POST /api/v1/gc, starting a run on behalf of actor.
func (c *Collector) HandleStart(r *http.Request, actor string) (int, any) {
	var req StartRequest
	body, err := io.ReadAll(r.Body)
	var mbe *http.MaxBytesError
	switch {
	case errors.As(err, &mbe):
		return http.StatusRequestEntityTooLarge, apiError{"the request body is too large"}
	case err != nil:
		return http.StatusBadRequest, apiError{"reading the request body: " + err.Error()}
	}
	if len(bytes.TrimSpace(body)) > 0 {
		dec := json.NewDecoder(bytes.NewReader(body))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&req); err != nil {
			return http.StatusBadRequest, apiError{"the request body is not a valid start request: " + err.Error()}
		}
		if dec.More() {
			return http.StatusBadRequest, apiError{"unexpected data after the request object"}
		}
	}
	rep, err := c.Start(RunOptions{DryRun: req.DryRun, Trigger: TriggerAPI, Actor: actor})
	switch {
	case errors.Is(err, ErrRunning):
		return http.StatusConflict, apiError{"a garbage collection run is already in progress"}
	case errors.Is(err, ErrClosed):
		return http.StatusServiceUnavailable, apiError{"the server is shutting down"}
	case err != nil:
		return http.StatusInternalServerError, apiError{"internal error"}
	}
	return http.StatusAccepted, rep
}
