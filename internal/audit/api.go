package audit

import (
	"bufio"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/terrabyteian/flint/internal/meta"
	"github.com/terrabyteian/flint/internal/server"
)

// Paths of the audit endpoints of the admin API.
const (
	QueryPath  = "/api/v1/audit"
	ExportPath = "/api/v1/audit/export"
)

// Query page sizes.
const (
	DefaultLimit = 100
	MaxLimit     = 1000
)

// syncTimeout bounds how long a request waits for the stream to catch up
// before it reads.
const syncTimeout = 5 * time.Second

// Register adds the audit endpoints to srv, each wrapped by guard, which
// must admit only administrators.
func (l *Log) Register(srv *server.Server, guard func(http.Handler) http.Handler) {
	srv.Handle("GET "+QueryPath, guard(http.HandlerFunc(l.handleQuery)))
	srv.Handle("GET "+ExportPath, guard(http.HandlerFunc(l.handleExport)))
}

// RecordJSON is a record as the API shows it.
type RecordJSON struct {
	Seq    uint64    `json:"seq"`
	Time   time.Time `json:"time"`
	Actor  string    `json:"actor"`
	Action string    `json:"action"`
	Target string    `json:"target"`
	Keys   []KeyJSON `json:"keys"`
}

// KeyJSON is a touched key as the API shows it: its components, split at
// the 0x00 separators metadata keys use, or for a key that is not UTF-8,
// its bytes in hex.
type KeyJSON struct {
	Op     string   `json:"op"` // "put" or "delete"
	Key    []string `json:"key,omitempty"`
	KeyHex string   `json:"keyHex,omitempty"`
}

// ToJSON returns r as the API shows it.
func ToJSON(r *Record) RecordJSON {
	out := RecordJSON{
		Seq: uint64(r.Seq), Time: r.Time.UTC(), Actor: r.Actor, Action: r.Action,
		Target: r.Target, Keys: make([]KeyJSON, len(r.Keys)),
	}
	for i, k := range r.Keys {
		kj := KeyJSON{Op: "put"}
		if k.Delete {
			kj.Op = "delete"
		}
		if utf8.Valid(k.Key) {
			kj.Key = strings.Split(string(k.Key), "\x00")
		} else {
			kj.KeyHex = hex.EncodeToString(k.Key)
		}
		out.Keys[i] = kj
	}
	return out
}

// pageJSON is a page of query results. Next, if set, is the after
// parameter that fetches the next page.
type pageJSON struct {
	Records []RecordJSON `json:"records"`
	Next    uint64       `json:"next,omitempty"`
}

type apiError struct {
	Error string `json:"error"`
}

// parseFilter reads a Filter from the query parameters after, since,
// until, actor, action, and target.
func parseFilter(r *http.Request) (Filter, error) {
	q := r.URL.Query()
	var f Filter
	if s := q.Get("after"); s != "" {
		n, err := strconv.ParseUint(s, 10, 64)
		if err != nil {
			return f, fmt.Errorf("after %q is not a sequence number", s)
		}
		f.After = meta.Seq(n)
	}
	for _, p := range []struct {
		name string
		t    *time.Time
	}{{"since", &f.Since}, {"until", &f.Until}} {
		if s := q.Get(p.name); s != "" {
			t, err := time.Parse(time.RFC3339Nano, s)
			if err != nil {
				return f, fmt.Errorf("%s %q is not an RFC 3339 time such as \"2026-01-02T15:04:05Z\"", p.name, s)
			}
			*p.t = t
		}
	}
	f.Actor, f.Action, f.Target = q.Get("actor"), q.Get("action"), q.Get("target")
	return f, nil
}

// syncForRead catches the stream up so a read sees the latest changes.
// A failure is logged by Sync's fault reporting; the read goes ahead
// with what is durable.
func (l *Log) syncForRead(r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), syncTimeout)
	defer cancel()
	l.Sync(ctx)
}

// handleQuery serves GET /api/v1/audit: a page of records, oldest first.
func (l *Log) handleQuery(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	f, err := parseFilter(r)
	limit := DefaultLimit
	if s := r.URL.Query().Get("limit"); s != "" && err == nil {
		n, perr := strconv.Atoi(s)
		if perr != nil || n < 1 || n > MaxLimit {
			err = fmt.Errorf("limit %q is not a number from 1 to %d", s, MaxLimit)
		}
		limit = n
	}
	if err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{err.Error()})
		return
	}
	l.syncForRead(r)
	page := pageJSON{Records: []RecordJSON{}}
	err = l.Scan(r.Context(), f, func(rec *Record) bool {
		if len(page.Records) == limit {
			page.Next = page.Records[limit-1].Seq
			return false
		}
		page.Records = append(page.Records, ToJSON(rec))
		return true
	})
	if err != nil {
		l.log.Error("audit: query failed", "err", err)
		writeJSON(w, http.StatusInternalServerError, apiError{"internal error"})
		return
	}
	writeJSON(w, http.StatusOK, page)
}

// handleExport serves GET /api/v1/audit/export: every selected record as
// JSON lines, oldest first. If reading fails partway, the response is
// aborted, so a client never mistakes a partial export for a whole one.
func (l *Log) handleExport(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	f, err := parseFilter(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, apiError{err.Error()})
		return
	}
	l.syncForRead(r)
	w.Header().Set("Content-Type", "application/x-ndjson")
	cw := &countingWriter{w: w}
	bw := bufio.NewWriterSize(cw, 64<<10)
	enc := json.NewEncoder(bw)
	var werr error
	err = l.Scan(r.Context(), f, func(rec *Record) bool {
		werr = enc.Encode(ToJSON(rec))
		return werr == nil
	})
	if err == nil && werr == nil {
		werr = bw.Flush()
	}
	switch {
	case err != nil && !errors.Is(err, context.Canceled):
		l.log.Error("audit: export failed", "err", err)
		if cw.n == 0 {
			writeJSON(w, http.StatusInternalServerError, apiError{"internal error"})
			return
		}
		panic(http.ErrAbortHandler)
	case err != nil || werr != nil:
		panic(http.ErrAbortHandler) // the client went away
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(v)
}

// countingWriter counts the bytes written through it.
type countingWriter struct {
	w http.ResponseWriter
	n int64
}

func (c *countingWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}
