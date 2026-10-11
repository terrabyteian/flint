package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/terrabyteian/flint/internal/gc"
)

const gcUsage = `usage: flint gc <command> [flags]

Runs garbage collection on a running flint server through its admin API,
which needs the global admin role.

commands:
  run      start a run and wait for its report (flint gc run [-dry-run] [-detach])
  status   show the run in progress, the last run, and the schedule

flags:
`

// gcPollInterval is how often flint gc run asks whether its run finished.
var gcPollInterval = time.Second

// gcCmd runs the gc subcommands and returns the process exit code.
func gcCmd(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 || (args[0] != "run" && args[0] != "status") {
		fmt.Fprint(stderr, gcUsage)
		newGCFlags(stderr).fs.PrintDefaults()
		return 2
	}
	cmd := args[0]
	f := newGCFlags(stderr)
	f.fs.Usage = func() {
		fmt.Fprint(stderr, gcUsage)
		f.fs.PrintDefaults()
	}
	var dryRun, detach bool
	if cmd == "run" {
		f.fs.BoolVar(&dryRun, "dry-run", false, "report what the run would delete, without deleting anything")
		f.fs.BoolVar(&detach, "detach", false, "start the run and return without waiting for it")
	}
	if err := f.fs.Parse(args[1:]); err != nil {
		return 2
	}
	if f.fs.NArg() > 0 {
		fmt.Fprintf(stderr, "flint gc %s: unexpected arguments %q\n", cmd, f.fs.Args())
		return 2
	}
	c, err := newGCClient(f, stdin)
	if err != nil {
		fmt.Fprintf(stderr, "flint gc: %v\n", err)
		return 1
	}

	if cmd == "status" {
		var st gc.Status
		if err := c.call(ctx, http.MethodGet, nil, &st); err != nil {
			fmt.Fprintf(stderr, "flint gc: %v\n", err)
			return 1
		}
		if f.json {
			printJSON(stdout, st)
		} else {
			printStatus(stdout, &st)
		}
		return 0
	}

	var started gc.Report
	if err := c.call(ctx, http.MethodPost, gc.StartRequest{DryRun: dryRun}, &started); err != nil {
		fmt.Fprintf(stderr, "flint gc: %v\n", err)
		return 1
	}
	if detach {
		if f.json {
			printJSON(stdout, started)
		} else {
			fmt.Fprintf(stdout, "garbage collection started at %s; see flint gc status\n", started.Started.Format(time.RFC3339))
		}
		return 0
	}
	rep, err := c.wait(ctx, started.Started)
	if err != nil {
		fmt.Fprintf(stderr, "flint gc: %v\n", err)
		return 1
	}
	if f.json {
		printJSON(stdout, rep)
	} else {
		printReport(stdout, rep)
	}
	if rep.State != gc.StateSucceeded {
		return 1
	}
	return 0
}

// gcFlags are the flags every gc command takes.
type gcFlags struct {
	fs                      *flag.FlagSet
	url, user, passwordFile string
	json                    bool
}

func newGCFlags(stderr io.Writer) *gcFlags {
	f := &gcFlags{fs: flag.NewFlagSet("flint gc", flag.ContinueOnError)}
	f.fs.SetOutput(stderr)
	f.fs.StringVar(&f.url, "url", "", "the server's base `URL`; default $FLINT_URL")
	f.fs.StringVar(&f.user, "user", "", "user `name`; default $FLINT_USER, else __token__, to authenticate with an API token")
	f.fs.StringVar(&f.passwordFile, "password-file", "", "`file` holding the password or API token, - for standard input; default $FLINT_PASSWORD")
	f.fs.BoolVar(&f.json, "json", false, "print JSON")
	return f
}

// gcClient calls the garbage-collection admin API.
type gcClient struct {
	url, user, password string
	client              *http.Client
}

func newGCClient(f *gcFlags, stdin io.Reader) (*gcClient, error) {
	c := &gcClient{client: &http.Client{Timeout: time.Minute}}
	base := firstSet(f.url, os.Getenv("FLINT_URL"))
	if base == "" {
		return nil, errors.New("no server: give -url or set FLINT_URL")
	}
	c.url = strings.TrimSuffix(base, "/") + "/api/v1/gc"

	c.user = firstSet(f.user, os.Getenv("FLINT_USER"), "__token__")
	c.password = os.Getenv("FLINT_PASSWORD")
	switch f.passwordFile {
	case "":
	case "-":
		b, err := io.ReadAll(io.LimitReader(stdin, 64<<10))
		if err != nil {
			return nil, fmt.Errorf("reading the password from standard input: %w", err)
		}
		c.password = trimNewline(string(b))
	default:
		b, err := os.ReadFile(f.passwordFile)
		if err != nil {
			return nil, fmt.Errorf("reading the password: %w", err)
		}
		c.password = trimNewline(string(b))
	}
	if c.password == "" {
		return nil, errors.New("no password or API token: give -password-file or set FLINT_PASSWORD")
	}
	return c, nil
}

// firstSet returns the first of ss that is not empty.
func firstSet(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}

// trimNewline removes one trailing newline, as flint does for password files.
func trimNewline(s string) string {
	s = strings.TrimSuffix(s, "\n")
	return strings.TrimSuffix(s, "\r")
}

// call makes an admin API request and decodes its JSON response into out.
func (c *gcClient) call(ctx context.Context, method string, body, out any) error {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.url, rd)
	if err != nil {
		return err
	}
	req.SetBasicAuth(c.user, c.password)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode >= 300 {
		var e struct{ Error string }
		if json.Unmarshal(b, &e) == nil && e.Error != "" {
			return fmt.Errorf("the server answered %d: %s", resp.StatusCode, e.Error)
		}
		return fmt.Errorf("the server answered %s", resp.Status)
	}
	if err := json.Unmarshal(b, out); err != nil {
		return fmt.Errorf("decoding the server's answer: %w", err)
	}
	return nil
}

// wait waits for the run that started at started to finish and returns
// its report.
func (c *gcClient) wait(ctx context.Context, started time.Time) (*gc.Report, error) {
	for {
		var st gc.Status
		if err := c.call(ctx, http.MethodGet, nil, &st); err != nil {
			return nil, err
		}
		if st.Running == nil || !st.Running.Started.Equal(started) {
			if st.Last == nil || !st.Last.Started.Equal(started) {
				return nil, errors.New("the run finished, but a later run replaced its report; see the server's log")
			}
			return st.Last, nil
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("%w; the run continues on the server", ctx.Err())
		case <-time.After(gcPollInterval):
		}
	}
}

func printJSON(w io.Writer, v any) {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(v)
}

func printStatus(w io.Writer, st *gc.Status) {
	fmt.Fprintf(w, "grace period: %s\n", st.GracePeriod)
	if st.Interval != "" {
		fmt.Fprintf(w, "schedule:     every %s, next at %s\n", st.Interval, st.NextRun.Format(time.RFC3339))
	} else {
		fmt.Fprintf(w, "schedule:     none; runs start with flint gc run\n")
	}
	if st.Running != nil {
		fmt.Fprintf(w, "\nrunning:\n")
		printReport(w, st.Running)
	}
	if st.Last != nil {
		fmt.Fprintf(w, "\nlast run:\n")
		printReport(w, st.Last)
	} else if st.Running == nil {
		fmt.Fprintf(w, "\nno run yet\n")
	}
}

func printReport(w io.Writer, r *gc.Report) {
	state := r.State
	if r.Phase != "" {
		state += ", " + r.Phase
	}
	if r.DryRun {
		state += " (dry run)"
	}
	line := func(label, format string, args ...any) {
		fmt.Fprintf(w, "  %-16s %s\n", label+":", fmt.Sprintf(format, args...))
	}
	count := func(c gc.Count) string { return fmt.Sprintf("%d blobs, %s", c.Blobs, formatBytes(c.Bytes)) }
	line("state", "%s", state)
	line("started", "%s by %s (%s)", r.Started.Format(time.RFC3339), r.Actor, r.Trigger)
	if !r.Finished.IsZero() {
		line("finished", "%s, after %s", r.Finished.Format(time.RFC3339), r.Finished.Sub(r.Started).Round(time.Millisecond))
	}
	line("grace period", "%s", r.GracePeriod)
	line("referenced", "%d blobs", r.Referenced)
	line("stored", "%s", count(r.Stored))
	line("unreferenced", "%s", count(r.Unreferenced))
	line("in grace period", "%s", count(r.InGracePeriod))
	line("kept", "%s", count(r.Kept))
	if r.DryRun {
		line("would delete", "%s", count(r.Deleted))
	} else {
		line("deleted", "%s", count(r.Deleted))
	}
	if r.PinnedViews > 0 {
		line("pinned views", "%d", r.PinnedViews)
	}
	for _, s := range r.Refused {
		line("refused", "%s", s)
	}
	if r.Error != "" {
		line("error", "%s", r.Error)
	}
	for _, s := range r.Errors {
		line("delete error", "%s", s)
	}
	for _, b := range r.Blobs {
		fmt.Fprintf(w, "    %s  %10s  committed %s\n", b.Digest, formatBytes(b.Size), b.Committed.Format(time.RFC3339))
	}
	if r.BlobsTruncated {
		fmt.Fprintf(w, "    ... and %d more\n", r.Deleted.Blobs-int64(len(r.Blobs)))
	}
}
