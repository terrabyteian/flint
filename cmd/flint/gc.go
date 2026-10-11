package main

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/terrabyteian/flint/internal/auth"
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
func gcCmd(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	cmd := ""
	if len(args) > 0 {
		cmd = args[0]
	}
	fs := flag.NewFlagSet("flint gc "+cmd, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprint(stderr, gcUsage)
		fs.PrintDefaults()
	}
	server := fs.String("url", cmp.Or(os.Getenv("FLINT_URL"), "http://127.0.0.1:5000"), "base `URL` of the flint server; the default is $FLINT_URL if set")
	user := fs.String("user", auth.TokenUser, "user `name` to authenticate as; the default takes an API token as the password")
	passwordFile := fs.String("password-file", "", "`file` holding the password or API token of an administrator (required)")
	caFile := fs.String("ca-file", "", "PEM `file` of certificate authorities to trust for an https URL, besides the system's")
	jsonOut := fs.Bool("json", false, "print JSON")
	var dryRun, detach bool
	if cmd == "run" {
		fs.BoolVar(&dryRun, "dry-run", false, "report what the run would delete, without deleting anything")
		fs.BoolVar(&detach, "detach", false, "start the run and return without waiting for it")
	}
	if cmd != "run" && cmd != "status" {
		fs.Usage()
		return 2
	}
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	if fs.NArg() > 0 || *passwordFile == "" {
		if fs.NArg() > 0 {
			fmt.Fprintf(stderr, "flint gc %s: unexpected arguments %q\n", cmd, fs.Args())
		} else {
			fmt.Fprintf(stderr, "flint gc %s: -password-file is required\n", cmd)
		}
		fs.Usage()
		return 2
	}
	c, err := newAdminClient(*server, gc.APIPath, *user, *passwordFile, *caFile)
	if err != nil {
		fmt.Fprintf(stderr, "flint gc: %v\n", err)
		return 1
	}

	if cmd == "status" {
		var st gc.Status
		if err := c.do(ctx, http.MethodGet, nil, http.StatusOK, &st); err != nil {
			fmt.Fprintf(stderr, "flint gc: %v\n", err)
			return 1
		}
		if *jsonOut {
			printJSON(stdout, st)
		} else {
			printStatus(stdout, &st)
		}
		return 0
	}

	var started gc.Report
	if err := c.do(ctx, http.MethodPost, gc.StartRequest{DryRun: dryRun}, http.StatusAccepted, &started); err != nil {
		fmt.Fprintf(stderr, "flint gc: %v\n", err)
		return 1
	}
	if detach {
		if *jsonOut {
			printJSON(stdout, started)
		} else {
			fmt.Fprintf(stdout, "garbage collection started at %s; see flint gc status\n", started.Started.Format(time.RFC3339))
		}
		return 0
	}
	rep, err := waitGC(ctx, c, started.Started)
	if err != nil {
		fmt.Fprintf(stderr, "flint gc: %v\n", err)
		return 1
	}
	if *jsonOut {
		printJSON(stdout, rep)
	} else {
		printReport(stdout, rep)
	}
	if rep.State != gc.StateSucceeded {
		return 1
	}
	return 0
}

// waitGC waits for the run that started at started to finish and returns
// its report.
func waitGC(ctx context.Context, c *adminClient, started time.Time) (*gc.Report, error) {
	for {
		var st gc.Status
		if err := c.do(ctx, http.MethodGet, nil, http.StatusOK, &st); err != nil {
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
		line("would prune", "%d expired records", r.Pruned)
	} else {
		line("pruned", "%d expired records", r.Pruned)
	}
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
