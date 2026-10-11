package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/terrabyteian/flint/internal/auth"
	"github.com/terrabyteian/flint/internal/backup"
)

const backupUsage = `usage:
  flint backup [flags]                      back up a running server and wait for it to finish
  flint backup list <backup-dir>            list the backups in a backup directory
  flint backup verify [-backup <id>] <backup-dir>
                                            check a backup without restoring it
  flint restore [-backup <id>] <backup-dir> <data-dir>
                                            restore a backup into a new data directory

flint backup asks the server, through the admin API, to back up to the
backup.directory of its configuration. Run "flint backup -h" for its flags.
`

// backupPollInterval is how often flint backup asks for the status.
var backupPollInterval = 2 * time.Second

// backupCmd runs flint backup and its subcommands and returns the process
// exit code.
func backupCmd(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 {
		switch args[0] {
		case "list":
			return backupListCmd(args[1:], stdout, stderr)
		case "verify":
			return backupVerifyCmd(ctx, args[1:], stdout, stderr)
		case "help":
			fmt.Fprint(stdout, backupUsage)
			return 0
		}
	}
	fs := flag.NewFlagSet("flint backup", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprint(stderr, backupUsage+"\nflags of flint backup:\n")
		fs.PrintDefaults()
	}
	server := fs.String("url", "http://127.0.0.1:5000", "base `URL` of the flint server")
	user := fs.String("user", auth.TokenUser, "user `name` to authenticate as; the default takes an API token as the password")
	passwordFile := fs.String("password-file", "", "`file` holding the password or API token of an administrator (required)")
	caFile := fs.String("ca-file", "", "PEM `file` of certificate authorities to trust for an https URL, besides the system's")
	noWait := fs.Bool("no-wait", false, "return once the backup has started, without waiting for it to finish")
	timeout := fs.Duration("timeout", 0, "give up waiting after this `duration`; 0 waits as long as the backup runs")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() > 0 || *passwordFile == "" {
		if fs.NArg() > 0 {
			fmt.Fprintf(stderr, "flint backup: unexpected arguments %q\n", fs.Args())
		} else {
			fmt.Fprintln(stderr, "flint backup: -password-file is required")
		}
		fs.Usage()
		return 2
	}
	c, err := newAdminClient(*server, *user, *passwordFile, *caFile)
	if err != nil {
		fmt.Fprintf(stderr, "flint backup: %v\n", err)
		return 1
	}
	if *timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, *timeout)
		defer cancel()
	}
	run, err := c.start(ctx)
	if err != nil {
		fmt.Fprintf(stderr, "flint backup: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "backup %s started at sequence %d\n", run.ID, run.Sequence)
	if *noWait {
		return 0
	}
	run, err = c.wait(ctx, run.ID)
	if err != nil {
		fmt.Fprintf(stderr, "flint backup: %v\n", err)
		return 1
	}
	if run.State != backup.StateSucceeded {
		fmt.Fprintf(stderr, "flint backup: backup %s failed: %s\n", run.ID, run.Error)
		return 1
	}
	fmt.Fprintf(stdout, "backup %s succeeded in %s: %d records, %d blobs (%s), %d copied (%s)\n",
		run.ID, time.Duration(run.DurationSeconds*float64(time.Second)).Round(time.Millisecond),
		run.Records, run.Blobs, formatBytes(run.Bytes), run.CopiedBlobs, formatBytes(run.CopiedBytes))
	return 0
}

// adminClient calls the backup endpoint of the admin API.
type adminClient struct {
	url        string
	user, pass string
	http       *http.Client
}

func newAdminClient(base, user, passwordFile, caFile string) (*adminClient, error) {
	pw, err := os.ReadFile(passwordFile)
	if err != nil {
		return nil, err
	}
	c := &adminClient{
		url:  strings.TrimSuffix(base, "/") + backup.APIPath,
		user: user,
		pass: strings.TrimSuffix(strings.TrimSuffix(string(pw), "\n"), "\r"),
		http: &http.Client{Timeout: time.Minute},
	}
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, err
		}
		pool, err := x509.SystemCertPool()
		if err != nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("%s holds no PEM certificates", caFile)
		}
		tr := http.DefaultTransport.(*http.Transport).Clone()
		tr.TLSClientConfig = &tls.Config{RootCAs: pool}
		c.http.Transport = tr
	}
	return c, nil
}

// do sends a request and decodes the JSON response into out. A response
// other than want is an error carrying the server's message.
func (c *adminClient) do(ctx context.Context, method string, want int, out any) error {
	req, err := http.NewRequestWithContext(ctx, method, c.url, nil)
	if err != nil {
		return err
	}
	req.SetBasicAuth(c.user, c.pass)
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode != want {
		var e struct{ Error string }
		if json.Unmarshal(b, &e) == nil && e.Error != "" {
			return fmt.Errorf("%s %s: %s (%s)", method, c.url, e.Error, resp.Status)
		}
		return fmt.Errorf("%s %s: %s: %s", method, c.url, resp.Status, bytes.TrimSpace(b))
	}
	if err := json.Unmarshal(b, out); err != nil {
		return fmt.Errorf("%s %s: decoding the response: %w", method, c.url, err)
	}
	return nil
}

func (c *adminClient) start(ctx context.Context) (backup.Run, error) {
	var run backup.Run
	err := c.do(ctx, "POST", http.StatusAccepted, &run)
	return run, err
}

// maxPollErrors is how many status requests in a row may fail, for
// example while the server restarts, before wait gives up.
const maxPollErrors = 5

// wait polls the status until backup id finishes and returns it.
func (c *adminClient) wait(ctx context.Context, id string) (backup.Run, error) {
	failures := 0
	for {
		select {
		case <-ctx.Done():
			return backup.Run{}, fmt.Errorf("waiting for backup %s: %w", id, ctx.Err())
		case <-time.After(backupPollInterval):
		}
		var st backup.Status
		if err := c.do(ctx, "GET", http.StatusOK, &st); err != nil {
			if ctx.Err() != nil {
				continue
			}
			if failures++; failures >= maxPollErrors {
				return backup.Run{}, fmt.Errorf("waiting for backup %s: %w", id, err)
			}
			continue
		}
		failures = 0
		switch {
		case st.Running != nil && st.Running.ID == id:
			continue
		case st.Last != nil && st.Last.ID == id:
			return *st.Last, nil
		case st.LastSuccess != nil && st.LastSuccess.ID == id:
			return *st.LastSuccess, nil // and another backup finished since
		}
		return backup.Run{}, fmt.Errorf("the server no longer reports backup %s; it may have restarted, which interrupts a backup", id)
	}
}

func backupListCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) != 1 || strings.HasPrefix(args[0], "-") {
		fmt.Fprint(stderr, backupUsage)
		return 2
	}
	ents, err := backup.List(nil, args[0])
	if err != nil {
		fmt.Fprintf(stderr, "flint backup list: %v\n", err)
		return 1
	}
	tw := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tSTATE\tFINISHED\tSEQUENCE\tRECORDS\tBLOBS\tSIZE")
	for _, e := range ents {
		switch r := e.Record; {
		case e.Err != nil:
			fmt.Fprintf(tw, "%s\tunreadable: %v\t\t\t\t\t\n", e.ID, e.Err)
		case r == nil:
			fmt.Fprintf(tw, "%s\tincomplete\t\t\t\t\t\n", e.ID)
		default:
			fmt.Fprintf(tw, "%s\tcomplete\t%s\t%d\t%d\t%d\t%s\n", e.ID, r.Finished.UTC().Format(time.RFC3339),
				r.Sequence, r.Records, r.Blobs, formatBytes(r.Bytes))
		}
	}
	tw.Flush()
	return 0
}

func backupVerifyCmd(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("flint backup verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	id := fs.String("backup", "", "`ID` of the backup to check; the default is the latest complete one")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprint(stderr, backupUsage)
		return 2
	}
	rep, err := backup.Verify(ctx, fs.Arg(0), backup.VerifyOptions{
		ID: *id, References: blobReferences, Progress: progressPrinter(stderr, "checked"),
	})
	if err != nil {
		fmt.Fprintf(stderr, "flint backup verify: %v\n", err)
		return 1
	}
	if rep.NProblems > 0 {
		fmt.Fprintf(stderr, "backup %s has %d problems:\n", rep.Record.ID, rep.NProblems)
		for _, p := range rep.Problems {
			fmt.Fprintf(stderr, "  %s\n", p)
		}
		if rep.NProblems > len(rep.Problems) {
			fmt.Fprintf(stderr, "  ... and %d more\n", rep.NProblems-len(rep.Problems))
		}
		return 1
	}
	r := rep.Record
	fmt.Fprintf(stdout, "backup %s is ok: sequence %d, %d records, %d blobs (%s)\n",
		r.ID, r.Sequence, r.Records, r.Blobs, formatBytes(r.Bytes))
	return 0
}

// restoreCmd runs flint restore and returns the process exit code.
func restoreCmd(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("flint restore", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprint(stderr, `usage: flint restore [-backup <id>] <backup-dir> <data-dir>

Restores a backup into a new, empty data directory, checking every blob's
digest as it copies it. Start flint on the data directory afterwards.

`)
		fs.PrintDefaults()
	}
	id := fs.String("backup", "", "`ID` of the backup to restore; the default is the latest complete one")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 2 {
		fs.Usage()
		return 2
	}
	dir, dataDir := fs.Arg(0), fs.Arg(1)
	if err := os.MkdirAll(dataDir, 0o750); err != nil {
		fmt.Fprintf(stderr, "flint restore: creating the data directory: %v\n", err)
		return 1
	}
	unlock, err := lockDataDir(dataDir)
	if err != nil {
		fmt.Fprintf(stderr, "flint restore: %v\n", err)
		return 1
	}
	defer unlock()
	rep, err := backup.Restore(ctx, dir, dataDir, backup.VerifyOptions{
		ID: *id, References: blobReferences, Progress: progressPrinter(stderr, "restored"),
	})
	if err != nil {
		fmt.Fprintf(stderr, "flint restore: %v\n", err)
		return 1
	}
	r := rep.Record
	fmt.Fprintf(stdout, "restored backup %s into %s: sequence %d, %d records, %d blobs (%s)\n",
		r.ID, dataDir, r.Sequence, r.Records, r.Blobs, formatBytes(r.Bytes))
	return 0
}

// progressPrinter returns a progress callback that reports at most every
// ten seconds.
func progressPrinter(w io.Writer, verb string) func(blobs, bytes int64) {
	last := time.Now()
	return func(blobs, bytes int64) {
		if time.Since(last) >= 10*time.Second {
			last = time.Now()
			fmt.Fprintf(w, "%s %d blobs (%s)\n", verb, blobs, formatBytes(bytes))
		}
	}
}

// formatBytes formats n with a binary unit.
func formatBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}
