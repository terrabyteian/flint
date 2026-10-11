package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"

	"github.com/terrabyteian/flint/internal/auth"
	"github.com/terrabyteian/flint/internal/backup"
	"github.com/terrabyteian/flint/internal/blob"
	"github.com/terrabyteian/flint/internal/config"
	"github.com/terrabyteian/flint/internal/flock"
	"github.com/terrabyteian/flint/internal/fsys"
	"github.com/terrabyteian/flint/internal/meta"
	"github.com/terrabyteian/flint/internal/metrics"
	"github.com/terrabyteian/flint/internal/oci"
	"github.com/terrabyteian/flint/internal/server"
	"github.com/terrabyteian/flint/internal/upstream"
)

// defaultConfigPath is where serve looks for its configuration without -config.
const defaultConfigPath = "/etc/flint/config.json"

// serve runs the server until ctx is done, then shuts it down gracefully.
// It returns the process exit code.
func serve(ctx context.Context, args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("flint serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", defaultConfigPath, "path to the JSON configuration `file`")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "flint serve: unexpected arguments %q\n", fs.Args())
		fs.Usage()
		return 2
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(stderr, "flint: %v\n", err)
		return 1
	}
	logger := newLogger(stderr, cfg.Log.Level)
	slog.SetDefault(logger)
	if err := runServer(ctx, cfg, logger); err != nil {
		logger.Error("flint stopped", "err", err)
		return 1
	}
	return 0
}

func newLogger(w io.Writer, level string) *slog.Logger {
	var l slog.Level
	l.UnmarshalText([]byte(level)) // the config is validated
	return slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{Level: l}))
}

// runServer opens the data directory, serves until ctx is done, and shuts
// down: it stops accepting connections, waits for in-flight requests up
// to the configured timeout, and closes the stores.
func runServer(ctx context.Context, cfg *config.Config, logger *slog.Logger) (err error) {
	if err := os.MkdirAll(cfg.DataDir, 0o750); err != nil {
		return fmt.Errorf("creating the data directory: %w", err)
	}
	unlock, err := lockDataDir(cfg.DataDir)
	if err != nil {
		return err
	}
	defer unlock()
	if _, err := os.Stat(filepath.Join(cfg.DataDir, backup.RestoreMarker)); err == nil {
		return fmt.Errorf("the data directory %s holds a restore that did not finish (%s exists); "+
			"remove the directory and run flint restore again", cfg.DataDir, backup.RestoreMarker)
	}

	store, err := meta.Open(filepath.Join(cfg.DataDir, "meta"), meta.Options{Logger: logger})
	if err != nil {
		return err
	}
	defer func() {
		if cerr := store.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("closing the metadata store: %w", cerr)
		}
	}()
	blobs, err := blob.NewFS(cfg.DataDir, blob.Options{})
	if err != nil {
		return err
	}

	srv, registry, backups, err := newServer(ctx, cfg, logger, fsys.OS, store, blobs)
	if err != nil {
		return err
	}
	if backups != nil {
		// Cancel a running backup before the stores close.
		defer backups.Close()
	}
	// Expire abandoned uploads, and run the proxy repositories' upkeep,
	// in the background until the stores close.
	janitorCtx, stopJanitor := context.WithCancel(context.Background())
	var janitors sync.WaitGroup
	janitors.Go(func() { registry.RunJanitor(janitorCtx, oci.JanitorInterval, oci.UploadMaxAge) })
	janitors.Go(func() { registry.RunProxy(janitorCtx) })
	defer func() {
		stopJanitor()
		janitors.Wait()
	}()
	addr, err := srv.Listen()
	if err != nil {
		return err
	}
	logger.Info("flint listening", "addr", addr.String(), "tls", cfg.TLS != nil,
		"data_dir", cfg.DataDir, "version", version)
	served := make(chan error, 1)
	go func() { served <- srv.Serve() }()

	select {
	case err := <-served:
		return fmt.Errorf("serving: %w", err)
	case <-ctx.Done():
	}
	logger.Info("shutting down", "timeout", cfg.ShutdownTimeout.String())
	sctx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout.Duration)
	defer cancel()
	if err := srv.Shutdown(sctx); err != nil {
		logger.Warn("shutdown timed out; closed the remaining connections", "err", err)
	}
	if err := <-served; err != nil {
		return fmt.Errorf("serving: %w", err)
	}
	logger.Info("shutdown complete")
	return nil
}

// newServer builds the HTTP server and its metrics over open stores. The
// format and auth packages register their routes, middleware, and
// readiness checks on it here, using store and blobs. fsy is the data
// directory's filesystem. The backup manager is nil unless backups are
// configured; the caller closes it before the stores.
func newServer(ctx context.Context, cfg *config.Config, logger *slog.Logger, fsy fsys.FS, store meta.Store, blobs blob.Store) (*server.Server, *oci.Handler, *backup.Manager, error) {
	reg := metrics.NewRegistry()
	metrics.RegisterRuntime(reg, version)
	registerStoreMetrics(reg, store)

	opts := server.Options{
		Addr:           cfg.Listen,
		TrustedProxies: cfg.Proxies(),
		Logger:         logger,
		Metrics:        reg,
	}
	if cfg.TLS != nil {
		opts.TLS = &server.TLSFiles{CertFile: cfg.TLS.CertFile, KeyFile: cfg.TLS.KeyFile}
	}
	// The metadata store adds no readiness check: a store poisoned by a
	// failed write keeps serving reads, so the server stays ready, and
	// the fault shows in flint_meta_store_poisoned and the logs.
	srv, err := server.New(opts)
	if err != nil {
		return nil, nil, nil, err
	}

	authz, err := auth.New(auth.Options{
		Store:   store,
		KeyDir:  filepath.Join(cfg.DataDir, "auth"),
		FS:      fsy,
		Config:  cfg,
		Logger:  logger,
		Metrics: reg,
	})
	if err != nil {
		return nil, nil, nil, err
	}
	if b := cfg.Auth.BootstrapAdmin; b != nil {
		if _, err := authz.Bootstrap(ctx, b.Username, b.PasswordFile); err != nil {
			return nil, nil, nil, err
		}
	} else if ok, err := authz.HasAdmin(); err != nil {
		return nil, nil, nil, err
	} else if !ok {
		logger.Warn("no administrator exists; set auth.bootstrapAdmin in the configuration to create one")
	}
	authz.Register(srv)

	var space *upstream.Space
	for _, r := range cfg.Repositories {
		if r.Type == config.TypeProxy {
			space = upstream.NewSpace(upstream.SpaceOptions{
				Path:    cfg.DataDir,
				MinFree: cfg.ProxyCache.MinFreeSpace.Of,
				Logger:  logger,
			})
			break
		}
	}
	registry, err := oci.New(oci.Options{
		Meta:         store,
		Blobs:        blobs,
		Repositories: cfg.Repositories,
		Authorizer:   authz,
		// Helm clients send basic credentials and know no token service.
		HelmAuthorizer: authz.Authorizer(auth.Challenge{Style: auth.ChallengeBasic}),
		Actor:          authz.Actor,
		Logger:         logger,
		Metrics:        reg,
		Upstream:       upstream.Options{UserAgent: "flint/" + version},
		Space:          space,
	})
	if err != nil {
		return nil, nil, nil, err
	}
	registry.Register(srv)

	var backups *backup.Manager
	if cfg.Backup.Directory != "" {
		backups, err = backup.New(backup.Options{
			Meta:       store,
			Blobs:      blobs,
			Dir:        cfg.Backup.Directory,
			References: blobReferences,
			Version:    version,
			Logger:     logger,
			Metrics:    reg,
		})
		if err != nil {
			return nil, nil, nil, err
		}
	}
	backup.Register(srv, backups, authz.AdminHandler, authz.Actor)
	return srv, registry, backups, nil
}

// blobReferences report the blobs every format package's records
// reference, for backups to check that they hold them all.
var blobReferences = []backup.References{oci.References}

// registerStoreMetrics exposes the metadata store's counters and health.
func registerStoreMetrics(reg *metrics.Registry, store meta.Store) {
	stat := func(f func(meta.Stats) float64) func() float64 {
		return func() float64 { return f(store.Stats()) }
	}
	reg.GaugeFunc("flint_meta_store_poisoned",
		"1 if a failed log write or fsync made the metadata store reject writes until restarted, else 0.",
		stat(func(s meta.Stats) float64 {
			if s.Poisoned != nil {
				return 1
			}
			return 0
		}))
	for _, g := range []struct {
		name, help string
		f          func(meta.Stats) float64
	}{
		{"flint_meta_sequence", "Sequence number of the latest durable metadata batch.",
			func(s meta.Stats) float64 { return float64(s.Seq) }},
		{"flint_meta_keys", "Live keys in the metadata store.",
			func(s meta.Stats) float64 { return float64(s.Keys) }},
		{"flint_meta_log_segments", "Metadata log segments on disk.",
			func(s meta.Stats) float64 { return float64(s.Segments) }},
		{"flint_meta_log_bytes", "Bytes in metadata log segments on disk.",
			func(s meta.Stats) float64 { return float64(s.LogBytes) }},
		{"flint_meta_snapshot_sequence", "Sequence number of the latest metadata snapshot, 0 if none.",
			func(s meta.Stats) float64 { return float64(s.SnapshotSeq) }},
		{"flint_meta_pinned_views", "Metadata views pinned for garbage collection.",
			func(s meta.Stats) float64 { return float64(s.PinnedViews) }},
	} {
		reg.GaugeFunc(g.name, g.help, stat(g.f))
	}
	for _, c := range []struct {
		name, help string
		f          func(meta.Stats) float64
	}{
		{"flint_meta_commits_total", "Metadata batches committed since start.",
			func(s meta.Stats) float64 { return float64(s.Commits) }},
		{"flint_meta_conflicts_total", "Metadata batches rejected by a precondition since start.",
			func(s meta.Stats) float64 { return float64(s.Conflicts) }},
		{"flint_meta_group_commits_total", "Metadata log writes, each followed by one fsync, since start.",
			func(s meta.Stats) float64 { return float64(s.GroupCommits) }},
		{"flint_meta_snapshots_total", "Metadata snapshots written since start.",
			func(s meta.Stats) float64 { return float64(s.Snapshots) }},
		{"flint_meta_snapshot_errors_total", "Failed metadata snapshot attempts since start.",
			func(s meta.Stats) float64 { return float64(s.SnapshotErrors) }},
	} {
		reg.CounterFunc(c.name, c.help, stat(c.f))
	}
}

// lockDataDir takes the exclusive lock on <dir>/LOCK that marks the data
// directory as in use, so a second flint process on the same directory
// refuses to start.
func lockDataDir(dir string) (unlock func(), err error) {
	unlock, err = flock.Lock(filepath.Join(dir, "LOCK"))
	if errors.Is(err, flock.ErrLocked) {
		return nil, fmt.Errorf("the data directory is in use by another flint process: %w", err)
	}
	return unlock, err
}
