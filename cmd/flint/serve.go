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
	"time"

	"github.com/terrabyteian/flint/internal/audit"
	"github.com/terrabyteian/flint/internal/auth"
	"github.com/terrabyteian/flint/internal/backup"
	"github.com/terrabyteian/flint/internal/blob"
	"github.com/terrabyteian/flint/internal/config"
	"github.com/terrabyteian/flint/internal/flock"
	"github.com/terrabyteian/flint/internal/fsys"
	"github.com/terrabyteian/flint/internal/gc"
	"github.com/terrabyteian/flint/internal/meta"
	"github.com/terrabyteian/flint/internal/metrics"
	"github.com/terrabyteian/flint/internal/oci"
	"github.com/terrabyteian/flint/internal/pypi"
	"github.com/terrabyteian/flint/internal/server"
	"github.com/terrabyteian/flint/internal/upstream"
)

// defaultConfigPath is where serve looks for its configuration without -config.
const defaultConfigPath = "/etc/flint/config.json"

// now is the clock of the blob store, the registry, and the garbage
// collector. Only a binary built for end-to-end tests changes it.
var now = time.Now

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
	blobs, err := blob.NewFS(cfg.DataDir, blob.Options{Now: now})
	if err != nil {
		return err
	}

	a, err := newServer(ctx, cfg, logger, fsys.OS, store, blobs)
	if err != nil {
		return err
	}
	srv := a.srv
	defer func() {
		// The audit log writes the last batches' records before the
		// metadata store closes.
		if cerr := a.audit.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("closing the audit log: %w", cerr)
		}
	}()
	if a.backups != nil {
		// Cancel a running backup before the stores close.
		defer a.backups.Close()
	}
	// Expire abandoned uploads, run the proxy repositories' upkeep, keep
	// the audit log current, and run scheduled garbage collection, in
	// the background until the stores close. A garbage collection run in
	// progress is cancelled first.
	janitorCtx, stopJanitor := context.WithCancel(context.Background())
	var janitors sync.WaitGroup
	janitors.Go(func() { a.oci.RunJanitor(janitorCtx, oci.JanitorInterval, oci.UploadMaxAge) })
	janitors.Go(func() { a.oci.RunProxy(janitorCtx) })
	janitors.Go(func() { a.pypi.RunProxy(janitorCtx) })
	janitors.Go(func() { a.docs.Run(janitorCtx, a.revalidate) })
	if a.space != nil {
		janitors.Go(func() { a.space.Run(janitorCtx, upstream.SpaceCheckInterval) })
	}
	janitors.Go(func() { a.audit.Run(janitorCtx) })
	janitors.Go(func() { a.gc.RunSchedule(janitorCtx) })
	defer func() {
		stopJanitor()
		janitors.Wait()
		a.gc.Close()
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

// app is a server and the parts of it that run in the background: the
// package format handlers, the free-space watcher and document cache
// their proxy repositories share, the audit log, and the backup manager.
type app struct {
	srv     *server.Server
	oci     *oci.Handler
	pypi    *pypi.Handler
	space   *upstream.Space // nil without proxy repositories
	audit   *audit.Log
	backups *backup.Manager // nil unless backups are configured
	gc      *gc.Collector
	// docs caches the documents proxy repositories of every format
	// fetch, and revalidate is the longest revalidation window of any.
	docs       *upstream.DocCache
	revalidate time.Duration
}

// newServer builds the HTTP server and its metrics over open stores. The
// format and auth packages register their routes, middleware, and
// readiness checks on it here, using store and blobs, and the garbage
// collector is set up with the marker of every package that writes
// metadata. fsy is the data directory's filesystem. It opens the audit
// log, which the caller must close before the metadata store. The backup
// manager is nil unless backups are configured; the caller closes it, and
// the collector, before the stores.
func newServer(ctx context.Context, cfg *config.Config, logger *slog.Logger, fsy fsys.FS, store meta.Store, blobs blob.Store) (_ *app, err error) {
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
		return nil, err
	}

	auditLog, err := audit.Open(audit.Options{
		Store:   store,
		Dir:     filepath.Join(cfg.DataDir, "audit"),
		FS:      fsy,
		MaxAge:  cfg.Audit.Retention.MaxAge.Duration,
		MaxSize: cfg.Audit.Retention.MaxSize.Bytes,
		Logger:  logger,
		Metrics: reg,
	})
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			auditLog.Close()
		}
	}()

	authz, err := auth.New(auth.Options{
		Store:   store,
		KeyDir:  filepath.Join(cfg.DataDir, "auth"),
		FS:      fsy,
		Config:  cfg,
		Logger:  logger,
		Metrics: reg,
	})
	if err != nil {
		return nil, err
	}
	if b := cfg.Auth.BootstrapAdmin; b != nil {
		if _, err := authz.Bootstrap(ctx, b.Username, b.PasswordFile); err != nil {
			return nil, err
		}
	} else if ok, err := authz.HasAdmin(); err != nil {
		return nil, err
	} else if !ok {
		logger.Warn("no administrator exists; set auth.bootstrapAdmin in the configuration to create one")
	}
	authz.Register(srv)
	auditLog.Register(srv, authz.AdminHandler)

	var space *upstream.Space
	var revalidate time.Duration
	for _, r := range cfg.Repositories {
		if r.Type != config.TypeProxy {
			continue
		}
		revalidate = max(revalidate, r.Proxy.RevalidateAfter.Duration)
		if space == nil {
			space = upstream.NewSpace(upstream.SpaceOptions{
				Path:    cfg.DataDir,
				MinFree: cfg.ProxyCache.MinFreeSpace.Of,
				Logger:  logger,
			})
		}
	}
	// Proxy repositories of every format share one fetcher, one document
	// cache, and one set of proxy metrics.
	fetcher := upstream.NewFetcher(blobs, 0)
	proxyMetrics := upstream.NewMetrics(reg, fetcher, space)
	docs := upstream.NewDocCache(upstream.DocCacheOptions{Meta: store, Blobs: blobs, Space: space,
		Metrics: proxyMetrics, Logger: logger})
	upOpts := upstream.Options{UserAgent: "flint/" + version}
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
		Upstream:       upOpts,
		Space:          space,
		Now:            now,
		Fetcher:        fetcher,
		ProxyMetrics:   proxyMetrics,
	})
	if err != nil {
		return nil, err
	}
	registry.Register(srv)
	index, err := pypi.New(pypi.Options{
		Meta:         store,
		Blobs:        blobs,
		Repositories: cfg.Repositories,
		Authorizer:   authz,
		Actor:        authz.Actor,
		Logger:       logger,
		Metrics:      reg,
		Upstream:     upOpts,
		Space:        space,
		Now:          now,
		Fetcher:      fetcher,
		ProxyMetrics: proxyMetrics,
		Docs:         docs,
	})
	if err != nil {
		return nil, err
	}
	index.Register(srv)

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
			return nil, err
		}
	}
	backup.Register(srv, backups, authz.AdminHandler, authz.Actor)

	collector, err := gc.New(gc.Options{
		Meta:        store,
		Blobs:       blobs,
		Markers:     []gc.Marker{oci.GCMarker(), pypi.GCMarker(), upstream.Marks, auth.GCMarker()},
		Pruners:     []gc.Pruner{registry.GCPruner()},
		GracePeriod: cfg.GC.GracePeriod.Duration,
		Interval:    cfg.GC.Interval.Duration,
		Logger:      logger,
		Metrics:     reg,
		Now:         now,
	})
	if err != nil {
		return nil, err
	}
	authz.HandleAdmin(srv, gc.StatusPattern, collector.HandleStatus)
	authz.HandleAdmin(srv, gc.StartPattern, collector.HandleStart)
	return &app{srv: srv, oci: registry, pypi: index, space: space, audit: auditLog, backups: backups, gc: collector,
		docs: docs, revalidate: revalidate}, nil
}

// blobReferences report the blobs every format package's records, and
// the proxy cache the formats share, reference, for backups to check that
// they hold them all.
var blobReferences = []backup.References{oci.References, pypi.References, upstream.References}

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
