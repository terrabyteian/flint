package upstream

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"
)

var errStatfsUnsupported = errors.New("free space cannot be measured on this platform")

// Space intervals.
const (
	// SpaceCheckInterval is how often Run measures the free space.
	SpaceCheckInterval = 10 * time.Second
	// spaceMaxAge is how old a measurement Reserve relies on may be.
	spaceMaxAge = time.Second
)

// SpaceOptions configures a Space.
type SpaceOptions struct {
	// Path is a path on the filesystem to watch, normally the data
	// directory. Required.
	Path string
	// MinFree returns the free space, in bytes, below which caching
	// stops, for a filesystem of total bytes.
	MinFree func(total uint64) uint64
	// Statfs measures the free and total bytes of the filesystem holding
	// a path; nil means the operating system's.
	Statfs func(path string) (free, total uint64, err error)
	// Logger receives warnings; nil means slog.Default().
	Logger *slog.Logger
	// Now is the clock; nil means time.Now.
	Now func() time.Time
}

// Space watches the free space of the filesystem that holds the cache,
// so proxies stop caching new content before the disk fills. Cached
// content keeps being served, and nothing is deleted to make room:
// content that would bring the free space below the threshold is passed
// through from the upstream instead of being stored. Entering and
// leaving that state is logged, and Pressure reports it for metrics.
//
// Fetches reserve the size of what they are about to store, so
// concurrent fetches cannot together overrun the threshold that each
// alone would respect.
type Space struct {
	path    string
	minFree func(uint64) uint64
	statfs  func(string) (uint64, uint64, error)
	log     *slog.Logger
	now     func() time.Time

	mu       sync.Mutex
	free     uint64
	total    uint64
	checked  time.Time
	reserved uint64
	pressure bool
	failed   bool // the last measurement failed
}

// NewSpace returns a Space and takes a first measurement.
func NewSpace(opts SpaceOptions) *Space {
	s := &Space{path: opts.Path, minFree: opts.MinFree, statfs: opts.Statfs, log: opts.Logger, now: opts.Now}
	if s.minFree == nil {
		s.minFree = func(uint64) uint64 { return 0 }
	}
	if s.statfs == nil {
		s.statfs = statfs
	}
	if s.log == nil {
		s.log = slog.Default()
	}
	if s.now == nil {
		s.now = time.Now
	}
	s.mu.Lock()
	s.measure()
	s.mu.Unlock()
	return s
}

// measure updates the measurement and the pressure state. It must be
// called with s.mu held.
func (s *Space) measure() {
	s.checked = s.now()
	free, total, err := s.statfs(s.path)
	if err != nil {
		// Without a measurement, caching continues: the disk filling up
		// would fail writes, which never lose cached content.
		if !s.failed {
			s.log.Warn("cannot measure the free space of the data directory; proxy repositories cache without checking it",
				"path", s.path, "err", err)
		}
		s.failed = true
		s.setPressure(false)
		return
	}
	s.failed = false
	s.free, s.total = free, total
	s.setPressure(s.below(0))
}

// below reports whether storing n more bytes would leave less free space
// than the threshold. It must be called with s.mu held.
func (s *Space) below(n uint64) bool {
	if s.failed {
		return false
	}
	need := s.minFree(s.total) + s.reserved + n
	return need < s.reserved || s.free < need // the first guards overflow
}

func (s *Space) setPressure(p bool) {
	if p == s.pressure {
		return
	}
	s.pressure = p
	attrs := []any{"path", s.path, "free_bytes", s.free, "min_free_bytes", s.minFree(s.total)}
	if p {
		s.log.Warn("the data directory is nearly full: proxy repositories stop caching new content "+
			"and pass it through from upstream; cached content keeps being served", attrs...)
	} else {
		s.log.Info("the data directory has free space again: proxy repositories cache new content", attrs...)
	}
}

// Reserve reports whether n more bytes (0 if the size is unknown) may be
// cached without bringing the free space below the threshold, counting
// what other fetches have reserved. If they may, they stay reserved until
// release is called.
func (s *Space) Reserve(n int64) (release func(), ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.now().Sub(s.checked) >= spaceMaxAge {
		s.measure()
	}
	u := uint64(max(n, 0))
	if s.below(u) {
		if !s.pressure && s.below(0) {
			s.setPressure(true)
		}
		return nil, false
	}
	s.reserved += u
	var once sync.Once
	return func() {
		once.Do(func() {
			s.mu.Lock()
			s.reserved -= u
			s.mu.Unlock()
		})
	}, true
}

// Pressure reports whether the free space is below the threshold,
// measuring it again if the last measurement is not recent.
func (s *Space) Pressure() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.now().Sub(s.checked) >= spaceMaxAge {
		s.measure()
	}
	return s.pressure
}

// Free returns the free bytes last measured.
func (s *Space) Free() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.free
}

// Run measures the free space every interval until ctx is done, so
// pressure is noticed and logged even while nothing is being fetched.
func (s *Space) Run(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.mu.Lock()
			s.measure()
			s.mu.Unlock()
		}
	}
}
