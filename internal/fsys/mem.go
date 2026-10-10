package fsys

import (
	"errors"
	"io"
	"io/fs"
	"math/rand/v2"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"
)

// ErrCrashed is returned by every operation on a [Mem] after it has crashed.
var ErrCrashed = errors.New("fsys: simulated crash")

// errNotEmpty is returned when removing a directory that still has entries.
var errNotEmpty = errors.New("directory not empty")

// errIsDir and errNotDir are returned for operations on the wrong kind of inode.
var (
	errIsDir  = errors.New("is a directory")
	errNotDir = errors.New("not a directory")
)

// Op names a filesystem operation, for fault injection.
type Op string

// Operations reported to a fault hook.
const (
	OpOpen     Op = "open"
	OpRead     Op = "read"
	OpWrite    Op = "write"
	OpSync     Op = "sync"
	OpTruncate Op = "truncate"
	OpClose    Op = "close"
	OpRename   Op = "rename"
	OpRemove   Op = "remove"
	OpMkdir    Op = "mkdir"
	OpReadDir  Op = "readdir"
	OpStat     Op = "stat"
	OpChtimes  Op = "chtimes"
	OpSyncDir  Op = "syncdir"
)

// pageSize is the granularity at which a torn crash keeps or drops unsynced data.
const pageSize = 4096

// Mem is a strict in-memory filesystem for crash tests.
//
// It tracks, for every file, the contents last made durable by Sync, and for
// every directory, the entries last made durable by SyncDir. [Mem.Restart]
// builds the filesystem a machine would see after losing power at that
// moment: unsynced file data is gone (or, with a random source, torn at page
// granularity), and every create, rename, remove, and mkdir whose parent
// directory was not synced afterwards is undone.
//
// Mem is safe for concurrent use.
type Mem struct {
	mu      sync.Mutex
	root    *inode
	now     func() time.Time
	crashed bool
	crashIn int64 // mutating operations left before a crash; negative means never
	ops     int64 // mutating operations performed
	fault   func(op Op, name string) error
}

type inode struct {
	dir   bool
	mode  fs.FileMode
	mtime time.Time

	// Files.
	data   []byte
	synced []byte

	// Directories.
	entries map[string]*inode
	durable map[string]*inode
}

var _ FS = (*Mem)(nil)

// NewMem returns an empty in-memory filesystem whose root directory exists.
func NewMem() *Mem {
	m := &Mem{now: time.Now, crashIn: -1}
	m.root = m.newDir(0o755)
	return m
}

func (m *Mem) newDir(perm fs.FileMode) *inode {
	return &inode{dir: true, mode: fs.ModeDir | perm.Perm(), mtime: m.now(),
		entries: map[string]*inode{}, durable: map[string]*inode{}}
}

// SetClock sets the source of modification times. The default is time.Now.
func (m *Mem) SetClock(now func() time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.now = now
}

// SetFault installs a hook called before every operation with the operation
// and the name it acts on; a nil hook removes it. If the hook returns an
// error, the operation fails with it, except that a failing OpWrite first
// writes half of its bytes, simulating a short write. The hook runs with the
// filesystem locked and must not call back into it.
func (m *Mem) SetFault(hook func(op Op, name string) error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.fault = hook
}

// CrashAfter arranges for the filesystem to crash once n more mutating
// operations (writes, syncs, truncates, creates, renames, removes, and
// mkdirs) have succeeded. The crash happens instead of operation n+1.
func (m *Mem) CrashAfter(n int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.crashIn = n
}

// Crash crashes the filesystem now. Every later operation fails with ErrCrashed.
func (m *Mem) Crash() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.crashed = true
}

// Crashed reports whether the filesystem has crashed.
func (m *Mem) Crashed() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.crashed
}

// Ops returns the number of mutating operations performed so far.
func (m *Mem) Ops() int64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.ops
}

// Restart crashes the filesystem if it has not crashed yet and returns a new
// filesystem holding what survived. With a nil rng every unsynced write is
// lost. With an rng, each file whose contents were not synced comes back
// with its synced or its latest size, and each page of it from either its
// synced or its latest contents, chosen at random; bytes neither version
// holds read as zero. Directory entries follow SyncDir strictly either way.
func (m *Mem) Restart(rng *rand.Rand) *Mem {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.crashed = true
	n := &Mem{now: m.now, crashIn: -1}
	seen := map[*inode]*inode{}
	var clone func(*inode) *inode
	clone = func(src *inode) *inode {
		if c, ok := seen[src]; ok {
			return c
		}
		c := &inode{dir: src.dir, mode: src.mode, mtime: src.mtime}
		seen[src] = c
		if src.dir {
			c.entries = make(map[string]*inode, len(src.durable))
			c.durable = make(map[string]*inode, len(src.durable))
			for name, child := range src.durable {
				cc := clone(child)
				c.entries[name] = cc
				c.durable[name] = cc
			}
			return c
		}
		c.data = survivingData(src, rng)
		c.synced = slices.Clone(c.data)
		return c
	}
	n.root = clone(m.root)
	return n
}

// survivingData returns the contents of file f after a crash.
func survivingData(f *inode, rng *rand.Rand) []byte {
	if rng == nil || slices.Equal(f.data, f.synced) {
		return slices.Clone(f.synced)
	}
	size := len(f.synced)
	if rng.IntN(2) == 0 {
		size = len(f.data)
	}
	out := make([]byte, size)
	for off := 0; off < size; off += pageSize {
		end := min(off+pageSize, size)
		src := f.synced
		if rng.IntN(2) == 0 {
			src = f.data
		}
		if off < len(src) {
			copy(out[off:end], src[off:min(end, len(src))])
		}
	}
	return out
}

// step checks whether an operation may run. It must be called with m.mu held.
func (m *Mem) step(op Op, name string, mutating bool) error {
	if m.crashed {
		return ErrCrashed
	}
	if m.fault != nil {
		if err := m.fault(op, name); err != nil {
			return err
		}
	}
	if !mutating {
		return nil
	}
	if m.crashIn == 0 {
		m.crashed = true
		return ErrCrashed
	}
	if m.crashIn > 0 {
		m.crashIn--
	}
	m.ops++
	return nil
}

// split returns the components of name, relative to the root.
func split(name string) []string {
	p := path.Clean("/" + filepath.ToSlash(name))
	if p == "/" {
		return nil
	}
	return strings.Split(p[1:], "/")
}

// lookup resolves the directory holding name and the final component.
// For the root itself it returns (nil, "", root).
func (m *Mem) lookup(name string) (parent *inode, base string, ino *inode, err error) {
	parts := split(name)
	if len(parts) == 0 {
		return nil, "", m.root, nil
	}
	dir := m.root
	for _, p := range parts[:len(parts)-1] {
		next, ok := dir.entries[p]
		if !ok {
			return nil, "", nil, fs.ErrNotExist
		}
		if !next.dir {
			return nil, "", nil, errNotDir
		}
		dir = next
	}
	base = parts[len(parts)-1]
	return dir, base, dir.entries[base], nil
}

func pathErr(op Op, name string, err error) error {
	return &fs.PathError{Op: string(op), Path: name, Err: err}
}

// OpenFile implements [FS].
func (m *Mem) OpenFile(name string, flag int, perm fs.FileMode) (File, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	mutating := flag&(os.O_CREATE|os.O_TRUNC) != 0
	if err := m.step(OpOpen, name, mutating); err != nil {
		return nil, pathErr(OpOpen, name, err)
	}
	parent, base, ino, err := m.lookup(name)
	if err != nil {
		return nil, pathErr(OpOpen, name, err)
	}
	writable := flag&(os.O_WRONLY|os.O_RDWR) != 0
	switch {
	case ino == nil && flag&os.O_CREATE == 0:
		return nil, pathErr(OpOpen, name, fs.ErrNotExist)
	case ino == nil:
		ino = &inode{mode: perm.Perm(), mtime: m.now()}
		parent.entries[base] = ino
	case flag&(os.O_CREATE|os.O_EXCL) == os.O_CREATE|os.O_EXCL:
		return nil, pathErr(OpOpen, name, fs.ErrExist)
	case ino.dir && writable:
		return nil, pathErr(OpOpen, name, errIsDir)
	}
	if flag&os.O_TRUNC != 0 && writable && len(ino.data) > 0 {
		ino.data = nil
		ino.mtime = m.now()
	}
	return &memFile{m: m, name: name, ino: ino, flag: flag}, nil
}

// Open implements [FS].
func (m *Mem) Open(name string) (File, error) { return m.OpenFile(name, os.O_RDONLY, 0) }

// Rename implements [FS].
func (m *Mem) Rename(oldpath, newpath string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.step(OpRename, oldpath, true); err != nil {
		return &os.LinkError{Op: string(OpRename), Old: oldpath, New: newpath, Err: err}
	}
	op, ob, ino, err := m.lookup(oldpath)
	if err == nil && ino == nil {
		err = fs.ErrNotExist
	}
	if err != nil {
		return &os.LinkError{Op: string(OpRename), Old: oldpath, New: newpath, Err: err}
	}
	np, nb, target, err := m.lookup(newpath)
	if err != nil {
		return &os.LinkError{Op: string(OpRename), Old: oldpath, New: newpath, Err: err}
	}
	if op == nil || np == nil {
		return &os.LinkError{Op: string(OpRename), Old: oldpath, New: newpath, Err: errIsDir}
	}
	if target == ino {
		return nil
	}
	if target != nil && (target.dir || ino.dir) {
		return &os.LinkError{Op: string(OpRename), Old: oldpath, New: newpath, Err: fs.ErrExist}
	}
	delete(op.entries, ob)
	np.entries[nb] = ino
	return nil
}

// Remove implements [FS].
func (m *Mem) Remove(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.step(OpRemove, name, true); err != nil {
		return pathErr(OpRemove, name, err)
	}
	parent, base, ino, err := m.lookup(name)
	switch {
	case err != nil:
		return pathErr(OpRemove, name, err)
	case ino == nil:
		return pathErr(OpRemove, name, fs.ErrNotExist)
	case parent == nil:
		return pathErr(OpRemove, name, errIsDir)
	case ino.dir && len(ino.entries) > 0:
		return pathErr(OpRemove, name, errNotEmpty)
	}
	delete(parent.entries, base)
	return nil
}

// Mkdir implements [FS].
func (m *Mem) Mkdir(name string, perm fs.FileMode) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.mkdir(name, perm)
}

func (m *Mem) mkdir(name string, perm fs.FileMode) error {
	if err := m.step(OpMkdir, name, true); err != nil {
		return pathErr(OpMkdir, name, err)
	}
	parent, base, ino, err := m.lookup(name)
	switch {
	case err != nil:
		return pathErr(OpMkdir, name, err)
	case ino != nil:
		return pathErr(OpMkdir, name, fs.ErrExist)
	}
	parent.entries[base] = m.newDir(perm)
	return nil
}

// MkdirAll implements [FS].
func (m *Mem) MkdirAll(name string, perm fs.FileMode) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	parts := split(name)
	dir := m.root
	for i, p := range parts {
		next, ok := dir.entries[p]
		if !ok {
			if err := m.mkdir("/"+strings.Join(parts[:i+1], "/"), perm); err != nil {
				return err
			}
			next = dir.entries[p]
		} else if !next.dir {
			return pathErr(OpMkdir, name, errNotDir)
		}
		dir = next
	}
	return nil
}

// ReadDir implements [FS].
func (m *Mem) ReadDir(name string) ([]fs.DirEntry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.step(OpReadDir, name, false); err != nil {
		return nil, pathErr(OpReadDir, name, err)
	}
	_, _, ino, err := m.lookup(name)
	switch {
	case err != nil:
		return nil, pathErr(OpReadDir, name, err)
	case ino == nil:
		return nil, pathErr(OpReadDir, name, fs.ErrNotExist)
	case !ino.dir:
		return nil, pathErr(OpReadDir, name, errNotDir)
	}
	out := make([]fs.DirEntry, 0, len(ino.entries))
	for base, child := range ino.entries {
		out = append(out, fs.FileInfoToDirEntry(child.info(base)))
	}
	slices.SortFunc(out, func(a, b fs.DirEntry) int { return strings.Compare(a.Name(), b.Name()) })
	return out, nil
}

// Stat implements [FS].
func (m *Mem) Stat(name string) (fs.FileInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.step(OpStat, name, false); err != nil {
		return nil, pathErr(OpStat, name, err)
	}
	_, base, ino, err := m.lookup(name)
	if err == nil && ino == nil {
		err = fs.ErrNotExist
	}
	if err != nil {
		return nil, pathErr(OpStat, name, err)
	}
	return ino.info(base), nil
}

// Chtimes implements [FS]. Mem keeps only modification times.
func (m *Mem) Chtimes(name string, atime, mtime time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.step(OpChtimes, name, true); err != nil {
		return pathErr(OpChtimes, name, err)
	}
	_, _, ino, err := m.lookup(name)
	if err == nil && ino == nil {
		err = fs.ErrNotExist
	}
	if err != nil {
		return pathErr(OpChtimes, name, err)
	}
	ino.mtime = mtime
	return nil
}

// SyncDir implements [FS].
func (m *Mem) SyncDir(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.step(OpSyncDir, name, true); err != nil {
		return pathErr(OpSyncDir, name, err)
	}
	_, _, ino, err := m.lookup(name)
	switch {
	case err != nil:
		return pathErr(OpSyncDir, name, err)
	case ino == nil:
		return pathErr(OpSyncDir, name, fs.ErrNotExist)
	case !ino.dir:
		return pathErr(OpSyncDir, name, errNotDir)
	}
	ino.durable = make(map[string]*inode, len(ino.entries))
	for k, v := range ino.entries {
		ino.durable[k] = v
	}
	return nil
}

func (n *inode) info(name string) fs.FileInfo {
	if name == "" {
		name = "/"
	}
	return memInfo{name: name, size: int64(len(n.data)), mode: n.mode, mtime: n.mtime}
}

type memInfo struct {
	name  string
	size  int64
	mode  fs.FileMode
	mtime time.Time
}

func (i memInfo) Name() string       { return i.name }
func (i memInfo) Size() int64        { return i.size }
func (i memInfo) Mode() fs.FileMode  { return i.mode }
func (i memInfo) ModTime() time.Time { return i.mtime }
func (i memInfo) IsDir() bool        { return i.mode.IsDir() }
func (i memInfo) Sys() any           { return nil }

// memFile is an open file of a Mem.
type memFile struct {
	m      *Mem
	name   string
	ino    *inode
	flag   int
	off    int64
	closed bool
}

func (f *memFile) Name() string { return f.name }

// check runs the common checks for an operation on f. It must be called with f.m.mu held.
func (f *memFile) check(op Op, mutating bool) error {
	if f.closed {
		return pathErr(op, f.name, fs.ErrClosed)
	}
	if err := f.m.step(op, f.name, mutating); err != nil {
		return pathErr(op, f.name, err)
	}
	return nil
}

func (f *memFile) readable() bool { return f.flag&os.O_WRONLY == 0 }
func (f *memFile) writable() bool { return f.flag&(os.O_WRONLY|os.O_RDWR) != 0 }

func (f *memFile) Read(p []byte) (int, error) {
	f.m.mu.Lock()
	defer f.m.mu.Unlock()
	n, err := f.readAt(p, f.off)
	f.off += int64(n)
	if err == io.EOF && n > 0 {
		err = nil
	}
	return n, err
}

func (f *memFile) ReadAt(p []byte, off int64) (int, error) {
	f.m.mu.Lock()
	defer f.m.mu.Unlock()
	return f.readAt(p, off)
}

func (f *memFile) readAt(p []byte, off int64) (int, error) {
	if err := f.check(OpRead, false); err != nil {
		return 0, err
	}
	switch {
	case f.ino.dir:
		return 0, pathErr(OpRead, f.name, errIsDir)
	case !f.readable():
		return 0, pathErr(OpRead, f.name, fs.ErrPermission)
	case off < 0:
		return 0, pathErr(OpRead, f.name, fs.ErrInvalid)
	case off >= int64(len(f.ino.data)):
		if len(p) == 0 {
			return 0, nil
		}
		return 0, io.EOF
	}
	n := copy(p, f.ino.data[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

func (f *memFile) Write(p []byte) (int, error) {
	f.m.mu.Lock()
	defer f.m.mu.Unlock()
	if f.closed {
		return 0, pathErr(OpWrite, f.name, fs.ErrClosed)
	}
	if !f.writable() {
		return 0, pathErr(OpWrite, f.name, fs.ErrPermission)
	}
	if f.flag&os.O_APPEND != 0 {
		f.off = int64(len(f.ino.data))
	}
	if err := f.check(OpWrite, true); err != nil {
		if errors.Is(err, ErrCrashed) {
			return 0, err
		}
		n := len(p) / 2
		f.writeAt(p[:n])
		return n, err
	}
	f.writeAt(p)
	return len(p), nil
}

// writeAt writes p at the file offset and advances it.
func (f *memFile) writeAt(p []byte) {
	end := f.off + int64(len(p))
	if end > int64(len(f.ino.data)) {
		f.ino.data = append(f.ino.data, make([]byte, end-int64(len(f.ino.data)))...)
	}
	copy(f.ino.data[f.off:], p)
	f.off = end
	f.ino.mtime = f.m.now()
}

func (f *memFile) Seek(offset int64, whence int) (int64, error) {
	f.m.mu.Lock()
	defer f.m.mu.Unlock()
	if f.closed {
		return 0, pathErr("seek", f.name, fs.ErrClosed)
	}
	if f.m.crashed {
		return 0, pathErr("seek", f.name, ErrCrashed)
	}
	var abs int64
	switch whence {
	case io.SeekStart:
		abs = offset
	case io.SeekCurrent:
		abs = f.off + offset
	case io.SeekEnd:
		abs = int64(len(f.ino.data)) + offset
	default:
		return 0, pathErr("seek", f.name, fs.ErrInvalid)
	}
	if abs < 0 {
		return 0, pathErr("seek", f.name, fs.ErrInvalid)
	}
	f.off = abs
	return abs, nil
}

func (f *memFile) Stat() (fs.FileInfo, error) {
	f.m.mu.Lock()
	defer f.m.mu.Unlock()
	if err := f.check(OpStat, false); err != nil {
		return nil, err
	}
	return f.ino.info(path.Base(filepath.ToSlash(f.name))), nil
}

func (f *memFile) Sync() error {
	f.m.mu.Lock()
	defer f.m.mu.Unlock()
	if err := f.check(OpSync, true); err != nil {
		return err
	}
	if !f.ino.dir {
		f.ino.synced = slices.Clone(f.ino.data)
	}
	return nil
}

func (f *memFile) Truncate(size int64) error {
	f.m.mu.Lock()
	defer f.m.mu.Unlock()
	if !f.writable() {
		return pathErr(OpTruncate, f.name, fs.ErrPermission)
	}
	if size < 0 {
		return pathErr(OpTruncate, f.name, fs.ErrInvalid)
	}
	if err := f.check(OpTruncate, true); err != nil {
		return err
	}
	if size <= int64(len(f.ino.data)) {
		f.ino.data = f.ino.data[:size:size]
	} else {
		f.ino.data = append(f.ino.data, make([]byte, size-int64(len(f.ino.data)))...)
	}
	f.ino.mtime = f.m.now()
	return nil
}

func (f *memFile) Close() error {
	f.m.mu.Lock()
	defer f.m.mu.Unlock()
	if f.closed {
		return pathErr(OpClose, f.name, fs.ErrClosed)
	}
	f.closed = true
	if f.m.fault != nil {
		if err := f.m.fault(OpClose, f.name); err != nil {
			return pathErr(OpClose, f.name, err)
		}
	}
	return nil
}
