package blob

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"hash/crc32"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/terrabyteian/flint/internal/fsys"
)

// Options configures a filesystem store.
type Options struct {
	// FS is the filesystem to use. Nil means fsys.OS.
	FS fsys.FS
	// Now returns the current time, used as the commit time of blobs.
	// Nil means time.Now.
	Now func() time.Time
}

// fsStore is the filesystem Store. Its layout under dir is
//
//	blobs/sha256/<2 hex>/<64 hex>  committed blobs
//	uploads/<id>                   staged bytes of an upload
//	uploads/<id>.state             hash state of a suspended upload
//	uploads/<id>.state.tmp         a state file being written
type fsStore struct {
	fs      fsys.FS
	now     func() time.Time
	blobs   string
	uploads string

	mu     sync.Mutex
	active map[string]bool // uploads open in this process, or being purged
}

// stateSuffix and tmpSuffix name an upload's state file and its temporary
// copy, next to the upload's data file.
const (
	stateSuffix = ".state"
	tmpSuffix   = ".tmp"
)

// NewFS returns a filesystem Store rooted at dir, creating its directories
// if needed. dir is normally the data directory; blobs/ and uploads/ inside
// it must be on one filesystem so commits can rename.
func NewFS(dir string, opts Options) (Store, error) {
	s := &fsStore{
		fs:      opts.FS,
		now:     opts.Now,
		blobs:   filepath.Join(dir, "blobs", "sha256"),
		uploads: filepath.Join(dir, "uploads"),
		active:  map[string]bool{},
	}
	if s.fs == nil {
		s.fs = fsys.OS
	}
	if s.now == nil {
		s.now = time.Now
	}
	if err := s.init(dir); err != nil {
		return nil, fmt.Errorf("blob: opening store in %s: %w", dir, err)
	}
	return s, nil
}

// init creates the directory layout, including all 256 fan-out
// directories, and makes it durable. Creating the fan-out directories up
// front keeps directory creation, and its parent fsync, out of commits.
func (s *fsStore) init(dir string) error {
	// dir's entry lives in its parent; each ancestor MkdirAll creates
	// needs its own parent synced too.
	parents := []string{filepath.Dir(dir)}
	for p := parents[0]; p != filepath.Dir(p); p = filepath.Dir(p) {
		if _, err := s.fs.Stat(p); err == nil {
			break
		} else if !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		parents = append(parents, filepath.Dir(p))
	}
	if err := s.fs.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	for _, p := range parents {
		if err := s.fs.SyncDir(p); err != nil {
			return err
		}
	}
	if err := s.mkdirs(dir, "blobs", "uploads"); err != nil {
		return err
	}
	if err := s.mkdirs(filepath.Join(dir, "blobs"), "sha256"); err != nil {
		return err
	}
	fanout := make([]string, 256)
	for i := range fanout {
		fanout[i] = fmt.Sprintf("%02x", i)
	}
	return s.mkdirs(s.blobs, fanout...)
}

// mkdirs creates the named subdirectories of parent that do not exist yet
// and syncs parent.
func (s *fsStore) mkdirs(parent string, names ...string) error {
	for _, name := range names {
		err := s.fs.Mkdir(filepath.Join(parent, name), 0o755)
		switch {
		case err == nil:
		case errors.Is(err, fs.ErrExist):
			if fi, err := s.fs.Stat(filepath.Join(parent, name)); err != nil {
				return err
			} else if !fi.IsDir() {
				return fmt.Errorf("%s is not a directory", filepath.Join(parent, name))
			}
		default:
			return err
		}
	}
	return s.fs.SyncDir(parent)
}

func (s *fsStore) fanoutDir(d Digest) string { return filepath.Join(s.blobs, d.Hex()[:2]) }
func (s *fsStore) blobPath(d Digest) string  { return filepath.Join(s.blobs, d.Hex()[:2], d.Hex()) }
func (s *fsStore) dataPath(id string) string { return filepath.Join(s.uploads, id) }
func (s *fsStore) statePath(id string) string {
	return filepath.Join(s.uploads, id+stateSuffix)
}

// claim marks upload id as open in this process. It reports false if it already is.
func (s *fsStore) claim(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.active[id] {
		return false
	}
	s.active[id] = true
	return true
}

func (s *fsStore) release(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.active, id)
}

// idLen is the length of an upload ID: 16 random bytes, hex-encoded.
const idLen = 32

func validID(id string) bool { return len(id) == idLen && isLowerHex(id) }

func (s *fsStore) NewUpload(ctx context.Context) (Upload, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var b [idLen / 2]byte
	rand.Read(b[:])
	id := hex.EncodeToString(b[:])
	if !s.claim(id) {
		return nil, fmt.Errorf("blob: upload ID collision on %s", id)
	}
	f, err := s.fs.OpenFile(s.dataPath(id), os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		s.release(id)
		return nil, fmt.Errorf("blob: starting upload: %w", err)
	}
	return &upload{s: s, id: id, f: f, h: sha256.New()}, nil
}

func (s *fsStore) ResumeUpload(ctx context.Context, id string) (Upload, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !validID(id) {
		return nil, fmt.Errorf("%w %q", ErrUploadUnknown, abbrev(id))
	}
	if !s.claim(id) {
		return nil, fmt.Errorf("%w: %s", ErrUploadBusy, id)
	}
	u, err := s.resume(id)
	if err != nil {
		s.release(id)
		return nil, err
	}
	return u, nil
}

// resume reopens upload id, which the caller has claimed.
func (s *fsStore) resume(id string) (*upload, error) {
	size, h, err := s.readState(id)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%w: %s", ErrUploadUnknown, id)
	}
	if err != nil {
		return nil, err
	}
	f, err := s.fs.OpenFile(s.dataPath(id), os.O_RDWR, 0)
	if errors.Is(err, fs.ErrNotExist) {
		// The data is gone, for example because a commit renamed it into
		// place and crashed before removing the state file.
		s.removeUpload(id)
		return nil, fmt.Errorf("%w: %s", ErrUploadUnknown, id)
	}
	if err != nil {
		return nil, fmt.Errorf("blob: resuming upload %s: %w", id, err)
	}
	fi, err := f.Stat()
	if err == nil && fi.Size() < size {
		err = fmt.Errorf("%w: %s has %d staged bytes, its state needs %d", ErrUploadUnknown, id, fi.Size(), size)
		f.Close()
		s.removeUpload(id)
		return nil, err
	}
	// Bytes written after the last Suspend were never acknowledged; drop them.
	if err == nil && fi.Size() > size {
		err = f.Truncate(size)
	}
	if err == nil {
		_, err = f.Seek(size, io.SeekStart)
	}
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("blob: resuming upload %s: %w", id, err)
	}
	return &upload{s: s, id: id, f: f, h: h, size: size}, nil
}

// State file format, all integers big-endian:
//
//	magic "FLUP", version byte, size uint64, hash state length uint16,
//	hash state, CRC-32C of everything before it.
const (
	stateMagic   = "FLUP"
	stateVersion = 1
	maxStateLen  = 1 << 10
)

var castagnoli = crc32.MakeTable(crc32.Castagnoli)

func encodeState(size int64, h hash.Hash) ([]byte, error) {
	hs, err := h.(encoding.BinaryMarshaler).MarshalBinary()
	if err != nil {
		return nil, err
	}
	b := make([]byte, 0, len(stateMagic)+1+8+2+len(hs)+4)
	b = append(b, stateMagic...)
	b = append(b, stateVersion)
	b = binary.BigEndian.AppendUint64(b, uint64(size))
	b = binary.BigEndian.AppendUint16(b, uint16(len(hs)))
	b = append(b, hs...)
	return binary.BigEndian.AppendUint32(b, crc32.Checksum(b, castagnoli)), nil
}

// readState reads the state file of upload id. A missing or damaged state
// file is reported as an error wrapping fs.ErrNotExist.
func (s *fsStore) readState(id string) (int64, hash.Hash, error) {
	f, err := s.fs.Open(s.statePath(id))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return 0, nil, err
		}
		return 0, nil, fmt.Errorf("blob: reading upload state %s: %w", id, err)
	}
	b, err := io.ReadAll(io.LimitReader(f, maxStateLen))
	f.Close()
	if err != nil {
		return 0, nil, fmt.Errorf("blob: reading upload state %s: %w", id, err)
	}
	size, h, ok := decodeState(b)
	if !ok {
		// A damaged state cannot be resumed; forget the upload.
		s.removeUpload(id)
		return 0, nil, fmt.Errorf("upload state %s is damaged: %w", id, fs.ErrNotExist)
	}
	return size, h, nil
}

func decodeState(b []byte) (int64, hash.Hash, bool) {
	const head = len(stateMagic) + 1 + 8 + 2
	if len(b) < head+4 || string(b[:len(stateMagic)]) != stateMagic || b[len(stateMagic)] != stateVersion {
		return 0, nil, false
	}
	body, sum := b[:len(b)-4], binary.BigEndian.Uint32(b[len(b)-4:])
	if crc32.Checksum(body, castagnoli) != sum {
		return 0, nil, false
	}
	size := binary.BigEndian.Uint64(b[len(stateMagic)+1:])
	hlen := int(binary.BigEndian.Uint16(b[len(stateMagic)+9:]))
	if len(body) != head+hlen || size > 1<<62 {
		return 0, nil, false
	}
	h := sha256.New()
	if err := h.(encoding.BinaryUnmarshaler).UnmarshalBinary(body[head:]); err != nil {
		return 0, nil, false
	}
	return int64(size), h, true
}

// removeUpload removes every file of upload id, ignoring files that do not exist.
func (s *fsStore) removeUpload(id string) error {
	var first error
	for _, name := range []string{s.dataPath(id), s.statePath(id), s.statePath(id) + tmpSuffix} {
		if err := s.fs.Remove(name); err != nil && !errors.Is(err, fs.ErrNotExist) && first == nil {
			first = err
		}
	}
	return first
}

func (s *fsStore) Open(ctx context.Context, d Digest) (Reader, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if d.IsZero() {
		return nil, fmt.Errorf("%w: zero digest", ErrNotFound)
	}
	f, err := s.fs.Open(s.blobPath(d))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, d)
	}
	if err != nil {
		return nil, fmt.Errorf("blob: opening %s: %w", d, err)
	}
	// Hand out the file itself: for fsys.OS it is an *os.File, which lets
	// net/http serve it with sendfile.
	return f, nil
}

func (s *fsStore) Stat(ctx context.Context, d Digest) (Info, error) {
	if err := ctx.Err(); err != nil {
		return Info{}, err
	}
	if d.IsZero() {
		return Info{}, fmt.Errorf("%w: zero digest", ErrNotFound)
	}
	fi, err := s.fs.Stat(s.blobPath(d))
	if errors.Is(err, fs.ErrNotExist) {
		return Info{}, fmt.Errorf("%w: %s", ErrNotFound, d)
	}
	if err != nil {
		return Info{}, fmt.Errorf("blob: stat %s: %w", d, err)
	}
	return Info{Digest: d, Size: fi.Size(), ModTime: fi.ModTime()}, nil
}

func (s *fsStore) Delete(ctx context.Context, d Digest) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if d.IsZero() {
		return fmt.Errorf("%w: zero digest", ErrNotFound)
	}
	err := s.fs.Remove(s.blobPath(d))
	if errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("%w: %s", ErrNotFound, d)
	}
	if err == nil {
		err = s.fs.SyncDir(s.fanoutDir(d))
	}
	if err != nil {
		return fmt.Errorf("blob: deleting %s: %w", d, err)
	}
	return nil
}

func (s *fsStore) Walk(ctx context.Context, fn func(Info) error) error {
	for i := range 256 {
		if err := ctx.Err(); err != nil {
			return err
		}
		prefix := fmt.Sprintf("%02x", i)
		dir := filepath.Join(s.blobs, prefix)
		entries, err := s.fs.ReadDir(dir)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			return fmt.Errorf("blob: walking %s: %w", dir, err)
		}
		for _, e := range entries {
			name := e.Name()
			if len(name) != 2*sha256.Size || !strings.HasPrefix(name, prefix) || !isLowerHex(name) || e.IsDir() {
				continue // not a blob; never ours to report
			}
			fi, err := e.Info()
			if errors.Is(err, fs.ErrNotExist) {
				continue // deleted since the listing
			}
			if err != nil {
				return fmt.Errorf("blob: walking %s: %w", dir, err)
			}
			var d Digest
			hex.Decode(d.sum[:], []byte(name))
			d.set = true
			if err := fn(Info{Digest: d, Size: fi.Size(), ModTime: fi.ModTime()}); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *fsStore) PurgeUploads(ctx context.Context, before time.Time) (int, error) {
	entries, err := s.fs.ReadDir(s.uploads)
	if err != nil {
		return 0, fmt.Errorf("blob: listing uploads: %w", err)
	}
	ids := map[string]bool{}
	var order []string
	for _, e := range entries {
		id, _, _ := strings.Cut(e.Name(), ".")
		if validID(id) && !ids[id] {
			ids[id] = true
			order = append(order, id)
		}
	}
	removed := 0
	for _, id := range order {
		if err := ctx.Err(); err != nil {
			return removed, err
		}
		if !s.claim(id) {
			continue // open in this process
		}
		// Look again now that the upload is claimed: the listing may
		// predate a Suspend that finished since.
		fi, err := s.fs.Stat(s.statePath(id))
		switch {
		case err == nil && !fi.ModTime().Before(before):
			// A recently suspended upload; keep it, minus any
			// state file a crash left half written.
			if err := s.fs.Remove(s.statePath(id) + tmpSuffix); err != nil && !errors.Is(err, fs.ErrNotExist) {
				s.release(id)
				return removed, fmt.Errorf("blob: purging upload %s: %w", id, err)
			}
		case err == nil || errors.Is(err, fs.ErrNotExist):
			if err := s.removeUpload(id); err != nil {
				s.release(id)
				return removed, fmt.Errorf("blob: purging upload %s: %w", id, err)
			}
			removed++
		default:
			s.release(id)
			return removed, fmt.Errorf("blob: purging upload %s: %w", id, err)
		}
		s.release(id)
	}
	return removed, nil
}

// upload is an upload of a fsStore.
type upload struct {
	s    *fsStore
	id   string
	f    fsys.File
	h    hash.Hash
	size int64
	err  error // sticky write error
	done bool
}

func (u *upload) ID() string  { return u.id }
func (u *upload) Size() int64 { return u.size }

func (u *upload) Write(p []byte) (int, error) {
	if u.done {
		return 0, ErrUploadClosed
	}
	if u.err != nil {
		return 0, u.err
	}
	n, err := u.f.Write(p)
	u.h.Write(p[:n])
	u.size += int64(n)
	if err != nil {
		u.err = fmt.Errorf("blob: writing upload %s: %w", u.id, err)
		return n, u.err
	}
	return n, nil
}

// copyBufSize is the buffer ReadFrom uses: large enough that a stream
// costs few write calls, small enough to keep per-upload memory low.
const copyBufSize = 256 << 10

var copyBufs = sync.Pool{New: func() any { return new([copyBufSize]byte) }}

// ReadFrom makes io.Copy into an upload use a larger buffer than its default.
func (u *upload) ReadFrom(r io.Reader) (int64, error) {
	buf := copyBufs.Get().(*[copyBufSize]byte)
	defer copyBufs.Put(buf)
	var total int64
	for {
		n, rerr := r.Read(buf[:])
		if n > 0 {
			w, err := u.Write(buf[:n])
			total += int64(w)
			if err != nil {
				return total, err
			}
		}
		if rerr == io.EOF {
			return total, nil
		}
		if rerr != nil {
			return total, rerr
		}
	}
}

func (u *upload) Commit(ctx context.Context, want Digest) (Info, error) {
	if u.done {
		return Info{}, ErrUploadClosed
	}
	info, err := u.commit(ctx, want)
	if err != nil {
		u.discard()
		return Info{}, err
	}
	u.finish()
	return info, nil
}

func (u *upload) commit(ctx context.Context, want Digest) (Info, error) {
	if u.err != nil {
		return Info{}, u.err
	}
	if err := ctx.Err(); err != nil {
		return Info{}, err
	}
	got := fromSum(u.h.Sum(nil))
	if !want.IsZero() && want != got {
		return Info{}, fmt.Errorf("%w: content is %s, client claimed %s", ErrDigestMismatch, got, want)
	}
	s := u.s
	final := s.blobPath(got)
	if fi, err := s.fs.Stat(final); err == nil && fi.Size() == u.size {
		// Identical content is stored once. The blob may have been
		// renamed into place by a concurrent commit that has not synced
		// its directory yet, so sync it before relying on it.
		if err := s.fs.SyncDir(s.fanoutDir(got)); err != nil {
			return Info{}, fmt.Errorf("blob: committing %s: %w", got, err)
		}
		u.f.Close()
		s.removeUpload(u.id)
		return Info{Digest: got, Size: fi.Size(), ModTime: fi.ModTime()}, nil
	} else if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return Info{}, fmt.Errorf("blob: committing %s: %w", got, err)
	}
	// The blob is new, or a damaged copy of the wrong size that this
	// verified one replaces. The modification time is the commit time,
	// whenever the bytes were written.
	now := s.now()
	err := s.fs.Chtimes(u.f.Name(), now, now)
	if err == nil {
		err = u.f.Sync()
	}
	var fi fs.FileInfo
	if err == nil {
		fi, err = u.f.Stat()
	}
	if err == nil {
		err = u.f.Close()
	}
	if err == nil {
		err = s.fs.Rename(u.f.Name(), final)
	}
	if err == nil {
		err = s.fs.SyncDir(s.fanoutDir(got))
	}
	if err != nil {
		return Info{}, fmt.Errorf("blob: committing %s: %w", got, err)
	}
	// A state file left from an earlier Suspend no longer matters: without
	// its data file it cannot be resumed, and PurgeUploads removes it.
	s.fs.Remove(s.statePath(u.id))
	return Info{Digest: got, Size: fi.Size(), ModTime: fi.ModTime()}, nil
}

func (u *upload) Suspend() error {
	if u.done {
		return ErrUploadClosed
	}
	if err := u.suspend(); err != nil {
		u.discard()
		return fmt.Errorf("blob: suspending upload %s: %w", u.id, err)
	}
	u.finish()
	return nil
}

// suspend makes the data, then the state describing it, durable. The data
// must be durable first: after a crash the state must never describe bytes
// that were lost, or a resumed upload could commit content its hash state
// never saw.
func (u *upload) suspend() error {
	if u.err != nil {
		return u.err
	}
	state, err := encodeState(u.size, u.h)
	if err != nil {
		return err
	}
	if err := u.f.Sync(); err != nil {
		return err
	}
	if err := u.f.Close(); err != nil {
		return err
	}
	s := u.s
	tmp := s.statePath(u.id) + tmpSuffix
	f, err := s.fs.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	_, err = f.Write(state)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = s.fs.Rename(tmp, s.statePath(u.id))
	}
	if err == nil {
		// Makes the state file, and the data file's own creation, durable.
		err = s.fs.SyncDir(s.uploads)
	}
	return err
}

func (u *upload) Cancel() error {
	if u.done {
		return ErrUploadClosed
	}
	u.f.Close()
	err := u.s.removeUpload(u.id)
	u.finish()
	if err != nil {
		return fmt.Errorf("blob: cancelling upload %s: %w", u.id, err)
	}
	return nil
}

// discard removes the upload after a failure, as best it can; PurgeUploads
// cleans up whatever is left.
func (u *upload) discard() {
	u.f.Close()
	u.s.removeUpload(u.id)
	u.finish()
}

func (u *upload) finish() {
	u.done = true
	u.s.release(u.id)
}
