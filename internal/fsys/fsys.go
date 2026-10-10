// Package fsys is the small filesystem interface that flint's storage code
// does all of its file I/O through.
//
// Production uses [OS], which is the os package with nothing in between: its
// files are *os.File values, so a blob opened through it can be handed to
// net/http unwrapped and served with sendfile. Tests use [Mem], a strict
// in-memory filesystem that can simulate a power loss and discards everything
// that was not made durable with Sync or SyncDir.
//
// Durability follows POSIX rules. File contents are durable once the file is
// synced. A create, rename, remove, or mkdir is durable once the parent
// directory of every name it changed is synced with SyncDir.
package fsys

import (
	"io"
	"io/fs"
	"os"
	"time"
)

// FS is a filesystem. Names use the operating system's path syntax.
type FS interface {
	// OpenFile opens a file like os.OpenFile. It supports the flags
	// os.O_RDONLY, os.O_WRONLY, os.O_RDWR, os.O_CREATE, os.O_EXCL,
	// os.O_TRUNC, and os.O_APPEND.
	OpenFile(name string, flag int, perm fs.FileMode) (File, error)
	// Open opens a file for reading.
	Open(name string) (File, error)
	// Rename renames a file, atomically replacing newpath if it exists.
	Rename(oldpath, newpath string) error
	// Remove removes a file or an empty directory.
	Remove(name string) error
	// Mkdir creates a directory.
	Mkdir(name string, perm fs.FileMode) error
	// MkdirAll creates a directory and any missing parents.
	MkdirAll(name string, perm fs.FileMode) error
	// ReadDir lists a directory, sorted by name.
	ReadDir(name string) ([]fs.DirEntry, error)
	// Stat describes a file or directory.
	Stat(name string) (fs.FileInfo, error)
	// Chtimes sets a file's access and modification times. Like other
	// file metadata, the change is durable once the file is synced.
	Chtimes(name string, atime, mtime time.Time) error
	// SyncDir makes the creates, renames, and removes of entries in
	// directory name durable.
	SyncDir(name string) error
}

// File is an open file. *os.File implements it.
type File interface {
	io.Reader
	io.ReaderAt
	io.Writer
	io.Seeker
	io.Closer
	Name() string
	Stat() (fs.FileInfo, error)
	// Sync makes the file's contents and size durable.
	Sync() error
	Truncate(size int64) error
}

var _ File = (*os.File)(nil)

// OS is the filesystem of the operating system.
var OS FS = osFS{}

type osFS struct{}

func (osFS) OpenFile(name string, flag int, perm fs.FileMode) (File, error) {
	f, err := os.OpenFile(name, flag, perm)
	if err != nil {
		return nil, err
	}
	return f, nil
}

func (osFS) Open(name string) (File, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	return f, nil
}

func (osFS) Rename(oldpath, newpath string) error         { return os.Rename(oldpath, newpath) }
func (osFS) Remove(name string) error                     { return os.Remove(name) }
func (osFS) Mkdir(name string, perm fs.FileMode) error    { return os.Mkdir(name, perm) }
func (osFS) MkdirAll(name string, perm fs.FileMode) error { return os.MkdirAll(name, perm) }
func (osFS) ReadDir(name string) ([]fs.DirEntry, error)   { return os.ReadDir(name) }
func (osFS) Stat(name string) (fs.FileInfo, error)        { return os.Stat(name) }
func (osFS) Chtimes(name string, atime, mtime time.Time) error {
	return os.Chtimes(name, atime, mtime)
}

func (osFS) SyncDir(name string) error {
	d, err := os.Open(name)
	if err != nil {
		return err
	}
	err = d.Sync()
	if cerr := d.Close(); err == nil {
		err = cerr
	}
	return err
}
