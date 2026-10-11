//go:build linux || darwin

package flock

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"syscall"
)

// Lock takes an exclusive flock on the file at path, creating it if
// needed, without waiting. It returns ErrLocked if another process, or
// another open of the file, holds the lock. The lock is released by
// unlock or when the process exits, however it exits. The file holds the
// owner's PID, for diagnosis only.
func Lock(path string) (unlock func(), err error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("opening the lock file: %w", err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, fmt.Errorf("%w (%s is locked)", ErrLocked, path)
		}
		return nil, fmt.Errorf("locking %s: %w", path, err)
	}
	if err := f.Truncate(0); err == nil {
		f.WriteAt([]byte(strconv.Itoa(os.Getpid())+"\n"), 0)
	}
	return func() { f.Close() }, nil
}
