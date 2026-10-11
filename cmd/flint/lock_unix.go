//go:build linux || darwin

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
)

// lockDataDir takes the exclusive flock on <dir>/LOCK that marks the data
// directory as in use, so a second flint process on the same directory
// refuses to start. The lock is released when the process exits, however
// it exits. The file holds the owner's PID, for diagnosis only.
func lockDataDir(dir string) (unlock func(), err error) {
	path := filepath.Join(dir, "LOCK")
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("opening the data directory lock: %w", err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, fmt.Errorf("%w (%s is locked)", errLocked, path)
		}
		return nil, fmt.Errorf("locking %s: %w", path, err)
	}
	if err := f.Truncate(0); err == nil {
		f.WriteAt([]byte(strconv.Itoa(os.Getpid())+"\n"), 0)
	}
	return func() { f.Close() }, nil
}
