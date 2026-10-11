//go:build linux || darwin

package flock

import (
	"errors"
	"path/filepath"
	"testing"
)

func TestLock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "LOCK")
	unlock, err := Lock(path)
	if err != nil {
		t.Fatal(err)
	}
	// flock locks belong to the open file, so a second open conflicts
	// even within one process.
	if _, err := Lock(path); !errors.Is(err, ErrLocked) {
		t.Fatalf("second Lock: %v, want ErrLocked", err)
	}
	unlock()
	unlock, err = Lock(path)
	if err != nil {
		t.Fatalf("Lock after unlock: %v", err)
	}
	unlock()
}
