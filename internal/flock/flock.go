// Package flock takes the exclusive file locks that keep two flint
// processes from using one directory at once: the data directory, and a
// backup directory while a backup or restore writes to it.
package flock

import "errors"

// ErrLocked means another process holds the lock.
var ErrLocked = errors.New("locked by another process")
