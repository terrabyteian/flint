//go:build !(linux || darwin)

package main

import "errors"

// lockDataDir is implemented for linux and darwin, flint's release targets.
func lockDataDir(dir string) (func(), error) {
	return nil, errors.New("locking the data directory is not supported on this platform")
}
