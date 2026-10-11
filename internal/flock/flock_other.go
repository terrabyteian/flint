//go:build !(linux || darwin)

package flock

import "errors"

// Lock is implemented for linux and darwin, flint's release targets.
func Lock(path string) (func(), error) {
	return nil, errors.New("file locks are not supported on this platform")
}
