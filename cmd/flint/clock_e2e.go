//go:build e2e

package main

import (
	"os"
	"time"
)

// A binary built with the e2e tag, for end-to-end tests only, runs its
// clock FLINT_E2E_CLOCK_OFFSET, a duration, ahead, so a test can take the
// content it stored past the garbage collector's grace period.
func init() {
	if off, err := time.ParseDuration(os.Getenv("FLINT_E2E_CLOCK_OFFSET")); err == nil {
		now = func() time.Time { return time.Now().Add(off) }
	}
}
