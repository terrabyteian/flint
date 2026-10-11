//go:build e2e

package main

import (
	"os"
	"strings"
	"time"
)

// A binary built with the e2e tag, for end-to-end tests only, runs its
// clock ahead by the duration in the file FLINT_E2E_CLOCK_FILE, if it
// holds one, read at every reading of the clock, so a test can take the
// content it stored past the garbage collector's grace period while the
// server runs.
func init() {
	path := os.Getenv("FLINT_E2E_CLOCK_FILE")
	if path == "" {
		return
	}
	now = func() time.Time {
		t := time.Now()
		if b, err := os.ReadFile(path); err == nil {
			if off, err := time.ParseDuration(strings.TrimSpace(string(b))); err == nil {
				return t.Add(off)
			}
		}
		return t
	}
}
