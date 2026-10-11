//go:build !linux && !darwin

package upstream

// statfs is not implemented on this platform; Space then never reports
// pressure.
func statfs(string) (free, total uint64, err error) { return 0, 0, errStatfsUnsupported }
