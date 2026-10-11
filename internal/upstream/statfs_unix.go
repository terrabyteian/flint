//go:build linux || darwin

package upstream

import "syscall"

// statfs returns the space available to unprivileged users and the size
// of the filesystem holding path.
func statfs(path string) (free, total uint64, err error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, 0, err
	}
	return st.Bavail * uint64(st.Bsize), st.Blocks * uint64(st.Bsize), nil
}
