//go:build !windows

package sandbox

// ModeHasPermissions reports whether a file mode on this platform carries
// permission bits that mean anything. Every Unix keeps a real mode, so the
// bits are the file's own.
const ModeHasPermissions = true
