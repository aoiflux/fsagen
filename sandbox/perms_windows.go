//go:build windows

package sandbox

// ModeHasPermissions reports whether a file mode on this platform carries
// permission bits that mean anything. Windows keeps a read-only flag rather
// than an owner/group/other triple, and Go synthesises the bits it reports
// from that flag, so a caller publishing a mode has to decide what to say
// instead of them.
const ModeHasPermissions = false
