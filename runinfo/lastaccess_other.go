//go:build !windows

package runinfo

// LastAccessPolicy is only read on Windows; elsewhere it is a mount option
// (noatime, relatime), recorded as unknown.
func LastAccessPolicy() string { return "" }
