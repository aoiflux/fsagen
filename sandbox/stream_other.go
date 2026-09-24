//go:build !windows

package sandbox

import "os"

// Named streams are an NTFS/ReFS feature; elsewhere every stream operation
// reports ErrStreamsUnsupported and the capability pre-flight refuses (or,
// with --on-unsupported=skip, skips) the ads and motw actions.
func probeVolume(*os.Root) (bool, string) { return false, "" }

func writeStream(*os.Root, string, string, []byte) error { return ErrStreamsUnsupported }

func readStream(*os.Root, string, string) ([]byte, error) { return nil, ErrStreamsUnsupported }

func listStreams(*os.Root, string) ([]Stream, error) { return nil, nil }
