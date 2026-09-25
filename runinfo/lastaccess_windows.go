//go:build windows

package runinfo

import (
	"fmt"

	"golang.org/x/sys/windows/registry"
)

// LastAccessPolicy reads NtfsDisableLastAccessUpdate. The low bit set means
// access times are not updated on read; 0x80000000 marks a value the system
// manages (and may change as the volume grows).
func LastAccessPolicy() string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\FileSystem`, registry.QUERY_VALUE)
	if err != nil {
		return ""
	}
	defer k.Close()
	v, _, err := k.GetIntegerValue("NtfsDisableLastAccessUpdate")
	if err != nil {
		return ""
	}
	state := "updated on read"
	if v&1 != 0 {
		state = "not updated on read"
	}
	owner := "set by the user"
	if v&0x80000000 != 0 {
		owner = "managed by the system"
	}
	return fmt.Sprintf("NtfsDisableLastAccessUpdate=0x%08x (access times %s, %s)", v, state, owner)
}
