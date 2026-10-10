//go:build !windows

package sandbox

import (
	"errors"
	"os"
	"strings"
)

// noLinks are the file systems that store neither hard links nor symlinks.
var noLinks = map[string]bool{"VFAT": true, "EXFAT": true}

func linkCaps(v volume) LinkCaps {
	if noLinks[strings.ToUpper(v.name)] {
		return LinkCaps{}
	}
	return LinkCaps{Hard: true, Sym: true}
}

func symlink(r *os.Root, name, target string, _ bool) error { return r.Symlink(target, name) }

func junction(*os.Root, string, string) error {
	return errors.New("junctions are an NTFS feature of Windows")
}
