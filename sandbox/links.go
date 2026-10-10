package sandbox

import (
	"os"
	"path/filepath"
	"sync"

	"github.com/aoiflux/fsagen/target"
)

// LinkCaps says which links a volume stores and this process may make.
type LinkCaps struct {
	Hard, Sym, Junction bool
}

// The kinds of link Meta reports.
const (
	LinkSymlink  = target.LinkSymlink
	LinkJunction = target.LinkJunction
)

// volume is what probing a root's volume found out.
type volume struct {
	name                        string
	streams, hardlinks, reparse bool
}

// LinkCaps reports which links can be made under this root.
func (f *FS) LinkCaps() LinkCaps { return f.links }

// Link gives the file oldname a second name, newname: a hard link.
func (f *FS) Link(oldname, newname string) error {
	if err := f.MkdirParent(newname); err != nil {
		return err
	}
	return f.root.Link(native(oldname), native(newname))
}

// Symlink makes name a symlink to target, which is written as given and
// never followed. dir says whether it points at a directory, which Windows
// records in the link whether or not the target is there.
func (f *FS) Symlink(name, target string, dir bool) error {
	if err := f.MkdirParent(name); err != nil {
		return err
	}
	return symlink(f.root, native(name), target, dir)
}

// Junction makes name a junction to target, a directory in the output.
// Windows stores a junction's target as an absolute path, so it names the
// directory wherever the output is now.
func (f *FS) Junction(name, target string) error {
	if err := f.MkdirParent(name); err != nil {
		return err
	}
	return junction(f.root, native(name), filepath.Join(f.dir, native(target)))
}

var (
	symlinkOnce sync.Once
	symlinkOK   bool
)

// SymlinksAllowed reports whether this process may make a symlink at all,
// which on Windows takes Developer Mode or the privilege. It is tried once,
// in a temporary directory of its own.
func SymlinksAllowed() bool {
	symlinkOnce.Do(func() {
		dir, err := os.MkdirTemp("", "fsagen-symlink-probe-")
		if err != nil {
			return
		}
		defer os.RemoveAll(dir)
		r, err := os.OpenRoot(dir)
		if err != nil {
			return
		}
		defer r.Close()
		symlinkOK = symlink(r, "probe", "target", false) == nil
	})
	return symlinkOK
}

// relativeTarget is a junction's absolute target as a path in the output,
// when it is in it, and otherwise as it is.
func (f *FS) relativeTarget(target string) string {
	if rel, err := filepath.Rel(f.dir, target); err == nil && filepath.IsLocal(rel) {
		return filepath.ToSlash(rel)
	}
	return target
}
