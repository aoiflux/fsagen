package fat

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/aoiflux/fsagen/pathpolicy"
	"github.com/aoiflux/fsagen/target"
	"github.com/aoiflux/fsagen/volume"
)

// Reader reads a FAT32 volume from disk, knowing nothing of how it was
// written: the boot sector says where everything is, and every name, time
// and byte is read from the directories and the first FAT.
type Reader struct {
	dev  *volume.Device
	g    Geometry
	fat  []uint32
	root *entryNode
}

// entryNode is one object as its directory entry describes it.
type entryNode struct {
	name     string
	dir, ro  bool
	first    uint32
	size     int64
	times    target.Times
	addr     int64
	children []*entryNode
	byKey    map[string]*entryNode
}

// Open reads the volume on dev.
func Open(dev *volume.Device) (*Reader, error) {
	boot := make([]byte, sectorSize)
	if _, err := dev.ReadAt(boot, 0); err != nil {
		return nil, err
	}
	le := binary.LittleEndian
	if boot[510] != 0x55 || boot[511] != 0xAA || string(boot[82:90]) != "FAT32   " {
		return nil, errors.New("fat: no FAT32 boot sector")
	}
	if le.Uint16(boot[11:]) != sectorSize {
		return nil, fmt.Errorf("fat: %d-byte sectors are not read", le.Uint16(boot[11:]))
	}
	spc := int(boot[13])
	g := Geometry{Sectors: le.Uint32(boot[32:]), SecPerClus: spc, ClusterSize: spc * sectorSize, FATSectors: le.Uint32(boot[36:])}
	if le.Uint16(boot[14:]) != reservedSectors || boot[16] != numFATs || le.Uint32(boot[44:]) != rootCluster || spc == 0 {
		return nil, errors.New("fat: a layout this reader does not know")
	}
	g.Clusters = int((int64(g.Sectors) - g.dataSector()) / int64(spc))
	raw := make([]byte, int64(g.FATSectors)*sectorSize)
	if _, err := dev.ReadAt(raw, g.fatOffset(0)); err != nil {
		return nil, err
	}
	r := &Reader{dev: dev, g: g, fat: make([]uint32, g.Clusters+2)}
	for i := range r.fat {
		r.fat[i] = le.Uint32(raw[i*4:]) & 0x0FFFFFFF
	}
	r.root = &entryNode{dir: true, first: rootCluster, addr: 2}
	if err := r.load(r.root, "."); err != nil {
		return nil, err
	}
	return r, nil
}

// chain follows the FAT from first.
func (r *Reader) chain(first uint32) ([]uint32, error) {
	var out []uint32
	for c := first; c >= 2 && c < 0x0FFFFFF8; c = r.fat[c] {
		if int(c) >= len(r.fat) || len(out) > r.g.Clusters {
			return nil, fmt.Errorf("fat: the chain from cluster %d is broken", first)
		}
		if r.fat[c] == 0 {
			return nil, fmt.Errorf("fat: the chain from cluster %d runs into free cluster %d", first, c)
		}
		out = append(out, c)
	}
	return out, nil
}

// content reads size bytes of the chain from first; a negative size reads
// every cluster.
func (r *Reader) content(first uint32, size int64) ([]byte, error) {
	if first == 0 {
		if size > 0 {
			return nil, errors.New("fat: a non-empty file with no cluster")
		}
		return nil, nil
	}
	chain, err := r.chain(first)
	if err != nil {
		return nil, err
	}
	cs := int64(r.g.ClusterSize)
	if size < 0 {
		size = int64(len(chain)) * cs
	}
	if (size+cs-1)/cs != int64(len(chain)) {
		return nil, fmt.Errorf("fat: %d bytes in a chain of %d clusters", size, len(chain))
	}
	out := make([]byte, size)
	for i, c := range chain {
		end := min(int64(i+1)*cs, size)
		if _, err := r.dev.ReadAt(out[int64(i)*cs:end], r.g.clusterOffset(c)); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// load reads directory d, named p, and every directory under it.
func (r *Reader) load(d *entryNode, p string) error {
	data, err := r.content(d.first, -1)
	if err != nil {
		return fmt.Errorf("%s: %w", p, err)
	}
	chain, _ := r.chain(d.first)
	d.byKey = map[string]*entryNode{}
	var long []uint16
	var sum byte
	want := 0
	for i := 0; i < len(data)/entrySize; i++ {
		e := data[i*entrySize : (i+1)*entrySize]
		if e[0] == 0 {
			break
		}
		if e[0] == deleted {
			long, want = nil, 0
			continue
		}
		if e[11] == attrLFN {
			ord := int(e[0] &^ 0x40)
			if e[0]&0x40 != 0 {
				long, want, sum = make([]uint16, ord*lfnUnits), ord, e[13]
			}
			if ord != want || ord == 0 || e[13] != sum {
				long, want = nil, 0
				continue
			}
			for k, off := range lfnOffsets {
				long[(ord-1)*lfnUnits+k] = le16(e[off:])
			}
			want--
			continue
		}
		if e[11]&attrVolumeID != 0 {
			long, want = nil, 0
			continue
		}
		name := shortName(e[:11])
		if s := name.String(); s == "." || s == ".." {
			if d == r.root || i > 1 {
				return fmt.Errorf("%s: a %q entry out of place", p, s)
			}
			continue
		}
		n := &entryNode{dir: e[11]&attrDirectory != 0, ro: e[11]&attrReadOnly != 0, first: firstCluster(e), size: int64(le32(e[28:]))}
		n.name = readable(name, e[12])
		if long != nil && want == 0 && lfnChecksum(name) == sum {
			if end := slices.Index(long, 0); end >= 0 {
				long = long[:end]
			}
			n.name = string(utf16.Decode(long))
		}
		long, want = nil, 0
		off := int64(i * entrySize)
		n.addr = r.g.address(r.g.clusterOffset(chain[off/int64(r.g.ClusterSize)]) + off%int64(r.g.ClusterSize))
		n.times = target.Times{
			Btime: decode(le16(e[16:]), le16(e[14:]), e[13]),
			Mtime: decode(le16(e[24:]), le16(e[22:]), 0),
			Atime: decode(le16(e[18:]), 0, 0),
		}
		key := pathpolicy.FoldKey(n.name)
		if _, dup := d.byKey[key]; dup {
			return fmt.Errorf("%s: two entries named %q", p, n.name)
		}
		d.byKey[key] = n
		d.children = append(d.children, n)
	}
	slices.SortFunc(d.children, func(a, b *entryNode) int { return strings.Compare(a.name, b.name) })
	for _, c := range d.children {
		if c.dir {
			if err := r.load(c, path.Join(p, c.name)); err != nil {
				return err
			}
		}
	}
	return nil
}

// readable is a short name with the case its NTRes bits restore.
func readable(s shortName, bits byte) string {
	base, ext := strings.TrimRight(string(s[:8]), " "), strings.TrimRight(string(s[8:]), " ")
	if bits&lowerBase != 0 {
		base = strings.ToLower(base)
	}
	if bits&lowerExt != 0 {
		ext = strings.ToLower(ext)
	}
	if base != "" && base[0] == 0x05 {
		base = "\xE5" + base[1:]
	}
	if ext == "" {
		return base
	}
	return base + "." + ext
}

func le16(b []byte) uint16 { return binary.LittleEndian.Uint16(b) }
func le32(b []byte) uint32 { return binary.LittleEndian.Uint32(b) }

func perr(op, name string, err error) error { return &fs.PathError{Op: op, Path: name, Err: err} }

// lookup finds name, ignoring case as FAT does.
func (r *Reader) lookup(name string) (*entryNode, error) {
	n := r.root
	name = path.Clean(name)
	if name == "." {
		return n, nil
	}
	for c := range strings.SplitSeq(name, "/") {
		if !n.dir {
			return nil, fs.ErrNotExist
		}
		next, ok := n.byKey[pathpolicy.FoldKey(c)]
		if !ok {
			return nil, fs.ErrNotExist
		}
		n = next
	}
	return n, nil
}

// dirEntry is a directory entry and its file information at once.
type dirEntry struct{ n *entryNode }

func (e dirEntry) Name() string               { return e.n.name }
func (e dirEntry) IsDir() bool                { return e.n.dir }
func (e dirEntry) Type() fs.FileMode          { return e.Mode().Type() }
func (e dirEntry) Info() (fs.FileInfo, error) { return e, nil }
func (e dirEntry) Size() int64                { return e.n.size }
func (e dirEntry) ModTime() time.Time         { return e.n.times.Mtime }
func (e dirEntry) Sys() any                   { return nil }

// Mode is what Go reports on Windows for the same attributes.
func (e dirEntry) Mode() fs.FileMode {
	switch {
	case e.n.dir:
		return fs.ModeDir | 0o777
	case e.n.ro:
		return 0o444
	}
	return 0o666
}

// WalkDir walks the volume in lexical order, the root first.
func (r *Reader) WalkDir(fn fs.WalkDirFunc) error { return volume.Walk(r, fn) }

// ReadDirQuiet lists a directory, sorted by name.
func (r *Reader) ReadDirQuiet(name string) ([]fs.DirEntry, error) {
	n, err := r.lookup(name)
	if err == nil && !n.dir {
		err = errors.New("not a directory")
	}
	if err != nil {
		return nil, perr("readdir", name, err)
	}
	out := make([]fs.DirEntry, len(n.children))
	for i, c := range n.children {
		out[i] = dirEntry{c}
	}
	return out, nil
}

// Meta reads an object's times and its entry's address.
func (r *Reader) Meta(name string) (target.Meta, error) {
	n, err := r.lookup(name)
	if err != nil {
		return target.Meta{}, perr("read metadata", name, err)
	}
	return target.Meta{Times: n.times, ID: strconv.FormatInt(n.addr, 10), Links: 1}, nil
}

// Times reads an object's times.
func (r *Reader) Times(name string) (target.Times, error) {
	m, err := r.Meta(name)
	return m.Times, err
}

// Granularity is how finely FAT keeps times.
func (r *Reader) Granularity() target.Granularity {
	return target.Granularity{Atime: 24 * time.Hour, Mtime: 2 * time.Second, Btime: 10 * time.Millisecond}
}

// ReadFile reads a file whole.
func (r *Reader) ReadFile(name string) ([]byte, error) {
	n, err := r.lookup(name)
	if err == nil && n.dir {
		err = errors.New("not a regular file")
	}
	if err != nil {
		return nil, perr("read", name, err)
	}
	data, err := r.content(n.first, n.size)
	if err != nil {
		return nil, perr("read", name, err)
	}
	return data, nil
}

// OpenQuiet opens a file for reading.
func (r *Reader) OpenQuiet(name string) (io.ReadCloser, error) {
	data, err := r.ReadFile(name)
	if err != nil {
		return nil, err
	}
	return io.NopCloser(bytes.NewReader(data)), nil
}

// Streams lists an object's named streams: FAT has none.
func (r *Reader) Streams(name string) ([]target.Stream, error) {
	if _, err := r.lookup(name); err != nil {
		return nil, perr("list streams", name, err)
	}
	return nil, nil
}

// ReadStream reads a named stream: FAT has none.
func (r *Reader) ReadStream(name, stream string) ([]byte, error) {
	return nil, perr("read stream", name+":"+stream, fs.ErrNotExist)
}

// OpenStreamQuiet opens a named stream: FAT has none.
func (r *Reader) OpenStreamQuiet(name, stream string) (io.ReadCloser, error) {
	return nil, perr("read stream", name+":"+stream, fs.ErrNotExist)
}

var _ target.Reader = (*Reader)(nil)
