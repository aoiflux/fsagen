package ext4

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

	"github.com/aoiflux/fsagen/target"
	"github.com/aoiflux/fsagen/volume"
)

// Reader reads an ext4 volume from disk, knowing nothing of how it was
// written: the superblock and group descriptors say where everything is,
// and every name, time and byte is read from the inodes, their extent
// trees and the directories. On a volume with metadata_csum, every
// checksum it reads past is checked. lost+found, the file system's own, is
// left out of the tree.
type Reader struct {
	dev    *volume.Device
	bs     int64
	blocks uint64
	ipg    uint32
	inodes uint32
	tables []uint64
	// csum says the volume keeps checksums, which start from seed.
	csum bool
	seed uint32
	root *entryNode
}

// entryNode is one name and the inode it names.
type entryNode struct {
	name     string
	ino, gen uint32
	mode     uint16
	uid, gid uint32
	links    uint16
	size     int64
	times    target.Times
	blocks   []uint64
	target   string
	children []*entryNode
	byName   map[string]*entryNode
}

func (n *entryNode) isDir() bool { return n.mode&modeType == modeDir }

// Open reads the volume on dev.
func Open(dev *volume.Device) (*Reader, error) {
	sb := make([]byte, superSize)
	if _, err := dev.ReadAt(sb, superOffset); err != nil {
		return nil, err
	}
	le := binary.LittleEndian
	if le.Uint16(sb[0x38:]) != magic {
		return nil, errors.New("ext4: no superblock")
	}
	if le.Uint32(sb[0x4C:]) != 1 || le.Uint16(sb[0x58:]) < 128 {
		return nil, errors.New("ext4: a revision or inode size this reader does not know")
	}
	if in := le.Uint32(sb[0x60:]); in&^(incompatFiletype|incompatExtents|incompatFlexBG) != 0 {
		return nil, fmt.Errorf("ext4: incompatible features %#x this reader does not know", in)
	}
	r := &Reader{dev: dev, bs: 1024 << le.Uint32(sb[0x18:]), blocks: uint64(le.Uint32(sb[0x04:])), ipg: le.Uint32(sb[0x28:]), inodes: le.Uint32(sb[0x00:])}
	if r.bs > 65536 || r.ipg == 0 || le.Uint16(sb[0x58:]) != inodeSize || le.Uint16(sb[0xFE:]) > descSize {
		return nil, errors.New("ext4: a geometry this reader does not know")
	}
	if r.csum = le.Uint32(sb[0x64:])&roMetadataCsum != 0; r.csum {
		if sb[0x175] != csumCRC32c || le.Uint32(sb[0x3FC:]) != crc32c(^uint32(0), sb[:0x3FC]) {
			return nil, errors.New("ext4: the superblock's checksum is wrong")
		}
		r.seed = crc32c(^uint32(0), sb[0x68:0x78])
	}
	first, bpg := uint64(le.Uint32(sb[0x14:])), uint64(le.Uint32(sb[0x20:]))
	groups := (r.blocks - first + bpg - 1) / bpg
	gdt := make([]byte, groups*descSize)
	if _, err := dev.ReadAt(gdt, int64(first+1)*r.bs); err != nil {
		return nil, err
	}
	for i := range groups {
		d := gdt[i*descSize : (i+1)*descSize]
		if r.csum {
			var n [4]byte
			le.PutUint32(n[:], uint32(i))
			check := bytes.Clone(d)
			le.PutUint16(check[30:], 0)
			if le.Uint16(d[30:]) != uint16(crc32c(crc32c(r.seed, n[:]), check)) {
				return nil, fmt.Errorf("ext4: group %d's descriptor checksum is wrong", i)
			}
		}
		r.tables = append(r.tables, uint64(le.Uint32(d[8:])))
	}
	root, err := r.node(rootIno, "")
	if err != nil {
		return nil, err
	}
	r.root = root
	if err := r.load(root, "."); err != nil {
		return nil, err
	}
	return r, nil
}

// node reads inode ino, named name.
func (r *Reader) node(ino uint32, name string) (*entryNode, error) {
	if ino == 0 || ino > r.inodes {
		return nil, fmt.Errorf("ext4: inode %d is out of range", ino)
	}
	b := make([]byte, inodeSize)
	group, idx := (ino-1)/r.ipg, (ino-1)%r.ipg
	if _, err := r.dev.ReadAt(b, int64(r.tables[group])*r.bs+int64(idx)*inodeSize); err != nil {
		return nil, err
	}
	le := binary.LittleEndian
	if r.csum {
		check := bytes.Clone(b)
		setInodeCsum(check, r.seed, ino)
		if !bytes.Equal(check, b) {
			return nil, fmt.Errorf("ext4: inode %d's checksum is wrong", ino)
		}
	}
	n := &entryNode{
		name: name, ino: ino, gen: le.Uint32(b[100:]), mode: le.Uint16(b[0:]), links: le.Uint16(b[26:]),
		uid:  uint32(le.Uint16(b[2:])) | uint32(le.Uint16(b[120:]))<<16,
		gid:  uint32(le.Uint16(b[24:])) | uint32(le.Uint16(b[122:]))<<16,
		size: int64(le.Uint32(b[4:])) | int64(le.Uint32(b[108:]))<<32,
	}
	if n.links == 0 {
		return nil, fmt.Errorf("ext4: inode %d is named but has no links", ino)
	}
	extra := le.Uint16(b[128:])
	at := func(base, ext int) time.Time {
		x := uint32(0)
		if ext+4 <= 128+int(extra) {
			x = le.Uint32(b[ext:])
		}
		return decodeTime(le.Uint32(b[base:]), x)
	}
	n.times = target.Times{Atime: at(8, 140), Ctime: at(12, 132), Mtime: at(16, 136)}
	if 148+4 <= 128+int(extra) {
		n.times.Btime = at(144, 148)
	}
	flags := le.Uint32(b[32:])
	if n.mode&modeType == modeSymlink && flags&flagExtents == 0 {
		if n.size >= 60 {
			return nil, fmt.Errorf("ext4: inode %d is a %d-byte symlink kept in the inode", ino, n.size)
		}
		n.target = string(b[40 : 40+n.size])
		return n, nil
	}
	if flags&flagExtents == 0 {
		return nil, fmt.Errorf("ext4: inode %d maps its blocks without extents", ino)
	}
	blocks, err := r.walk(b[40:100], -1, inodeSeed(r.seed, ino, n.gen))
	if err != nil {
		return nil, fmt.Errorf("ext4: inode %d: %w", ino, err)
	}
	if want := (n.size + r.bs - 1) / r.bs; int64(len(blocks)) < want {
		return nil, fmt.Errorf("ext4: inode %d holds %d bytes in %d blocks", ino, n.size, len(blocks))
	}
	n.blocks = blocks
	if n.mode&modeType == modeSymlink {
		data, err := r.content(n)
		if err != nil {
			return nil, err
		}
		n.target = string(data)
	}
	return n, nil
}

// walk reads an extent tree node and returns the blocks it maps, in
// logical order; depth is the depth its parent says it has (-1 for the
// inode's own root), and seed the inode's checksum seed, which a node in a
// block of its own is checked against.
func (r *Reader) walk(b []byte, depth int, seed uint32) ([]uint64, error) {
	le := binary.LittleEndian
	if le.Uint16(b[0:]) != extentMagic {
		return nil, errors.New("an extent node without its magic number")
	}
	entries, d := int(le.Uint16(b[2:])), int(le.Uint16(b[6:]))
	if 12+12*entries > len(b) || entries > int(le.Uint16(b[4:])) || depth >= 0 && d != depth || d > 5 {
		return nil, errors.New("a malformed extent node")
	}
	var out []uint64
	for i := range entries {
		e := b[12+12*i:]
		logical := uint64(le.Uint32(e[0:]))
		if d == 0 {
			n := uint64(le.Uint16(e[4:]))
			if n > maxExtent {
				return nil, errors.New("an unwritten extent")
			}
			start := uint64(le.Uint32(e[8:])) | uint64(le.Uint16(e[6:]))<<32
			if logical != uint64(len(out)) {
				return nil, fmt.Errorf("a hole at block %d", len(out))
			}
			if start+n > r.blocks {
				return nil, errors.New("an extent past the end of the volume")
			}
			for k := range n {
				out = append(out, start+k)
			}
			continue
		}
		leaf := uint64(le.Uint32(e[4:])) | uint64(le.Uint16(e[8:]))<<32
		if leaf >= r.blocks {
			return nil, errors.New("an extent index past the end of the volume")
		}
		child := make([]byte, r.bs)
		if _, err := r.dev.ReadAt(child, int64(leaf)*r.bs); err != nil {
			return nil, err
		}
		if end := 12 + 12*int(le.Uint16(child[4:])); r.csum && (end+4 > len(child) || le.Uint32(child[end:]) != crc32c(seed, child[:end])) {
			return nil, fmt.Errorf("extent block %d's checksum is wrong", leaf)
		}
		sub, err := r.walk(child, d-1, seed)
		if err != nil {
			return nil, err
		}
		if logical != uint64(len(out)) {
			return nil, fmt.Errorf("a hole at block %d", len(out))
		}
		out = append(out, sub...)
	}
	return out, nil
}

// content reads n's size bytes.
func (r *Reader) content(n *entryNode) ([]byte, error) {
	out := make([]byte, n.size)
	for i, b := range n.blocks {
		lo := int64(i) * r.bs
		if lo >= n.size {
			break
		}
		if _, err := r.dev.ReadAt(out[lo:min(lo+r.bs, n.size)], int64(b)*r.bs); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// load reads directory d, named p, and every directory under it.
func (r *Reader) load(d *entryNode, p string) error {
	data, err := r.content(d)
	if err != nil {
		return fmt.Errorf("%s: %w", p, err)
	}
	le := binary.LittleEndian
	d.byName = map[string]*entryNode{}
	seed := inodeSeed(r.seed, d.ino, d.gen)
	for blk := int64(0); blk < int64(len(data)); blk += r.bs {
		b := data[blk:min(blk+r.bs, int64(len(data)))]
		if r.csum {
			t := b[len(b)-tailSize:]
			if le.Uint32(t[0:]) != 0 || le.Uint16(t[4:]) != tailSize || t[7] != tailFileType || le.Uint32(t[8:]) != crc32c(seed, b[:len(b)-tailSize]) {
				return fmt.Errorf("%s: block %d's checksum is wrong", p, blk/r.bs)
			}
			b = b[:len(b)-tailSize]
		}
		for off := 0; off < len(b); {
			ino, rl, nl := le.Uint32(b[off:]), int(le.Uint16(b[off+4:])), int(b[off+6])
			if rl < 8 || rl%4 != 0 || off+rl > len(b) || ino != 0 && 8+nl > rl {
				return fmt.Errorf("%s: a malformed entry at byte %d", p, blk+int64(off))
			}
			name := string(b[off+8 : off+8+nl])
			off += rl
			if ino == 0 || name == "." || name == ".." {
				continue
			}
			if d == r.root && name == "lost+found" && ino == lostFound {
				continue
			}
			if _, dup := d.byName[name]; dup {
				return fmt.Errorf("%s: two entries named %q", p, name)
			}
			n, err := r.node(ino, name)
			if err != nil {
				return fmt.Errorf("%s: %w", path.Join(p, name), err)
			}
			d.byName[name] = n
			d.children = append(d.children, n)
		}
	}
	slices.SortFunc(d.children, func(a, b *entryNode) int { return strings.Compare(a.name, b.name) })
	for _, c := range d.children {
		if c.isDir() {
			if err := r.load(c, path.Join(p, c.name)); err != nil {
				return err
			}
		}
	}
	return nil
}

func perr(op, name string, err error) error { return &fs.PathError{Op: op, Path: name, Err: err} }

// lookup finds name, without following any link.
func (r *Reader) lookup(name string) (*entryNode, error) {
	n := r.root
	name = path.Clean(name)
	if name == "." {
		return n, nil
	}
	for c := range strings.SplitSeq(name, "/") {
		if !n.isDir() {
			return nil, fs.ErrNotExist
		}
		next, ok := n.byName[c]
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
func (e dirEntry) IsDir() bool                { return e.n.isDir() }
func (e dirEntry) Type() fs.FileMode          { return e.Mode().Type() }
func (e dirEntry) Info() (fs.FileInfo, error) { return e, nil }
func (e dirEntry) Size() int64                { return e.n.size }
func (e dirEntry) ModTime() time.Time         { return e.n.times.Mtime }
func (e dirEntry) Sys() any                   { return nil }

// Mode is the inode's type and permission bits.
func (e dirEntry) Mode() fs.FileMode {
	perm := fs.FileMode(e.n.mode & 0o777)
	switch e.n.mode & modeType {
	case modeDir:
		return fs.ModeDir | perm
	case modeSymlink:
		return fs.ModeSymlink | perm
	}
	return perm
}

// WalkDir walks the volume in lexical order, the root first.
func (r *Reader) WalkDir(fn fs.WalkDirFunc) error { return volume.Walk(r, fn) }

// ReadDirQuiet lists a directory, sorted by name.
func (r *Reader) ReadDirQuiet(name string) ([]fs.DirEntry, error) {
	n, err := r.lookup(name)
	if err == nil && !n.isDir() {
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

// Meta reads an object's times, inode number, owner and links.
func (r *Reader) Meta(name string) (target.Meta, error) {
	n, err := r.lookup(name)
	if err != nil {
		return target.Meta{}, perr("read metadata", name, err)
	}
	m := target.Meta{Times: n.times, ID: strconv.FormatUint(uint64(n.ino), 10), UID: int(n.uid), GID: int(n.gid), Links: int(n.links)}
	if n.mode&modeType == modeSymlink {
		m.Link, m.Target = target.LinkSymlink, n.target
	}
	return m, nil
}

// Times reads an object's times.
func (r *Reader) Times(name string) (target.Times, error) {
	m, err := r.Meta(name)
	return m.Times, err
}

// Granularity is how finely ext4 keeps times.
func (r *Reader) Granularity() target.Granularity { return Granularity() }

// ReadFile reads a file whole.
func (r *Reader) ReadFile(name string) ([]byte, error) {
	n, err := r.lookup(name)
	if err == nil && n.mode&modeType != modeFile {
		err = errors.New("not a regular file")
	}
	if err != nil {
		return nil, perr("read", name, err)
	}
	data, err := r.content(n)
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

// Streams lists an object's named streams: ext4 has none.
func (r *Reader) Streams(name string) ([]target.Stream, error) {
	if _, err := r.lookup(name); err != nil {
		return nil, perr("list streams", name, err)
	}
	return nil, nil
}

// ReadStream reads a named stream: ext4 has none.
func (r *Reader) ReadStream(name, stream string) ([]byte, error) {
	return nil, perr("read stream", name+":"+stream, fs.ErrNotExist)
}

// OpenStreamQuiet opens a named stream: ext4 has none.
func (r *Reader) OpenStreamQuiet(name, stream string) (io.ReadCloser, error) {
	return nil, perr("read stream", name+":"+stream, fs.ErrNotExist)
}

var _ target.Reader = (*Reader)(nil)
