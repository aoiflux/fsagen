package ntfs

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"path"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/aoiflux/fsagen/internal/reparse"
	"github.com/aoiflux/fsagen/target"
	"github.com/aoiflux/fsagen/volume"
)

// Reader reads an NTFS volume from disk, knowing nothing of how it was
// written: the boot sector says where $MFT is, $MFT's own record where
// every other record is, and every name comes from the directories'
// $I30 indexes, walked as B-trees, every time from $STANDARD_INFORMATION
// and every byte from $DATA. Every record and index block's update
// sequence array is checked. The system files at the root are left out of
// the tree.
type Reader struct {
	dev     *volume.Device
	cs      int64
	mftRuns []run
	root    *rnode
	// reparse are the reparse points the tree holds, by file reference,
	// with their tags.
	reparse map[uint64]uint32
}

// rnode is one name and the record it names.
type rnode struct {
	name  string
	num   uint32
	dir   bool
	attrs uint32
	links int
	times target.Times
	// fn are the times of the name's $FILE_NAME in the record.
	fn    target.Times
	size  int64
	value []byte
	runs  []run
	// streams are the named $DATA attributes, by name.
	streams map[string]*rattr
	// link is target.LinkSymlink or target.LinkJunction for a reparse
	// point of either kind, tag its reparse tag, and target what it points
	// at.
	link, target string
	tag          uint32
	children     []*rnode
	byName       map[string]*rnode
}

// rattr is an attribute as the reader parses it.
type rattr struct {
	typ      uint32
	name     string
	resident bool
	value    []byte
	runs     []run
	size     int64
}

// Open reads the volume on dev.
func Open(dev *volume.Device) (*Reader, error) {
	b := make([]byte, sectorSize)
	if _, err := dev.ReadAt(b, 0); err != nil {
		return nil, err
	}
	le := binary.LittleEndian
	if string(b[3:11]) != "NTFS    " || le.Uint16(b[0x0B:]) != sectorSize || le.Uint16(b[0x1FE:]) != 0xAA55 {
		return nil, errors.New("ntfs: no NTFS boot sector")
	}
	spc := int64(b[0x0D])
	if spc > 0x80 {
		spc = 1 << (256 - spc)
	}
	r := &Reader{dev: dev, cs: spc * sectorSize, reparse: map[uint64]uint32{}}
	if rs := int8(b[0x40]); rs >= 0 && int64(rs)*r.cs != recordSize || rs < 0 && 1<<-rs != recordSize {
		return nil, errors.New("ntfs: an MFT record size this reader does not know")
	}
	mft := int64(le.Uint64(b[0x30:]))
	rec := make([]byte, recordSize)
	if _, err := dev.ReadAt(rec, mft*r.cs); err != nil {
		return nil, err
	}
	_, _, attrs, err := parseRecord(rec, recMFT)
	if err != nil {
		return nil, err
	}
	data := findAttr(attrs, atData, "")
	if data == nil || data.resident {
		return nil, errors.New("ntfs: $MFT has no runlist")
	}
	r.mftRuns = data.runs
	root, err := r.node(recRoot<<48|recRoot, ".", recRoot)
	if err != nil {
		return nil, err
	}
	r.root = root
	if err := r.load(root, "."); err != nil {
		return nil, err
	}
	if err := r.checkReparse(); err != nil {
		return nil, err
	}
	return r, nil
}

// checkReparse checks that $Extend\$Reparse's $R index files exactly the
// reparse points the tree holds, each under its tag and file reference,
// in order.
func (r *Reader) checkReparse() error {
	le := binary.LittleEndian
	filed := map[uint64]uint32{}
	var last []byte
	err := r.indexWalk(recReparse, "$R", func(e []byte) error {
		n, kl := int(le.Uint16(e[8:])), int(le.Uint16(e[10:]))
		if kl != 12 || n < 16+kl {
			return errors.New("a $R entry that is not a tag and a file reference")
		}
		key := e[16 : 16+kl]
		if last != nil && byULongs(entry{dataOffset: 28, body: last}, entry{dataOffset: 28, body: key}) >= 0 {
			return errors.New("$R is out of order")
		}
		last = key
		filed[le.Uint64(key[4:])] = le.Uint32(key)
		return nil
	})
	if err != nil {
		return fmt.Errorf("ntfs: $Reparse: %w", err)
	}
	for ref, tag := range r.reparse {
		if got, ok := filed[ref]; !ok || got != tag {
			return fmt.Errorf("ntfs: $Reparse does not file record %d's reparse point", refNum(ref))
		}
	}
	if len(filed) != len(r.reparse) {
		return fmt.Errorf("ntfs: $Reparse files %d reparse points, and the tree holds %d", len(filed), len(r.reparse))
	}
	return nil
}

// readRuns reads n bytes from byte pos of the clusters runs map; a hole
// reads as zeros.
func (r *Reader) readRuns(runs []run, pos, n int64) ([]byte, error) {
	out := make([]byte, n)
	for done := int64(0); done < n; {
		vcn, within := (pos+done)/r.cs, (pos+done)%r.cs
		lcn := int64(-2)
		for _, x := range runs {
			if vcn < x.length {
				lcn = x.lcn
				if lcn >= 0 {
					lcn += vcn
				}
				break
			}
			vcn -= x.length
		}
		k := min(r.cs-within, n-done)
		switch lcn {
		case -2:
			return nil, fmt.Errorf("byte %d is past what the runlist maps", pos+done)
		case -1:
		default:
			if _, err := r.dev.ReadAt(out[done:done+k], lcn*r.cs+within); err != nil {
				return nil, err
			}
		}
		done += k
	}
	return out, nil
}

// parseRecord checks and parses a record read from disk: its flags,
// sequence number, link count and attributes.
func parseRecord(b []byte, num uint32) (uint16, uint16, []rattr, error) {
	le := binary.LittleEndian
	if string(b[:4]) != "FILE" {
		return 0, 0, nil, fmt.Errorf("ntfs: record %d is not a FILE record", num)
	}
	if err := unprotect(b); err != nil {
		return 0, 0, nil, fmt.Errorf("ntfs: record %d: %w", num, err)
	}
	if le.Uint32(b[28:]) != recordSize || le.Uint32(b[24:]) > recordSize {
		return 0, 0, nil, fmt.Errorf("ntfs: record %d is malformed", num)
	}
	var attrs []rattr
	for p := int(le.Uint16(b[20:])); ; {
		if p+8 > recordSize {
			return 0, 0, nil, fmt.Errorf("ntfs: record %d has no end marker", num)
		}
		typ := le.Uint32(b[p:])
		if typ == atEnd {
			break
		}
		n := int(le.Uint32(b[p+4:]))
		if n < 24 || p+n > recordSize {
			return 0, 0, nil, fmt.Errorf("ntfs: record %d has a malformed attribute", num)
		}
		a := b[p : p+n]
		ra := rattr{typ: typ, resident: a[8] == 0}
		if nl, no := int(a[9]), int(le.Uint16(a[10:])); nl > 0 {
			if no+2*nl > n {
				return 0, 0, nil, fmt.Errorf("ntfs: record %d has a malformed attribute", num)
			}
			ra.name = fromUTF16le(a[no : no+2*nl])
		}
		if ra.resident {
			vl, vo := int(le.Uint32(a[16:])), int(le.Uint16(a[20:]))
			if vo+vl > n {
				return 0, 0, nil, fmt.Errorf("ntfs: record %d has a malformed attribute", num)
			}
			ra.value, ra.size = slices.Clone(a[vo:vo+vl]), int64(vl)
		} else {
			if n < 64 || le.Uint64(a[16:]) != 0 {
				return 0, 0, nil, fmt.Errorf("ntfs: record %d has an attribute in pieces, which this reader does not follow", num)
			}
			runs, err := decodeRuns(a[le.Uint16(a[32:]):])
			if err != nil {
				return 0, 0, nil, fmt.Errorf("ntfs: record %d: %w", num, err)
			}
			ra.runs, ra.size = runs, int64(le.Uint64(a[48:]))
		}
		attrs = append(attrs, ra)
		p += n
	}
	return le.Uint16(b[22:]), le.Uint16(b[16:]), attrs, nil
}

func findAttr(attrs []rattr, typ uint32, name string) *rattr {
	for i := range attrs {
		if attrs[i].typ == typ && attrs[i].name == name {
			return &attrs[i]
		}
	}
	return nil
}

// record reads and parses record num.
func (r *Reader) record(num uint32) (uint16, uint16, []byte, []rattr, error) {
	b, err := r.readRuns(r.mftRuns, int64(num)*recordSize, recordSize)
	if err != nil {
		return 0, 0, nil, nil, fmt.Errorf("ntfs: record %d: %w", num, err)
	}
	flags, seq, attrs, err := parseRecord(b, num)
	return flags, seq, b, attrs, err
}

// node reads the record ref names, named name in directory record parent.
func (r *Reader) node(ref uint64, name string, parent uint32) (*rnode, error) {
	num := refNum(ref)
	flags, seq, b, attrs, err := r.record(num)
	if err != nil {
		return nil, err
	}
	if flags&recInUse == 0 || seq != uint16(ref>>48) {
		return nil, fmt.Errorf("ntfs: %q names record %d, sequence %d, which is not in use", name, num, ref>>48)
	}
	n := &rnode{name: name, num: num, dir: flags&recDir != 0, links: int(binary.LittleEndian.Uint16(b[18:])), streams: map[string]*rattr{}}
	si := findAttr(attrs, atStdInfo, "")
	if si == nil || len(si.value) < 48 {
		return nil, fmt.Errorf("ntfs: record %d has no $STANDARD_INFORMATION", num)
	}
	n.times = toTimes(readTimes(si.value))
	n.attrs = binary.LittleEndian.Uint32(si.value[32:])
	found := false
	for i := range attrs {
		a := &attrs[i]
		switch {
		case a.typ == atFileName && !found:
			fn, err := readFileName(a.value)
			if err != nil {
				return nil, fmt.Errorf("ntfs: record %d: %w", num, err)
			}
			if refNum(fn.parent) == parent && collate(fn.name, name) == 0 {
				n.fn, found = toTimes(fn.t), true
			}
		case a.typ == atData && a.name != "":
			if !a.resident && ceil(a.size, r.cs) > clusters(a.runs) {
				return nil, fmt.Errorf("ntfs: record %d holds %d bytes of stream %q in %d clusters", num, a.size, a.name, clusters(a.runs))
			}
			n.streams[a.name] = a
		}
	}
	if !found {
		return nil, fmt.Errorf("ntfs: record %d has no $FILE_NAME for %q", num, name)
	}
	if rp := findAttr(attrs, atReparse, ""); rp != nil {
		if n.attrs&faReparse == 0 {
			return nil, fmt.Errorf("ntfs: record %d has a reparse point, and its flags say it has none", num)
		}
		if err := n.readLink(rp.value); err != nil {
			return nil, fmt.Errorf("ntfs: record %d: %w", num, err)
		}
	}
	if n.dir {
		return n, nil
	}
	d := findAttr(attrs, atData, "")
	if d == nil {
		return nil, fmt.Errorf("ntfs: file record %d has no $DATA", num)
	}
	n.size, n.value, n.runs = d.size, d.value, d.runs
	if !d.resident && ceil(n.size, r.cs) > clusters(d.runs) {
		return nil, fmt.Errorf("ntfs: record %d holds %d bytes in %d clusters", num, n.size, clusters(d.runs))
	}
	return n, nil
}

func toTimes(t times) target.Times {
	return target.Times{Btime: t.created, Mtime: t.modified, Ctime: t.changed, Atime: t.accessed}
}

// readLink reads a symlink's or junction's reparse data: a symlink's
// target as stored, with '/' between names, and a junction's as a path on
// the volume when it is on junctionDrive.
func (n *rnode) readLink(data []byte) error {
	tag, t, err := reparse.PrintName(data)
	if err != nil {
		return err
	}
	n.tag = tag
	switch tag {
	case reparse.TagSymlink:
		n.link, n.target = target.LinkSymlink, strings.ReplaceAll(t, `\`, "/")
	case reparse.TagMountPoint:
		n.link, n.target = target.LinkJunction, t
		if rel, ok := strings.CutPrefix(t, junctionDrive+`\`); ok {
			n.target = strings.ReplaceAll(rel, `\`, "/")
			if n.target == "" {
				n.target = "."
			}
		}
	}
	return nil
}

// content reads n's bytes.
func (r *Reader) content(n *rnode) ([]byte, error) {
	if n.runs == nil {
		return slices.Clone(n.value), nil
	}
	return r.readRuns(n.runs, 0, n.size)
}

// indexEntries lists directory d's entries, in index order: its
// $INDEX_ROOT's, each preceded by those of the index block it points to.
// Each block must be the one its VCN names and marked in use in $BITMAP,
// and each entry must point to a block exactly when its node says it has
// children.
func (r *Reader) indexEntries(d *rnode) ([]fileEntryRef, error) {
	le := binary.LittleEndian
	var out []fileEntryRef
	err := r.indexWalk(d.num, "$I30", func(e []byte) error {
		fn, err := readFileName(e[16 : 16+int(le.Uint16(e[10:]))])
		if err != nil {
			return err
		}
		out = append(out, fileEntryRef{le.Uint64(e[0:]), fn})
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("ntfs: directory record %d: %w", d.num, err)
	}
	return out, nil
}

// indexWalk calls visit with each entry of record num's index name, in
// index order, the end entries left out (see indexEntries).
func (r *Reader) indexWalk(num uint32, name string, visit func(e []byte) error) error {
	_, _, _, attrs, err := r.record(num)
	if err != nil {
		return err
	}
	ir := findAttr(attrs, atIndexRoot, name)
	if ir == nil || len(ir.value) < 32 {
		return fmt.Errorf("no %s index", name)
	}
	ia, bm := findAttr(attrs, atIndexAlloc, name), findAttr(attrs, atBitmap, name)
	le := binary.LittleEndian
	h := ir.value[16:]
	var walk func(h []byte, depth int) error
	walk = func(h []byte, depth int) error {
		if depth > 32 {
			return errors.New("an index deeper than any NTFS makes")
		}
		eo, il := int(le.Uint32(h[0:])), int(le.Uint32(h[4:]))
		if eo < 16 || il > len(h) || eo > il {
			return errors.New("a malformed index node")
		}
		node := h[12]&ihLarge != 0
		for p := eo; ; {
			if p+16 > il {
				return errors.New("an index node with no end entry")
			}
			e := h[p:]
			n, kl, flags := int(le.Uint16(e[8:])), int(le.Uint16(e[10:])), le.Uint16(e[12:])
			if n < 16 || p+n > il || 16+kl > n {
				return errors.New("a malformed index entry")
			}
			if (flags&ieNode != 0) != node {
				return errors.New("an index entry out of step with its node")
			}
			if node {
				if ia == nil || bm == nil {
					return errors.New("an index entry points at an index block, but there are none")
				}
				vcn := int64(le.Uint64(e[n-8:]))
				if bit := r.blockPos(vcn) / indexSize; vcn < 0 || bit/8 >= int64(len(bm.value)) || bm.value[bit/8]&(1<<(bit%8)) == 0 {
					return fmt.Errorf("index block %d is not in use", vcn)
				}
				blk, err := r.indexBlock(ia.runs, vcn)
				if err != nil {
					return err
				}
				if err := walk(blk[0x18:], depth+1); err != nil {
					return err
				}
			}
			if flags&ieEnd != 0 {
				return nil
			}
			if err := visit(e[:n]); err != nil {
				return err
			}
			p += n
		}
	}
	return walk(h, 0)
}

// blockPos is where index block vcn starts in $INDEX_ALLOCATION.
func (r *Reader) blockPos(vcn int64) int64 {
	if r.cs > indexSize {
		return vcn * sectorSize
	}
	return vcn * r.cs
}

// indexBlock reads index block vcn of the $INDEX_ALLOCATION runs map, and
// checks it is the block its VCN names.
func (r *Reader) indexBlock(runs []run, vcn int64) ([]byte, error) {
	blk, err := r.readRuns(runs, r.blockPos(vcn), indexSize)
	if err != nil {
		return nil, err
	}
	if string(blk[:4]) != "INDX" {
		return nil, fmt.Errorf("index block %d is not an INDX block", vcn)
	}
	if err := unprotect(blk); err != nil {
		return nil, fmt.Errorf("index block %d: %w", vcn, err)
	}
	if got := int64(binary.LittleEndian.Uint64(blk[16:])); got != vcn {
		return nil, fmt.Errorf("index block %d says it is block %d", vcn, got)
	}
	return blk, nil
}

// fileEntryRef is an entry of a directory's index.
type fileEntryRef struct {
	ref uint64
	fn  fileName
}

// load reads directory d, named p, and every directory under it.
func (r *Reader) load(d *rnode, p string) error {
	es, err := r.indexEntries(d)
	if err != nil {
		return err
	}
	d.byName = map[string]*rnode{}
	for i, e := range es {
		if i > 0 && collate(es[i-1].fn.name, e.fn.name) >= 0 {
			return fmt.Errorf("ntfs: %s: its index is out of order at %q", p, e.fn.name)
		}
		num := refNum(e.ref)
		if e.fn.namespace == 2 || d == r.root && num < 16 {
			continue
		}
		if refNum(e.fn.parent) != d.num {
			return fmt.Errorf("ntfs: %s: %q's $FILE_NAME names record %d as its parent", p, e.fn.name, refNum(e.fn.parent))
		}
		n, err := r.node(e.ref, e.fn.name, d.num)
		if err != nil {
			return fmt.Errorf("%s: %w", path.Join(p, e.fn.name), err)
		}
		d.byName[n.name] = n
		d.children = append(d.children, n)
		if n.link != "" {
			r.reparse[e.ref] = n.tag
		}
	}
	slices.SortFunc(d.children, func(a, b *rnode) int { return strings.Compare(a.name, b.name) })
	for _, c := range d.children {
		if c.dir && c.link == "" {
			if err := r.load(c, path.Join(p, c.name)); err != nil {
				return err
			}
		}
	}
	return nil
}

func perr(op, name string, err error) error { return &fs.PathError{Op: op, Path: name, Err: err} }

// lookup finds name, as written or differing only in case.
func (r *Reader) lookup(name string) (*rnode, error) {
	n := r.root
	name = path.Clean(name)
	if name == "." {
		return n, nil
	}
	for c := range strings.SplitSeq(name, "/") {
		if !n.dir || n.link != "" {
			return nil, fs.ErrNotExist
		}
		next, ok := n.byName[c]
		if !ok {
			for k, v := range n.byName {
				if collate(k, c) == 0 {
					next, ok = v, true
				}
			}
		}
		if !ok {
			return nil, fs.ErrNotExist
		}
		n = next
	}
	return n, nil
}

// dirEntry is a directory entry and its file information at once.
type dirEntry struct{ n *rnode }

func (e dirEntry) Name() string               { return e.n.name }
func (e dirEntry) IsDir() bool                { return e.n.dir && e.n.link == "" }
func (e dirEntry) Type() fs.FileMode          { return e.Mode().Type() }
func (e dirEntry) Info() (fs.FileInfo, error) { return e, nil }
func (e dirEntry) Size() int64                { return e.n.size }
func (e dirEntry) ModTime() time.Time         { return e.n.times.Mtime }
func (e dirEntry) Sys() any                   { return nil }
func (e dirEntry) Mode() fs.FileMode {
	if e.n.link != "" {
		return fs.ModeSymlink | 0o777
	}
	return mode(e.n.dir, e.n.attrs)
}

// WalkDir walks the volume in lexical order, the root first.
func (r *Reader) WalkDir(fn fs.WalkDirFunc) error { return volume.Walk(r, fn) }

// ReadDirQuiet lists a directory, sorted by name.
func (r *Reader) ReadDirQuiet(name string) ([]fs.DirEntry, error) {
	n, err := r.lookup(name)
	if err == nil && (!n.dir || n.link != "") {
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

// Meta reads an object's times, record number, links, and the times of
// the name's $FILE_NAME.
func (r *Reader) Meta(name string) (target.Meta, error) {
	n, err := r.lookup(name)
	if err != nil {
		return target.Meta{}, perr("read metadata", name, err)
	}
	fn := n.fn
	return target.Meta{Times: n.times, ID: strconv.FormatUint(uint64(n.num), 10), Links: n.links, FileName: &fn, Link: n.link, Target: n.target}, nil
}

// Times reads an object's times.
func (r *Reader) Times(name string) (target.Times, error) {
	m, err := r.Meta(name)
	return m.Times, err
}

// Granularity is how finely NTFS keeps times.
func (r *Reader) Granularity() target.Granularity { return Granularity() }

// ReadFile reads a file whole.
func (r *Reader) ReadFile(name string) ([]byte, error) {
	n, err := r.lookup(name)
	if err == nil && (n.dir || n.link != "") {
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

// Streams lists an object's named streams, sorted by name. A link has
// none of its own.
func (r *Reader) Streams(name string) ([]target.Stream, error) {
	n, err := r.lookup(name)
	if err != nil {
		return nil, perr("list streams", name, err)
	}
	if n.link != "" {
		return nil, nil
	}
	var out []target.Stream
	for _, s := range slices.Sorted(maps.Keys(n.streams)) {
		out = append(out, target.Stream{Name: s, Size: n.streams[s].size})
	}
	return out, nil
}

// ReadStream reads a named stream whole.
func (r *Reader) ReadStream(name, stream string) ([]byte, error) {
	n, err := r.lookup(name)
	if err != nil {
		return nil, perr("read stream", name+":"+stream, err)
	}
	a, ok := n.streams[stream]
	if !ok || n.link != "" {
		return nil, perr("read stream", name+":"+stream, fs.ErrNotExist)
	}
	if a.resident {
		return slices.Clone(a.value), nil
	}
	data, err := r.readRuns(a.runs, 0, a.size)
	if err != nil {
		return nil, perr("read stream", name+":"+stream, err)
	}
	return data, nil
}

// OpenStreamQuiet opens a named stream for reading.
func (r *Reader) OpenStreamQuiet(name, stream string) (io.ReadCloser, error) {
	data, err := r.ReadStream(name, stream)
	if err != nil {
		return nil, err
	}
	return io.NopCloser(bytes.NewReader(data)), nil
}

var _ target.Reader = (*Reader)(nil)
