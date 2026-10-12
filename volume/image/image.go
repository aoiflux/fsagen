// Package image makes the disk images fsagen writes scenarios into: a file
// system from package volume's drivers, in a container from package
// container. An image is written to a temporary file beside its name and
// takes that name only once the run has succeeded.
package image

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/aoiflux/fsagen/prng"
	"github.com/aoiflux/fsagen/runinfo"
	"github.com/aoiflux/fsagen/target"
	"github.com/aoiflux/fsagen/volume"
	"github.com/aoiflux/fsagen/volume/container"
	"github.com/aoiflux/fsagen/volume/ext4"
	"github.com/aoiflux/fsagen/volume/fat"
	"github.com/aoiflux/fsagen/volume/ntfs"
	"github.com/aoiflux/libtable"
)

// The file systems an image can hold.
const (
	FSFAT32 = "fat32"
	FSExt4  = "ext4"
	FSNTFS  = "ntfs"
)

// FileSystems lists them.
var FileSystems = []string{FSFAT32, FSExt4, FSNTFS}

// Options say what image to make.
type Options struct {
	// Path is the image file.
	Path string
	// FS is the file system, Size the image's size in bytes and
	// ClusterSize its clusters' or blocks' (0 for the file system's
	// default).
	FS          string
	Size        int64
	ClusterSize int
	// Partition is container.PartitionMBR or PartitionNone.
	Partition string
	Label     string
	// Time stamps what the file system creates before the scenario sets
	// its times, and the VHD footer.
	Time time.Time
	// Alloc is the allocation policy (volume.NextFit by default).
	Alloc string
	// Journal gives an NTFS volume its change journal.
	Journal bool
	// Seed draws the volume serial or UUID, disk signature and VHD ID.
	Seed int64
}

// Plan is an image laid out but not yet written. FAT, Ext4 or NTFS is
// the file system's geometry, as FS says.
type Plan struct {
	Options
	Format string
	Layout container.Layout
	FAT    fat.Geometry
	Ext4   ext4.Geometry
	NTFS   ntfs.Geometry
}

// Caps is what the planned file system holds.
func (p Plan) Caps() target.Caps {
	switch p.FS {
	case FSExt4:
		return ext4.Caps(p.Ext4.BlockSize)
	case FSNTFS:
		return ntfs.Caps(p.NTFS.ClusterSize)
	}
	return fat.Caps(p.FAT.ClusterSize)
}

// clusterSize is the planned file system's allocation unit.
func (p Plan) clusterSize() int {
	switch p.FS {
	case FSExt4:
		return p.Ext4.BlockSize
	case FSNTFS:
		return p.NTFS.ClusterSize
	}
	return p.FAT.ClusterSize
}

// timeRange is what times the file system can store, and its name for
// them.
func timeRange(fs string) (time.Time, time.Time, string) {
	switch fs {
	case FSExt4:
		return ext4.MinTime, ext4.MaxTime, "ext4"
	case FSNTFS:
		return ntfs.MinTime, ntfs.MaxTime, "NTFS"
	}
	return fat.MinTime, fat.MaxTime, "FAT"
}

// NewPlan checks o and lays the image out.
func NewPlan(o Options) (Plan, error) {
	format, err := container.FormatFor(o.Path)
	if err != nil {
		return Plan{}, err
	}
	if !slices.Contains(FileSystems, o.FS) {
		return Plan{}, fmt.Errorf("unknown image file system %q (want %s)", o.FS, strings.Join(FileSystems, ", "))
	}
	if o.Partition == "" {
		o.Partition = container.PartitionMBR
	}
	if o.Alloc == "" {
		o.Alloc = volume.NextFit
	}
	if !slices.Contains(volume.Policies, o.Alloc) {
		return Plan{}, fmt.Errorf("unknown allocation policy %q (want %s)", o.Alloc, strings.Join(volume.Policies, " or "))
	}
	switch o.FS {
	case FSExt4:
		err = ext4.ValidLabel(o.Label)
	case FSNTFS:
		err = ntfs.ValidLabel(o.Label)
	default:
		if err = fat.ValidLabel(o.Label); err == nil {
			o.Label = strings.ToUpper(o.Label)
		}
	}
	if err != nil {
		return Plan{}, err
	}
	if lo, hi, name := timeRange(o.FS); o.Time.Before(lo) || o.Time.After(hi) {
		return Plan{}, fmt.Errorf("image time %s is outside what %s can store (%d to %d)", o.Time.Format(time.RFC3339), name, lo.Year(), hi.Year())
	}
	if o.Partition == container.PartitionGPT && o.FS != FSNTFS {
		return Plan{}, fmt.Errorf("--partition gpt lays a disk out as Windows does, around an NTFS volume; %s goes in an MBR partition or none", o.FS)
	}
	l, err := container.Plan(format, o.Partition, o.Size)
	if err != nil {
		return Plan{}, err
	}
	for _, part := range l.Parts {
		var what string
		switch part.Type {
		case container.TypeEFISystem:
			what, err = "EFI system partition", fatPlan(part.Size)
		case container.TypeWinRecovery:
			what, err = "recovery partition", ntfsPlan(part.Size)
		}
		if err != nil {
			return Plan{}, fmt.Errorf("the %s: %w", what, err)
		}
	}
	p := Plan{Options: o, Format: format, Layout: l}
	switch o.FS {
	case FSExt4:
		p.Ext4, err = ext4.Plan(l.Size, o.ClusterSize)
	case FSNTFS:
		p.NTFS, err = ntfs.Plan(l.Size, o.ClusterSize)
	default:
		p.FAT, err = fat.Plan(l.Size, o.ClusterSize)
	}
	if err != nil {
		return Plan{}, err
	}
	return p, nil
}

// Image is an image being written: a target until it is finished, then a
// file to close or abort.
type Image struct {
	*volume.Volume
	p Plan
	f *os.File
	// serial is a FAT volume's serial number, serial64 an NTFS volume's,
	// and uuid an ext4 volume's.
	serial   uint32
	serial64 uint64
	uuid     [16]byte
	closed   bool
}

// key is where every identifier the image carries is drawn from; it is
// apart from every content key, so an image changes no file's bytes.
func (p Plan) key() prng.Key { return prng.Root(p.Seed).Derive("image", p.FS) }

// Create starts writing the image planned, in a temporary file beside it.
func Create(p Plan) (*Image, error) {
	if err := os.MkdirAll(filepath.Dir(p.Path), 0o755); err != nil {
		return nil, err
	}
	f, err := os.CreateTemp(filepath.Dir(p.Path), "."+filepath.Base(p.Path)+".*.tmp")
	if err != nil {
		return nil, err
	}
	img := &Image{
		p: p, f: f, serial: binary.LittleEndian.Uint32(p.key().Derive("serial").Stream().Bytes(4)),
		serial64: binary.LittleEndian.Uint64(p.key().Derive("serial").Stream().Bytes(8)), uuid: uuid(p.key().Derive("uuid")),
	}
	if err := img.start(); err != nil {
		img.Abort()
		return nil, err
	}
	return img, nil
}

// uuid is a random (version 4) UUID drawn from k, as uuid_generate makes
// one.
func uuid(k prng.Key) [16]byte {
	var u [16]byte
	copy(u[:], k.Stream().Bytes(16))
	u[6] = u[6]&0x0F | 0x40
	u[8] = u[8]&0x3F | 0x80
	return u
}

func (img *Image) start() error {
	p := img.p
	if err := img.f.Truncate(p.Layout.File()); err != nil {
		return err
	}
	kind := libtable.MBRTypeFAT32LBA
	switch p.FS {
	case FSExt4:
		kind = libtable.MBRTypeLinux
	case FSNTFS:
		kind = libtable.MBRTypeNTFS
	}
	if err := container.WriteMBR(img.f, p.Layout, kind, p.key()); err != nil {
		return err
	}
	if err := container.WriteGPT(img.f, p.Layout, p.key()); err != nil {
		return err
	}
	if err := img.formatOthers(); err != nil {
		return err
	}
	dev := volume.NewDevice(img.f, p.Layout.Offset, p.Layout.Size)
	res := &volume.Tracker{}
	var d volume.Driver
	var err error
	switch p.FS {
	case FSExt4:
		d, err = ext4.Format(dev, ext4.Options{
			BlockSize: p.Ext4.BlockSize, Label: p.Label, UUID: img.uuid, HashSeed: uuid(p.key().Derive("hash_seed")),
			Clock: p.Time, Alloc: p.Alloc, Generations: p.key().Derive("generation").Stream(),
		}, res)
	case FSNTFS:
		d, err = ntfs.Format(dev, ntfs.Options{
			ClusterSize: p.NTFS.ClusterSize, Label: p.Label, Serial: img.serial64,
			Hidden: uint32(p.Layout.Offset / volume.SectorSize), Clock: p.Time, Alloc: p.Alloc, Journal: p.Journal,
		}, res)
	default:
		d, err = fat.Format(dev, fat.Options{
			ClusterSize: p.FAT.ClusterSize, Label: p.Label, Serial: img.serial,
			Hidden: uint32(p.Layout.Offset / volume.SectorSize), Clock: p.Time, Alloc: p.Alloc,
		}, res)
	}
	if err != nil {
		return err
	}
	img.Volume = volume.New(d, res, img.f)
	return nil
}

// fatPlan and ntfsPlan check that a partition of size bytes holds FAT32 or
// NTFS at its default cluster size.
func fatPlan(size int64) error {
	_, err := fat.Plan(size, 0)
	return err
}

func ntfsPlan(size int64) error {
	_, err := ntfs.Plan(size, 0)
	return err
}

// formatOthers formats a GPT disk's partitions besides the scenario's, as
// Windows Setup leaves them before anything is installed: the EFI system
// partition FAT32 and the recovery partition NTFS, both empty, and the
// Microsoft reserved partition unformatted. Their serials are drawn from
// the image's key.
func (img *Image) formatOthers() error {
	p := img.p
	for i, part := range p.Layout.Parts {
		dev := volume.NewDevice(img.f, part.Offset, part.Size)
		k := p.key().Derive("partition", strconv.Itoa(i), "serial").Stream()
		var d volume.Driver
		var err error
		switch part.Type {
		case container.TypeEFISystem:
			d, err = fat.Format(dev, fat.Options{
				Serial: binary.LittleEndian.Uint32(k.Bytes(4)), Hidden: uint32(part.Offset / volume.SectorSize), Clock: p.Time, Alloc: volume.NextFit,
			}, &volume.Tracker{})
		case container.TypeWinRecovery:
			d, err = ntfs.Format(dev, ntfs.Options{
				Serial: binary.LittleEndian.Uint64(k.Bytes(8)), Hidden: uint32(part.Offset / volume.SectorSize), Clock: p.Time, Alloc: volume.NextFit,
			}, &volume.Tracker{})
		default:
			continue
		}
		if err != nil {
			return fmt.Errorf("partition %d: %w", i+1, err)
		}
		if err := d.Flush(); err != nil {
			return err
		}
	}
	return nil
}

// Close finishes the container, gives the image its name and returns its
// SHA-256. The volume must be finished.
func (img *Image) Close() (string, error) {
	if err := container.WriteFooter(img.f, img.p.Layout, img.p.Time, img.p.key()); err != nil {
		img.Abort()
		return "", err
	}
	if err := img.f.Sync(); err != nil {
		img.Abort()
		return "", err
	}
	if _, err := img.f.Seek(0, io.SeekStart); err != nil {
		img.Abort()
		return "", err
	}
	h := sha256.New()
	if _, err := io.Copy(h, img.f); err != nil {
		img.Abort()
		return "", err
	}
	tmp := img.f.Name()
	if err := img.f.Close(); err != nil {
		img.Abort()
		return "", err
	}
	img.closed = true
	if err := os.Rename(tmp, img.p.Path); err != nil {
		os.Remove(tmp)
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Abort throws the unfinished image away, leaving any image already at its
// name as it was.
func (img *Image) Abort() {
	if img.closed {
		return
	}
	img.closed = true
	img.f.Close()
	os.Remove(img.f.Name())
}

// Record is the run manifest's description of the image.
func (img *Image) Record() *runinfo.Image {
	p := img.p
	r := &runinfo.Image{
		FS: p.FS, Format: p.Format, Partition: p.Layout.Partition, PartitionOffset: p.Layout.Offset,
		Size: p.Layout.File(), ClusterSize: p.clusterSize(),
		Label: p.Label, Time: p.Time.UTC().Format(time.RFC3339Nano), Alloc: p.Alloc,
	}
	switch p.FS {
	case FSExt4:
		u := img.uuid
		r.UUID = fmt.Sprintf("%x-%x-%x-%x-%x", u[0:4], u[4:6], u[6:8], u[8:10], u[10:16])
	case FSNTFS:
		r.Serial = fmt.Sprintf("%016X", img.serial64)
		r.USNJournal = &p.Journal
		for _, part := range p.Layout.Parts {
			r.Partitions = append(r.Partitions, runinfo.Partition{Type: part.Type, Name: part.Name, Offset: part.Offset, Size: part.Size})
		}
	default:
		r.Serial, r.TimeZone = fmt.Sprintf("%04X-%04X", img.serial>>16, img.serial&0xFFFF), "UTC"
	}
	return r
}

// ParseSize reads a size in bytes, or with a K, M, G or T suffix (powers of
// 1024, an optional trailing B or iB).
func ParseSize(s string) (int64, error) {
	t := strings.ToUpper(strings.TrimSpace(s))
	t = strings.TrimSuffix(strings.TrimSuffix(t, "B"), "I")
	mult := int64(1)
	if t != "" {
		if i := strings.IndexByte("KMGT", t[len(t)-1]); i >= 0 {
			mult = 1 << (10 * (i + 1))
			t = t[:len(t)-1]
		}
	}
	n, err := strconv.ParseInt(t, 10, 64)
	if err != nil || n <= 0 || n > (1<<62)/mult {
		return 0, fmt.Errorf("%q is not a size: give bytes, or a number with K, M, G or T", s)
	}
	return n * mult, nil
}
