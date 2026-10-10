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
	"github.com/aoiflux/fsagen/volume/fat"
)

// The file systems an image can hold.
const FSFAT32 = "fat32"

// FileSystems lists them.
var FileSystems = []string{FSFAT32}

// Options say what image to make.
type Options struct {
	// Path is the image file.
	Path string
	// FS is the file system, Size the image's size in bytes and
	// ClusterSize its clusters' (0 for the file system's default).
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
	// Seed draws the volume serial, disk signature and VHD ID.
	Seed int64
}

// Plan is an image laid out but not yet written.
type Plan struct {
	Options
	Format string
	Layout container.Layout
	FAT    fat.Geometry
}

// Caps is what the planned file system holds.
func (p Plan) Caps() target.Caps { return fat.Caps(p.FAT.ClusterSize) }

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
	if err := fat.ValidLabel(o.Label); err != nil {
		return Plan{}, err
	}
	o.Label = strings.ToUpper(o.Label)
	if o.Time.Before(fat.MinTime) || o.Time.After(fat.MaxTime) {
		return Plan{}, fmt.Errorf("image time %s is outside what FAT can store (%d to %d)", o.Time.Format(time.RFC3339), fat.MinTime.Year(), fat.MaxTime.Year())
	}
	l, err := container.Plan(format, o.Partition, o.Size)
	if err != nil {
		return Plan{}, err
	}
	g, err := fat.Plan(l.Size, o.ClusterSize)
	if err != nil {
		return Plan{}, err
	}
	return Plan{Options: o, Format: format, Layout: l, FAT: g}, nil
}

// Image is an image being written: a target until it is finished, then a
// file to close or abort.
type Image struct {
	*volume.Volume
	p      Plan
	f      *os.File
	serial uint32
	closed bool
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
	img := &Image{p: p, f: f, serial: binary.LittleEndian.Uint32(p.key().Derive("serial").Stream().Bytes(4))}
	if err := img.start(); err != nil {
		img.Abort()
		return nil, err
	}
	return img, nil
}

func (img *Image) start() error {
	p := img.p
	if err := img.f.Truncate(p.Layout.File()); err != nil {
		return err
	}
	if err := container.WriteMBR(img.f, p.Layout, 0x0C, p.key()); err != nil {
		return err
	}
	dev := volume.NewDevice(img.f, p.Layout.Offset, p.Layout.Size)
	res := &volume.Tracker{}
	fsys, err := fat.Format(dev, fat.Options{
		ClusterSize: p.FAT.ClusterSize, Label: p.Label, Serial: img.serial,
		Hidden: uint32(p.Layout.Offset / volume.SectorSize), Clock: p.Time, Alloc: p.Alloc,
	}, res)
	if err != nil {
		return err
	}
	img.Volume = volume.New(fsys, res, img.f)
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
	return &runinfo.Image{
		FS: p.FS, Format: p.Format, Partition: p.Layout.Partition, PartitionOffset: p.Layout.Offset,
		Size: p.Layout.File(), ClusterSize: p.FAT.ClusterSize, Serial: fmt.Sprintf("%04X-%04X", img.serial>>16, img.serial&0xFFFF),
		Label: p.Label, Time: p.Time.UTC().Format(time.RFC3339Nano), Alloc: p.Alloc, TimeZone: "UTC",
	}
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
