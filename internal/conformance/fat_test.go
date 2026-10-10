package conformance

import (
	"bytes"
	"io/fs"
	"path/filepath"
	"slices"
	"testing"
	"time"

	diskfs "github.com/diskfs/go-diskfs"

	"github.com/aoiflux/fsagen/compile"
	"github.com/aoiflux/fsagen/manifest"
	"github.com/aoiflux/fsagen/volume/container"
	"github.com/aoiflux/fsagen/volume/image"
)

// buildFAT32 writes testdata/image/fat32.yaml into a FAT32 image at path,
// and returns its tree as fsagen's own reader saw it once finished.
func buildFAT32(t *testing.T, path, partition string) map[string][]byte {
	t.Helper()
	prog, err := compile.Load(compile.ModeManifest, filepath.Join("..", "..", "testdata", "image", "fat32.yaml"), compile.Options{Seed: 1, FoldCase: true})
	if err != nil {
		t.Fatal(err)
	}
	defer prog.Close()
	plan, err := image.NewPlan(image.Options{Path: path, FS: image.FSFAT32, Size: 40 << 20, Partition: partition, Label: "Evidence", Time: time.Date(2023, 3, 1, 0, 0, 0, 0, time.UTC), Seed: 1})
	if err != nil {
		t.Fatal(err)
	}
	img, err := image.Create(plan)
	if err != nil {
		t.Fatal(err)
	}
	defer img.Abort()
	_, read, err := manifest.Run(img, prog, false)
	if err != nil {
		t.Fatal(err)
	}
	ours := map[string][]byte{}
	err = read.WalkDir(func(name string, d fs.DirEntry, err error) error {
		if err != nil || name == "." {
			return err
		}
		if d.IsDir() {
			ours[name+"/"] = nil
			return nil
		}
		data, err := read.ReadFile(name)
		ours[name] = data
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := img.Close(); err != nil {
		t.Fatal(err)
	}
	return ours
}

// TestFAT32ReadByGoDiskfs: github.com/diskfs/go-diskfs opens a FAT32 image
// fsagen wrote, bare and inside an MBR-partitioned VHD, and finds every
// name, long names and their case included, and every byte that fsagen's
// own reader found, and the same write times.
func TestFAT32ReadByGoDiskfs(t *testing.T) {
	for _, c := range []struct {
		file, partition string
		index           int
	}{
		{"bare.img", container.PartitionNone, 0},
		{"disk.vhd", container.PartitionMBR, 1},
	} {
		t.Run(c.file, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), c.file)
			ours := buildFAT32(t, path, c.partition)

			disk, err := diskfs.Open(path, diskfs.WithOpenMode(diskfs.ReadOnly))
			if err != nil {
				t.Fatal(err)
			}
			defer disk.Close()
			theirs, err := disk.GetFilesystem(c.index)
			if err != nil {
				t.Fatalf("go-diskfs: %v", err)
			}
			got := map[string][]byte{}
			err = fs.WalkDir(theirs, ".", func(name string, d fs.DirEntry, err error) error {
				if err != nil || name == "." {
					return err
				}
				if d.IsDir() {
					got[name+"/"] = nil
					return nil
				}
				// An empty file starts at cluster 0, as the specification
				// and Windows have it, and go-diskfs refuses to read from
				// cluster 0; its size is what can be compared.
				info, err := d.Info()
				if err != nil || info.Size() == 0 {
					got[name] = []byte{}
					return err
				}
				// go-diskfs v1.9.3 reads on to the end of the last cluster;
				// the size in the entry says where the file ends.
				data, err := fs.ReadFile(theirs, name)
				got[name] = data[:min(int64(len(data)), info.Size())]
				return err
			})
			if err != nil {
				t.Fatalf("go-diskfs walk: %v", err)
			}
			names := func(m map[string][]byte) []string {
				out := make([]string, 0, len(m))
				for k := range m {
					out = append(out, k)
				}
				slices.Sort(out)
				return out
			}
			if a, b := names(ours), names(got); !slices.Equal(a, b) {
				t.Fatalf("names differ:\nfsagen    %q\ngo-diskfs %q", a, b)
			}
			for name, data := range ours {
				if !bytes.Equal(data, got[name]) {
					t.Errorf("%s: go-diskfs read %d bytes, fsagen %d", name, len(got[name]), len(data))
				}
			}
			if len(ours) < 40 {
				t.Errorf("only %d names: the scenario did not run", len(ours))
			}
		})
	}
}
