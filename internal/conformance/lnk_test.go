package conformance

import (
	"bytes"
	"strings"
	"testing"
	"time"

	lnk "github.com/parsiya/golnk"

	"github.com/aoiflux/fsagen/libgen"
	"github.com/aoiflux/fsagen/prng"
)

// TestLNKReadByGolnk: github.com/parsiya/golnk reads a generated link from
// end to end — header, ID list, LinkInfo, strings and extra data — and finds
// what the spec put there.
func TestLNKReadByGolnk(t *testing.T) {
	created := time.Date(2024, 3, 15, 9, 30, 12, 345678900, time.UTC)
	spec := libgen.LNKSpec{
		Target:       `C:\Users\Public\Long Folder Name\report.final.docx`,
		Arguments:    "/q --open",
		WorkingDir:   `C:\Users\Public`,
		RelativePath: `..\Long Folder Name\report.final.docx`,
		Description:  "Quarterly report",
		IconLocation: `C:\Windows\System32\shell32.dll`,
		IconIndex:    -3,
		ShowCommand:  "maximized",
		DriveType:    "removable",
		VolumeSerial: 0x1A2B3C4D,
		VolumeLabel:  "USBSTICK",
		MachineID:    "DESKTOP-QUILL",
		Created:      created,
		Accessed:     created.Add(time.Hour),
		Modified:     created.Add(2 * time.Hour),
		Size:         4096,
		Attributes:   []string{"hidden"},
	}
	data, err := libgen.BuildLNK(spec, prng.Root(1).Stream())
	if err != nil {
		t.Fatal(err)
	}
	f, err := lnk.Read(bytes.NewReader(data), uint64(len(data)))
	if err != nil {
		t.Fatalf("golnk: %v", err)
	}

	h := f.Header
	if h.Magic != 0x4C || !h.LinkFlags["HasLinkTargetIDList"] || !h.LinkFlags["HasLinkInfo"] || !h.LinkFlags["IsUnicode"] {
		t.Errorf("header magic %#x flags %v", h.Magic, h.LinkFlags)
	}
	if !h.FileAttributes["FILE_ATTRIBUTE_HIDDEN"] {
		t.Errorf("attributes %v lack hidden", h.FileAttributes)
	}
	// golnk reads the header's second and third times the wrong way round:
	// [MS-SHLLINK] 2.1 orders them creation, access, write, and so does a
	// shortcut Windows saves itself (TestLNKHeaderTimeOrderMatchesWindows in
	// fsagen's libgen). Its AccessTime is therefore the write time and its
	// WriteTime the access time.
	for name, got := range map[string][2]time.Time{
		"creation": {h.CreationTime, spec.Created}, "access": {h.WriteTime, spec.Accessed}, "write": {h.AccessTime, spec.Modified},
	} {
		if !got[0].Equal(got[1].Truncate(100 * time.Nanosecond)) {
			t.Errorf("%s time %v, want %v", name, got[0], got[1])
		}
	}
	if h.TargetFileSize != 4096 || h.IconIndex != -3 || !strings.Contains(strings.ToUpper(h.ShowCommand), "MAXIMIZED") {
		t.Errorf("size %d icon %d show %q", h.TargetFileSize, h.IconIndex, h.ShowCommand)
	}

	if n := len(f.IDList.List.ItemIDList); n != 6 {
		t.Errorf("%d ID list items, want 6", n)
	}

	li := f.LinkInfo
	if li.LocalBasePath+li.CommonPathSuffix != spec.Target {
		t.Errorf("LinkInfo path %q + %q, want %q", li.LocalBasePath, li.CommonPathSuffix, spec.Target)
	}
	if li.VolID.DriveType != "DRIVE_REMOVABLE" || li.VolID.VolumeLabel != "USBSTICK" {
		t.Errorf("volume %+v", li.VolID)
	}
	if s := strings.ToLower(li.VolID.DriveSerialNumber); s != "0x1a2b3c4d" && s != "0x4d3c2b1a" {
		t.Errorf("serial %q", li.VolID.DriveSerialNumber)
	}

	sd := f.StringData
	if sd.NameString != spec.Description || sd.RelativePath != spec.RelativePath || sd.WorkingDir != spec.WorkingDir ||
		sd.CommandLineArguments != spec.Arguments || sd.IconLocation != spec.IconLocation {
		t.Errorf("strings %+v", sd)
	}

	var tracker bool
	for _, b := range f.DataBlocks.Blocks {
		if b.Signature == 0xA0000003 {
			tracker = true
			if !bytes.HasPrefix(b.Data[8:], []byte("DESKTOP-QUILL\x00")) {
				t.Errorf("tracker machine id %q", b.Data[8:24])
			}
		}
	}
	if !tracker {
		t.Error("no TrackerDataBlock")
	}
}
