package libgen

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"path"
	"strings"
	"testing"
	"time"
)

// TestBulkForensicKindsParse: every forensic kind a bulk corpus holds reads
// back with the reader each format's own tests use, and is named the way the
// artefact is: a prefetch file for the program it records, with its hash; a
// hive, login record and audit log by their real names.
func TestBulkForensicKindsParse(t *testing.T) {
	start := time.Date(2026, 3, 4, 8, 0, 0, 0, time.UTC)
	_, jobs := Plan(11, 1, 1)
	seen := map[string]bool{}
	for _, j := range jobs {
		k := kinds[j.kind]
		data, err := k.render(j.key.Derive("content").Stream(), start, j.Path)
		if err != nil {
			t.Fatalf("%s: %v", j.Path, err)
		}
		base := path.Base(j.Path)
		switch k.id {
		case "lnk":
			if l := lnkReader(t, data); !strings.HasSuffix(l.basePath, ".docx") {
				t.Errorf("%s: shortcut to %q", base, l.basePath)
			}
		case "pf":
			r := readPrefetch(t, data)
			exe, _, _ := strings.Cut(base, "-")
			name, err := PrefetchFileName(prefetchDir+exe, DefaultHarddiskVolume)
			if err != nil || name != base || r.name != exe || fmt.Sprintf("%08X", r.hash) != strings.TrimSuffix(strings.SplitN(base, "-", 2)[1], ".pf") {
				t.Errorf("%s records %s with hash %08X (%v)", base, r.name, r.hash, err)
			}
		case "evtx":
			if r := readEvtx(t, data); len(r.records) < 4 {
				t.Errorf("%s: %d records", base, len(r.records))
			}
		case "ntuser":
			run := readHive(t, data)[`\Software\Microsoft\Windows\CurrentVersion\Run`]
			if base != "NTUSER.DAT" || len(run.values) != 1 {
				t.Errorf("%s: Run key %+v", base, run)
			}
		case "wtmp":
			if base != "wtmp" || len(data) != 3*UtmpSize || binary.LittleEndian.Uint32(data) != 2 {
				t.Errorf("%s: %d bytes, first record type %d", base, len(data), binary.LittleEndian.Uint32(data))
			}
		case "audit":
			if base != "audit.log" || !strings.HasPrefix(string(data), "type=USER_AUTH msg=audit(") || !strings.Contains(string(data), "type=EXECVE") {
				t.Errorf("%s:\n%s", base, data)
			}
		case "docm", "xlsm":
			project := officeProject(t, data)
			f, err := readCFB(project)
			if err != nil {
				t.Fatalf("%s: %v", base, err)
			}
			found := false
			for name, s := range f.streams {
				if !strings.HasPrefix(name, "VBA/") || name == "VBA/dir" || name == "VBA/_VBA_PROJECT" {
					continue
				}
				src, err := ovbaDecompress(s)
				if err != nil {
					t.Fatalf("%s: %s: %v", base, name, err)
				}
				found = found || strings.Contains(string(src), `marker = "FSAGEN-VBA:`)
			}
			if !found {
				t.Errorf("%s: no module holds the macro", base)
			}
		default:
			continue
		}
		seen[k.id] = true
	}
	for _, id := range []string{"lnk", "pf", "evtx", "ntuser", "wtmp", "audit", "docm", "xlsm"} {
		if !seen[id] {
			t.Errorf("the plan has no %s", id)
		}
	}
}

// officeProject is the VBA project inside an Office package.
func officeProject(t *testing.T, data []byte) []byte {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range zr.File {
		if strings.HasSuffix(f.Name, "/vbaProject.bin") {
			r, err := f.Open()
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			b, err := io.ReadAll(r)
			if err != nil {
				t.Fatal(err)
			}
			return b
		}
	}
	t.Fatal("no vbaProject.bin")
	return nil
}
