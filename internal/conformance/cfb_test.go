package conformance

import (
	"archive/zip"
	"bytes"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/richardlehane/mscfb"

	"github.com/aoiflux/fsagen/libgen"
	"github.com/aoiflux/fsagen/prng"
)

// readCompoundFile lists every stream mscfb finds in a compound file, by its
// path, with its bytes.
func readCompoundFile(t *testing.T, b []byte) map[string][]byte {
	t.Helper()
	r, err := mscfb.New(bytes.NewReader(b))
	if err != nil {
		t.Fatalf("mscfb: %v", err)
	}
	out := map[string][]byte{}
	for e, err := r.Next(); err != io.EOF; e, err = r.Next() {
		if err != nil {
			t.Fatalf("mscfb: %v", err)
		}
		if e.FileInfo().IsDir() {
			continue
		}
		data, err := io.ReadAll(e)
		if err != nil {
			t.Fatalf("mscfb: %s: %v", e.Name, err)
		}
		out[strings.Join(append(append([]string(nil), e.Path...), e.Name), "/")] = data
	}
	return out
}

// TestCompoundFileReadByMscfb: Richard Lehane's mscfb, the compound-file
// reader siegfried identifies Office files with, reads every stream of a
// generated compound file back exactly: streams in the mini stream, at the
// cutoff, across many sectors, and empty, under nested storages.
func TestCompoundFileReadByMscfb(t *testing.T) {
	s := prng.Root(9).Derive("cfb").Stream()
	entries := []libgen.CFBEntry{
		{Name: "Outer", Storage: true, Children: []libgen.CFBEntry{
			{Name: "Inner", Storage: true, Children: []libgen.CFBEntry{{Name: "deep", Data: s.Bytes(64)}}},
			{Name: "mini", Data: s.Bytes(1000)},
			{Name: "cutoff", Data: s.Bytes(4096)},
			{Name: "large", Data: s.Bytes(200000)},
			{Name: "empty"},
		}},
		{Name: "top", Data: []byte("top")},
	}
	b, err := libgen.BuildCFB(entries)
	if err != nil {
		t.Fatal(err)
	}
	got := readCompoundFile(t, b)
	want := map[string][]byte{
		"Outer/Inner/deep": entries[0].Children[0].Children[0].Data,
		"Outer/mini":       entries[0].Children[1].Data,
		"Outer/cutoff":     entries[0].Children[2].Data,
		"Outer/large":      entries[0].Children[3].Data,
		"Outer/empty":      nil,
		"top":              []byte("top"),
	}
	if len(got) != len(want) {
		t.Errorf("mscfb found %d streams, want %d: %v", len(got), len(want), keys(got))
	}
	for p, w := range want {
		if g, ok := got[p]; !ok || !bytes.Equal(g, w) {
			t.Errorf("%s: %d bytes back (found %v), want %d", p, len(g), ok, len(w))
		}
	}
}

// TestVBAProjectReadByMscfb: mscfb opens the VBA project inside a generated
// .docm and finds the streams [MS-OVBA] requires, each holding what the
// builder put there.
func TestVBAProjectReadByMscfb(t *testing.T) {
	spec := libgen.VBASpec{Host: libgen.VBAWord, EntryPoint: "AutoOpen", Marker: "FSAGEN-VBA:conformance"}
	vba, err := libgen.BuildVBAProject(spec, prng.Root(1).Derive("vba").Stream())
	if err != nil {
		t.Fatal(err)
	}
	docm, err := libgen.Docm("text", libgen.DocxMeta{Created: time.Date(2026, 3, 11, 9, 0, 0, 0, time.UTC)}, vba)
	if err != nil {
		t.Fatal(err)
	}
	zr, err := zip.NewReader(bytes.NewReader(docm), int64(len(docm)))
	if err != nil {
		t.Fatal(err)
	}
	var bin []byte
	for _, f := range zr.File {
		if f.Name == "word/vbaProject.bin" {
			rc, _ := f.Open()
			bin, _ = io.ReadAll(rc)
			rc.Close()
		}
	}
	if !bytes.Equal(bin, vba) {
		t.Fatal("the package does not carry the project as built")
	}
	got := readCompoundFile(t, bin)
	if p := got["VBA/_VBA_PROJECT"]; !bytes.Equal(p, []byte{0xCC, 0x61, 0xFF, 0xFF, 0, 0, 0}) {
		t.Errorf("_VBA_PROJECT = %x", p)
	}
	for _, m := range libgen.VBAModules(spec) {
		if g := got["VBA/"+m.Name]; !bytes.Equal(g, libgen.OVBACompress([]byte(m.Source))) {
			t.Errorf("module %s: %d bytes, not its compressed source", m.Name, len(g))
		}
	}
	for _, name := range []string{"VBA/dir", "PROJECT", "PROJECTwm"} {
		if len(got[name]) == 0 {
			t.Errorf("no %s stream", name)
		}
	}
	if !strings.HasPrefix(string(got["PROJECT"]), `ID="{`) {
		t.Errorf("PROJECT: %q", got["PROJECT"])
	}
}

func keys(m map[string][]byte) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}
