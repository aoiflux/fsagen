package fat

import (
	"testing"
)

// The short names Windows 11 gave these names, read with dir /x; the
// checksum form is what it gives the fifth name with the same six-letter
// start, and a name whose base keeps two characters or fewer at once.
func TestShortNamesMatchWindows(t *testing.T) {
	cases := []struct {
		names []string
		want  []string
	}{
		{
			[]string{"Long File Name Number1.text", "Long File Name Number2.text", "Long File Name Number3.text", "Long File Name Number4.text", "Long File Name Number5.text", "Long File Name Number6.text", "Long File Name Number7.text"},
			[]string{"LONGFI~1.TEX", "LONGFI~2.TEX", "LONGFI~3.TEX", "LONGFI~4.TEX", "LO710A~1.TEX", "LO2901~1.TEX", "LO0B0E~1.TEX"},
		},
		{[]string{"ab.html"}, []string{"AB74F4~1.HTM"}},
		{[]string{"été.txt"}, []string{"TDA51~1.TXT"}},
		{[]string{"x y.txt"}, []string{"XY3573~1.TXT"}},
		{[]string{".hidden"}, []string{"HIDDEN~1"}},
		{[]string{"a+b=c[1].txt"}, []string{"A_B_C_~1.TXT"}},
		{[]string{"file.tar.gz"}, []string{"FILETA~1.GZ"}},
		{[]string{"résumé final.docx"}, []string{"RSUMFI~1.DOC"}},
		{[]string{"verylongname.html"}, []string{"VERYLO~1.HTM"}},
	}
	for _, c := range cases {
		used := map[shortName]bool{}
		for i, name := range c.names {
			s, err := generate(name, func(s shortName) bool { return used[s] })
			if err != nil {
				t.Fatal(err)
			}
			used[s] = true
			if s.String() != c.want[i] {
				t.Errorf("%q: short name %s, Windows gives %s", name, s, c.want[i])
			}
		}
	}
}

// A name that is already 8.3 is kept as itself: all upper or all lower
// case per part needs no long name (the lower case is kept in NTRes bits);
// mixed case within a part does.
func TestNamesThatFit(t *testing.T) {
	cases := []struct {
		name         string
		short        string
		bits         byte
		mixed, valid bool
	}{
		{"README.TXT", "README.TXT", 0, false, true},
		{"readme.txt", "README.TXT", lowerBase | lowerExt, false, true},
		{"README.txt", "README.TXT", lowerExt, false, true},
		{"ReadMe.txt", "README.TXT", 0, true, true},
		{"NOEXT", "NOEXT", 0, false, true},
		{"a1_$~.c", "A1_$~.C", lowerBase | lowerExt, false, true},
		{"toolongname.txt", "", 0, false, false},
		{"a.text", "", 0, false, false},
		{"a b.txt", "", 0, false, false},
		{"a+b.txt", "", 0, false, false},
		{"two.dots.x", "", 0, false, false},
		{"é.txt", "", 0, false, false},
	}
	for _, c := range cases {
		s, bits, mixed, ok := fits(c.name)
		if ok != c.valid || ok && (s.String() != c.short || bits != c.bits || mixed != c.mixed) {
			t.Errorf("%q: %s bits %#x mixed %v ok %v; want %s %#x %v %v", c.name, s, bits, mixed, ok, c.short, c.bits, c.mixed, c.valid)
		}
	}
}

// Long-name entries carry 13 characters each, last part first and marked
// 0x40, padded with one NUL and then 0xFFFF, all tied to the short entry
// by its checksum.
func TestLongNameEntries(t *testing.T) {
	var s shortName
	copy(s[:], "LONGFI~1TEX")
	es := lfnEntries("Long File Name Number1.text", s)
	if len(es) != 3 {
		t.Fatalf("%d entries for 27 characters, want 3", len(es))
	}
	sum := lfnChecksum(s)
	for i, e := range es {
		ord := byte(3 - i)
		if i == 0 {
			ord |= 0x40
		}
		if e[0] != ord || e[11] != attrLFN || e[13] != sum {
			t.Errorf("entry %d: ord %#x attr %#x sum %#x", i, e[0], e[11], e[13])
		}
	}
	// The last part holds the 27th character, "t", a NUL, then 0xFFFF to
	// the end.
	last := es[0]
	if last[1] != 't' || last[2] != 0 || last[3] != 0 || last[4] != 0 || last[5] != 0xFF || last[31] != 0xFF {
		t.Errorf("padding: % x", last[:])
	}
}

// Names FAT cannot hold are refused before anything is written.
func TestValidName(t *testing.T) {
	for _, bad := range []string{"a?b", "a*", "pipe|", `quote"`, "lt<", "tab\t"} {
		if ValidName(bad) == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	for _, good := range []string{"a+b=c[1].txt", "été.txt", ".hidden", "x y"} {
		if err := ValidName(good); err != nil {
			t.Errorf("%q: %v", good, err)
		}
	}
}
