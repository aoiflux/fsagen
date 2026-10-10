package libgen

import (
	"bytes"
	"cmp"
	"encoding/binary"
	"fmt"
	"math/bits"
	"regexp"
	"slices"
	"strings"

	"github.com/aoiflux/fsagen/prng"
)

// A VBA project ([MS-OVBA]) is the compound file Office keeps a document's
// macros in, vbaProject.bin. fsagen writes one whose single macro is inert:
// an entry point Office runs when the document opens, whose body assigns a
// marker string to a local variable and does nothing else. There is no way
// to give it other code. The project carries source only, no compiled
// p-code: its _VBA_PROJECT stream says so (version 0xFFFF), as the
// specification requires of a writer, and Office compiles the source when
// it opens the document.

// VBAHosts are the applications a project can belong to.
const (
	VBAWord  = "word"
	VBAExcel = "excel"
)

// VBAEntryPoints are, per host, the macros Office runs as a document opens:
// one in a standard module (AutoOpen, Auto_Open) and one in the document's
// own module (Document_Open, Workbook_Open). The first of each is the
// default.
var VBAEntryPoints = map[string][]string{
	VBAWord:  {"AutoOpen", "Document_Open"},
	VBAExcel: {"Auto_Open", "Workbook_Open"},
}

// VBA module types, as the dir stream records them.
const (
	vbaProcedural = 0x0021
	vbaDocument   = 0x0022
)

// VBAModule is one module of a project and its source.
type VBAModule struct {
	Name     string
	Document bool
	Source   string
}

// VBASpec is the inert macro a project holds.
type VBASpec struct {
	Host       string
	EntryPoint string
	// Module is the standard module that holds an AutoOpen or Auto_Open;
	// an entry point that belongs to the document's module ignores it.
	Module string
	// Marker is the string the macro assigns.
	Marker string
}

// DefaultVBAModule is the standard module an AutoOpen or Auto_Open goes in
// when the scenario does not name one: Word's own default, and Excel's.
var DefaultVBAModule = map[string]string{VBAWord: "NewMacros", VBAExcel: "Module1"}

var reVBAName = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]{0,30}$`)

// vbaDocumentModules are the modules a host's document always has, each
// with the class it is based on.
var vbaDocumentModules = map[string][]struct{ name, base string }{
	VBAWord:  {{"ThisDocument", "1Normal.ThisDocument"}},
	VBAExcel: {{"ThisWorkbook", "0{00020819-0000-0000-C000-000000000046}"}, {"Sheet1", "0{00020820-0000-0000-C000-000000000046}"}},
}

// vbaTemplateDerived is how each host marks its document modules: Word's
// come from the Normal template, Excel's from nothing.
var vbaTemplateDerived = map[string]string{VBAWord: "True", VBAExcel: "False"}

// vbaProjectName is the name each host gives a new document's project.
var vbaProjectName = map[string]string{VBAWord: "Project", VBAExcel: "VBAProject"}

// MaxVBAMarker bounds a marker: one line of source, comfortably.
const MaxVBAMarker = 200

// CheckVBA reports what is wrong with spec, or nil.
func CheckVBA(spec VBASpec) error {
	entries, ok := VBAEntryPoints[spec.Host]
	if !ok {
		return fmt.Errorf("unknown VBA host %q", spec.Host)
	}
	if !slices.Contains(entries, spec.EntryPoint) {
		return fmt.Errorf("entry_point %q (want one of: %s)", spec.EntryPoint, strings.Join(entries, ", "))
	}
	if spec.Module != "" {
		if spec.EntryPoint != entries[0] {
			return fmt.Errorf("module_name: %s belongs to the document's own module, so there is no module to name", spec.EntryPoint)
		}
		if !reVBAName.MatchString(spec.Module) {
			return fmt.Errorf("module_name %q is not a VBA name (a letter, then up to 30 letters, digits or underscores)", spec.Module)
		}
		for _, d := range vbaDocumentModules[spec.Host] {
			if strings.EqualFold(spec.Module, d.name) {
				return fmt.Errorf("module_name %q is the document's own module", spec.Module)
			}
		}
		if strings.EqualFold(spec.Module, vbaProjectName[spec.Host]) {
			return fmt.Errorf("module_name %q is the project's name", spec.Module)
		}
	}
	if n := len(spec.Marker); n == 0 || n > MaxVBAMarker {
		return fmt.Errorf("marker must be 1 to %d characters", MaxVBAMarker)
	}
	for _, c := range []byte(spec.Marker) {
		if c < 0x20 || c > 0x7E || c == '"' {
			return fmt.Errorf("marker %q may hold printable ASCII only, and no double quote", spec.Marker)
		}
	}
	return nil
}

// VBAModules are the modules spec's project holds, document modules first,
// each with its full source as Office stores it.
func VBAModules(spec VBASpec) []VBAModule {
	entries := VBAEntryPoints[spec.Host]
	var out []VBAModule
	for i, d := range vbaDocumentModules[spec.Host] {
		src := vbaLines(
			`Attribute VB_Name = "`+d.name+`"`,
			`Attribute VB_Base = "`+d.base+`"`,
			`Attribute VB_GlobalNameSpace = False`,
			`Attribute VB_Creatable = False`,
			`Attribute VB_PredeclaredId = True`,
			`Attribute VB_Exposed = True`,
			`Attribute VB_TemplateDerived = `+vbaTemplateDerived[spec.Host],
			`Attribute VB_Customizable = True`,
		)
		if i == 0 && spec.EntryPoint == entries[1] {
			src += vbaBody("Private Sub "+spec.EntryPoint+"()", spec.Marker)
		}
		out = append(out, VBAModule{Name: d.name, Document: true, Source: src})
	}
	if spec.EntryPoint == entries[0] {
		name := cmp.Or(spec.Module, DefaultVBAModule[spec.Host])
		out = append(out, VBAModule{Name: name, Source: vbaLines(`Attribute VB_Name = "`+name+`"`) + vbaBody("Sub "+spec.EntryPoint+"()", spec.Marker)})
	}
	return out
}

// vbaBody is the inert macro: a comment, and the marker assigned to a local
// variable.
func vbaBody(header, marker string) string {
	return vbaLines(
		header,
		`    ' fsagen test macro. It does nothing.`,
		`    Dim marker As String`,
		`    marker = "`+marker+`"`,
		`End Sub`,
	)
}

func vbaLines(lines ...string) string { return strings.Join(lines, "\r\n") + "\r\n" }

// BuildVBAProject writes the vbaProject.bin for spec. The project's ID and
// the bytes that obscure its protection fields are drawn from s.
func BuildVBAProject(spec VBASpec, s *prng.Stream) ([]byte, error) {
	if err := CheckVBA(spec); err != nil {
		return nil, err
	}
	modules := VBAModules(spec)
	id := MustGUID(s.UUID()).String()

	vba := []CFBEntry{
		// No performance cache: the version 0xFFFF tells Office to compile
		// the source.
		{Name: "_VBA_PROJECT", Data: []byte{0xCC, 0x61, 0xFF, 0xFF, 0x00, 0x00, 0x00}},
		{Name: "dir", Data: OVBACompress(vbaDir(spec.Host, modules))},
	}
	for _, m := range modules {
		vba = append(vba, CFBEntry{Name: m.Name, Data: OVBACompress([]byte(m.Source))})
	}
	return BuildCFB([]CFBEntry{
		{Name: "VBA", Storage: true, Children: vba},
		{Name: "PROJECT", Data: vbaProjectStream(spec.Host, id, modules, s)},
		{Name: "PROJECTwm", Data: vbaNameMap(modules)},
	})
}

// vbaProjectStream is the PROJECT stream: the project's properties as text.
// Its protection state, password and visibility are written obscured, as
// the specification requires: unprotected, no password, visible.
func vbaProjectStream(host, id string, modules []VBAModule, s *prng.Stream) []byte {
	var b strings.Builder
	line := func(format string, args ...any) { fmt.Fprintf(&b, format+"\r\n", args...) }
	line(`ID="%s"`, id)
	for _, m := range modules {
		if m.Document {
			line(`Document=%s/&H00000000`, m.Name)
		} else {
			line(`Module=%s`, m.Name)
		}
	}
	line(`Name="%s"`, vbaProjectName[host])
	line(`HelpContextID="0"`)
	line(`VersionCompatible32="393222000"`)
	line(`CMG="%X"`, ovbaEncrypt(id, []byte{0, 0, 0, 0}, s))
	line(`DPB="%X"`, ovbaEncrypt(id, []byte{0}, s))
	line(`GC="%X"`, ovbaEncrypt(id, []byte{0xFF}, s))
	line(``)
	line(`[Host Extender Info]`)
	line(`&H00000001={3832D640-CF90-11CF-8E43-00A0C911005A};VBE;&H00000000`)
	line(``)
	line(`[Workspace]`)
	for _, m := range modules {
		line(`%s=0, 0, 0, 0, C`, m.Name)
	}
	return []byte(b.String())
}

// ovbaEncrypt obscures data as the specification's data encryption does: a
// seed byte, the version, the project key (the byte sum of the project's
// ID), a few ignored bytes, the length and the data, each byte chained to
// the two before it.
func ovbaEncrypt(projectID string, data []byte, s *prng.Stream) []byte {
	seed := s.Bytes(1)[0]
	var key byte
	for _, c := range []byte(projectID) {
		key += c
	}
	out := []byte{seed, seed ^ 2, seed ^ key}
	plain1, enc1, enc2 := key, seed^key, seed^2
	put := func(c byte) {
		e := c ^ (enc2 + plain1)
		out = append(out, e)
		enc2, enc1, plain1 = enc1, e, c
	}
	ignored := s.Bytes(int(seed&6) / 2)
	for _, c := range ignored {
		put(c)
	}
	for _, c := range binary.LittleEndian.AppendUint32(nil, uint32(len(data))) {
		put(c)
	}
	for _, c := range data {
		put(c)
	}
	return out
}

// vbaNameMap is the PROJECTwm stream: each module's name in the code page
// and in UTF-16.
func vbaNameMap(modules []VBAModule) []byte {
	var out []byte
	for _, m := range modules {
		out = append(out, m.Name...)
		out = append(out, 0)
		out = append(out, utf16z(m.Name)...)
	}
	return append(out, 0, 0)
}

// The project's code page and locale: Windows-1252, English (United States).
const (
	vbaCodePage = 1252
	vbaLCID     = 0x0409
)

// stdoleLibid is the reference every project carries, to OLE Automation.
const stdoleLibid = `*\G{00020430-0000-0000-C000-000000000046}#2.0#0#C:\Windows\System32\stdole2.tlb#OLE Automation`

// vbaDir is the dir stream, before compression: the project's information,
// its one reference and its modules, as records.
func vbaDir(host string, modules []VBAModule) []byte {
	var b bytes.Buffer
	u16 := func(v uint16) { b.Write(binary.LittleEndian.AppendUint16(nil, v)) }
	u32 := func(v uint32) { b.Write(binary.LittleEndian.AppendUint32(nil, v)) }
	rec := func(id uint16, data []byte) {
		u16(id)
		u32(uint32(len(data)))
		b.Write(data)
	}
	le16 := func(v uint16) []byte { return binary.LittleEndian.AppendUint16(nil, v) }
	le32 := func(v uint32) []byte { return binary.LittleEndian.AppendUint32(nil, v) }

	rec(0x0001, le32(1)) // SysKind: 32-bit Windows
	rec(0x0002, le32(vbaLCID))
	rec(0x0014, le32(vbaLCID))
	rec(0x0003, le16(vbaCodePage))
	rec(0x0004, []byte(vbaProjectName[host]))
	rec(0x0005, nil) // doc string
	rec(0x0040, nil) // and in UTF-16
	rec(0x0006, nil) // help file
	rec(0x003D, nil) // and its second copy
	rec(0x0007, le32(0))
	rec(0x0008, le32(0))
	// The version record's size field is fixed at 4, though six bytes
	// follow it.
	u16(0x0009)
	u32(4)
	u32(1)
	u16(0)
	rec(0x000C, nil) // constants
	rec(0x003C, nil) // and in UTF-16

	rec(0x0016, []byte("stdole"))
	rec(0x003E, utf16le("stdole"))
	libid := binary.LittleEndian.AppendUint32(nil, uint32(len(stdoleLibid)))
	libid = append(libid, stdoleLibid...)
	libid = append(libid, 0, 0, 0, 0, 0, 0)
	rec(0x000D, libid)

	rec(0x000F, le16(uint16(len(modules))))
	rec(0x0013, le16(0xFFFF))
	for _, m := range modules {
		rec(0x0019, []byte(m.Name))
		rec(0x0047, utf16le(m.Name))
		rec(0x001A, []byte(m.Name)) // the stream is named for the module
		rec(0x0032, utf16le(m.Name))
		rec(0x001C, nil)
		rec(0x0048, nil)
		rec(0x0031, le32(0)) // the source starts the stream: no p-code before it
		rec(0x001E, le32(0))
		rec(0x002C, le16(0xFFFF))
		kind := uint16(vbaProcedural)
		if m.Document {
			kind = vbaDocument
		}
		rec(kind, nil)
		rec(0x002B, nil)
	}
	rec(0x0010, nil)
	return b.Bytes()
}

// OVBACompress compresses data as [MS-OVBA] 2.4.1 does: 4096-byte chunks,
// each a run of tokens that are literal bytes or copies of up to a few
// thousand bytes from earlier in the chunk, choosing at each step the
// longest match, nearest first, as the specification's own pseudocode does.
func OVBACompress(data []byte) []byte {
	out := []byte{0x01}
	for start := 0; start < len(data); start += 4096 {
		out = ovbaChunk(out, data, start, min(start+4096, len(data)))
	}
	return out
}

// ovbaChunk appends the chunk of data from start to end.
func ovbaChunk(out, data []byte, start, end int) []byte {
	header := len(out)
	out = append(out, 0, 0)
	for cur := start; cur < end; {
		flags := len(out)
		out = append(out, 0)
		for bit := 0; bit < 8 && cur < end; bit++ {
			offset, length := ovbaMatch(data, start, cur, end)
			if length == 0 {
				out = append(out, data[cur])
				cur++
				continue
			}
			bitCount := ovbaBitCount(cur - start)
			token := uint16(offset-1)<<(16-bitCount) | uint16(length-3)
			out = binary.LittleEndian.AppendUint16(out, token)
			out[flags] |= 1 << bit
			cur += length
		}
	}
	if size := len(out) - header; size <= 4098 {
		binary.LittleEndian.PutUint16(out[header:], 0xB000|uint16(size-3))
		return out
	}
	// Compression made it bigger: the chunk goes in raw, 4096 bytes padded
	// with zeros.
	out = append(out[:header], 0xFF, 0x3F)
	out = append(out, data[start:end]...)
	return append(out, make([]byte, 4096-(end-start))...)
}

// ovbaMatch finds the longest earlier copy, within the chunk, of the bytes
// at cur, preferring the nearest of equal length.
func ovbaMatch(data []byte, start, cur, end int) (offset, length int) {
	best, bestLen := 0, 0
	for cand := cur - 1; cand >= start; cand-- {
		n := 0
		for cur+n < end && data[cand+n] == data[cur+n] {
			n++
		}
		if n > bestLen {
			best, bestLen = cand, n
		}
	}
	if bestLen < 3 {
		return 0, 0
	}
	return cur - best, min(bestLen, 0xFFFF>>ovbaBitCount(cur-start)+3)
}

// ovbaBitCount is how many of a copy token's 16 bits hold the offset, at a
// distance diff into the chunk: enough for any offset back to its start,
// and at least four.
func ovbaBitCount(diff int) int {
	return max(bits.Len(uint(diff-1)), 4)
}
