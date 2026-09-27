package libgen

import (
	"encoding/binary"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"
)

// A PE here is a container for a parser to read, not a program to run. It has
// the headers, sections, import table and version resource that a forensic
// tool looks at, and its sections hold filler: nothing in the image is code,
// and its entry point does nothing. That is the point. A corpus needs files
// that debug/pe, pefile, Detect It Easy and the like can open and report on,
// and it must never contain something that could actually execute.
//
// The one exception is the DOS stub, the sixteen-bit "This program cannot be
// run in DOS mode" boilerplate that sits in every Windows binary. Leaving it
// out would itself be a forensic tell.

// PEMachines and PESubsystems are the closed sets a scenario may name.
var (
	PEMachines   = []string{"amd64", "i386", "arm64"}
	PESubsystems = []string{"console", "gui", "native"}
	// PESectionFlags are the characteristics a section may be given. With
	// none, they are inferred from the section's name.
	PESectionFlags = []string{"code", "initialized_data", "uninitialized_data", "execute", "read", "write", "discardable"}
)

const (
	peFileAlign    = 0x200
	peSectionAlign = 0x1000

	scnCode        = 0x00000020
	scnInitData    = 0x00000040
	scnUninitData  = 0x00000080
	scnDiscardable = 0x02000000
	scnExecute     = 0x20000000
	scnRead        = 0x40000000
	scnWrite       = 0x80000000
)

// MaxPESectionName is the eight bytes a PE section header holds for a name.
const MaxPESectionName = 8

// idataSection and rsrcSection are the sections BuildPE adds itself and then
// back-patches by name, once every section has an address.
const (
	idataSection = ".idata"
	rsrcSection  = ".rsrc"
)

// ReservedPESection reports whether a name belongs to a section BuildPE adds
// and fills in itself. A caller-supplied section of that name would have its
// contents overwritten by the import table or the version resource.
func ReservedPESection(name string) bool {
	return name == idataSection || name == rsrcSection
}

var peMachineCodes = map[string]uint16{"i386": 0x014c, "amd64": 0x8664, "arm64": 0xaa64}

var peSubsystemCodes = map[string]uint16{"native": 1, "gui": 2, "console": 3}

var peSectionFlagBits = map[string]uint32{
	"code": scnCode, "initialized_data": scnInitData, "uninitialized_data": scnUninitData,
	"execute": scnExecute, "read": scnRead, "write": scnWrite, "discardable": scnDiscardable,
}

// PESection is one section of the image.
type PESection struct {
	Name string
	// Data is what the section holds. fsagen fills it with the operation's
	// filler; nothing in it is executed.
	Data []byte
	// Flags are names from PESectionFlags. Empty means infer from Name.
	Flags []string
}

// PEImport is one DLL and the functions imported from it. The import table is
// what gives a file an imphash, which is how tools group related samples.
type PEImport struct {
	DLL       string
	Functions []string
}

// PEVersion is the VS_VERSIONINFO resource: the properties Windows Explorer
// and every metadata tool read off a binary.
type PEVersion struct {
	FileVersion      string // "1.2.3.4"
	ProductVersion   string
	CompanyName      string
	FileDescription  string
	InternalName     string
	OriginalFilename string
	ProductName      string
	LegalCopyright   string
}

// PESpec describes the executable to write.
type PESpec struct {
	Machine   string // one of PEMachines; empty means amd64
	Subsystem string // one of PESubsystems; empty means console
	DLL       bool
	Timestamp time.Time
	Sections  []PESection
	Imports   []PEImport
	Version   *PEVersion
	// Overlay is appended after the last section, where installers and packers
	// put their payload and where a tool reports "overlay".
	Overlay []byte
}

// Header and table sizes the PE format fixes.
const (
	dosHeaderLen     = 0x80 // the MZ header and the stub that follows it
	peSignatureLen   = 4    // "PE\0\0"
	coffHeaderLen    = 20
	optHeaderLen32   = 224
	optHeaderLen64   = 240
	sectionHeaderLen = 40
	// maxSections is how many sections the section table can describe.
	maxSections = 96
	// dataDirectories is the fixed number of data-directory slots.
	dataDirectories = 16
	// importDirIndex, resourceDirIndex and iatDirIndex are the slots the loader
	// reads for the import table, the resources and the import address table.
	importDirIndex   = 1
	resourceDirIndex = 2
	iatDirIndex      = 12
)

// placedSection is one section of the image and where it lands, both in memory
// and in the file.
type placedSection struct {
	name  string
	data  []byte
	flags uint32
	// vaddr and vsize are where the loader maps it.
	vaddr, vsize uint32
	// raw and rsize are where it sits in the file, both file-aligned.
	raw, rsize uint32
}

// peImage is an image being assembled: what it targets, its sections once they
// have addresses, and the header values that follow from them.
type peImage struct {
	spec PESpec
	// code and subsystem are the machine and subsystem the header names; wide
	// marks a 64-bit image, which changes the shape of the optional header.
	code, subsystem uint16
	wide            bool

	sections []placedSection
	// imports and versionBlob are laid out with everything else and filled in
	// afterwards: their length is fixed by the names and strings in them, but
	// the addresses inside them are only known once every section has one.
	imports     importPlan
	versionBlob []byte

	optSize       int
	sizeOfHeaders uint32
	sizeOfImage   uint32

	// The data directories that point into the sections above.
	importDir, importDirSize     uint32
	iatAddr, iatSize             uint32
	resourceDir, resourceDirSize uint32
}

// BuildPE assembles the image.
func BuildPE(s PESpec) ([]byte, error) {
	img, err := newPEImage(s)
	if err != nil {
		return nil, err
	}
	img.layout()
	img.fillDirectories()
	return img.bytes(), nil
}

// newPEImage resolves what the spec targets and builds the section list, adding
// the import and resource sections the image needs.
func newPEImage(s PESpec) (*peImage, error) {
	machine := or(s.Machine, "amd64")
	code, ok := peMachineCodes[machine]
	if !ok {
		return nil, fmt.Errorf("pe: unknown machine %q (want one of: %s)", machine, strings.Join(PEMachines, ", "))
	}
	subsystem := or(s.Subsystem, "console")
	sub, ok := peSubsystemCodes[subsystem]
	if !ok {
		return nil, fmt.Errorf("pe: unknown subsystem %q (want one of: %s)", subsystem, strings.Join(PESubsystems, ", "))
	}

	img := &peImage{spec: s, code: code, subsystem: sub, wide: machine != "i386"}
	if err := img.addSpecSections(); err != nil {
		return nil, err
	}
	img.addImportSection()
	img.addResourceSection()
	if len(img.sections) > maxSections {
		return nil, fmt.Errorf("pe: %d sections is more than an image holds", len(img.sections))
	}
	return img, nil
}

// addSpecSections adds the sections the scenario asked for.
func (img *peImage) addSpecSections() error {
	for _, in := range img.spec.Sections {
		if len(in.Name) > MaxPESectionName {
			return fmt.Errorf("pe: section name %q is longer than the eight bytes the format stores", in.Name)
		}
		flags, err := sectionFlags(in.Name, in.Flags)
		if err != nil {
			return err
		}
		img.sections = append(img.sections, placedSection{name: in.Name, data: in.Data, flags: flags})
	}
	if len(img.sections) == 0 {
		return fmt.Errorf("pe: an image needs at least one section")
	}
	return nil
}

// addImportSection reserves room for the import table, if there is one.
func (img *peImage) addImportSection() {
	img.imports = planImports(img.spec.Imports, img.wide)
	if img.imports.size == 0 {
		return
	}
	img.sections = append(img.sections, placedSection{
		name: idataSection, data: make([]byte, img.imports.size), flags: scnInitData | scnRead,
	})
}

// addResourceSection reserves room for the version resource, if there is one.
func (img *peImage) addResourceSection() {
	if img.spec.Version == nil {
		return
	}
	img.versionBlob = versionResource(*img.spec.Version, img.spec.DLL)
	img.sections = append(img.sections, placedSection{
		name: rsrcSection, data: make([]byte, resourceSize(len(img.versionBlob))), flags: scnInitData | scnRead,
	})
}

// layout gives every section its address in memory and its offset in the file,
// and settles how big the headers and the whole image are.
func (img *peImage) layout() {
	img.optSize = optHeaderLen32
	if img.wide {
		img.optSize = optHeaderLen64
	}
	headers := dosHeaderLen + peSignatureLen + coffHeaderLen + img.optSize + sectionHeaderLen*len(img.sections)
	img.sizeOfHeaders = align(uint32(headers), peFileAlign)

	va, off := uint32(peSectionAlign), img.sizeOfHeaders
	for i := range img.sections {
		sec := &img.sections[i]
		sec.vaddr, sec.vsize = va, uint32(len(sec.data))
		sec.raw, sec.rsize = off, align(uint32(len(sec.data)), peFileAlign)
		// A zero-length section still occupies one page in memory.
		va = align(va+max(sec.vsize, 1), peSectionAlign)
		off += sec.rsize
	}
	img.sizeOfImage = va
}

// fillDirectories renders the import table and the version resource, now that
// every section has an address, and records where the loader finds them.
func (img *peImage) fillDirectories() {
	for i := range img.sections {
		sec := &img.sections[i]
		switch sec.name {
		case idataSection:
			sec.data = img.imports.render(sec.vaddr)
			img.importDir, img.importDirSize = sec.vaddr, img.imports.descriptorSize
			img.iatAddr, img.iatSize = sec.vaddr+img.imports.iatOffset, img.imports.iatSize
		case rsrcSection:
			sec.data = resourceSection(img.versionBlob, sec.vaddr)
			img.resourceDir, img.resourceDirSize = sec.vaddr, uint32(len(sec.data))
		}
	}
}

// sectionSizes totals the section sizes the optional header reports, and the
// addresses it names: the entry point and the first section of each kind.
func (img *peImage) sectionSizes() (sizeOfCode, sizeOfInit, sizeOfUninit, entry, baseOfCode, baseOfData uint32) {
	for _, sec := range img.sections {
		switch {
		case sec.flags&scnCode != 0:
			sizeOfCode += sec.rsize
			setFirst(&baseOfCode, sec.vaddr)
			setFirst(&entry, sec.vaddr)
		case sec.flags&scnUninitData != 0:
			sizeOfUninit += sec.rsize
			setFirst(&baseOfData, sec.vaddr)
		default:
			sizeOfInit += sec.rsize
			setFirst(&baseOfData, sec.vaddr)
		}
	}
	return sizeOfCode, sizeOfInit, sizeOfUninit, entry, baseOfCode, baseOfData
}

// characteristics is the COFF flags word: what kind of image this is.
func (img *peImage) characteristics() uint16 {
	c := uint16(0x0002) // EXECUTABLE_IMAGE
	if img.wide {
		c |= 0x0020 // LARGE_ADDRESS_AWARE
	} else {
		c |= 0x0100 // 32BIT_MACHINE
	}
	if img.spec.DLL {
		c |= 0x2000 // DLL
	}
	return c
}

// imageBase is where the image prefers to be loaded, which depends on both its
// width and whether it is a library.
func (img *peImage) imageBase() uint64 {
	switch {
	case !img.wide && img.spec.DLL:
		return 0x10000000
	case !img.wide:
		return 0x400000
	case img.spec.DLL:
		return 0x180000000
	}
	return 0x140000000
}

// dllCharacteristics is what the image asks the loader to do with it.
func (img *peImage) dllCharacteristics() uint16 {
	c := uint16(0x0040 | 0x0100 | 0x8000) // dynamic base, NX, terminal-server aware
	if img.wide {
		c |= 0x0020 // high-entropy address space
	}
	return c
}

// timestamp is the build stamp in the header. A zero stamp is a real thing to
// want: it is what a reproducible build writes, and tools report it as such.
func (img *peImage) timestamp() uint32 {
	if img.spec.Timestamp.IsZero() || img.spec.Timestamp.Unix() <= 0 {
		return 0
	}
	return uint32(img.spec.Timestamp.UTC().Unix())
}

// bytes writes the whole image: the headers, the section table, then each
// section's bytes at its file offset, and finally the header checksum over all
// of it.
func (img *peImage) bytes() []byte {
	b := make([]byte, 0, int(img.sizeOfHeaders))
	b = append(b, dosHeader()...)
	b = img.writeCOFFHeader(b)
	b, checksumAt := img.writeOptionalHeader(b)
	b = img.writeSectionTable(b)
	b = append(b, make([]byte, int(img.sizeOfHeaders)-len(b))...)
	b = img.writeSectionData(b)

	binary.LittleEndian.PutUint32(b[checksumAt:], peChecksum(b, checksumAt))
	return b
}

// writeCOFFHeader writes the PE signature and the COFF header after it.
func (img *peImage) writeCOFFHeader(b []byte) []byte {
	b = append(b, 'P', 'E', 0, 0)
	b = le16(b, img.code)
	b = le16(b, uint16(len(img.sections)))
	b = le32(b, img.timestamp())
	b = le32(b, 0) // no symbol table
	b = le32(b, 0)
	b = le16(b, uint16(img.optSize))
	return le16(b, img.characteristics())
}

// writeOptionalHeader writes the optional header and the data directories,
// returning the offset of the checksum field, which is patched once the whole
// file exists.
func (img *peImage) writeOptionalHeader(b []byte) ([]byte, int) {
	sizeOfCode, sizeOfInit, sizeOfUninit, entry, baseOfCode, baseOfData := img.sectionSizes()
	imageBase := img.imageBase()

	if img.wide {
		b = le16(b, 0x20b) // PE32+
	} else {
		b = le16(b, 0x10b) // PE32
	}
	b = append(b, 14, 0) // linker version
	b = le32(b, sizeOfCode)
	b = le32(b, sizeOfInit)
	b = le32(b, sizeOfUninit)
	b = le32(b, entry)
	b = le32(b, baseOfCode)
	if !img.wide {
		b = le32(b, baseOfData)
		b = le32(b, uint32(imageBase))
	} else {
		b = le64(b, imageBase)
	}
	b = le32(b, peSectionAlign)
	b = le32(b, peFileAlign)
	b = le16(b, 6) // operating system version
	b = le16(b, 0)
	major, minor := img.imageVersion()
	b = le16(b, major)
	b = le16(b, minor)
	b = le16(b, 6) // subsystem version
	b = le16(b, 0)
	b = le32(b, 0) // Win32VersionValue
	b = le32(b, img.sizeOfImage)
	b = le32(b, img.sizeOfHeaders)
	checksumAt := len(b)
	b = le32(b, 0) // patched once the whole file exists
	b = le16(b, img.subsystem)
	b = le16(b, img.dllCharacteristics())
	b = img.writeStackAndHeap(b)
	b = le32(b, 0) // loader flags
	b = le32(b, dataDirectories)
	return img.writeDataDirectories(b), checksumAt
}

// imageVersion is the image version in the header, taken from the version
// resource when there is one.
func (img *peImage) imageVersion() (major, minor uint16) {
	if img.spec.Version == nil {
		return 0, 0
	}
	return firstTwo(img.spec.Version.FileVersion)
}

// writeStackAndHeap writes the four reserve and commit sizes, in the pointer
// width of the image.
func (img *peImage) writeStackAndHeap(b []byte) []byte {
	const reserve, commit = 0x100000, 0x1000
	for _, v := range []uint64{reserve, commit, reserve, commit} {
		if img.wide {
			b = le64(b, v)
			continue
		}
		b = le32(b, uint32(v))
	}
	return b
}

// writeDataDirectories writes every directory slot, filling in the three this
// image uses and leaving the rest empty.
func (img *peImage) writeDataDirectories(b []byte) []byte {
	dirs := make([][2]uint32, dataDirectories)
	dirs[importDirIndex] = [2]uint32{img.importDir, img.importDirSize}
	dirs[resourceDirIndex] = [2]uint32{img.resourceDir, img.resourceDirSize}
	dirs[iatDirIndex] = [2]uint32{img.iatAddr, img.iatSize}
	for _, dir := range dirs {
		b = le32(b, dir[0])
		b = le32(b, dir[1])
	}
	return b
}

// writeSectionTable writes one header per section.
func (img *peImage) writeSectionTable(b []byte) []byte {
	for _, sec := range img.sections {
		var name [MaxPESectionName]byte
		copy(name[:], sec.name)
		b = append(b, name[:]...)
		b = le32(b, max(sec.vsize, 1))
		b = le32(b, sec.vaddr)
		b = le32(b, sec.rsize)
		b = le32(b, sec.raw)
		b = le32(b, 0) // relocations
		b = le32(b, 0) // line numbers
		b = le16(b, 0)
		b = le16(b, 0)
		b = le32(b, sec.flags)
	}
	return b
}

// writeSectionData writes each section's bytes, padded to its file-aligned
// length, and then any overlay appended after the image.
func (img *peImage) writeSectionData(b []byte) []byte {
	for _, sec := range img.sections {
		b = append(b, sec.data...)
		b = append(b, make([]byte, int(sec.rsize)-len(sec.data))...)
	}
	return append(b, img.spec.Overlay...)
}

func sectionFlags(name string, names []string) (uint32, error) {
	if len(names) == 0 {
		switch name {
		case ".text":
			return scnCode | scnExecute | scnRead, nil
		case ".data":
			return scnInitData | scnRead | scnWrite, nil
		case ".bss":
			return scnUninitData | scnRead | scnWrite, nil
		case ".reloc":
			return scnInitData | scnRead | scnDiscardable, nil
		default:
			return scnInitData | scnRead, nil
		}
	}
	var out uint32
	for _, n := range names {
		bit, ok := peSectionFlagBits[n]
		if !ok {
			return 0, fmt.Errorf("pe: unknown section characteristic %q (want one of: %s)", n, strings.Join(PESectionFlags, ", "))
		}
		out |= bit
	}
	return out, nil
}

// dosHeader is the MS-DOS header and the stub every Windows binary carries.
func dosHeader() []byte {
	h := make([]byte, 0x80)
	copy(h, []byte{
		'M', 'Z', 0x90, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00,
		0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	})
	binary.LittleEndian.PutUint32(h[0x3c:], 0x80)
	// The stub: print the message and exit. It is the only code in the file.
	copy(h[0x40:], []byte{0x0e, 0x1f, 0xba, 0x0e, 0x00, 0xb4, 0x09, 0xcd, 0x21, 0xb8, 0x01, 0x4c, 0xcd, 0x21})
	copy(h[0x4e:], "This program cannot be run in DOS mode.\r\r\n$")
	return h
}

// peChecksum is the algorithm Windows uses: a folded sum of sixteen-bit words
// with the checksum field itself read as zero, plus the file's length.
func peChecksum(b []byte, skip int) uint32 {
	var sum uint64
	for i := 0; i+1 < len(b); i += 2 {
		if i == skip || i == skip+2 {
			continue
		}
		sum += uint64(binary.LittleEndian.Uint16(b[i:]))
		sum = sum&0xffff + sum>>16
	}
	if len(b)%2 == 1 {
		sum += uint64(b[len(b)-1])
		sum = sum&0xffff + sum>>16
	}
	sum = sum&0xffff + sum>>16
	return uint32(sum) + uint32(len(b))
}

// importPlan is the shape of an .idata section: every length is known from
// the names alone, so the section can be sized before it is placed and filled
// in once its address is known.
type importPlan struct {
	imports        []PEImport
	wide           bool
	ptr            uint32
	descriptorSize uint32
	iltOffset      uint32
	iatOffset      uint32
	iatSize        uint32
	namesOffset    uint32 // hint/name entries
	dllOffset      uint32
	size           uint32
	hintAt         []uint32 // per dll, per function
	dllAt          []uint32
}

func planImports(imports []PEImport, wide bool) importPlan {
	p := importPlan{imports: imports, wide: wide, ptr: 4}
	if wide {
		p.ptr = 8
	}
	if len(imports) == 0 {
		return p
	}
	p.descriptorSize = uint32(20 * (len(imports) + 1))
	p.iltOffset = p.descriptorSize
	thunks := uint32(0)
	for _, im := range imports {
		thunks += uint32(len(im.Functions)+1) * p.ptr
	}
	p.iatOffset = p.iltOffset + thunks
	p.iatSize = thunks
	p.namesOffset = p.iatOffset + thunks

	at := p.namesOffset
	for _, im := range imports {
		for _, fn := range im.Functions {
			p.hintAt = append(p.hintAt, at)
			// A hint/name entry is a 2-byte hint, the name, and a NUL, and
			// each one starts on an even offset.
			at = align(at+uint32(2+len(fn)+1), 2)
		}
	}
	p.dllOffset = at
	for _, im := range imports {
		p.dllAt = append(p.dllAt, at)
		at += uint32(len(im.DLL) + 1)
	}
	p.size = at
	return p
}

// render writes the section's bytes now that it sits at base.
func (p importPlan) render(base uint32) []byte {
	if p.size == 0 {
		return nil
	}
	out := make([]byte, p.size)
	ilt, iat, fn := p.iltOffset, p.iatOffset, 0
	for i, im := range p.imports {
		d := 20 * i
		binary.LittleEndian.PutUint32(out[d:], base+ilt)
		binary.LittleEndian.PutUint32(out[d+12:], base+p.dllAt[i])
		binary.LittleEndian.PutUint32(out[d+16:], base+iat)
		for range im.Functions {
			// The lookup table and the address table start out identical; the
			// loader overwrites the address table with real addresses.
			rva := base + p.hintAt[fn]
			p.putThunk(out[ilt:], rva)
			p.putThunk(out[iat:], rva)
			ilt += p.ptr
			iat += p.ptr
			fn++
		}
		ilt += p.ptr // the null thunk that ends each list
		iat += p.ptr
	}
	fn = 0
	for _, im := range p.imports {
		for _, name := range im.Functions {
			copy(out[p.hintAt[fn]+2:], name)
			fn++
		}
	}
	for i, im := range p.imports {
		copy(out[p.dllAt[i]:], im.DLL)
	}
	return out
}

// ParseImports turns "kernel32.dll!CreateFileW" entries into one PEImport per
// DLL, keeping the order each DLL and function first appears in.
func ParseImports(entries []string) ([]PEImport, error) {
	var out []PEImport
	index := map[string]int{}
	for _, e := range entries {
		dll, fn, ok := strings.Cut(e, "!")
		dll, fn = strings.TrimSpace(dll), strings.TrimSpace(fn)
		if !ok || dll == "" || fn == "" {
			return nil, fmt.Errorf("import %q: write it as dll!function, for example kernel32.dll!CreateFileW", e)
		}
		if strings.ContainsAny(dll+fn, "\x00\r\n") {
			return nil, fmt.Errorf("import %q: a name cannot hold a NUL or a line break", e)
		}
		key := strings.ToLower(dll)
		i, seen := index[key]
		if !seen {
			index[key] = len(out)
			out = append(out, PEImport{DLL: dll})
			i = len(out) - 1
		}
		out[i].Functions = append(out[i].Functions, fn)
	}
	return out, nil
}

// resourceSize is the length of a .rsrc section holding one version resource:
// three one-entry directories, a data entry, and the blob itself.
func resourceSize(blob int) int { return 3*24 + 16 + blob }

// resourceSection writes the three-level resource tree Windows expects (type,
// then name, then language) around one VS_VERSIONINFO blob.
func resourceSection(blob []byte, base uint32) []byte {
	out := make([]byte, resourceSize(len(blob)))
	dir := func(at int, entryID uint32, target int, isDir bool) {
		binary.LittleEndian.PutUint16(out[at+12:], 0) // named entries
		binary.LittleEndian.PutUint16(out[at+14:], 1) // id entries
		binary.LittleEndian.PutUint32(out[at+16:], entryID)
		v := uint32(target)
		if isDir {
			v |= 0x80000000
		}
		binary.LittleEndian.PutUint32(out[at+20:], v)
	}
	dir(0, 16, 24, true)       // RT_VERSION
	dir(24, 1, 48, true)       // resource id 1
	dir(48, 0x0409, 72, false) // US English
	binary.LittleEndian.PutUint32(out[72:], base+88)
	binary.LittleEndian.PutUint32(out[76:], uint32(len(blob)))
	copy(out[88:], blob)
	return out
}

// verNode is one node of the VS_VERSIONINFO tree, which is a sequence of
// length-prefixed records aligned to four bytes.
type verNode struct {
	key      string
	value    []byte
	valueLen uint16 // characters for text, bytes for binary
	text     bool
	children []*verNode
}

func (n *verNode) bytes() []byte {
	out := make([]byte, 6)
	out = append(out, utf16z(n.key)...)
	out = pad4(out)
	out = append(out, n.value...)
	// Each child starts on a four-byte boundary. The padding between nodes
	// counts towards this node's length; any that aligns the node after it
	// does not, so it is added before a child rather than after.
	for _, c := range n.children {
		out = pad4(out)
		out = append(out, c.bytes()...)
	}
	if len(out) > math.MaxUint16 {
		// The node records its own length in 16 bits, so a longer one would
		// wrap and describe a resource the parser could not walk. Only a
		// version string far longer than any real one reaches this.
		panic(fmt.Sprintf("pe: version resource node %q is %d bytes, more than the format records", n.key, len(out)))
	}
	binary.LittleEndian.PutUint16(out, uint16(len(out)))
	binary.LittleEndian.PutUint16(out[2:], n.valueLen)
	if n.text {
		binary.LittleEndian.PutUint16(out[4:], 1)
	}
	return out
}

func textNode(key, value string) *verNode {
	v := utf16z(value)
	return &verNode{key: key, value: v, valueLen: uint16(len(v) / 2), text: true}
}

// versionResource builds VS_VERSIONINFO: the fixed block every tool reads and
// the string table Explorer shows.
func versionResource(v PEVersion, dll bool) []byte {
	fileMS, fileLS := versionParts(v.FileVersion)
	prodMS, prodLS := versionParts(or(v.ProductVersion, v.FileVersion))
	fixed := make([]byte, 0, 52)
	fixed = le32(fixed, 0xfeef04bd)
	fixed = le32(fixed, 0x00010000)
	fixed = le32(fixed, fileMS)
	fixed = le32(fixed, fileLS)
	fixed = le32(fixed, prodMS)
	fixed = le32(fixed, prodLS)
	fixed = le32(fixed, 0x3f) // file flags mask
	fixed = le32(fixed, 0)    // no debug or prerelease flags
	fixed = le32(fixed, 0x40004)
	if dll {
		fixed = le32(fixed, 2) // VFT_DLL
	} else {
		fixed = le32(fixed, 1) // VFT_APP
	}
	fixed = le32(fixed, 0) // subtype
	fixed = le32(fixed, 0) // file date
	fixed = le32(fixed, 0)

	var strings_ []*verNode
	for _, kv := range [][2]string{
		{"CompanyName", v.CompanyName},
		{"FileDescription", v.FileDescription},
		{"FileVersion", v.FileVersion},
		{"InternalName", v.InternalName},
		{"LegalCopyright", v.LegalCopyright},
		{"OriginalFilename", v.OriginalFilename},
		{"ProductName", v.ProductName},
		{"ProductVersion", or(v.ProductVersion, v.FileVersion)},
	} {
		if kv[1] != "" {
			strings_ = append(strings_, textNode(kv[0], kv[1]))
		}
	}
	table := &verNode{key: "040904b0", text: true, children: strings_}
	sfi := &verNode{key: "StringFileInfo", text: true, children: []*verNode{table}}
	translation := &verNode{key: "Translation", value: []byte{0x09, 0x04, 0xb0, 0x04}, valueLen: 4}
	vfi := &verNode{key: "VarFileInfo", text: true, children: []*verNode{translation}}

	root := &verNode{key: "VS_VERSION_INFO", value: fixed, valueLen: 52, children: []*verNode{sfi, vfi}}
	return root.bytes()
}

// versionParts splits "1.2.3.4" into the two words the fixed block stores.
func versionParts(s string) (ms, ls uint32) {
	var n [4]uint32
	for i, part := range strings.SplitN(s, ".", 4) {
		v, err := strconv.ParseUint(strings.TrimSpace(part), 10, 16)
		if err == nil {
			n[i] = uint32(v)
		}
	}
	return n[0]<<16 | n[1], n[2]<<16 | n[3]
}

func firstTwo(s string) (uint16, uint16) {
	ms, _ := versionParts(s)
	return uint16(ms >> 16), uint16(ms)
}

func utf16z(s string) []byte {
	out := make([]byte, 0, 2*len(s)+2)
	for _, u := range utf16.Encode([]rune(s)) {
		out = append(out, byte(u), byte(u>>8))
	}
	return append(out, 0, 0)
}

func pad4(b []byte) []byte {
	for len(b)%4 != 0 {
		b = append(b, 0)
	}
	return b
}

func align(v, to uint32) uint32 { return (v + to - 1) / to * to }

func le16(b []byte, v uint16) []byte { return append(b, byte(v), byte(v>>8)) }

func le32(b []byte, v uint32) []byte {
	return append(b, byte(v), byte(v>>8), byte(v>>16), byte(v>>24))
}

func le64(b []byte, v uint64) []byte {
	return append(le32(b, uint32(v)), byte(v>>32), byte(v>>40), byte(v>>48), byte(v>>56))
}

func or(a, b string) string {
	if strings.TrimSpace(a) == "" {
		return b
	}
	return a
}

// setFirst records a value the first time one is seen, leaving a slot that is
// already set alone. The PE header names the first section of each kind.
func setFirst(slot *uint32, v uint32) {
	if *slot == 0 {
		*slot = v
	}
}

// putThunk writes one import thunk, in the pointer width of the image.
func (p importPlan) putThunk(out []byte, rva uint32) {
	if p.wide {
		binary.LittleEndian.PutUint64(out, uint64(rva))
		return
	}
	binary.LittleEndian.PutUint32(out, rva)
}
