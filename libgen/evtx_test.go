package libgen

import (
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"strings"
	"testing"
	"time"
	"unicode/utf16"

	"github.com/aoiflux/libntfs"
)

// sampleEvtxSpec is a Security log as an intrusion leaves it: a network
// logon, the process it started, then the log cleared.
func sampleEvtxSpec() EvtxSpec {
	at := time.Date(2024, 3, 15, 9, 30, 12, 345678900, time.UTC)
	logon, _ := EvtxBuiltins(4624)
	logon.Event.Time, logon.Event.ProcessID, logon.Event.ThreadID = at, 724, 1408
	set(&logon.Event, "TargetUserSid", "S-1-5-21-3623811015-3361044348-30300820-1013")
	set(&logon.Event, "TargetUserName", "user1")
	set(&logon.Event, "TargetDomainName", "CORP")
	set(&logon.Event, "TargetLogonId", "0x3e7a2c1")
	set(&logon.Event, "LogonType", "10")
	set(&logon.Event, "IpAddress", "203.0.113.7")
	set(&logon.Event, "LogonGuid", "{0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0}")

	proc, _ := EvtxBuiltins(4688)
	proc.Event.Time, proc.Event.ProcessID, proc.Event.ThreadID = at.Add(90*time.Second), 4, 3120
	set(&proc.Event, "NewProcessName", `C:\Windows\System32\cmd.exe`)
	set(&proc.Event, "CommandLine", `cmd.exe /c whoami`)
	set(&proc.Event, "NewProcessId", "0x1a2c")

	cleared, _ := EvtxBuiltins(1102)
	cleared.Event.Time, cleared.Event.ProcessID, cleared.Event.ThreadID = at.Add(time.Hour), 1180, 4412
	set(&cleared.Event, "SubjectUserName", "user1")

	return EvtxSpec{Channel: "Security", Computer: "WS01.corp.example", FirstRecordID: 1001,
		Events: []EvtxEvent{logon.Event, proc.Event, cleared.Event}}
}

func set(ev *EvtxEvent, name, value string) {
	for i := range ev.Fields {
		if ev.Fields[i].Name == name {
			ev.Fields[i].Value = value
			return
		}
	}
	panic("no field " + name)
}

// evtxRead is a log as a reader finds it.
type evtxRead struct {
	records []evtxRecordRead
	chunks  int
	next    uint64
}

type evtxRecordRead struct {
	id   uint64
	time time.Time
	xml  string
}

// readEvtx parses a log the way libevtx documents the format, checking every
// CRC and count, and renders each record's binary XML to text in the form
// Windows' own ToXml gives it.
func readEvtx(t *testing.T, data []byte) evtxRead {
	t.Helper()
	le := binary.LittleEndian
	if string(data[:8]) != "ElfFile\x00" {
		t.Fatalf("file signature %q", data[:8])
	}
	if got := crc32.ChecksumIEEE(data[:120]); got != le.Uint32(data[124:]) {
		t.Errorf("file header CRC %#x, stored %#x", got, le.Uint32(data[124:]))
	}
	if minor, major := le.Uint16(data[36:]), le.Uint16(data[38:]); major != 3 || minor != 2 {
		t.Errorf("format version %d.%d, want 3.2", major, minor)
	}
	n := int(le.Uint16(data[42:]))
	if len(data) != evtxFileHeaderSize+n*evtxChunkSize {
		t.Fatalf("%d bytes for %d chunks", len(data), n)
	}
	if last := le.Uint64(data[16:]); last != uint64(n-1) {
		t.Errorf("last chunk %d, want %d", last, n-1)
	}
	out := evtxRead{chunks: n, next: le.Uint64(data[24:])}
	for i := range n {
		chunk := data[evtxFileHeaderSize+i*evtxChunkSize:][:evtxChunkSize]
		if string(chunk[:8]) != "ElfChnk\x00" {
			t.Fatalf("chunk %d signature %q", i, chunk[:8])
		}
		free := le.Uint32(chunk[48:])
		if got := crc32.ChecksumIEEE(chunk[evtxChunkHeaderSize:free]); got != le.Uint32(chunk[52:]) {
			t.Errorf("chunk %d records CRC %#x, stored %#x", i, got, le.Uint32(chunk[52:]))
		}
		h := crc32.NewIEEE()
		h.Write(chunk[:120])
		h.Write(chunk[128:evtxChunkHeaderSize])
		if h.Sum32() != le.Uint32(chunk[124:]) {
			t.Errorf("chunk %d header CRC %#x, stored %#x", i, h.Sum32(), le.Uint32(chunk[124:]))
		}
		first, last := le.Uint64(chunk[24:]), le.Uint64(chunk[32:])
		off := uint32(evtxChunkHeaderSize)
		for id := first; id <= last; id++ {
			rec := chunk[off:]
			size := le.Uint32(rec[4:])
			if string(rec[:4]) != "\x2a\x2a\x00\x00" || le.Uint32(rec[size-4:]) != size || size%8 != 0 {
				t.Fatalf("chunk %d record at %#x: signature % x, size %d, copy %d", i, off, rec[:4], size, le.Uint32(rec[size-4:]))
			}
			if got := le.Uint64(rec[8:]); got != id {
				t.Errorf("chunk %d: record id %d, want %d", i, got, id)
			}
			r := evtxRenderer{chunk: chunk, t: t}
			xml := r.record(int(off) + 24)
			ft := le.Uint64(rec[16:])
			out.records = append(out.records, evtxRecordRead{
				id:   id,
				time: libntfs.FiletimeToTime(ft),
				xml:  xml,
			})
			if id == last && off != le.Uint32(chunk[44:]) {
				t.Errorf("chunk %d: last record at %#x, header says %#x", i, off, le.Uint32(chunk[44:]))
			}
			off += size
		}
		if off != free {
			t.Errorf("chunk %d: records end at %#x, free space starts at %#x", i, off, free)
		}
	}
	return out
}

// evtxRenderer turns a record's binary XML into text.
type evtxRenderer struct {
	chunk []byte
	t     *testing.T
}

func (r evtxRenderer) u16(p int) int { return int(binary.LittleEndian.Uint16(r.chunk[p:])) }
func (r evtxRenderer) u32(p int) int { return int(binary.LittleEndian.Uint32(r.chunk[p:])) }

func (r evtxRenderer) utf16(p, units int) string {
	u := make([]uint16, units)
	for i := range u {
		u[i] = uint16(r.u16(p + 2*i))
	}
	return string(utf16.Decode(u))
}

// name reads a name reference at p and returns the name and where the
// reference ends: right after the offset, or after the name itself when it
// is stored inline. It checks the name's hash.
func (r evtxRenderer) name(p int) (string, int) {
	off := r.u32(p)
	n := r.u16(off + 6)
	s := r.utf16(off+8, n)
	h := uint32(0)
	for _, u := range utf16.Encode([]rune(s)) {
		h = h*65599 + uint32(u)
	}
	if uint16(h) != uint16(r.u16(off+4)) {
		r.t.Errorf("name %q has hash %#x, want %#x", s, r.u16(off+4), uint16(h))
	}
	if off == p+4 {
		return s, off + 8 + 2*(n+1)
	}
	return s, p + 4
}

type evtxSub struct {
	typ  byte
	data []byte
}

// record renders the record's fragment: a template instance and its values.
func (r evtxRenderer) record(p int) string {
	if r.chunk[p] != 0x0f || r.chunk[p+4] != 0x0c {
		r.t.Fatalf("record at %#x does not start with a fragment holding a template instance", p)
	}
	p += 6
	def := r.u32(p + 4)
	p += 8
	bodySize := r.u32(def + 20)
	if def == p {
		p += 24 + bodySize
	}
	count := r.u32(p)
	p += 4
	subs := make([]evtxSub, count)
	q := p + 4*count
	for i := range subs {
		size := r.u16(p + 4*i)
		subs[i] = evtxSub{r.chunk[p+4*i+2], r.chunk[q : q+size]}
		q += size
	}
	if r.chunk[q] != 0x00 {
		r.t.Errorf("record fragment not closed at %#x", q)
	}
	body := def + 24
	if r.chunk[body] != 0x0f {
		r.t.Fatalf("template at %#x has no fragment header", def)
	}
	xml, end := r.element(body+4, subs)
	if r.chunk[end] != 0x00 || end+1 != body+bodySize {
		r.t.Errorf("template at %#x: element ends at %#x, data at %#x", def, end, body+bodySize)
	}
	return xml
}

// element renders the element at p and returns where it ends.
func (r evtxRenderer) element(p int, subs []evtxSub) (string, int) {
	tok := r.chunk[p]
	start := p
	size := r.u32(p + 3)
	name, p := r.name(p + 7)
	var b strings.Builder
	b.WriteString("<" + name)
	if tok == 0x41 {
		p += 4
		for {
			last := r.chunk[p] == 0x06
			var attr, val string
			attr, p = r.name(p + 1)
			val, p = r.value(p, subs)
			fmt.Fprintf(&b, " %s='%s'", attr, val)
			if last {
				break
			}
		}
	}
	switch r.chunk[p] {
	case 0x03:
		b.WriteString("/>")
		p++
	case 0x02:
		b.WriteString(">")
		p++
		for r.chunk[p] != 0x04 {
			if r.chunk[p]&0xbf == 0x01 {
				var child string
				child, p = r.element(p, subs)
				b.WriteString(child)
				continue
			}
			var text string
			text, p = r.value(p, subs)
			b.WriteString(text)
		}
		b.WriteString("</" + name + ">")
		p++
	default:
		r.t.Fatalf("element %s: token %#x where its start tag should close", name, r.chunk[p])
	}
	if got := p - start - 7; got != size {
		r.t.Errorf("element %s is %d bytes, its size says %d", name, got, size)
	}
	return b.String(), p
}

// value renders literal text or a substitution.
func (r evtxRenderer) value(p int, subs []evtxSub) (string, int) {
	switch r.chunk[p] {
	case 0x05, 0x45:
		n := r.u16(p + 2)
		return r.utf16(p+4, n), p + 4 + 2*n
	case 0x0d, 0x0e:
		s := subs[r.u16(p+1)]
		if s.typ != r.chunk[p+3] {
			r.t.Errorf("substitution %d is a %#x, the template says %#x", r.u16(p+1), s.typ, r.chunk[p+3])
		}
		return formatEvtxValue(s), p + 4
	}
	r.t.Fatalf("token %#x at %#x is not a value", r.chunk[p], p)
	return "", 0
}

// formatEvtxValue renders a value as Windows' ToXml does.
func formatEvtxValue(s evtxSub) string {
	le := binary.LittleEndian
	switch s.typ {
	case 0x01:
		u := make([]uint16, len(s.data)/2)
		for i := range u {
			u[i] = le.Uint16(s.data[2*i:])
		}
		return string(utf16.Decode(u))
	case 0x04:
		return fmt.Sprint(s.data[0])
	case 0x06:
		return fmt.Sprint(le.Uint16(s.data))
	case 0x08:
		return fmt.Sprint(le.Uint32(s.data))
	case 0x0a:
		return fmt.Sprint(le.Uint64(s.data))
	case 0x14:
		return fmt.Sprintf("0x%x", le.Uint32(s.data))
	case 0x15:
		return fmt.Sprintf("0x%x", le.Uint64(s.data))
	case 0x0f:
		// Windows renders a GUID value in lower case, unlike its own
		// literal text, which it leaves as written.
		return fmt.Sprintf("{%08x-%04x-%04x-%x-%x}", le.Uint32(s.data), le.Uint16(s.data[4:]), le.Uint16(s.data[6:]), s.data[8:10], s.data[10:16])
	case 0x11:
		ft := le.Uint64(s.data)
		t := libntfs.FiletimeToTime(ft)
		return t.Format("2006-01-02T15:04:05.0000000Z")
	case 0x13:
		auth := uint64(0)
		for _, b := range s.data[2:8] {
			auth = auth<<8 | uint64(b)
		}
		out := fmt.Sprintf("S-%d-%d", s.data[0], auth)
		for i := 0; i < int(s.data[1]); i++ {
			out += fmt.Sprintf("-%d", le.Uint32(s.data[8+4*i:]))
		}
		return out
	}
	return fmt.Sprintf("?%#x", s.typ)
}

// sampleEvtxXML is the XML of sampleEvtxSpec's events, as Windows' ToXml
// renders them.
var sampleEvtxXML = []string{
	`<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-A5BA-3E3B0328C30D}'/><EventID>4624</EventID><Version>2</Version><Level>0</Level><Task>12544</Task><Opcode>0</Opcode><Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime='2024-03-15T09:30:12.3456789Z'/><EventRecordID>1001</EventRecordID><Correlation/><Execution ProcessID='724' ThreadID='1408'/><Channel>Security</Channel><Computer>WS01.corp.example</Computer><Security/></System><EventData><Data Name='SubjectUserSid'>S-1-0-0</Data><Data Name='SubjectUserName'>-</Data><Data Name='SubjectDomainName'>-</Data><Data Name='SubjectLogonId'>0x0</Data><Data Name='TargetUserSid'>S-1-5-21-3623811015-3361044348-30300820-1013</Data><Data Name='TargetUserName'>user1</Data><Data Name='TargetDomainName'>CORP</Data><Data Name='TargetLogonId'>0x3e7a2c1</Data><Data Name='LogonType'>10</Data><Data Name='LogonProcessName'>-</Data><Data Name='AuthenticationPackageName'>-</Data><Data Name='WorkstationName'>-</Data><Data Name='LogonGuid'>{0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0}</Data><Data Name='TransmittedServices'>-</Data><Data Name='LmPackageName'>-</Data><Data Name='KeyLength'>0</Data><Data Name='ProcessId'>0x0</Data><Data Name='ProcessName'>-</Data><Data Name='IpAddress'>203.0.113.7</Data><Data Name='IpPort'>-</Data><Data Name='ImpersonationLevel'>%%1833</Data><Data Name='RestrictedAdminMode'>-</Data><Data Name='TargetOutboundUserName'>-</Data><Data Name='TargetOutboundDomainName'>-</Data><Data Name='VirtualAccount'>%%1843</Data><Data Name='TargetLinkedLogonId'>0x0</Data><Data Name='ElevatedToken'>%%1842</Data></EventData></Event>`,
	`<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-A5BA-3E3B0328C30D}'/><EventID>4688</EventID><Version>2</Version><Level>0</Level><Task>13312</Task><Opcode>0</Opcode><Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime='2024-03-15T09:31:42.3456789Z'/><EventRecordID>1002</EventRecordID><Correlation/><Execution ProcessID='4' ThreadID='3120'/><Channel>Security</Channel><Computer>WS01.corp.example</Computer><Security/></System><EventData><Data Name='SubjectUserSid'>S-1-0-0</Data><Data Name='SubjectUserName'>-</Data><Data Name='SubjectDomainName'>-</Data><Data Name='SubjectLogonId'>0x0</Data><Data Name='NewProcessId'>0x1a2c</Data><Data Name='NewProcessName'>C:\Windows\System32\cmd.exe</Data><Data Name='TokenElevationType'>%%1936</Data><Data Name='ProcessId'>0x0</Data><Data Name='CommandLine'>cmd.exe /c whoami</Data><Data Name='TargetUserSid'>S-1-0-0</Data><Data Name='TargetUserName'>-</Data><Data Name='TargetDomainName'>-</Data><Data Name='TargetLogonId'>0x0</Data><Data Name='ParentProcessName'>-</Data><Data Name='MandatoryLabel'>S-1-16-8192</Data></EventData></Event>`,
	`<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Eventlog' Guid='{FC65DDD8-D6EF-4962-83D5-6E5CFE9CE148}'/><EventID>1102</EventID><Version>0</Version><Level>4</Level><Task>104</Task><Opcode>0</Opcode><Keywords>0x4020000000000000</Keywords><TimeCreated SystemTime='2024-03-15T10:30:12.3456789Z'/><EventRecordID>1003</EventRecordID><Correlation/><Execution ProcessID='1180' ThreadID='4412'/><Channel>Security</Channel><Computer>WS01.corp.example</Computer><Security/></System><UserData><LogFileCleared xmlns='http://manifests.microsoft.com/win/2004/08/windows/eventlog'><SubjectUserSid>S-1-0-0</SubjectUserSid><SubjectUserName>user1</SubjectUserName><SubjectDomainName>-</SubjectDomainName><SubjectLogonId>0x0</SubjectLogonId></LogFileCleared></UserData></Event>`,
}

// TestEvtxReadBack: a reader written from the format's documentation finds
// every CRC, size and count right and renders each record to the XML the
// events describe.
func TestEvtxReadBack(t *testing.T) {
	spec := sampleEvtxSpec()
	data, err := BuildEvtx(spec)
	if err != nil {
		t.Fatal(err)
	}
	got := readEvtx(t, data)
	if got.chunks != 1 || got.next != 1004 || len(got.records) != 3 {
		t.Fatalf("%d chunks, next record id %d, %d records; want 1, 1004, 3", got.chunks, got.next, len(got.records))
	}
	for i, r := range got.records {
		if r.id != uint64(1001+i) || !r.time.Equal(spec.Events[i].Time) {
			t.Errorf("record %d: id %d time %v, want %d %v", i, r.id, r.time, 1001+i, spec.Events[i].Time)
		}
		if r.xml != sampleEvtxXML[i] {
			t.Errorf("record %d renders as\n%s\nwant\n%s", i, r.xml, sampleEvtxXML[i])
		}
	}
}

// TestEvtxSpansChunks: a log too big for one chunk continues in the next,
// with each chunk defining the names and templates it uses again, since a
// chunk refers to nothing outside itself; record ids run on unbroken.
func TestEvtxSpansChunks(t *testing.T) {
	proc, _ := EvtxBuiltins(4688)
	var events []EvtxEvent
	for i := range 600 {
		ev := proc.Event
		ev.Fields = append([]EvtxField(nil), proc.Event.Fields...)
		ev.Time = time.Date(2024, 3, 15, 9, 0, i, 0, time.UTC)
		set(&ev, "CommandLine", fmt.Sprintf(`powershell.exe -enc %s`, strings.Repeat("QQBCAEMA", 1+i%40)))
		events = append(events, ev)
	}
	data, err := BuildEvtx(EvtxSpec{Channel: "Security", Computer: "WS01", Events: events})
	if err != nil {
		t.Fatal(err)
	}
	got := readEvtx(t, data)
	if got.chunks < 3 {
		t.Fatalf("%d events fit in %d chunks; the test needs them to span several", len(events), got.chunks)
	}
	if len(got.records) != len(events) || got.next != uint64(len(events)+1) {
		t.Fatalf("%d records, next id %d; want %d, %d", len(got.records), got.next, len(events), len(events)+1)
	}
	for i, r := range got.records {
		if r.id != uint64(i+1) || !strings.Contains(r.xml, fmt.Sprintf(`<EventRecordID>%d</EventRecordID>`, i+1)) {
			t.Fatalf("record %d has id %d", i, r.id)
		}
	}
}

// TestEvtxValues: each value type encodes as the format stores it, and what
// a type cannot hold is refused.
func TestEvtxValues(t *testing.T) {
	for _, tc := range []struct {
		typ, value, want string
	}{
		{"uint8", "255", "255"},
		{"uint16", "0x1f90", "8080"},
		{"uint32", "4294967295", "4294967295"},
		{"hex64", "999", "0x3e7"},
		{"hex32", "0xdeadbeef", "0xdeadbeef"},
		{"sid", "S-1-5-18", "S-1-5-18"},
		{"sid", "S-1-5-21-1-2-3-500", "S-1-5-21-1-2-3-500"},
		{"guid", "{0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0}", "{0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0}"},
		{"filetime", "2024-03-15T09:30:12.1234567Z", "2024-03-15T09:30:12.1234567Z"},
		{"string", "naïve ☃", "naïve ☃"},
	} {
		data, err := EvtxValue(tc.typ, tc.value)
		if err != nil {
			t.Errorf("%s %q: %v", tc.typ, tc.value, err)
			continue
		}
		if got := formatEvtxValue(evtxSub{evtxTypeCode[tc.typ], data}); got != tc.want {
			t.Errorf("%s %q renders as %q, want %q", tc.typ, tc.value, got, tc.want)
		}
	}
	for _, tc := range []struct{ typ, value string }{
		{"uint8", "256"}, {"uint16", "-1"}, {"uint32", "ten"}, {"sid", "S-2-5"}, {"sid", "S-1-5-x"},
		{"guid", "not-a-guid"}, {"bool", "yes"}, {"filetime", "1500-01-01T00:00:00Z"}, {"float", "1"},
	} {
		if _, err := EvtxValue(tc.typ, tc.value); err == nil {
			t.Errorf("%s %q was accepted", tc.typ, tc.value)
		}
	}
}
