package libgen

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"maps"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/aoiflux/libntfs"
)

// A Windows XML event log (.evtx), as Windows Vista and later write one: a
// 4 KiB file header, then 64 KiB chunks of event records. Each record is
// binary XML: a template that lays out the event's XML once per chunk, with
// the values that differ from event to event substituted into it. Names are
// interned per chunk in a 64-bucket string table, templates in a 32-bucket
// template table, and the chunk header carries a CRC of itself and one of its
// records, as does the file header, so a reader that checks them finds them
// right.
//
// The layout follows what Windows 10 and 11 write: format version 3.2, a
// name stored inline where it is first used, a template defined inline in the
// first record that uses it, records padded to eight bytes. The event XML has
// the System element every event carries and either an EventData element of
// named Data values or, for an event whose manifest says so, a UserData
// element. Unlike Windows, which nests the event data in a template of its
// own, each event is one template; every reader renders the same XML from
// either.

const (
	evtxFileHeaderSize  = 4096
	evtxChunkSize       = 65536
	evtxChunkHeaderSize = 512
	evtxNamespace       = "http://schemas.microsoft.com/win/2004/08/events/event"
)

// EvtxTypes is the closed set of value types event data can have.
var EvtxTypes = []string{"string", "uint8", "uint16", "uint32", "uint64", "hex32", "hex64", "bool", "guid", "sid", "filetime"}

var evtxTypeCode = map[string]byte{
	"string": 0x01, "uint8": 0x04, "uint16": 0x06, "uint32": 0x08, "uint64": 0x0a,
	"bool": 0x0d, "guid": 0x0f, "filetime": 0x11, "sid": 0x13, "hex32": 0x14, "hex64": 0x15,
}

// EvtxField is one named value of an event's data.
type EvtxField struct {
	Name, Type, Value string
}

// EvtxUserData says an event's data is a UserData element holding one
// element in its own namespace, as the events of some manifests are, rather
// than EventData's named Data elements.
type EvtxUserData struct {
	Element, Namespace string
}

// EvtxEvent is one event as its record holds it.
type EvtxEvent struct {
	EventID uint16
	// Qualifiers is the EventID's Qualifiers attribute, which events from a
	// classic event source carry; nil is none.
	Qualifiers *uint16
	// Provider is the provider's name; ProviderGUID and EventSourceName are
	// left out of the XML when empty.
	Provider, ProviderGUID, EventSourceName string
	Version, Level, Opcode                  uint8
	Task                                    uint16
	Keywords                                uint64
	// Time is when the event was logged, which is also the record's time.
	Time                time.Time
	ProcessID, ThreadID uint32
	// UserSID is the Security element's UserID; empty is none.
	UserSID string
	Fields  []EvtxField
	// UserData, when set, puts the fields in a UserData element instead of
	// EventData.
	UserData *EvtxUserData
}

// EvtxSpec is a log: the channel and computer every event names, and the
// events in the order they were written.
type EvtxSpec struct {
	Channel, Computer string
	// FirstRecordID is the record id of the first event; zero is 1.
	FirstRecordID uint64
	Events        []EvtxEvent
}

// MaxEvtxRecordIDs bounds a log's record ids, so the next one still fits.
const MaxEvtxRecordIDs = 1 << 62

// BuildEvtx writes the log.
func BuildEvtx(spec EvtxSpec) ([]byte, error) {
	if len(spec.Events) == 0 {
		return nil, errors.New("an event log needs at least one event")
	}
	if strings.TrimSpace(spec.Channel) == "" || strings.TrimSpace(spec.Computer) == "" {
		return nil, errors.New("an event log needs a channel and a computer")
	}
	id := max(spec.FirstRecordID, 1)
	if id+uint64(len(spec.Events)) > MaxEvtxRecordIDs {
		return nil, fmt.Errorf("record ids from %d for %d events run past %d", id, len(spec.Events), uint64(MaxEvtxRecordIDs))
	}
	var chunks [][]byte
	c := newEvtxChunk()
	for i, ev := range spec.Events {
		values, err := evtxValues(ev)
		if err != nil {
			return nil, fmt.Errorf("event %d (%d): %w", i, ev.EventID, err)
		}
		saved := c.snapshot()
		rec, err := c.record(spec, ev, id, values)
		if errors.Is(err, errChunkFull) && c.count > 0 {
			c.restore(saved)
			chunks = append(chunks, c.finish())
			c = newEvtxChunk()
			rec, err = c.record(spec, ev, id, values)
		}
		if errors.Is(err, errChunkFull) {
			return nil, fmt.Errorf("event %d (%d) is %d bytes, more than a 64 KiB chunk holds", i, ev.EventID, len(rec))
		}
		if err != nil {
			return nil, fmt.Errorf("event %d (%d): %w", i, ev.EventID, err)
		}
		id++
	}
	chunks = append(chunks, c.finish())
	if len(chunks) > 0xFFFF {
		return nil, fmt.Errorf("%d chunks is more than the file header can count", len(chunks))
	}

	le := binary.LittleEndian
	h := make([]byte, evtxFileHeaderSize)
	copy(h, "ElfFile\x00")
	le.PutUint64(h[8:], 0)
	le.PutUint64(h[16:], uint64(len(chunks)-1))
	le.PutUint64(h[24:], id)
	le.PutUint32(h[32:], 128)
	le.PutUint16(h[36:], 2) // version 3.2, as Windows 10 2004 and later write
	le.PutUint16(h[38:], 3)
	le.PutUint16(h[40:], evtxFileHeaderSize)
	le.PutUint16(h[42:], uint16(len(chunks)))
	le.PutUint32(h[124:], crc32.ChecksumIEEE(h[:120]))
	return slices.Concat(append([][]byte{h}, chunks...)...), nil
}

var errChunkFull = errors.New("the chunk is full")

// evtxChunk is a chunk being filled: its bytes, the names and templates
// already defined in it, and its two hash tables.
type evtxChunk struct {
	buf         []byte
	names       map[string]uint32
	templates   map[string]evtxTemplate
	strTable    [64]uint32
	tplTable    [32]uint32
	first, last uint64
	lastRecord  int
	count       int
}

type evtxTemplate struct {
	id     uint32
	offset uint32
}

func newEvtxChunk() *evtxChunk {
	return &evtxChunk{
		buf:       make([]byte, evtxChunkHeaderSize, evtxChunkSize),
		names:     map[string]uint32{},
		templates: map[string]evtxTemplate{},
	}
}

// snapshot and restore undo a record that did not fit.
func (c *evtxChunk) snapshot() evtxChunk {
	s := *c
	s.names, s.templates = maps.Clone(c.names), maps.Clone(c.templates)
	return s
}

func (c *evtxChunk) restore(s evtxChunk) {
	buf := c.buf[:len(s.buf)]
	*c = s
	c.buf = buf
}

// record appends one event record and returns its bytes.
func (c *evtxChunk) record(spec EvtxSpec, ev EvtxEvent, id uint64, values []evtxValue) ([]byte, error) {
	le := binary.LittleEndian
	values[evsRecordID].data = le.AppendUint64(nil, id)
	start := len(c.buf)
	b := append(c.buf, 0x2a, 0x2a, 0, 0, 0, 0, 0, 0)
	b = le.AppendUint64(b, id)
	b = le.AppendUint64(b, libntfs.TimeToFiletime(ev.Time))
	b = append(b, 0x0f, 0x01, 0x01, 0x00) // fragment header

	key, root := evtxTemplateFor(spec, ev)
	sum := sha256.Sum256([]byte(key))
	tpl, known := c.templates[key]
	if !known {
		tpl.id = le.Uint32(sum[:4])
		for _, t := range c.templates {
			if t.id == tpl.id {
				return nil, fmt.Errorf("two templates in one chunk share the id %#x", tpl.id)
			}
		}
	}
	b = append(b, 0x0c, 0x01)
	b = le.AppendUint32(b, tpl.id)
	if known {
		b = le.AppendUint32(b, tpl.offset)
	} else {
		tpl.offset = uint32(len(b) + 4)
		b = le.AppendUint32(b, tpl.offset)
		bucket := tpl.id % 32
		b = le.AppendUint32(b, c.tplTable[bucket])
		c.tplTable[bucket] = tpl.offset
		b = append(b, sum[:16]...)
		sizeAt := len(b)
		b = append(b, 0, 0, 0, 0)
		b = append(b, 0x0f, 0x01, 0x01, 0x00)
		b = c.element(b, root)
		b = append(b, 0x00) // end of the template's fragment
		le.PutUint32(b[sizeAt:], uint32(len(b)-sizeAt-4))
		c.templates[key] = tpl
	}

	b = le.AppendUint32(b, uint32(len(values)))
	for _, v := range values {
		b = le.AppendUint16(b, uint16(len(v.data)))
		b = append(b, v.typ, 0)
	}
	for _, v := range values {
		b = append(b, v.data...)
	}
	b = append(b, 0x00) // end of the record's fragment
	for (len(b)-start+4)%8 != 0 {
		b = append(b, 0)
	}
	size := len(b) - start + 4
	b = le.AppendUint32(b, uint32(size))
	le.PutUint32(b[start+4:], uint32(size))
	c.buf = b
	if len(b) > evtxChunkSize {
		return b[start:], errChunkFull
	}
	if c.count == 0 {
		c.first = id
	}
	c.last, c.lastRecord = id, start
	c.count++
	return b[start:], nil
}

// finish writes the chunk header: record numbers and ids, offsets, the two
// tables, and the CRCs.
func (c *evtxChunk) finish() []byte {
	le := binary.LittleEndian
	out := make([]byte, evtxChunkSize)
	copy(out, c.buf)
	copy(out, "ElfChnk\x00")
	le.PutUint64(out[8:], c.first) // a fresh log numbers its records by their ids
	le.PutUint64(out[16:], c.last)
	le.PutUint64(out[24:], c.first)
	le.PutUint64(out[32:], c.last)
	le.PutUint32(out[40:], 128)
	le.PutUint32(out[44:], uint32(c.lastRecord))
	le.PutUint32(out[48:], uint32(len(c.buf)))
	le.PutUint32(out[52:], crc32.ChecksumIEEE(out[evtxChunkHeaderSize:len(c.buf)]))
	le.PutUint32(out[120:], 1) // what Windows writes here in every chunk it closes
	for i, off := range c.strTable {
		le.PutUint32(out[128+4*i:], off)
	}
	for i, off := range c.tplTable {
		le.PutUint32(out[384+4*i:], off)
	}
	h := crc32.NewIEEE()
	h.Write(out[:120])
	h.Write(out[128:evtxChunkHeaderSize])
	le.PutUint32(out[124:], h.Sum32())
	return out
}

// xmlNode is an element of the event's XML as a template lays it out.
type xmlNode struct {
	name     string
	attrs    []xmlAttr
	content  *xmlValue
	children []*xmlNode
}

type xmlAttr struct {
	name  string
	value xmlValue
}

// xmlValue is literal text, or the substitution of value number sub, of type
// typ, from the record's values.
type xmlValue struct {
	text string
	sub  int
	typ  byte
}

func literal(s string) xmlValue             { return xmlValue{text: s, sub: -1} }
func subst(n int, typ byte) xmlValue        { return xmlValue{sub: n, typ: typ} }
func leaf(name string, v xmlValue) *xmlNode { return &xmlNode{name: name, content: &v} }

// element appends an element: its start tag with its name and attributes,
// then its content and children and its end tag, or the empty element's
// close.
func (c *evtxChunk) element(b []byte, n *xmlNode) []byte {
	le := binary.LittleEndian
	tok := byte(0x01)
	if len(n.attrs) > 0 {
		tok = 0x41
	}
	b = append(b, tok, 0xff, 0xff) // no dependency on a substitution
	sizeAt := len(b)
	b = append(b, 0, 0, 0, 0)
	b = c.nameRef(b, n.name)
	if len(n.attrs) > 0 {
		listAt := len(b)
		b = append(b, 0, 0, 0, 0)
		for i, a := range n.attrs {
			tok := byte(0x46)
			if i == len(n.attrs)-1 {
				tok = 0x06
			}
			b = append(b, tok)
			b = c.nameRef(b, a.name)
			b = appendXMLValue(b, a.value)
		}
		le.PutUint32(b[listAt:], uint32(len(b)-listAt-4))
	}
	if n.content == nil && len(n.children) == 0 {
		b = append(b, 0x03)
	} else {
		b = append(b, 0x02)
		if n.content != nil {
			b = appendXMLValue(b, *n.content)
		}
		for _, ch := range n.children {
			b = c.element(b, ch)
		}
		b = append(b, 0x04)
	}
	le.PutUint32(b[sizeAt:], uint32(len(b)-sizeAt-4))
	return b
}

func appendXMLValue(b []byte, v xmlValue) []byte {
	if v.sub >= 0 {
		b = append(b, 0x0d)
		b = binary.LittleEndian.AppendUint16(b, uint16(v.sub))
		return append(b, v.typ)
	}
	b = append(b, 0x05, 0x01)
	b = binary.LittleEndian.AppendUint16(b, uint16(len(utf16.Encode([]rune(v.text)))))
	return append(b, utf16le(v.text)...)
}

// nameRef appends a reference to a name: its offset in the chunk, followed,
// the first time the chunk uses it, by the name itself, which joins the
// front of its bucket's chain in the string table.
func (c *evtxChunk) nameRef(b []byte, name string) []byte {
	le := binary.LittleEndian
	if off, ok := c.names[name]; ok {
		return le.AppendUint32(b, off)
	}
	off := uint32(len(b) + 4)
	b = le.AppendUint32(b, off)
	units := utf16.Encode([]rune(name))
	h := uint32(0)
	for _, u := range units {
		h = h*65599 + uint32(u)
	}
	bucket := uint16(h) % 64
	b = le.AppendUint32(b, c.strTable[bucket])
	b = le.AppendUint16(b, uint16(h))
	b = le.AppendUint16(b, uint16(len(units)))
	b = append(b, utf16z(name)...)
	c.strTable[bucket] = off
	c.names[name] = off
	return b
}

// evtxValue is one substitution value as the record stores it.
type evtxValue struct {
	typ  byte
	data []byte
}

// The fixed substitutions every event's System element takes, in order.
// Optional ones (the qualifiers and the user) follow them when present, then
// the data fields.
const (
	evsEventID = iota
	evsVersion
	evsLevel
	evsTask
	evsOpcode
	evsKeywords
	evsTime
	evsRecordID
	evsProcessID
	evsThreadID
	evsFixed
)

// evtxValues is an event's substitution values, in the order its template
// numbers them. The record id is filled in when the record is written.
func evtxValues(ev EvtxEvent) ([]evtxValue, error) {
	le := binary.LittleEndian
	v := []evtxValue{
		{0x06, le.AppendUint16(nil, ev.EventID)},
		{0x04, []byte{ev.Version}},
		{0x04, []byte{ev.Level}},
		{0x06, le.AppendUint16(nil, ev.Task)},
		{0x04, []byte{ev.Opcode}},
		{0x15, le.AppendUint64(nil, ev.Keywords)},
		{0x11, le.AppendUint64(nil, libntfs.TimeToFiletime(ev.Time))},
		{0x0a, nil},
		{0x08, le.AppendUint32(nil, ev.ProcessID)},
		{0x08, le.AppendUint32(nil, ev.ThreadID)},
	}
	if ev.Qualifiers != nil {
		v = append(v, evtxValue{0x06, le.AppendUint16(nil, *ev.Qualifiers)})
	}
	if ev.UserSID != "" {
		sid, err := EncodeSID(ev.UserSID)
		if err != nil {
			return nil, fmt.Errorf("user sid: %w", err)
		}
		v = append(v, evtxValue{0x13, sid})
	}
	for _, f := range ev.Fields {
		data, err := EvtxValue(f.Type, f.Value)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", f.Name, err)
		}
		v = append(v, evtxValue{evtxTypeCode[f.Type], data})
	}
	return v, nil
}

// evtxTemplateFor lays out an event's XML, and returns it with a key that is
// the same for every event the same layout serves: same provider, channel and
// computer, same optional parts, same field names and types.
func evtxTemplateFor(spec EvtxSpec, ev EvtxEvent) (string, *xmlNode) {
	var key strings.Builder
	fmt.Fprintf(&key, "%q %q %q %q %q %v %v", ev.Provider, ev.ProviderGUID, ev.EventSourceName, spec.Channel, spec.Computer, ev.Qualifiers != nil, ev.UserSID != "")
	if ev.UserData != nil {
		fmt.Fprintf(&key, " userdata %q %q", ev.UserData.Element, ev.UserData.Namespace)
	}
	for _, f := range ev.Fields {
		fmt.Fprintf(&key, " %q:%s", f.Name, f.Type)
	}

	provider := &xmlNode{name: "Provider", attrs: []xmlAttr{{"Name", literal(ev.Provider)}}}
	if ev.ProviderGUID != "" {
		provider.attrs = append(provider.attrs, xmlAttr{"Guid", literal(ev.ProviderGUID)})
	}
	if ev.EventSourceName != "" {
		provider.attrs = append(provider.attrs, xmlAttr{"EventSourceName", literal(ev.EventSourceName)})
	}
	next := evsFixed
	eventID := leaf("EventID", subst(evsEventID, 0x06))
	if ev.Qualifiers != nil {
		eventID.attrs = []xmlAttr{{"Qualifiers", subst(next, 0x06)}}
		next++
	}
	security := &xmlNode{name: "Security"}
	if ev.UserSID != "" {
		security.attrs = []xmlAttr{{"UserID", subst(next, 0x13)}}
		next++
	}
	system := &xmlNode{name: "System", children: []*xmlNode{
		provider,
		eventID,
		leaf("Version", subst(evsVersion, 0x04)),
		leaf("Level", subst(evsLevel, 0x04)),
		leaf("Task", subst(evsTask, 0x06)),
		leaf("Opcode", subst(evsOpcode, 0x04)),
		leaf("Keywords", subst(evsKeywords, 0x15)),
		{name: "TimeCreated", attrs: []xmlAttr{{"SystemTime", subst(evsTime, 0x11)}}},
		leaf("EventRecordID", subst(evsRecordID, 0x0a)),
		{name: "Correlation"},
		{name: "Execution", attrs: []xmlAttr{{"ProcessID", subst(evsProcessID, 0x08)}, {"ThreadID", subst(evsThreadID, 0x08)}}},
		leaf("Channel", literal(spec.Channel)),
		leaf("Computer", literal(spec.Computer)),
		security,
	}}

	var data *xmlNode
	if ev.UserData != nil {
		inner := &xmlNode{name: ev.UserData.Element, attrs: []xmlAttr{{"xmlns", literal(ev.UserData.Namespace)}}}
		for _, f := range ev.Fields {
			inner.children = append(inner.children, leaf(f.Name, subst(next, evtxTypeCode[f.Type])))
			next++
		}
		data = &xmlNode{name: "UserData", children: []*xmlNode{inner}}
	} else {
		data = &xmlNode{name: "EventData"}
		for _, f := range ev.Fields {
			d := leaf("Data", subst(next, evtxTypeCode[f.Type]))
			d.attrs = []xmlAttr{{"Name", literal(f.Name)}}
			data.children = append(data.children, d)
			next++
		}
	}
	root := &xmlNode{name: "Event", attrs: []xmlAttr{{"xmlns", literal(evtxNamespace)}}, children: []*xmlNode{system, data}}
	return key.String(), root
}

// EvtxValue encodes a data value of one of EvtxTypes as an event record
// stores it, or says why it cannot: a number out of its type's range, a GUID
// or SID that does not parse.
func EvtxValue(typ, value string) ([]byte, error) {
	le := binary.LittleEndian
	unsigned := func(bits int) (uint64, error) {
		v := strings.TrimSpace(value)
		base := 10
		if strings.HasPrefix(v, "0x") || strings.HasPrefix(v, "0X") {
			v, base = v[2:], 16
		}
		n, err := strconv.ParseUint(v, base, bits)
		if err != nil {
			return 0, fmt.Errorf("%q is not a %d-bit unsigned number", value, bits)
		}
		return n, nil
	}
	switch typ {
	case "string":
		return utf16le(value), nil
	case "uint8":
		n, err := unsigned(8)
		return []byte{byte(n)}, err
	case "uint16":
		n, err := unsigned(16)
		return le.AppendUint16(nil, uint16(n)), err
	case "uint32", "hex32":
		n, err := unsigned(32)
		return le.AppendUint32(nil, uint32(n)), err
	case "uint64", "hex64":
		n, err := unsigned(64)
		return le.AppendUint64(nil, n), err
	case "bool":
		switch value {
		case "true":
			return le.AppendUint32(nil, 1), nil
		case "false":
			return le.AppendUint32(nil, 0), nil
		}
		return nil, fmt.Errorf("%q is not true or false", value)
	case "guid":
		g, err := ParseGUID(value)
		if err != nil {
			return nil, err
		}
		return appendGUID(nil, g), nil
	case "sid":
		return EncodeSID(value)
	case "filetime":
		t, err := time.Parse(time.RFC3339Nano, value)
		if err != nil {
			return nil, fmt.Errorf("%q is not an RFC 3339 time", value)
		}
		if t.Before(MinFiletime) || t.After(MaxFiletime) {
			return nil, fmt.Errorf("%s is outside what a FILETIME holds", value)
		}
		return le.AppendUint64(nil, libntfs.TimeToFiletime(t)), nil
	}
	return nil, fmt.Errorf("value type %q (want one of: %s)", typ, strings.Join(EvtxTypes, ", "))
}

// EncodeSID writes a security identifier written as S-1-5-21-..., in its
// binary form: revision, number of sub-authorities, the 48-bit authority
// big-endian, then each sub-authority little-endian.
func EncodeSID(s string) ([]byte, error) {
	parts := strings.Split(s, "-")
	if len(parts) < 3 || parts[0] != "S" || parts[1] != "1" || len(parts) > 3+15 {
		return nil, fmt.Errorf("%q is not a SID (want S-1-<authority>-<sub-authority>..., at most 15 of those)", s)
	}
	auth, err := strconv.ParseUint(parts[2], 10, 48)
	if err != nil {
		return nil, fmt.Errorf("%q: authority %q is not a 48-bit number", s, parts[2])
	}
	b := []byte{1, byte(len(parts) - 3)}
	b = append(b, byte(auth>>40), byte(auth>>32), byte(auth>>24), byte(auth>>16), byte(auth>>8), byte(auth))
	for _, p := range parts[3:] {
		n, err := strconv.ParseUint(p, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("%q: sub-authority %q is not a 32-bit number", s, p)
		}
		b = binary.LittleEndian.AppendUint32(b, uint32(n))
	}
	return b, nil
}

// EvtxBuiltin is an event fsagen knows the shape of: who logs it, to which
// channel, with which version, level, task, opcode and keywords, and the
// names and types of its data, each with the value Windows writes when it
// has none.
type EvtxBuiltin struct {
	Channel string
	Event   EvtxEvent
}

// EvtxBuiltinIDs are the event ids EvtxBuiltins knows.
var EvtxBuiltinIDs = []int{1102, 4624, 4688, 7045}

// EvtxBuiltins returns the built-in shape of an event id.
func EvtxBuiltins(id int) (EvtxBuiltin, bool) {
	b, ok := evtxBuiltins[id]
	if !ok {
		return EvtxBuiltin{}, false
	}
	b.Event.Fields = slices.Clone(b.Event.Fields)
	return b, true
}

const (
	securityAuditing     = "Microsoft-Windows-Security-Auditing"
	securityAuditingGUID = "{54849625-5478-4994-A5BA-3E3B0328C30D}"
	auditSuccess         = 0x8020000000000000
	nullSID              = "S-1-0-0"
	nullGUID             = "{00000000-0000-0000-0000-000000000000}"
)

var scmQualifiers = uint16(16384)

var evtxBuiltins = map[int]EvtxBuiltin{
	// The security log was cleared. Logged by the event log service itself,
	// as the first record of the cleared log.
	1102: {"Security", EvtxEvent{
		EventID: 1102, Provider: "Microsoft-Windows-Eventlog", ProviderGUID: "{FC65DDD8-D6EF-4962-83D5-6E5CFE9CE148}",
		Level: 4, Task: 104, Keywords: 0x4020000000000000,
		UserData: &EvtxUserData{Element: "LogFileCleared", Namespace: "http://manifests.microsoft.com/win/2004/08/windows/eventlog"},
		Fields: []EvtxField{
			{"SubjectUserSid", "sid", nullSID}, {"SubjectUserName", "string", "-"},
			{"SubjectDomainName", "string", "-"}, {"SubjectLogonId", "hex64", "0x0"},
		},
	}},
	// An account was successfully logged on (version 2, Windows 10 and later).
	4624: {"Security", EvtxEvent{
		EventID: 4624, Provider: securityAuditing, ProviderGUID: securityAuditingGUID,
		Version: 2, Task: 12544, Keywords: auditSuccess,
		Fields: []EvtxField{
			{"SubjectUserSid", "sid", nullSID}, {"SubjectUserName", "string", "-"},
			{"SubjectDomainName", "string", "-"}, {"SubjectLogonId", "hex64", "0x0"},
			{"TargetUserSid", "sid", nullSID}, {"TargetUserName", "string", "-"},
			{"TargetDomainName", "string", "-"}, {"TargetLogonId", "hex64", "0x0"},
			{"LogonType", "uint32", "0"}, {"LogonProcessName", "string", "-"},
			{"AuthenticationPackageName", "string", "-"}, {"WorkstationName", "string", "-"},
			{"LogonGuid", "guid", nullGUID}, {"TransmittedServices", "string", "-"},
			{"LmPackageName", "string", "-"}, {"KeyLength", "uint32", "0"},
			{"ProcessId", "hex64", "0x0"}, {"ProcessName", "string", "-"},
			{"IpAddress", "string", "-"}, {"IpPort", "string", "-"},
			{"ImpersonationLevel", "string", "%%1833"}, {"RestrictedAdminMode", "string", "-"},
			{"TargetOutboundUserName", "string", "-"}, {"TargetOutboundDomainName", "string", "-"},
			{"VirtualAccount", "string", "%%1843"}, {"TargetLinkedLogonId", "hex64", "0x0"},
			{"ElevatedToken", "string", "%%1842"},
		},
	}},
	// A new process has been created (version 2, Windows 10 and later).
	4688: {"Security", EvtxEvent{
		EventID: 4688, Provider: securityAuditing, ProviderGUID: securityAuditingGUID,
		Version: 2, Task: 13312, Keywords: auditSuccess,
		Fields: []EvtxField{
			{"SubjectUserSid", "sid", nullSID}, {"SubjectUserName", "string", "-"},
			{"SubjectDomainName", "string", "-"}, {"SubjectLogonId", "hex64", "0x0"},
			{"NewProcessId", "hex64", "0x0"}, {"NewProcessName", "string", "-"},
			{"TokenElevationType", "string", "%%1936"}, {"ProcessId", "hex64", "0x0"},
			{"CommandLine", "string", ""}, {"TargetUserSid", "sid", nullSID},
			{"TargetUserName", "string", "-"}, {"TargetDomainName", "string", "-"},
			{"TargetLogonId", "hex64", "0x0"}, {"ParentProcessName", "string", "-"},
			{"MandatoryLabel", "sid", "S-1-16-8192"},
		},
	}},
	// A service was installed in the system. Logged by the classic Service
	// Control Manager source, hence the qualifiers.
	7045: {"System", EvtxEvent{
		EventID: 7045, Qualifiers: &scmQualifiers,
		Provider: "Service Control Manager", ProviderGUID: "{555908D1-A6D7-4695-8E1E-26931D2012F4}", EventSourceName: "Service Control Manager",
		Level: 4, Keywords: 0x8080000000000000,
		Fields: []EvtxField{
			{"ServiceName", "string", "-"}, {"ImagePath", "string", "-"},
			{"ServiceType", "string", "user mode service"}, {"StartType", "string", "demand start"},
			{"AccountName", "string", "LocalSystem"},
		},
	}},
}
