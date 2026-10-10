package manifest

import (
	"cmp"
	"encoding/binary"
	"fmt"
	"maps"
	"net"
	"path"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/aoiflux/fsagen/compile"
	"github.com/aoiflux/fsagen/libgen"
	"github.com/aoiflux/fsagen/spec"
)

// mp4Duration is how long the video a scenario asks for claims to be. It is
// fixed because nothing reads it but a metadata tool, and a knob nobody turns
// is a knob that goes untested.
const mp4Duration = 3 * time.Second

// defaultPESections are the sections an executable gets when the scenario
// does not list its own: the shape of an ordinary small binary.
var defaultPESections = []spec.PeSection{
	{Name: ".text", Size: 1024},
	{Name: ".rdata", Size: 512},
	{Name: ".data", Size: 256},
}

// buildContent is the bytes an operation writes. Without a format that is its
// content, or the filler compile decided it needs; with one, it is a file of
// that type built around them.
func buildContent(c compile.Op) ([]byte, error) {
	op := c.Operation
	body := contentOf(c)

	switch op.Format {
	case "", spec.FormatRaw, spec.FormatText:
		return body, nil

	case spec.FormatPDF:
		meta, err := pdfMeta(op)
		if err != nil {
			return nil, err
		}
		return libgen.RenderPDF(string(body), meta)

	case spec.FormatDOCX, spec.FormatDOCM:
		meta, err := officeMeta(op.Docx, "docx", c.When)
		if err != nil {
			return nil, err
		}
		if op.Format == spec.FormatDOCX {
			return libgen.Docx(string(body), meta)
		}
		vba, err := buildVBA(c)
		if err != nil {
			return nil, err
		}
		return libgen.Docm(string(body), meta, vba)

	case spec.FormatXLSX, spec.FormatXLSM:
		meta, err := officeMeta(op.Xlsx, "xlsx", c.When)
		if err != nil {
			return nil, err
		}
		var vba []byte
		if op.Format == spec.FormatXLSM {
			if vba, err = buildVBA(c); err != nil {
				return nil, err
			}
		}
		return libgen.Xlsx(string(body), meta, vba)

	case spec.FormatPE:
		return buildPE(c, body)

	case spec.FormatZip:
		return libgen.ZipFiller("data.bin", body, c.When)

	case spec.FormatPNG:
		return libgen.PNG(libgen.DefaultImageSize, libgen.DefaultImageSize, c.Rand.Derive("image").Stream(), body)

	case spec.FormatJPEG:
		return libgen.JPEG(libgen.DefaultImageSize, libgen.DefaultImageSize, c.Rand.Derive("image").Stream(), body)

	case spec.FormatMP4:
		return libgen.MP4(c.When, mp4Duration, 320, 240, body), nil

	case spec.FormatLNK:
		return buildLNK(c)

	case spec.FormatPrefetch:
		return buildPrefetch(c)

	case spec.FormatEvtx:
		return buildEvtx(c)

	case spec.FormatRegistry:
		return buildRegistry(c)

	case spec.FormatUtmp:
		return buildUtmp(c)

	case spec.FormatAuditd:
		return buildAuditd(c)

	case spec.FormatChromeHistory, spec.FormatFirefoxPlaces:
		hist, err := historyOf(c)
		if err != nil {
			return nil, err
		}
		s := c.Rand.Derive("history").Stream()
		if op.Format == spec.FormatChromeHistory {
			return libgen.ChromeHistory(hist, s)
		}
		return libgen.FirefoxPlaces(hist, s)
	}
	return nil, fmt.Errorf("unknown format %q (want one of: %s)", op.Format, strings.Join(spec.FormatNames(compile.TypedFormats), ", "))
}

// officeMeta is a Word or Excel document's properties from its docx or
// xlsx block (named block), its dates defaulting to the operation's time.
func officeMeta(d *spec.DocxSpec, block string, when time.Time) (libgen.DocxMeta, error) {
	if d == nil {
		return libgen.DocxMeta{Created: when, Modified: when}, nil
	}
	created, err := timeOr(d.Created, block+".created", when)
	if err != nil {
		return libgen.DocxMeta{}, err
	}
	modified, err := timeOr(d.Modified, block+".modified", created)
	if err != nil {
		return libgen.DocxMeta{}, err
	}
	return libgen.DocxMeta{
		Title:    d.Title,
		Author:   d.Author,
		Created:  created,
		Modified: modified,
	}, nil
}

// markerLetters are the letters a drawn marker is made of: none of them a
// hex digit, so a scanner looking for hex strings in the macro finds none.
const markerLetters = "ghijklmnopqrstuv"

// buildVBA is the VBA project a macro-enabled document carries. A marker
// the scenario does not give is FSAGEN-VBA: and sixteen letters drawn from
// the seed; the project's ID and the bytes obscuring its protection fields
// come from a stream of their own, so giving a marker changes nothing else.
func buildVBA(c compile.Op) ([]byte, error) {
	s := compile.VBAOf(c.Operation)
	if s.Marker == "" {
		b := c.Rand.Derive("vba", "marker").Stream().Bytes(16)
		for i := range b {
			b[i] = markerLetters[b[i]&15]
		}
		s.Marker = "FSAGEN-VBA:" + string(b)
	}
	return libgen.BuildVBAProject(s, c.Rand.Derive("vba").Stream())
}

// timeOr reads an optional RFC 3339 time, falling back when the scenario does
// not give one. The fallback is always another scenario time, never the wall
// clock, which is what keeps a metadata date reproducible.
func timeOr(value, field string, fallback time.Time) (time.Time, error) {
	t, err := optionalTime(value, field)
	if err != nil {
		return time.Time{}, err
	}
	if t.IsZero() {
		return fallback, nil
	}
	return t, nil
}

// buildPE fills each section with the operation's filler and puts the
// content_len filler in the overlay, where an installer keeps its payload.
func buildPE(c compile.Op, overlay []byte) ([]byte, error) {
	in := c.Pe
	if in == nil {
		in = &spec.PeSpec{}
	}
	stamp := c.When
	switch s := strings.TrimSpace(in.Timestamp); {
	case s == "0":
		stamp = time.Time{}
	case s != "":
		t, err := time.Parse(time.RFC3339, s)
		if err != nil {
			return nil, fmt.Errorf("pe.timestamp: %w", err)
		}
		stamp = t
	}

	sections := in.Sections
	if len(sections) == 0 {
		sections = defaultPESections
	}
	out := make([]libgen.PESection, 0, len(sections))
	for _, sec := range sections {
		size := sec.Size
		if size == 0 {
			size = 512
		}
		out = append(out, libgen.PESection{
			Name:  sec.Name,
			Data:  libgen.Filler(c.ContentKind, size, c.Rand.Derive("pe.section", sec.Name).Stream()),
			Flags: sec.Flags,
		})
	}
	imports, err := libgen.ParseImports(in.Imports)
	if err != nil {
		return nil, err
	}
	var version *libgen.PEVersion
	if v := in.Version; v != nil {
		version = &libgen.PEVersion{
			FileVersion: v.FileVersion, ProductVersion: v.ProductVersion,
			CompanyName: v.CompanyName, FileDescription: v.FileDescription,
			InternalName: v.InternalName, OriginalFilename: v.OriginalFilename,
			ProductName: v.ProductName, LegalCopyright: v.LegalCopyright,
		}
	}
	return libgen.BuildPE(libgen.PESpec{
		Machine:   in.Machine,
		Subsystem: in.Subsystem,
		DLL:       in.Dll,
		Timestamp: stamp,
		Sections:  out,
		Imports:   imports,
		Version:   version,
		Overlay:   overlay,
	})
}

// buildLNK maps the lnk block to the link builder. The target's times default
// to the operation's; what a real link carries that the scenario leaves out —
// the volume serial, the machine's name, the target's NTFS file reference —
// is drawn from the operation's own stream, every value in a fixed order
// whether it is used or not, so giving one never moves another.
func buildLNK(c compile.Op) ([]byte, error) {
	in := c.Lnk
	s := c.Rand.Derive("lnk").Stream()
	serial := uint32(s.Uint64())
	machine := "DESKTOP-" + s.Text(7)
	mftEntry := uint64(64 + s.IntN(1<<20))
	mftSeq := uint16(1 + s.IntN(8))

	if in.VolumeSerial != "" {
		v, err := libgen.ParseVolumeSerial(in.VolumeSerial)
		if err != nil {
			return nil, err
		}
		serial = v
	}
	times := map[string]time.Time{}
	for _, f := range []struct{ key, val string }{
		{"lnk.target_crtime", in.TargetCrtime}, {"lnk.target_atime", in.TargetAtime}, {"lnk.target_mtime", in.TargetMtime},
	} {
		t, err := timeOr(f.val, f.key, c.When)
		if err != nil {
			return nil, err
		}
		times[f.key] = t
	}
	return libgen.BuildLNK(libgen.LNKSpec{
		Target:       in.Target,
		Dir:          in.TargetType == "dir",
		Arguments:    in.Arguments,
		WorkingDir:   in.WorkingDir,
		RelativePath: in.RelativePath,
		Description:  in.Description,
		IconLocation: in.Icon,
		IconIndex:    int32(in.IconIndex),
		ShowCommand:  in.ShowCommand,
		DriveType:    in.DriveType,
		VolumeSerial: serial,
		VolumeLabel:  in.VolumeLabel,
		MachineID:    cmp.Or(in.MachineID, machine),
		Created:      times["lnk.target_crtime"],
		Accessed:     times["lnk.target_atime"],
		Modified:     times["lnk.target_mtime"],
		Size:         in.TargetSize,
		Attributes:   in.TargetAttributes,
		MFTEntry:     mftEntry,
		MFTSequence:  mftSeq,
	}, s)
}

// buildPrefetch maps the prefetch block to the prefetch builder. The program
// last ran at the operation time unless the block says when. A volume the
// block does not describe gets a serial and a formatting time from the
// operation's stream, drawn per drive letter, so describing one volume never
// changes another; the time is up to three years before the operation.
func buildPrefetch(c compile.Op) ([]byte, error) {
	in := c.Prefetch
	var runs []time.Time
	for i, v := range in.LastRunTimes {
		t, err := timeOr(v, fmt.Sprintf("prefetch.last_run_times[%d]", i), c.When)
		if err != nil {
			return nil, err
		}
		runs = append(runs, t)
	}
	if len(runs) == 0 {
		runs = []time.Time{c.When}
	}
	count := uint32(in.RunCount)
	if count == 0 {
		count = uint32(len(runs))
	}
	var loaded []string
	if len(in.ReferencedFiles) > 0 {
		loaded = in.ReferencedFiles
	}
	drives, err := libgen.PrefetchDrives(in.Executable, loaded)
	if err != nil {
		return nil, err
	}
	volumes := map[byte]libgen.PrefetchVolume{}
	for _, d := range drives {
		s := c.Rand.Derive("prefetch.volume", string(d)).Stream()
		volumes[d] = libgen.PrefetchVolume{
			Serial:  uint32(s.Uint64()),
			Created: c.When.Add(-time.Duration(1+s.IntN(3*365*24*3600)) * time.Second).Truncate(time.Second),
		}
	}
	for i, v := range in.Volumes {
		d := strings.ToUpper(strings.TrimSuffix(v.Drive, ":"))[0]
		vol := volumes[d]
		if v.Serial != "" {
			serial, err := libgen.ParseVolumeSerial(v.Serial)
			if err != nil {
				return nil, err
			}
			vol.Serial = serial
		}
		created, err := timeOr(v.Created, fmt.Sprintf("prefetch.volumes[%d].created", i), vol.Created)
		if err != nil {
			return nil, err
		}
		vol.Created = created
		volumes[d] = vol
	}
	return libgen.BuildPrefetch(libgen.PrefetchSpec{
		Version:        in.Version,
		Executable:     in.Executable,
		Loaded:         loaded,
		RunCount:       count,
		LastRuns:       runs,
		HarddiskVolume: in.HarddiskVolume,
		Volumes:        volumes,
		Uncompressed:   in.Compressed != nil && !*in.Compressed,
	}, c.Rand.Derive("prefetch").Stream())
}

// buildEvtx maps the evtx block to the event log builder. A built-in event
// starts from Windows' own shape for it and takes the block's values over
// it; any other event is the block's, with level Information unless it says
// otherwise and its data as strings in name order. What the block leaves out
// is drawn from the operation's stream: the computer's name, a process id
// per provider (a multiple of four, as Windows' are) and a thread id per
// event.
func buildEvtx(c compile.Op) ([]byte, error) {
	in := c.Evtx
	computer := in.Computer
	if computer == "" {
		computer = "DESKTOP-" + c.Rand.Derive("evtx.computer").Stream().Text(7)
	}
	out := libgen.EvtxSpec{
		Channel:       compile.EvtxChannel(in),
		Computer:      computer,
		FirstRecordID: uint64(in.FirstRecordID),
	}
	for i, e := range in.Events {
		ev := libgen.EvtxEvent{EventID: uint16(e.EventID), Provider: e.Provider, ProviderGUID: e.ProviderGUID, Level: 4}
		b, builtin := compile.EvtxBuiltin(e)
		if builtin {
			ev = b.Event
			ev.ProviderGUID = cmp.Or(e.ProviderGUID, ev.ProviderGUID)
			for j, f := range ev.Fields {
				if v, ok := e.Data[f.Name]; ok {
					ev.Fields[j].Value = v
				}
			}
		} else {
			for _, name := range slices.Sorted(maps.Keys(e.Data)) {
				ev.Fields = append(ev.Fields, libgen.EvtxField{Name: name, Type: "string", Value: e.Data[name]})
			}
		}
		when, err := timeOr(e.Time, fmt.Sprintf("evtx.events[%d].time", i), c.When)
		if err != nil {
			return nil, err
		}
		ev.Time = when
		for _, n := range []struct {
			given *int
			set   func(int)
		}{
			{e.Version, func(v int) { ev.Version = uint8(v) }},
			{e.Level, func(v int) { ev.Level = uint8(v) }},
			{e.Task, func(v int) { ev.Task = uint16(v) }},
			{e.Opcode, func(v int) { ev.Opcode = uint8(v) }},
		} {
			if n.given != nil {
				n.set(*n.given)
			}
		}
		if e.Keywords != "" {
			k, err := libgen.EvtxValue("hex64", e.Keywords)
			if err != nil {
				return nil, fmt.Errorf("evtx.events[%d].keywords: %w", i, err)
			}
			ev.Keywords = binary.LittleEndian.Uint64(k)
		}
		ev.ProcessID = uint32(4 * (100 + c.Rand.Derive("evtx.process", ev.Provider).Stream().IntN(1000)))
		ev.ThreadID = uint32(4 * (1 + c.Rand.Derive("evtx.thread", strconv.Itoa(i)).Stream().IntN(4000)))
		if e.ProcessID != nil {
			ev.ProcessID = uint32(*e.ProcessID)
		}
		if e.ThreadID != nil {
			ev.ThreadID = uint32(*e.ThreadID)
		}
		ev.UserSID = e.UserSID
		out.Events = append(out.Events, ev)
	}
	return libgen.BuildEvtx(out)
}

// buildRegistry builds the hive a registry block describes. Which hive it is
// comes from the file's name; the base block records the file's path the way
// Windows does, as \??\C:\... when the output's first directory is a drive
// letter.
func buildRegistry(c compile.Op) ([]byte, error) {
	keys, err := compile.RegistryKeys(c.Registry, libgen.HiveKind(path.Base(c.Path)), c.When)
	if err != nil {
		return nil, fmt.Errorf("registry: %w", err)
	}
	name := strings.ReplaceAll(c.Path, "/", `\`)
	if len(name) > 2 && name[1] == '\\' && unicode.IsLetter(rune(name[0])) {
		name = `\??\` + name[:1] + ":" + name[1:]
	}
	return libgen.BuildHive(libgen.HiveSpec{FileName: name, Modified: c.When, Keys: keys})
}

// defaultKernel is the kernel release a boot or shutdown record names when
// the scenario gives none.
const defaultKernel = "6.8.0-31-generic"

// buildUtmp maps a utmp block to its records. A login or failed login whose
// pid is not given gets one from the operation's stream, drawn per record,
// and a login's session defaults to its pid, as sshd's does.
func buildUtmp(c compile.Op) ([]byte, error) {
	var out []libgen.UtmpRecord
	for i, r := range c.Utmp.Records {
		when, err := timeOr(r.Time, fmt.Sprintf("utmp.records[%d].time", i), c.When)
		if err != nil {
			return nil, err
		}
		rec := libgen.UtmpRecord{Kind: r.Type, User: r.User, Line: r.Line, Host: r.Host, PID: int32(r.PID), Session: int32(r.Session), Time: when}
		pid := int32(1000 + c.Rand.Derive("utmp.pid", strconv.Itoa(i)).Stream().IntN(30000))
		switch r.Type {
		case "boot", "shutdown":
			rec.Host = cmp.Or(r.Host, defaultKernel)
		case "login", "logout":
			rec.Line = cmp.Or(r.Line, "pts/0")
		case "failed":
			rec.Line = cmp.Or(r.Line, "ssh:notty")
		}
		if rec.PID == 0 && (r.Type == "login" || r.Type == "failed") {
			rec.PID = pid
		}
		if rec.Session == 0 && r.Type == "login" {
			rec.Session = rec.PID
		}
		out = append(out, rec)
	}
	return libgen.BuildUtmp(out)
}

// buildAuditd maps an auditd block to its events. What the block leaves out
// comes from the operation's stream: the first serial, the login session
// and the sshd and shell process ids once for the log, and each program's
// own process id.
func buildAuditd(c compile.Op) ([]byte, error) {
	in := c.Auditd
	d := c.Rand.Derive("auditd.defaults").Stream()
	serial := uint64(1000 + d.IntN(900000))
	session := uint32(1 + d.IntN(50))
	sshd, shell := uint32(1000+d.IntN(30000)), uint32(1000+d.IntN(30000))
	if in.FirstSerial > 0 {
		serial = uint64(in.FirstSerial)
	}
	log := libgen.AuditLog{FirstSerial: serial}
	for i, e := range in.Events {
		when, err := timeOr(e.Time, fmt.Sprintf("auditd.events[%d].time", i), c.When.Add(time.Duration(i)*time.Second))
		if err != nil {
			return nil, err
		}
		uid := uint32(1000)
		if e.User == "root" {
			uid = 0
		}
		if e.UID != nil {
			uid = uint32(*e.UID)
		}
		auid := uid
		if e.AUID != nil {
			auid = uint32(*e.AUID)
		}
		home := "/home/" + e.User
		if uid == 0 {
			home = "/root"
		}
		ev := libgen.AuditEvent{
			Kind: e.Type, Time: when, User: e.User, UID: uid, AUID: auid, Session: session,
			PID: sshd, PPID: 1, Exe: cmp.Or(e.Exe, "/usr/sbin/sshd"), Argv: e.Argv, Cwd: cmp.Or(e.Cwd, home),
			Key: e.Key, Host: e.Host, Addr: e.Host, TTY: e.TTY, Success: e.Success == nil || *e.Success,
		}
		if net.ParseIP(e.Host) == nil {
			ev.Addr = "?"
		}
		if e.Session != 0 {
			ev.Session = uint32(e.Session)
		}
		switch e.Type {
		case "execve":
			ev.PID, ev.PPID = uint32(1000+c.Rand.Derive("auditd.pid", strconv.Itoa(i)).Stream().IntN(30000)), shell
			ev.TTY = cmp.Or(e.TTY, "pts0")
			if e.Exe == "" {
				ev.Exe = e.Argv[0]
				if !strings.HasPrefix(ev.Exe, "/") {
					ev.Exe = "/usr/bin/" + path.Base(ev.Exe)
				}
			}
		case "login":
			ev.Terminal = cmp.Or(e.Terminal, "/dev/pts/0")
		default:
			ev.Terminal = cmp.Or(e.Terminal, "ssh")
		}
		if e.PID != 0 {
			ev.PID = uint32(e.PID)
		}
		if e.PPID != 0 {
			ev.PPID = uint32(e.PPID)
		}
		log.Events = append(log.Events, ev)
	}
	return libgen.BuildAuditLog(log, c.Rand.Derive("auditd").Stream())
}

// historyOf turns the scenario's visits into the builder's, filling in the
// operation's time where a visit gives none.
func historyOf(c compile.Op) (libgen.HistorySpec, error) {
	var out libgen.HistorySpec
	in := c.History
	if in == nil {
		return out, fmt.Errorf("format: %s needs a history block", c.Format)
	}
	at := func(value, field string) (time.Time, error) { return timeOr(value, field, c.When) }
	for i, v := range in.Visits {
		when, err := at(v.Time, fmt.Sprintf("history.visits[%d].time", i))
		if err != nil {
			return out, err
		}
		out.Visits = append(out.Visits, libgen.Visit{
			URL: v.URL, Title: v.Title, Time: when, Transition: v.Transition, FromVisit: v.FromVisit,
		})
	}
	for i, d := range in.Downloads {
		start, err := at(d.Start, fmt.Sprintf("history.downloads[%d].start", i))
		if err != nil {
			return out, err
		}
		end, err := optionalTime(d.End, fmt.Sprintf("history.downloads[%d].end", i))
		if err != nil {
			return out, err
		}
		if end.IsZero() {
			end = start
		}
		out.Downloads = append(out.Downloads, libgen.Download{
			URL: d.URL, TargetPath: d.TargetPath, Start: start, End: end,
			Received: d.ReceivedBytes, Total: d.TotalBytes, MimeType: d.MimeType,
		})
	}
	return out, nil
}

func pdfMeta(op spec.Operation) (libgen.PDFMeta, error) {
	if op.Pdf == nil {
		return libgen.PDFMeta{}, nil
	}
	created, err := optionalTime(op.Pdf.Created, "pdf.created")
	if err != nil {
		return libgen.PDFMeta{}, err
	}
	modified, err := optionalTime(op.Pdf.Modified, "pdf.modified")
	if err != nil {
		return libgen.PDFMeta{}, err
	}
	return libgen.PDFMeta{
		Title:    op.Pdf.Title,
		Author:   op.Pdf.Author,
		Subject:  op.Pdf.Subject,
		Keywords: op.Pdf.Keywords,
		Creator:  op.Pdf.Creator,
		Producer: op.Pdf.Producer,
		Created:  created,
		Modified: modified,
		PageSize: op.Pdf.PageSize,
	}, nil
}
