package spec

// Manifest describes a set of operations to apply under a root directory.
type Manifest struct {
	// Start is the reference time for operations that give no mtime: what
	// ${DATE} formats and what unpinned pdf and email dates default to.
	// RFC3339, or "now" for a run that cannot be reproduced. Optional.
	Start      string            `yaml:"start" json:"start"`
	Variables  map[string]string `yaml:"variables" json:"variables"` // Variables for ${VAR:name} templating
	Operations []Operation       `yaml:"operations" json:"operations"`
}

// ActionName is what an operation does. It is a named type rather than a bare
// string so that an action and one of the many other vocabularies spelled as
// strings here — a format, a content kind, a template name — cannot be passed
// for one another; and the constants below mean a renamed action is a compile
// error at every mention rather than a value nothing matches at run time.
type ActionName string

// The closed set of actions. Actions is the published order, so adding one
// means adding it here, and compile.Fields says which keys it takes.
const (
	ActionCreate   ActionName = "create"
	ActionUpdate   ActionName = "update"
	ActionAppend   ActionName = "append"
	ActionEdit     ActionName = "edit"
	ActionDelete   ActionName = "delete"
	ActionMACE     ActionName = "mace"
	ActionRename   ActionName = "rename"
	ActionCopy     ActionName = "copy"
	ActionTruncate ActionName = "truncate"
	ActionRotate   ActionName = "rotate"
	ActionArchive  ActionName = "archive"
	ActionEmail    ActionName = "email"
	ActionVault    ActionName = "ansible-vault"
	ActionADS      ActionName = "ads"
	ActionMOTW     ActionName = "motw"
)

// Actions is the closed set of action names, in documentation order. It sits
// beside the constants rather than in compile, so the set and the values it
// holds cannot drift apart.
var Actions = []ActionName{
	ActionCreate, ActionUpdate, ActionAppend, ActionEdit, ActionDelete,
	ActionMACE, ActionRename, ActionCopy, ActionTruncate, ActionRotate,
	ActionArchive, ActionEmail, ActionVault, ActionADS, ActionMOTW,
}

// ActionNames is Actions as plain strings, for the messages and schemas that
// list them, so every such list is in the one published order.
func ActionNames() []string {
	out := make([]string, len(Actions))
	for i, a := range Actions {
		out[i] = string(a)
	}
	return out
}

// Format is what kind of file an operation builds. Like ActionName it is a
// named type, so a format cannot be passed where an action is wanted; which
// formats each action accepts is compile.Formats, and the empty Format means
// the content is written through unchanged.
type Format string

// The formats an operation may ask for. Empty, FormatRaw and FormatText write
// the content through; the rest build a file of that type.
const (
	FormatRaw           Format = "raw"
	FormatText          Format = "text"
	FormatPDF           Format = "pdf"
	FormatDOCX          Format = "docx"
	FormatPE            Format = "pe"
	FormatZip           Format = "zip"
	FormatPNG           Format = "png"
	FormatJPEG          Format = "jpeg"
	FormatMP4           Format = "mp4"
	FormatChromeHistory Format = "chrome_history"
	FormatFirefoxPlaces Format = "firefox_places"
	FormatLNK           Format = "lnk"
	FormatPrefetch      Format = "prefetch"
	FormatEvtx          Format = "evtx"
	FormatRegistry      Format = "regf"
	FormatUtmp          Format = "utmp"
	FormatAuditd        Format = "auditd"
	FormatEML           Format = "eml"
	FormatMbox          Format = "mbox"
)

// FormatNames is a list of formats as plain strings, for a message or a schema
// that lists them.
func FormatNames(formats []Format) []string {
	out := make([]string, len(formats))
	for i, f := range formats {
		out[i] = string(f)
	}
	return out
}

// Operation represents a single action. The closed set of action names is
// Actions; which keys each one takes is compile.Fields. This struct is the
// union of every key any action takes.
type Operation struct {
	Action     ActionName `yaml:"action" json:"action"`
	Path       string     `yaml:"path" json:"path"`               // required for most actions
	ID         string     `yaml:"id" json:"id" render:"-"`        // names what this action creates or renames, for later ref/refs
	Ref        string     `yaml:"ref" json:"ref" render:"-"`      // instead of path: the one live path created under this id
	Refs       string     `yaml:"refs" json:"refs" render:"-"`    // instead of path: every live path created under this id
	MissingOK  bool       `yaml:"missing_ok" json:"missing_ok"`   // delete: a missing path is a recorded no-op, not an error
	NewPath    string     `yaml:"new_path" json:"new_path"`       // for rename/rotate/copy
	Type       string     `yaml:"type" json:"type"`               // for create: file|dir
	Ext        string     `yaml:"ext" json:"ext"`                 // for create file when path is a directory
	Content    string     `yaml:"content" json:"content"`         // optional literal content
	ContentLen int        `yaml:"content_len" json:"content_len"` // if Content empty, generate deterministic random of this length
	// ContentKind is what the invented bytes look like: text (the default,
	// base32), bytes, zeros, pattern or lorem.
	ContentKind string `yaml:"content_kind" json:"content_kind"`
	Atime       string `yaml:"atime" json:"atime"`   // RFC3339, access time
	Mtime       string `yaml:"mtime" json:"mtime"`   // RFC3339, modification time
	Ctime       string `yaml:"ctime" json:"ctime"`   // RFC3339, metadata change time (Windows NTFS/ReFS only)
	Crtime      string `yaml:"crtime" json:"crtime"` // RFC3339, creation (birth) time (Windows only)

	// Authoring extras
	ContentFile string `yaml:"content_file" json:"content_file"` // load content from a file relative to the manifest/playbook
	Render      *bool  `yaml:"render" json:"render"`             // run ${...} substitution over the content; defaults to false for content_file, true for inline content
	Mode        string `yaml:"mode" json:"mode"`                 // octal file permissions, e.g. "0600"
	// Format says what kind of file to build rather than how to write the
	// bytes through: compile.TypedFormats for a create or an update, eml or
	// mbox for an email. Empty, raw and text write the content unchanged.
	Format Format `yaml:"format" json:"format"`

	// Typed generators
	Pdf     *PdfSpec     `yaml:"pdf" json:"pdf"`         // metadata for format: pdf
	Docx    *DocxSpec    `yaml:"docx" json:"docx"`       // metadata for format: docx
	Pe      *PeSpec      `yaml:"pe" json:"pe"`           // for format: pe
	History *HistorySpec `yaml:"history" json:"history"` // for format: chrome_history or firefox_places
	Lnk     *LnkSpec     `yaml:"lnk" json:"lnk"`         // for format: lnk
	// Prefetch is for format: prefetch, a Windows prefetch file.
	Prefetch *PrefetchSpec `yaml:"prefetch" json:"prefetch"`
	// Evtx is for format: evtx, a Windows event log.
	Evtx *EvtxSpec `yaml:"evtx" json:"evtx"`
	// Registry is for format: regf, a Windows registry hive file.
	Registry *RegistrySpec `yaml:"registry" json:"registry"`
	// Utmp is for format: utmp, a Linux utmp, wtmp or btmp login record.
	Utmp *UtmpSpec `yaml:"utmp" json:"utmp"`
	// Auditd is for format: auditd, a Linux audit log.
	Auditd *AuditdSpec `yaml:"auditd" json:"auditd"`
	// Slack asks for bytes past the end of the file, in the rest of its last
	// cluster, where a carver looks and a file read never does.
	Slack   *SlackSpec   `yaml:"slack" json:"slack"`
	Email   *EmailSpec   `yaml:"email" json:"email"`     // for the email action
	Vault   *VaultSpec   `yaml:"vault" json:"vault"`     // for the ansible-vault action
	Archive *ArchiveSpec `yaml:"archive" json:"archive"` // for the archive action
	Edit    *EditSpec    `yaml:"edit" json:"edit"`       // for the edit action

	// Windows-only extras
	Stream      string `yaml:"stream" json:"stream"`             // for ads: stream name (e.g., Zone.Identifier)
	ZoneID      int    `yaml:"zone_id" json:"zone_id"`           // for motw: ZoneId value (0-4)
	HostURL     string `yaml:"host_url" json:"host_url"`         // for motw
	ReferrerURL string `yaml:"referrer_url" json:"referrer_url"` // for motw

	// Annotations: what the action means, never what it does.

	// Mitre lists the ATT&CK techniques the action exhibits (T1070.006,
	// T1564.004), for the answer key and the Navigator layer. It changes
	// nothing the action does and no byte it writes.
	Mitre []string `yaml:"mitre" json:"mitre" render:"-"`
}

// DocxSpec carries the document properties a .docx keeps inside itself, which
// is what a metadata tool reports and what survives a copy.
type DocxSpec struct {
	Title    string `yaml:"title" json:"title"`
	Author   string `yaml:"author" json:"author"`
	Created  string `yaml:"created" json:"created"`   // RFC3339; defaults to the operation time
	Modified string `yaml:"modified" json:"modified"` // RFC3339; defaults to created
}

// PeSpec describes a Windows executable. What fsagen writes is a container
// for a parser to read: headers, sections of filler, an import table and a
// version resource. It holds no program and does nothing if it is run.
type PeSpec struct {
	Machine   string      `yaml:"machine" json:"machine"`     // amd64 (default), i386, arm64
	Subsystem string      `yaml:"subsystem" json:"subsystem"` // console (default), gui, native
	Dll       bool        `yaml:"dll" json:"dll"`             // mark the image as a DLL
	Timestamp string      `yaml:"timestamp" json:"timestamp"` // RFC3339; defaults to the operation time
	Sections  []PeSection `yaml:"sections" json:"sections"`
	Imports   []string    `yaml:"imports" json:"imports"` // "kernel32.dll!CreateFileW"
	Version   *PeVersion  `yaml:"version" json:"version"`
}

// PeSection is one section of the image.
type PeSection struct {
	Name  string   `yaml:"name" json:"name"`
	Size  int      `yaml:"size" json:"size"`   // bytes of filler; defaults to 512
	Flags []string `yaml:"flags" json:"flags"` // code, initialized_data, execute, read, write, ...
}

// PeVersion is the version resource Explorer and every metadata tool read.
type PeVersion struct {
	FileVersion      string `yaml:"file_version" json:"file_version"`
	ProductVersion   string `yaml:"product_version" json:"product_version"`
	CompanyName      string `yaml:"company_name" json:"company_name"`
	FileDescription  string `yaml:"file_description" json:"file_description"`
	InternalName     string `yaml:"internal_name" json:"internal_name"`
	OriginalFilename string `yaml:"original_filename" json:"original_filename"`
	ProductName      string `yaml:"product_name" json:"product_name"`
	LegalCopyright   string `yaml:"legal_copyright" json:"legal_copyright"`
}

// LnkSpec describes a Windows shell link (.lnk): what it points at, and what
// it records about the target, the target's volume and the machine it was
// made on. Every time defaults to the operation time; the volume serial,
// machine name and the target's NTFS file reference are drawn from the seed
// when not given.
type LnkSpec struct {
	Target       string `yaml:"target" json:"target"`           // a Windows path on a drive letter, C:\dir\file.exe; required
	TargetType   string `yaml:"target_type" json:"target_type"` // file (default) or dir
	Arguments    string `yaml:"arguments" json:"arguments"`
	WorkingDir   string `yaml:"working_dir" json:"working_dir"`
	RelativePath string `yaml:"relative_path" json:"relative_path"`
	Description  string `yaml:"description" json:"description"`
	Icon         string `yaml:"icon" json:"icon"` // icon location
	IconIndex    int    `yaml:"icon_index" json:"icon_index"`
	ShowCommand  string `yaml:"show_command" json:"show_command"`   // normal (default), maximized, minimized
	DriveType    string `yaml:"drive_type" json:"drive_type"`       // fixed (default), removable, cdrom, ramdisk
	VolumeSerial string `yaml:"volume_serial" json:"volume_serial"` // 1A2B-3C4D or 1A2B3C4D
	VolumeLabel  string `yaml:"volume_label" json:"volume_label"`
	MachineID    string `yaml:"machine_id" json:"machine_id"`       // NetBIOS name, at most 15 ASCII characters
	TargetCrtime string `yaml:"target_crtime" json:"target_crtime"` // RFC3339
	TargetAtime  string `yaml:"target_atime" json:"target_atime"`   // RFC3339
	TargetMtime  string `yaml:"target_mtime" json:"target_mtime"`   // RFC3339
	TargetSize   int64  `yaml:"target_size" json:"target_size"`
	// TargetAttributes are any of readonly, hidden, system and archive. With
	// none, a file is archive.
	TargetAttributes []string `yaml:"target_attributes" json:"target_attributes"`
}

// PrefetchSpec describes a Windows prefetch file (.pf): which program ran,
// how many times and when it last did, and what it loaded. Windows' own name
// for the file is the program's name and the hash of its path,
// CMD.EXE-D269B812.pf; a file named that way must match.
type PrefetchSpec struct {
	Executable string `yaml:"executable" json:"executable"` // the program's Windows path, C:\Windows\System32\cmd.exe; required
	Version    string `yaml:"version" json:"version"`       // win11 (default) or win10
	// Compressed says whether the file is MAM-compressed, as Windows 10 and
	// 11 write it; default true.
	Compressed *bool `yaml:"compressed" json:"compressed"`
	RunCount   int   `yaml:"run_count" json:"run_count"` // defaults to the number of last_run_times
	// LastRunTimes are when the program last ran, RFC3339, at most 8, in any
	// order; default the operation time.
	LastRunTimes []string `yaml:"last_run_times" json:"last_run_times"`
	// ReferencedFiles are the Windows paths of what the program loaded besides
	// itself and ntdll.dll, which are always listed. Without them it loaded
	// kernel32.dll and KernelBase.dll.
	ReferencedFiles []string `yaml:"referenced_files" json:"referenced_files"`
	// HarddiskVolume is the n of \Device\HarddiskVolume<n> for the
	// executable's volume, which the hash is computed over; default 3.
	HarddiskVolume int `yaml:"harddisk_volume" json:"harddisk_volume"`
	// Volumes say what the file records about the volumes its files are on;
	// a drive not listed gets a serial and creation time from the seed.
	Volumes []PrefetchVolume `yaml:"volumes" json:"volumes"`
}

// PrefetchVolume is a volume as a prefetch file records it.
type PrefetchVolume struct {
	Drive   string `yaml:"drive" json:"drive"`     // the drive letter, C
	Serial  string `yaml:"serial" json:"serial"`   // 1A2B-3C4D or 1A2B3C4D
	Created string `yaml:"created" json:"created"` // RFC3339, when the volume was formatted
}

// EvtxSpec describes a Windows event log (.evtx): one channel's events, as
// a machine logged them. Events 1102, 4624, 4688 and 7045 are built in: their
// provider, channel, version, level, task, opcode, keywords and the names and
// types of their data are Windows' own, and a data value left out is what
// Windows writes when it has none. Any other event names its provider, and
// its data are strings.
type EvtxSpec struct {
	// Channel is the log's channel, Security or System; default the channel
	// the built-in events are logged to, else Application.
	Channel string `yaml:"channel" json:"channel"`
	// Computer is the name of the machine that logged the events; default
	// DESKTOP- and seven characters from the seed.
	Computer      string      `yaml:"computer" json:"computer"`
	FirstRecordID int64       `yaml:"first_record_id" json:"first_record_id"` // the first event's record id; default 1
	Events        []EvtxEvent `yaml:"events" json:"events"`
}

// EvtxEvent is one logged event. Every field but event_id has a default.
type EvtxEvent struct {
	EventID int    `yaml:"event_id" json:"event_id"`
	Time    string `yaml:"time" json:"time"` // RFC3339; default the operation time
	// Provider and ProviderGUID name who logged the event; required for an
	// event that is not built in.
	Provider     string `yaml:"provider" json:"provider"`
	ProviderGUID string `yaml:"provider_guid" json:"provider_guid"`
	Version      *int   `yaml:"version" json:"version"`
	Level        *int   `yaml:"level" json:"level"` // 0 LogAlways, 1 Critical, 2 Error, 3 Warning, 4 Information (default), 5 Verbose
	Task         *int   `yaml:"task" json:"task"`
	Opcode       *int   `yaml:"opcode" json:"opcode"`
	Keywords     string `yaml:"keywords" json:"keywords"` // 64 bits, 0x8020000000000000
	// ProcessID and ThreadID are of the process that logged the event;
	// default from the seed.
	ProcessID *int   `yaml:"process_id" json:"process_id"`
	ThreadID  *int   `yaml:"thread_id" json:"thread_id"`
	UserSID   string `yaml:"user_sid" json:"user_sid"` // the Security element's UserID, S-1-5-18; default none
	// Data are the event's data values by name. A built-in event takes the
	// names Windows gives its data, each in its own type; any other event
	// takes strings, written in name order.
	Data map[string]string `yaml:"data" json:"data"`
}

// RegistrySpec describes a Windows registry hive file: its keys and their
// values, and the artefacts Windows writes that a scenario most often wants,
// each where its hive keeps it. Which hive a file is comes from its name:
// NTUSER.DAT, USRCLASS.DAT, SYSTEM, SOFTWARE, SAM, SECURITY or DEFAULT.
type RegistrySpec struct {
	Keys []RegistryKey `yaml:"keys" json:"keys"`
	// Run are programs started at logon, in NTUSER.DAT or SOFTWARE.
	Run []RegistryRun `yaml:"run" json:"run"`
	// UserAssist are Explorer's records of programs a user started, in
	// NTUSER.DAT.
	UserAssist []RegistryUserAssist `yaml:"userassist" json:"userassist"`
	// USBStor are USB storage devices the machine has seen, in SYSTEM.
	USBStor []RegistryUSB `yaml:"usbstor" json:"usbstor"`
}

// RegistryKey is a key, by its path below the hive's root, and its values.
// A key's parents are created as needed.
type RegistryKey struct {
	Path        string          `yaml:"path" json:"path"`                 // Software\Microsoft\Windows\CurrentVersion\Run
	LastWritten string          `yaml:"last_written" json:"last_written"` // RFC3339; default the operation time
	Values      []RegistryValue `yaml:"values" json:"values"`
}

// RegistryValue is one value. Data is text for the string types, a number
// for the integer types and hex bytes for REG_BINARY and REG_NONE;
// REG_MULTI_SZ takes strings instead.
type RegistryValue struct {
	Name    string   `yaml:"name" json:"name"` // empty is the key's default value
	Type    string   `yaml:"type" json:"type"` // REG_SZ (default), REG_EXPAND_SZ, REG_MULTI_SZ, REG_DWORD, REG_QWORD, REG_BINARY, REG_NONE, REG_DWORD_BIG_ENDIAN
	Data    string   `yaml:"data" json:"data"`
	Strings []string `yaml:"strings" json:"strings"`
}

// RegistryRun is one program started at logon.
type RegistryRun struct {
	Name    string `yaml:"name" json:"name"`
	Command string `yaml:"command" json:"command"`
}

// RegistryUserAssist is one program or shortcut a user started from
// Explorer.
type RegistryUserAssist struct {
	Path        string `yaml:"path" json:"path"`                   // the program's or the shortcut's Windows path
	RunCount    int    `yaml:"run_count" json:"run_count"`         // default 1
	FocusCount  int    `yaml:"focus_count" json:"focus_count"`     // times it had the focus
	FocusTimeMs int    `yaml:"focus_time_ms" json:"focus_time_ms"` // how long it had the focus, in milliseconds
	LastRun     string `yaml:"last_run" json:"last_run"`           // RFC3339; default the operation time
}

// RegistryUSB is a USB storage device as the SYSTEM hive remembers it.
type RegistryUSB struct {
	Vendor   string `yaml:"vendor" json:"vendor"`     // at most 8 characters
	Product  string `yaml:"product" json:"product"`   // at most 16 characters
	Revision string `yaml:"revision" json:"revision"` // at most 4 characters
	Serial   string `yaml:"serial" json:"serial"`
	// FirstInstall and LastArrival default to the operation time; a device
	// without a LastRemoval is still connected.
	FirstInstall string `yaml:"first_install" json:"first_install"`
	LastArrival  string `yaml:"last_arrival" json:"last_arrival"`
	LastRemoval  string `yaml:"last_removal" json:"last_removal"`
}

// UtmpSpec describes a Linux login record file: utmp (who is logged in),
// wtmp (logins, logouts, boots and shutdowns) or btmp (failed logins), which
// the file's name says. Each record is glibc's struct utmp, which holds no
// time after 2038-01-19T03:14:07Z.
type UtmpSpec struct {
	Records []UtmpRecord `yaml:"records" json:"records"`
}

// UtmpRecord is one record.
type UtmpRecord struct {
	Type string `yaml:"type" json:"type"` // boot, shutdown, login, logout or failed (btmp only)
	// User is who logged in or tried to; in a playbook it defaults to the
	// actor.
	User string `yaml:"user" json:"user"`
	// Line is the terminal: pts/0 by default, ssh:notty for a failed SSH
	// login. A logout names the line of the login it ends.
	Line string `yaml:"line" json:"line"`
	// Host is where a login came from, a name or an address; for a boot or
	// shutdown, the kernel release.
	Host    string `yaml:"host" json:"host"`
	PID     int    `yaml:"pid" json:"pid"`         // the login process; default from the seed, and a logout's is its login's
	Session int    `yaml:"session" json:"session"` // the session id
	Time    string `yaml:"time" json:"time"`       // RFC3339; default the operation time
}

// AuditdSpec describes a Linux audit log (audit.log) in auditd's raw format:
// programs executed, as the kernel records an execve, and logins, as PAM and
// sshd record them.
type AuditdSpec struct {
	FirstSerial int64         `yaml:"first_serial" json:"first_serial"` // the first event's serial; default from the seed
	Events      []AuditdEvent `yaml:"events" json:"events"`
}

// AuditdEvent is one event.
type AuditdEvent struct {
	Type string `yaml:"type" json:"type"` // execve, auth, login or session_start
	// Time is when it happened, RFC3339; default the operation time plus a
	// second for each event before it.
	Time string `yaml:"time" json:"time"`
	// User is the account; in a playbook it defaults to the actor.
	User string `yaml:"user" json:"user"`
	UID  *int   `yaml:"uid" json:"uid"`   // default 0 for root, else 1000
	AUID *int   `yaml:"auid" json:"auid"` // the login's user id; default the uid
	// Session is the login session's number; default from the seed.
	Session int `yaml:"session" json:"session"`
	PID     int `yaml:"pid" json:"pid"`   // default from the seed
	PPID    int `yaml:"ppid" json:"ppid"` // default from the seed
	// Exe is the program run, or the service a login went through
	// (default /usr/sbin/sshd). Argv are its arguments, the program first;
	// Cwd where it ran, default the user's home.
	Exe  string   `yaml:"exe" json:"exe"`
	Argv []string `yaml:"argv" json:"argv"`
	Cwd  string   `yaml:"cwd" json:"cwd"`
	Key  string   `yaml:"key" json:"key"` // the audit rule key, which ausearch -k finds
	// Host is where a login came from; Terminal what it was on (default ssh,
	// and the pts for a login); TTY the terminal a program ran on.
	Host     string `yaml:"host" json:"host"`
	Terminal string `yaml:"terminal" json:"terminal"`
	TTY      string `yaml:"tty" json:"tty"`
	Success  *bool  `yaml:"success" json:"success"` // default true
}

// SlackSpec is what fills a file's slack: the bytes between the end of its
// content and the end of its last cluster.
type SlackSpec struct {
	ClusterSize int    `yaml:"cluster_size" json:"cluster_size"` // bytes; 4096 by default, and on a live volume it must be the volume's
	Kind        string `yaml:"kind" json:"kind"`                 // canary (default), pattern or fragment
	// FragmentOf is, for kind fragment, the id of a file still present at
	// that point in the scenario; its first bytes fill the slack, as an
	// earlier file's would that once had the cluster.
	FragmentOf string `yaml:"fragment_of" json:"fragment_of" render:"-"`
}

// HistorySpec is the browsing a profile database records.
type HistorySpec struct {
	Visits    []HistoryVisit    `yaml:"visits" json:"visits"`
	Downloads []HistoryDownload `yaml:"downloads" json:"downloads"` // Chrome only
}

// HistoryVisit is one page view.
type HistoryVisit struct {
	URL        string `yaml:"url" json:"url"`
	Title      string `yaml:"title" json:"title"`
	Time       string `yaml:"time" json:"time"`             // RFC3339; defaults to the operation time
	Transition string `yaml:"transition" json:"transition"` // link (default), typed, bookmark, generated, form_submit, reload
	// FromVisit is the 1-based position in this list of the visit this one
	// came from. Zero means none.
	FromVisit int `yaml:"from_visit" json:"from_visit"`
}

// HistoryDownload is one completed download.
type HistoryDownload struct {
	URL           string `yaml:"url" json:"url"`
	TargetPath    string `yaml:"target_path" json:"target_path"`
	Start         string `yaml:"start" json:"start"` // RFC3339; defaults to the operation time
	End           string `yaml:"end" json:"end"`     // RFC3339; defaults to start
	ReceivedBytes int64  `yaml:"received_bytes" json:"received_bytes"`
	TotalBytes    int64  `yaml:"total_bytes" json:"total_bytes"`
	MimeType      string `yaml:"mime_type" json:"mime_type"`
}

// ArchiveSpec selects what goes into an archive and how.
type ArchiveSpec struct {
	Method  string `yaml:"method" json:"method"`   // store (default) or deflate
	Comment string `yaml:"comment" json:"comment"` // the archive comment
	// Members are glob patterns, relative to the actor base, matched against
	// the tree as it stands when the archive is written.
	Members []string `yaml:"members" json:"members"`
	// MemberRefs name ids; every live path created under each one joins the
	// archive, in the order it was created.
	MemberRefs []string `yaml:"member_refs" json:"member_refs" render:"-"`
	// Base is stripped from each member's stored name. Without it a member is
	// stored under its whole path relative to the output root.
	Base string `yaml:"base" json:"base"`
}

// EditSpec changes a file in place. The steps run in the order they are
// listed here: lines go first, then substitutions, then insertions.
type EditSpec struct {
	// DeleteLines is a 1-based inclusive range ("40-60") or a single line.
	DeleteLines string `yaml:"delete_lines" json:"delete_lines"`
	// DeleteMatching removes every line the regular expression matches.
	DeleteMatching string        `yaml:"delete_matching" json:"delete_matching"`
	Replace        []EditReplace `yaml:"replace" json:"replace"`
	InsertAfter    []EditInsert  `yaml:"insert_after" json:"insert_after"`
}

// EditReplace is one regular-expression substitution over the whole file.
type EditReplace struct {
	Pattern string `yaml:"pattern" json:"pattern"`
	With    string `yaml:"with" json:"with"`   // $1 and ${name} expand to groups
	Count   int    `yaml:"count" json:"count"` // 0 means every match
}

// EditInsert puts a line after each line the pattern matches.
type EditInsert struct {
	Pattern string `yaml:"pattern" json:"pattern"`
	Text    string `yaml:"text" json:"text"`
}

// PdfSpec carries PDF document metadata. Every field is optional; the
// timestamps are RFC3339 and pinning them is what keeps output reproducible.
type PdfSpec struct {
	Title    string `yaml:"title" json:"title"`
	Author   string `yaml:"author" json:"author"`
	Subject  string `yaml:"subject" json:"subject"`
	Keywords string `yaml:"keywords" json:"keywords"`
	Creator  string `yaml:"creator" json:"creator"`
	Producer string `yaml:"producer" json:"producer"`
	Created  string `yaml:"created" json:"created"`     // RFC3339
	Modified string `yaml:"modified" json:"modified"`   // RFC3339
	PageSize string `yaml:"page_size" json:"page_size"` // A4 (default), Letter, A3, A5
}

// Header is a single message header. Headers are an ordered sequence rather
// than a map because order is observable and Received: legitimately repeats.
type Header struct {
	Name  string `yaml:"name" json:"name"`
	Value string `yaml:"value" json:"value"`
}

// Attachment names one MIME attachment part.
type Attachment struct {
	SourceFile  string `yaml:"source_file" json:"source_file"`   // path relative to the manifest/playbook file
	SourceRoot  string `yaml:"source_root" json:"source_root"`   // path relative to the output root, for chaining generated artifacts
	Ref         string `yaml:"ref" json:"ref" render:"-"`        // instead of source_root: the one live path created under this id
	Content     string `yaml:"content" json:"content"`           // inline literal content
	Name        string `yaml:"name" json:"name"`                 // filename shown to the recipient
	ContentType string `yaml:"content_type" json:"content_type"` // defaults from the filename extension
	Disposition string `yaml:"disposition" json:"disposition"`   // attachment (default) or inline
	ContentID   string `yaml:"content_id" json:"content_id"`     // for disposition: inline
}

// EmailSpec describes one RFC 5322 message.
type EmailSpec struct {
	From         string       `yaml:"from" json:"from"`
	To           []string     `yaml:"to" json:"to"`
	Cc           []string     `yaml:"cc" json:"cc"`
	Bcc          []string     `yaml:"bcc" json:"bcc"`
	ReplyTo      string       `yaml:"reply_to" json:"reply_to"`
	ReturnPath   string       `yaml:"return_path" json:"return_path"`
	Subject      string       `yaml:"subject" json:"subject"`
	Date         string       `yaml:"date" json:"date"` // RFC3339, rendered into the Date: header as RFC 5322
	MessageID    string       `yaml:"message_id" json:"message_id"`
	InReplyTo    string       `yaml:"in_reply_to" json:"in_reply_to"`
	References   []string     `yaml:"references" json:"references"`
	Headers      []Header     `yaml:"headers" json:"headers"`
	BodyText     string       `yaml:"body_text" json:"body_text"`
	BodyHTML     string       `yaml:"body_html" json:"body_html"`
	BodyTextFile string       `yaml:"body_text_file" json:"body_text_file"`
	BodyHTMLFile string       `yaml:"body_html_file" json:"body_html_file"`
	Attachments  []Attachment `yaml:"attachments" json:"attachments"`
}

// VaultSpec configures the ansible-vault action.
type VaultSpec struct {
	Password string `yaml:"password" json:"password"`
	VaultID  string `yaml:"vault_id" json:"vault_id"` // non-empty selects the 1.2 header format
	Salt     string `yaml:"salt" json:"salt"`         // optional 32-byte hex salt; drawn from the operation's random stream when empty
}

type Playbook struct {
	// Start time for the playbook, RFC3339 or "now"
	Start     string            `yaml:"start" json:"start"`
	Variables map[string]string `yaml:"variables" json:"variables"` // Global variables for templating
	// SubsecondJitter adds a seeded fraction of a second to every time
	// derived from the schedule (never to an explicit one), so a corpus does
	// not have every timestamp on a whole second.
	SubsecondJitter bool    `yaml:"subsecond_jitter" json:"subsecond_jitter"`
	Actors          []Actor `yaml:"actors" json:"actors"`
	Steps           []Step  `yaml:"steps" json:"steps"`
}

type Actor struct {
	Name      string            `yaml:"name" json:"name"`
	Base      string            `yaml:"base" json:"base"`           // base directory under root for this actor
	Variables map[string]string `yaml:"variables" json:"variables"` // Actor-specific variables
}

type Step struct {
	Actor      string   `yaml:"actor" json:"actor"`
	Offset     string   `yaml:"offset" json:"offset"` // duration from playbook start for first iteration
	Every      string   `yaml:"every" json:"every"`   // repeat interval
	Repeat     int      `yaml:"repeat" json:"repeat"`
	Condition  string   `yaml:"condition" json:"condition"`     // "odd", "even", "first", "last"; tested against the iteration index
	BatchCount int      `yaml:"batch_count" json:"batch_count"` // Generate N files in this step
	Mitre      []string `yaml:"mitre" json:"mitre"`             // ATT&CK techniques every action in the step exhibits
	Actions    []Action `yaml:"actions" json:"actions"`
}

// Action is one operation in a playbook step, with the scheduling a playbook
// adds around it: when it fires relative to its step, and which occurrences it
// applies to. Everything else it carries is the operation itself, embedded, so
// a key an operation takes is a key an action takes and the two cannot drift.
type Action struct {
	Operation `yaml:",inline"`

	Template  string `yaml:"template" json:"template"`   // Predefined template: "email", "log", "script", "doc"
	Offset    string `yaml:"offset" json:"offset"`       // relative to step occurrence time
	Condition string `yaml:"condition" json:"condition"` // Action-level condition; tested against the batch index
}
