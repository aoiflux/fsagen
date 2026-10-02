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
	Email   *EmailSpec   `yaml:"email" json:"email"`     // for the email action
	Vault   *VaultSpec   `yaml:"vault" json:"vault"`     // for the ansible-vault action
	Archive *ArchiveSpec `yaml:"archive" json:"archive"` // for the archive action
	Edit    *EditSpec    `yaml:"edit" json:"edit"`       // for the edit action

	// Windows-only extras
	Stream      string `yaml:"stream" json:"stream"`             // for ads: stream name (e.g., Zone.Identifier)
	ZoneID      int    `yaml:"zone_id" json:"zone_id"`           // for motw: ZoneId value (0-4)
	HostURL     string `yaml:"host_url" json:"host_url"`         // for motw
	ReferrerURL string `yaml:"referrer_url" json:"referrer_url"` // for motw
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
