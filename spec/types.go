package spec

// Manifest describes a set of operations to apply under a root directory.
type Manifest struct {
	Variables  map[string]string `yaml:"variables" json:"variables"` // Variables for ${VAR:name} templating
	Operations []Operation       `yaml:"operations" json:"operations"`
}

// Operation represents a single action.
// Actions: create, update, append, delete, mace, rename, copy, truncate,
// rotate, ads, motw, email, ansible-vault
type Operation struct {
	Action     string `yaml:"action" json:"action"`
	Path       string `yaml:"path" json:"path"`               // required for most actions
	ID         string `yaml:"id" json:"id" render:"-"`        // names what this action creates or renames, for later ref/refs
	Ref        string `yaml:"ref" json:"ref" render:"-"`      // instead of path: the one live path created under this id
	Refs       string `yaml:"refs" json:"refs" render:"-"`    // instead of path: every live path created under this id
	MissingOK  bool   `yaml:"missing_ok" json:"missing_ok"`   // delete: a missing path is a recorded no-op, not an error
	NewPath    string `yaml:"new_path" json:"new_path"`       // for rename/rotate/copy
	Type       string `yaml:"type" json:"type"`               // for create: file|dir
	Ext        string `yaml:"ext" json:"ext"`                 // for create file when path is a directory
	Content    string `yaml:"content" json:"content"`         // optional literal content
	ContentLen int    `yaml:"content_len" json:"content_len"` // if Content empty, generate deterministic random of this length
	Atime      string `yaml:"atime" json:"atime"`             // RFC3339
	Mtime      string `yaml:"mtime" json:"mtime"`             // RFC3339

	// Authoring extras
	ContentFile string `yaml:"content_file" json:"content_file"` // load content from a file relative to the manifest/playbook
	Render      *bool  `yaml:"render" json:"render"`             // run ${...} substitution over the content; defaults to false for content_file, true for inline content
	Mode        string `yaml:"mode" json:"mode"`                 // octal file permissions, e.g. "0600"
	Format      string `yaml:"format" json:"format"`             // raw|pdf|eml|mbox - how to interpret the content when creating

	// Typed generators
	Pdf   *PdfSpec   `yaml:"pdf" json:"pdf"`     // metadata for format: pdf
	Email *EmailSpec `yaml:"email" json:"email"` // for the email action
	Vault *VaultSpec `yaml:"vault" json:"vault"` // for the ansible-vault action

	// Windows-only extras
	Stream      string `yaml:"stream" json:"stream"`             // for ads: stream name (e.g., Zone.Identifier)
	ZoneID      int    `yaml:"zone_id" json:"zone_id"`           // for motw: ZoneId value (0-4)
	HostURL     string `yaml:"host_url" json:"host_url"`         // for motw
	ReferrerURL string `yaml:"referrer_url" json:"referrer_url"` // for motw
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
	Salt     string `yaml:"salt" json:"salt"`         // optional 32-byte hex salt; drawn from the seeded PRNG when empty
}

type Playbook struct {
	// Start time for the playbook, RFC3339 or "now"
	Start     string            `yaml:"start" json:"start"`
	Variables map[string]string `yaml:"variables" json:"variables"` // Global variables for templating
	Actors    []Actor           `yaml:"actors" json:"actors"`
	Steps     []Step            `yaml:"steps" json:"steps"`
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

// Action mirrors Operation but supports a relative time offset and template selection.
type Action struct {
	Action     string `yaml:"action" json:"action"`
	Path       string `yaml:"path" json:"path"`
	ID         string `yaml:"id" json:"id" render:"-"`
	Ref        string `yaml:"ref" json:"ref" render:"-"`
	Refs       string `yaml:"refs" json:"refs" render:"-"`
	MissingOK  bool   `yaml:"missing_ok" json:"missing_ok"`
	NewPath    string `yaml:"new_path" json:"new_path"`
	Type       string `yaml:"type" json:"type"`
	Ext        string `yaml:"ext" json:"ext"`
	Content    string `yaml:"content" json:"content"`
	ContentLen int    `yaml:"content_len" json:"content_len"`
	Template   string `yaml:"template" json:"template"`   // Predefined template: "email", "log", "script", "doc"
	Offset     string `yaml:"offset" json:"offset"`       // relative to step occurrence time
	Condition  string `yaml:"condition" json:"condition"` // Action-level condition; tested against the batch index
	// Optional explicit times override the computed time when provided
	Atime string `yaml:"atime" json:"atime"`
	Mtime string `yaml:"mtime" json:"mtime"`

	// Authoring extras
	ContentFile string `yaml:"content_file" json:"content_file"`
	Render      *bool  `yaml:"render" json:"render"`
	Mode        string `yaml:"mode" json:"mode"`
	Format      string `yaml:"format" json:"format"`

	// Typed generators
	Pdf   *PdfSpec   `yaml:"pdf" json:"pdf"`
	Email *EmailSpec `yaml:"email" json:"email"`
	Vault *VaultSpec `yaml:"vault" json:"vault"`

	// Windows-only extras
	Stream      string `yaml:"stream" json:"stream"`
	ZoneID      int    `yaml:"zone_id" json:"zone_id"`
	HostURL     string `yaml:"host_url" json:"host_url"`
	ReferrerURL string `yaml:"referrer_url" json:"referrer_url"`
}
