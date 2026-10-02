// Package constant holds the values that define what this build produces: the
// file types it can write, the sizes it defaults to, and the version number
// that says which bytes those add up to.
//
// The types a bulk run or a manifest can create:
//   - Text and documents: .txt, .md, .docx, .pdf
//   - Images and media: .png, .jpg, .mp4
//   - Data and markup: .csv, .json, .jsonl, .xml, .html
//   - Logs: .log, .syslog
//   - Archives: .zip
//   - Email: .eml, .mbox
//   - Browser history: .db (Chrome urls and visits), .sqlite (Firefox places)
//   - Windows artifacts: .reg, .exe (a real PE image with headers, sections of
//     filler, an import table and a version resource, holding no code)
//
// Every one is built to be read by a forensic tool rather than used by the
// application that owns it: the structure a parser walks is there, and the
// payload inside it is invented.
package constant

const (
	// FileNameLen is how many characters long an invented file or directory
	// name is, before its extension.
	FileNameLen = 10
	// ContentLen is how many bytes of invented content a bulk file carries
	// when nothing says otherwise.
	ContentLen = 200000
)

// GeneratorVersion identifies the byte output of this build. It is bumped by
// every change that alters a covered output (file and stream content, the
// dry-run listing, the ledger, the answer key, the modelled timeline, the
// run manifest) for some seed and input, and is never reused for different
// bytes.
//
// Version 1 matches 7accc8d for valid inputs. Version 2 draws every random
// value from a stream keyed by the operation (prng), reads no wall clock,
// writes empty content as empty and runs playbooks in time order. Version 3
// sets all four times from the scenario, settles and verifies them, copies
// streams with a copy, writes a ledger, and lists intended times in the
// dry-run listing. Version 4 adds MD5s, the kind of a deleted object, the
// stream an ads or motw wrote, the object a rotate moves and the explicit
// time fields to the ledger, and writes the answer key. Version 5 makes the
// tool answerable for what it claims: it verifies every time it set by reading
// it back, records what it could not do, and writes a modelled timeline beside
// the observed one. Version 6 builds the bulk eml, mbox and pdf with the same
// builders the email and pdf formats use, rather than a second hand-written
// copy of each: a generated message carries canonical folded headers and a
// Message-ID, an mbox escapes a body line beginning "From " and dates its
// separator the way mbox does, and a pdf is paginated with margins and with
// its first line on the page.
const GeneratorVersion = 6

const (
	TxtExtension    = ".txt"
	DocxExtension   = ".docx"
	PngExtension    = ".png"
	PdfExtension    = ".pdf"
	MP4Extension    = ".mp4"
	CsvExtension    = ".csv"
	JSONExtension   = ".json"
	XMLExtension    = ".xml"
	HTMLExtension   = ".html"
	LogExtension    = ".log"
	RegExtension    = ".reg"
	ZipExtension    = ".zip"
	JSONLExtension  = ".jsonl"
	EmlExtension    = ".eml"
	MboxExtension   = ".mbox"
	MdExtension     = ".md"
	SyslogExtension = ".syslog"
	ExeExtension    = ".exe"
	JpgExtension    = ".jpg"
	DBExtension     = ".db"
	SQLiteExtension = ".sqlite"
)
