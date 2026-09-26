package constant

// Supported file types and behaviors are documented via these extension constants.
// Bulk generator and manifest/playbook modes can create files of these types:
// - Text and docs: .txt, .md, .docx, .pdf
// - Images/media: .png, .mp4, .jpg (via content),
// - Data/markup: .csv, .json, .jsonl, .xml, .html
// - Logs: .log, .syslog (also JSONL logs)
// - Archives: .zip
// - Email: .eml, .mbox
// - Browser history: .db (Chrome urls/visits), .sqlite (Firefox places)
// - Windows artifacts: .reg, .exe (EXE is a 256-byte DOS MZ stub, not a loadable PE)
// Note: Some formats are simplistic or synthetic, focused on filesystem artifact generation.
const (
	FileNameLen = 10
	ContentLen  = 200000
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
// time fields to the ledger, and writes the answer key.
const GeneratorVersion = 5

const (
	TxtExtension    = ".txt"
	DocxExtension   = ".docx"
	PngExtension    = ".png"
	PdfExtension    = ".pdf"
	Mp4Extension    = ".mp4"
	CsvExtension    = ".csv"
	JsonExtension   = ".json"
	XmlExtension    = ".xml"
	HtmlExtension   = ".html"
	LogExtension    = ".log"
	RegExtension    = ".reg"
	ZipExtension    = ".zip"
	JsonlExtension  = ".jsonl"
	EmlExtension    = ".eml"
	MboxExtension   = ".mbox"
	MdExtension     = ".md"
	SyslogExtension = ".syslog"
	ExeExtension    = ".exe"
	JpgExtension    = ".jpg"
	DbExtension     = ".db"
	SqLiteExtension = ".sqlite"
)
