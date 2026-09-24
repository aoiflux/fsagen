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
// dry-run listing, the run manifest) for some seed and input, and is never
// reused for different bytes. Version 1 matches 7accc8d for valid inputs.
const GeneratorVersion = 1

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
	DbExtension     = ".db"
	SqLiteExtension = ".sqlite"
)
