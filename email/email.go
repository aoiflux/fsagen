// Package email builds RFC 5322 messages with full MIME structure: alternative
// text and HTML bodies, base64 attachments, threading headers and an arbitrary
// ordered header block.
package email

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"github.com/aoiflux/fsagen/spec"
	"mime"
	"mime/quotedprintable"
	"net/mail"
	"path/filepath"
	"strings"
	"time"
)

const crlf = "\r\n"

// Options carries everything Build needs beyond the message itself.
type Options struct {
	Spec spec.EmailSpec
	// ReadSource reads body_text_file, body_html_file and attachment
	// source_file, as written in the manifest or playbook. fsagen passes a
	// reader confined to the YAML file's directory.
	ReadSource func(string) ([]byte, error)
	// ReadOutput reads attachment source_root, a path in the output tree, so a
	// message can attach an artifact an earlier step generated. fsagen passes a
	// reader confined to the output root.
	ReadOutput func(string) ([]byte, error)
	// Boundary must be deterministic for a given seed. multipart's own
	// randomBoundary draws from crypto/rand and would break reproducibility.
	Boundary func() string
}

// Build assembles the message and returns it alongside the parsed Date, which
// callers use as the default file mtime.
func Build(opts Options) ([]byte, time.Time, error) {
	s := opts.Spec

	var date time.Time
	if v := strings.TrimSpace(s.Date); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			return nil, time.Time{}, fmt.Errorf("email date %q: %w", v, err)
		}
		date = t
	}

	text, err := loadBody(s.BodyText, s.BodyTextFile, opts.ReadSource)
	if err != nil {
		return nil, date, fmt.Errorf("body_text_file: %w", err)
	}
	html, err := loadBody(s.BodyHTML, s.BodyHTMLFile, opts.ReadSource)
	if err != nil {
		return nil, date, fmt.Errorf("body_html_file: %w", err)
	}
	attachments, err := loadAttachments(s.Attachments, opts.ReadSource, opts.ReadOutput)
	if err != nil {
		return nil, date, err
	}

	var body bytes.Buffer
	contentHeaders, err := writeBody(&body, text, html, attachments, opts.Boundary)
	if err != nil {
		return nil, date, err
	}

	var msg bytes.Buffer
	writeHeaders(&msg, s, date, contentHeaders)
	msg.WriteString(crlf)
	msg.Write(body.Bytes())

	return msg.Bytes(), date, nil
}

// writeHeaders emits author-supplied headers first, in the exact order given,
// then the structured fields. Putting the free-form block first is what lets a
// scenario place a Received: chain and Authentication-Results where a real MTA
// would have written them, above the message's own headers.
func writeHeaders(w *bytes.Buffer, s spec.EmailSpec, date time.Time, content []spec.Header) {
	for _, h := range s.Headers {
		if strings.TrimSpace(h.Name) == "" {
			continue
		}
		writeHeader(w, h.Name, h.Value)
	}

	writeHeaderIf(w, "Return-Path", s.ReturnPath)
	if !date.IsZero() {
		writeHeader(w, "Date", date.Format(time.RFC1123Z))
	}
	writeHeaderIf(w, "From", formatAddressList([]string{s.From}))
	writeHeaderIf(w, "To", formatAddressList(s.To))
	writeHeaderIf(w, "Cc", formatAddressList(s.Cc))
	writeHeaderIf(w, "Bcc", formatAddressList(s.Bcc))
	writeHeaderIf(w, "Reply-To", formatAddressList([]string{s.ReplyTo}))
	writeHeaderIf(w, "Subject", encodeWord(s.Subject))
	writeHeaderIf(w, "Message-ID", s.MessageID)
	writeHeaderIf(w, "In-Reply-To", s.InReplyTo)
	writeHeaderIf(w, "References", strings.Join(nonEmpty(s.References), " "))

	writeHeader(w, "MIME-Version", "1.0")
	for _, h := range content {
		writeHeader(w, h.Name, h.Value)
	}
}

func writeHeaderIf(w *bytes.Buffer, name, value string) {
	if strings.TrimSpace(value) != "" {
		writeHeader(w, name, value)
	}
}

// writeHeader folds long values at whitespace. A value that already contains
// newlines keeps the author's own folding, so a hand-written Received: chain
// comes out exactly as written.
func writeHeader(w *bytes.Buffer, name, value string) {
	value = strings.ReplaceAll(value, "\r\n", "\n")
	if strings.Contains(value, "\n") {
		lines := strings.Split(value, "\n")
		w.WriteString(name + ": " + strings.TrimSpace(lines[0]) + crlf)
		for _, l := range lines[1:] {
			w.WriteString("\t" + strings.TrimSpace(l) + crlf)
		}
		return
	}

	line := name + ": " + value
	if len(line) <= 78 {
		w.WriteString(line + crlf)
		return
	}

	// Continuation lines use a single space rather than a tab: the folding
	// whitespace survives unfolding, and a tab then shows up inside the value
	// when a tool prints the reassembled header.
	const limit = 78
	cur := name + ":"
	for _, word := range strings.Fields(value) {
		if cur != name+":" && len(cur)+1+len(word) > limit {
			w.WriteString(cur + crlf)
			cur = " " + word
			continue
		}
		cur += " " + word
	}
	if strings.TrimSpace(cur) != name+":" {
		w.WriteString(cur + crlf)
	}
}

// writeBody picks the smallest MIME shape that fits the content and returns the
// Content-* headers the top level needs.
func writeBody(w *bytes.Buffer, text, html string, attachments []loadedAttachment, boundary func() string) ([]spec.Header, error) {
	hasAlt := text != "" && html != ""

	if len(attachments) == 0 {
		if !hasAlt {
			ct, part := singlePart(text, html)
			w.WriteString(part)
			return ct, nil
		}
		b := boundary()
		writeAlternative(w, text, html, b)
		return []spec.Header{{Name: "Content-Type", Value: `multipart/alternative; boundary="` + b + `"`}}, nil
	}

	outer := boundary()
	headers := []spec.Header{{Name: "Content-Type", Value: `multipart/mixed; boundary="` + outer + `"`}}

	if hasAlt {
		inner := boundary()
		w.WriteString("--" + outer + crlf)
		w.WriteString(`Content-Type: multipart/alternative; boundary="` + inner + `"` + crlf + crlf)
		writeAlternative(w, text, html, inner)
	} else {
		ct, part := singlePart(text, html)
		w.WriteString("--" + outer + crlf)
		for _, h := range ct {
			w.WriteString(h.Name + ": " + h.Value + crlf)
		}
		w.WriteString(crlf)
		w.WriteString(part)
	}

	for _, a := range attachments {
		w.WriteString(crlf + "--" + outer + crlf)
		writeAttachment(w, a)
	}
	w.WriteString(crlf + "--" + outer + "--" + crlf)

	return headers, nil
}

func singlePart(text, html string) ([]spec.Header, string) {
	content, mediaType := text, "text/plain"
	if text == "" && html != "" {
		content, mediaType = html, "text/html"
	}
	return []spec.Header{
			{Name: "Content-Type", Value: mediaType + `; charset="UTF-8"`},
			{Name: "Content-Transfer-Encoding", Value: "quoted-printable"},
		},
		encodeQP(content)
}

func writeAlternative(w *bytes.Buffer, text, html, boundary string) {
	w.WriteString("--" + boundary + crlf)
	w.WriteString(`Content-Type: text/plain; charset="UTF-8"` + crlf)
	w.WriteString("Content-Transfer-Encoding: quoted-printable" + crlf + crlf)
	w.WriteString(encodeQP(text))

	w.WriteString(crlf + "--" + boundary + crlf)
	w.WriteString(`Content-Type: text/html; charset="UTF-8"` + crlf)
	w.WriteString("Content-Transfer-Encoding: quoted-printable" + crlf + crlf)
	w.WriteString(encodeQP(html))

	w.WriteString(crlf + "--" + boundary + "--" + crlf)
}

func writeAttachment(w *bytes.Buffer, a loadedAttachment) {
	disposition := a.Disposition
	if disposition == "" {
		disposition = "attachment"
	}

	w.WriteString("Content-Type: " + mime.FormatMediaType(a.ContentType, map[string]string{"name": a.Name}) + crlf)
	w.WriteString("Content-Transfer-Encoding: base64" + crlf)
	if a.ContentID != "" {
		w.WriteString("Content-ID: " + a.ContentID + crlf)
	}
	w.WriteString("Content-Disposition: " + mime.FormatMediaType(disposition, map[string]string{"filename": a.Name}) + crlf + crlf)
	w.WriteString(encodeBase64Lines(a.Data))
}

// encodeQP encodes to quoted-printable with CRLF line endings, as mail bodies
// require. YAML block scalars hand us bare LF.
func encodeQP(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\n", crlf)
	var buf bytes.Buffer
	qp := quotedprintable.NewWriter(&buf)
	_, _ = qp.Write([]byte(s))
	_ = qp.Close()
	return buf.String()
}

func encodeBase64Lines(data []byte) string {
	enc := base64.StdEncoding.EncodeToString(data)
	var buf strings.Builder
	for len(enc) > 76 {
		buf.WriteString(enc[:76])
		buf.WriteString(crlf)
		enc = enc[76:]
	}
	if enc != "" {
		buf.WriteString(enc)
		buf.WriteString(crlf)
	}
	return buf.String()
}

type loadedAttachment struct {
	Name        string
	ContentType string
	Disposition string
	ContentID   string
	Data        []byte
}

func loadAttachments(specs []spec.Attachment, readSource, readOutput func(string) ([]byte, error)) ([]loadedAttachment, error) {
	out := make([]loadedAttachment, 0, len(specs))
	for i, a := range specs {
		var (
			data   []byte
			origin string
			err    error
		)
		switch {
		case a.SourceFile != "":
			origin = a.SourceFile
			data, err = read(readSource, a.SourceFile)
		case a.SourceRoot != "":
			origin = a.SourceRoot
			data, err = read(readOutput, a.SourceRoot)
		case a.Content != "":
			origin = a.Name
			data = []byte(a.Content)
		default:
			return nil, fmt.Errorf("attachment %d: one of source_file, source_root or content is required", i+1)
		}
		if err != nil {
			return nil, fmt.Errorf("attachment %d: %w", i+1, err)
		}

		name := a.Name
		if name == "" {
			name = filepath.Base(filepath.FromSlash(origin))
		}
		ctype := a.ContentType
		if ctype == "" {
			ctype = mime.TypeByExtension(filepath.Ext(name))
		}
		if ctype == "" {
			ctype = "application/octet-stream"
		}
		// FormatMediaType rejects a type that already carries parameters.
		if idx := strings.IndexByte(ctype, ';'); idx >= 0 {
			ctype = strings.TrimSpace(ctype[:idx])
		}

		out = append(out, loadedAttachment{
			Name:        name,
			ContentType: ctype,
			Disposition: a.Disposition,
			ContentID:   a.ContentID,
			Data:        data,
		})
	}
	return out, nil
}

func loadBody(inline, file string, readSource func(string) ([]byte, error)) (string, error) {
	if file == "" {
		return inline, nil
	}
	if inline != "" {
		return "", fmt.Errorf("inline body and body file are mutually exclusive")
	}
	data, err := read(readSource, file)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func read(reader func(string) ([]byte, error), p string) ([]byte, error) {
	if reader == nil {
		return nil, fmt.Errorf("no reader for %q", p)
	}
	return reader(p)
}

// formatAddressList re-emits addresses, RFC 2047-encoding a display name that
// needs it. An address that will not parse is passed through verbatim so a
// scenario can carry a deliberately malformed header.
func formatAddressList(addrs []string) string {
	out := make([]string, 0, len(addrs))
	for _, raw := range nonEmpty(addrs) {
		parsed, err := mail.ParseAddress(raw)
		if err != nil || parsed.Name == "" {
			out = append(out, strings.TrimSpace(raw))
			continue
		}
		out = append(out, (&mail.Address{Name: parsed.Name, Address: parsed.Address}).String())
	}
	return strings.Join(out, ", ")
}

func encodeWord(s string) string {
	if s == "" {
		return ""
	}
	return mime.QEncoding.Encode("UTF-8", s)
}

func nonEmpty(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		if strings.TrimSpace(s) != "" {
			out = append(out, s)
		}
	}
	return out
}

// ToMbox wraps a message in an mboxrd entry. mbox files conventionally use LF
// line endings, so the CRLF message body is converted; ">From " escaping keeps
// a body line that starts with "From " from being read as a new entry.
func ToMbox(msg []byte, sender string, date time.Time) []byte {
	if sender == "" {
		sender = "MAILER-DAEMON"
	}
	if date.IsZero() {
		date = time.Unix(0, 0).UTC()
	}

	var buf bytes.Buffer
	fmt.Fprintf(&buf, "From %s %s\n", sender, date.Format("Mon Jan _2 15:04:05 2006"))
	for _, line := range strings.Split(strings.ReplaceAll(string(msg), "\r\n", "\n"), "\n") {
		if strings.HasPrefix(strings.TrimLeft(line, ">"), "From ") {
			buf.WriteByte('>')
		}
		buf.WriteString(line)
		buf.WriteByte('\n')
	}
	buf.WriteByte('\n')
	return buf.Bytes()
}

// EnvelopeSender extracts the bare address for an mbox "From " line, preferring
// Return-Path the way a real MTA does.
func EnvelopeSender(s spec.EmailSpec) string {
	for _, candidate := range []string{s.ReturnPath, s.From} {
		if strings.TrimSpace(candidate) == "" {
			continue
		}
		if parsed, err := mail.ParseAddress(candidate); err == nil {
			return parsed.Address
		}
		return strings.Trim(strings.TrimSpace(candidate), "<>")
	}
	return ""
}
