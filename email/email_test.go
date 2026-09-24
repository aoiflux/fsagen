package email

import (
	"github.com/aoiflux/fsagen/spec"
	"mime"
	"net/mail"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fixedBoundary stands in for the seeded generator so tests can assert on the
// exact bytes.
func fixedBoundary() func() string {
	n := 0
	return func() string {
		n++
		return "BOUNDARY" + strings.Repeat("X", n)
	}
}

func baseSpec() spec.EmailSpec {
	return spec.EmailSpec{
		From:      "Dana Reyes <d.reyes@northbridge.example>",
		To:        []string{"Priyan N <priyan.n@acmecorp.example>"},
		Subject:   "Technical assessment",
		Date:      "2026-03-02T09:14:00+05:30",
		MessageID: "<c3f1a9@northbridge.example>",
		BodyText:  "Hi Priyan,\n\nDetails below.\n",
	}
}

func TestBuildPlainMessage(t *testing.T) {
	msg, date, err := Build(Options{Spec: baseSpec(), Boundary: fixedBoundary()})
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	if !date.Equal(time.Date(2026, 3, 2, 9, 14, 0, 0, time.FixedZone("", 5*3600+1800))) {
		t.Errorf("date = %v", date)
	}

	parsed, err := mail.ReadMessage(strings.NewReader(string(msg)))
	if err != nil {
		t.Fatalf("message does not parse: %v", err)
	}
	if got := parsed.Header.Get("Subject"); got != "Technical assessment" {
		t.Errorf("Subject = %q", got)
	}
	if got := parsed.Header.Get("Message-ID"); got != "<c3f1a9@northbridge.example>" {
		t.Errorf("Message-ID = %q", got)
	}
	if got := parsed.Header.Get("Content-Type"); !strings.HasPrefix(got, "text/plain") {
		t.Errorf("Content-Type = %q, want text/plain for a single-part message", got)
	}
	if strings.Contains(string(msg), "multipart") {
		t.Error("a body-only message should not be multipart")
	}
}

// Every header line must end CRLF; a bare LF makes strict parsers and some
// mail clients reject the message.
func TestBuildUsesCRLF(t *testing.T) {
	msg, _, err := Build(Options{Spec: baseSpec(), Boundary: fixedBoundary()})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	headers, _, ok := strings.Cut(string(msg), "\r\n\r\n")
	if !ok {
		t.Fatal("no CRLFCRLF header/body separator")
	}
	for _, line := range strings.Split(headers, "\r\n") {
		if strings.Contains(line, "\n") {
			t.Errorf("bare LF inside header line %q", line)
		}
	}
}

func TestBuildHeaderOrderPutsCustomHeadersFirst(t *testing.T) {
	s := baseSpec()
	s.Headers = []spec.Header{
		{Name: "Received", Value: "from mx01.acmecorp.example; Mon, 2 Mar 2026 09:14:07 +0530"},
		{Name: "Received", Value: "from smtp-out.northbridge.example; Mon, 2 Mar 2026 09:14:03 +0530"},
		{Name: "Authentication-Results", Value: "spf=pass; dkim=pass; dmarc=none"},
	}

	msg, _, err := Build(Options{Spec: s, Boundary: fixedBoundary()})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	text := string(msg)

	if strings.Index(text, "Received: from mx01") > strings.Index(text, "\r\nDate:") {
		t.Error("Received headers should precede the structured headers")
	}
	if n := strings.Count(text, "Received: from"); n != 2 {
		t.Errorf("Received count = %d, want 2 (repeated headers must survive)", n)
	}
	if strings.Index(text, "from mx01") > strings.Index(text, "from smtp-out") {
		t.Error("author-supplied header order was not preserved")
	}
}

func TestBuildAlternativeBodies(t *testing.T) {
	s := baseSpec()
	s.BodyHTML = "<html><body><p>Details below.</p></body></html>"

	msg, _, err := Build(Options{Spec: s, Boundary: fixedBoundary()})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	text := string(msg)

	if !strings.Contains(text, `Content-Type: multipart/alternative; boundary="BOUNDARYX"`) {
		t.Error("expected a multipart/alternative container")
	}
	if !strings.Contains(text, "text/plain") || !strings.Contains(text, "text/html") {
		t.Error("expected both body parts")
	}
	if !strings.Contains(text, "\r\n--BOUNDARYX--\r\n") {
		t.Error("missing closing boundary")
	}
}

func TestBuildWithAttachmentNestsAlternativeInsideMixed(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "brief.pdf"), []byte("%PDF-1.4 fake"), 0o644); err != nil {
		t.Fatal(err)
	}

	s := baseSpec()
	s.BodyHTML = "<p>hi</p>"
	s.Attachments = []spec.Attachment{{SourceFile: "brief.pdf", Name: "Brief.pdf"}}

	msg, _, err := Build(Options{Spec: s, ReadSource: dirReader(dir), Boundary: fixedBoundary()})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	text := string(msg)

	if !strings.Contains(text, `multipart/mixed; boundary="BOUNDARYX"`) {
		t.Error("outer container should be multipart/mixed")
	}
	if !strings.Contains(text, `multipart/alternative; boundary="BOUNDARYXX"`) {
		t.Error("bodies should be nested in a multipart/alternative")
	}
	if !strings.Contains(text, "Content-Transfer-Encoding: base64") {
		t.Error("attachment should be base64 encoded")
	}
	if !strings.Contains(text, `filename=Brief.pdf`) && !strings.Contains(text, `filename="Brief.pdf"`) {
		t.Errorf("attachment filename missing from Content-Disposition")
	}
	if !strings.Contains(text, "Content-Type: application/pdf") {
		t.Error("content type should be inferred from the .pdf extension")
	}
}

func TestBuildAttachmentFromRoot(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "report.pdf"), []byte("%PDF-1.4"), 0o644); err != nil {
		t.Fatal(err)
	}

	s := baseSpec()
	s.Attachments = []spec.Attachment{{SourceRoot: "report.pdf"}}

	msg, _, err := Build(Options{Spec: s, ReadOutput: dirReader(root), Boundary: fixedBoundary()})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if !strings.Contains(string(msg), "report.pdf") {
		t.Error("attachment name should default to the source basename")
	}
}

func TestBuildRejectsAttachmentWithNoSource(t *testing.T) {
	s := baseSpec()
	s.Attachments = []spec.Attachment{{Name: "nothing.txt"}}
	if _, _, err := Build(Options{Spec: s, Boundary: fixedBoundary()}); err == nil {
		t.Error("an attachment with no source should be rejected")
	}
}

func TestBuildRejectsBadDate(t *testing.T) {
	s := baseSpec()
	s.Date = "2 March 2026"
	if _, _, err := Build(Options{Spec: s, Boundary: fixedBoundary()}); err == nil {
		t.Error("a non-RFC3339 date should be rejected")
	}
}

func TestBuildFoldsLongHeaders(t *testing.T) {
	s := baseSpec()
	s.Headers = []spec.Header{{Name: "Received", Value: strings.Repeat("word ", 40)}}

	msg, _, err := Build(Options{Spec: s, Boundary: fixedBoundary()})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	headers, _, _ := strings.Cut(string(msg), "\r\n\r\n")
	for _, line := range strings.Split(headers, "\r\n") {
		if len(line) > 78 && strings.HasPrefix(line, "Received:") {
			t.Errorf("unfolded header line of %d chars", len(line))
		}
	}
	if _, err := mail.ReadMessage(strings.NewReader(string(msg))); err != nil {
		t.Errorf("folded message no longer parses: %v", err)
	}
}

// A value the author already folded must be preserved verbatim, so a
// hand-written Received: chain keeps its shape.
func TestBuildPreservesAuthorFolding(t *testing.T) {
	s := baseSpec()
	s.Headers = []spec.Header{{Name: "Received", Value: "from mx01.acmecorp.example\nby wks-0417; Mon, 2 Mar 2026 09:14:07 +0530"}}

	msg, _, err := Build(Options{Spec: s, Boundary: fixedBoundary()})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if !strings.Contains(string(msg), "Received: from mx01.acmecorp.example\r\n\tby wks-0417;") {
		t.Errorf("author folding not preserved:\n%s", msg)
	}
}

func TestToMboxEscapesFromLines(t *testing.T) {
	msg := []byte("Subject: x\r\n\r\nFrom the top this must be escaped\r\nnormal line\r\n")
	out := string(ToMbox(msg, "d.reyes@northbridge.example", time.Date(2026, 3, 1, 11, 2, 0, 0, time.UTC)))

	if !strings.HasPrefix(out, "From d.reyes@northbridge.example Sun Mar  1 11:02:00 2026\n") {
		t.Errorf("bad From_ line: %q", strings.SplitN(out, "\n", 2)[0])
	}
	if !strings.Contains(out, "\n>From the top") {
		t.Error("a body line starting with \"From \" must be escaped")
	}
	if strings.Contains(out, "\r\n") {
		t.Error("mbox output should use LF line endings")
	}
}

func TestEnvelopeSenderPrefersReturnPath(t *testing.T) {
	s := baseSpec()
	s.ReturnPath = "bounce@relay.example"
	if got := EnvelopeSender(s); got != "bounce@relay.example" {
		t.Errorf("EnvelopeSender = %q, want the Return-Path address", got)
	}

	s.ReturnPath = ""
	if got := EnvelopeSender(s); got != "d.reyes@northbridge.example" {
		t.Errorf("EnvelopeSender = %q, want the From address", got)
	}
}

func TestBuildEncodesNonASCIISubject(t *testing.T) {
	s := baseSpec()
	s.Subject = "Réunion technique"

	msg, _, err := Build(Options{Spec: s, Boundary: fixedBoundary()})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if !strings.Contains(string(msg), "=?UTF-8?q?") {
		t.Error("a non-ASCII subject should be RFC 2047 encoded")
	}

	parsed, _ := mail.ReadMessage(strings.NewReader(string(msg)))
	dec, err := new(mime.WordDecoder).DecodeHeader(parsed.Header.Get("Subject"))
	if err != nil {
		t.Fatalf("decode subject: %v", err)
	}
	if dec != "Réunion technique" {
		t.Errorf("round-tripped subject = %q", dec)
	}
}

func dirReader(dir string) func(string) ([]byte, error) {
	return func(p string) ([]byte, error) { return os.ReadFile(filepath.Join(dir, filepath.FromSlash(p))) }
}
