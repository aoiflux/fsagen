package libgen

import (
	"bytes"
	"net/mail"
	"strings"
	"testing"
	"time"

	"github.com/aoiflux/fsagen/prng"
)

// TestBulkEmailAndPdfComeFromTheSharedBuilders: the eml, mbox and pdf kinds go
// through email.Build, email.ToMbox and RenderPDF rather than assembling their
// own, so a bulk message parses as RFC 5322, a bulk mbox separates and dates
// its messages the way mbox does, and a bulk pdf is a real document. All three
// were hand-written and uncovered, which is how the mbox came to date its
// separator in RFC 5322 form and to skip its ">From " escaping.
func TestBulkEmailAndPdfComeFromTheSharedBuilders(t *testing.T) {
	start := time.Date(2026, 3, 4, 8, 0, 0, 0, time.UTC)
	stream := func() *prng.Stream { return prng.Root(7).Derive("content").Stream() }

	eml, err := genEml(stream(), start)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(bytes.ReplaceAll(eml, []byte("\r\n"), nil), []byte("\n")) {
		t.Errorf("eml has a bare LF, so it is not CRLF throughout:\n%q", eml)
	}
	msg, err := mail.ReadMessage(bytes.NewReader(eml))
	if err != nil {
		t.Fatalf("eml does not parse: %v\n%q", err, eml)
	}
	for _, h := range []string{"Date", "From", "To", "Subject", "Message-ID", "MIME-Version"} {
		if msg.Header.Get(h) == "" {
			t.Errorf("eml has no %s header", h)
		}
	}
	if _, err := mail.ParseDate(msg.Header.Get("Date")); err != nil {
		t.Errorf("Date header is not RFC 5322: %v", err)
	}

	mbox, err := genMbox(stream(), start)
	if err != nil {
		t.Fatal(err)
	}
	// An mbox separates messages with a "From " line at the start of a line and
	// dates it in ctime form, which is not the form the Date header takes.
	var seps []string
	for line := range strings.SplitSeq(string(mbox), "\n") {
		if strings.HasPrefix(line, "From ") {
			seps = append(seps, line)
		}
	}
	if len(seps) != bulkMboxMessages {
		t.Fatalf("got %d mbox separators, want %d:\n%q", len(seps), bulkMboxMessages, mbox)
	}
	for _, sep := range seps {
		stamp := strings.TrimPrefix(sep, "From alice@example.com ")
		if _, err := time.Parse("Mon Jan _2 15:04:05 2006", stamp); err != nil {
			t.Errorf("mbox separator is not ctime-dated: %q", sep)
		}
	}

	pdf, err := genPdf(stream(), start)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(pdf, []byte("%PDF-")) || !bytes.Contains(pdf, []byte("%%EOF")) {
		t.Errorf("pdf is not a document: %d bytes starting %q", len(pdf), pdf[:min(8, len(pdf))])
	}
}
