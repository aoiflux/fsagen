package main

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"debug/pe"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"mime/quotedprintable"
	"net/mail"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aoiflux/fsagen/compile"
	"github.com/aoiflux/fsagen/ledger"
	"github.com/aoiflux/fsagen/runinfo"
	"github.com/aoiflux/fsagen/sandbox"
)

// acceptancePlaybook is a compressed stand-in for the evidence playbook of
// the Mutant QUILLDROP workshop, whose audit brief (plan.json) is where the
// consumer requirements come from.
var acceptancePlaybook = filepath.Join("testdata", "acceptance", "quilldrop-lite.playbook.yaml")

const (
	acceptanceSeed    = "4242"
	acceptanceStage   = "Users/priyan.nair/AppData/Local/Temp/quill"
	acceptanceDropper = "Users/priyan.nair/Downloads/Invoice_MRD-88412.pdf.exe"
)

// TestConsumerAcceptance checks CR-1 to CR-11 from plan.json against one
// scenario, so fsagen can tell whether it still gives its consumer what that
// consumer asked for without depending on the consumer's repository. CR-12
// (go install github.com/aoiflux/fsagen@latest works) is the owner's check
// after pushing and has no test here.
func TestConsumerAcceptance(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "corpus")
	body := filepath.Join(dir, "quilldrop.body")
	args := []string{"--seed", acceptanceSeed, "--playbook", acceptancePlaybook, "--timeline", body}
	if runtime.GOOS != "windows" {
		args = append(args, "--on-unsupported=skip")
	}
	if code, _, errOut := runCLI(t, append(args, out)...); code != exitOK {
		acceptanceSkipIfAVRefused(t, errOut)
		t.Fatalf("exit %d: %s", code, errOut)
	}
	fsys, err := sandbox.Open(out)
	if err != nil {
		t.Fatal(err)
	}
	defer fsys.Close()
	facts := acceptanceFacts(t, out)

	// Read the dropper's times before anything in this test reads the file:
	// with last-access updates on, the test's own reads would move them and
	// CR-4 would be checking itself.
	dropperTimes, err := fsys.Times(acceptanceDropper)
	if err != nil {
		t.Fatal(err)
	}

	// CR-1: a Sleuth Kit bodyfile, because the name ends in .body.
	t.Run("CR-1_bodyfile", func(t *testing.T) {
		records := acceptanceBodyfile(t, body)
		if len(records) < 10 {
			t.Fatalf("the bodyfile holds %d records", len(records))
		}
		var seen bool
		for _, f := range records {
			if f[1] == "/Users/priyan.nair/Downloads/Invoice_MRD-88412.pdf.exe" {
				seen = true
			}
		}
		if !seen {
			t.Error("the dropper has no record in the bodyfile")
		}
	})

	// CR-2: the phishing message exactly as the playbook writes it.
	t.Run("CR-2_phishing_email", func(t *testing.T) {
		raw := acceptanceRead(t, out, "Users/priyan.nair/AppData/Local/Microsoft/Outlook/Inbox/0001.eml")
		if bytes.Contains(bytes.ReplaceAll(raw, []byte("\r\n"), nil), []byte("\n")) {
			t.Error("the message has a bare LF in it")
		}
		msg, err := mail.ReadMessage(bytes.NewReader(raw))
		if err != nil {
			t.Fatalf("net/mail will not read it: %v", err)
		}
		for _, h := range []struct{ name, want string }{
			{"Subject", "Invoice MRD-88412 is overdue"},
			{"Message-Id", "<mrd-88412@mrd-invoices.example>"},
			{"Reply-To", "no-reply@mrd-invoices.example"},
			{"Date", "Wed, 11 Mar 2026 08:00:00 +0000"},
		} {
			if got := msg.Header.Get(h.name); got != h.want {
				t.Errorf("%s: %q, want %q", h.name, got, h.want)
			}
		}
		// The author's own headers lead, in the order they were written, so
		// a Received: chain reads the way an MTA would have left it.
		if i, j := bytes.Index(raw, []byte("Received:")), bytes.Index(raw, []byte("Authentication-Results:")); i != 0 || j < i {
			t.Errorf("author headers are at %d and %d, want them first and in order", i, j)
		}
		got, err := io.ReadAll(quotedprintable.NewReader(msg.Body))
		if err != nil {
			t.Fatal(err)
		}
		want := "Dear Priyan,\r\n\r\nInvoice MRD-88412 is 21 days overdue. The statement is here:\r\n" +
			"https://cdn.mrd-invoices.example/Invoice_MRD-88412.pdf.exe\r\n\r\nMRD Billing\r\n"
		if string(got) != want {
			t.Errorf("body:\n%q\nwant:\n%q", got, want)
		}
	})

	// CR-3: both executables are PEs a parser reads, with the build time the
	// playbook asked for. fsagen's content_len is the size of the filler a
	// file carries, which for a PE is its overlay.
	t.Run("CR-3_valid_PEs", func(t *testing.T) {
		dropper := acceptanceRead(t, out, acceptanceDropper)
		df := acceptancePE(t, dropper)
		defer df.Close()
		// "0" is the scrubbed build time the workshop teaches; it has to
		// survive rather than be replaced by the action's own time.
		if df.FileHeader.TimeDateStamp != 0 {
			t.Errorf("the dropper's TimeDateStamp is %d, want the scrubbed 0", df.FileHeader.TimeDateStamp)
		}
		if got := acceptanceOverlay(df, len(dropper)); got != 4096 {
			t.Errorf("the dropper's overlay is %d bytes, want the content_len of 4096", got)
		}
		for _, s := range []struct {
			name string
			size uint32
		}{{".text", 8192}, {".rdata", 2048}, {".data", 1024}} {
			sec := df.Section(s.name)
			if sec == nil {
				t.Errorf("no %s section", s.name)
				continue
			}
			if sec.Size != s.size {
				t.Errorf("%s is %d bytes, want %d", s.name, sec.Size, s.size)
			}
		}
		syms, err := df.ImportedSymbols()
		if err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{"RegSetValueExW", "URLDownloadToFileW"} {
			if !strings.Contains(strings.Join(syms, " "), want) {
				t.Errorf("the dropper does not import %s: %v", want, syms)
			}
		}

		implant := acceptanceRead(t, out, "Users/priyan.nair/AppData/Roaming/Quill/quilld.exe")
		imf := acceptancePE(t, implant)
		defer imf.Close()
		stamp := time.Date(2026, 3, 11, 8, 40, 0, 0, time.UTC)
		if got := int64(imf.FileHeader.TimeDateStamp); got != stamp.Unix() {
			t.Errorf("the implant's TimeDateStamp is %d, want %d", got, stamp.Unix())
		}
		if got := acceptanceOverlay(imf, len(implant)); got != 1024 {
			t.Errorf("the implant's overlay is %d bytes, want the content_len of 1024", got)
		}
		// The version resource is what a metadata tool reports, so it has to
		// be in the image, not just in the YAML.
		if !bytes.Contains(implant, acceptanceUTF16("Quill Service Host")) {
			t.Error("the implant carries no version resource")
		}
	})

	// CR-4: the mark of the web carries the campaign's URLs and leaves the
	// dropper's times alone, although it runs a minute later.
	t.Run("CR-4_motw", func(t *testing.T) {
		if fsys.SupportsStreams() {
			zone, err := fsys.ReadStream(acceptanceDropper, "Zone.Identifier")
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				"ZoneId=3",
				"HostUrl=https://cdn.mrd-invoices.example/Invoice_MRD-88412.pdf.exe",
				"ReferrerUrl=https://mail.northwindlogistics.example/",
			} {
				if !strings.Contains(string(zone), want) {
					t.Errorf("Zone.Identifier = %q, want it to contain %q", zone, want)
				}
			}
		}
		if !fsys.TimeCaps().Birth {
			return
		}
		created := time.Date(2026, 3, 11, 8, 35, 0, 0, time.UTC)
		for _, f := range []struct {
			name string
			got  time.Time
		}{
			{"access", dropperTimes.Atime}, {"modification", dropperTimes.Mtime},
			{"change", dropperTimes.Ctime}, {"creation", dropperTimes.Btime},
		} {
			if !f.got.UTC().Equal(created) {
				t.Errorf("%s time is %s, want the create at %s: the mark of the web moved it",
					f.name, f.got.UTC().Format(time.RFC3339Nano), created.Format(time.RFC3339))
			}
		}
	})

	// CR-5: the implant's quill stream is in the timeline, with its size.
	t.Run("CR-5_quill_stream_in_timeline", func(t *testing.T) {
		if !fsys.SupportsStreams() {
			t.Skip("no named streams on this volume")
		}
		const want = "/Users/priyan.nair/AppData/Roaming/Quill/quilld.exe:quill"
		for _, f := range acceptanceBodyfile(t, body) {
			if f[1] == want {
				if f[6] != "29" {
					t.Errorf("the quill record is %s bytes, want 29", f[6])
				}
				return
			}
		}
		t.Errorf("no %s record in the bodyfile", want)
	})

	// CR-6: after the stomp on 12 March, exactly four files have a
	// modification time earlier than their creation time. A platform that
	// cannot set a creation time cannot show that at all, and fsagen does
	// not pretend otherwise: the answer key then claims no stomp, and the
	// ledger records crtime as uncontrolled for the four files concerned.
	t.Run("CR-6_four_stomped_files", func(t *testing.T) {
		var stomped []string
		for _, f := range facts {
			if f.Event == ledger.MtimeBeforeCrtime {
				stomped = append(stomped, f.Path)
			}
		}
		if !fsys.TimeCaps().Birth {
			if len(stomped) != 0 {
				t.Fatalf("this platform cannot set a creation time, so no stomp is observable, "+
					"yet the answer key names %d: %v", len(stomped), stomped)
			}
			acceptanceCrtimeUncontrolled(t, out)
			return
		}
		if len(stomped) != 4 {
			t.Errorf("the answer key names %d stomped files, want 4: %v", len(stomped), stomped)
		}
		onDisk := 0
		err := fsys.WalkDir(func(name string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			times, err := fsys.Times(name)
			if err != nil {
				return err
			}
			if times.Mtime.Before(times.Btime) {
				onDisk++
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		if onDisk != 4 {
			t.Errorf("%d files on disk have mtime < crtime, want exactly the 4 stomped", onDisk)
		}
	})

	// CR-7: the archive is a real zip of the staged files, each member's
	// CRC-32, size and bytes matching what the scenario staged. The sources
	// are gone by the end of the run, so the answer key is the ground truth
	// they are compared against.
	t.Run("CR-7_zip_matches_sources", func(t *testing.T) {
		data := acceptanceRead(t, out, "Users/priyan.nair/AppData/Local/Temp/bkp_20260311.zip")
		zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
		if err != nil {
			t.Fatalf("the archive is not a zip: %v", err)
		}
		if zr.Comment != "quilldrop-lite staging" {
			t.Errorf("comment %q", zr.Comment)
		}
		if len(zr.File) != 24 {
			t.Fatalf("the archive holds %d members, want the 24 staged files", len(zr.File))
		}
		staged := map[string]ledger.Fact{}
		for _, f := range facts {
			if f.Event == ledger.Created && strings.HasPrefix(f.Path, acceptanceStage+"/") {
				staged[strings.TrimPrefix(f.Path, acceptanceStage+"/")] = f
			}
		}
		for i, f := range zr.File {
			if want := fmt.Sprintf("stage-%d.dat", i); f.Name != want {
				t.Errorf("member %d is %q, want %q in creation order", i, f.Name, want)
			}
			src, ok := staged[f.Name]
			if !ok {
				t.Errorf("%s was never staged", f.Name)
				continue
			}
			// Reading the member to the end is what checks its CRC-32:
			// archive/zip returns ErrChecksum when the stored one is wrong.
			rc, err := f.Open()
			if err != nil {
				t.Errorf("%s: %v", f.Name, err)
				continue
			}
			got, err := io.ReadAll(rc)
			rc.Close()
			if err != nil {
				t.Errorf("%s: %v", f.Name, err)
				continue
			}
			if src.Size == nil || int64(len(got)) != *src.Size {
				t.Errorf("%s is %d bytes, the staged file was %v", f.Name, len(got), src.Size)
			}
			if sum := sha256.Sum256(got); hex.EncodeToString(sum[:]) != src.SHA256 {
				t.Errorf("%s differs from the file that was staged", f.Name)
			}
			// The member keeps the time the scenario gave the file, not the
			// time the archive happened to be written.
			if want := time.Date(2026, 3, 11, 10, 0, 0, 0, time.UTC); !f.Modified.UTC().Equal(want) {
				t.Errorf("%s is dated %s, want the staging time %s", f.Name, f.Modified.UTC(), want)
			}
		}
	})

	// CR-8: the staging files are really gone, and their removal is in the
	// ground truth rather than only implied by their absence.
	t.Run("CR-8_staging_deleted_and_recorded", func(t *testing.T) {
		deleted := map[string]bool{}
		for _, f := range facts {
			if f.Event == ledger.Deleted {
				deleted[f.Path] = true
			}
		}
		if len(deleted) != 24 {
			t.Errorf("the answer key records %d deletions, want 24", len(deleted))
		}
		for i := 0; i < 24; i++ {
			p := fmt.Sprintf("%s/stage-%d.dat", acceptanceStage, i)
			if !deleted[p] {
				t.Errorf("%s is not recorded as deleted", p)
			}
			if _, err := os.Stat(filepath.Join(out, filepath.FromSlash(p))); !os.IsNotExist(err) {
				t.Errorf("%s is still on disk", p)
			}
		}
	})

	// CR-9: the beacon log has a hole in its sequence, not a short tail.
	t.Run("CR-9_gap_in_beacon_log", func(t *testing.T) {
		log := string(acceptanceRead(t, out, "Users/priyan.nair/AppData/Roaming/Quill/beacon.log"))
		var seq []int
		for _, line := range strings.Split(strings.TrimRight(log, "\n"), "\n") {
			n, err := strconv.Atoi(strings.TrimPrefix(strings.Fields(line)[0], "seq="))
			if err != nil {
				t.Fatalf("line %q: %v", line, err)
			}
			seq = append(seq, n)
		}
		want := []int{0, 1, 2, 7, 8, 9, 10, 11}
		if fmt.Sprint(seq) != fmt.Sprint(want) {
			t.Errorf("sequence numbers %v, want %v: four check-ins cut out of the middle", seq, want)
		}
	})

	// CR-10: something every student can compare byte for byte.
	t.Run("CR-10_byte_comparable", func(t *testing.T) {
		first := filepath.Join(dir, "first.body")
		second := filepath.Join(dir, "second.body")
		run := func(name, timeline string) string {
			t.Helper()
			root := filepath.Join(dir, name)
			args := []string{"--seed", acceptanceSeed, "--playbook", acceptancePlaybook,
				"--timeline", timeline, "--timeline-source", "modelled"}
			if runtime.GOOS != "windows" {
				args = append(args, "--on-unsupported=skip")
			}
			if code, _, errOut := runCLI(t, append(args, root)...); code != exitOK {
				t.Fatalf("exit %d: %s", code, errOut)
			}
			return root
		}
		a, b := run("again", first), run("third", second)
		if x, y := sidecar(t, a, runinfo.SumsFileName), sidecar(t, b, runinfo.SumsFileName); !bytes.Equal(x, y) {
			t.Error("two runs of the same scenario have different SHA256SUMS")
		}
		x, err := os.ReadFile(first)
		if err != nil {
			t.Fatal(err)
		}
		y, err := os.ReadFile(second)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(x, y) {
			t.Error("two modelled bodyfiles of the same scenario differ")
		}
		if !bytes.Contains(x, []byte("stage-0.dat")) {
			t.Error("the modelled bodyfile leaves out the deleted staging files")
		}
	})

	// CR-11: on a machine with no named streams the run either refuses
	// before writing anything, or lists what it left out.
	t.Run("CR-11_unsupported_reported", func(t *testing.T) {
		testCaps = &compile.Caps{}
		defer func() { testCaps = nil }()

		refused := filepath.Join(dir, "refused")
		code, _, errOut := runCLI(t, "--seed", acceptanceSeed, "--playbook", acceptancePlaybook, refused)
		if code != exitRuntime {
			t.Fatalf("exit %d, want a refusal: %s", code, errOut)
		}
		for _, want := range []string{"[ads]", "[motw]", "--on-unsupported=skip"} {
			if !strings.Contains(errOut, want) {
				t.Errorf("the refusal does not mention %s:\n%s", want, errOut)
			}
		}
		if _, err := os.Stat(refused); !os.IsNotExist(err) {
			t.Error("the refused run created its output directory")
		}

		skipped := filepath.Join(dir, "skipped")
		if code, _, errOut := runCLI(t, "--seed", acceptanceSeed, "--playbook", acceptancePlaybook,
			"--on-unsupported=skip", skipped); code != exitOK {
			t.Fatalf("exit %d: %s", code, errOut)
		}
		rm := readManifest(t, skipped+".fsagen")
		if rm.Status != runinfo.StatusComplete || len(rm.Skipped) != 2 {
			t.Fatalf("run manifest: status %q, %d skipped", rm.Status, len(rm.Skipped))
		}
		// In the order the scenario schedules them: the mark of the web at
		// 36 minutes, then the stream at 41.
		if rm.Skipped[0].Action != "motw" || rm.Skipped[1].Action != "ads" {
			t.Errorf("skipped %+v, want the motw and ads operations", rm.Skipped)
		}
	})
}

// acceptanceSkipIfAVRefused stops the test when the machine's antivirus
// deleted a file fsagen had just written, rather than reporting it as a
// defect. Defender's machine-learning detection does this to generated PE
// images unpredictably: it has allowed and then refused the same bytes
// minutes apart. The run failing loudly is the right behaviour and
// TestFailedRunMarksSidecarFailed covers it; what is missing here is a
// corpus to make assertions about. The match is on the English message, so
// on a machine in another language the test fails instead of skipping,
// which is the safe direction.
func acceptanceSkipIfAVRefused(t *testing.T, errOut string) {
	t.Helper()
	if strings.Contains(errOut, "virus or potentially unwanted software") {
		t.Skipf("this machine's antivirus removed a generated executable, so there is no corpus to check "+
			"(see Limits in README.md; exclude the output folder from scanning):\n%s", errOut)
	}
}

// acceptanceFacts reads a run's answer key.
func acceptanceFacts(t *testing.T, out string) []ledger.Fact {
	t.Helper()
	var facts []ledger.Fact
	for _, line := range strings.Split(string(sidecar(t, out, ledger.AnswerKeyFileName)), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var f ledger.Fact
		if err := json.Unmarshal([]byte(line), &f); err != nil {
			t.Fatalf("answer key line %q: %v", line, err)
		}
		facts = append(facts, f)
	}
	return facts
}

// acceptanceCrtimeUncontrolled checks that a platform which cannot set a
// creation time says so, for each of the four files the scenario stomps.
// Without that record a reader could not tell a scenario that stomps nothing
// from a platform that could not carry the stomp out.
func acceptanceCrtimeUncontrolled(t *testing.T, out string) {
	t.Helper()
	want := []string{
		"Users/priyan.nair/Documents/quarterly-0.docx",
		"Users/priyan.nair/Documents/quarterly-2.docx",
		"Users/priyan.nair/Documents/quarterly-3.docx",
		"Users/priyan.nair/Documents/quarterly-5.docx",
	}
	seen := map[string]bool{}
	for _, line := range strings.Split(string(sidecar(t, out, ledger.FileName)), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var e ledger.Entry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("ledger line %q: %v", line, err)
		}
		if !slices.Contains(want, e.Path) {
			continue
		}
		seen[e.Path] = true
		if !slices.Contains(e.Uncontrolled, "crtime") {
			t.Errorf("%s: the ledger records uncontrolled=%v, want crtime among them",
				e.Path, e.Uncontrolled)
		}
	}
	for _, p := range want {
		if !seen[p] {
			t.Errorf("the ledger has no entry for %s", p)
		}
	}
}

// acceptanceBodyfile splits a bodyfile into its eleven pipe-separated fields
// per record, failing if any record has another shape.
func acceptanceBodyfile(t *testing.T, path string) [][]string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out [][]string
	for i, line := range strings.Split(strings.TrimRight(string(data), "\n"), "\n") {
		fields := strings.Split(line, "|")
		if len(fields) != 11 {
			t.Fatalf("record %d has %d fields, a bodyfile has 11: %q", i+1, len(fields), line)
		}
		if !strings.HasPrefix(fields[1], "/") {
			t.Errorf("record %d names %q, a bodyfile path starts at the root", i+1, fields[1])
		}
		out = append(out, fields)
	}
	return out
}

func acceptanceRead(t *testing.T, out, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(out, filepath.FromSlash(path)))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func acceptancePE(t *testing.T, data []byte) *pe.File {
	t.Helper()
	f, err := pe.NewFile(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("debug/pe will not read it: %v", err)
	}
	return f
}

// acceptanceOverlay is how many bytes follow the last section's data.
func acceptanceOverlay(f *pe.File, size int) int {
	var end uint32
	for _, s := range f.Sections {
		if e := s.Offset + s.Size; e > end {
			end = e
		}
	}
	return size - int(end)
}

// acceptanceUTF16 is how a version resource stores a string.
func acceptanceUTF16(s string) []byte {
	out := make([]byte, 0, 2*len(s))
	for _, r := range s {
		out = append(out, byte(r), byte(r>>8))
	}
	return out
}
