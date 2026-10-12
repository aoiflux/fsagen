package main

import (
	"bytes"
	"database/sql"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aoiflux/fsagen/ledger"
	"github.com/aoiflux/fsagen/volume/container"
	"github.com/aoiflux/libntfs"
)

// The workshop playbooks each teach one finding. These tests build each one
// into an NTFS image exactly as workshops/README.md says, read the evidence
// back through libntfs and SQLite rather than through fsagen, and check that
// the finding is there to be found, and that the decoys beside it are not
// findings. A playbook edit that quietly removed the lesson fails here.

// workshopImage builds a workshop playbook into an NTFS image with the seed
// and image time its README gives, and opens the volume.
func workshopImage(t *testing.T, name string, seed int) (string, *libntfs.Volume) {
	t.Helper()
	img := filepath.Join(t.TempDir(), name+".img")
	if code, _, stderr := runCLI(t, "--seed", fmt.Sprint(seed), "--playbook", filepath.Join("workshops", name+".playbook.yaml"),
		"--image", img, "--image-fs", "ntfs", "--image-size", "64M", "--image-time", "2026-03-12T06:00:00Z"); code != exitOK {
		t.Fatalf("%s: exit %d: %s", name, code, stderr)
	}
	f, err := os.Open(img)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	info, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	start := int64(container.MBRStart) * 512
	vol, err := libntfs.OpenWithOptions(io.NewSectionReader(f, start, info.Size()-start), libntfs.Options{ReadOnly: true, Strict: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { vol.Close() })
	return img, vol
}

func workshopFile(t *testing.T, vol *libntfs.Volume, path string) *libntfs.File {
	t.Helper()
	f, err := vol.OpenPath("/" + path)
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return f
}

func workshopRead(t *testing.T, vol *libntfs.Volume, path, stream string) []byte {
	t.Helper()
	f := workshopFile(t, vol, path)
	if stream != "" {
		s, err := f.OpenStream(stream)
		if err != nil {
			t.Fatalf("%s:%s: %v", path, stream, err)
		}
		f = s
	}
	b, err := f.ReadAll()
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return b
}

func workshopDB(t *testing.T, data []byte) *sql.DB {
	t.Helper()
	p := filepath.Join(t.TempDir(), "x.sqlite")
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func workshopStrings(t *testing.T, db *sql.DB, query string) []string {
	t.Helper()
	rows, err := db.Query(query)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			t.Fatal(err)
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// The timestomped tool was created before it was named: its
// $STANDARD_INFORMATION creation time is months before its $FILE_NAME one,
// and on a whole second where every scheduled time carries a fraction. The
// archive and the copied policy are older than their own birth, but both
// clocks agree on when they were born.
func TestWorkshopTimestomp(t *testing.T) {
	img, vol := workshopImage(t, "timestomp", 2902)
	clocks := func(path string) (*libntfs.StandardInformation, *libntfs.FileName) {
		f := workshopFile(t, vol, path)
		si, err := f.GetMetadata()
		if err != nil {
			t.Fatal(err)
		}
		fn, err := f.GetFileName()
		if err != nil {
			t.Fatal(err)
		}
		return si, fn
	}

	si, fn := clocks("Users/user1/AppData/Roaming/SyncAgent/sync-helper.exe")
	if want := time.Date(2025, 11, 4, 10, 12, 0, 0, time.UTC); !si.CreateTime.Equal(want) {
		t.Errorf("tool $SI created %v, want %v", si.CreateTime, want)
	}
	if !si.CreateTime.Before(fn.CreateTime) || fn.CreateTime.Format("2006-01-02 15:04") != "2026-03-11 09:20" {
		t.Errorf("tool $SI created %v, $FN created %v: want $FN at 09:20 on 2026-03-11, after $SI", si.CreateTime, fn.CreateTime)
	}
	if si.CreateTime.Nanosecond() != 0 || fn.CreateTime.Nanosecond() == 0 {
		t.Errorf("tool $SI fraction %d, $FN fraction %d: want the stomped time whole and the real one jittered", si.CreateTime.Nanosecond(), fn.CreateTime.Nanosecond())
	}
	// The third clock: setting the times changed the record at 09:21.
	if got := si.MFTChangeTime.Format("2006-01-02 15:04"); got != "2026-03-11 09:21" || si.MFTChangeTime.Nanosecond() == 0 {
		t.Errorf("tool $SI changed %v, want 09:21 on 2026-03-11, when the stomp ran", si.MFTChangeTime)
	}

	// The change journal saw the tool made at 09:20 and its times set at
	// 09:21, and the archive's at 09:45, whatever times they claim.
	var journal []string
	if err := vol.EachUSNRecord(func(r *libntfs.USNRecord) error {
		if r.Name == "sync-helper.exe" || r.Name == "collect.zip" {
			journal = append(journal, fmt.Sprintf("%s %s %s", r.Timestamp.Format("15:04"), r.Name, strings.Join(r.ReasonNames(), "|")))
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"09:20 sync-helper.exe FileCreate", "09:21 sync-helper.exe BasicInfoChange|Close", "09:40 collect.zip FileCreate", "09:45 collect.zip BasicInfoChange|Close"} {
		if !slices.Contains(journal, want) {
			t.Errorf("the journal has no %q:\n%s", want, strings.Join(journal, "\n"))
		}
	}

	for _, path := range []string{"Users/user1/AppData/Local/Temp/collect.zip", "Users/user1/Documents/policy-2023.txt"} {
		si, fn := clocks(path)
		if !si.ModifyTime.Before(si.CreateTime) {
			t.Errorf("%s: modified %v, created %v: want older than its birth", path, si.ModifyTime, si.CreateTime)
		}
		if !si.CreateTime.Equal(fn.CreateTime) {
			t.Errorf("%s: $SI created %v, $FN created %v: want the clocks to agree", path, si.CreateTime, fn.CreateTime)
		}
	}

	key, err := os.ReadFile(filepath.Join(img+metaDirSuffix, ledger.AnswerKeyFileName))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(key, []byte(`"timestomp_detected":true`)) {
		t.Error("the answer key does not record the timestomp as detectable")
	}
}

// The ad chain: a click, then two hops nobody clicked, each a server
// redirect; a download whose url chain ends at the CDN its Mark-of-the-Web
// names; and a tracker that set a cookie although the history never went
// there.
func TestWorkshopMalvertising(t *testing.T) {
	_, vol := workshopImage(t, "malvertising", 3303)
	const profile = "Users/user1/AppData/Local/Google/Chrome/User Data/Default/"

	history := workshopDB(t, workshopRead(t, vol, profile+"History", ""))
	got := workshopStrings(t, history, `SELECT u.url || ' <- ' || v.from_visit || ' ' || printf('0x%08x', v.transition) FROM visits v JOIN urls u ON u.id = v.url WHERE v.id >= 4 ORDER BY v.id`)
	want := []string{
		"https://clk.ads.test/c?ad=50513 <- 3 0x10000000",
		"https://rtb.ads.test/r?ad=50513 <- 4 0x80000000",
		"https://www.driver-updates.test/codec <- 5 0xa0000000",
		"https://www.driver-updates.test/codec/download <- 6 0x30000000",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("the chain:\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	chain := workshopStrings(t, history, `SELECT url FROM downloads_url_chains WHERE id = 2 ORDER BY chain_index`)
	if len(chain) != 2 || chain[1] != "https://cdn.driver-updates.test/f/CodecUpdate_x64.exe" {
		t.Errorf("the payload's url chain %v", chain)
	}

	jar := workshopDB(t, workshopRead(t, vol, profile+"Network/Cookies", ""))
	hosts := workshopStrings(t, jar, `SELECT host_key FROM cookies ORDER BY host_key`)
	visited := strings.Join(workshopStrings(t, history, `SELECT url FROM urls`), " ")
	var unvisited []string
	for _, h := range hosts {
		if !strings.Contains(visited, strings.TrimPrefix(h, ".")) {
			unvisited = append(unvisited, h)
		}
	}
	if strings.Join(unvisited, ",") != ".px.tracker.test" {
		t.Errorf("cookies from hosts the history never visited: %v, want only the tracker", unvisited)
	}
	if enc := workshopStrings(t, jar, `SELECT count(*) FROM cookies WHERE value = '' AND hex(substr(encrypted_value, 1, 3)) = '763130'`); enc[0] != fmt.Sprint(len(hosts)) {
		t.Errorf("%s of %d cookies encrypted as Chrome stores them", enc[0], len(hosts))
	}

	zone := string(workshopRead(t, vol, "Users/user1/Downloads/CodecUpdate_x64.exe", "Zone.Identifier"))
	if zone != "[ZoneTransfer]\r\nZoneId=3\r\nReferrerUrl=https://www.driver-updates.test/codec/download\r\nHostUrl=https://cdn.driver-updates.test/f/CodecUpdate_x64.exe\r\n" {
		t.Errorf("the payload's Mark-of-the-Web %q", zone)
	}
	if !bytes.HasPrefix(workshopRead(t, vol, "Users/user1/Downloads/CodecUpdate_x64.exe", ""), []byte("MZ")) {
		t.Error("the payload is not a PE")
	}
}

// The three entries the intruder added sit in the hives beside the ordinary
// ones, and the logs record the service and the processes.
func TestWorkshopRegistryPersistence(t *testing.T) {
	_, vol := workshopImage(t, "registry-persistence", 4404)
	utf16 := func(s string) []byte {
		var b []byte
		for _, r := range s {
			b = append(b, byte(r), byte(r>>8))
		}
		return b
	}
	for path, want := range map[string][]string{
		"Users/user1/NTUSER.DAT":           {"SyncAgent", `C:\Users\user1\AppData\Roaming\SyncAgent\sync-helper.exe`, "NotesApp"},
		"Windows/System32/config/SOFTWARE": {"CacheRebuild", `rundll32.exe C:\Users\Public\libcache.dll,Start`, "AudioTray"},
		"Windows/System32/config/SYSTEM":   {"UpdateBroker", `C:\ProgramData\UpdateBroker\broker.exe`},
	} {
		hive := workshopRead(t, vol, path, "")
		if !bytes.HasPrefix(hive, []byte("regf")) {
			t.Errorf("%s is not a hive", path)
		}
		for _, w := range want {
			if !bytes.Contains(hive, []byte(w)) && !bytes.Contains(hive, utf16(w)) {
				t.Errorf("%s does not hold %q", path, w)
			}
		}
	}
	for _, log := range []string{"System", "Security"} {
		if b := workshopRead(t, vol, "Windows/System32/winevt/Logs/"+log+".evtx", ""); !bytes.HasPrefix(b, []byte("ElfFile\x00")) {
			t.Errorf("%s.evtx is not an event log", log)
		}
	}
}
