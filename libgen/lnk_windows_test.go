//go:build windows

package libgen

import (
	"encoding/binary"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/aoiflux/fsagen/prng"
)

// TestLNKReadByWindowsShell: Windows' own shell link parser, through the
// WScript.Shell and Shell.Application COM objects, reads a generated link
// back with the target, strings, icon and window state the spec gave. It
// skips where PowerShell cannot be run.
func TestLNKReadByWindowsShell(t *testing.T) {
	ps, err := exec.LookPath("powershell.exe")
	if err != nil {
		t.Skip("powershell.exe not found")
	}
	spec := sampleLNKSpec()
	data, err := BuildLNK(spec, prng.Root(1).Stream())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "sample.lnk")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	script := `$s = (New-Object -ComObject WScript.Shell).CreateShortcut($env:LNK_PATH);` +
		`$f = (New-Object -ComObject Shell.Application).Namespace((Split-Path $env:LNK_PATH)).ParseName((Split-Path $env:LNK_PATH -Leaf));` +
		`[pscustomobject]@{Target=$s.TargetPath; Args=$s.Arguments; Dir=$s.WorkingDirectory; Desc=$s.Description; Icon=$s.IconLocation; Style=$s.WindowStyle; ShellPath=$f.GetLink.Path} | ConvertTo-Json -Compress`
	cmd := exec.Command(ps, "-NoProfile", "-NonInteractive", "-Command", script)
	cmd.Env = append(os.Environ(), "LNK_PATH="+path)
	out, err := cmd.Output()
	if err != nil {
		t.Skipf("the shell could not be asked: %v", err)
	}
	var got struct {
		Target, Args, Dir, Desc, Icon, ShellPath string
		Style                                    int
	}
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("%s: %v", out, err)
	}
	if got.Target != spec.Target || got.ShellPath != spec.Target {
		t.Errorf("Windows resolves the target as %q (WScript) and %q (Shell), want %q", got.Target, got.ShellPath, spec.Target)
	}
	if got.Args != spec.Arguments || got.Dir != spec.WorkingDir || got.Desc != spec.Description {
		t.Errorf("strings: %+v", got)
	}
	if got.Icon != spec.IconLocation+",-3" || got.Style != 3 {
		t.Errorf("icon %q style %d", got.Icon, got.Style)
	}
}

// TestLNKHeaderTimeOrderMatchesWindows: the header's three FILETIMEs are in
// the order Windows itself writes them. A shortcut saved through WScript.Shell
// to a file whose creation, write and access times are all different shows
// which offset holds which; fsagen must put its times at the same offsets.
// (At least one Go parser reads the last two the other way round, which is
// why this is settled against Windows rather than against a parser.)
func TestLNKHeaderTimeOrderMatchesWindows(t *testing.T) {
	ps, err := exec.LookPath("powershell.exe")
	if err != nil {
		t.Skip("powershell.exe not found")
	}
	dir := t.TempDir()
	script := `$t = Join-Path $env:LNK_DIR 'target.txt'; Set-Content $t 'x'; $f = Get-Item $t;` +
		`$f.CreationTimeUtc = [datetime]::new(2001,1,1,0,0,0,[DateTimeKind]::Utc);` +
		`$f.LastWriteTimeUtc = [datetime]::new(2002,2,2,0,0,0,[DateTimeKind]::Utc);` +
		`$f.LastAccessTimeUtc = [datetime]::new(2003,3,3,0,0,0,[DateTimeKind]::Utc);` +
		`$s = (New-Object -ComObject WScript.Shell).CreateShortcut((Join-Path $env:LNK_DIR 'w.lnk')); $s.TargetPath = $t; $s.Save()`
	cmd := exec.Command(ps, "-NoProfile", "-NonInteractive", "-Command", script)
	cmd.Env = append(os.Environ(), "LNK_DIR="+dir)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("Windows could not save a shortcut: %v %s", err, out)
	}
	windows, err := os.ReadFile(filepath.Join(dir, "w.lnk"))
	if err != nil {
		t.Fatal(err)
	}
	year := func(b []byte, off int) int { return fromFiletime(binary.LittleEndian.Uint64(b[off:])).Year() }
	// Access times move when the shell opens the target, so only the two
	// that cannot are compared directly; access is whatever is left.
	if year(windows, 28) != 2001 || year(windows, 44) != 2002 {
		t.Fatalf("Windows wrote %d, %d, %d at offsets 28, 36, 44; want creation 2001 at 28 and write 2002 at 44",
			year(windows, 28), year(windows, 36), year(windows, 44))
	}

	ours, err := BuildLNK(LNKSpec{
		Target:   `C:\x.txt`,
		Created:  time.Date(2001, 1, 1, 0, 0, 0, 0, time.UTC),
		Modified: time.Date(2002, 2, 2, 0, 0, 0, 0, time.UTC),
		Accessed: time.Date(2003, 3, 3, 0, 0, 0, 0, time.UTC),
	}, prng.Root(1).Stream())
	if err != nil {
		t.Fatal(err)
	}
	if year(ours, 28) != 2001 || year(ours, 36) != 2003 || year(ours, 44) != 2002 {
		t.Errorf("fsagen wrote %d, %d, %d at offsets 28, 36, 44; want 2001, 2003, 2002 as Windows does",
			year(ours, 28), year(ours, 36), year(ours, 44))
	}
}
