// Command gate is fsagen's local release gate (there is no CI by design):
//
//	go run ./tools/gate
//
// It runs go vet, a line-ending-insensitive gofmt check, a go.mod tidiness
// check, the tests (with the race detector where cgo is available; the
// product itself never needs cgo), and CGO_ENABLED=0 builds for windows,
// linux, darwin and freebsd on amd64 and arm64. Setting GOOS/GOARCH for the
// child builds is how cross-compiling works; fsagen itself reads no
// environment variables.
package main

import (
	"bytes"
	"fmt"
	"go/format"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
)

func main() { os.Exit(gate()) }

// gate runs every check and reports how many failed. main turns that into the
// exit status, so the deferred cleanup below always runs.
func gate() int {
	failed := 0
	step := func(name string, err error) {
		if err != nil {
			failed++
			fmt.Printf("FAIL  %s\n%v\n", name, err)
			return
		}
		fmt.Printf("ok    %s\n", name)
	}

	step("go vet ./...", run(nil, "go", "vet", "./..."))
	step("gofmt", gofmtCheck())
	// -diff reports what tidying would change without changing it, so the
	// README's claim that every dependency is used stays true.
	step("go mod tidy", run(nil, "go", "mod", "tidy", "-diff"))

	race := raceAvailable()
	args := []string{"test", "-count=1", "./..."}
	name := "go test ./..."
	if race {
		args = []string{"test", "-race", "-count=1", "./..."}
		name = "go test -race ./..."
	} else {
		fmt.Println("note  the race detector needs cgo and a C compiler; running tests without -race")
	}
	step(name, run(nil, "go", args...))

	tmp, err := os.MkdirTemp("", "fsagen-gate")
	if err != nil {
		step("temp dir", err)
	} else {
		defer os.RemoveAll(tmp)
		for _, target := range buildTargets() {
			step("build "+target.goos+"/"+target.goarch, target.build(tmp))
		}
	}

	if failed > 0 {
		fmt.Printf("\n%d check(s) failed\n", failed)
		return 1
	}
	fmt.Println("\nall checks passed")
	return 0
}

func run(env []string, name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Env = append(os.Environ(), env...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w\n%s", err, out)
	}
	return nil
}

// gofmtCheck formats every Go file with CR bytes removed, so a Windows
// checkout under core.autocrlf does not report every file.
func gofmtCheck() error {
	var bad []string
	err := filepath.WalkDir(".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && slices.Contains(skippedDirs, d.Name()) {
			return filepath.SkipDir
		}
		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(p, ".go") {
			return nil
		}
		src, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		src = bytes.ReplaceAll(src, []byte("\r\n"), []byte("\n"))
		formatted, err := format.Source(src)
		if err != nil {
			bad = append(bad, p+": "+err.Error())
			return nil
		}
		if !bytes.Equal(src, formatted) {
			bad = append(bad, p)
		}
		return nil
	})
	if err != nil {
		return err
	}
	if len(bad) > 0 {
		return fmt.Errorf("not gofmt-formatted:\n  %s", strings.Join(bad, "\n  "))
	}
	return nil
}

// raceAvailable reports whether "go test -race" can build here.
func raceAvailable() bool {
	out, err := exec.Command("go", "env", "CGO_ENABLED").Output()
	if err != nil || strings.TrimSpace(string(out)) != "1" {
		return false
	}
	cc, err := exec.Command("go", "env", "CC").Output()
	if err != nil {
		return false
	}
	_, err = exec.LookPath(strings.Fields(strings.TrimSpace(string(cc)) + " gcc")[0])
	return err == nil
}

// target is one platform the product has to build for.
type target struct{ goos, goarch string }

// buildTargets is every platform fsagen is built for. Setting GOOS and GOARCH
// for the child build is how cross-compiling works; fsagen itself reads no
// environment variables.
func buildTargets() []target {
	var out []target
	for _, goos := range []string{"windows", "linux", "darwin", "freebsd"} {
		for _, goarch := range []string{"amd64", "arm64"} {
			out = append(out, target{goos, goarch})
		}
	}
	return out
}

// build compiles the product for this target into dir, without cgo, so the
// result needs no C toolchain on the machine it runs on.
func (t target) build(dir string) error {
	env := []string{"CGO_ENABLED=0", "GOOS=" + t.goos, "GOARCH=" + t.goarch}
	return run(env, "go", "build", "-o", filepath.Join(dir, t.goos+"-"+t.goarch), ".")
}

// skippedDirs are the directories the gofmt check does not walk into: version
// control, the code index, and fixtures that are compared byte for byte.
var skippedDirs = []string{".git", ".codegraph", "testdata", "node_modules"}
