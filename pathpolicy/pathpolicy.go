// Package pathpolicy decides which paths a manifest or playbook may name. The
// rules are the same on every operating system, so a scenario is either valid
// everywhere or rejected everywhere with the same message: "fsagen validate"
// on Linux must not accept what Windows would silently turn into something
// else.
package pathpolicy

import (
	"errors"
	"fmt"
	"io/fs"
	"path"
	"strings"
	"unicode/utf16"

	"golang.org/x/text/cases"
	"golang.org/x/text/unicode/norm"
)

// maxComponent is the longest name NTFS, ext4 and APFS all accept, in UTF-16
// code units (NTFS) or bytes (ext4); we apply the stricter reading of both.
const maxComponent = 255

// portableBudget is the longest relative path accepted without
// --allow-nonportable. It leaves room for the output root inside Windows'
// 260-character MAX_PATH, which many forensic tools still enforce.
const portableBudget = 200

// Output resolves a path from YAML, optionally beneath an actor base, into a
// clean slash-separated path relative to the output root. dir reports a
// trailing "/", which marks a directory and is captured before cleaning
// removes it.
//
// A ".." that stays inside the root is allowed (an actor based in AppData can
// reach ../../Documents); one that leaves the root is refused.
func Output(base, p string) (clean string, dir bool, err error) {
	if p == "" {
		return "", false, errors.New("path is empty")
	}
	if err := checkRaw(p); err != nil {
		return "", false, err
	}
	if base != "" {
		if err := checkRaw(base); err != nil {
			return "", false, fmt.Errorf("actor base: %w", err)
		}
	}

	dir = strings.HasSuffix(p, "/")
	joined := p
	if base != "" {
		joined = base + "/" + p
	}
	clean = path.Clean(joined)
	if clean == "." {
		return "", false, fmt.Errorf("path %q resolves to the output root itself", p)
	}
	if !fs.ValidPath(clean) {
		return "", false, fmt.Errorf("path %q escapes the output root", joined)
	}
	for comp := range strings.SplitSeq(clean, "/") {
		if err := checkComponent(comp); err != nil {
			return "", false, fmt.Errorf("path %q: %w", p, err)
		}
	}
	return clean, dir, nil
}

// checkRaw applies the character rules that hold before any joining.
func checkRaw(p string) error {
	switch {
	case strings.ContainsRune(p, 0):
		return errors.New("NUL byte in path")
	case strings.Contains(p, `\`):
		return fmt.Errorf("path %q contains '\\'; YAML paths use '/' on every platform", p)
	case strings.Contains(p, ":"):
		return fmt.Errorf("path %q contains ':'; drive letters are not allowed and alternate data streams are written with action: ads and stream:", p)
	case strings.HasPrefix(p, "/"):
		return fmt.Errorf("path %q is absolute; paths are relative to the output root", p)
	}
	return nil
}

// checkComponent rejects names that every platform would store differently
// from how they were written. Windows strips a trailing dot or space, so
// "notes." would silently become "notes": that is never allowed, portable or
// not.
func checkComponent(c string) error {
	if strings.HasSuffix(c, ".") || strings.HasSuffix(c, " ") {
		return fmt.Errorf("component %q ends in a dot or space, which Windows silently strips", c)
	}
	if n := len(utf16.Encode([]rune(c))); n > maxComponent || len(c) > maxComponent {
		return fmt.Errorf("component %q is longer than %d characters", c, maxComponent)
	}
	return nil
}

// Portable reports the hazards that make one tree come out differently on
// different platforms. --allow-nonportable waives them; the hard rules in
// Output cannot be waived.
func Portable(clean string) error {
	if n := len(utf16.Encode([]rune(clean))); n > portableBudget {
		return fmt.Errorf("path %q is %d characters, over the %d-character portable budget", clean, n, portableBudget)
	}
	for c := range strings.SplitSeq(clean, "/") {
		if reservedName(c) {
			return fmt.Errorf("component %q is a reserved device name on Windows", c)
		}
	}
	return nil
}

var reserved = map[string]bool{
	"CON": true, "PRN": true, "AUX": true, "NUL": true, "CONIN$": true, "CONOUT$": true,
}

// reservedName matches CON, PRN, AUX, NUL, COM0-9, LPT0-9 (and the
// superscript-digit forms), with or without an extension.
func reservedName(c string) bool {
	stem := c
	if i := strings.IndexByte(stem, '.'); i >= 0 {
		stem = stem[:i]
	}
	stem = strings.ToUpper(strings.TrimRight(stem, " "))
	if reserved[stem] {
		return true
	}
	if r := []rune(stem); len(r) == 4 && (string(r[:3]) == "COM" || string(r[:3]) == "LPT") {
		d := r[3]
		return (d >= '0' && d <= '9') || d == '¹' || d == '²' || d == '³'
	}
	return false
}

var folder = cases.Fold()

// FoldKey maps a clean path to the key under which case-insensitive,
// normalisation-insensitive file systems (NTFS, APFS) would store it. Two
// different paths with the same key collide on those systems but not on ext4.
func FoldKey(clean string) string {
	return folder.String(norm.NFC.String(clean))
}

// Stream validates an alternate data stream name.
func Stream(name string) error {
	switch {
	case name == "":
		return errors.New("stream name is empty")
	case strings.ContainsAny(name, "\\/:\x00"):
		return fmt.Errorf("stream name %q contains one of \\ / : or NUL", name)
	case len(utf16.Encode([]rune(name))) > maxComponent:
		return fmt.Errorf("stream name %q is longer than %d characters", name, maxComponent)
	}
	return nil
}

// Source classifies a path to an input file (content_file, email bodies,
// attachments). A relative path that stays inside the YAML file's directory
// is returned cleaned; an absolute or escaping path is reported as external,
// which is only honoured with --allow-external-sources.
func Source(p string) (clean string, external bool, err error) {
	switch {
	case p == "":
		return "", false, errors.New("source path is empty")
	case strings.ContainsRune(p, 0):
		return "", false, errors.New("NUL byte in source path")
	case strings.Contains(p, `\`):
		return "", false, fmt.Errorf("source path %q contains '\\'; YAML paths use '/' on every platform", p)
	}
	// A path rooted anywhere but the YAML file's directory is external, and only
	// --allow-external-sources honours one. What counts as rooted is decided
	// here rather than by the host's filepath rules: "C:/x" names a drive
	// wherever the scenario runs, so it is external on Linux too, and this
	// package's promise that a scenario is valid everywhere or nowhere holds.
	if strings.HasPrefix(p, "/") || hasDriveLetter(p) {
		return p, true, nil
	}
	if strings.Contains(p, ":") {
		return "", false, fmt.Errorf("source path %q contains ':'", p)
	}
	clean = path.Clean(p)
	if !fs.ValidPath(clean) || clean == "." {
		return p, true, nil
	}
	return clean, false, nil
}

// hasDriveLetter reports whether p is rooted at a Windows drive, as "C:/x" is.
// A bare "C:" is drive-relative rather than rooted, and is not one.
func hasDriveLetter(p string) bool {
	return len(p) > 2 && p[1] == ':' && p[2] == '/' && isASCIILetter(p[0])
}

func isASCIILetter(c byte) bool {
	lower := c | 0x20
	return 'a' <= lower && lower <= 'z'
}
