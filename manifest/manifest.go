// Package manifest executes compiled operations. Every write goes through a
// sandbox.FS confined to the output root; compile has already proved each
// operation's preconditions against a model of the tree, so a failure here is
// an I/O problem, never an input mistake.
package manifest

import (
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
	"time"

	"github.com/aoiflux/fsagen/compile"
	"github.com/aoiflux/fsagen/email"
	"github.com/aoiflux/fsagen/libgen"
	"github.com/aoiflux/fsagen/sandbox"
	"github.com/aoiflux/fsagen/spec"
	"github.com/aoiflux/fsagen/util"
)

// ExecContext carries the state every operation needs beyond its own fields.
type ExecContext struct {
	// FS is the confined output root.
	FS *sandbox.FS
	// Sources reads email bodies and attachments from the YAML's directory.
	Sources *sandbox.Sources
}

// ExecuteManifest compiles a manifest and applies it under root with default
// options. It is the library entry point; the CLI adds root checks, the
// capability pre-flight and the run manifest around the same steps.
func ExecuteManifest(root, manifestPath string, opts compile.Options) error {
	return executeFile(compile.ModeManifest, root, manifestPath, opts)
}

// ExecutePlaybook compiles a playbook and applies it under root with default
// options.
func ExecutePlaybook(root, playbookPath string, opts compile.Options) error {
	return executeFile(compile.ModePlaybook, root, playbookPath, opts)
}

func executeFile(mode compile.Mode, root, file string, opts compile.Options) error {
	prog, err := compile.Load(mode, file, opts)
	if err != nil {
		return err
	}
	defer prog.Close()

	fsys, err := sandbox.Open(root)
	if err != nil {
		return err
	}
	defer fsys.Close()

	if err := compile.Preflight(prog, compile.Caps{NamedStreams: fsys.SupportsStreams()}, false); err != nil {
		return err
	}
	return Execute(ExecContext{FS: fsys, Sources: prog.Sources}, prog.Ops)
}

// Execute applies the operations in order, leaving out those marked NoOp
// and those marked Skip (unsupported here). Every operation draws from its
// own random stream, so leaving one out changes no other file's bytes.
func Execute(ctx ExecContext, ops []compile.Op) error {
	for _, op := range ops {
		if op.NoOp != "" || op.Skip != "" {
			continue
		}
		if err := executeOp(ctx, op); err != nil {
			return fmt.Errorf("%s: %s %s: %w", op.Src, op.Action, op.Path, err)
		}
	}
	return nil
}

func executeOp(ctx ExecContext, c compile.Op) error {
	op := c.Operation
	fs := ctx.FS
	target := op.Path

	switch op.Action {
	case "create":
		if c.Dir {
			// The mode is given to MkdirAll; a directory's times are stamped
			// without a separate chmod.
			if err := fs.MkdirAll(target, dirModeFor(op)); err != nil {
				return err
			}
			return applyTimes(fs, op, target)
		}
		content, err := renderContent(op, contentOf(c))
		if err != nil {
			return err
		}
		return writeArtifact(fs, op, target, content)

	case "update":
		content, err := renderContent(op, contentOf(c))
		if err != nil {
			return err
		}
		return writeArtifact(fs, op, target, content)

	case "append":
		if err := fs.MkdirParent(target); err != nil {
			return err
		}
		f, err := fs.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_APPEND, fileModeFor(op))
		if err != nil {
			return err
		}
		if _, err := f.Write(contentOf(c)); err != nil {
			_ = f.Close()
			return err
		}
		if err := f.Close(); err != nil {
			return err
		}
		return applyModeAndTimes(fs, op, target)

	case "delete":
		if err := fs.Remove(target); err != nil {
			return err
		}
		// A delete's times, when given, describe the parent directory after
		// the removal.
		if at, mt, ok := parseTimes(op.Atime, op.Mtime); ok {
			return fs.Chtimes(path.Dir(target), at, mt)
		}
		return nil

	case "mace":
		if err := applyMode(fs, op, target); err != nil {
			return err
		}
		return applyTimes(fs, op, target)

	case "rename":
		if err := fs.MkdirParent(op.NewPath); err != nil {
			return err
		}
		return fs.Rename(target, op.NewPath)

	case "copy":
		if err := copyFile(fs, target, op.NewPath, fileModeFor(op)); err != nil {
			return err
		}
		return applyModeAndTimes(fs, op, op.NewPath)

	case "truncate":
		f, err := fs.OpenFile(target, os.O_WRONLY|os.O_TRUNC, fileModeFor(op))
		if err != nil {
			return err
		}
		if err := f.Close(); err != nil {
			return err
		}
		return applyModeAndTimes(fs, op, target)

	case "rotate":
		if err := fs.MkdirParent(op.NewPath); err != nil {
			return err
		}
		if err := fs.Rename(target, op.NewPath); err != nil {
			return err
		}
		f, err := fs.OpenFile(target, os.O_CREATE|os.O_WRONLY, fileModeFor(op))
		if err != nil {
			return err
		}
		if err := f.Close(); err != nil {
			return err
		}
		if at, mt, ok := parseTimes(op.Atime, op.Mtime); ok {
			if err := fs.Chtimes(op.NewPath, at, mt); err != nil {
				return err
			}
			if err := fs.Chtimes(target, at, mt); err != nil {
				return err
			}
		}
		return nil

	case "email":
		return writeEmail(ctx, c, target)

	case "ansible-vault":
		salt := op.Vault.Salt
		if strings.TrimSpace(salt) == "" {
			salt = hex.EncodeToString(c.Rand.Derive("vault.salt").Stream().Bytes(32))
		}
		encrypted, err := util.AnsibleVaultEncrypt([]byte(op.Content), op.Vault.Password, op.Vault.VaultID, salt)
		if err != nil {
			return err
		}
		return writeArtifact(fs, op, target, encrypted)

	case "ads":
		if err := fs.WriteStream(target, op.Stream, contentOf(c)); err != nil {
			return err
		}
		// Writing a stream updates the base file's mtime, so restore the times
		// the operation asked for.
		return applyTimes(fs, op, target)

	case "motw":
		content := "[ZoneTransfer]\r\n" + fmt.Sprintf("ZoneId=%d\r\n", op.ZoneID)
		if op.ReferrerURL != "" {
			content += fmt.Sprintf("ReferrerUrl=%s\r\n", op.ReferrerURL)
		}
		if op.HostURL != "" {
			content += fmt.Sprintf("HostUrl=%s\r\n", op.HostURL)
		}
		if err := fs.WriteStream(target, "Zone.Identifier", []byte(content)); err != nil {
			return err
		}
		return applyTimes(fs, op, target)
	}
	return fmt.Errorf("unknown action %q", op.Action)
}

// renderContent applies the typed generator selected by format. Without one,
// content is written through unchanged.
func renderContent(op spec.Operation, raw []byte) ([]byte, error) {
	switch op.Format {
	case "", "raw", "text":
		return raw, nil
	case "pdf":
		meta, err := pdfMeta(op)
		if err != nil {
			return nil, err
		}
		return libgen.RenderPDF(string(raw), meta)
	}
	return nil, fmt.Errorf("unknown format %q (want raw or pdf)", op.Format)
}

func pdfMeta(op spec.Operation) (libgen.PDFMeta, error) {
	if op.Pdf == nil {
		return libgen.PDFMeta{}, nil
	}
	created, err := optionalTime(op.Pdf.Created, "pdf.created")
	if err != nil {
		return libgen.PDFMeta{}, err
	}
	modified, err := optionalTime(op.Pdf.Modified, "pdf.modified")
	if err != nil {
		return libgen.PDFMeta{}, err
	}
	return libgen.PDFMeta{
		Title:    op.Pdf.Title,
		Author:   op.Pdf.Author,
		Subject:  op.Pdf.Subject,
		Keywords: op.Pdf.Keywords,
		Creator:  op.Pdf.Creator,
		Producer: op.Pdf.Producer,
		Created:  created,
		Modified: modified,
		PageSize: op.Pdf.PageSize,
	}, nil
}

// writeEmail builds the message and either writes it as a standalone .eml or
// appends it to an mbox. The format defaults from the path extension.
func writeEmail(ctx ExecContext, c compile.Op, target string) error {
	op := c.Operation
	boundaries := c.Rand.Derive("email.boundary").Stream()
	var readSource func(string) ([]byte, error)
	if ctx.Sources != nil {
		readSource = ctx.Sources.ReadFile
	}
	msg, date, err := email.Build(email.Options{
		Spec:       *op.Email,
		ReadSource: readSource,
		ReadOutput: ctx.FS.ReadFile,
		Boundary:   func() string { return "----=_fsagen_" + boundaries.Hex(24) },
	})
	if err != nil {
		return err
	}

	format := op.Format
	if format == "" {
		if strings.EqualFold(path.Ext(target), ".mbox") {
			format = "mbox"
		} else {
			format = "eml"
		}
	}

	switch format {
	case "eml":
		if err := ctx.FS.WriteFile(target, msg, fileModeFor(op)); err != nil {
			return err
		}
	case "mbox":
		// Append, so a whole thread accumulates across steps.
		if err := ctx.FS.MkdirParent(target); err != nil {
			return err
		}
		f, err := ctx.FS.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_APPEND, fileModeFor(op))
		if err != nil {
			return err
		}
		if _, err := f.Write(email.ToMbox(msg, email.EnvelopeSender(*op.Email), date)); err != nil {
			_ = f.Close()
			return err
		}
		if err := f.Close(); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unknown email format %q (want eml or mbox)", op.Format)
	}

	// A message with no explicit times inherits its own Date header, which is
	// what an actual mail store would show.
	if strings.TrimSpace(op.Atime) == "" && strings.TrimSpace(op.Mtime) == "" && !date.IsZero() {
		if err := applyMode(ctx.FS, op, target); err != nil {
			return err
		}
		return ctx.FS.Chtimes(target, date, date)
	}
	return applyModeAndTimes(ctx.FS, op, target)
}

// writeArtifact writes the file with the right permissions, creating its
// parent, and then stamps its times.
func writeArtifact(fs *sandbox.FS, op spec.Operation, target string, data []byte) error {
	if err := fs.WriteFile(target, data, fileModeFor(op)); err != nil {
		return err
	}
	return applyModeAndTimes(fs, op, target)
}

func copyFile(fs *sandbox.FS, src, dst string, mode os.FileMode) error {
	in, err := fs.OpenFile(src, os.O_RDONLY, 0)
	if err != nil {
		return err
	}
	defer in.Close()

	if err := fs.MkdirParent(dst); err != nil {
		return err
	}
	out, err := fs.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}

// applyModeAndTimes chmods before stamping times: chmod itself touches ctime,
// so doing it afterwards would disturb the timeline we just set.
func applyModeAndTimes(fs *sandbox.FS, op spec.Operation, target string) error {
	if err := applyMode(fs, op, target); err != nil {
		return err
	}
	return applyTimes(fs, op, target)
}

func applyMode(fs *sandbox.FS, op spec.Operation, target string) error {
	mode, ok, err := util.ParseFileMode(op.Mode)
	if err != nil || !ok {
		return err
	}
	// WriteFile only applies the mode when it creates the file, so an existing
	// target needs an explicit chmod.
	return fs.Chmod(target, mode)
}

func applyTimes(fs *sandbox.FS, op spec.Operation, target string) error {
	at, mt, ok := parseTimes(op.Atime, op.Mtime)
	if !ok {
		return nil
	}
	if at.IsZero() {
		at = mt
	}
	if mt.IsZero() {
		mt = at
	}
	return fs.Chtimes(target, at, mt)
}

// fileModeFor and dirModeFor read a mode that compile has already validated.
func fileModeFor(op spec.Operation) os.FileMode {
	if mode, ok, _ := util.ParseFileMode(op.Mode); ok {
		return mode
	}
	return sandbox.FileMode
}

func dirModeFor(op spec.Operation) os.FileMode {
	if mode, ok, _ := util.ParseFileMode(op.Mode); ok {
		return mode
	}
	return sandbox.DirMode
}

// contentOf returns what the operation writes: its random text when compile
// decided it has no content of its own, else exactly its content, which may
// be empty.
func contentOf(c compile.Op) []byte {
	if c.Random > 0 {
		return []byte(c.Rand.Derive("content").Stream().Text(c.Random))
	}
	return []byte(c.Content)
}

func optionalTime(value, field string) (time.Time, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}, nil
	}
	t, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("%s: %w", field, err)
	}
	return t, nil
}

// parseTimes reads atime and mtime, which compile has already validated;
// ok reports whether either was given.
func parseTimes(at, mt string) (time.Time, time.Time, bool) {
	var atT, mtT time.Time
	if s := strings.TrimSpace(at); s != "" {
		atT, _ = time.Parse(time.RFC3339, s)
	}
	if s := strings.TrimSpace(mt); s != "" {
		mtT, _ = time.Parse(time.RFC3339, s)
	}
	return atT, mtT, !atT.IsZero() || !mtT.IsZero()
}
