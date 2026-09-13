package manifest

import (
	"fmt"
	"fsagen/email"
	"fsagen/libgen"
	"fsagen/render"
	"fsagen/spec"
	"fsagen/util"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	yaml "gopkg.in/yaml.v2"
)

type Manifest = spec.Manifest
type Operation = spec.Operation
type Attachment = spec.Attachment
type EmailSpec = spec.EmailSpec
type Header = spec.Header
type PdfSpec = spec.PdfSpec
type VaultSpec = spec.VaultSpec

// Files land at 0644 and directories at 0755 unless an operation sets mode.
// The generator previously wrote everything 0777, which is not a permission set
// any real file carries.
const (
	defaultFileMode = os.FileMode(0o644)
	defaultDirMode  = os.FileMode(0o755)
)

// ExecContext carries the state every operation needs beyond its own fields.
type ExecContext struct {
	// Root is the output directory all paths are relative to.
	Root string
	// BaseDir is the directory holding the manifest or playbook, used to
	// resolve content_file, email bodies and attachment sources.
	BaseDir string
	// Boundary supplies deterministic MIME boundaries.
	Boundary func() string
}

func defaultBoundary() string { return "----=_fsagen_" + util.GetRandomHex(24) }

// ExecuteManifest reads a YAML manifest file and applies operations under root.
func ExecuteManifest(root string, manifestPath string, vars map[string]string) error {
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return err
	}
	var m Manifest
	// Strict: an unrecognised key is a typo, and silently dropping it produces
	// plausible-looking but wrong artifacts.
	if err := yaml.UnmarshalStrict(data, &m); err != nil {
		return fmt.Errorf("parse manifest: %w", err)
	}

	baseDir := filepath.Dir(manifestPath)
	merged := render.MergeVariables(m.Variables, vars)

	ops, err := prepareManifestOperations(m.Operations, baseDir, merged)
	if err != nil {
		return err
	}

	return ExecuteOperations(ExecContext{Root: root, BaseDir: baseDir}, ops)
}

// prepareManifestOperations renders templates and loads external content.
// Sequence is 1-based and increments per operation in the provided order.
func prepareManifestOperations(ops []Operation, baseDir string, vars map[string]string) ([]Operation, error) {
	out := make([]Operation, 0, len(ops))
	for i, op := range ops {
		// ${DATE:...} in a manifest resolves against that operation's own
		// mtime, falling back to now when it has none.
		refTime := time.Now().UTC()
		if t, err := time.Parse(time.RFC3339, strings.TrimSpace(op.Mtime)); err == nil {
			refTime = t
		}

		prepared, err := PrepareOperation(op, baseDir, render.Context{
			Seq:       i + 1,
			Timestamp: refTime,
			Variables: vars,
		})
		if err != nil {
			return nil, fmt.Errorf("op %d (%s %s): %w", i+1, op.Action, op.Path, err)
		}
		out = append(out, prepared)
	}
	return out, nil
}

// ExecuteOperations applies the provided operations under the given root,
// sequentially. Operations are expected to already be prepared.
func ExecuteOperations(ctx ExecContext, ops []Operation) error {
	if ctx.Boundary == nil {
		ctx.Boundary = defaultBoundary
	}
	for idx, op := range ops {
		if err := executeOp(ctx, op); err != nil {
			return fmt.Errorf("op %d (%s %s): %w", idx+1, op.Action, op.Path, err)
		}
	}
	return nil
}

func executeOp(ctx ExecContext, op Operation) error {
	action := strings.ToLower(strings.TrimSpace(op.Action))
	target := filepath.Join(ctx.Root, filepath.FromSlash(op.Path))

	switch action {
	case "create":
		if strings.ToLower(op.Type) == "dir" || (op.Ext == "" && strings.HasSuffix(op.Path, "/")) {
			if err := os.MkdirAll(target, dirModeFor(op)); err != nil {
				return err
			}
			return applyTimes(op, target)
		}
		if op.Ext != "" && filepath.Ext(target) == "" {
			target += op.Ext
		}
		content, err := renderContent(op, contentOrRandom(op, 1024))
		if err != nil {
			return err
		}
		return writeArtifact(op, target, content)

	case "update":
		// create MkdirAll's its parent; update used not to, which made an
		// update to a not-yet-existing directory fail on a fresh tree.
		if err := os.MkdirAll(filepath.Dir(target), defaultDirMode); err != nil {
			return err
		}
		content, err := renderContent(op, contentOrRandom(op, 1024))
		if err != nil {
			return err
		}
		return writeArtifact(op, target, content)

	case "append":
		if err := os.MkdirAll(filepath.Dir(target), defaultDirMode); err != nil {
			return err
		}
		f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_APPEND, fileModeFor(op))
		if err != nil {
			return err
		}
		if _, err := f.Write(contentOrRandom(op, 256)); err != nil {
			_ = f.Close()
			return err
		}
		if err := f.Close(); err != nil {
			return err
		}
		return applyModeAndTimes(op, target)

	case "delete":
		var dirAt, dirMt *time.Time
		if at, mt, ok := parseTimes(op.Atime, op.Mtime); ok {
			dirAt, dirMt = &at, &mt
		}
		return util.RemoveFile(target, dirAt, dirMt)

	case "mace":
		at, mt, _ := parseTimes(op.Atime, op.Mtime)
		if at.IsZero() && mt.IsZero() {
			return fmt.Errorf("mace requires at least one of atime/mtime")
		}
		if at.IsZero() {
			at = mt
		}
		if mt.IsZero() {
			mt = at
		}
		if mode, ok, err := util.ParseFileMode(op.Mode); err != nil {
			return err
		} else if ok {
			if err := os.Chmod(target, mode); err != nil {
				return err
			}
		}
		return util.SetTimes(target, at, mt)

	case "rename":
		if strings.TrimSpace(op.NewPath) == "" {
			return fmt.Errorf("rename requires new_path")
		}
		newTarget := filepath.Join(ctx.Root, filepath.FromSlash(op.NewPath))
		if err := os.MkdirAll(filepath.Dir(newTarget), defaultDirMode); err != nil {
			return err
		}
		return os.Rename(target, newTarget)

	case "copy":
		if strings.TrimSpace(op.NewPath) == "" {
			return fmt.Errorf("copy requires new_path")
		}
		newTarget := filepath.Join(ctx.Root, filepath.FromSlash(op.NewPath))
		if err := copyFile(target, newTarget, fileModeFor(op)); err != nil {
			return err
		}
		return applyModeAndTimes(op, newTarget)

	case "truncate":
		if err := os.MkdirAll(filepath.Dir(target), defaultDirMode); err != nil {
			return err
		}
		f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, fileModeFor(op))
		if err != nil {
			return err
		}
		if err := f.Close(); err != nil {
			return err
		}
		return applyModeAndTimes(op, target)

	case "rotate":
		if strings.TrimSpace(op.NewPath) == "" {
			return fmt.Errorf("rotate requires new_path")
		}
		newTarget := filepath.Join(ctx.Root, filepath.FromSlash(op.NewPath))
		if err := os.MkdirAll(filepath.Dir(newTarget), defaultDirMode); err != nil {
			return err
		}
		if err := os.Rename(target, newTarget); err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(target), defaultDirMode); err != nil {
			return err
		}
		f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY, fileModeFor(op))
		if err != nil {
			return err
		}
		if err := f.Close(); err != nil {
			return err
		}
		if at, mt, ok := parseTimes(op.Atime, op.Mtime); ok {
			_ = util.SetTimes(newTarget, at, mt)
			_ = util.SetTimes(target, at, mt)
		}
		return nil

	case "email":
		return writeEmail(ctx, op, target)

	case "ansible-vault", "ansible_vault":
		if op.Vault == nil {
			return fmt.Errorf("ansible-vault requires a vault block")
		}
		encrypted, err := util.AnsibleVaultEncrypt([]byte(op.Content), op.Vault.Password, op.Vault.VaultID, op.Vault.Salt)
		if err != nil {
			return err
		}
		return writeArtifact(op, target, encrypted)

	case "ads":
		if !util.IsWindows() {
			return fmt.Errorf("ads action is only supported on Windows")
		}
		if strings.TrimSpace(op.Stream) == "" {
			return fmt.Errorf("ads requires stream name")
		}
		if err := os.MkdirAll(filepath.Dir(target), defaultDirMode); err != nil {
			return err
		}
		if err := util.WriteADS(target, op.Stream, contentOrRandom(op, 128)); err != nil {
			return err
		}
		// Writing a stream updates the base file's mtime, so restore the times
		// the operation asked for.
		return applyTimes(op, target)

	case "motw":
		if !util.IsWindows() {
			return fmt.Errorf("motw action is only supported on Windows")
		}
		zone := op.ZoneID
		if zone < 0 || zone > 4 {
			zone = 3
		}
		if err := os.MkdirAll(filepath.Dir(target), defaultDirMode); err != nil {
			return err
		}
		if err := util.WriteMOTW(target, zone, op.HostURL, op.ReferrerURL); err != nil {
			return err
		}
		return applyTimes(op, target)

	default:
		return fmt.Errorf("unknown action: %s", op.Action)
	}
}

// renderContent applies the typed generator selected by format. Without one,
// content is written through unchanged.
func renderContent(op Operation, raw []byte) ([]byte, error) {
	switch strings.ToLower(strings.TrimSpace(op.Format)) {
	case "", "raw", "text":
		return raw, nil
	case "pdf":
		meta, err := pdfMeta(op)
		if err != nil {
			return nil, err
		}
		return libgen.RenderPDF(string(raw), meta)
	default:
		return nil, fmt.Errorf("unknown format %q (want raw or pdf)", op.Format)
	}
}

func pdfMeta(op Operation) (libgen.PDFMeta, error) {
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
func writeEmail(ctx ExecContext, op Operation, target string) error {
	if op.Email == nil {
		return fmt.Errorf("email action requires an email block")
	}

	msg, date, err := email.Build(email.Options{
		Spec:     *op.Email,
		BaseDir:  ctx.BaseDir,
		Root:     ctx.Root,
		Boundary: ctx.Boundary,
	})
	if err != nil {
		return err
	}

	format := strings.ToLower(strings.TrimSpace(op.Format))
	if format == "" {
		if strings.EqualFold(filepath.Ext(target), ".mbox") {
			format = "mbox"
		} else {
			format = "eml"
		}
	}

	if err := os.MkdirAll(filepath.Dir(target), defaultDirMode); err != nil {
		return err
	}

	switch format {
	case "eml":
		if err := os.WriteFile(target, msg, fileModeFor(op)); err != nil {
			return err
		}
	case "mbox":
		// Append, so a whole thread accumulates across steps.
		f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_APPEND, fileModeFor(op))
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
		if err := applyMode(op, target); err != nil {
			return err
		}
		return util.SetTimes(target, date, date)
	}
	return applyModeAndTimes(op, target)
}

// writeArtifact creates the parent directory, writes the file with the right
// permissions and then stamps its times.
func writeArtifact(op Operation, target string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(target), defaultDirMode); err != nil {
		return err
	}
	if err := os.WriteFile(target, data, fileModeFor(op)); err != nil {
		return err
	}
	return applyModeAndTimes(op, target)
}

func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	if err := os.MkdirAll(filepath.Dir(dst), defaultDirMode); err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
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
func applyModeAndTimes(op Operation, target string) error {
	if err := applyMode(op, target); err != nil {
		return err
	}
	return applyTimes(op, target)
}

func applyMode(op Operation, target string) error {
	mode, ok, err := util.ParseFileMode(op.Mode)
	if err != nil {
		return err
	}
	if !ok {
		return nil
	}
	// WriteFile only applies the mode when it creates the file, so an existing
	// target needs an explicit chmod.
	return os.Chmod(target, mode)
}

func applyTimes(op Operation, target string) error {
	at, mt, _ := parseTimes(op.Atime, op.Mtime)
	if at.IsZero() && mt.IsZero() {
		return nil
	}
	if at.IsZero() {
		at = mt
	}
	if mt.IsZero() {
		mt = at
	}
	return util.SetTimes(target, at, mt)
}

func fileModeFor(op Operation) os.FileMode {
	if mode, ok, err := util.ParseFileMode(op.Mode); err == nil && ok {
		return mode
	}
	return defaultFileMode
}

func dirModeFor(op Operation) fs.FileMode {
	if mode, ok, err := util.ParseFileMode(op.Mode); err == nil && ok {
		return mode
	}
	return defaultDirMode
}

// contentOrRandom returns the operation's content, falling back to
// deterministic random bytes of content_len (or fallbackLen) when it has none.
func contentOrRandom(op Operation, fallbackLen int) []byte {
	if len(op.Content) > 0 {
		return []byte(op.Content)
	}
	sz := op.ContentLen
	if sz <= 0 {
		sz = fallbackLen
	}
	return []byte(util.GetRandomString(sz))
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

func parseTimes(at, mt string) (time.Time, time.Time, bool) {
	var atT, mtT time.Time
	ok := false
	if strings.TrimSpace(at) != "" {
		if t, err := time.Parse(time.RFC3339, at); err == nil {
			atT = t
			ok = true
		}
	}
	if strings.TrimSpace(mt) != "" {
		if t, err := time.Parse(time.RFC3339, mt); err == nil {
			mtT = t
			ok = true
		}
	}
	return atT, mtT, ok
}
