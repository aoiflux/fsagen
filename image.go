package main

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aoiflux/fsagen/compile"
	libgenpkg "github.com/aoiflux/fsagen/libgen"
	manifestpkg "github.com/aoiflux/fsagen/manifest"
	"github.com/aoiflux/fsagen/runinfo"
	"github.com/aoiflux/fsagen/sandbox"
	timelinepkg "github.com/aoiflux/fsagen/timeline"
	"github.com/aoiflux/fsagen/volume"
	"github.com/aoiflux/fsagen/volume/container"
	imagepkg "github.com/aoiflux/fsagen/volume/image"
)

// imageOnly lists the flags that describe an image, with whether each was
// given, for refusing them without --image.
func imageOnly(c *config) []struct {
	name  string
	given bool
} {
	return []struct {
		name  string
		given bool
	}{
		{"--image-fs", c.imageFS != ""},
		{"--image-size", c.imageSize != ""},
		{"--cluster-size", c.clusterSize != 0},
		{"--partition", c.partition != container.PartitionMBR},
		{"--image-label", c.imageLabel != ""},
		{"--image-time", c.imageTime != ""},
		{"--alloc", c.alloc != volume.NextFit},
	}
}

// validateImageFlags rejects image flags that contradict each other or the
// rest of the command line.
func validateImageFlags(c *config) error {
	if c.image == "" {
		for _, f := range imageOnly(c) {
			if f.given {
				return usagef("%s needs --image", f.name)
			}
		}
		return nil
	}
	switch {
	case c.out != "":
		return usagef("--image is written instead of an output directory; give one or the other, not both")
	case c.intoExisting:
		return usagef("--into-existing merges into a directory; an image is always made new")
	case c.imageFS == "":
		return usagef("--image needs --image-fs (%s)", strings.Join(imagepkg.FileSystems, ", "))
	case c.imageSize == "":
		return usagef("--image needs --image-size")
	case !c.checkOnly() && inputModes(c) == 0:
		return usagef("--image needs --manifest, --playbook or --bulk")
	}
	if c.imageTime != "" {
		if _, err := time.Parse(time.RFC3339Nano, c.imageTime); err != nil {
			return usagef("--image-time %q is not an RFC 3339 time", c.imageTime)
		}
	}
	if _, err := imagepkg.ParseSize(c.imageSize); err != nil {
		return usagef("--image-size: %v", err)
	}
	return nil
}

// imagePlan lays out the image the flags describe.
func imagePlan(c *config) (imagepkg.Plan, error) {
	abs, err := filepath.Abs(c.image)
	if err != nil {
		return imagepkg.Plan{}, err
	}
	size, err := imagepkg.ParseSize(c.imageSize)
	if err != nil {
		return imagepkg.Plan{}, usagef("--image-size: %v", err)
	}
	when := libgenpkg.DefaultStart
	if c.imageTime != "" {
		when, _ = time.Parse(time.RFC3339Nano, c.imageTime)
	}
	p, err := imagepkg.NewPlan(imagepkg.Options{
		Path: abs, FS: c.imageFS, Size: size, ClusterSize: c.clusterSize, Partition: c.partition,
		Label: c.imageLabel, Time: when.UTC(), Alloc: c.alloc, Seed: c.seed,
	})
	if err != nil {
		return imagepkg.Plan{}, usageError{err.Error()}
	}
	return p, nil
}

// generateImage writes the scenario into a new image. It is generate for
// an image: the capabilities are the file system's, not the host's, and
// the image takes its name only once everything about it is recorded.
func generateImage(c *config, vars map[string]string, varsInput *sandbox.Input, tl *timelineRequest, stdout io.Writer) error {
	plan, err := imagePlan(c)
	if err != nil {
		return err
	}
	absImg := plan.Path
	metaDir, err := resolveMetaDir(c.meta, absImg)
	if err != nil {
		return err
	}
	if c.timeline != "" {
		if err := outside(c.timeline, absImg, "the timeline"); err != nil {
			return err
		}
	}
	switch info, err := os.Stat(absImg); {
	case err == nil && info.IsDir():
		return fmt.Errorf("image path %s is a directory", absImg)
	case err == nil && !c.clean:
		return fmt.Errorf("image %s already exists; pass --clean to replace it (it is replaced only once the new one is complete)", absImg)
	case err != nil && !errors.Is(err, fs.ErrNotExist):
		return err
	}

	caps := plan.Caps()
	rm, rinfo := newRecords(c, varsInput, caps, absImg)
	rm.Target = runinfo.TargetImage
	rinfo.Filesystem = plan.FS + " image"

	var prog *compile.Program
	if c.bulkMode() {
		recordBulkOptions(rm, c)
	} else {
		if prog, err = compileInput(c, vars, nil, caps); err != nil {
			return err
		}
		defer prog.Close()
		if err := recordProgram(rm, rinfo, prog); err != nil {
			return err
		}
	}

	img, err := imagepkg.Create(plan)
	if err != nil {
		return err
	}
	defer img.Abort()
	rm.Image = img.Record()
	rm.Capabilities.TimeResolution = runinfo.ResolutionOf(img.Granularity())
	if err := writeRecords(metaDir, rm, rinfo); err != nil {
		return err
	}

	fmt.Fprintln(stdout, "Generating artifacts...")
	g := runGeneration(c, img, prog, caps, rm, metaDir)
	// An observed timeline is read from the finished image before it is
	// closed; failing to read it fails only the timeline.
	var built *timelinepkg.Timeline
	var tlErr error
	switch {
	case g.err != nil || tl == nil:
	case tl.source == timelinepkg.SourceModelled:
		built = manifestpkg.ModelledTimeline(prog.Model, g.entries, caps)
	default:
		if built, tlErr = timelinepkg.GenerateFrom(g.read, timelinepkg.Options{HashLimit: tl.hashLimit}); built != nil {
			built.Root = absImg
		}
	}
	if g.err == nil {
		var sum string
		if sum, g.err = img.Close(); g.err == nil {
			rm.Outputs.Image = sum
		}
	}
	rinfo.Finished = time.Now().UTC().Format(time.RFC3339Nano)
	if ierr := rinfo.Write(metaDir); ierr != nil && g.err == nil {
		g.err = fmt.Errorf("write run info: %w", ierr)
	}
	if g.err != nil {
		return recordImageFailure(metaDir, rm, g.err, absImg)
	}
	if err := recordSuccess(metaDir, rm, stdout); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "Image written to: %s\n", absImg)
	if tlErr != nil {
		return fmt.Errorf("timeline of %s: %w (the image is complete; only the timeline is missing)", absImg, tlErr)
	}
	return writeTimeline(tl, built, rm, metaDir, absImg, stdout)
}

// recordImageFailure marks the run failed. No image is left behind: it
// takes its name only when the run succeeds.
func recordImageFailure(metaDir string, rm *runinfo.Manifest, cause error, absImg string) error {
	rm.Status, rm.Failure = runinfo.StatusFailed, cause.Error()
	if werr := rm.Write(metaDir); werr != nil {
		return fmt.Errorf("%w (and the run manifest could not be updated: %v)", cause, werr)
	}
	return fmt.Errorf("%w\nno image was written to %s; its run manifest says why", cause, absImg)
}
