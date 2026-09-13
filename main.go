package main

import (
	"flag"
	"fmt"
	libgenpkg "fsagen/libgen"
	manifestpkg "fsagen/manifest"
	playbookpkg "fsagen/playbook"
	"fsagen/render"
	schemapkg "fsagen/schema"
	timelinepkg "fsagen/timeline"
	"fsagen/util"
	"os"
	"path/filepath"
	"strings"

	yaml "gopkg.in/yaml.v2"
)

func main() {
	seed := flag.Int64("seed", 1, "PRNG seed for deterministic generation")
	manifestPath := flag.String("manifest", "", "Path to a YAML manifest that defines specific artifacts and actions")
	playbookPath := flag.String("playbook", "", "Path to a YAML playbook that describes a modus operandi (high-level timeline)")
	generateSchema := flag.Bool("generate-schema", false, "Write separate JSON schemas for manifest/playbook inputs and exit")
	schemaOut := flag.String("schema-out", "examples", "Output directory for --generate-schema")
	// Super-simple bulk generation (no manifest/playbook): generate a bunch of files
	bulkLimit := flag.Int("bulk", 0, "Bulk generation: number of items per level (no manifest/playbook)")
	bulkDepth := flag.Int("depth", 1, "Bulk generation: directory depth (default 1)")
	timelineOutput := flag.String("timeline", "", "Generate forensic timeline after execution (formats: csv, txt, bodyfile, macb)")
	varsFile := flag.String("vars-file", "", "YAML file of key: value variables available to manifests and playbooks as ${VAR:name}")
	var varFlags varList
	flag.Var(&varFlags, "var", "Set a template variable as key=value (repeatable; overrides --vars-file)")
	flag.Parse()

	if *generateSchema {
		manifestOut, playbookOut, err := writeInputSchemas(*schemaOut)
		if err != nil {
			handle(err)
		}
		fmt.Printf("Manifest schema written to: %s\n", manifestOut)
		fmt.Printf("Playbook schema written to: %s\n", playbookOut)
		return
	}

	args := flag.Args()
	if len(args) < 1 {
		printUsage()
		return
	}

	// Initialize deterministic RNG
	util.Seed(*seed)

	vars, err := loadVariables(*varsFile, varFlags)
	handle(err)

	path := args[0]
	absPath, err := getRootPath(path)
	handle(err)

	// Timeline-only mode: if only --timeline is specified, skip generation and just scan the folder
	timelineOnly := *timelineOutput != "" && *playbookPath == "" && *manifestPath == "" && *bulkLimit == 0

	if timelineOnly {
		// Just generate timeline from existing artifacts
		fmt.Printf("Scanning existing artifacts in %s...\n", absPath)
	} else {
		// Require either playbook, manifest, or bulk for generation
		if *playbookPath == "" && *manifestPath == "" && *bulkLimit == 0 {
			fmt.Println("Error: either --manifest, --playbook, or --bulk is required (or use --timeline alone for timeline-only mode)")
			printUsage()
			os.Exit(1)
		}

		fmt.Println("Generating artifacts...")

		if *playbookPath != "" {
			if err := playbookpkg.ExecutePlaybook(absPath, *playbookPath, vars); err != nil {
				handle(err)
			}
		} else if *manifestPath != "" {
			if err := manifestpkg.ExecuteManifest(absPath, *manifestPath, vars); err != nil {
				handle(err)
			}
		} else if *bulkLimit > 0 {
			// Bulk generation mode
			if *bulkDepth < 1 {
				*bulkDepth = 1
			}
			if err := libgenpkg.GenerateFiles(absPath, int64(*bulkLimit), int64(*bulkDepth)); err != nil {
				handle(err)
			}
		}

		fmt.Println("Done!")
	}

	// Generate timeline if requested
	if *timelineOutput != "" {
		fmt.Println("\nGenerating forensic timeline...")
		if err := generateTimeline(absPath, *timelineOutput); err != nil {
			fmt.Printf("Warning: timeline generation failed: %v\n", err)
		} else {
			fmt.Printf("Timeline written to: %s\n", *timelineOutput)
		}
	}
}

func printUsage() {
	fmt.Println("Usage: fsagen [OPTIONS] <output-path>")
	fmt.Println()
	fmt.Println("Generate deterministic filesystem artifacts for forensic testing.")
	fmt.Println()
	fmt.Println("Options:")
	fmt.Println("  --seed N           PRNG seed for deterministic generation (default: 1)")
	fmt.Println("  --manifest FILE    Execute a YAML manifest (simple file operations)")
	fmt.Println("  --playbook FILE    Execute a YAML playbook (complex modus operandi)")
	fmt.Println("  --generate-schema  Write separate JSON schemas (manifest/playbook) and exit")
	fmt.Println("  --schema-out DIR   Output directory for --generate-schema (default: examples)")
	fmt.Println("  --bulk N           Super-simple bulk generation: N items per level (no manifest/playbook)")
	fmt.Println("  --depth D          Bulk generation depth (default: 1)")
	fmt.Println("  --timeline FILE    Generate forensic timeline after execution")
	fmt.Println("  --vars-file FILE   YAML map of variables exposed to templates as ${VAR:name}")
	fmt.Println("  --var k=v          Set one template variable (repeatable; overrides --vars-file)")
	fmt.Println()
	fmt.Println("Timeline-only mode:")
	fmt.Println("  If --timeline is specified without --manifest/--playbook/--bulk, fsagen will")
	fmt.Println("  scan the existing folder and generate a timeline without creating new artifacts.")
	fmt.Println()
	fmt.Println("Timeline formats (detected by file extension):")
	fmt.Println("  .csv               CSV format with full metadata")
	fmt.Println("  .txt               Human-readable text format")
	fmt.Println("  .bodyfile          Bodyfile format (compatible with mactime)")
	fmt.Println("  .macb              MACB timeline format")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  fsagen --generate-schema")
	fmt.Println("  fsagen --generate-schema --schema-out ./schemas")
	fmt.Println("  fsagen --seed 42 --manifest basic.yaml ./output")
	fmt.Println("  fsagen --seed 100 --playbook adversary.yaml ./crime-scene")
	fmt.Println("  fsagen --seed 100 --playbook adversary.yaml --timeline timeline.csv ./output")
	fmt.Println("  fsagen --seed 7  --bulk 3 --depth 2 ./quick-bulk")
	fmt.Println()
	fmt.Println("Timeline-only mode (no artifact generation):")
	fmt.Println("  fsagen --timeline timeline.csv ./existing-artifacts")
	fmt.Println()
	fmt.Println("Either --manifest, --playbook, or --bulk is required for artifact generation.")
	fmt.Println("Use --timeline alone to generate a timeline from existing artifacts.")
}

func generateTimeline(root string, outputPath string) error {
	// Generate the timeline
	tl, err := timelinepkg.Generate(root)
	if err != nil {
		return fmt.Errorf("generate timeline: %w", err)
	}

	// Create output file
	f, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("create timeline file: %w", err)
	}
	defer f.Close()

	// Determine format from file extension
	ext := strings.ToLower(filepath.Ext(outputPath))

	switch ext {
	case ".csv":
		return tl.WriteCSV(f)
	case ".txt":
		return tl.WriteTXT(f)
	case ".bodyfile":
		return tl.WriteBodyfile(f)
	case ".macb":
		return tl.WriteMACB(f)
	default:
		// Default to CSV if extension not recognized
		return tl.WriteCSV(f)
	}
}

func getRootPath(path string) (string, error) {
	finfo, err := os.Stat(path)
	if os.IsNotExist(err) {
		// MkdirAll, not Mkdir: an output path several levels deep is normal
		// when each evidence item writes to its own directory.
		if err := os.MkdirAll(path, 0o755); err != nil {
			return "", err
		}
	}

	absPath, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}

	if finfo != nil {
		if !finfo.IsDir() {
			return filepath.Dir(absPath), nil
		}
	}

	return absPath, nil
}

func handle(err error) {
	if err != nil {
		fmt.Printf("\n\n%v\n\n", err)
		os.Exit(1)
	}
}

func writeInputSchemas(outputDir string) (string, string, error) {
	if strings.TrimSpace(outputDir) == "" {
		return "", "", fmt.Errorf("schema output directory cannot be empty")
	}
	if strings.EqualFold(filepath.Ext(outputDir), ".json") {
		outputDir = filepath.Dir(outputDir)
	}
	if err := os.MkdirAll(outputDir, os.ModePerm); err != nil {
		return "", "", fmt.Errorf("prepare schema output directory: %w", err)
	}

	manifestPath := filepath.Join(outputDir, "manifest-schema.json")
	playbookPath := filepath.Join(outputDir, "playbook-schema.json")

	manifestSchema, err := schemapkg.BuildManifestSchema()
	if err != nil {
		return "", "", fmt.Errorf("build manifest schema: %w", err)
	}
	playbookSchema, err := schemapkg.BuildPlaybookSchema()
	if err != nil {
		return "", "", fmt.Errorf("build playbook schema: %w", err)
	}

	if err := os.WriteFile(manifestPath, manifestSchema, 0o644); err != nil {
		return "", "", fmt.Errorf("write manifest schema: %w", err)
	}
	if err := os.WriteFile(playbookPath, playbookSchema, 0o644); err != nil {
		return "", "", fmt.Errorf("write playbook schema: %w", err)
	}
	return manifestPath, playbookPath, nil
}

// varList collects repeated --var key=value flags.
type varList []string

func (v *varList) String() string { return strings.Join(*v, ",") }

func (v *varList) Set(s string) error {
	if _, _, err := render.ParseVarAssignment(s); err != nil {
		return err
	}
	*v = append(*v, s)
	return nil
}

// loadVariables merges a --vars-file with any --var overrides. Command-line
// values win, so one persona file can drive every scenario while a single value
// is overridden per run.
func loadVariables(varsFile string, overrides varList) (map[string]string, error) {
	vars := map[string]string{}

	if strings.TrimSpace(varsFile) != "" {
		data, err := os.ReadFile(varsFile)
		if err != nil {
			return nil, fmt.Errorf("read vars file: %w", err)
		}
		if err := yaml.UnmarshalStrict(data, &vars); err != nil {
			return nil, fmt.Errorf("parse vars file %s (expected a flat map of key: value): %w", varsFile, err)
		}
	}

	for _, assignment := range overrides {
		k, val, err := render.ParseVarAssignment(assignment)
		if err != nil {
			return nil, err
		}
		vars[k] = val
	}
	return vars, nil
}
