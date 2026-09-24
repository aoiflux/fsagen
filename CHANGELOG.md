# Changelog

## Unreleased: P0, stop silent wrong output and unsafe writes

Generator version: **1** (unchanged bytes for valid inputs; see below).

This is the first phase of the correctness overhaul planned from the Mutant
QUILLDROP audit (`plan.json`). Its rule: every input mistake becomes an error
reported before anything is written; nothing is written or read outside its
root; timeline format and exit codes are honest.

### Output bytes

For every input that is still valid, output is byte-identical to 7accc8d.
`TestExampleContentGoldens` records names, contents and NTFS streams for all
15 shipped examples at seed 42. The v1 goldens were taken from 7accc8d's
behaviour and cross-checked against an unmodified 7accc8d binary before any
behaviour changed. Eight examples only gained `format: text` markers, and
their bytes are unchanged. The examples listed under *Examples* changed
because their inputs changed.

### Breaking: inputs that now fail

Each error names the file, line and column, the operation or step/action, and
the field.

- **Keys:**
  - unknown or duplicate keys, with the list of valid keys;
  - keys the action does not use (per-action field matrix, `compile.Fields`).
- **Values:**
  - a non-RFC 3339 time (atime, mtime, `pdf.created`/`modified`, `email.date`, `start`);
  - a negative `every`; `repeat` above 1 without `every`;
  - `repeat`/`batch_count`/`content_len` below 1;
  - `zone_id` outside 0-4; an invalid `mode`; line breaks in `host_url`/`referrer_url`.
- **Closed sets:** action names, `type`, `format`, conditions and templates.
  Action and condition names are now case-sensitive.
- **Tokens:**
  - an undefined `${VAR:x}` (was left verbatim);
  - an unknown, zero-length or unterminated token;
  - `${ACTOR}` in a manifest.
  - `$${` writes a literal `${`.
- **Template:** `template` together with `content`/`content_file` (the template
  used to win silently); an unknown template (was 256 random characters).
- **Existence:**
  - `delete` of a missing path (use `missing_ok: true`);
  - `update`/`truncate` of a missing file (use `create`);
  - `ads`/`motw` on a missing base;
  - `rename`/`copy`/`rotate` onto an existing path;
  - deleting a non-empty directory.
- **Paths:** `..` that leaves the root, absolute paths, drive letters, `:`,
  `\`, NUL, and names ending in a dot or space.
- **Portability** (waived by `--allow-nonportable`): reserved Windows device
  names, paths that collide by case or Unicode normalisation, relative paths
  over 200 characters.
- **Sources:** `content_file`, email body files and `attachments[].source_file`
  outside the YAML's directory (waived by `--allow-external-sources`);
  `source_root` must name a file already in the output.
- **Random content under a structured extension** (`.exe`, `.zip`, `.png`,
  `.jpg`, `.sqlite`, `.docx`, `.mp4`, `.eml`, ...). Use `format: text` for a
  deliberate placeholder.
- **`content: ''`** (explicitly empty). Generator version 1 writes random text
  for empty content. Until the next byte-changing version fixes that, it is
  refused rather than answered with 1024 characters of base32; `append` creates
  a missing log.
- **Playbooks** must state `start` (RFC 3339 or `now`).
- **Unsupported operations** (`ads`/`motw` where the volume has no named
  streams) fail before anything is written unless `--on-unsupported=skip`.
- **Command line:**
  - an output path that is a file;
  - a non-empty output directory without `--clean` or `--into-existing`;
  - a timeline with an unknown extension, or inside the output directory;
  - timeline-only mode on a missing directory.

### New

- **Module path** `github.com/aoiflux/fsagen`, so `go install` works once pushed.
- **References between actions:** `id`, `ref`, `refs`, `missing_ok`.
- **Flags:**
  - `--validate`, `--dry-run` (JSON lines);
  - `--clean`, `--into-existing`, `--on-unsupported`;
  - `--allow-nonportable`, `--allow-external-sources`, `--meta`;
  - `--timeline-format` (`.body` is now a bodyfile);
  - `--version`.
- **`run-manifest.json`** beside the output (`<out>.fsagen/`). Its status is
  `running` until the run ends, then `complete` or `failed` with the failing
  operation. It also records the generator version, seed, SHA-256 of every
  input, options, platform, filesystem and skipped operations. It contains no
  absolute paths or wall-clock times.
- **Exit codes:** 0 success, 1 generation failed, 2 command-line error.
  Diagnostics go to stderr.
- **Confined I/O:**
  - every manifest/playbook write goes through `os.Root`;
  - NTFS streams are opened relative to a handle on their base file
    (`NtCreateFile`), so they can only belong to a file inside the root;
  - streams are enumerated with `FileStreamInfo`.
- **Tooling:** JSON Schemas generated from the validator's own field table
  (`schemas/`, drift test), MIT `LICENSE`, `.gitattributes`, and
  `go run ./tools/gate`.
- **Platforms:** builds for darwin and freebsd (the timeline stat reader is
  split per OS).

### Examples

These now do what their comments said. Their outputs changed because their
inputs did:

- `playbook-basic`: each update rewrites the report its iteration created, and
  the photo is really deleted.
- `playbook-email-and-archive`: the originals are really deleted (`refs`).
- `playbook-insider-threat-exfil`: the final clean-up deletes every saved
  attachment (`refs`).
- `playbook-malware-lifecycle`: the dropper, its Zone.Identifier stream and
  its Run key name the same file.
- `playbook-log-tampering`, `playbook-log-rotate-and-truncate`,
  `playbook-persistence-artifacts`: log lines end in real line breaks (a
  single-quoted `'\n'` is a literal backslash-n in YAML), and no log starts
  with 1024 random characters.
- Eight examples gained `format: text` on placeholder files. Their bytes are
  unchanged; P4 replaces the placeholders with real formats.

### Known, deliberately deferred

These are unchanged in P0 because fixing them changes bytes for existing seeds.
They wait for the generator-version bump planned in P1:

- per-operation random streams;
- empty content meaning an empty file;
- bulk-mode determinism;
- repeated `email` actions re-rendering their own spec each iteration.

Timestamps (P2), timelines (P3) and typed artefacts (P4) follow the plan.
Remaining doc claims are handled in P5: TIMELINE_FEATURE.md and
examples/*.md still claim deterministic timelines.

### Evidence that each test can fail

Every P0 test was shown to fail with its guard removed. Each guarded condition
was disabled or inverted, the test was run and failed, and the file was
restored. All 34 mutations were killed:

| Finding | Mutation | Test |
|---|---|---|
| F-SEC-1 | pathpolicy stops rejecting escapes | TestPathRules |
| F-SEC-1 | sandbox writes by joined path instead of `os.Root` | TestNothingWrittenOutsideRoot |
| F-SEC-2 | `:` allowed in paths | TestPathRules |
| F-SEC-3 | output path may be a file | TestOutputIsFileRefused |
| F-SEC-5 | non-empty output accepted | TestNonEmptyRootNeedsCleanOrIntoExisting |
| F-IN-1 | unknown keys left to the decoder | TestUnknownKeyPerStruct |
| F-IN-2 | bad times accepted | TestBadTimeIsError |
| F-IN-3 | negative `every` accepted | TestDurations |
| F-IN-4 | unknown condition accepted | TestUnknownCondition |
| F-IN-5 | undefined variable left verbatim | TestUndefinedVariableIsError |
| F-IN-6 | template + content accepted | TestTemplateRules |
| F-IN-7 | delete of a missing path always a no-op | TestDeleteMissing |
| F-IN-8 | `refs` not expanded | TestRefsDeleteAllStaging |
| F-IN-9 | zone range unchecked | TestValueRules |
| F-IN-10 | stream base existence unchecked | TestPreconditions |
| F-IN-11 | update of a missing file accepted | TestUpdateMissingIsError |
| F-IN-12 | backslashes accepted | TestPathRules |
| F-IN-14 | one string field skipped by rendering | TestEveryStringFieldRenders |
| F-IN-16 | `repeat` without `every` accepted | TestRepeatWithoutEvery |
| F-TL-1 | `.body` not mapped to bodyfile | TestTimelineFormats |
| F-TL-8 | timeline inside the root accepted | TestTimelineFailures |
| F-PLAT-2 | pre-flight disabled | TestUnsupportedOpsFailBeforeAnyWrite |
| F-PLAT-3 | usage exit code 1 / runtime exit code 3 | TestNoArgsExit2Stderr, TestRuntimeErrorExit1Stderr |
| F-PLAT-8 | reserved names allowed | TestPortability |
| F-PLAT-8 | case collisions allowed | TestFoldCollision |
| F-GEN-1 | random content under `.exe` allowed | TestRandomContentWithTypedExtension |
| unconfined reads | external sources allowed | TestContentFileConfined |
| invalid mode | mode not validated | TestValueRules |
| partial tree | failed run marked complete | TestFailedRunMarksSidecarFailed |
| rename over | rename onto an existing path allowed | TestPreconditions |
| empty content | `content: ''` allowed | TestValueRules |
| skip | skipped `ads` makes no random draw | TestOnUnsupportedSkipRecordsAndKeepsOtherBytes |
| golden guard | random text drawn differently | TestExampleContentGoldens |

The mutation pass also caught a weak test: the exit-code tests compared
against the same constants the code uses. They now assert the literal codes.
