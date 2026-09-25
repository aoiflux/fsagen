# Changelog

## Unreleased: P2, timestamps that mean what the scenario says

Generator version: **3**. File and stream contents are unchanged for every
example (the v3 content goldens equal v2's); only a `copy` of a file with
streams gains those streams. The dry-run listing now shows each operation's
intended times, the run manifest gains time capabilities, and the new ledger
is a covered output, which is why the version moves.

### Times

- **All four times come from the scenario.** Each operation happens at a
  time T and sets the times of what it creates or changes by fixed rules,
  listed in README's new *Timestamps* section and in `compile/times.go`:
  creation makes everything T; writes set access, modification and change
  and keep creation; `mace` sets only what it names; `ads`/`motw` leave the
  file's times alone; rename keeps them and sets change; rotate keeps the
  rotated file's times; a copy is born at T with its source's mtime; a
  directory's modification and change times follow the last entry added,
  removed or renamed in it. Explicit times always win.
- **New fields `ctime` and `crtime`** (change and creation time) on create,
  update, append, truncate, mace, copy, email and ansible-vault. `mace` now
  needs at least one of the four times. On Windows they are set, with the
  access and modification times, in one `FILE_BASIC_INFO` call on a handle
  opened relative to the output root. The spike that decided the capability
  matrix: NTFS stores a change time set this way exactly
  (`TestChangeTimeSticks`); FAT does not store one.
- **Capabilities, never faked.** An explicit `crtime` or `ctime` where it
  cannot be set (Linux, macOS; `ctime` on FAT) fails pre-flight, naming the
  line and field; `--on-unsupported=skip` performs the operation without it
  and records the dropped field in the run manifest. A time the scenario
  only implies is listed as `uncontrolled` in the ledger.
- **Reference times.** A manifest operation happens at its `mtime`, else its
  `atime` (new), else `start`. One with none of them leaves its times to the
  file system; before, it did too, but nothing said so.
- **Playbooks no longer copy the scheduled time into `atime`/`mtime`.** The
  fields hold only what the author wrote. Behaviour changes that follow: a
  `mace` naming only `mtime` no longer also sets the access time (v2 set both
  to the one value), and an `ads`/`motw` keeps the file's times instead of
  stamping it with its own scheduled time (F-TIME-3). The `mace` change
  applies to manifests too. Other manifest operations that give only one of
  `atime`/`mtime` still get it for both, because that time is their T.
- **`delete`** stamps the object with its final times just before removing
  it, so what is left on disk carries scenario times. Its `atime`/`mtime`
  still set the directory it leaves; on a file at the top of the output this
  is now an error, since the output directory's own times are never set.
- **`rotate`** keeps the rotated file's times; v2 stamped both files with the
  rotate time (N-7). **`copy`** carries named streams, as the Windows
  `CopyFile` does, and keeps the source's mtime; v2 dropped the streams and
  stamped the op time (N-7).
- **Fractions of a second** are kept end to end (RFC 3339 with nanoseconds,
  100 ns on NTFS). A playbook's `subsecond_jitter: true` adds a seeded
  fraction of a second to every derived time, never to an explicit one
  (F-TIME-5).
- **Settle and verify.** After each operation fsagen stamps what it touched.
  After the last, it stamps the whole tree again, files first and then
  directories deepest first, and reads every time back. Any time that
  differs by more than the volume's resolution fails the run with a list.
  Only access times may be settled again, a few times, after a short pause:
  with last-access updates on, another process reading the new files (on
  this machine, Defender scanning a new `.bat` in a Startup folder) moves
  them. If they keep moving, the error says why.

### New

- **`ledger.jsonl`** in the sidecar: per operation, the object (a number that
  survives renames), content SHA-256 before and after, size, streams with
  their digests, intended times, uncontrolled times and the outcome
  (done, no-op, skipped). A failed run writes it up to the failing
  operation. The run manifest records its digest; the determinism harness
  compares it across runs; the example goldens pin it.
- **Run manifest capabilities:** `birth_time`, `change_time`,
  `filename_times_controlled: false` (NTFS `$FILE_NAME` times, F-TIME-6) and
  `root_times_controlled: false`. **`run-info.json`** records the host's
  `NtfsDisableLastAccessUpdate`.
- **Dry-run listing:** each line carries `times`, the intended times of the
  object after the operation, in place of the raw `atime`/`mtime` fields.
- **Reads leave access times alone** (F-TIME-4). Digests for the ledger and
  the timeline, and the timeline's directory listings, go through handles
  that suspend access-time updates on Windows (`SetFileTime` with all ones)
  and use `O_NOATIME` on Linux when the caller owns the file. The timeline
  now walks the output through the sandbox, and lists every named stream
  instead of probing three names.
- **API:** `manifest.ExecuteFile` returns the ledger; `ExecutePlaybook` is
  gone (use `ExecuteFile`). `manifest.Execute` returns the ledger;
  `Settle`, `Verify` and `SettleAndVerify` are new; `ExecContext` carries the
  capability set, so an injected set behaves as that platform would.
- **Removed dead code:** `Program.Skipped`, `model.Kind.String`,
  `sandbox.HashReader`, `FS.Lstat`, `FS.Stat`, `FS.Chtimes`.
- README: the stale sentence "Steps run in the order they are written"
  (wrong since P1) now says operations run in time order.

### Goldens

`testdata/golden/v3/` holds the dry-run listings, the Windows content
fingerprints (identical to v2's) and, new, each example's Windows ledger.
`testdata/golden/v1/` and `v2/` are no longer read by any test; removing them
is the owner's call.

### Not done here

- The timeline still writes three times per entry, with the creation time
  in the Ctime column on Windows, and its bodyfile and MACB layouts are
  unchanged: that is P3, together with the modelled timeline and the answer
  key built from this ledger.
- The Linux `O_NOATIME` path, Unix time read-back and the Unix skips of the
  creation and change time tests have been cross-compiled and vetted, not
  run. The owner's Linux/macOS pass covers them.

### Evidence that each test can fail

Every P2 test was shown to fail with its guard removed: the code was
mutated, the named tests ran and failed, and the file was restored. All 33
mutations were killed. One first survived: making a create keep an existing
file's birth time went unnoticed because no test created a file twice, so
`TestCreateSetsCreationTime` gained that case, and the F-TIME-1 mutation was
moved to the fix itself (the creation time never being set).

| Finding | Mutation | Test |
|---|---|---|
| F-TIME-2 | change time not set | TestChangeTimeSticks, TestMaceSetsFourTimes |
| F-TIME-1 | creation time never set | TestCreateSetsCreationTime |
| F-TIME-1 | create over an existing file keeps its birth | TestCreateSetsCreationTime |
| CR-6 | a stomp also moves crtime | TestQuilldropLiteStompCount |
| F-TIME-3 | a stream write counts as a write | TestAdsAndMotwKeepTimes |
| F-TIME-3 | entries do not touch their directory | TestDirTimesFollowLastChildEvent |
| settle | settle pass skipped | TestExamples |
| verify | verify accepts anything | TestVerifyPassMatchesModel |
| N-7 | rotated file born again | TestRotateKeepsRotatedTimes |
| N-7 | copy takes a new mtime | TestCopySemantics |
| N-7 | copy drops streams | TestCopyCarriesStreams |
| F-TIME-5 | sub-second part dropped | TestNanoPrecisionRoundTrip |
| F-TIME-5 | jitter from the clock | TestJitterDeterministicAndNeverOnExplicit |
| F-TIME-5 | jitter never applied | TestJitterDeterministicAndNeverOnExplicit |
| ledger | previous digest forgotten | TestLedgerCreateStompRenameDelete |
| ledger | claims times the platform cannot set | TestDefaultCrtimeRecordedUncontrolled |
| F-PLAT-2 | explicit crtime not checked | TestExplicitCrtimeUnsupportedPreflight, TestDroppedTimeFieldRecorded |
| delete | not stamped before removal | TestDeleteStampsBeforeRemoval |
| delete | times on the output root accepted | TestDeleteTimesAtRootRefused |
| reference time | manifest ignores atime | TestManifestReferenceTime |
| explicit | scheduled time copied into atime | TestScheduledTimeIsNotExplicit |
| mace | touches times it does not name | TestMaceLeavesUnnamedTimes |
| email | mbox born again at every message | TestEmailTimesFromDate |
| F-TIME-4 | quiet open does not suspend access times | TestOpenQuietKeepsAtime, TestReadDirQuietKeepsAtime, TestTimelinePassKeepsAtime |
| F-TIME-4 | timeline digests with a plain read | TestTimelinePassKeepsAtime |
| sandbox | a zero time written as 1601 | TestSetTimesZeroLeavesAlone |
| F-TIME-6 | `filename_times_controlled` left out | TestRunManifestTimeCapabilities |
| ledger | digest not in the run manifest | TestRunManifestTimeCapabilities |
| ledger | lost when the run fails | TestFailedRunMarksSidecarFailed |
| timeline | only well-known streams listed | TestTimelineListsEveryStream |
| settle | never retried | TestSettleRetriesOnlyForAccessTimes |
| settle | retried for any time | TestSettleRetriesOnlyForAccessTimes |
| version | dry-run changed without a new version | TestDryRunGoldens |

## P1: determinism you can state in one sentence (31b10e1)

Generator version: **2**. Output changes for every seed. Corpora made by
version 1 are reproduced with the build that made them (tag 7accc8d and
62d759c before landing this).

README's *Determinism contract* is the statement: for one generator version,
the pinned toolchain, the same seed and the same inputs, file and stream
contents, paths, the dry-run listing and `run-manifest.json` are
byte-identical, on every platform, for every operation the platform supports.

### Output bytes

- **Every random value comes from its own keyed stream** (new `prng`
  package). A stream's key comes from the seed plus what the value is for:
  - the operation's `id`, or else a hash of its YAML;
  - for playbooks, the actor, step offset, iteration and batch;
  - the field;
  - the token kind and its position among tokens of that kind in the field.

  Adding, removing or reordering an unrelated action, field or token no
  longer changes any other value. Skipping an unsupported operation changes
  nothing else, so v1's placeholder draws (`drawOnly`) are gone. ChaCha8
  (`math/rand/v2`) supplies the bits. Text, hex, UUIDs and bounded integers
  are mapped in fsagen's own code, not by math/rand helpers that may change
  between Go releases. `TestPRNGGoldenVectors` pins the scheme.
- **Nothing reads the wall clock:**
  - A manifest's `${DATE}` uses the operation's `mtime`, else the new
    top-level `start`. With neither it is an error (v1 used the current
    time).
  - Unpinned `format: pdf` dates and an email with no `date` default to the
    scheduled time in playbooks, and to `mtime`/`start` in manifests. If
    one pdf date is given, the other copies it. With no reference time
    these are errors. v1 used the current time, or left an email without a
    `Date` header and dated its mbox entry 1970.
  - Bulk mode takes `--bulk-start` (default 2021-01-01T00:00:00Z) for its
    JSON, PDF, log, mail, zip and history dates.
  - Only `start: now` reads the clock, and it marks the run
    `"reproducible": false`.
- **`content: ''` writes an empty file.** v1 wrote 1024 random characters, and
  P0 refused it. Random content is used only when an operation gives no
  content, content_file or template.
- **Repeated email, pdf and vault specs are copied per occurrence.** Each
  occurrence renders its own tokens and gets its own date. v1 rendered the
  first occurrence in place and every later one reused it.
- **Playbooks run in time order.** Operations are stable-sorted by scheduled
  time, and ties keep declaration order. Overlapping repeating steps now
  interleave; before, one step ran to completion before the next started
  (F-IN-15). `${SEQ}` still counts in declaration order. In the examples,
  `playbook-insider-threat-exfil` and `playbook-malware-lifecycle` run in a
  different order.
- **`refs` over several files draws random content per file**, keyed by path.
- **The vault salt** comes from the operation's own stream when `salt` is not
  given.
- **Bulk mode is reproducible:**
  - The plan (directories, names, per-file keys) is built in one sequential
    pass.
  - A bounded worker pool renders each file in memory and writes it through
    the output root. Every worker is waited for on success and on failure.
    The error reported comes from the first failing file in plan order.
  - SQLite databases are built in a private temporary directory with no
    journal and then copied in, so stray `-journal` files are gone.
  - `.docx` comes from fsagen's own OOXML writer: stored members in a fixed
    order. The docx library it replaces wrote its members in Go map order,
    so the same seed gave different bytes. This writer was planned for P4
    and moved here for that reason.
  - `.mp4` is still placeholder text, now written directly.
  - The 19-versus-20 goroutine count mismatch and the nil-file writes after a
    failed create are gone with the old code (F-DET-1/2, F-GEN-6).

### New

- **`SHA256SUMS`** in the sidecar directory: every file and `path:stream`,
  sorted, in `sha256sum` format. `run-manifest.json` records its digest and
  counts.
- **`run-manifest.json` is deterministic:**
  - These moved out of it: module version, VCS revision, OS, architecture and
    file system.
  - It keeps the Go version and the capability set.
  - The non-reproducible facts go to the new **`run-info.json`**: build,
    host, platform, absolute paths, start and finish times.
- **`--bulk-start`**, and a top-level **`start`** for manifests (also in the
  schema).
- **Timelines** are written in UTC, sort equal times by path, and carry no
  `Generated:` wall-clock line. They record the live file system and remain
  outside the contract.
- **Pinned toolchain:** `go.mod` has `toolchain go1.27.0`. PDF streams and PNG
  output go through compress/flate, so a different Go release may change
  their bytes; the run manifest's `go_version` says which one was used.
- **Dependencies:**
  - `glebarez/sqlite` (GORM) is replaced by the plain `database/sql` driver
    `glebarez/go-sqlite`;
  - `gingfrederik/docx` is replaced by fsagen's own writer;
  - `abema/go-mp4` is dropped: it only passed bytes through. A real container
    is P4.
- **API:** `manifest.ExecuteManifest`/`ExecutePlaybook` now take
  `compile.Options`, which carries the seed. The global generator
  (`util.Seed`, `GetRandom*`) is gone. `util.AnsibleVaultEncrypt` requires a
  salt.
- **Schema:** a new test checks that the hand-written top-level keys match
  the Go types. Without it, `start` would have gone missing from the
  manifest schema unnoticed.

### Goldens

The goldens under `testdata/golden/v2/` were recorded with the version bump. v1's
goldens under `testdata/golden/v1/` are no longer read by any test. They are
kept until the owner decides whether to remove them; the tags reproduce them.

### Deferred

Timestamps (P2), timeline fidelity (P3) and typed artefacts (P4) are
unchanged. `TIMELINE_FEATURE.md` and `examples/*.md` still describe
timelines as deterministic; P5 corrects them.

### Evidence that each test can fail

As in P0, every P1 test was shown to fail with its guard removed: the code
was mutated, the test ran and failed, and the file was restored. All 26
mutations were killed. One mutation first survived: `TestSidecarRecords`
missed a path it did not look for, so the mutation was corrected to record
the path that test checks. The token test gained an assertion so that it
catches a counter shared across token kinds.

| Finding | Mutation | Test |
|---|---|---|
| F-DET-5 | operation key includes its position (`${SEQ}`) | TestInsertingUnrelatedActionLeavesOtherFilesUnchanged |
| F-DET-5 | one draw counter shared by all token kinds | TestTokenDrawIndependentOfOtherFields |
| F-DET-5 | scheme name changed | TestPRNGGoldenVectors |
| F-DET-5 | text mapping changed | TestExampleContentGoldens |
| contract | root key ignores the seed | TestDeterminismHarness |
| F-DET-1 | bulk content keyed by wall time | TestBulkDeterministic |
| F-DET-2 | one file kind left out of the plan | TestBulkNoJournalExactCounts |
| F-DET-2 | workers not awaited | TestBulkErrorReturnedNoLeak |
| F-DET-3 | bulk JSON timestamp from the clock | TestNoWallClockInContent |
| F-DET-3 | bulk PDF dates unpinned | TestNoWallClockInContent |
| F-GEN-10 | manifest `${DATE}` falls back to now | TestManifestDateNeedsTime |
| F-DET-3 | `start: now` ignores the injected clock | TestStartNowFlagged |
| F-DET-4 | timeline in local time | TestTimelineZoneIndependent |
| F-TL-9 | equal times ordered against path | TestTimelineTieOrder |
| F-DET-4 | `Generated:` wall-clock line | TestNoWallClockInTimeline |
| F-IN-15 | playbook left in declaration order | TestPlaybookRunsInTimeOrder |
| empty content | `content: ''` treated as absent | TestEmptyContentIsEmpty, TestEmptyContentWritesEmptyFile |
| shared specs | email spec not copied per occurrence | TestRepeatedEmailRendersPerIteration |
| refs | refs targets share one key | TestRefsTargetsDrawOwnContent |
| SHA256SUMS | streams left out | TestCrossCapabilityContentEquality |
| SHA256SUMS | a file left out | TestSidecarRecords |
| run manifest | absolute input path recorded | TestSidecarRecords |
| schema | manifest `start` missing | TestSchemaRootKeysMatchSpec |
| D-10 | docx part renamed | TestDocxOpensWithParts |
| vault | missing salt accepted | TestVaultNeedsSalt |

## P0: stop silent wrong output and unsafe writes (b4a5d3e)

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
