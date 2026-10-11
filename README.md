<div align="center">

# fsagen

**File System Artifacts Generator**

Deterministic file-system artifacts for testing forensic tools.

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Go](https://img.shields.io/badge/go-1.26%2B-00ADD8.svg?logo=go&logoColor=white)](go.mod)
[![Platforms](https://img.shields.io/badge/platforms-windows%20%7C%20linux%20%7C%20macos%20%7C%20freebsd-lightgrey.svg)](#platform-support)
[![Paper](https://img.shields.io/badge/paper-Springer%202026-orange.svg)](https://link.springer.com/chapter/10.1007/978-981-96-9443-3_17)

</div>

Describe a scenario in YAML; fsagen writes the corpus, records every operation,
and tells you what a tool examining that corpus should find. The same seed and
the same inputs give byte-identical output on every run and every machine — so
two tools disagreeing about a corpus is a finding about the tools, not the data.

Built for exercising forensic suites (Autopsy, EnCase, FTK and the rest): a
**manifest** for a flat list of operations, a **playbook** for a full modus
operandi with actors and a schedule, or the **bulk generator** for a quick
synthetic corpus with no YAML at all.

## Contents

**Start here** · [Features](#features) · [Install](#install) ·
[Quick start](#quick-start) · [Usage](#usage) ·
[Bulk generation](#bulk-generation)

**Writing scenarios** · [Manifest schema](#manifest-schema) ·
[Playbook schema](#playbook-schema) ·
[Email, PDF and Ansible vault](#email-pdf-and-ansible-vault) ·
[ATT&CK tags](#attck-tags) · [Slack](#slack) · [Disk images](#disk-images) ·
[Sharing values](#sharing-values-across-scenarios) ·
[File formats](#file-formats)

**What it guarantees** · [Timestamps](#timestamps) ·
[Determinism contract](#determinism-contract) ·
[Forensic timelines](#forensic-timelines) ·
[Scoring a tool](#scoring-a-tool-diff-oracle) ·
[Platform support](#platform-support) · [Limits](#limits)

**Project** · [Development](#development) · [Dependencies](#dependencies) ·
[Citation](#citation)

## How a run works

```text
INPUT                 PLAN — nothing on disk yet            OUTPUT
─────                 ──────────────────────────            ──────
manifest.yaml ┐       load       strict YAML + positions    corpus/
playbook.yaml ├─────▶ compile    operations, times, paths ─▶  files
--bulk N      ┘       check      closed sets, formats          streams
                      simulate   in-memory tree               all 4 times
                      pre-flight platform capabilities
                               │                            corpus.fsagen/
                               ▼                               run records
                      a problem stops the run here,            timeline
                      with nothing written at all
```

Nothing reaches the disk until the whole scenario is known to be possible. An
input that asks for something the platform cannot do fails **before** the first
byte, unless `--on-unsupported=skip` is given — and then every skipped operation
is recorded rather than silently dropped.

## Features

- Deterministic output with `--seed`: the same seed and inputs give
  byte-identical files (see _Determinism contract_)
- Manifest mode: simple, declarative file operations
  (create/update/append/edit/delete/mace/timestomp/rename/copy/truncate/rotate/archive/ads/motw/email/ansible-vault/hardlink/symlink/junction)
- Playbook mode: complex timelines with actors, timed steps, and templating
- Bulk mode: super-simple synthetic corpus generation with `--bulk` and
  `--depth`
- Author content in real files with `content_file`, shared across scenarios with
  `--vars-file`
- Files a tool can actually parse: PE executables, zip, PNG, JPEG, MP4, docx,
  macro-enabled Word and Excel documents (`.docm`, `.xlsm`) whose one macro is
  inert, `.xlsx` workbooks, PDF, Windows shortcuts (`.lnk`), Prefetch files, event logs (`.evtx`),
  registry hives (with Run keys, UserAssist and USB history), Linux login
  records (`wtmp`, `utmp`, `btmp`) and audit logs, and Chrome and Firefox
  history databases. Every one of them is read back in the test suite — by
  `debug/pe`, `archive/zip`, `image/png`, `image/jpeg`, a box walk, SQLite,
  Windows' own shell, event log reader, registry and decompressor, util-linux
  and third-party parsers — and fsagen refuses the formats it cannot build
  rather than writing random bytes under a name that promises one (see _File
  formats_)
- Real RFC 5322 email: MIME multipart, threading headers, base64 attachments,
  `.eml` and `.mbox`
- Real PDFs from Markdown, with full control of document metadata
- Real `$ANSIBLE_VAULT;1.1;AES256` files that `ansible-vault` can decrypt
- `archive` zips what the scenario staged, and `edit` cuts lines back out of a
  log
- All four timestamps (access, modification, change, creation) taken from the
  scenario on Windows NTFS, access and modification elsewhere; set, then settled
  and verified after the last operation (see _Timestamps_)
- Forensic timelines in The Sleuth Kit's bodyfile, a mactime-style MACB listing,
  CSV, JSON lines, Timesketch JSON lines and text, with four times per entry
  and every NTFS stream;
  observed (read back from disk) or modelled (what the scenario intends, deleted
  files included, byte-identical on every run)
- A ledger of every operation and an answer key of what a tool should find,
  beside the output
- `fsagen diff-oracle` scores what a forensic tool reports (a Sleuth Kit
  bodyfile, Plaso's l2tcsv, dynamic CSV or JSON lines) against what the run
  made: names, deleted entries, streams, times, digests, links and NTFS
  `$FILE_NAME` times, with precision, recall and F1 per category and a JSON
  scorecard
- Disk images built byte by byte, in a raw or VHD disk: FAT32 with Windows'
  short names and deleted entries left where Windows leaves them; ext4 laid
  out as mke2fs lays it out, byte for byte, with nanosecond times, links,
  and deletes that wipe what Linux wipes; NTFS laid out as mkntfs lays it
  out, byte for byte, with 100 ns times, streams, links, slack, the
  `$FILE_NAME` times a timestomp sets, and deleted records and index entries
  left whole, as Windows leaves them. Every piece of residue is in the
  answer key. Read
  back by go-diskfs, go-ext4, go-ntfs, 7-Zip, `fsck.vfat`, `e2fsck`, ntfs-3g
  and The Sleuth Kit (see _Disk images_)
- ATT&CK technique tags (`mitre:`) on any action or step, carried into the
  ledger and answer key and written as an ATT&CK Navigator layer; tagging an
  action never changes a byte it writes
- Octal file permissions
- Windows-specific: NTFS ADS and Mark-of-the-Web (MoTW)

## Install

**Download a release.** Pick your platform from the
[latest release](https://github.com/aoiflux/fsagen/releases/latest), then verify
it before use:

```sh
sha256sum -c SHA256SUMS
```

| Platform | Asset                                                         |
| -------- | ------------------------------------------------------------- |
| Windows  | `fsagen_<version>_windows_amd64.exe`, `..._windows_arm64.exe` |
| Linux    | `fsagen_<version>_linux_amd64`, `..._linux_arm64`             |
| macOS    | `fsagen_<version>_darwin_amd64`, `..._darwin_arm64`           |

**Or install with Go** (1.26 or newer):

```sh
go install github.com/aoiflux/fsagen@latest
```

**Or build from source.** Pure Go — `CGO_ENABLED=0` works on Windows, Linux,
macOS and FreeBSD:

```sh
go build -o fsagen .
```

To build every released binary at once, with checksums, run the release script
for your shell with the version to build. Both write to `dist/` and produce the
same `SHA256SUMS` for the same version and toolchain:

```sh
./build.sh v0.2.0       # POSIX
.\build.ps1 v0.2.0      # Windows
```

```text
dist/
├── fsagen_<version>_windows_amd64.exe
├── fsagen_<version>_windows_arm64.exe
├── fsagen_<version>_linux_amd64
├── fsagen_<version>_linux_arm64
├── fsagen_<version>_darwin_amd64
├── fsagen_<version>_darwin_arm64
└── SHA256SUMS
```

`<version>` is the version you passed. It names every file and is stamped into
the binaries, so `fsagen --version` reports it too — the build fails if it does
not. Leave it out and both scripts fall back to `git describe`
(`v0.1.0-2-gda99bb6` two commits after a tag), which is what a test build wants;
a release should be built from its tag, and the scripts say so when it is not.

Both scripts produce release builds: `-trimpath` keeps the build host's paths
out, and `-s -w` drop the symbol table and DWARF, which is about a third of the
size. A panic still names its functions, files and lines — those come from the
pclntab, not from either section stripped — so only a debugger loses anything.
Go has no optimisation level to raise; `go build` always optimises. For a
debuggable binary use the plain `go build` above.

Released under the MIT License (see `LICENSE`).

## Quick start

```sh
# 1. Check a scenario, and see exactly what it would do — nothing is written
fsagen --playbook examples/playbook-basic.yaml --validate
fsagen --playbook examples/playbook-basic.yaml --dry-run

# 2. Generate it, with a Sleuth Kit bodyfile timeline
fsagen --seed 42 --playbook examples/playbook-basic.yaml \
       --timeline case.body ./crime-scene

# 3. Confirm the corpus is intact, and see what a tool should find
cd crime-scene && sha256sum -c ../crime-scene.fsagen/SHA256SUMS
cat ../crime-scene.fsagen/answer-key.jsonl

# 4. Score what a tool found (here The Sleuth Kit, on an image of the scene)
fls -r -m / scene.img > fls.body
fsagen diff-oracle --meta ../crime-scene.fsagen fls.body
```

Sixteen worked examples ship in `examples/`, from a two-file scenario up to
ransomware, insider exfiltration and malware lifecycle playbooks.

## Usage

fsagen can generate artifacts using a manifest, a playbook, or the bulk
generator:

```pwsh
fsagen [OPTIONS] <output-path>
```

**Options:**

- `--seed N` - PRNG seed for deterministic generation (default: 1)
- `--manifest FILE` - Execute a YAML manifest (simple file operations)
- `--playbook FILE` - Execute a YAML playbook (complex modus operandi)
- `--bulk N` - Super-simple bulk generation: N items per level (no YAML)
- `--depth D` - Bulk generation depth (default: 1)
- `--bulk-start T` - Bulk generation: the RFC 3339 time the dates inside
  generated files count from (default `2021-01-01T00:00:00Z`)
- `--vars-file FILE` - YAML map of variables exposed to templates as
  `${VAR:name}`
- `--var k=v` - Set one template variable (repeatable; overrides `--vars-file`)
- `--validate` - Check the manifest or playbook and exit; nothing is written
- `--dry-run` - Print the compiled operations (resolved paths, times, content
  hashes) as JSON lines and exit
- `--clean` - Empty a non-empty output directory before generating
- `--into-existing` - Generate into a non-empty output directory, merging
  (recorded in the run manifest)
- `--on-unsupported fail|skip` - What to do with operations the platform cannot
  perform (default `fail`, before anything is written; `skip` generates the rest
  and records each skipped operation)
- `--allow-nonportable` - Allow paths that only work on some platforms (reserved
  device names, case-only differences, very long paths)
- `--allow-external-sources` - Allow `content_file`, email bodies and
  attachments from outside the YAML file's directory
- `--meta DIR` - Where to write `run-manifest.json`, `SHA256SUMS`,
  `ledger.jsonl`, `answer-key.jsonl` and `run-info.json` (default:
  `<output-path>.fsagen`, beside the output)
- `--timeline FILE` - Write a timeline of the output after generating; `FILE`
  must be outside the output directory
- `--timeline-format csv|txt|bodyfile|macb|jsonl|timesketch` - Timeline format
  (default: from the extension: `.csv`, `.txt`, `.bodyfile`, `.body`, `.macb`,
  `.jsonl`; any other extension is an error). `timesketch` is JSON lines too, so
  only the flag selects it

- `--timeline-source observed|modelled` - `observed` (default) reads the output
  back from disk; `modelled` writes what the scenario intends, including the
  objects it deleted, and is the same bytes on every run (needs `--manifest` or
  `--playbook`). See _Forensic timelines_
- `--hash-limit N` - Observed timeline: leave out the MD5 of files and streams
  larger than N bytes (default: hash everything)
- `--generate-schema` - Write JSON schemas for manifests and playbooks and exit
  (`--schema-out DIR`, default `schemas`)
- `--version` - Print the module version, generator version and build

**Exit status:** 0 success, 1 generation failed, 2 command-line error.
Diagnostics go to stderr.

`fsagen diff-oracle --meta DIR [OPTIONS] <tool-output>` scores a forensic
tool's report of the output instead of generating; see _Scoring a tool_. It is
a subcommand only as the first argument, so an output directory named
`diff-oracle` is written `./diff-oracle`.

**Output directory:** must be a directory or not exist. A non-empty one is
refused unless `--clean` or `--into-existing` is given.

**Run records:** every generation writes its records _beside_ the output, never
inside it, so the corpus is only ever what the scenario asked for:

```text
corpus/                    the artefacts, and nothing else
corpus.fsagen/             (or wherever --meta points)
├── run-manifest.json      seed, SHA-256 of every input, options, platform
│                          capabilities, skipped ops, dropped time fields
├── SHA256SUMS             every file and NTFS stream, as path:stream
├── ledger.jsonl           one line per operation, before/after hashes
├── answer-key.jsonl       what a tool should find, one fact per line
├── mitre-layer.json       ATT&CK Navigator layer (only when something is tagged)
└── run-info.json          the part that cannot be reproducible
```

- `run-manifest.json`: generator version, Go version, seed, SHA-256 of every
  input read, options, capabilities (which times can be set, whether
  `$FILE_NAME` times are, how far slack is kept and the cluster size, and which
  links can be made), skipped
  operations and dropped time fields, the digests of `SHA256SUMS`,
  `ledger.jsonl` and `answer-key.jsonl`, the timeline written after the run (its
  source and format, and for a modelled one its digest), and a status that reads
  `running` until the run ends and then `complete` or `failed`. A tree whose run
  manifest does not say `complete` is not a finished corpus. It holds no
  absolute path, host name or wall-clock time, so it is itself reproducible.
- `SHA256SUMS`: the SHA-256 of every file and NTFS stream in the output
  (`path:stream`), in `sha256sum` format, sorted by path; every name of a
  hard-linked file, and no link. Check a corpus with
  `sha256sum -c` from inside the output directory.
- `ledger.jsonl` (manifest and playbook runs): one line per operation: the
  object it acted on (a number that survives renames; for a rotate, also the
  object it moved aside), its kind (and a link's `target`), its content SHA-256 before and after (and
  MD5 after), its size and streams, the stream an `ads` or `motw` wrote, the
  times the scenario intends it to have, which of them the operation stated
  itself (`explicit`), which were left to the file system (`uncontrolled`), and
  whether it was done, a no-op or skipped; `links` counts the names of a
  hard-linked file. A failed run still writes the ledger up to the failing
  operation.
- `answer-key.jsonl` (complete manifest and playbook runs): what a tool
  examining the output should find, derived from the ledger and the model, one
  fact per line: each object `created` or `modified` (content, with its size,
  SHA-256 and MD5), `renamed` (with
  `from`), `deleted`, `stomped` (a `mace` or `timestomp`, with the fields it
  set; a `timestomp`'s also gives the `$FILE_NAME` times — see _Timestomp_), each named
  `stream` written, each name a file is `linked` under, each name `unlinked`
  from a file that keeps another (see _Links_), and each object that ends with
  an `mtime_before_crtime` (a copy has one without being stomped, as copies
  do). A symlink or junction is `created` with its `target`. Directories made only as
  missing parents are not listed as created. `TestAnswerKeyEntries` checks every
  kind of fact. A fact from a tagged operation carries its `mitre`
  techniques.
- `mitre-layer.json` (runs with at least one tagged operation that ran): an
  ATT&CK Navigator layer (format 4.5, `enterprise-attack`) scoring each
  technique by how many operations exhibit it, with the ledger numbers and
  paths behind each score; see _ATT&CK tags_. Its digest is recorded in the run
  manifest. A rerun with no tags removes a layer an earlier run left there.
- `run-info.json`: what is not reproducible: build revision, host, OS, file
  system, the host's last-access-time policy, absolute paths and start and
  finish times.

**Examples:**

Check a playbook, then see exactly what it would do:

```pwsh
fsagen --playbook examples/playbook-basic.yaml --validate
fsagen --playbook examples/playbook-basic.yaml --dry-run
```

Regenerate the JSON schemas in `schemas/` (they document the input format for
editors; fsagen validates its input itself):

```pwsh
fsagen --generate-schema
```

Simple bulk generation with manifest:

```pwsh
fsagen --seed 42 --manifest examples/manifest-bulk-simple.yaml ./output
```

Complex adversary simulation with playbook:

```pwsh
fsagen --seed 100 --playbook examples/playbook-adversary-data-theft.yaml ./crime-scene
```

Generate artifacts with a Sleuth Kit bodyfile timeline:

```pwsh
fsagen --seed 42 --playbook examples/playbook-comprehensive-ransomware.yaml --timeline timeline.body ./output
```

Quick synthetic corpus with bulk generator (no YAML):

```pwsh
fsagen --seed 7 --bulk 3 --depth 2 ./quick-bulk
```

## Manifest schema

YAML with an optional `start` and a sequence of operations:

- start (top level, optional): RFC 3339, or `now` for a run that cannot be
  reproduced. It is the reference time for operations without an `mtime` or
  `atime`: when they happen (see _Timestamps_), what `${DATE}` formats and what
  an unpinned pdf's dates and an email's `Date` default to. With neither, those
  are errors; fsagen never reads the wall clock for them.

**What to do, and where**

| Field          | Meaning                                                                                                                              |
| -------------- | ------------------------------------------------------------------------------------------------------------------------------------ |
| `action`       | `create` `update` `append` `edit` `truncate` `rotate` `delete` `mace` `timestomp` `rename` `copy` `archive` `ads` `motw` `email` `ansible-vault` `hardlink` `symlink` `junction` |
| `path`         | target path relative to the output root (see _Paths_ below)                                                                          |
| `id`           | name for what this action creates or renames, so a later action can refer to it                                                      |
| `ref` / `refs` | instead of `path`, act on the one path (`ref`) or every path (`refs`) created under an `id` that still exists; ids follow renames    |
| `new_path`     | new location for `rename`, `rotate` or `copy`, or the new name a `hardlink` gives a file                                             |
| `target`       | what a `symlink` or `junction` points at — see _Links_                                                                               |
| `type`         | `file` or `dir` (for `create`)                                                                                                       |
| `ext`          | file extension to append if `path` has no extension                                                                                  |
| `missing_ok`   | for `delete`, a path that does not exist is a recorded no-op instead of an error                                                     |
| `mitre`        | ATT&CK technique IDs the action exhibits (`[T1070.006, T1564.004]`); any action takes it, and it changes nothing written — see _ATT&CK tags_ |

**Content**

| Field          | Meaning                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| -------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `content`      | literal content (optional); `content: ''` writes an empty file                                                                                                                                                                                                                                                                                                                                                                                |
| `content_file` | load content from a file inside the manifest's directory (optional)                                                                                                                                                                                                                                                                                                                                                                           |
| `content_len`  | how much deterministic filler the file carries, at least 1. With no content of any kind the default is 1024 characters (256 for `append`, 128 for `ads`). For a structured format it is the size of the _filler region_, not of the file: the PE overlay, the zip member, the PNG chunk, the JPEG comments, the MP4 `mdat`, the PDF or Word document's text, a workbook's one cell (see _File formats_). A structured format with no `content_len` gets the smallest valid file |
| `content_kind` | what invented bytes look like — `text` (the default: base32), `bytes` (uniform random), `zeros`, `pattern` (a counting ramp) or `lorem` (words). It only applies to bytes fsagen invents, so giving it beside `content`, `content_file` or `template` is an error                                                                                                                                                                             |
| `render`       | run `${...}` substitution over the content. Defaults to `true` for inline `content` and `false` for `content_file`, because scripts and PEM keys contain `${...}` sequences of their own that must survive verbatim                                                                                                                                                                                                                           |
| `mode`         | octal file permissions, e.g. `"0600"` (default 0644 files, 0755 directories)                                                                                                                                                                                                                                                                                                                                                                  |
| `format`       | what to build — `raw` (default) or `text` writes the content through; `pdf`, `docx`, `docm`, `xlsx`, `xlsm`, `pe`, `zip`, `png`, `jpeg`, `mp4`, `lnk`, `prefetch`, `evtx`, `regf`, `utmp`, `auditd`, `chrome_history` and `firefox_places` build a file of that type. With no `format` and no content of its own, the extension picks one (see _File formats_). For the `email` action, `eml` or `mbox`                                                                                                                    |

**Typed blocks** — each belongs to one `format` or action, and is an error
beside any other

| Field     | Meaning                                                                                                          |
| --------- | ---------------------------------------------------------------------------------------------------------------- |
| `pdf`     | document metadata for `format: pdf` — see _`format: pdf`_                                                        |
| `docx`    | `title`, `author`, `created`, `modified` for `format: docx` or `docm`                                            |
| `xlsx`    | the same, for `format: xlsx` or `xlsm`                                                                           |
| `vba`     | the inert macro of `format: docm` or `xlsm`: its entry point, module and marker — see _`vba:`_                   |
| `pe`      | machine, subsystem, dll, timestamp, sections, imports and version resource for `format: pe` — see _File formats_ |
| `history` | `visits` and (Chrome) `downloads` for `format: chrome_history` or `firefox_places` — see _File formats_          |
| `lnk`     | the target and what the link records about it, for `format: lnk` — see _`lnk:`_                                  |
| `prefetch` | the program, its runs and what it loaded, for `format: prefetch` — see _`prefetch:`_                            |
| `evtx`    | the channel, computer and events, for `format: evtx` — see _`evtx:`_                                              |
| `registry` | keys, values, Run entries, UserAssist and USB devices, for `format: regf` — see _`registry:`_                   |
| `utmp`    | login, logout, boot, shutdown and failed-login records, for `format: utmp` — see _`utmp:` and `auditd:`_          |
| `auditd`  | executions and logins, for `format: auditd` — see _`utmp:` and `auditd:`_                                         |
| `slack`   | bytes left past the end of the file, in the rest of its last cluster (`create`, `update`) — see _Slack_         |
| `archive` | what goes into the `archive` action's zip — see _File formats_                                                   |
| `edit`    | the changes the `edit` action makes — see _File formats_                                                         |
| `email`   | message definition for the `email` action — see _`email` action_                                                 |
| `vault`   | password, vault_id and salt for the `ansible-vault` action                                                       |

**Times and Windows-only fields**

| Field                                 | Meaning                                                                                                                                                                                                                                                                                                                                       |
| ------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `atime` `mtime` `ctime` `crtime`      | RFC 3339 access, modification, change and creation (birth) times, fractions of a second kept. They override what the action would otherwise set (see _Timestamps_). `ctime` needs Windows on NTFS or ReFS and `crtime` Windows; elsewhere either is a pre-flight error unless `--on-unsupported=skip`, which drops the field and records that |
| `stream`                              | ADS stream name (for the `ads` action, Windows-only)                                                                                                                                                                                                                                                                                          |
| `zone_id`, `host_url`, `referrer_url` | for the `motw` action (Windows-only)                                                                                                                                                                                                                                                                                                          |

A manifest may also carry a top-level `variables:` map.

**Input is strict.** fsagen refuses to generate anything from an input it would
have to guess about, and says where the problem is (file, line and column, the
operation or step/action, and the field). All of these are errors:

- an unknown or duplicated key, or a key the action does not use (for example
  `stream` on `create`, or times on `rename`, which keeps a file's times)
- a time that is not RFC 3339, a malformed or negative duration, `zone_id`
  outside 0-4, an invalid `mode`, `content_len` below 1
- an undefined `${VAR:name}`, an unknown or unterminated `${...}` token (write
  `$${` for a literal `${`)
- `delete` of a path that does not exist (unless `missing_ok: true`), `update`
  or `truncate` of a missing file (use `create`), `ads`/`motw` on a missing
  file, `rename`/`copy`/`rotate` onto a path that already exists, deleting a
  non-empty directory. `append` creates a missing file, as a log comes into
  being.
- random content (`content_len`, or no content at all) under an extension that
  promises a format fsagen cannot build: `.pptx`, `.gif`, `.bmp`,
  `.mov`, `.sqlite`, `.db`, `.eml`, `.mbox`, and `.pdf` without `format: pdf`.
  The error says what the extension promises and what to use instead
  (`action: email` for a message, `format: chrome_history` for a profile). Add
  `format: text` to write placeholder text on purpose, or give
  `content`/`content_file`. An extension fsagen _can_ build gets a real file of
  that type instead of an error (see _File formats_).
- a typed block beside the wrong format (`pe:` with `format: docx`), or
  `content`, `content_file`, `template` or `render` beside a format that builds
  the file itself
- an operation the platform cannot perform (`ads`/`motw` off NTFS), unless
  `--on-unsupported=skip`

**Paths** use `/` on every platform and are relative to the output root (and to
the actor's `base` in playbooks). A trailing `/` means a directory. `..` is
allowed only while it stays inside the root. Backslashes, `:` (drive letters,
stream syntax), absolute paths, NUL and names ending in a dot or space are
refused everywhere. Unless `--allow-nonportable` is given, so are reserved
Windows device names (`CON`, `NUL`, `COM1.log`, ...), two paths that differ only
by case or Unicode normalisation, and paths over 200 characters.

Files read by a scenario (`content_file`, `body_text_file`, `body_html_file`,
`attachments[].source_file`) must lie inside the directory of the YAML that
names them, unless `--allow-external-sources` is given;
`attachments[].source_root` must name a file already generated in the output.

**Examples:**

- `examples/manifest-basic.yaml` - Basic create/update/delete operations
- `examples/manifest-bulk-simple.yaml` - Many files of every type fsagen can
  build, in one manifest
- `examples/manifest-history.yaml` - Chrome and Firefox history databases, each
  in its own epoch

## Playbook schema

YAML with a timeline and actors:

- **start** (required): RFC3339, or "now" for a run that cannot be reproduced
  (recorded as such in the run manifest)
- **variables**: Global variables for templating (map of key-value pairs)
- **subsecond_jitter**: `true` adds a seeded fraction of a second (in 100 ns
  steps) to every time derived from the schedule, so a corpus does not have
  every timestamp on a whole second. Explicit times are never jittered, and the
  same seed gives the same fractions
  (`TestJitterDeterministicAndNeverOnExplicit`)
- **actors**: List of { name, base, variables }
  - name: Actor identifier (unique, case-insensitively)
  - base: Base directory for this actor's files
  - variables: Actor-specific variables (override global variables)
- **steps**: Timeline steps
  - actor: Actor name
  - offset: time.Duration from start for first occurrence (e.g., 5m, 2h)
  - every: Repeat interval; required when `repeat` is above 1 (`every: 0s`
    stacks the occurrences on one instant on purpose)
  - repeat: Number of occurrences (default 1)
  - condition: Step-level conditional execution (`odd`, `even`, `first`,
    `last`), tested against the iteration index
  - batch_count: Generate N files in this step (multiplies actions)
  - mitre: ATT&CK technique IDs every action in the step exhibits, on top of
    each action's own (see _ATT&CK tags_)
  - actions: List of operations with extras:
    - offset: time.Duration relative to the step occurrence
    - condition: Action-level conditional execution, tested against the batch
      index
    - template: Predefined content template (`email`, `log`, `script`, `doc`)
      for create/update/append; cannot be combined with `content` or
      `content_file`
    - All standard manifest fields (action, path, id, ref, content, etc.)

Operations run in time order; operations scheduled for the same instant keep the
order they are written in (`TestPlaybookRunsInTimeOrder`). `${SEQ}` counts every
action in the order it is written, so two actions rendering `file-${SEQ}.txt`
name two different files: give the first an `id` and refer to it with
`ref`/`refs`.

Operations supported:
`create|update|append|edit|truncate|rotate|delete|mace|timestomp|rename|copy|archive|ads|motw|email|ansible-vault|hardlink|symlink|junction`
(all operations work in both manifest and playbook). `ads` and `motw` are
Windows-only. Each action happens at its scheduled time, which sets the times of
what it creates or changes (see _Timestamps_); explicit
`atime`/`mtime`/`ctime`/`crtime` override them.

Durations accept `d` and `w` in addition to Go's own units, so a step can be
`offset: 2d6h` rather than `54h`.

**Playbook templating:**

- `${SEQ}` - Monotonic sequence counter
- `${RND:N}` or `${RANDOM:N}` - Deterministic random string of length N (N at
  least 1)
- `${DATE:layout}` - The action's scheduled time (in a manifest, the operation's
  `mtime`, else the manifest's `start`; with neither it is an error) formatted
  with a Go layout (e.g., `${DATE:2006-01-02T15:04:05Z07:00}`)
- `${ACTOR}` - Current actor name (playbooks only)
- `${VAR:name}` - Variable substitution (from global or actor-specific
  variables); undefined names are errors
- `${UUID}` - Deterministic random version-4 UUID
- `${IP}` - Deterministic IP address (192.168.x.x range)
- `${IP:cidr}` - Deterministic address inside a block, e.g. `${IP:10.10.0.0/16}`
  or `${IP:2001:db8::/32}`. IPv4 blocks with room to spare leave out the network
  and broadcast addresses (`TestIPStaysInCIDR`)
- `${HASH:N}` - Deterministic lowercase hex string of length N
- `${BATCH}` - Current batch index (when using batch_count)
- `${ITER}` - Current iteration index (when using repeat)

**Advanced Playbook Features:**

1. **Variables**: Define reusable values at global and actor scope

```yaml
variables:
  campaign_id: "OP-2024-001"
  target_org: "ACME Corp"
actors:
  - name: attacker
    base: users/victim/Downloads
    variables:
      ip_addr: "192.0.2.42"
```

2. **Conditional Execution**: Control when steps/actions run

```yaml
steps:
  - actor: malware
    repeat: 10
    condition: even # Only runs on even iterations (0, 2, 4, ...)
    actions:
      - action: create
        path: file-${ITER}.txt
        condition: odd # Further filtering at action level
```

3. **Batch Operations**: Generate multiple files in one step

```yaml
steps:
  - actor: ransomware
    batch_count: 100 # Creates 100 files
    actions:
      - action: create
        path: encrypted-${BATCH}.locked
        content_len: 2048
```

4. **Content Templates**: Use predefined realistic content

```yaml
actions:
  - action: create
    path: message.eml
    template: email # a real RFC 5322 message; the email action gives full control
```

Available templates: `email`, `log`, `script`, `doc`

**Example playbooks:**

- `examples/playbook-basic.yaml` - Simple two-actor workflow
- `examples/playbook-adversary-data-theft.yaml` - Stages documents, zips them,
  writes exfil logs, backdates
- `examples/playbook-browsing.yaml` - Two users browsing, one Chrome profile and
  one Firefox
- `examples/playbook-log-tampering.yaml` - Creates baseline logs, injects
  tampered entries, backdates, then cuts the injected lines out with `edit`
- `examples/playbook-persistence-artifacts.yaml` - Drops startup-like files and
  .reg exports
- `examples/playbook-email-and-archive.yaml` - Real messages and JPEGs, a real
  zip of both by id, then deletes the originals
- `examples/playbook-log-rotate-and-truncate.yaml` - Demonstrates log rotation
  and truncation
- `examples/playbook-windows-ads-motw.yaml` - Adds NTFS ADS and Mark-of-the-Web
  (Windows-only)
- `examples/playbook-macro-phish.yaml` - A macro-enabled invoice (`.docm`, its
  macro inert), a payload whose times are stomped with `timestomp`, a hard link
  hiding a second name for it, and an `.xlsx`
- `examples/playbook-email-thread.yaml` - Four-message RFC 5322 thread as `.eml`
  and `.mbox`, with a generated PDF attachment
- `examples/playbook-comprehensive-ransomware.yaml` - **Advanced**: Full
  ransomware attack with variables, batching, conditions, and templates
- `examples/playbook-insider-threat-exfil.yaml` - **Advanced**: 7-day insider
  threat scenario with repeated access patterns
- `examples/playbook-malware-lifecycle.yaml` - **Advanced**: 48-hour malware
  infection lifecycle: a PE dropper with imports and a version resource,
  beaconing, lateral-movement logs named from `${IP:10.10.0.0/16}`, and
  anti-forensics

`examples/INVESTIGATION_WORKFLOW.md` walks that last one end to end — generate,
timeline, `mactime`, and what the answer key says a tool should find.

## Email, PDF and Ansible vault

### `email` action

Builds a real RFC 5322 message: CRLF throughout, quoted-printable bodies, base64
attachments, and a MIME shape chosen to fit the content (`multipart/mixed`
wrapping a `multipart/alternative` when there are both bodies and attachments).
Writes a `.eml`, or appends to a `.mbox` with mboxrd `>From` escaping.

```yaml
- action: email
  path: Users/priyan/Mail/Inbox/0003.eml
  format: eml # or mbox (appends); inferred from the extension
  email:
    from: "Dana Reyes <d.reyes@aperture-talent.example>"
    to: ["Priyan N <priyan.nair@northwindlogistics.example>"]
    cc: ["scheduling@aperture-talent.example"]
    return_path: "bounces+0188@aperture-talent.example"
    subject: "Re: technical assessment"
    date: "2026-02-25T10:05:00+05:30" # RFC3339; also the file's times
    message_id: "<c3f1a97b@aperture-talent.example>"
    in_reply_to: "<b2e0d8f1@northwindlogistics.example>"
    references: [
      "<CAF9a2c1e@aperture-talent.example>",
      "<b2e0d8f1@northwindlogistics.example>",
    ]
    headers: # an ordered LIST, so Received: can repeat
      - name: Received
        value: "from mx01... ; Wed, 25 Feb 2026 10:05:14 +0530"
      - name: Authentication-Results
        value: "spf=pass; dkim=pass; dmarc=pass"
    body_text_file: content/msg-03.txt
    body_html_file: content/msg-03.html
    attachments:
      - source_file: content/brief.pdf # inside the manifest/playbook's directory
        name: "Technical_Assessment_Brief.pdf"
      - source_root: reports/review.pdf # a file an earlier step generated in
      # the output root
      - ref: quarterly # the one live path under that id,
# whatever it was named
```

Every field:

| Field                                     | Meaning                                                                                                                                                                         |
| ----------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `from`                                    | the sender; one address, with or without a display name                                                                                                                         |
| `to`, `cc`, `bcc`                         | lists of addresses; `bcc` is written into the file, as a message in a sender's own mailbox has it                                                                               |
| `reply_to`, `return_path`                 | `Reply-To:` and `Return-Path:`                                                                                                                                                  |
| `subject`                                 | `Subject:`; non-ASCII is encoded-word wrapped                                                                                                                                   |
| `date`                                    | RFC3339 in, RFC 5322 out, and the file's times; defaults to the scheduled time                                                                                                  |
| `message_id`, `in_reply_to`, `references` | the threading headers; each is written only when given, so a thread that needs `Message-ID:` states it (`template: email` draws one from the operation's random stream instead) |
| `headers`                                 | an ordered list of `{name, value}` written before everything else                                                                                                               |
| `body_text`, `body_html`                  | the bodies, inline                                                                                                                                                              |
| `body_text_file`, `body_html_file`        | the same, read from a file beside the YAML                                                                                                                                      |
| `attachments`                             | see below                                                                                                                                                                       |

An attachment names its bytes in one of four ways, exactly one per entry:
`source_file` (beside the YAML), `source_root` (a path in the output root an
earlier step wrote), `ref` (the one live path under an id, whatever it ended up
being called), or `content` (inline literal). `name` is the filename the
recipient sees, `content_type` overrides the type guessed from that name,
`disposition` is `attachment` (the default) or `inline`, and `content_id` gives
an inline part the `Content-ID:` an HTML body refers to with `cid:`. Every one
of these fields is checked in `TestEveryDocumentedFieldIsWritten`.

Author-supplied `headers` are emitted first, in order, then the structured
fields — so a `Received:` chain and `Authentication-Results` land where a real
MTA would have written them. A header value that already contains newlines keeps
the author's folding.

MIME boundaries are drawn from the operation's own random stream, so `--seed`
reproducibility holds across the message body too. A message with no `date` is
dated at its scheduled time (in a manifest: its `mtime`, else `start`).

`examples/playbook-email-thread.yaml` is a worked four-message thread using all
of the above.

### `format: pdf`

Renders a Markdown subset (`#`/`##`/`###` headings, `-` bullets, `|a|b|` tables
with wrapping cells and repeating headers, ``` fenced blocks, `---` rules) into
a paginated PDF, with full control of the document metadata.

```yaml
- action: create
  path: reports/configuration-review.pdf
  format: pdf
  content_file: content/report.md
  render: true
  pdf:
    title: "Configuration Review"
    author: "svc-agent@example.local"
    subject: "Automated assessment"
    keywords: "secrets; review"
    creator: "SentinelIQ Threat Agent 2.1.4"
    producer: "SentinelIQ Report Engine 2.1.4"
    created: "2026-03-14T02:33:12+05:30" # RFC3339; pin these for
    modified: "2026-03-14T02:33:12+05:30" # byte-identical output
    page_size: A4 # A4 (default), A3, A5, Letter
```

Inline markers are **not** interpreted or stripped. A report body carrying
`Wint3r-R0t****-2026` keeps its asterisks; silently rewriting a redaction mask
into something that reads like a real password would be worse than showing a
literal asterisk.

Unpinned dates default to the action's scheduled time (in a manifest: its
`mtime`, else `start`), and one given date stands in for the other, so two
renders of the same input always produce byte-identical files. That is what lets
one artifact be attached to a message and land with the same SHA256 as its copy
on disk.

### `ansible-vault` action

Produces a genuine `$ANSIBLE_VAULT;1.1;AES256` payload — PBKDF2-HMAC-SHA256
(10,000 iterations), AES-256-CTR, HMAC-SHA256 — that the real `ansible-vault`
decrypts.

```yaml
- action: ansible-vault
  path: infra/group_vars/prod/vault.yml
  content_file: content/vault-plaintext.yml
  mode: "0640"
  vault:
    password: "${VAR:vault_password}"
    vault_id: "" # non-empty selects the 1.2 header form
    salt: "" # optional 32-byte hex; when empty it comes from the seed
```

```bash
printf '%s' 'the-password' > /tmp/vpw
ansible-vault view --vault-password-file /tmp/vpw out/infra/group_vars/prod/vault.yml
```

## ATT&CK tags

Any manifest operation, playbook action or playbook step can say which ATT&CK
techniques it exhibits:

```yaml
steps:
  - actor: attacker
    offset: 2h
    mitre: [T1070.004] # every action in the step
    actions:
      - action: mace
        path: var/log/app.jsonl
        mtime: "2021-06-15T12:00:00Z"
        mitre: [T1070.006] # this action too
      - action: delete
        path: var/log/app.jsonl
```

- An action exhibits its step's techniques and its own, sorted, each once.
- Each ID must look like `T1234` or `T1234.001`. fsagen carries no copy of the
  ATT&CK catalogue, so it checks the shape, not that ATT&CK defines the ID. An
  empty list or the same ID twice in one list is an error
  (`TestMitreValidation`).
- Tags annotate; they never change what is written. An action without an `id`
  takes its random key from a hash of its own YAML, and `mitre` is left out of
  that hash, so adding or removing tags moves no byte of the corpus
  (`TestMitreLeavesRandomKeyAlone`, `TestMitreLayerWritten`).
- The ledger, the answer key and the `--dry-run` listing carry each
  operation's techniques. `mitre-layer.json` in the run records directory is an
  ATT&CK Navigator layer built from the operations that ran: a skipped or no-op
  operation scores nothing, as it leaves no evidence. A tagged sub-technique
  whose parent is not tagged brings an unscored parent entry, so the layer
  opens with every tagged ID visible (`TestLayerContent`, `TestLayerGolden`).

## Timestomp

`timestomp` sets times the way anti-forensic tools do. Its `atime`, `mtime`,
`ctime` and `crtime` are the `$STANDARD_INFORMATION` times, which Explorer,
`dir` and `stat` show, and it sets them exactly as `mace` does. Its
`fn_atime`, `fn_mtime`, `fn_ctime` and `fn_crtime` are the `$FILE_NAME` times
beside them, which only a raw read of the MFT shows. It needs at least one of
the eight.

```yaml
- action: timestomp
  path: Users/victim/AppData/Local/Temp/payload.exe
  crtime: "2019-03-07T10:12:44Z"
  mtime: "2019-03-07T10:12:44Z"
  mitre: [T1070.006]
```

What a tool should find is in its `stomped` fact in the answer key:

- `times` and `fields`, as for `mace`: the `$STANDARD_INFORMATION` times
  afterwards and the ones the action set.
- `fn_times`: the `$FILE_NAME` times the scenario means, from the rules under
  _Timestamps_. A stomp of `$STANDARD_INFORMATION` alone leaves them at the
  times the file was born or last renamed.
- `fn_controlled`: whether `fn_times` are on disk. **On a live volume they never
  are**: Windows writes them itself, at the moment fsagen actually creates the
  file, and no call a program can make changes them. `fn_times` is then what
  the scenario intends, for comparison with what a tool reads, not a claim
  about the disk. Asking for an `fn_` time is a pre-flight error there; with
  `--on-unsupported=skip` the action sets the other times, its ledger entry
  lists the `fn_` fields as `uncontrolled`, and the run manifest records each
  one skipped (`TestFileNameTimesPreflight`, `TestTimestompOnLiveVolume`).
  **On an NTFS image they always are**: fsagen writes them into the record and
  the directory's index (see _Disk images_).
- `delta`: for each time, `$STANDARD_INFORMATION` minus `$FILE_NAME`, in
  seconds, written exactly (`-258454860`, `0.75`) so a stomp decades away keeps
  its 100-nanosecond ticks (`TestSecondsBetween`).
- `timestomp_detected`: whether the `$STANDARD_INFORMATION` creation time is
  earlier than the `$FILE_NAME` one, the comparison MFTECmd's `SI<FN` column
  makes (`TestTimestompFact`).

The fact describes the file as the stomp left it. A later `rename` copies the
stomped times into `$FILE_NAME`, as NTFS does, after which the two sets agree
and `SI<FN` sees nothing: the double-rename trick. The model follows it
(`TestFileNameTimeRules`), but only a `timestomp`'s own fact reports
`$FILE_NAME` times; on an NTFS image, a modelled timeline lists every name's
too. The ledger entry carries `fn_times` too, and so does the
`--dry-run` listing (`TestDryRunListsFileNameTimes`).

## Links

Three actions make links. fsagen writes each and **never follows one**:
nothing is written, read, copied or streamed through a link, no walk of the
output descends through one, and a time set on a link is the link's own.

```yaml
- action: hardlink # a second name for a file: same bytes, same times
  path: Users/victim/Desktop/payroll.xlsx
  new_path: Users/Public/Libraries/cache.dat
- action: symlink
  path: Users/victim/Desktop/notes # the link
  target: ../Documents/notes.txt # relative to the link's directory
- action: symlink
  path: tmp/shadow
  target: /etc/shadow # outside the output: written as given, never followed
  allow_external_target: true
- action: symlink
  path: staging/next
  target: ../exfil # not there yet; Windows records the type, so say it
  target_type: dir
- action: junction # Windows only
  path: Users/Public/Libraries/docs
  target: Users/victim/Documents # a directory in the output, written as path is
```

- `hardlink` takes `path` (or `ref`) and `new_path`. Only a file can be
  hard-linked. It is one object under two names: an update through either is
  seen through both, the file's change time moves as its link count does,
  and each name keeps its own `$FILE_NAME` times, the new one written with
  the file's times at that moment. Deleting a name the file is not left
  without only unlinks it; the file goes with its last name.
- `symlink` takes `path`, `target`, `target_type` and `allow_external_target`.
  A target relative to the link's directory that stays inside the output is
  checked and stored as written, and may be dangling. Any other target (an
  absolute path, a drive, a share, or a relative one that climbs out) needs
  `allow_external_target: true`. `target_type` (`file` or `dir`) defaults to
  what the target is, and a file where it is not there; on Windows it decides
  whether the link is a directory link, which fsagen writes itself, as
  `CreateSymbolicLinkW` writes it, rather than letting the target decide.
- `junction` takes `path` and `target`, a directory that exists in the output
  by then. Windows stores a junction's target as an absolute path, so it
  names the directory wherever the output is; fsagen writes the reparse data
  exactly as `mklink /J` does (`TestWindowsLinksAsWindowsMakesThem`).
- `mace`, `timestomp`, `rename` and `delete` act on a link itself. `update`,
  `append`, `edit`, `truncate`, `copy`, `rotate`, `ads`, `motw`, a typed
  create over a link, or a path through one are compile errors.
- A link this platform or volume cannot make stops the run, with
  `--on-unsupported=skip` too: later actions, and the settle pass, would act
  on a name that is not there. Symlinks on Windows need Developer Mode or the
  privilege, tried once in a temporary directory.

What it leaves:

- SHA256SUMS lists every name of a hard-linked file, and leaves links out
  (they have no content of their own); `outputs.links` in the run manifest
  counts them.
- The ledger's `kind` is `symlink` or `junction` with its `target`, and
  `links` counts a hard-linked file's names. The answer key says `linked`
  (with `from`), `unlinked`, or `created` with the link's `target`.
- A modelled timeline has an entry for each name of a hard-linked file, with
  `links`, and names a link `path -> target`, as The Sleuth Kit does. An
  observed one reads both kinds back as links with their targets (a junction
  pointing into the output as a path in it), and never hashes or descends
  through one.
- `--into-existing` seeds links as links and a hard-linked file's names as
  one object, so a run into such a tree unlinks rather than deletes, and
  refuses to write through a link it finds (`TestIntoExistingSeedsLinks`).
- Loops (two symlinks pointing at each other, one pointing at its own
  directory, a junction inside the directory it names) are written and every
  walk ends (`TestLinkLoopsTerminate`).

`TestHardLinksEndToEnd`, `TestSymlinksEndToEnd`, `TestLinkRules` and
`TestLinkSimulation` cover the rest; all of them run on Windows 11 and Linux.

## Slack

A `create` or `update` can leave bytes in the file's **slack** — between the
end of its content and the end of its last cluster — where no read of the file
sees them and a carver reading the volume does:

```yaml
- action: create
  id: secret
  path: Users/u/secret.txt
  content: "account 4417, PIN 2208"
- action: create
  path: Users/u/notes.txt
  content_len: 5000
  slack:
    cluster_size: 4096 # the default; on a live volume it must be the volume's
    kind: canary # canary (default), pattern or fragment
- action: create
  path: Users/u/draft.txt
  content_len: 9000
  slack: { kind: fragment, fragment_of: secret } # the start of another file
```

- **canary** is `FSAGEN-SLACK:<object>:` (the ledger's object number), then
  seeded text, with the marker again at every 512-byte sector boundary;
  **pattern** is the marker repeated; **fragment** is the first bytes of the
  file `fragment_of` names (an `id` still present at that point), then zeros.
- The slack runs from the end of the content to the end of its cluster. The
  file must have content whose size is known before the run — filler or
  literal content, not a structured format — and that size must stop short of
  a cluster's end; an empty file has no cluster at all
  (`TestSlackRules`).
- The ledger and the answer key (a `slack` fact) record the kind, cluster
  size, offset, length and SHA-256 of what was written, and whether fsagen
  could verify it stayed (`TestSlackOnLiveNTFS`).

**Where it can be kept.** User-mode code cannot write into a cluster past the
end of a file; it can only write the file long, flush, and shrink it back,
and then it is up to the file system:

| Target              | Slack                                                                                                                                                                                                                                                                                                                                                                |
| ------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| live NTFS           | best effort, `verified: false`. NTFS leaves the rest of the last cluster alone when a file shrinks; Windows may zero the rest of the sector the file ends in, which is why the canary restarts at every sector. A file of 1 KiB or less is refused, as it may live inside its MFT record with no cluster at all, and so is a `cluster_size` that is not the volume's |
| live elsewhere      | refused: ext4 zeroes the tail of a block when a file shrinks, and tmpfs and btrfs keep no fixed cluster tail                                                                                                                                                                                                                                                         |
| FAT32 or ext4 image | exact, `verified: true`: fsagen writes the cluster itself. `cluster_size` must be the image's (`TestImageGolden`)                                                                                                                                                                                                                                                    |
| NTFS image          | exact, `verified: true`, as for FAT32 and ext4. A file of 1 KiB or less is refused, as on live NTFS                                                                                                                                                                                                                                                                  |

A refused slack fails the pre-flight, or with `--on-unsupported=skip` the file
is written without it and the run manifest records the dropped `slack` field
(`TestSlackPreflight`). `TestSlackSurvivesOnRawNTFS`, in the conformance
suite, reads the volume raw as an administrator through the file's own data
runs and finds the canary in the cluster.

## Disk images

Instead of an output directory, a run can write a **disk image** that fsagen
builds byte by byte, with no operating system in between:

```sh
fsagen --seed 42 --playbook adversary.yaml \
  --image case.vhd --image-fs fat32 --image-size 512M
fsagen --seed 42 --manifest scene.yaml \
  --image scene.img --image-fs ext4 --image-size 256M
fsagen --seed 42 --manifest scene.yaml \
  --image scene.vhd --image-fs ntfs --image-size 256M
```

Every byte of the image is fsagen's, so the same seed and input give the same
image on every platform, and what a delete or an overwrite leaves behind is
part of the answer key.

**The image.**
- `--image` names the file. `.raw`, `.dd` and `.img` are raw disks; `.vhd`
  is a fixed VHD, a raw disk followed by a 512-byte footer that Windows,
  Hyper-V, 7-Zip and qemu read.
- `--partition mbr` (the default) puts the file system in one partition 1
  MiB in, as Windows' and Linux's disk tools align it: type `0x0C` for
  FAT32, `0x83` for ext4, `0x07` for NTFS. `--partition none` writes the
  file system alone.
- `--image-size` takes bytes or `K`, `M`, `G`, `T` (powers of 1024). A VHD's
  disk is rounded down to a whole number of its cylinders, so the footer's
  size and its geometry agree.
- `--image-label` sets the volume label.
- The volume serial (FAT32's 32 bits, NTFS's 64) or UUID and directory
  hash seed (ext4), the disk signature, the VHD's ID and ext4's inode
  generation numbers are drawn from the seed. Nothing else in the run draws from that key, so writing
  into an image changes no file's bytes.
- `--image-time` (default `2021-01-01T00:00:00Z`) stamps what the file
  system creates before the scenario sets its times: FAT's label and `.` and
  `..` entries, ext4's root directory, lost+found and superblock, NTFS's
  system files and root, and the VHD footer. ext4 also stamps a delete with
  the operation's own time.
- The image is written to a temporary file beside it and takes its name only
  once the run has succeeded. An existing image is replaced only with
  `--clean`, and only then. `--into-existing` is refused.
- The run's records go to `<image>.fsagen`. `run-manifest.json` says
  `"target": "image"`, describes the image (`fs`, `format`, `partition`,
  `partition_offset`, `size`, `cluster_size`, `serial` or `uuid`, `alloc`)
  and gives its `image_sha256`.

**FAT32** (`--image-fs fat32`) is laid out as Windows formats and writes it:
- **Format.** A 32-sector reserved area holds the boot sector, FSInfo and
  their backups at sectors 6 and 7. Two FATs follow, sized by Microsoft's
  formula, then the root directory in cluster 2. Clusters default to Windows'
  size for the volume: 512 bytes up to 64 MiB, 4 KiB from 256 MiB to 8 GiB.
  `--cluster-size` overrides the default. A volume with fewer than 65,525
  clusters is refused, as FAT32 must have that many.
- **Names.** Every name that needs a long name gets one, and its short name
  is what Windows would generate: up to six characters, then `~1` to `~4`;
  from the fifth on, two characters, a four-digit checksum of the long name
  and `~1`. The checksum was checked against names Windows 11 generated
  itself (`TestShortNamesMatchWindows`). A name that is already 8.3 keeps
  its case in the entry's NTRes bits when each part is all one case, and
  takes a long name only when a part mixes cases.
- **Times** are in UTC. FAT stores the creation time to 10 ms, the write
  time to 2 seconds, the access date to the day, and no change time.
- **What a write leaves behind.**
  - A deleted name's entries are marked `0xE5` over their first byte; the
    rest, including the start cluster and size, stays. Its FAT chain is
    freed, and its content stays in the clusters.
  - A new name reuses the first run of free entries in its directory,
    deleted ones included, as Windows does.
  - A renamed object gets new entries, and its old ones are left deleted.
  - A file rewritten after it was truncated gets new clusters, and the old
    ones keep its old content.
  - The rest of the sector a file ends in is zeroed. The rest of its last
    cluster keeps whatever it held, which is how a previous file's bytes
    turn up in another file's slack.
- **Allocation.** `--alloc next-fit` (the default) searches on from the last
  allocation, as Windows does, so freed clusters survive until the volume
  wraps round. `--alloc first-fit` reuses them at once.

What FAT cannot hold is refused before anything is written
(`TestImageValidate`):
- streams, links and change times;
- a time before 1980 or after 2107;
- a name with a character Windows forbids in it;
- two names that differ only in case, even with `--allow-nonportable`.

**ext4** (`--image-fs ext4`) is laid out as mke2fs 1.47 formats it and
Linux writes it:
- **Format.** An empty volume is mke2fs's byte for byte, checksums
  included, given the same UUID, hash seed and time
  (`TestFormatMatchesMke2fs`, nine geometries from one group to eighteen).
  - The features are mke2fs's ext4 set less the journal, `64bit`,
    `resize_inode`, `dir_index`, `huge_file` and `ext_attr`: `filetype`,
    `extent`, `flex_bg`, `sparse_super`, `large_file`, `dir_nlink`,
    `extra_isize` and `metadata_csum`.
  - Blocks are 4 KiB (`--cluster-size` takes 1024, 2048 or 4096).
  - Inodes are 256 bytes, one per 4 KiB below 512 MiB and one per 16 KiB
    above, with 5% of blocks reserved.
  - Superblock and descriptor backups are in groups 0, 1 and the powers of
    3, 5 and 7. Each flex group's bitmaps and inode tables are packed at its
    start, and groups nothing has used yet are left uninitialised.
  - lost+found is ready with 16 KiB of entries.
  - Every superblock, descriptor, bitmap, inode, extent block and directory
    block carries its crc32c.
- **Names** are any bytes but `/` and NUL, up to 255 of them, and case
  matters. `lost+found` at the root is the file system's own, and is
  refused.
- **Times.** All four times are kept, to the nanosecond, from 1901-12-13 to
  2446-05-10. The change time is the scenario's too, as the executor stamps
  it.
- **Links.** Hard links share an inode and count its names. A symlink's
  target lives in the inode up to 59 bytes, else in a block of its own.
- **What a write leaves behind,** as Linux has left it since 5.14:
  - A deleted name's directory entry is wiped: folded into the entry before
    it and zeroed. The first entry of a block keeps only its length.
  - The inode keeps its mode, owner and times, and gains its deletion time,
    which is also its change time. It loses its size, its links and its
    blocks count.
  - Each extent's start and length are zeroed, and its logical block kept.
    A fast symlink's target is zeroed. The blocks are freed with their
    bytes in place.
  - A rename's old entry is wiped the same way, so a rename leaves nothing.
    A deleted directory goes as a file does, its block freed with its
    entries in it.
  - A new object takes the lowest free inode in its parent's flex group.
    An inode deleted within the last minute is skipped while there is
    another, as Linux skips it on a volume with no journal.
  - A file rewritten after it was truncated gets new blocks (with
    `next-fit`), and the old ones keep its old content.
  - The rest of a file's last block is zeroed, as the page cache writes it.
- **Allocation** is `next-fit` or `first-fit` as for FAT32. It is not
  mballoc, so where a file's blocks land is not where Linux would put them.

What ext4 cannot hold is refused before anything is written: streams,
junctions, a time outside its range, and a name longer than 255 bytes.

**NTFS** (`--image-fs ntfs`) is laid out as mkntfs 2022.10.3 formats it and
Windows writes it:
- **Format.** An empty volume is mkntfs's byte for byte, given the same
  serial number, partition start and time (`TestFormatMatchesMkntfs`, nine
  geometries from 3 MiB to 64 MiB and from 512-byte to 64 KiB clusters).
  Only the boot code, which fsagen leaves out, and the padding mkntfs leaves
  holding whatever its buffers held, are masked.
  - Clusters are 4 KiB (`--cluster-size` takes any power of two from 512
    bytes to 2 MiB). Records are 1 KiB and index blocks 4 KiB.
  - `$Boot` is in cluster 0, `$MFT`'s bitmap after it, and `$MFT` from 16
    KiB with its 27 records. `$MFTMirr` and `$LogFile` (all `0xFF`, sized
    as mkntfs sizes it) are in the middle of the volume.
  - The root's security descriptor and index block, `$AttrDef`, `$Bitmap`,
    `$Secure`'s `$SDS` and `$UpCase` follow the MFT zone, an eighth of the
    volume after `$MFT`.
  - `$UpCase` is the table Windows 8 and later write, with its CRC in
    `$UpCase:$Info`. `$Secure` holds mkntfs's two descriptors.
- **Records.** A file or directory gets the lowest free record from 64 up,
  as libntfs-3g counts from there, a deleted one's included.
  - Its `$STANDARD_INFORMATION` is NTFS 3's, pointing at one of two
    descriptors fsagen adds to `$Secure` the first time it needs them: a
    file's and a directory's, owned by the Administrators, with the ACEs
    they inherit from the root.
  - Its `$FILE_NAME` is in the Win32 namespace, or the Win32 and DOS
    namespace when the name is a valid upper-case 8.3 name, as Windows with
    short names off writes it. No short name is generated.
  - `$MFT` grows a record at a time, and its clusters 16 records at a time,
    right after its last one, as libntfs-3g grows it.
- **Content** stays in the record while it fits there, and once it has left
  for clusters it stays in clusters. A file rewritten after it was
  truncated gets new clusters, the old ones keeping its old content. The
  rest of the last cluster is zeroed, as the cache manager writes it.
- **Directories.** A directory's index is a B-tree of 4 KiB index blocks
  under its `$INDEX_ROOT`, in `$UpCase` order, built and changed as
  libntfs-3g 2022.10.3 builds and changes one (`TestIndexMatchesLibntfs3g`).
  Where Windows splits a block cannot be read without an administrator.
  - Entries stay in `$INDEX_ROOT` while the record keeps 120 bytes free.
    Then they move to an index block, and the root points there.
  - A full block splits at its median entry: the entries after it go to a
    new block, and the median goes up into the parent. A full parent splits
    first; a full root moves to a block, and the tree is a level deeper.
  - A removed entry in a node with children is replaced by the next name,
    from the leftmost leaf after it. A leaf left empty is freed, and the
    parent's entry that pointed to it is filed again from the top. A root
    left with no entries is a leaf again.
  - A new block takes the lowest VCN free in `$BITMAP`, which grows 8 bytes
    at a time, and is written whole. `$INDEX_ALLOCATION` grows after its
    last cluster and never shrinks.
- **Names** are what Windows takes: up to 255 UTF-16 code units, with no
  control character and none of `"*/:<>?\|`. Case is kept but does not
  count. `$MFT`, `$Extend` and NTFS's other names at the root are the file
  system's own, in any case, and are refused there.
- **Streams** are named `$DATA` attributes, in the record while they fit
  and in clusters once they do not; writing one replaces it. A directory
  takes one too.
- **Hard links** are further `$FILE_NAME` attributes of the record, in the
  POSIX namespace (Windows gives a hard link no short name), each with an
  entry in its own directory's index and its own `$FILE_NAME` times.
  Removing a name leaves the record to the others.
- **Symlinks and junctions** are reparse points, an empty file or directory
  with the reparse data the live Windows target writes, filed in
  `$Extend\$Reparse`'s `$R` index by tag and file reference as libntfs-3g
  files them (`TestReparseIndexMatchesLibntfs3g`). The directory's entry
  carries the reparse flag and tag; the record's `$FILE_NAME` does once a
  rename writes it anew. A junction's target is a path on `C:`, the drive a
  system volume has; an image has no drive letter of its own.
- **Times.** All four times are kept, to 100 ns, from 1601 to 30828.
  `$FILE_NAME`'s times are set as NTFS sets them: at birth from the file's
  own, and again when it is renamed or gets a hard link, as the model has
  them (`TestNTFSSetsFileNameTimesAsTheModel`). A timestomp's `fn_` times
  are written into the record and the directory's index alike.
- **Slack** is written into the rest of the last cluster, on a file of more
  than 1 KiB, which never stays in its record.
- **What a write leaves behind,** as Windows leaves it:
  - A deleted object's record loses its in-use flag and its sequence number
    goes up. It keeps its attributes: its names, times and runlist, and its
    content if that was in the record. Its clusters are freed with their
    bytes in place.
  - Its entry leaves its parent's index. The entries after it move up over
    it, and their old bytes stay past the index's end, as index slack.
  - A renamed object's entry moves; its old bytes may stay behind as slack
    in the same way.
  - A freed index block is left on disk as it was last written, with every
    name it held.
  - A deleted file's streams leave their clusters too.
- **Allocation** is `next-fit` or `first-fit` as for FAT32, from the end of
  the MFT zone, which only `$MFT` grows into while the rest of the volume
  has room.

What an NTFS image cannot hold is refused before anything is written: slack
on a file of 1 KiB or less, a time before 1601, and a name Windows forbids
(`TestNTFSRefusesWhatItCannotHold`).

**Residue in the answer key.** Each thing a write left behind is a `residue`
fact, tied to the operation that left it:

```json
{"event":"residue","n":58,"object":16,"kind":"file","path":"Logs/application-event-000.log",
 "residue":{"cause":"delete",
  "entry":{"type":"fat_dirent","number":311,"offset":676480,"length":32,"overwritten":true},
  "extents":[{"offset":676864,"length":1}],"size":1,"sha256":"fcb5…","recoverable":"full"}}
```

- `cause` is `delete`, `rename` or `overwrite`.
- `entry` is the deleted entry: FAT's short entry (`fat_dirent`), ext4's
  inode (`ext4_inode`) or NTFS's MFT record (`ntfs_mft_record`, with the
  sequence number its deletion gave it as `seq`). `number` is its address as
  The Sleuth Kit numbers it, which `istat` takes, and `offset` is where it
  lies in the image file.
- On NTFS, an entry a delete or a rename took out of a directory's index is
  residue of its own (`ntfs_index_entry`) where its bytes are still whole in
  one of the directory's index blocks: in the slack past a block's entries,
  in a block the index freed, or in a deleted directory's blocks. `number`
  and `seq` are the file reference it held.
  `overwritten` says a later write took it over, so no tool will find it.
  ext4's gives `deleted`, the time of the delete, which the inode keeps as
  its change time and, to the second, as its deletion time.
- `extents` are where the freed content lies in the image file, in order,
  and `sha256` its digest then.
- `recoverable` is `full`, `partial` or `none`, depending on how much of
  that content the finished image still holds. `overwritten` ranges say
  which bytes later writes changed.

Slack on an image is written into the cluster itself and recorded
`verified: true` (see _Slack_).

**How it is checked.**
- **During the run.** Every run is verified and digested through fsagen's own
  parser of the file system, which reads the finished image and knows
  nothing of how it was written; ext4's checks every checksum it passes.
  Every time the run controls is compared, to the file system's resolution.
- **Every example.** Each example a file system can hold makes an image whose
  `SHA256SUMS` and ledger are, byte for byte, those of the same run in
  memory (`TestImagesTakeEveryExample`). On FAT32, the one example with a
  hard link is refused; ext4 and NTFS take it.
- **Pinned images.** `testdata/image/fat32.yaml`, `testdata/image/ext4.yaml`
  and `testdata/image/ntfs.yaml` take each driver through every path above.
  Their images, residue and `SHA256SUMS` are pinned, the same on Windows and
  Linux (`TestImageGolden`, `TestExt4ImageGolden`, `TestNTFSImageGolden`).
  fsagen's own observed timeline of the ext4 image scores 1.0 with no time
  tolerance at all (`TestExt4ObservedTimelineToTheNanosecond`), and of the
  NTFS image too, streams, links and every name's `$FILE_NAME` times included
  (`TestNTFSObservedTimelineTo100ns`).
- **Independent readers.**
  - go-diskfs reads every name and byte back, bare and in a VHD
    (`TestFAT32ReadByGoDiskfs`, `TestExt4ReadByGoDiskfs`), checking ext4's
    checksums as it goes.
  - go-ext4 reads the ext4 image too (`TestExt4ReadByGoExt4`).
  - go-ntfs walks the NTFS image's indexes and reads every name, byte,
    stream, record number, link count, reparse point, time and
    `$FILE_NAME` time to the 100 ns, bare and in a VHD; every deleted record
    the answer key names, with its sequence number; and every index entry
    it names, carved from the directory's index blocks
    (`TestNTFSReadByGoNTFS`). It reads a directory whose index spans dozens
    of blocks the same way.
  - libntfs-3g runs a workload that grows directories three levels deep and
    shrinks them again, through a small C harness
    (`volume/ntfs/testdata/libntfs3g`). After every phase, each directory's
    B-tree is fsagen's node for node: the same entries in each block, the
    same VCNs and the same `$BITMAP` (`TestIndexMatchesLibntfs3g`, recorded
    in `volume/ntfs/testdata/libntfs3g-index.txt`). It makes symlinks too,
    and `$R` is fsagen's after each phase (`TestReparseIndexMatchesLibntfs3g`,
    recorded in `volume/ntfs/testdata/libntfs3g-reparse.txt`).
  - 7-Zip extracts every file of the FAT32 and NTFS images through the VHD
    and the MBR, and on NTFS every stream, both symlinks and the junction as
    links, and the hard link as a second name of its file
    (`TestImageReadBy7Zip`).
  - `fsck.vfat -n` and `e2fsck -fn` find nothing to fix
    (`TestImageCheckedByFsckVfat`, `TestExt4CheckedByE2fsck`). `e2fsck` also
    checks every volume the ext4 driver's unit tests make.
  - The Sleuth Kit's `fls` lists every file. It lists every deleted FAT entry
    at the address the answer key gives (`TestImageListedByTSK`), every
    deleted ext4 inode as `$OrphanFiles/OrphanFile-N` (`TestExt4ListedByTSK`),
    and every deleted NTFS record under its name in its directory
    (`TestNTFSListedByTSK`). `fls` and ntfs-3g's `ntfsls` also read every
    volume the NTFS driver's unit tests make.
- **Scoring.** `fsagen diff-oracle` scores TSK's bodyfile of each image at
  1.0 for files, deleted entries and times, and on NTFS for streams and
  every name's `$FILE_NAME` times, given the modelled timeline as the model,
  but for the one thing below. On ext4 it takes a deleted inode's change
  time from the residue's `deleted`.

Two things found on the way about The Sleuth Kit 4.12.1:
- It lists **no** ext4 orphan at all once any directory on the volume has
  been deleted. Linux empties a deleted directory's inode, and TSK fails to
  open it while looking for orphans, so it drops them all. The ext4 fixture
  deletes no directory for that reason; deleting one is tested in the
  driver's own tests.
- It lists the entries of an NTFS index block the index has freed as files
  that are there. TSK reads every block `$INDEX_ALLOCATION` maps, without
  `$BITMAP`, and libntfs-3g leaves a freed block as it was, so the NTFS
  fixture's one such entry is to TSK a live file, and its deletion is
  missed (`TestNTFSListedByTSK` pins exactly that).

## Sharing values across scenarios

`--vars-file` takes a flat YAML map and exposes every key as `${VAR:name}` in
paths, content and timestamps. One persona file can drive a whole set of
separate manifests, so a hostname or a date is defined once.

```yaml
# personas.yaml
org: "Northwind Logistics"
victim_host: "NWL-WKS-0417"
t_report_generated: "2026-03-14T02:33:12+05:30"
```

```pwsh
fsagen --seed 1414 --vars-file personas.yaml --manifest evidence-02.yaml ./out/02
fsagen --seed 1414 --vars-file personas.yaml --var org="Acme" --manifest evidence-03.yaml ./out/03
```

Precedence is `--var` > `--vars-file` > actor variables > playbook/manifest
variables. An undefined `${VAR:name}` is an error that names the file, line and
the variables that are defined; it is never left in the output. The run manifest
records the vars file's SHA-256 and a hash of the `--var` values, not the values
themselves (they can hold a vault password).

## Timestamps

Every operation happens at a time T: its scheduled time in a playbook; in a
manifest its `mtime`, else its `atime`, else the manifest's `start`; for an
email, its `Date`. What it creates or changes gets its times from T by these
rules, and an explicit `atime`, `mtime`, `ctime` or `crtime` on the action
always wins:

| Action                                                                         | Times                                                                                                                                                                                                                              |
| ------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `create`, `archive`, `ansible-vault`, `email` to an `.eml`                     | born at T: all four times are T (creating a file that exists makes it anew)                                                                                                                                                        |
| `update`, `append`, `edit`, `truncate`, a later message appended to an `.mbox` | access, modification and change become T; creation is kept                                                                                                                                                                         |
| `mace`                                                                         | only the times it names (at least one)                                                                                                                                                                                             |
| `timestomp`                                                                    | only the times it names, as `mace`, and the `$FILE_NAME` times it names (see _Timestomp_)                                                                                                                                         |
| `ads`, `motw`                                                                  | the file's times do not change                                                                                                                                                                                                     |
| `rename`                                                                       | the object keeps its times; its change time becomes T                                                                                                                                                                              |
| `rotate`                                                                       | the rotated file is renamed (keeps its times); the empty file left at the old path is born at T                                                                                                                                    |
| `copy`                                                                         | the copy is born at T but keeps its source's modification time, and its named streams                                                                                                                                              |
| `hardlink`                                                                     | the file keeps its times; its change time becomes T (its link count changed)                                                                                                                                                       |
| `symlink`, `junction`                                                          | the link is born at T, as a create; its target's times do not change                                                                                                                                                               |
| `delete`                                                                       | the object is stamped with its final times just before it is removed; `atime`/`mtime` on a delete set the directory it leaves; a hard-linked file that keeps a name stays, its change time T                                     |
| directories                                                                    | born with the operation that creates them, explicitly or as a missing parent; every entry added, removed or renamed in them sets their modification and change times to T; a `mace` on a directory holds until the next such event |

A manifest operation with no time of its own and no `start` has no T: its times
are left to the file system, and the ledger lists them as uncontrolled.

Each object also has the four times NTFS keeps in its `$FILE_NAME` attribute,
which Windows sets itself. fsagen models them as Windows does: all four are T
when the object is born (an explicit time on the create does not reach them,
being set the way a program sets times, which leaves `$FILE_NAME` alone); a
`rename` copies the object's times into them; writes and `mace` leave them as
they are; and only a `timestomp`'s `fn_` times set them
(`TestFileNameTimeRules`). No live volume lets fsagen write them, so there
they appear only in a `timestomp`'s ledger entry and answer-key fact. An NTFS
image keeps them, and the settle pass sets every name's, as it sets the
other times.

After each operation fsagen stamps what it touched. After the last one it
settles the whole tree, files first and then directories deepest first, and
reads every time back; any time that differs from the scenario by more than the
volume's resolution fails the run and lists the differences. On Windows the
times are set through handles opened relative to the output root, all four in
one call (`FILE_BASIC_INFO`).

The resolution is 100 ns on NTFS and ReFS, and FAT's and exFAT's own where the
volume is one of those. Elsewhere on Unix it is read from the output directory's
change time, which only the kernel sets: on a volume that keeps whole seconds
(ext3, ext4 with 128-byte inodes, which `mkfs.ext4` picks below 512 MB, HFS+) it
always falls on a whole second, and there times are checked to the second;
otherwise to the microsecond (`TestGranularityFromRootChangeTime`, run on tmpfs,
btrfs and such an ext4). The ledger and the modelled timeline keep the fractions
the scenario asked for either way.

A time the platform cannot set is never faked: if the input asks for it, the run
stops before writing (or, with `--on-unsupported=skip`, drops the field and
records it in the run manifest); if the scenario only implies it, the ledger
lists it as uncontrolled. Which platform can set which time is in _Platform
support_; what fsagen cannot control at all, and what can disturb the output
after the run, is in _Limits_.

Verified by `TestCreateSetsCreationTime`, `TestMaceSetsFourTimes`,
`TestMaceLeavesUnnamedTimes`, `TestQuilldropLiteStompCount`,
`TestAdsAndMotwKeepTimes`, `TestDirTimesFollowLastChildEvent`,
`TestRotateKeepsRotatedTimes`, `TestCopySemantics`, `TestCopyCarriesStreams`,
`TestEmailTimesFromDate`, `TestNanoPrecisionRoundTrip`,
`TestDeleteStampsBeforeRemoval`, `TestManifestReferenceTime`,
`TestVerifyPassMatchesModel`, `TestLedgerCreateStompRenameDelete`,
`TestDefaultCrtimeRecordedUncontrolled`,
`TestExplicitCrtimeUnsupportedPreflight`, `TestDroppedTimeFieldRecorded`,
`TestRunManifestTimeCapabilities`, `TestSettleRetriesOnlyForAccessTimes`,
`TestChangeTimeSticks` and `TestTimelinePassKeepsAtime`. The creation and change
time tests run on Windows (11 and 10); on Linux they are skipped, and the rest
pass on Fedora 40, on tmpfs and btrfs. None of it has run on macOS or FreeBSD.

## Determinism contract

For one **generator version** (`fsagen --version`), built with the Go toolchain
pinned in `go.mod` (`GOTOOLCHAIN=go1.27.0` forces it; the Go version is recorded
in `run-manifest.json`), the same `--seed` and the same **inputs** (the YAML
file, the vars file, `--var` values, and every file read through `content_file`,
email bodies or attachments, all listed by SHA-256 in `run-manifest.json`),
fsagen produces byte-identical:

1. content of every regular file and named stream it writes, as listed in
   `SHA256SUMS`;
2. set of relative paths;
3. `--dry-run` listing (with each operation's intended times), `ledger.jsonl`,
   `answer-key.jsonl`, `mitre-layer.json` and `run-manifest.json`;
4. the modelled timeline (`--timeline-source modelled`), in every format.

This holds on every platform, for every operation the platform supports. Which
operations were skipped as unsupported is recorded, and follows from the
capability set; skipping one changes no other file's bytes. Bulk mode is covered
too (with `--bulk-start` as one more input).

Three kinds of bytes hold only for the pinned toolchain and the pinned
dependency versions, both recorded in `run-manifest.json`: a `deflate` archive
member (`compress/flate`), a JPEG (`image/jpeg`) and an SQLite database (the
driver). Everything else is written by fsagen itself and does not depend on
either — store-only zips (which is what a docx is), PE images, MP4, and the PNG,
whose zlib stream is hand-rolled from stored blocks for exactly this reason.

How: every random value is drawn from a ChaCha8 stream keyed by the seed and the
name of what it is for (the operation's `id` or the hash of its YAML, its
iteration and batch, the field, the token), so adding, removing or reordering an
unrelated action changes nothing else. Nothing reads the wall clock except
`start: now`, which marks the run as not reproducible.

**Not covered:** anything read back from the live file system: observed
timelines; the times on disk themselves (the ledger states what they are meant
to be, and the verify pass checks them within the run); times the ledger lists
as uncontrolled; NTFS `$FILE_NAME` times; file IDs, allocation and directory
order; `run-info.json`; runs with `start: now`; files already present under
`--into-existing`.

Verified by `TestDeterminismHarness` (every example and bulk mode, two runs into
different directories, and a different seed), the version-pinned goldens
(`TestExampleContentGoldens`, which also pins each example's ledger, answer key
and modelled bodyfile, `TestDryRunGoldens`, and `TestBulkGoldens`, which pins
the names and bytes of a bulk corpus — one file of every kind, and a nested one
that repeats a kind), `TestBulkDeterministic`,
`TestNoWallClockInContent`,
`TestInsertingUnrelatedActionLeavesOtherFilesUnchanged`,
`TestModelledTimelineIdenticalAcrossRuns` and
`TestCrossCapabilityContentEquality`. The whole suite has been run on Windows
11, Windows Server 2025 and 2016, Windows 10, Ubuntu 24.04 and Fedora 40 (Linux
goldens recorded there: every file is byte-identical to Windows, less the NTFS
streams). macOS and FreeBSD are built by the gate but have never been run.

## Platform support

fsagen builds with `CGO_ENABLED=0` for Windows, Linux, macOS and FreeBSD on
amd64 and arm64, and `go run ./tools/gate` compiles all eight. What it can then
_do_ differs, and every difference is reported rather than faked: an input that
asks for something the platform cannot do stops the run before anything is
written, unless `--on-unsupported=skip` is given, and then each skipped
operation is listed in `run-manifest.json`
(`TestUnsupportedOpsFailBeforeAnyWrite`,
`TestOnUnsupportedSkipRecordsAndKeepsOtherBytes`).

|                                           | Windows, NTFS or ReFS        | Windows, FAT or exFAT      | Linux                                                                                                 | macOS, FreeBSD        |
| ----------------------------------------- | ---------------------------- | -------------------------- | ----------------------------------------------------------------------------------------------------- | --------------------- |
| files, directories, content               | yes                          | yes                        | yes                                                                                                   | compiled, never run   |
| access and modification times             | yes                          | yes                        | yes                                                                                                   | compiled, never run   |
| creation time (`crtime`)                  | yes                          | yes                        | no                                                                                                    | no                    |
| change time (`ctime`)                     | yes                          | no, the volume stores none | no                                                                                                    | no                    |
| `ads`, `motw`                             | yes                          | no                         | no                                                                                                    | no                    |
| POSIX `mode` bits                         | the read-only attribute only | the same                   | yes                                                                                                   | yes                   |
| birth time read into a timeline           | yes                          | yes                        | `statx` `STATX_BTIME` where the filesystem reports one, else unknown                                  | `Birthtimespec`       |
| named streams listed in a timeline        | yes, one record each         | none to list               | n/a                                                                                                   | n/a                   |
| timeline read without moving access times | yes, suspended per handle    | the same                   | `O_NOATIME` when the caller owns the file, else restored, which moves the change time and is recorded | best effort, recorded |
| `$FILE_NAME` times                        | never controlled; a `timestomp`'s `fn_` times are a pre-flight error | n/a | n/a                                                                                     | n/a                   |
| `hardlink`                                | yes                          | no                         | yes, but not on FAT or exFAT                                                                          | compiled, never run   |
| `symlink`                                 | with Developer Mode or the privilege | no                 | yes, but not on FAT or exFAT                                                                          | compiled, never run   |
| `junction`                                | yes                          | no                         | no                                                                                                    | no                    |

A "no" for something the input asks for outright is a pre-flight error; a "no"
for a default the scenario only implies is recorded as `uncontrolled` in the run
manifest and in the ledger, never guessed.

Where the suite has actually run: Windows 11 (build 26200), Windows Server 2025
(26100), Windows Server 2016 (14393) and Windows 10 (19045) on NTFS; Ubuntu
24.04 on ext4, under WSL2 and on its own; and Fedora 40 on tmpfs, btrfs and an
ext4 volume made with 128-byte inodes, which keeps whole seconds and no birth
time. Every test that is skipped on one of those hosts runs and passes on
another, so the set between them leaves nothing unexercised. macOS and FreeBSD
are compiled on every change and have **never been run**: their column is what
the code paths intend, not a measurement.

## Limits

What fsagen does not control, and what can change its output after it finishes:

- NTFS keeps a second set of times in each `$FILE_NAME` attribute, which no
  user-mode call can set. The run manifest says
  `filename_times_controlled:
  false`, and a `timestomp` that names one is refused (or, with
  `--on-unsupported=skip`, sets the other times only and records the rest).
  Windows sets them when fsagen actually writes each file, so a tool that
  compares the two sets (MFTECmd's `SI<FN`) flags every file whose scenario
  creation time is earlier than the run, not only the stomped ones. An NTFS
  image is different: fsagen writes them there (see _Disk images_).
- The output directory's own times are never set
  (`root_times_controlled:
  false`).
- NTFS tunneling hands a file created under a name used moments earlier in the
  same directory the _old_ file's creation time, which is exactly what a
  `rotate` does. fsagen stamps and then verifies all four times afterwards, so
  the scenario's time is what lands (`TestRotateKeepsRotatedTimes`).
- With last-access updates on (`NtfsDisableLastAccessUpdate`, recorded in
  `run-info.json`), anything that reads the output afterwards moves its access
  times. fsagen's own reads (digests, the ledger, the timeline) leave them
  alone. If another process reads files while the run settles, fsagen settles
  again a few times before failing, and the error says so.
- `mode` is applied when a file is written; times are stamped after it, so a
  chmod does not disturb them. Windows honours only the write bit; the field
  matters on Linux output. An explicit `mode` on a directory `create` is for
  that directory; missing parents get the default `0755`.
- Other software can change the output after fsagen finishes. On Windows 10,
  Windows Search adds an `OECustomProperty` stream to `.eml` files in indexed
  folders (the user profile outside `AppData`) within seconds, and holds it open
  while it does. Defender's machine-learning detection refuses writes of
  generated PE images often enough to matter: it flagged the persistence
  artifacts of `playbook-malware-lifecycle.yaml` (`Trojan:Win32/Bearfoos.B!ml`),
  and it refused the acceptance scenario's implant under the name `svchost.exe`,
  under a version resource claiming Microsoft, and under the default
  high-entropy filler. Its verdict is not stable either: it allowed and then
  refused the same bytes minutes apart. A refused write is a failed run, not a
  silent one, so nothing wrong reaches the corpus — but generate into a folder
  that is neither indexed nor scanned. The ledger, answer key and modelled
  timeline describe what fsagen wrote either way.
- An observed timeline is not reproducible, by construction: it reports inode
  numbers, allocation and whatever another process did to the tree. The modelled
  timeline is the artefact to compare between machines (see _Determinism
  contract_).
- A `deflate` archive member, a JPEG and an SQLite database are reproducible
  only for the toolchain and dependency versions `go.mod` pins, both recorded in
  the run manifest. Everything else fsagen writes itself.
- A generated PE is a container for a parser, not a program: its sections hold
  filler, its entry point is inside that filler, and running one does nothing.
  fsagen has no way to produce, and no intention of producing, working code.
- Not generated at all: `$Recycle.Bin`, SRUM, Amcache and ESE databases.
- On a FAT32 image, a deleted entry keeps the high word of its start
  cluster, which some Windows versions clear. The `.` and `..` entries keep
  the times their directory was made with.
- An ext4 image has no journal, and its directories stay linear lists
  however large they grow (no `dir_index`).
  - Blocks are placed by fsagen's allocator, not mballoc. Every directory's
    inode is chosen as a file's is, not spread across groups as Orlov
    spreads top-level directories.
  - Everything is owned by root.
  - The superblock is as mke2fs left it, its counts aside: never mounted.
- An NTFS image's `$LogFile` is as mkntfs left it, all `0xFF`, and no
  record carries a log sequence number: Windows starts the log afresh when
  it mounts the volume.
  - A hard link's name is in the POSIX namespace, taken from what `dir /x`
    shows of one Windows made, not read from a disk Windows wrote.
  - The reparse flag and tag reach a record's own `$FILE_NAME` only when a
    rename writes it, as libntfs-3g writes them; a `$FILE_NAME`'s sizes
    follow the content in the record and the index alike.
  - Index entries are residue only where they are whole in an index block,
    not in an `$INDEX_ROOT`'s slack in its record.
  - Clusters are placed by fsagen's allocator, and records counted from 64
    and directory indexes split and merged as libntfs-3g does it, which may
    not be how Windows does it.
  - Where a directory's record would not hold its `$INDEX_ROOT` at all,
    libntfs-3g moves the root out to an extension record. fsagen moves its
    entries to an index block instead, as it does when the record would
    keep less than 120 bytes free.
  - Every file and directory has one of two security descriptors, as a
    file and a folder an administrator makes at the root inherit, owned by
    the Administrators rather than a user.

## File formats

A `create` or `update` that gives no content of its own builds a file of the
type its extension promises. Give `format:` to say so outright, or to build a
type whose extension is ambiguous.

| `format`         | Inferred from               | What is written                                                                                                      | Where `content_len` goes            | Read back by                                                             |
| ---------------- | --------------------------- | -------------------------------------------------------------------------------------------------------------------- | ----------------------------------- | ------------------------------------------------------------------------ |
| `pe`             | `.exe` `.dll` `.sys` `.scr` | PE32 or PE32+: DOS stub, COFF and optional headers, sections, import table, version resource, a Windows checksum     | the overlay, after the last section | `debug/pe` (`TestTypedFormatsParse`, `TestPEHeaderFieldsEqualInputs`)    |
| `zip`            | `.zip` `.jar`               | a zip holding one member, `data.bin`                                                                                 | that member's size                  | `archive/zip` (`TestZipIsReadableWithSizesInPlace`)                      |
| `png`            | `.png`                      | a 64×64 truecolour PNG                                                                                               | an `fsAg` private ancillary chunk   | `image/png` (`TestPNGDecodesAndCarriesPadding`)                          |
| `jpeg`           | `.jpg` `.jpeg`              | a 64×64 baseline JPEG                                                                                                | `COM` segments after `SOI`          | `image/jpeg` (`TestJPEGDecodesAndCarriesPadding`)                        |
| `mp4`            | `.mp4`                      | `ftyp` + `moov` (`mvhd`, one video `trak`) + `mdat`, 320×240, 3 s                                                    | the `mdat` payload                  | a box walk (`TestMP4HasFtypMoovMdat`, `TestMP4DurationAndDimensions`)    |
| `docx`           | `.docx`                     | an OOXML package: `[Content_Types].xml`, `word/document.xml`, `docProps/core.xml` and `app.xml`, stored uncompressed | the document's text                 | `archive/zip` + the properties (`TestDocxOpensWithParts`)                |
| `docm`           | `.docm`                     | the same, macro-enabled, with a VBA project (`word/vbaProject.bin`) holding one inert macro                            | the document's text                 | Word, which compiles the macro; Windows' structured storage; mscfb; olevba (see _`vba:`_) |
| `xlsx`           | `.xlsx`                     | a workbook with one sheet, `Sheet1`, its column A holding the text a line to a row                                   | one line, so one cell               | Excel; `archive/zip` (`TestOfficeDocumentsParse`)                        |
| `xlsm`           | `.xlsm`                     | the same, macro-enabled, with a VBA project (`xl/vbaProject.bin`) holding one inert macro                              | one line, so one cell               | Excel; Windows' structured storage; mscfb; olevba (see _`vba:`_)          |
| `lnk`            | `.lnk`                      | a Windows shell link: header, ID list down to the target, LinkInfo (volume and path), strings, a link-tracking block  | not accepted                        | Windows' own shell and golnk (see _`lnk:`_)                              |
| `prefetch`       | `.pf`                       | a Windows 10 or 11 prefetch file (SCCA version 30 or 31), MAM-compressed with XPRESS Huffman                         | not accepted                        | Windows' own decompressor and go-prefetch (see _`prefetch:`_)            |
| `evtx`           | `.evtx`                     | a Windows event log: file header, 64 KiB chunks, binary XML records with templates, every CRC                        | not accepted                        | `Get-WinEvent` and Velocidex evtx (see _`evtx:`_)                         |
| `regf`           | `.hve`, and the names `NTUSER.DAT` `USRCLASS.DAT` `SYSTEM` `SOFTWARE` `SAM` `SECURITY` `DEFAULT` | a registry hive, version 1.5                                    | not accepted                        | Windows' own registry and regparser (see _`registry:`_)                  |
| `utmp`           | the names `utmp` `wtmp` `btmp` | glibc's `struct utmp` records                                                                                     | not accepted                        | util-linux (see _`utmp:` and `auditd:`_)                                 |
| `auditd`         | the name `audit.log`        | auditd's raw log format                                                                                              | not accepted                        | see _`utmp:` and `auditd:`_                                              |
| `pdf`            | _(explicit only)_           | a paginated PDF from a Markdown subset                                                                               | the document's text                 | see _`format: pdf`_                                                      |
| `chrome_history` | _(explicit only)_           | Chrome's `meta`, `urls`, `visits`, `downloads`, `downloads_url_chains` and `keyword_search_terms`, with its indexes  | not accepted                        | SQLite + the queries a tool runs (`TestStandardHistorySQLReturnsVisits`) |
| `firefox_places` | _(explicit only)_           | Firefox's `moz_origins`, `moz_places` (with `rev_host`) and `moz_historyvisits`, `user_version = 77`                 | not accepted                        | as above                                                                 |
| `text`, `raw`    | anything else               | the content, or filler, byte for byte                                                                                | the whole file                      | —                                                                        |

`.pdf` is deliberately not inferred: a PDF's dates are settled while the
operation is compiled, before its path is rendered, so it stays an explicit
`format: pdf`. A hive, a login record and an audit log are known by their
whole name rather than an extension, and `.dat` alone infers nothing: it names
plenty of files that are not hives. An extension that promises something fsagen still cannot build is
an error rather than a fake — see _Input is strict_.

Filler is base32 text unless `content_kind` says otherwise (`TestFillerKinds`,
`TestBytesEntropyAbove7_9At64KiB`, `TestContentKindShapesTheBytes`). A
structured format is built by fsagen, so it takes no `content`, `content_file`,
`template` or `render`; `pdf` and the Office formats (`docx`, `docm`, `xlsx`,
`xlsm`) are the exceptions, because there the content _is_ the document's text
(a workbook's, a line to a cell, at most 32767 characters each).

### `pe:` — Windows executables

What fsagen writes is a container for a parser to read, not a program to run:
headers, sections of filler, an import table and a version resource. Nothing in
the image is code — the entry point is inside filler — and it must stay that
way.

```yaml
- action: create
  path: AppData/Local/Temp/wupdmgr32.exe
  content_len: 8192 # the overlay
  pe:
    machine: amd64 # amd64 (default), i386, arm64
    subsystem: gui # console (default), gui, native
    dll: false
    timestamp: "2024-03-15T09:00:00Z" # RFC3339, or "0" for a reproducible
    # build; defaults to the action's time
    sections: # default: .text 1024, .rdata 512, .data 256
      - name: .text
        size: 4096
        flags: [code, execute, read]
      - name: .data
        size: 1024
        flags: [initialized_data, read, write]
    imports: # "dll!function"; the imphash is stable
      - kernel32.dll!CreateFileW
      - advapi32.dll!RegSetValueExW
    version: # the resource Explorer and every metadata tool read
      file_version: 10.0.19041.1
      product_version: 10.0.19041.1
      company_name: Microsoft Corporation
      file_description: Windows Update Manager
      internal_name: wupdmgr32
      original_filename: wupdmgr32.exe
      product_name: Microsoft Windows Operating System
      legal_copyright: "(c) Microsoft Corporation."
```

Section flags: `code`, `initialized_data`, `uninitialized_data`, `execute`,
`read`, `write`, `discardable`. The checksum in the header is the one Windows
itself computes: `TestPEChecksumMatchesWindows` asks `imagehlp` for it and
compares (on Windows; elsewhere `TestPEChecksumCoversTheWholeImage` checks only
that the stored value covers the image). The same imports always give the same
imphash (`TestImphashStable`).

### `history:` — browser profiles

Each engine keeps its own epoch, and getting that wrong is the classic way to
put a corpus in the year 1601: Chrome counts microseconds from 1601-01-01 and
Firefox from 1970-01-01 (`TestChromeWebKitEpoch`, `TestFirefoxPRTime`). fsagen
writes the tables a parser queries, with their indexes:
`TestStandardHistorySQLReturnsVisits` runs the SQL a history tool runs and gets
the scenario's visits, hosts, visit counts and transition codes back. Nothing
has been checked against a named forensic tool.

```yaml
- action: create
  path: Users/analyst/AppData/Local/Google/Chrome/User Data/Default/History
  format: chrome_history
  history:
    visits:
      - url: https://intranet.example/hr/handbook
        title: Employee handbook
        time: "2023-10-30T09:12:00Z" # defaults to the action's time
        transition: typed # link (default), typed, bookmark,
      # generated, form_submit, reload
      - url: https://intranet.example/hr/handbook/leave
        title: Leave policy
        time: "2023-10-30T09:13:20Z"
        from_visit: 1 # 1-based position in this list
    downloads: # Chrome only
      - url: https://intranet.example/hr/handbook.pdf
        target_path: C:\Users\analyst\Downloads\handbook.pdf
        start: "2023-10-30T09:14:00Z"
        end: "2023-10-30T09:14:03Z"
        received_bytes: 284160
        total_bytes: 284160
        mime_type: application/pdf
```

A history database is as big as its contents make it, so it takes no
`content_len`. `examples/manifest-history.yaml` and
`examples/playbook-browsing.yaml` are worked profiles.

### `vba:` — macro-enabled documents

A `.docm` or `.xlsm` carries a VBA project with exactly one macro, and that
macro is inert: it assigns a marker string to a local variable and does
nothing else. Nothing in the block can change that; there is no way to give
it code.

```yaml
- action: create
  path: Users/victim/Downloads/Invoice_4471.docm
  format: docm # needed here because the action gives content
  content: Please enable editing and content to view this invoice.
  docx: { author: Accounts }
  vba:
    entry_point: Document_Open # AutoOpen (default) or Document_Open; Auto_Open (default) or Workbook_Open for xlsm
    marker: FSAGEN-VBA:invoice-4471 # default: FSAGEN-VBA: and 16 letters from the seed
  mitre: [T1204.002]
- action: create
  path: Users/victim/Downloads/budget.xlsm # inferred; the defaults throughout
  vba: { module_name: Loader } # the standard module holding Auto_Open; Module1 by default
```

- The entry point is one Office runs when the document opens, so a scanner
  reports it: `AutoOpen` (in a standard module, `NewMacros` unless
  `module_name` says otherwise) or `Document_Open` (in `ThisDocument`) for
  Word; `Auto_Open` (in `Module1` unless named) or `Workbook_Open` (in
  `ThisWorkbook`) for Excel. `module_name` is a VBA name, and only applies to
  the standard-module entry points.
- The marker is printable ASCII without a double quote, up to 200 characters,
  so it can only ever be a string. A marker the scenario does not give is
  drawn from letters that are not hex digits, so a scanner hunting hex
  strings finds none in it.
- The project is what [MS-OVBA] describes: a compound file (version 3,
  written by fsagen's own `libgen/cfb.go`) holding `PROJECT`, `PROJECTwm`, and
  under `VBA` the `dir` stream, `_VBA_PROJECT` and one stream per module, the
  source compressed with the specification's algorithm, which reproduces its
  three worked examples byte for byte (`TestOVBASpecExamples`). There is no
  compiled p-code: `_VBA_PROJECT` says so, as the specification requires of a
  writer, and Office compiles the source as it opens the document. The
  project's protection fields say unprotected, no password, visible, obscured
  as the specification's data encryption obscures them, which the tests
  reverse (`TestVBAProjectReadBack`).
- Windows' own structured storage reads every stream back
  (`TestCFBReadByWindows`), and so does mscfb in the conformance module.
  With `FSAGEN_OFFICE=1`, `TestMacroDocumentsOpenInOffice` opens each kind in
  Word and Excel with every macro forcibly disabled: both find the project,
  Excel the code names, and Word compiles the source and saves it back
  unchanged. Where `olevba` is installed, `TestVBAReadByOlevba` checks that it
  extracts each macro and reports only its entry point (AutoExec); on an
  Excel project it also reports hex strings, which are the class GUIDs on the
  `Attribute VB_Base` lines that every Excel project carries, and which it
  reports in a workbook Excel wrote too.
- A `.xlsx` is the same workbook with no project. Neither is inferred from
  content given beside it: give `format:` then, as for `.docx`.

### `lnk:` — Windows shortcuts

A shell link as [MS-SHLLINK] lays it out: the header with the target's
creation, access and write times, size and attributes; the ID list a shell
walks (My Computer, the drive, then one item per folder, each with its 8.3 name
and a `0xBEEF0004` block holding the long name, creation and access times and
the NTFS file reference); the LinkInfo with the drive type, volume serial,
label and path; the strings; and the TrackerDataBlock with the machine's
NetBIOS name and the volume and object ids. Explorer resolves it, and a link
tool reports where the target was, when, on which volume and on which machine.

```yaml
- action: create
  path: Users/u/Desktop/report.lnk # .lnk implies format: lnk
  lnk:
    target: 'C:\Users\u\Documents\Q3 report.docx' # required: a path on a drive letter
    target_type: file # file (default) or dir
    arguments: /safe
    working_dir: 'C:\Users\u\Documents'
    relative_path: '..\Documents\Q3 report.docx'
    description: Quarterly report
    icon: 'C:\Windows\System32\shell32.dll'
    icon_index: 1
    show_command: normal # normal (default), maximized, minimized
    drive_type: removable # fixed (default), removable, cdrom, ramdisk
    volume_serial: 1A2B-3C4D # default: drawn from the seed
    volume_label: USBSTICK
    machine_id: DESKTOP-QUILL # default: DESKTOP- and 7 characters from the seed
    target_crtime: "2024-03-15T09:00:00Z" # target_crtime, _atime and _mtime
    target_mtime: "2024-03-15T11:00:00Z" # default to the action's time
    target_size: 48213
    target_attributes: [hidden] # readonly, hidden, system, archive
```

- The header's times are in [MS-SHLLINK]'s order — creation, access, write —
  which is what Windows writes itself (`TestLNKHeaderTimeOrderMatchesWindows`
  saves a shortcut through the shell and compares the offsets). At least one Go
  parser, golnk, reads the last two the other way round.
- The tracking block's object id is a version 1 GUID dated at the target's
  creation, with a node a tool reports as a MAC address; it is a locally
  administered address no real adapter has. The volume id is random, as an
  NTFS volume's is. Both come from the seed.
- A network target (`\\server\share`) is not built: a link records one with a
  different structure. Volume labels and machine names are ASCII; a non-ASCII
  target path is written in both the ANSI and the Unicode LinkInfo fields.
- Read back three ways: fsagen's own reader walks every structure from the
  sizes and offsets the link gives (`TestLNKRoundTrip`,
  `TestLNKMinimalAndUnicode`); Windows' shell resolves the target, strings,
  icon and window state through `WScript.Shell` and `Shell.Application`
  (`TestLNKReadByWindowsShell`); and golnk parses it end to end in the
  conformance suite (`TestLNKReadByGolnk`). Every value the block can give is
  checked before anything is written (`TestLNKBlockRules`).

### `prefetch:` — proof of execution

The prefetch file Windows 10 (SCCA version 30, in the layout Windows 10 1903
introduced) or Windows 11 (version 31) keeps for a program it has seen start:
the program's name and path hash, the run count, the last eight run times, the
files it loaded and the volumes they were on, compressed as Windows compresses
it, in a `MAM` header with XPRESS Huffman.

```yaml
- action: create
  path: Windows/Prefetch/MIMI.EXE-18453749.pf # .pf implies format: prefetch
  prefetch:
    executable: 'E:\Tools\mimi.exe' # required
    version: win11 # win11 (default) or win10
    run_count: 3 # default: the number of last_run_times
    last_run_times: # at most 8, any order; default the action's time
      - "2024-03-15T09:30:00Z"
      - "2024-03-14T22:10:00Z"
    referenced_files: # besides the program and ntdll.dll, which are always
      - 'C:\Windows\System32\advapi32.dll' # listed; default kernel32.dll and
      - 'E:\Tools\mimilib.dll' # KernelBase.dll
    harddisk_volume: 3 # N of \Device\HarddiskVolumeN, for the hash; default 3
    volumes: # serial and format time per drive; default from the seed
      - { drive: E, serial: 1A2B-3C4D, created: "2024-01-15T12:00:00Z" }
    compressed: true # default; false writes the SCCA data plain
```

- The hash is the one Windows computes, over the program's device path in
  upper-case UTF-16: `TestPrefetchHashMatchesWindows` reproduces the names of two
  real Windows 10 prefetch files. A file named the way Windows names one
  (`NAME.EXE-XXXXXXXX.pf`) must match its program and volume, or the scenario
  is refused (`TestPrefetchBlockRules`); any other name is a renamed copy and
  is left alone.
- Each volume is named as Windows names it, `\VOLUME{<creation FILETIME>-<serial>}`,
  and lists the directories its files are in. File references are left out,
  as Windows 10 and later leave them out. Fields whose meaning is unknown hold
  what Windows was seen to write, or zero; the run count is where Windows 10
  1903 and later keep it, and the field older files kept it in is zero, so
  every parser reads the same count.
- The XPRESS Huffman encoder is fsagen's own and deterministic. Windows'
  `RtlDecompressBufferEx` decodes everything it writes (`TestXpressDecodedByWindows`),
  as do a decoder written from [MS-XCA] (`TestXpressRoundTrip`) and
  go-prefetch's own (`TestPrefetchDecompressedByGoPrefetch`). fsagen's reader
  walks the decompressed file (`TestPrefetchReadBack`), and go-prefetch, the
  parser Velociraptor uses, reads the program, hash, run count, run times and
  loaded files for both versions (`TestPrefetchReadByGoPrefetch`).

### `evtx:` — Windows event logs

An event log as Windows writes one: the file header, 64 KiB chunks with their
string and template tables, and each event as binary XML, a template defined
once per chunk and filled with the event's values. Every CRC is right.

```yaml
- action: create
  path: Windows/System32/winevt/Logs/Security.evtx # .evtx implies format: evtx
  evtx:
    channel: Security # default: the built-in events' channel, else Application
    computer: WS01.corp.example # default: DESKTOP- and 7 characters from the seed
    first_record_id: 7000 # default 1
    events:
      - event_id: 4624 # built in: provider, version, task, keywords and the
        time: "2024-03-15T08:59:00Z" # names and types of its data are Windows' own
        data:
          TargetUserName: alice
          TargetDomainName: CORP
          LogonType: 10
          IpAddress: 203.0.113.7
      - event_id: 1102 # the log was cleared
        data: { SubjectUserName: alice }
      - event_id: 1000 # any other event names its provider; its data are strings
        provider: Application Error
        level: 2
        data: { AppName: dropper.exe }
```

- Built in: 4624 (an account logged on), 4688 (a process was created), 7045 (a
  service was installed) and 1102 (the audit log was cleared, written as
  `UserData` as Windows writes it). A data value left out is the one Windows
  writes when it has none (`-`, `0x0`, `S-1-0-0`); a name the event does not
  have, or a value its type cannot hold (a SID, a GUID, a number), is refused
  (`TestEvtxBlockRules`). A built-in event in a log of another channel is
  refused too.
- Each event is one template, where Windows nests the event data in a template
  of its own; every reader renders the same XML from either. Event times keep
  100 ns.
- Windows itself reads the log: `Get-WinEvent -Path` renders every record to
  exactly the XML the events describe (`TestEvtxReadByWindows`), and reads a
  log of several chunks whole and in order (`TestEvtxChunksReadByWindows`).
  fsagen's reader checks every CRC, size and offset and renders the binary XML
  (`TestEvtxReadBack`, `TestEvtxSpansChunks`), and Velocidex evtx reads every
  value back (`TestEvtxReadByVelocidex`, `TestEvtxChunksReadByVelocidex`).

### `registry:` — registry hives

A hive as Windows XP SP2 and later save one (version 1.5): the base block, hive
bins of cells, each key's subkeys in a hash leaf sorted the way Windows looks
names up (an index of leaves past 512), values inline, in a cell or split into
big-data segments, and one shared security descriptor. Which hive a file is
comes from its name, and decides where the artefacts below go.

```yaml
- action: create
  path: C/Users/alice/NTUSER.DAT # the name implies format: regf
  registry:
    keys:
      - path: 'Software\Sysinternals\PsExec'
        last_written: "2024-03-15T09:00:00Z" # default the action's time
        values:
          - { name: EulaAccepted, type: REG_DWORD, data: 1 }
          - { name: "", data: default value } # REG_SZ is the default type
          - { name: Blob, type: REG_BINARY, data: "de ad be ef" }
          - { name: Paths, type: REG_MULTI_SZ, strings: [a, b] }
    run: # NTUSER.DAT or SOFTWARE
      - { name: SystemUpdate, command: 'C:\Users\alice\AppData\Local\Temp\wupdmgr32.exe' }
    userassist: # NTUSER.DAT
      - { path: 'C:\Windows\System32\cmd.exe', run_count: 4, focus_time_ms: 61000, last_run: "2024-03-15T09:30:00Z" }
- action: create
  path: C/Windows/System32/config/SYSTEM
  registry:
    usbstor: # SYSTEM
      - vendor: SanDisk
        product: Cruzer Blade
        revision: "1.00"
        serial: 4C530001231117116491
        first_install: "2024-03-14T08:00:00Z" # first_install and last_arrival
        last_arrival: "2024-03-15T09:00:00Z" # default to the action's time;
        last_removal: "2024-03-15T10:00:00Z" # without one it is still connected
```

- Value types: `REG_SZ`, `REG_EXPAND_SZ`, `REG_MULTI_SZ`, `REG_DWORD`,
  `REG_DWORD_BIG_ENDIAN`, `REG_QWORD`, `REG_BINARY`, `REG_NONE`.
- `run` is the Run key of the hive it is in. `userassist` writes Explorer's
  records under the GUID for programs, or for shortcuts when the path is a
  `.lnk`: the name ROT13'd with its known folder as a GUID, the 72-byte value
  with the run count, focus count and time and the last run
  (`TestUserAssistEncoding`). `usbstor` writes the device's
  `ControlSet001\Enum\USBSTOR` key with the values the disk driver's
  installation writes, its install, arrival and removal times as FILETIME device
  properties, and the `Select` key a parser reads first (`TestUSBStorKeys`). An
  artefact in a hive that does not keep it is refused (`TestRegistryBlockRules`).
- Windows' own registry loads the hive, checking it as it does, and reads every
  key with its last-write time and every value with its type and data
  (`TestHiveLoadedByWindows`, which loads it as an application hive, as any user
  may). Big values are split as Windows requires: every segment holds a full
  16344 bytes, the last one padded. fsagen's reader checks the base block, the
  bins, the cells, the order and hashes of every leaf (`TestHiveReadBack`), and
  Velocidex regparser reads the keys and values back
  (`TestHiveReadByRegparser`).

### `utmp:` and `auditd:` — Linux logins and audit logs

`wtmp`, `utmp` and `btmp` are arrays of glibc's 384-byte `struct utmp`, the
same on amd64 and arm64. Its times are 32-bit, so nothing after
2038-01-19T03:14:07Z fits, and such a time is refused.

```yaml
- action: create
  path: var/log/wtmp # the names utmp, wtmp and btmp imply format: utmp
  utmp:
    records:
      - { type: boot, time: "2024-03-15T08:00:00Z" } # host: the kernel release
      - { type: login, user: alice, line: pts/0, host: 203.0.113.7 }
      - { type: logout, line: pts/0, time: "2024-03-15T10:00:00Z" }
      - { type: shutdown, time: "2024-03-15T11:00:00Z" }
- action: create
  path: var/log/btmp # failed logins only
  utmp:
    records:
      - { type: failed, user: root, host: 203.0.113.7 } # line: ssh:notty
- action: create
  path: var/log/audit/audit.log # the name implies format: auditd
  auditd:
    events: # each a second after the last, unless timed
      - { type: auth, user: alice, host: 203.0.113.7 }
      - { type: login, user: alice, host: 203.0.113.7 }
      - { type: execve, user: alice, argv: [curl, -o, /tmp/x, 'http://198.51.100.42/p'], key: exec }
```

- In a playbook a record or event that names no user is the actor's.
- A login's id is the last four characters of its line, as `login` and `sshd`
  make it; a logout takes its login's line, id and pid. Unless given, pids come
  from the seed and a login's session is its pid. util-linux reads the records
  back, `last` pairing each login with its logout (`TestUtmpReadByUtilLinux`,
  where `utmpdump` and `last` are installed), and a mirror of the C struct
  reads every field (`TestUtmpLayout`).
- An audit log is auditd's raw format. An execution is the kernel's `SYSCALL`
  record for `execve`, then `EXECVE`, `CWD`, a `PATH` for the program and its
  loader, and `PROCTITLE`, all with the event's serial. `auth`, `login` and
  `session_start` are the `USER_AUTH`, `USER_LOGIN` and `USER_START` records PAM
  and `sshd` write. A string with a space, a quote or anything outside
  printable ASCII is written as hex, as the kernel writes it
  (`TestAuditLogLines`). Serials start from the seed and rise. `ausearch` reads
  the log where it is installed (`TestAuditLogReadByAusearch`); it was not on
  any machine this was tested on.

### `archive` action

Zips files the scenario has already written. Members come from the model, so a
member's stored modification time is the time the scenario gave that file, not
the time it happened to be written; and they are resolved before the archive
object exists, so a pattern can never sweep the archive into itself.

```yaml
- action: archive
  path: staging/exfil-ready.zip
  archive:
    method: store # store (default) or deflate
    comment: staged for transfer
    member_refs: [mail, media] # every live path created under these ids,
    # in creation order
    members: # then glob patterns, in path order
      - "users/alice/staging/*.csv"
    base: users/alice/staging # stripped from each stored name
```

`member_refs` come first, in the order the files were created, then `members`,
in path order; a path named twice is stored once. A pattern that matches nothing
is an error, as is a member that does not lie under `base` — fsagen will not
invent a name for it (`TestArchiveRefusesEmptyPattern`,
`TestArchiveBaseMustCoverEveryMember`). Patterns are `path.Match` globs, so `*`
does not cross a `/`. In a playbook, both the patterns and `base` are relative
to the actor's base.

`store` is the default because deflated bytes come from `compress/flate` and so
are reproducible only for the Go toolchain `go.mod` pins. Members match their
sources byte for byte (`TestArchiveMembersMatchSources`).

### `edit` action

Changes a file in place. Cutting the injected lines back out of a log leaves a
gap in the record; truncating it leaves a file that is obviously short. Telling
those apart is the kind of thing a tool under test should be able to do, so
fsagen can produce both.

```yaml
- action: edit
  path: var/log/app.jsonl
  edit:
    delete_lines: "40-60" # 1-based, inclusive; or a single line
    delete_matching: '"level":"warn"' # every line the regexp matches
    replace:
      - pattern: 'user=(\w+)'
        with: "user=REDACTED"
        count: 0 # 0 means every match
    insert_after:
      - pattern: '"service start"'
        text: '{"ts":"2021-07-01T00:00:01Z","level":"info","msg":"ready"}'
```

The steps run in that fixed order whatever order they are written in: whole
lines, then substitutions over the text, then insertions. A scenario that needs
another order uses two `edit` actions, which is also what the ledger then shows.
Line endings survive, and a file that ended without a newline still does. A
range past the end of the file is an error (`TestEditDeleteLines40to60`,
`TestEditReplaceAndInsert`, `TestEditRefusesMissingLines`).

### Bulk mode

Bulk mode writes `--bulk` files of every one of these types in each directory it
makes, all structurally valid:

- **Documents**: .txt, .md, .docx, .pdf; .docm and .xlsm, each with one inert
  macro (see _`vba:`_)
- **Data**: .csv, .json, .jsonl, .xml, .html
- **Logs**: .log, .syslog, .jsonl; a Windows event log (.evtx, logons and
  process creations); and a Linux `wtmp` and `audit.log`, each in a host
  directory (`Host-xxxxxx/var/log/wtmp`, `Host-xxxxxx/var/log/audit/audit.log`)
- **Media**: .png, .jpg, .mp4
- **Archives**: .zip
- **Email**: .eml, .mbox
- **Browser history**: a Chrome profile (`Chrome-xxxxxx/Default/History`) and a
  Firefox one
  (`Firefox-xxxxxx/Profiles/xxxxxxxx.default-release/places.sqlite`), under the
  names a tool looks for
- **Windows**: .reg; .exe (a real PE with imports and a version resource); a
  shortcut (.lnk); a prefetch file named for its program and path hash
  (`XXXXXXXX.EXE-1A2B3C4D.pf`); and `Profile-xxxxxx/NTUSER.DAT`, with a Run key
  and UserAssist entries

Each file is built by the builder its format uses in a manifest, and the
corpus is written in the plan's order: files are rendered in parallel and
committed one at a time, so the order a file system allocates in is the
plan's too (`TestBulkForensicKindsParse`, `TestBulkGoldens`).

## Forensic timelines

After generating, fsagen can write a timeline of the output, from one of two
sources:

- **observed** (the default): read back from the file system after the run, as a
  tool examining the output would see it. It is not covered by the determinism
  contract: inode numbers, directory sizes and anything another process touched
  afterwards differ from run to run.
- **modelled** (`--timeline-source modelled`): built from the run's model and
  ledger, reading nothing from disk: the times, sizes and digests the scenario
  intends, **including the objects it deleted**, marked `(deleted)` as The
  Sleuth Kit marks them, which an observed timeline can never show. It is the
  same bytes on every run with the same inputs and capability set
  (`TestModelledTimelineIdenticalAcrossRuns`, and the determinism harness on
  every example). Its inode column is the ledger's object number, its mode is
  the one fsagen requests (before any umask), a directory's size is 0, and a
  time the platform cannot set is unknown rather than the scenario's wish. The
  text formats say which source they are; the run manifest records the source of
  every timeline, and the digest of a modelled one.

```pwsh
fsagen --seed 42 --playbook scenario.yaml --timeline case.body ./artifacts
fsagen --seed 42 --playbook scenario.yaml --timeline intended.body --timeline-source modelled ./artifacts2
```

**Formats** (from `--timeline-format` or the extension; an unknown extension is
an error, never a silent fall-back):

- **Bodyfile** (`.bodyfile`, `.body`): The Sleuth Kit's bodyfile,
  `MD5|name|inode|mode|UID|GID|size|atime|mtime|ctime|crtime`: names from the
  output root with a leading `/` and no root entry, `name:stream` for each named
  stream, `name ($FILE_NAME)` for a name's NTFS `$FILE_NAME` (an NTFS image
  only), `name -> target` for a link and `name (deleted)` for a deleted
  object (modelled only), in TSK's order, TSK mode
  strings (`r/rrw-r--r--`), times in whole seconds, and `0` for an unknown time
  or an MD5 that was not computed. `mactime` reads it (`TestMactimeAccepts`, run
  on Linux with The Sleuth Kit 4.12.1); `TestBodyfileStrictParserRoundTrip`
  parses every line of an observed and a modelled bodyfile strictly.
- **MACB** (`.macb`): one line per entry and distinct instant, in time order, as
  `mactime` prints it: the flags say which of the entry's times fall then
  (`MACB` when all four agree, `M...` and `.A.B` when they do not;
  `TestMACBSixteenCombinations` covers every combination).
- **CSV** (`.csv`): one row per entry: path, stream, type, size, mode, UID, GID,
  inode, the four times (RFC 3339 with fractions, empty when unknown), MD5 and
  deleted. A `$FILE_NAME` entry's type is `filename`.
- **JSON lines** (`.jsonl`): the same fields, one object per entry, with an
  octal mode, and `"file_name": true` on a `$FILE_NAME` entry.
- **Timesketch** (`--timeline-format timesketch`): the JSON lines Timesketch
  imports, one event per entry and known time as Plaso's file-stat parser
  emits them, so an entry with four known times is four events. Each has the
  fields Timesketch requires (`message`, `datetime`, `timestamp_desc` with
  Plaso's names: Content Modification Time, Last Access Time, Metadata
  Modification Time, Creation Time), `@timestamp` for OpenSearch, `timestamp`
  in integer microseconds, and the entry's path, stream, type, size, mode,
  inode, MD5 and `is_allocated`, and `"attribute_name": "$FILE_NAME"` on a
  `$FILE_NAME` entry's events, as Plaso names the attribute. Timesketch keeps microseconds, so a finer time
  is cut down to the microsecond, before 1970 too (`TestTimesketchEvents`).
- **Text** (`.txt`): a readable listing, one block per entry.

**Every entry has four times**: accessed, modified, changed (metadata) and born
(created), each read from its own source and never copied into another:
`FILE_BASIC_INFO` on Windows, `statx` on Linux (the birth time only where the
file system keeps one), `lstat` on macOS and FreeBSD (built, never run)
(`TestBodyfileCrtimeNotCtime`, `TestLinuxBtimeFromStatxOrZero`). Every named
stream is its own entry, with its size and MD5 and its file's times
(`TestStreamsQuillAndSpaceNameWithSizes`). The inode is the NTFS MFT record
number on Windows and the inode number on Unix; UID and GID are the owner on
Unix and 0 on Windows. On Windows the mode is written as The Sleuth Kit writes
it for NTFS (`rwxrwxrwx`, less the write bits of a read-only file).

**Reading does not change what is read**: every digest and directory listing
goes through a handle that leaves access times alone (Windows; Linux when you
own the files; `TestTimelinePassKeepsAtime`). Anything the walk cannot read is
an error that names it, never a shorter timeline (`TestWalkErrorReported`). The
whole timeline is built before its file is written. Entries are sorted by
modification time, then path; all times are UTC.

**Checked against The Sleuth Kit** (by hand, 2026-09-26; not part of the test
suite): a scenario with renames, a copy, a timestomp, streams, explicit creation
and change times and a deletion was generated onto a fresh ext4 image
(Fedora 40) and onto an NTFS volume (Windows 10), and each image was read with
`fls -r -m` (TSK 4.12.1). Every file and stream record of the observed bodyfile
matched `fls` in inode, mode, owner, size and all four times; the only
difference was the size of directories on NTFS, which Windows does not report
and TSK reads from the directory index. The modelled bodyfile's times matched
every live record, and on NTFS `fls` recovered the deleted file's MFT record
with the same size and four times as the modelled `(deleted)` entry.

**Timeline-only mode**: `fsagen --timeline FILE DIR` writes an observed timeline
of an existing directory without generating anything.

```pwsh
fsagen --timeline existing.csv ./already-generated-folder
fsagen --timeline evidence.body ./investigation
mactime -b evidence.body -d > detailed-timeline.txt
```

See `examples/TIMELINE_EXAMPLES.md` for more.

## Scoring a tool: diff-oracle

`fsagen diff-oracle` scores what a forensic tool reports about a generated
tree against what fsagen made there:

```sh
fls -r -m / scene.img > fls.body
fsagen diff-oracle --meta ./scene.fsagen fls.body
fsagen diff-oracle --meta ./scene.fsagen --scorecard score.json --fail-under 0.95 plaso.csv
```

**What it knows.** The run's sidecar directory (`--meta`, required) holds the
answer: the ledger, folded operation by operation into the state the run left
(every name and the object it names, content digests, streams, links, the
times the run controls, and every object it deleted), and `SHA256SUMS`, which
adds the files no operation made (those `--into-existing` found, and every file
of a bulk corpus) and must agree with the ledger about the rest. A run that did
not complete is refused, and so is a ledger that disagrees with `SHA256SUMS`:
the two are then from different runs.

**What it reads.** The tool's output (a file, or `-` for standard input), in a
format detected from its first line or named with `--format`:

| `--format`   | Written by                                                    | Read                                                                                                                                                                                                                                                                       |
| ------------ | ------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `bodyfile`   | `fls -r -m`, `tsk_gettimes`, fsagen                           | `:stream`, ` ($FILE_NAME)`, ` -> target`, ` (deleted)` and ` (deleted-realloc)` as The Sleuth Kit appends them; a name may hold `\|`; the digest column as an MD5 (or a SHA-256 where a tool puts one there)                                                                  |
| `l2tcsv`     | `psort -o l2tcsv`                                             | file-stat lines only (source `FILE`), in UTC; the lines of one entry fold back into one; type, link count and `(unallocated)` from the description; `md5_hash` and `sha256_hash` from the extra column when Plaso's hashers ran                                            |
| `dynamic`    | `psort` (its default output)                                  | the default fields, plus `filename`, `inode`, `is_allocated`, `md5_hash`, `sha256_hash` and `number_of_links` when added (`--additional_fields`); display names lose their `OS:`, `TSK:` or `NTFS:` prefix                                                                 |
| `timesketch` | fsagen `--timeline-format timesketch`, `psort -o json_line`  | one event per time, `fs:stat` events only, microseconds from `timestamp`; an MFT `$FILE_NAME` event is recognised as one                                                                                                                                                  |
| `jsonl`      | fsagen                                                        | everything fsagen writes, link targets and counts included                                                                                                                                                                                                                 |
| `csv`        | fsagen                                                        | everything fsagen writes                                                                                                                                                                                                                                                   |

**How paths are matched.** The tool's paths are read relative to the output
root, which is detected as the leading part that, taken off, leaves the most
paths naming something in the run (`--strip-prefix` gives it instead).
Backslashes are separators unless the scenario's own names hold one. Names are
compared without regard to case when the run wrote to a volume that does
(NTFS, ReFS, FAT, exFAT, APFS; `--case exact|fold` overrides), and because
Plaso writes a comma in a CSV value as a space, a name with a comma matches its
spaced form in `l2tcsv` and `dynamic`. Rows outside the output root, the
volume's own entries (`$MFT`, `$OrphanFiles` and the other `$` names TSK lists,
`System Volume Information`, `lost+found`, `$` streams such as `$I30`, a
directory's `.` and `..`), `$FILE_NAME` records of deleted entries or of
names the run did not leave, and streams of a deleted entry found by its
address are set aside and counted, never scored.

**What is scored**, each category with its true and false positives and
negatives, precision, recall and F1:

| Category  | One item per                                                      | Found when                                                                                                                                                                                                                                                                                   |
| --------- | ----------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `files`   | name the run left: file, directory or link, each hard link's name | the tool lists it. A name listed twice, or one where the run left nothing, is a false positive                                                                                                                                                                                              |
| `deleted` | object the run deleted                                            | the tool lists a deleted entry at its path. Several objects deleted from one path are each an item, and each deleted row is credited to the one whose times it matches best. A deleted entry under a name the run once used (a renamed file's old one) is a real trace, counted as an old name; one anywhere else is a false positive |
| `streams` | named stream on a name the run left                               | the tool lists it                                                                                                                                                                                                                                                                            |
| `times`   | time the run controls, of every name and deletion the tool found  | the tool's is within `--time-tolerance`: by default the format's resolution (1s for `bodyfile` and `l2tcsv`, 1us for `dynamic` and `timesketch`, 0 for `jsonl` and `csv`). A time the tool leaves unknown is missed; a different one is wrong, a false positive and a false negative at once |
| `hashes`  | file or stream found whose digest the run knows                   | the tool's MD5 matches, or failing that its SHA-256. A digest the tool did not compute is not held against it                                                                                                                                                                              |
| `links`   | name of a hard-linked file; symlink; junction                     | a hard-linked file's names share an inode (TSK's NTFS `entry-type-id` compared by entry) and, where the tool counts them, as many links as names; a symlink or junction points where the run made it point. A file with one name reported with more links is a false positive              |
| `filenames` | time of a name's NTFS `$FILE_NAME` that is known: one a timestomp set on an image, or any from a `--model` | the tool's `$FILE_NAME` record of the name has it within `--time-tolerance`, as for `times`. A hard-linked file's record holds a `$FILE_NAME` per name, and a tool may give any of them for any name, as The Sleuth Kit gives one for all: a row is scored against the name it agrees with best |

The report gives, per category, how many items there were, how many the tool's
output could be judged on (a time of an entry the tool did not list cannot be,
nor a digest it did not compute), and the counts and ratios; `overall` sums the
categories scored, which `--categories` picks. Then it lists up to 20 of what
each category missed, made up or got wrong, with the tool's line numbers;
`--scorecard FILE` writes all of it as JSON (`scorecard_version: 1`).
`--fail-under X` exits 3 when the overall F1 is below X.

**Which times are scored.** Only the times the run controls, as the ledger
states them: never those the ledger lists as `uncontrolled` (on Linux, the
change and creation times). Two kinds of time the ledger cannot give are left
unscored unless a model gives them: a directory's, which every entry added to or
taken from it moves at a time the ledger does not record, a file's change
time after a `rotate` renamed it or one of its hard links was deleted, and
the `$FILE_NAME` times of a name no timestomp set.
`--model FILE` takes them from a modelled timeline of the same run
(`--timeline-source modelled`, in any format above); a model that does not list
exactly the names the run left is refused as another run's.

**What a live volume can show.** A tool reading a live directory finds no
deleted entries, so `deleted` scores 0 there by design: score that category
against an image of the volume, or leave it out with `--categories`.

**How it is checked.** Every example's modelled bodyfile scores 1 in every
category against its ledger, on both platforms, with no tolerance
(`TestModelledBodyfilesScoreOne`): the check that the ledger, folded, is the
model it stands in for. A real run's modelled timeline scores 1 everywhere,
directory times included, and its observed timeline read back from disk scores
1 on everything a live volume keeps (`TestDiffOracleScoresFsagenTimelines`). A
dropped row lowers recall, a time a second off fails with no tolerance and
passes with a second's, and a row the run never made lowers precision
(`TestPerturbations`). An `fls`-shaped listing of an NTFS image of
`playbook-macro-phish`, with a mistake of every kind, has its report and
scorecard recorded (`TestGoldenReport`), and fsagen's own timelines read back
in every format (`TestFsagenTimelinesReadBack`). **Not run here: Plaso.** The
`l2tcsv`, `dynamic` and `json_line` readers follow Plaso's output modules as its
source writes them (`l2t_csv.py`, `dynamic.py`, `shared_dsv.py`,
`formatting_helper.py`), and their fixtures (`TestPlasoOutputsScoreOne`) were
written to that shape, not produced by Plaso.

**Exit status:** 0 scored, 1 error, 2 command-line error, 3 below
`--fail-under`.

## Bulk generation

Use the bulk generator when you need a fast, synthetic corpus without describing
a scenario:

```pwsh
# N items per level, depth D directories deep
fsagen --seed 7 --bulk 3 --depth 2 ./quick-bulk

# You can also emit a timeline for bulk output
fsagen --seed 7 --bulk 3 --depth 2 --timeline timeline.csv ./quick-bulk
```

What it does:

- Creates a directory fan-out up to `--depth` with `--bulk` sub-branches per
  level
- Populates each level with one file of every type in _File formats_ (txt, docx,
  png, jpg, pdf, mp4, csv, json, xml, html, log, reg, zip, exe, jsonl, syslog,
  md, eml, mbox, a Chrome profile and a Firefox one)
- Draws names and contents from `--seed`, reproducibly (see _Determinism
  contract_); dates inside files count from `--bulk-start`

Intended use:

- Quickly produce a sizeable, diverse dataset for tool demos, performance tests,
  or classroom exercises
- Warm-up data for timeline/report pipelines when a complex MO isn’t needed

Notes:

- Output size grows quickly with `--bulk` and `--depth`. Start small (e.g.,
  `--bulk 2 --depth 1` or `--bulk 3 --depth 2`).
- Bulk mode is structure/content focused; if you need precise timelines, actors,
  or conditions, prefer Playbooks.

## Development

`go run ./tools/gate` runs the checks a change must pass: `go vet`, a gofmt
check, the tests (with the race detector where cgo is available), and
`CGO_ENABLED=0` builds for Windows, Linux, macOS and FreeBSD on amd64 and arm64.
Golden files under `testdata/golden/v<generator version>/` pin generated bytes:
`dryrun/` and `bulk/` are platform-independent, `windows/` and `linux/` hold
what each records of a real file system. `go test -update` only rewrites a
golden whose input changed — output that moves for an unchanged input is a hard
failure telling you to bump `constant.GeneratorVersion`, never to edit the
fixture. Deleting a golden and recording it afresh is the only way past that
guard, and it is right only when what changed is how the harness *records* a
tree rather than what fsagen writes into one; check that the new fixture is a
permutation of the old before believing it.

Everything a run writes and reads back goes through the interfaces in
`target/`: a live directory (`sandbox`) is one target, and a disk image
(`volume/`) is another. A `volume.Volume` keeps the tree as the scenario sees
it and hands every change to a driver (`volume/fat`), which writes it through
to the image as its file system would and, once finished, reads the image
back. FAT32 and ext4 are read back through libfat and libext, opened
strict, so a chain, a long name, a FAT copy, a checksum or a block map that
is not as it should be is an error; NTFS is read with fsagen's own parser. `internal/memtarget` is a target held in memory;
`TestOneGoTargetReproducesWindowsGoldens` replays every example through it with
the capabilities of a Windows NTFS volume and checks the Windows goldens, byte
for byte, on any platform.

`docs/testing.md` maps every finding in `plan.json` to the test that closes it.
`TestConsumerAcceptance` runs `testdata/acceptance/quilldrop-lite.playbook.yaml`
and checks the eleven things fsagen's first consumer asked for, from a parseable
phishing message to a real gap in a beacon log.

### Cutting a release

1. `go run ./tools/gate`, and run the suite on the platforms whose goldens the
   change touches (see _Platform support_).
2. Close the changelog: the `## Unreleased:` sections become `###` subsections
   of one `## v<version> — <summary> (<date>)`, with a `### Verified on` saying
   which hosts ran what. Leaving them open is how five of them once piled up.
3. Write `docs/releases/v<version>.md`, which is the release body: what changed
   for someone upgrading, and whether a corpus they already generated still
   reproduces. Release notes are not in `docs_test.go`'s `docFiles` — like the
   changelog, each describes a version that has shipped and does not move with
   the tree.
4. Tag the commit you are releasing, and pass that tag to the build script. The
   version you pass names every asset and is stamped into the binaries, so
   `fsagen --version` reports the release rather than a pseudo-version.
5. `./build.sh v0.2.0` or `.\build.ps1 v0.2.0` — six binaries and a
   `SHA256SUMS` into `dist/`. Both produce the same checksums for the same
   version and toolchain, so it does not matter which one runs; each warns if
   the commit is not tagged, or is tagged as something else.
6. Publish `dist/` as the release assets, with `docs/releases/v<version>.md` as
   the body. The asset names carry the version the binaries themselves report,
   because the build fails when the two disagree.

### Dependencies

Nine direct ones, each here for a reason the standard library does not cover.
`go mod tidy` is clean, and the whole product builds with `CGO_ENABLED=0`.

| Module                          | Why                                                                                                                                             |
| ------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------- |
| `go.yaml.in/yaml/v3`            | YAML with `KnownFields` (an unknown key is an error) and a `Node` pass that gives every error a line and column. `gopkg.in/yaml.v2` has neither |
| `github.com/glebarez/go-sqlite` | a `database/sql` driver for SQLite with no cgo, for the Chrome and Firefox profiles and bulk mode's databases                                   |
| `github.com/jung-kurt/gofpdf`   | writes the PDFs, with the document metadata pinned so two renders match                                                                         |
| `golang.org/x/sys`              | `NtCreateFile` and `FILE_BASIC_INFO` on Windows, `statx` on Linux, `Birthtimespec` on the BSDs, and the last-access registry value              |
| `golang.org/x/text`             | Unicode case folding and NFC normalisation, so the portability check catches names that collide on a case-insensitive or normalising volume     |
| `github.com/aoiflux/libtable`   | the MBR entry, CHS and partition-type codecs and constants for disk images, from the owner's own partition-table parser                         |
| `github.com/aoiflux/libext`     | reads ext4 images back, strict, and gives the writer its constants, crc32c checksums, time codec and backup-group rule                          |
| `github.com/aoiflux/libfat`     | reads FAT32 images back, strict, and gives the writer its constants and its time and long-name checksum codecs                                  |
| `github.com/aoiflux/libvhdi`    | the VHD footer, its geometry, timestamp and checksum codecs, from the owner's own VHD parser                                                    |

**Test-only, in their own module.** `internal/conformance` reads what fsagen
writes with parsers fsagen did not write, so each binary format is checked
against someone else's reading of its specification too. It is a separate
module (`go -C internal/conformance test ./...`, run by the gate), so none of
these is a dependency of fsagen and none is in its `go.mod`:

| Module                                 | Reads                                                                             | Licence    |
| -------------------------------------- | --------------------------------------------------------------------------------- | ---------- |
| `github.com/parsiya/golnk`             | `lnk`                                                                             | Apache-2.0 |
| `www.velocidex.com/golang/go-prefetch` | `prefetch`, and XPRESS Huffman with its own decoder                               | Apache-2.0 |
| `www.velocidex.com/golang/evtx`        | `evtx`                                                                            | Apache-2.0 |
| `www.velocidex.com/golang/regparser`   | `regf`                                                                            | Apache-2.0 |
| `github.com/richardlehane/mscfb`       | the compound file inside `docm` and `xlsm` (the VBA project)                      | Apache-2.0 |
| `www.velocidex.com/golang/go-ntfs`     | NTFS images; and a live NTFS volume, raw, to read slack back (administrator only) | Apache-2.0 |
| `github.com/diskfs/go-diskfs`          | FAT32 and ext4 images, bare and inside an MBR-partitioned VHD                     | MIT        |
| `github.com/dsoprea/go-ext4`           | ext4 images (it reads only volumes with `flex_bg`)                                | MIT        |

## Citation

If fsagen is useful in your work, please cite the paper:

> Gogia, G. and Rughani, P., **File System Artefacts Generator (FSAGen): Towards
> Faster Forensic Tool Testing**, in _Information Security, Privacy and Digital
> Forensics_, Springer Nature Singapore, 2026, pp. 239-248.
>
> <https://link.springer.com/chapter/10.1007/978-981-96-9443-3_17>

<details>
<summary>BibTeX</summary>

```bibtex
@InProceedings{10.1007/978-981-96-9443-3_17,
author="Gogia, Gaurav
and Rughani, Parag",
editor="Gohil, Bhavesh N.
and Patel, Sankita J.
and Chaudhary, Naveen Kumar
and Iyengar, S. S.
and Modi, Chirag
and Padhya, Mukti",
title="File System Artefacts Generator (FSAGen): Towards Faster Forensic Tool Testing",
booktitle="Information Security, Privacy and Digital Forensics",
year="2026",
publisher="Springer Nature Singapore",
address="Singapore",
pages="239--248",
abstract="Software testing is one of the most fundamental steps in any software development lifecycle. The larger the scale, the more testing is required to ensure the correctness and reliability of the software. In the case of digital forensics, one of the main problems that researchers face is the availability of datasets for testing the reliability of the product they are evaluating. Different forensic tools with similar features may present different results even with similar inputs. This makes it extremely important to have standardised and reproducible datasets. This research explores synthetic dataset generators and introduces a novel command-line interface (CLI) tool for generating file system artefacts. The tool aims to facilitate the quick and convenient creation of synthetic datasets to aid in the validation of file system forensic tools. By offering a simplified and cross-platform solution, this tool addresses the need for standardised datasets in digital forensics research and enhances the reliability and accuracy of forensic tool evaluations.",
isbn="978-981-96-9443-3"
}
```

</details>
