# File System Artifacts Generator (fsagen)

Deterministic generator for creating diverse file-system artifacts to test forensic tools (Autopsy, EnCase, FTK, etc.). Use YAML manifests for simple operations, playbooks for complex modus operandi simulation, or the bulk generator for a quick synthetic corpus with no YAML required.

## Features

- Deterministic output with `--seed`: the same seed and inputs give byte-identical files (see *Determinism contract*)
- Manifest mode: simple, declarative file operations (create/update/append/delete/mace/rename/copy/truncate/rotate/ads/motw/email/ansible-vault)
- Playbook mode: complex timelines with actors, timed steps, and templating
- Bulk mode: super-simple synthetic corpus generation with `--bulk` and `--depth`
- Author content in real files with `content_file`, shared across scenarios with `--vars-file`
- Real RFC 5322 email: MIME multipart, threading headers, base64 attachments, `.eml` and `.mbox`
- Real PDFs from Markdown, with full control of document metadata
- Real `$ANSIBLE_VAULT;1.1;AES256` files that `ansible-vault` can decrypt
- Extensive file type support: documents, logs, archives, media, emails, Windows artifacts
- All four timestamps (access, modification, change, creation) taken from the scenario on Windows NTFS, access and modification elsewhere; set, then settled and verified after the last operation (see *Timestamps*)
- Octal file permissions
- Windows-specific: NTFS ADS and Mark-of-the-Web (MoTW)

## Install

```pwsh
go install github.com/aoiflux/fsagen@latest
```

or build from source (pure Go; `CGO_ENABLED=0` works on Windows, Linux, macOS and FreeBSD):

```pwsh
go build -v -o fsagen.exe
```

Released under the MIT License (see `LICENSE`).

## Usage

fsagen can generate artifacts using a manifest, a playbook, or the bulk generator:

```pwsh
fsagen [OPTIONS] <output-path>
```

**Options:**
- `--seed N` - PRNG seed for deterministic generation (default: 1)
- `--manifest FILE` - Execute a YAML manifest (simple file operations)
- `--playbook FILE` - Execute a YAML playbook (complex modus operandi)
- `--bulk N` - Super-simple bulk generation: N items per level (no YAML)
- `--depth D` - Bulk generation depth (default: 1)
- `--bulk-start T` - Bulk generation: the RFC 3339 time the dates inside generated files count from (default `2021-01-01T00:00:00Z`)
- `--vars-file FILE` - YAML map of variables exposed to templates as `${VAR:name}`
- `--var k=v` - Set one template variable (repeatable; overrides `--vars-file`)
- `--validate` - Check the manifest or playbook and exit; nothing is written
- `--dry-run` - Print the compiled operations (resolved paths, times, content hashes) as JSON lines and exit
- `--clean` - Empty a non-empty output directory before generating
- `--into-existing` - Generate into a non-empty output directory, merging (recorded in the run manifest)
- `--on-unsupported fail|skip` - What to do with operations the platform cannot perform (default `fail`, before anything is written; `skip` generates the rest and records each skipped operation)
- `--allow-nonportable` - Allow paths that only work on some platforms (reserved device names, case-only differences, very long paths)
- `--allow-external-sources` - Allow `content_file`, email bodies and attachments from outside the YAML file's directory
- `--meta DIR` - Where to write `run-manifest.json`, `SHA256SUMS`, `ledger.jsonl` and `run-info.json` (default: `<output-path>.fsagen`, beside the output)
- `--timeline FILE` - Write a timeline of the output after generating; `FILE` must be outside the output directory
- `--timeline-format csv|txt|bodyfile|macb` - Timeline format (default: from the extension: `.csv`, `.txt`, `.bodyfile`, `.body`, `.macb`; any other extension is an error)
- `--generate-schema` - Write JSON schemas for manifests and playbooks and exit (`--schema-out DIR`, default `schemas`)
- `--version` - Print the module version, generator version and build

**Exit status:** 0 success, 1 generation failed, 2 command-line error. Diagnostics go to stderr.

**Output directory:** must be a directory or not exist. A non-empty one is refused unless `--clean` or `--into-existing` is given.

**Run records:** every generation writes three files beside the output (never inside it):

- `run-manifest.json`: generator version, Go version, seed, SHA-256 of every input read, options, capabilities (including which times can be set), skipped operations and dropped time fields, the digests of `SHA256SUMS` and `ledger.jsonl`, and a status that reads `running` until the run ends and then `complete` or `failed`. A tree whose run manifest does not say `complete` is not a finished corpus. It holds no absolute path, host name or wall-clock time, so it is itself reproducible.
- `SHA256SUMS`: the SHA-256 of every file and NTFS stream in the output (`path:stream`), in `sha256sum` format, sorted by path. Check a corpus with `sha256sum -c` from inside the output directory.
- `ledger.jsonl` (manifest and playbook runs): one line per operation: the object it acted on (a number that survives renames), its content SHA-256 before and after, its size and streams, the times the scenario intends it to have, which times were left to the file system (`uncontrolled`), and whether it was done, a no-op or skipped. A failed run still writes the ledger up to the failing operation.
- `run-info.json`: what is not reproducible: build revision, host, OS, file system, the host's last-access-time policy, absolute paths and start and finish times.

**Examples:**

Check a playbook, then see exactly what it would do:
```pwsh
fsagen --playbook examples/playbook-basic.yaml --validate
fsagen --playbook examples/playbook-basic.yaml --dry-run
```

Regenerate the JSON schemas in `schemas/` (they document the input format for editors; fsagen validates its input itself):
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

- start (top level, optional): RFC 3339, or `now` for a run that cannot be reproduced. It is the reference time for operations without an `mtime` or `atime`: when they happen (see *Timestamps*), what `${DATE}` formats and what an unpinned pdf's dates and an email's `Date` default to. With neither, those are errors; fsagen never reads the wall clock for them.

- action: `create|update|append|truncate|rotate|delete|mace|rename|copy|ads|motw|email|ansible-vault`
- path: target path relative to output root (see *Paths* below)
- id: name for what this action creates or renames, so a later action can refer to it
- ref / refs: instead of `path`, act on the one path (`ref`) or every path (`refs`) created under an `id` that still exists; ids follow renames
- missing_ok: for `delete`, a path that does not exist is a recorded no-op instead of an error
- type: `file|dir` (for create)
- ext: file extension to append if `path` has no extension
- content: literal content (optional); `content: ''` writes an empty file
- content_file: load content from a file inside the manifest's directory (optional)
- content_len: size of deterministic random content, at least 1. With no content of any kind, the default is 1024 characters (256 for `append`, 128 for `ads`)
- render: run `${...}` substitution over the content. Defaults to `true` for inline
  `content` and `false` for `content_file`, because scripts and PEM keys contain
  `${...}` sequences of their own that must survive verbatim
- mode: octal file permissions, e.g. `"0600"` (default 0644 files, 0755 directories)
- format: `raw` (default) or `pdf`; for the `email` action, `eml` or `mbox`
- pdf: document metadata for `format: pdf` — see below
- email: message definition for the `email` action — see below
- vault: password, vault_id and salt for the `ansible-vault` action
- atime/mtime/ctime/crtime: RFC 3339 access, modification, change and creation (birth) times, fractions of a second kept. They override what the action would otherwise set (see *Timestamps*). `ctime` needs Windows on NTFS or ReFS and `crtime` Windows; elsewhere either is a pre-flight error unless `--on-unsupported=skip`, which drops the field and records that
- new_path: new location for `rename`, `rotate` or `copy`
- stream: ADS stream name (for `ads` action, Windows-only)
- zone_id, host_url, referrer_url: for `motw` action (Windows-only)

A manifest may also carry a top-level `variables:` map.

**Input is strict.** fsagen refuses to generate anything from an input it would
have to guess about, and says where the problem is (file, line and column, the
operation or step/action, and the field). All of these are errors:

- an unknown or duplicated key, or a key the action does not use (for example
  `stream` on `create`, or times on `rename`, which keeps a file's times)
- a time that is not RFC 3339, a malformed or negative duration, `zone_id`
  outside 0-4, an invalid `mode`, `content_len` below 1
- an undefined `${VAR:name}`, an unknown or unterminated `${...}` token
  (write `$${` for a literal `${`)
- `delete` of a path that does not exist (unless `missing_ok: true`), `update`
  or `truncate` of a missing file (use `create`), `ads`/`motw` on a missing file,
  `rename`/`copy`/`rotate` onto a path that already exists, deleting a non-empty
  directory. `append` creates a missing file, as a log comes into being.
- random content (`content_len`, or no content at all) under an extension that
  promises a structured format fsagen cannot generate yet (`.exe`, `.zip`,
  `.png`, `.jpg`, `.sqlite`, `.docx`, `.mp4`, `.eml`, ...). Add `format: text`
  to write placeholder text on purpose, or give `content`/`content_file`.
- an operation the platform cannot perform (`ads`/`motw` off NTFS), unless
  `--on-unsupported=skip`

**Paths** use `/` on every platform and are relative to the output root (and
to the actor's `base` in playbooks). A trailing `/` means a directory. `..` is
allowed only while it stays inside the root. Backslashes, `:` (drive letters,
stream syntax), absolute paths, NUL and names ending in a dot or space are
refused everywhere. Unless `--allow-nonportable` is given, so are reserved
Windows device names (`CON`, `NUL`, `COM1.log`, ...), two paths that differ
only by case or Unicode normalisation, and paths over 200 characters.

Files read by a scenario (`content_file`, `body_text_file`, `body_html_file`,
`attachments[].source_file`) must lie inside the directory of the YAML that
names them, unless `--allow-external-sources` is given; `attachments[].source_root`
must name a file already generated in the output.

**Examples:**
- `examples/manifest-basic.yaml` - Basic create/update/delete operations
- `examples/manifest-bulk-simple.yaml` - Quick bulk file generation across multiple types

## Playbook schema

YAML with a timeline and actors:

- **start** (required): RFC3339, or "now" for a run that cannot be reproduced (recorded as such in the run manifest)
- **variables**: Global variables for templating (map of key-value pairs)
- **subsecond_jitter**: `true` adds a seeded fraction of a second (in 100 ns steps) to every time derived from the schedule, so a corpus does not have every timestamp on a whole second. Explicit times are never jittered, and the same seed gives the same fractions (`TestJitterDeterministicAndNeverOnExplicit`)
- **actors**: List of { name, base, variables }
	- name: Actor identifier (unique, case-insensitively)
	- base: Base directory for this actor's files
	- variables: Actor-specific variables (override global variables)
- **steps**: Timeline steps
	- actor: Actor name
	- offset: time.Duration from start for first occurrence (e.g., 5m, 2h)
	- every: Repeat interval; required when `repeat` is above 1 (`every: 0s` stacks the occurrences on one instant on purpose)
	- repeat: Number of occurrences (default 1)
	- condition: Step-level conditional execution (`odd`, `even`, `first`, `last`), tested against the iteration index
	- batch_count: Generate N files in this step (multiplies actions)
	- actions: List of operations with extras:
		- offset: time.Duration relative to the step occurrence
		- condition: Action-level conditional execution, tested against the batch index
		- template: Predefined content template (`email`, `log`, `script`, `doc`) for create/update/append; cannot be combined with `content` or `content_file`
		- All standard manifest fields (action, path, id, ref, content, etc.)

Operations run in time order; operations scheduled for the same instant keep
the order they are written in (`TestPlaybookRunsInTimeOrder`). `${SEQ}` counts
every action in the order it is written, so two actions rendering
`file-${SEQ}.txt` name two different files: give the first an `id` and refer
to it with `ref`/`refs`.

Operations supported: `create|update|append|truncate|rotate|delete|mace|rename|copy|ads|motw|email|ansible-vault` (all operations work in both manifest and playbook). `ads` and `motw` are Windows-only. Each action happens at its scheduled time, which sets the times of what it creates or changes (see *Timestamps*); explicit `atime`/`mtime`/`ctime`/`crtime` override them.

Durations accept `d` and `w` in addition to Go's own units, so a step can be
`offset: 2d6h` rather than `54h`.

**Playbook templating:**
- `${SEQ}` - Monotonic sequence counter
- `${RND:N}` or `${RANDOM:N}` - Deterministic random string of length N (N at least 1)
- `${DATE:layout}` - The action's scheduled time (in a manifest, the operation's `mtime`, else the manifest's `start`; with neither it is an error) formatted with a Go layout (e.g., `${DATE:2006-01-02T15:04:05Z07:00}`)
- `${ACTOR}` - Current actor name (playbooks only)
- `${VAR:name}` - Variable substitution (from global or actor-specific variables); undefined names are errors
- `${UUID}` - Deterministic random version-4 UUID
- `${IP}` - Deterministic IP address (192.168.x.x range)
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
    condition: even  # Only runs on even iterations (0, 2, 4, ...)
    actions:
      - action: create
        path: file-${ITER}.txt
        condition: odd  # Further filtering at action level
```

3. **Batch Operations**: Generate multiple files in one step
```yaml
steps:
  - actor: ransomware
    batch_count: 100  # Creates 100 files
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
    template: email  # a simple LF-terminated message; use the email action for RFC 5322
```

Available templates: `email`, `log`, `script`, `doc`

**Example playbooks:**

- `examples/playbook-basic.yaml` - Simple two-actor workflow
- `examples/playbook-adversary-data-theft.yaml` - Stages documents, archives, writes exfil logs, backdates
- `examples/playbook-log-tampering.yaml` - Creates baseline logs, injects tampered entries, backdates, deletes
- `examples/playbook-persistence-artifacts.yaml` - Drops startup-like files and .reg exports
- `examples/playbook-email-and-archive.yaml` - Creates emails/images, archives, deletes originals
- `examples/playbook-log-rotate-and-truncate.yaml` - Demonstrates log rotation and truncation
- `examples/playbook-windows-ads-motw.yaml` - Adds NTFS ADS and Mark-of-the-Web (Windows-only)
- `examples/playbook-email-thread.yaml` - Four-message RFC 5322 thread as `.eml` and `.mbox`, with a generated PDF attachment
- `examples/playbook-comprehensive-ransomware.yaml` - **Advanced**: Full ransomware attack with variables, batching, conditions, and templates
- `examples/playbook-insider-threat-exfil.yaml` - **Advanced**: 7-day insider threat scenario with repeated access patterns
- `examples/playbook-malware-lifecycle.yaml` - **Advanced**: 48-hour malware infection lifecycle with beaconing and anti-forensics

## Email, PDF and Ansible vault

### `email` action

Builds a real RFC 5322 message: CRLF throughout, quoted-printable bodies,
base64 attachments, and a MIME shape chosen to fit the content
(`multipart/mixed` wrapping a `multipart/alternative` when there are both
bodies and attachments). Writes a `.eml`, or appends to a `.mbox` with mboxrd
`>From ` escaping.

```yaml
- action: email
  path: Users/priyan/Mail/Inbox/0003.eml
  format: eml                    # or mbox (appends); inferred from the extension
  email:
    from: "Dana Reyes <d.reyes@aperture-talent.example>"
    to: ["Priyan N <priyan.nair@northwindlogistics.example>"]
    cc: ["scheduling@aperture-talent.example"]
    return_path: "bounces+0188@aperture-talent.example"
    subject: "Re: technical assessment"
    date: "2026-02-25T10:05:00+05:30"     # RFC3339; also the file's times
    message_id: "<c3f1a97b@aperture-talent.example>"
    in_reply_to: "<b2e0d8f1@northwindlogistics.example>"
    references: ["<CAF9a2c1e@aperture-talent.example>", "<b2e0d8f1@northwindlogistics.example>"]
    headers:                     # an ordered LIST, so Received: can repeat
      - name: Received
        value: "from mx01... ; Wed, 25 Feb 2026 10:05:14 +0530"
      - name: Authentication-Results
        value: "spf=pass; dkim=pass; dmarc=pass"
    body_text_file: content/msg-03.txt
    body_html_file: content/msg-03.html
    attachments:
      - source_file: content/brief.pdf    # inside the manifest/playbook's directory
        name: "Technical_Assessment_Brief.pdf"
      - source_root: reports/review.pdf   # a file an earlier step generated in
                                          # the output root
```

Author-supplied `headers` are emitted first, in order, then the structured
fields — so a `Received:` chain and `Authentication-Results` land where a real
MTA would have written them. A header value that already contains newlines
keeps the author's folding.

MIME boundaries are drawn from the operation's own random stream, so `--seed`
reproducibility holds across the message body too. A message with no `date`
is dated at its scheduled time (in a manifest: its `mtime`, else `start`).

`examples/playbook-email-thread.yaml` is a worked four-message thread using
all of the above.

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
    created: "2026-03-14T02:33:12+05:30"   # RFC3339; pin these for
    modified: "2026-03-14T02:33:12+05:30"  # byte-identical output
    page_size: A4                          # A4 (default), A3, A5, Letter
```

Inline markers are **not** interpreted or stripped. A report body carrying
`Wint3r-R0t****-2026` keeps its asterisks; silently rewriting a redaction mask
into something that reads like a real password would be worse than showing a
literal asterisk.

Unpinned dates default to the action's scheduled time (in a manifest: its
`mtime`, else `start`), and one given date stands in for the other, so two
renders of the same input always produce byte-identical files. That is what lets one artifact be attached to a message
and land with the same SHA256 as its copy on disk.

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
    vault_id: ""     # non-empty selects the 1.2 header form
    salt: ""         # optional 32-byte hex; when empty it comes from the seed
```

```bash
printf '%s' 'the-password' > /tmp/vpw
ansible-vault view --vault-password-file /tmp/vpw out/infra/group_vars/prod/vault.yml
```

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

| Action | Times |
|---|---|
| `create`, `ansible-vault`, `email` to an `.eml` | born at T: all four times are T (creating a file that exists makes it anew) |
| `update`, `append`, `truncate`, a later message appended to an `.mbox` | access, modification and change become T; creation is kept |
| `mace` | only the times it names (at least one) |
| `ads`, `motw` | the file's times do not change |
| `rename` | the object keeps its times; its change time becomes T |
| `rotate` | the rotated file is renamed (keeps its times); the empty file left at the old path is born at T |
| `copy` | the copy is born at T but keeps its source's modification time, and its named streams |
| `delete` | the object is stamped with its final times just before it is removed; `atime`/`mtime` on a delete set the directory it leaves |
| directories | born with the operation that creates them, explicitly or as a missing parent; every entry added, removed or renamed in them sets their modification and change times to T; a `mace` on a directory holds until the next such event |

A manifest operation with no time of its own and no `start` has no T: its
times are left to the file system, and the ledger lists them as uncontrolled.

After each operation fsagen stamps what it touched. After the last one it
settles the whole tree, files first and then directories deepest first, and
reads every time back; any time that differs from the scenario by more than
the volume's resolution fails the run and lists the differences. On Windows
the times are set through handles opened relative to the output root, all
four in one call (`FILE_BASIC_INFO`).

What can be set:

| | Windows (NTFS, ReFS) | Windows (FAT, exFAT) | Linux, macOS, FreeBSD |
|---|---|---|---|
| access, modification | yes | yes | yes |
| creation (`crtime`) | yes | yes | no |
| change (`ctime`) | yes | no (not stored) | no |

A time the platform cannot set is never faked: if the input asks for it, the
run stops before writing (or, with `--on-unsupported=skip`, drops the field
and records it in the run manifest); if the scenario only implies it, the
ledger lists it as uncontrolled.

Limits:

- NTFS keeps a second set of times in each `$FILE_NAME` attribute, which no
  user-mode call can set. The run manifest says `filename_times_controlled:
  false`.
- The output directory's own times are never set (`root_times_controlled:
  false`).
- With last-access updates on (`NtfsDisableLastAccessUpdate`, recorded in
  `run-info.json`), anything that reads the output afterwards moves its access
  times. fsagen's own reads (digests, the ledger, the timeline) leave them
  alone. If another process reads files while the run settles, fsagen settles
  again a few times before failing, and the error says so.
- `mode` is applied when a file is written; times are stamped after it, so a
  chmod does not disturb them. Windows honours only the write bit; the field
  matters on Linux output.

Verified by `TestCreateSetsCreationTime`, `TestMaceSetsFourTimes`,
`TestMaceLeavesUnnamedTimes`, `TestQuilldropLiteStompCount`,
`TestAdsAndMotwKeepTimes`, `TestDirTimesFollowLastChildEvent`,
`TestRotateKeepsRotatedTimes`, `TestCopySemantics`, `TestCopyCarriesStreams`,
`TestEmailTimesFromDate`, `TestNanoPrecisionRoundTrip`,
`TestDeleteStampsBeforeRemoval`, `TestManifestReferenceTime`,
`TestVerifyPassMatchesModel`, `TestLedgerCreateStompRenameDelete`,
`TestDefaultCrtimeRecordedUncontrolled`, `TestExplicitCrtimeUnsupportedPreflight`,
`TestDroppedTimeFieldRecorded`, `TestRunManifestTimeCapabilities`,
`TestSettleRetriesOnlyForAccessTimes`,
`TestChangeTimeSticks` and `TestTimelinePassKeepsAtime`. The creation and
change time tests run on Windows; on Linux and macOS they are skipped, and
the release check runs the rest there.

## Determinism contract

For one **generator version** (`fsagen --version`), built with the Go
toolchain pinned in `go.mod` (`GOTOOLCHAIN=go1.27.0` forces it; the Go version
is recorded in `run-manifest.json`), the same `--seed` and the same **inputs**
(the YAML file, the vars file, `--var` values, and every file read through
`content_file`, email bodies or attachments, all listed by SHA-256 in
`run-manifest.json`), fsagen produces byte-identical:

1. content of every regular file and named stream it writes, as listed in
   `SHA256SUMS`;
2. set of relative paths;
3. `--dry-run` listing (with each operation's intended times),
   `ledger.jsonl` and `run-manifest.json`.

This holds on every platform, for every operation the platform supports.
Which operations were skipped as unsupported is recorded, and follows from the
capability set; skipping one changes no other file's bytes. Bulk mode is
covered too (with `--bulk-start` as one more input).

How: every random value is drawn from a ChaCha8 stream keyed by the seed and
the name of what it is for (the operation's `id` or the hash of its YAML,
its iteration and batch, the field, the token), so adding, removing or
reordering an unrelated action changes nothing else. Nothing reads the wall
clock except `start: now`, which marks the run as not reproducible.

**Not covered:** anything read back from the live file system: timelines;
the times on disk themselves (the ledger states what they are meant to be,
and the verify pass checks them within the run); times the ledger lists as
uncontrolled; NTFS `$FILE_NAME` times; file IDs, allocation and directory order; `run-info.json`; runs with
`start: now`; files already present under `--into-existing`.

Verified by `TestDeterminismHarness` (every example and bulk mode, two runs
into different directories, and a different seed), the version-pinned goldens
(`TestExampleContentGoldens`, which also pins each example's ledger, and
`TestDryRunGoldens`), `TestBulkDeterministic`,
`TestNoWallClockInContent`, `TestInsertingUnrelatedActionLeavesOtherFilesUnchanged`
and `TestCrossCapabilityContentEquality`. It has been run on Windows; the
Linux and macOS runs are part of the release check.

## Supported File Types

Bulk mode writes these types. Most are structurally valid; the exceptions are
called out:

- **Documents**: .txt, .md, .docx, .pdf
- **Data**: .csv, .json, .jsonl, .xml, .html
- **Logs**: .log, .syslog, .jsonl
- **Media**: .png; .mp4 (holds text, not video)
- **Archives**: .zip
- **Email**: .eml, .mbox
- **Browser history**: Chrome `urls`/`visits` (.db) and Firefox `moz_places` (.sqlite) databases
- **Windows**: .reg; .exe (a 256-byte DOS stub, not a loadable PE)

Manifests and playbooks write text, PDFs (`format: pdf`), email (`action: email`),
Ansible vaults and NTFS streams (`ads`, `motw`); see *Input is strict* for the
formats they refuse to fake.

## Forensic Timeline Generation

After generating artifacts, fsagen can automatically create forensic timelines for analysis:

```pwsh
fsagen --playbook scenario.yaml --timeline output.csv ./artifacts
```

**Timeline Formats:**

- **CSV** (`.csv`): Structured data with all metadata (path, size, mode, timestamps, MD5, type, ADS)
- **TXT** (`.txt`): Human-readable format with detailed file information
- **Bodyfile** (`.bodyfile` or `.body`): The Sleuth Kit's bodyfile layout, for `mactime -b`
- **MACB** (`.macb`): modified, accessed and changed events listed separately

The format comes from `--timeline-format` or the extension; an unknown extension
is an error, never a silent fall-back. The timeline file must lie outside the
output directory, or it would describe itself.

**Timeline Features:**

- MD5 hash calculation for all files (except files > 100MB)
- Access and modification times, plus a third time that is the creation time on Windows and the inode change time on Unix (the bodyfile currently writes it in both its ctime and crtime columns)
- Every named NTFS stream on each file (Windows; `TestTimelineListsEveryStream`)
- Reading files for their digests and listing directories does not move their access times (Windows; Linux when you own the files; `TestTimelinePassKeepsAtime`)
- Chronologically sorted by modification time (equal times by path); all times in UTC
- **Timeline-only mode**: Generate timelines from an existing directory without regenerating it

**Example workflows:**

```pwsh
# Generate ransomware scenario with CSV timeline
fsagen --seed 999 --playbook examples/playbook-comprehensive-ransomware.yaml --timeline ransomware.csv ./scene

# Create timeline compatible with mactime
fsagen --playbook examples/playbook-malware-lifecycle.yaml --timeline evidence.bodyfile ./analysis
mactime -b evidence.bodyfile -d > detailed-timeline.txt

# Generate MACB timeline for temporal analysis
fsagen --playbook examples/playbook-insider-threat-exfil.yaml --timeline investigation.macb ./case

# Timeline-only mode: generate timeline from existing artifacts (no regeneration)
fsagen --timeline existing-timeline.csv ./already-generated-folder
```

**Timeline-only mode:**

If you've already generated artifacts but forgot to create a timeline, you can generate one later without regenerating the artifacts:

```pwsh
# Generate timeline from existing folder
fsagen --timeline my-timeline.csv ./existing-artifacts

# Different formats
fsagen --timeline analysis.txt ./crime-scene
fsagen --timeline evidence.bodyfile ./investigation
fsagen --timeline temporal.macb ./case-folder
```

This scans the folder, collects all file metadata, calculates MD5 hashes, and outputs the timeline in your chosen format—no artifact regeneration needed.

See `examples/TIMELINE_EXAMPLES.md` for more timeline generation examples.

## Bulk Generation (no YAML)

Use the bulk generator when you need a fast, synthetic corpus without describing a scenario:

```pwsh
# N items per level, depth D directories deep
fsagen --seed 7 --bulk 3 --depth 2 ./quick-bulk

# You can also emit a timeline for bulk output
fsagen --seed 7 --bulk 3 --depth 2 --timeline timeline.csv ./quick-bulk
```

What it does:
- Creates a directory fan-out up to `--depth` with `--bulk` sub-branches per level
- Populates each level with many file types (txt, docx, png, pdf, mp4, csv, json, xml, html, log, reg, zip, exe, jsonl, syslog, md, eml, mbox, Chrome .db, Firefox .sqlite)
- Draws names and contents from `--seed`, reproducibly (see *Determinism contract*); dates inside files count from `--bulk-start`

Intended use:
- Quickly produce a sizeable, diverse dataset for tool demos, performance tests, or classroom exercises
- Warm-up data for timeline/report pipelines when a complex MO isn’t needed

Notes:
- Output size grows quickly with `--bulk` and `--depth`. Start small (e.g., `--bulk 2 --depth 1` or `--bulk 3 --depth 2`).
- Bulk mode is structure/content focused; if you need precise timelines, actors, or conditions, prefer Playbooks.

## Development

`go run ./tools/gate` runs the checks a change must pass: `go vet`, a gofmt
check, the tests (with the race detector where cgo is available), and
`CGO_ENABLED=0` builds for Windows, Linux, macOS and FreeBSD on amd64 and arm64.
Golden files under `testdata/golden/v<generator version>/` pin generated bytes;
`go test -update` only rewrites a golden whose input changed.

### Related Research Paper
https://link.springer.com/chapter/10.1007/978-981-96-9443-3_17

### Recommended Citation
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
