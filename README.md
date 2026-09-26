# File System Artifacts Generator (fsagen)

Deterministic generator for creating diverse file-system artifacts to test forensic tools (Autopsy, EnCase, FTK, etc.). Use YAML manifests for simple operations, playbooks for complex modus operandi simulation, or the bulk generator for a quick synthetic corpus with no YAML required.

## Features

- Deterministic output with `--seed`: the same seed and inputs give byte-identical files (see *Determinism contract*)
- Manifest mode: simple, declarative file operations (create/update/append/edit/delete/mace/rename/copy/truncate/rotate/archive/ads/motw/email/ansible-vault)
- Playbook mode: complex timelines with actors, timed steps, and templating
- Bulk mode: super-simple synthetic corpus generation with `--bulk` and `--depth`
- Author content in real files with `content_file`, shared across scenarios with `--vars-file`
- Files a tool can actually parse: PE executables, zip, PNG, JPEG, MP4, docx, PDF, and Chrome and Firefox history databases. Every one of them is read back in the test suite — by `debug/pe`, `archive/zip`, `image/png`, `image/jpeg`, a box walk, SQLite — and fsagen refuses the formats it cannot build rather than writing random bytes under a name that promises one (see *File formats*)
- Real RFC 5322 email: MIME multipart, threading headers, base64 attachments, `.eml` and `.mbox`
- Real PDFs from Markdown, with full control of document metadata
- Real `$ANSIBLE_VAULT;1.1;AES256` files that `ansible-vault` can decrypt
- `archive` zips what the scenario staged, and `edit` cuts lines back out of a log
- All four timestamps (access, modification, change, creation) taken from the scenario on Windows NTFS, access and modification elsewhere; set, then settled and verified after the last operation (see *Timestamps*)
- Forensic timelines in The Sleuth Kit's bodyfile, a mactime-style MACB listing, CSV, JSON lines and text, with four times per entry and every NTFS stream; observed (read back from disk) or modelled (what the scenario intends, deleted files included, byte-identical on every run)
- A ledger of every operation and an answer key of what a tool should find, beside the output
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
- `--meta DIR` - Where to write `run-manifest.json`, `SHA256SUMS`, `ledger.jsonl`, `answer-key.jsonl` and `run-info.json` (default: `<output-path>.fsagen`, beside the output)
- `--timeline FILE` - Write a timeline of the output after generating; `FILE` must be outside the output directory
- `--timeline-format csv|txt|bodyfile|macb|jsonl` - Timeline format (default: from the extension: `.csv`, `.txt`, `.bodyfile`, `.body`, `.macb`, `.jsonl`; any other extension is an error)
- `--timeline-source observed|modelled` - `observed` (default) reads the output back from disk; `modelled` writes what the scenario intends, including the objects it deleted, and is the same bytes on every run (needs `--manifest` or `--playbook`). See *Forensic Timeline Generation*
- `--hash-limit N` - Observed timeline: leave out the MD5 of files and streams larger than N bytes (default: hash everything)
- `--generate-schema` - Write JSON schemas for manifests and playbooks and exit (`--schema-out DIR`, default `schemas`)
- `--version` - Print the module version, generator version and build

**Exit status:** 0 success, 1 generation failed, 2 command-line error. Diagnostics go to stderr.

**Output directory:** must be a directory or not exist. A non-empty one is refused unless `--clean` or `--into-existing` is given.

**Run records:** every generation writes three files beside the output (never inside it):

- `run-manifest.json`: generator version, Go version, seed, SHA-256 of every input read, options, capabilities (including which times can be set), skipped operations and dropped time fields, the digests of `SHA256SUMS`, `ledger.jsonl` and `answer-key.jsonl`, the timeline written after the run (its source and format, and for a modelled one its digest), and a status that reads `running` until the run ends and then `complete` or `failed`. A tree whose run manifest does not say `complete` is not a finished corpus. It holds no absolute path, host name or wall-clock time, so it is itself reproducible.
- `SHA256SUMS`: the SHA-256 of every file and NTFS stream in the output (`path:stream`), in `sha256sum` format, sorted by path. Check a corpus with `sha256sum -c` from inside the output directory.
- `ledger.jsonl` (manifest and playbook runs): one line per operation: the object it acted on (a number that survives renames; for a rotate, also the object it moved aside), its kind, its content SHA-256 before and after (and MD5 after), its size and streams, the stream an `ads` or `motw` wrote, the times the scenario intends it to have, which of them the operation stated itself (`explicit`), which were left to the file system (`uncontrolled`), and whether it was done, a no-op or skipped. A failed run still writes the ledger up to the failing operation.
- `answer-key.jsonl` (complete manifest and playbook runs): what a tool examining the output should find, derived from the ledger and the model, one fact per line: each object `created`, `modified` (content), `renamed` (with `from`), `deleted`, `stomped` (a `mace`, with the fields it set), each named `stream` written, and each object that ends with an `mtime_before_crtime` (a copy has one without being stomped, as copies do). Directories made only as missing parents are not listed as created. `TestAnswerKeyEntries` checks every kind of fact.
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

- action: `create|update|append|edit|truncate|rotate|delete|mace|rename|copy|archive|ads|motw|email|ansible-vault`
- path: target path relative to output root (see *Paths* below)
- id: name for what this action creates or renames, so a later action can refer to it
- ref / refs: instead of `path`, act on the one path (`ref`) or every path (`refs`) created under an `id` that still exists; ids follow renames
- missing_ok: for `delete`, a path that does not exist is a recorded no-op instead of an error
- type: `file|dir` (for create)
- ext: file extension to append if `path` has no extension
- content: literal content (optional); `content: ''` writes an empty file
- content_file: load content from a file inside the manifest's directory (optional)
- content_len: how much deterministic filler the file carries, at least 1. With no content of any kind the default is 1024 characters (256 for `append`, 128 for `ads`). For a structured format it is the size of the *filler region*, not of the file: the PE overlay, the zip member, the PNG chunk, the JPEG comments, the MP4 `mdat`, the PDF or docx text (see *File formats*). A structured format with no `content_len` gets the smallest valid file
- content_kind: what invented bytes look like — `text` (the default: base32), `bytes` (uniform random), `zeros`, `pattern` (a counting ramp) or `lorem` (words). It only applies to bytes fsagen invents, so giving it beside `content`, `content_file` or `template` is an error
- render: run `${...}` substitution over the content. Defaults to `true` for inline
  `content` and `false` for `content_file`, because scripts and PEM keys contain
  `${...}` sequences of their own that must survive verbatim
- mode: octal file permissions, e.g. `"0600"` (default 0644 files, 0755 directories)
- format: what to build — `raw` (default) or `text` writes the content through; `pdf`, `docx`, `pe`, `zip`, `png`, `jpeg`, `mp4`, `chrome_history` and `firefox_places` build a file of that type. With no `format` and no content of its own, the extension picks one (see *File formats*). For the `email` action, `eml` or `mbox`
- pdf: document metadata for `format: pdf` — see below
- docx: `title`, `author`, `created`, `modified` for `format: docx`
- pe: machine, subsystem, dll, timestamp, sections, imports and version resource for `format: pe` — see *File formats*
- history: `visits` and (Chrome) `downloads` for `format: chrome_history` or `firefox_places` — see *File formats*
- archive: what goes into the `archive` action's zip — see *File formats*
- edit: the changes the `edit` action makes — see *File formats*
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
  promises a format fsagen cannot build: `.xlsx`, `.pptx`, `.gif`, `.bmp`,
  `.mov`, `.sqlite`, `.db`, `.eml`, `.mbox`, and `.pdf` without `format: pdf`.
  The error says what the extension promises and what to use instead
  (`action: email` for a message, `format: chrome_history` for a profile).
  Add `format: text` to write placeholder text on purpose, or give
  `content`/`content_file`. An extension fsagen *can* build gets a real file
  of that type instead of an error (see *File formats*).
- a typed block beside the wrong format (`pe:` with `format: docx`), or
  `content`, `content_file`, `template` or `render` beside a format that
  builds the file itself
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
- `examples/manifest-bulk-simple.yaml` - Many files of every type fsagen can build, in one manifest
- `examples/manifest-history.yaml` - Chrome and Firefox history databases, each in its own epoch

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

Operations supported: `create|update|append|edit|truncate|rotate|delete|mace|rename|copy|archive|ads|motw|email|ansible-vault` (all operations work in both manifest and playbook). `ads` and `motw` are Windows-only. Each action happens at its scheduled time, which sets the times of what it creates or changes (see *Timestamps*); explicit `atime`/`mtime`/`ctime`/`crtime` override them.

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
- `${IP:cidr}` - Deterministic address inside a block, e.g. `${IP:10.10.0.0/16}` or `${IP:2001:db8::/32}`. IPv4 blocks with room to spare leave out the network and broadcast addresses (`TestIPStaysInCIDR`)
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
    template: email  # a real RFC 5322 message; the email action gives full control
```

Available templates: `email`, `log`, `script`, `doc`

**Example playbooks:**

- `examples/playbook-basic.yaml` - Simple two-actor workflow
- `examples/playbook-adversary-data-theft.yaml` - Stages documents, zips them, writes exfil logs, backdates
- `examples/playbook-browsing.yaml` - Two users browsing, one Chrome profile and one Firefox
- `examples/playbook-log-tampering.yaml` - Creates baseline logs, injects tampered entries, backdates, then cuts the injected lines out with `edit`
- `examples/playbook-persistence-artifacts.yaml` - Drops startup-like files and .reg exports
- `examples/playbook-email-and-archive.yaml` - Real messages and JPEGs, a real zip of both by id, then deletes the originals
- `examples/playbook-log-rotate-and-truncate.yaml` - Demonstrates log rotation and truncation
- `examples/playbook-windows-ads-motw.yaml` - Adds NTFS ADS and Mark-of-the-Web (Windows-only)
- `examples/playbook-email-thread.yaml` - Four-message RFC 5322 thread as `.eml` and `.mbox`, with a generated PDF attachment
- `examples/playbook-comprehensive-ransomware.yaml` - **Advanced**: Full ransomware attack with variables, batching, conditions, and templates
- `examples/playbook-insider-threat-exfil.yaml` - **Advanced**: 7-day insider threat scenario with repeated access patterns
- `examples/playbook-malware-lifecycle.yaml` - **Advanced**: 48-hour malware infection lifecycle: a PE dropper with imports and a version resource, beaconing, lateral-movement logs named from `${IP:10.10.0.0/16}`, and anti-forensics

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
      - ref: quarterly                    # the one live path under that id,
                                          # whatever it was named
```

Every field:

| Field | Meaning |
|---|---|
| `from` | the sender; one address, with or without a display name |
| `to`, `cc`, `bcc` | lists of addresses; `bcc` is written into the file, as a message in a sender's own mailbox has it |
| `reply_to`, `return_path` | `Reply-To:` and `Return-Path:` |
| `subject` | `Subject:`; non-ASCII is encoded-word wrapped |
| `date` | RFC3339 in, RFC 5322 out, and the file's times; defaults to the scheduled time |
| `message_id`, `in_reply_to`, `references` | the threading headers; each is written only when given, so a thread that needs `Message-ID:` states it (`template: email` draws one from the operation's random stream instead) |
| `headers` | an ordered list of `{name, value}` written before everything else |
| `body_text`, `body_html` | the bodies, inline |
| `body_text_file`, `body_html_file` | the same, read from a file beside the YAML |
| `attachments` | see below |

An attachment names its bytes in one of four ways, exactly one per entry:
`source_file` (beside the YAML), `source_root` (a path in the output root an
earlier step wrote), `ref` (the one live path under an id, whatever it ended
up being called), or `content` (inline literal). `name` is the filename the
recipient sees, `content_type` overrides the type guessed from that name,
`disposition` is `attachment` (the default) or `inline`, and `content_id`
gives an inline part the `Content-ID:` an HTML body refers to with `cid:`. Every one of these fields is checked in
`TestEveryDocumentedFieldIsWritten`.

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
| `create`, `archive`, `ansible-vault`, `email` to an `.eml` | born at T: all four times are T (creating a file that exists makes it anew) |
| `update`, `append`, `edit`, `truncate`, a later message appended to an `.mbox` | access, modification and change become T; creation is kept |
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

The resolution is 100 ns on NTFS and ReFS, and FAT's and exFAT's own where
the volume is one of those. Elsewhere on Unix it is read from the output
directory's change time, which only the kernel sets: on a volume that keeps
whole seconds (ext3, ext4 with 128-byte inodes, which `mkfs.ext4` picks below
512 MB, HFS+) it always falls on a whole second, and there times are checked
to the second; otherwise to the microsecond
(`TestGranularityFromRootChangeTime`, run on tmpfs, btrfs and such an ext4).
The ledger and the modelled timeline keep the fractions the scenario asked
for either way.

A time the platform cannot set is never faked: if the input asks for it, the
run stops before writing (or, with `--on-unsupported=skip`, drops the field
and records it in the run manifest); if the scenario only implies it, the
ledger lists it as uncontrolled. Which platform can set which time is in
*Platform support*; what fsagen cannot control at all, and what can disturb
the output after the run, is in *Limits*.

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
change time tests run on Windows (11 and 10); on Linux they are skipped, and
the rest pass on Fedora 40, on tmpfs and btrfs. None of it has run on macOS
or FreeBSD.

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
   `ledger.jsonl`, `answer-key.jsonl` and `run-manifest.json`;
4. the modelled timeline (`--timeline-source modelled`), in every format.

This holds on every platform, for every operation the platform supports.
Which operations were skipped as unsupported is recorded, and follows from the
capability set; skipping one changes no other file's bytes. Bulk mode is
covered too (with `--bulk-start` as one more input).

Three kinds of bytes hold only for the pinned toolchain and the pinned
dependency versions, both recorded in `run-manifest.json`: a `deflate`
archive member (`compress/flate`), a JPEG (`image/jpeg`) and an SQLite
database (the driver). Everything else is written by fsagen itself and does
not depend on either — store-only zips (which is what a docx is), PE images,
MP4, and the PNG, whose zlib stream is hand-rolled from stored blocks for
exactly this reason.

How: every random value is drawn from a ChaCha8 stream keyed by the seed and
the name of what it is for (the operation's `id` or the hash of its YAML,
its iteration and batch, the field, the token), so adding, removing or
reordering an unrelated action changes nothing else. Nothing reads the wall
clock except `start: now`, which marks the run as not reproducible.

**Not covered:** anything read back from the live file system: observed
timelines;
the times on disk themselves (the ledger states what they are meant to be,
and the verify pass checks them within the run); times the ledger lists as
uncontrolled; NTFS `$FILE_NAME` times; file IDs, allocation and directory order; `run-info.json`; runs with
`start: now`; files already present under `--into-existing`.

Verified by `TestDeterminismHarness` (every example and bulk mode, two runs
into different directories, and a different seed), the version-pinned goldens
(`TestExampleContentGoldens`, which also pins each example's ledger, answer
key and modelled bodyfile, and `TestDryRunGoldens`), `TestBulkDeterministic`,
`TestNoWallClockInContent`, `TestInsertingUnrelatedActionLeavesOtherFilesUnchanged`,
`TestModelledTimelineIdenticalAcrossRuns` and
`TestCrossCapabilityContentEquality`. The whole suite has been run on Windows
11, Windows 10 and Fedora 40 (Linux goldens recorded there: every file is
byte-identical to Windows, less the NTFS streams). macOS and FreeBSD are
built by the gate but have never been run.

## Platform support

fsagen builds with `CGO_ENABLED=0` for Windows, Linux, macOS and FreeBSD on
amd64 and arm64, and `go run ./tools/gate` compiles all eight. What it can
then *do* differs, and every difference is reported rather than faked: an
input that asks for something the platform cannot do stops the run before
anything is written, unless `--on-unsupported=skip` is given, and then each
skipped operation is listed in `run-manifest.json`
(`TestUnsupportedOpsFailBeforeAnyWrite`,
`TestOnUnsupportedSkipRecordsAndKeepsOtherBytes`).

| | Windows, NTFS or ReFS | Windows, FAT or exFAT | Linux | macOS, FreeBSD |
|---|---|---|---|---|
| files, directories, content | yes | yes | yes | compiled, never run |
| access and modification times | yes | yes | yes | compiled, never run |
| creation time (`crtime`) | yes | yes | no | no |
| change time (`ctime`) | yes | no, the volume stores none | no | no |
| `ads`, `motw` | yes | no | no | no |
| POSIX `mode` bits | the read-only attribute only | the same | yes | yes |
| birth time read into a timeline | yes | yes | `statx` `STATX_BTIME` where the filesystem reports one, else unknown | `Birthtimespec` |
| named streams listed in a timeline | yes, one record each | none to list | n/a | n/a |
| timeline read without moving access times | yes, suspended per handle | the same | `O_NOATIME` when the caller owns the file, else restored, which moves the change time and is recorded | best effort, recorded |
| `$FILE_NAME` times | never controlled | n/a | n/a | n/a |

A "no" for something the input asks for outright is a pre-flight error; a
"no" for a default the scenario only implies is recorded as `uncontrolled` in
the run manifest and in the ledger, never guessed.

Where the suite has actually run: Windows 11 (build 26200) and Windows 10
(build 19045) on NTFS, and Fedora 40 on tmpfs, btrfs and an ext4 volume made
with 128-byte inodes, which keeps whole seconds and no birth time. macOS and
FreeBSD are compiled on every change and have **never been run**: their
column is what the code paths intend, not a measurement.

## Limits

What fsagen does not control, and what can change its output after it
finishes:

- NTFS keeps a second set of times in each `$FILE_NAME` attribute, which no
  user-mode call can set. The run manifest says `filename_times_controlled:
  false`.
- The output directory's own times are never set (`root_times_controlled:
  false`).
- NTFS tunneling hands a file created under a name used moments earlier in
  the same directory the *old* file's creation time, which is exactly what a
  `rotate` does. fsagen stamps and then verifies all four times afterwards,
  so the scenario's time is what lands (`TestRotateKeepsRotatedTimes`).
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
  folders (the user profile outside `AppData`) within seconds, and holds it
  open while it does. Defender's machine-learning detection refuses writes of
  generated PE images often enough to matter: it flagged the persistence
  artifacts of `playbook-malware-lifecycle.yaml`
  (`Trojan:Win32/Bearfoos.B!ml`), and it refused the acceptance scenario's
  implant under the name `svchost.exe`, under a version resource claiming
  Microsoft, and under the default high-entropy filler. Its verdict is not
  stable either: it allowed and then refused the same bytes minutes apart. A
  refused write is a failed run, not a silent one, so nothing wrong reaches
  the corpus — but generate into a folder that is neither indexed nor
  scanned. The ledger, answer key and modelled timeline describe what fsagen
  wrote either way.
- An observed timeline is not reproducible, by construction: it reports inode
  numbers, allocation and whatever another process did to the tree. The
  modelled timeline is the artefact to compare between machines (see
  *Determinism contract*).
- A `deflate` archive member, a JPEG and an SQLite database are reproducible
  only for the toolchain and dependency versions `go.mod` pins, both recorded
  in the run manifest. Everything else fsagen writes itself.
- A generated PE is a container for a parser, not a program: its sections
  hold filler, its entry point is inside that filler, and running one does
  nothing. fsagen has no way to produce, and no intention of producing,
  working code.
- Not generated at all: registry hives (a `.reg` export is text), EVTX, LNK,
  Prefetch, `$Recycle.Bin`, and disk images. fsagen writes into a directory on
  a live file system; making a FAT or NTFS image, with `$FILE_NAME` times and
  deleted-entry residue under fsagen's control, is a separate piece of work.

## File formats

A `create` or `update` that gives no content of its own builds a file of the
type its extension promises. Give `format:` to say so outright, or to build a
type whose extension is ambiguous.

| `format` | Inferred from | What is written | Where `content_len` goes | Read back by |
|---|---|---|---|---|
| `pe` | `.exe` `.dll` `.sys` `.scr` | PE32 or PE32+: DOS stub, COFF and optional headers, sections, import table, version resource, a Windows checksum | the overlay, after the last section | `debug/pe` (`TestTypedFormatsParse`, `TestPEHeaderFieldsEqualInputs`) |
| `zip` | `.zip` `.jar` | a zip holding one member, `data.bin` | that member's size | `archive/zip` (`TestZipIsReadableWithSizesInPlace`) |
| `png` | `.png` | a 64×64 truecolour PNG | an `fsAg` private ancillary chunk | `image/png` (`TestPNGDecodesAndCarriesPadding`) |
| `jpeg` | `.jpg` `.jpeg` | a 64×64 baseline JPEG | `COM` segments after `SOI` | `image/jpeg` (`TestJPEGDecodesAndCarriesPadding`) |
| `mp4` | `.mp4` | `ftyp` + `moov` (`mvhd`, one video `trak`) + `mdat`, 320×240, 3 s | the `mdat` payload | a box walk (`TestMP4HasFtypMoovMdat`, `TestMP4DurationAndDimensions`) |
| `docx` | `.docx` | an OOXML package: `[Content_Types].xml`, `word/document.xml`, `docProps/core.xml` and `app.xml`, stored uncompressed | the document's text | `archive/zip` + the properties (`TestDocxOpensWithParts`) |
| `pdf` | *(explicit only)* | a paginated PDF from a Markdown subset | the document's text | see *`format: pdf`* |
| `chrome_history` | *(explicit only)* | Chrome's `meta`, `urls`, `visits`, `downloads`, `downloads_url_chains` and `keyword_search_terms`, with its indexes | not accepted | SQLite + the queries a tool runs (`TestStandardHistorySQLReturnsVisits`) |
| `firefox_places` | *(explicit only)* | Firefox's `moz_origins`, `moz_places` (with `rev_host`) and `moz_historyvisits`, `user_version = 77` | not accepted | as above |
| `text`, `raw` | anything else | the content, or filler, byte for byte | the whole file | — |

`.pdf` is deliberately not inferred: a PDF's dates are settled while the
operation is compiled, before its path is rendered, so it stays an explicit
`format: pdf`. An extension that promises something fsagen still cannot build
is an error rather than a fake — see *Input is strict*.

Filler is base32 text unless `content_kind` says otherwise
(`TestFillerKinds`, `TestBytesEntropyAbove7_9At64KiB`,
`TestContentKindShapesTheBytes`). A structured format is built by fsagen, so
it takes no `content`, `content_file`, `template` or `render`; `pdf` and
`docx` are the exceptions, because there the content *is* the document's
text.

### `pe:` — Windows executables

What fsagen writes is a container for a parser to read, not a program to run:
headers, sections of filler, an import table and a version resource. Nothing
in the image is code — the entry point is inside filler — and it must stay
that way.

```yaml
- action: create
  path: AppData/Local/Temp/wupdmgr32.exe
  content_len: 8192            # the overlay
  pe:
    machine: amd64             # amd64 (default), i386, arm64
    subsystem: gui             # console (default), gui, native
    dll: false
    timestamp: "2024-03-15T09:00:00Z"   # RFC3339, or "0" for a reproducible
                                        # build; defaults to the action's time
    sections:                  # default: .text 1024, .rdata 512, .data 256
      - name: .text
        size: 4096
        flags: [code, execute, read]
      - name: .data
        size: 1024
        flags: [initialized_data, read, write]
    imports:                   # "dll!function"; the imphash is stable
      - kernel32.dll!CreateFileW
      - advapi32.dll!RegSetValueExW
    version:                   # the resource Explorer and every metadata tool read
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
compares (on Windows; elsewhere `TestPEChecksumCoversTheWholeImage` checks
only that the stored value covers the image). The same imports always give
the same imphash (`TestImphashStable`).

### `history:` — browser profiles

Each engine keeps its own epoch, and getting that wrong is the classic way to
put a corpus in the year 1601: Chrome counts microseconds from 1601-01-01 and
Firefox from 1970-01-01 (`TestChromeWebKitEpoch`, `TestFirefoxPRTime`).
fsagen writes the tables a parser queries, with their indexes:
`TestStandardHistorySQLReturnsVisits` runs the SQL a history tool runs and
gets the scenario's visits, hosts, visit counts and transition codes back.
Nothing has been checked against a named forensic tool.

```yaml
- action: create
  path: Users/analyst/AppData/Local/Google/Chrome/User Data/Default/History
  format: chrome_history
  history:
    visits:
      - url: https://intranet.example/hr/handbook
        title: Employee handbook
        time: "2023-10-30T09:12:00Z"   # defaults to the action's time
        transition: typed               # link (default), typed, bookmark,
                                        # generated, form_submit, reload
      - url: https://intranet.example/hr/handbook/leave
        title: Leave policy
        time: "2023-10-30T09:13:20Z"
        from_visit: 1                   # 1-based position in this list
    downloads:                          # Chrome only
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

### `archive` action

Zips files the scenario has already written. Members come from the model, so
a member's stored modification time is the time the scenario gave that file,
not the time it happened to be written; and they are resolved before the
archive object exists, so a pattern can never sweep the archive into itself.

```yaml
- action: archive
  path: staging/exfil-ready.zip
  archive:
    method: store            # store (default) or deflate
    comment: staged for transfer
    member_refs: [mail, media]   # every live path created under these ids,
                                 # in creation order
    members:                     # then glob patterns, in path order
      - "users/alice/staging/*.csv"
    base: users/alice/staging    # stripped from each stored name
```

`member_refs` come first, in the order the files were created, then
`members`, in path order; a path named twice is stored once. A pattern that
matches nothing is an error, as is a member that does not lie under `base` —
fsagen will not invent a name for it (`TestArchiveRefusesEmptyPattern`,
`TestArchiveBaseMustCoverEveryMember`).
Patterns are `path.Match` globs, so `*` does not cross a `/`. In a playbook,
both the patterns and `base` are relative to the actor's base.

`store` is the default because deflated bytes come from `compress/flate` and
so are reproducible only for the Go toolchain `go.mod` pins. Members match
their sources byte for byte (`TestArchiveMembersMatchSources`).

### `edit` action

Changes a file in place. Cutting the injected lines back out of a log leaves
a gap in the record; truncating it leaves a file that is obviously short.
Telling those apart is the kind of thing a tool under test should be able to
do, so fsagen can produce both.

```yaml
- action: edit
  path: var/log/app.jsonl
  edit:
    delete_lines: "40-60"            # 1-based, inclusive; or a single line
    delete_matching: '"level":"warn"' # every line the regexp matches
    replace:
      - pattern: 'user=(\w+)'
        with: 'user=REDACTED'
        count: 0                     # 0 means every match
    insert_after:
      - pattern: '"service start"'
        text: '{"ts":"2021-07-01T00:00:01Z","level":"info","msg":"ready"}'
```

The steps run in that fixed order whatever order they are written in: whole
lines, then substitutions over the text, then insertions. A scenario that
needs another order uses two `edit` actions, which is also what the ledger
then shows. Line endings survive, and a file that ended without a newline
still does. A range past the end of the file is an error
(`TestEditDeleteLines40to60`, `TestEditReplaceAndInsert`,
`TestEditRefusesMissingLines`).

### Bulk mode

Bulk mode writes `--bulk` files of every one of these types in each
directory it makes, all structurally valid:

- **Documents**: .txt, .md, .docx, .pdf
- **Data**: .csv, .json, .jsonl, .xml, .html
- **Logs**: .log, .syslog, .jsonl
- **Media**: .png, .jpg, .mp4
- **Archives**: .zip
- **Email**: .eml, .mbox
- **Browser history**: a Chrome profile (`Chrome-xxxxxx/Default/History`) and
  a Firefox one (`Firefox-xxxxxx/Profiles/xxxxxxxx.default-release/places.sqlite`),
  under the names a tool looks for
- **Windows**: .reg; .exe (a real PE with imports and a version resource)

## Forensic Timeline Generation

After generating, fsagen can write a timeline of the output, from one of two
sources:

- **observed** (the default): read back from the file system after the run,
  as a tool examining the output would see it. It is not covered by the
  determinism contract: inode numbers, directory sizes and anything another
  process touched afterwards differ from run to run.
- **modelled** (`--timeline-source modelled`): built from the run's model and
  ledger, reading nothing from disk: the times, sizes and digests the scenario
  intends, **including the objects it deleted**, marked `(deleted)` as The
  Sleuth Kit marks them, which an observed timeline can never show. It is the
  same bytes on every run with the same inputs and capability set
  (`TestModelledTimelineIdenticalAcrossRuns`, and the determinism harness on
  every example). Its inode column is the ledger's object number, its mode is
  the one fsagen requests (before any umask), a directory's size is 0, and a
  time the platform cannot set is unknown rather than the scenario's wish. The
  text formats say which source they are; the run manifest records the source
  of every timeline, and the digest of a modelled one.

```pwsh
fsagen --seed 42 --playbook scenario.yaml --timeline case.body ./artifacts
fsagen --seed 42 --playbook scenario.yaml --timeline intended.body --timeline-source modelled ./artifacts2
```

**Formats** (from `--timeline-format` or the extension; an unknown extension is
an error, never a silent fall-back):

- **Bodyfile** (`.bodyfile`, `.body`): The Sleuth Kit's bodyfile,
  `MD5|name|inode|mode|UID|GID|size|atime|mtime|ctime|crtime`: names from the
  output root with a leading `/` and no root entry, `name:stream` for each
  named stream and `name (deleted)` for a deleted object (modelled only), TSK
  mode strings (`r/rrw-r--r--`), times in whole seconds, and `0` for an
  unknown time or an MD5 that was not computed. `mactime` reads it
  (`TestMactimeAccepts`, run on Linux with The Sleuth Kit 4.12.1);
  `TestBodyfileStrictParserRoundTrip` parses every line of an observed and a
  modelled bodyfile strictly.
- **MACB** (`.macb`): one line per entry and distinct instant, in time order,
  as `mactime` prints it: the flags say which of the entry's times fall then
  (`MACB` when all four agree, `M...` and `.A.B` when they do not;
  `TestMACBSixteenCombinations` covers every combination).
- **CSV** (`.csv`): one row per entry: path, stream, type, size, mode, UID,
  GID, inode, the four times (RFC 3339 with fractions, empty when unknown),
  MD5 and deleted.
- **JSON lines** (`.jsonl`): the same fields, one object per entry, with an
  octal mode.
- **Text** (`.txt`): a readable listing, one block per entry.

**Every entry has four times**: accessed, modified, changed (metadata) and
born (created), each read from its own source and never copied into another:
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
an error that names it, never a shorter timeline (`TestWalkErrorReported`).
The whole timeline is built before its file is written. Entries are sorted by
modification time, then path; all times are UTC.

**Checked against The Sleuth Kit** (by hand, 2026-09-26; not part of the test
suite): a scenario with renames, a copy, a timestomp, streams, explicit
creation and change times and a deletion was generated onto a fresh ext4 image
(Fedora 40) and onto an NTFS volume (Windows 10), and each image was read with
`fls -r -m` (TSK 4.12.1). Every file and stream record of the observed
bodyfile matched `fls` in inode, mode, owner, size and all four times; the
only difference was the size of directories on NTFS, which Windows does not
report and TSK reads from the directory index. The modelled bodyfile's times
matched every live record, and on NTFS `fls` recovered the deleted file's MFT
record with the same size and four times as the modelled `(deleted)` entry.

**Timeline-only mode**: `fsagen --timeline FILE DIR` writes an observed
timeline of an existing directory without generating anything.

```pwsh
fsagen --timeline existing.csv ./already-generated-folder
fsagen --timeline evidence.body ./investigation
mactime -b evidence.body -d > detailed-timeline.txt
```

See `examples/TIMELINE_EXAMPLES.md` for more.

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
- Populates each level with one file of every type in *File formats* (txt, docx, png, jpg, pdf, mp4, csv, json, xml, html, log, reg, zip, exe, jsonl, syslog, md, eml, mbox, a Chrome profile and a Firefox one)
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

`docs/testing.md` maps every finding in `plan.json` to the test that closes
it. `TestConsumerAcceptance` runs
`testdata/acceptance/quilldrop-lite.playbook.yaml` and checks the eleven
things fsagen's first consumer asked for, from a parseable phishing message
to a real gap in a beacon log.

### Dependencies

Five direct ones, each here for a reason the standard library does not cover.
`go mod tidy` is clean, and the whole product builds with `CGO_ENABLED=0`.

| Module | Why |
|---|---|
| `go.yaml.in/yaml/v3` | YAML with `KnownFields` (an unknown key is an error) and a `Node` pass that gives every error a line and column. `gopkg.in/yaml.v2` has neither |
| `github.com/glebarez/go-sqlite` | a `database/sql` driver for SQLite with no cgo, for the Chrome and Firefox profiles and bulk mode's databases |
| `github.com/jung-kurt/gofpdf` | writes the PDFs, with the document metadata pinned so two renders match |
| `golang.org/x/sys` | `NtCreateFile` and `FILE_BASIC_INFO` on Windows, `statx` on Linux, `Birthtimespec` on the BSDs, and the last-access registry value |
| `golang.org/x/text` | Unicode case folding and NFC normalisation, so the portability check catches names that collide on a case-insensitive or normalising volume |

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
